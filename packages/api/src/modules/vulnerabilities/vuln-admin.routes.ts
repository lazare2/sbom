import { requireScope } from "../environments/scope.js";
import { createWriteStream } from "node:fs";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  classifySuppressionSchema,
  createSuppressionSchema,
  idParamSchema,
  setVulnProviderSchema,
  testXrayConnectionSchema,
  updateVulnSettingsSchema,
  updateXrayConnectionSchema,
  type VulnScanStatus,
  type XrayCoverage,
  type XrayDiagnosis,
} from "@sbom/shared";
import { BadRequestError, NotFoundError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import type { Actor } from "../admin/audit.service.js";
import { XrayScanner } from "../../services/scanner/xray.js";
import type { XrayCredentials } from "../../services/scanner/xray-client.js";

/** The acting admin, denormalised onto every audit row this request writes. */
function actorOf(request: FastifyRequest): Actor {
  const user = getUser(request);
  return { id: user.id, email: user.email };
}

/**
 * Admin control surface for vulnerability scanning.
 *
 * Registered inside the `requireAdmin` scope, so like every other route in that scope
 * it is guarded whether or not its author thought about it.
 *
 * What is deliberately NOT here: any way to set the grype binary path, or any other
 * value that decides what the server executes. Those live in the environment, where
 * changing them requires deployment access. This panel shows where the binary was
 * looked for and what was found, and offers actions — update, import, enable — but
 * never an arbitrary path. A published project whose admin UI can point the server at
 * any executable on disk ships a remote-code-execution primitive to everyone who
 * deploys it.
 */
export async function vulnAdminRoutes(fastify: FastifyInstance): Promise<void> {
  const { vulnDb, vulnWorker, vulnerabilities, settings, sweep, audit, config } = fastify.ctx;

  /**
   * Assembles the status payload, filling in the in-process sweep state the database
   * cannot know about.
   */
  async function status(): Promise<VulnScanStatus> {
    const base = await vulnDb.status();
    const active = await settings.vulnProvider();
    const xray = await settings.xraySettings();

    return {
      ...base,
      /*
        Grype matches everything it is handed, so nothing is uncovered. Xray's coverage is
        whatever the last probe measured -- and until one has run, nothing is known to be
        covered, which is reported as an unmeasured state rather than as full coverage.
      */
      provider: {
        active,
        uncoveredEcosystems: active === "xray" ? (xray.coverage?.uncovered ?? []) : [],
        coverageCheckedAt: active === "xray" ? (xray.coverage?.checkedAt ?? null) : null,
      },
      coverage: {
        ...base.coverage,
        sweeping: vulnWorker.sweeping,
        lastSweepFinishedAt: vulnWorker.lastSweepFinishedAt?.toISOString() ?? null,
      },
    };
  }

  fastify.get("/status", async (_request, reply) => {
    return reply.send(await status());
  });

  fastify.get("/history", async (request, reply) => {
    const query = parseOrThrow(
      z.object({ limit: z.coerce.number().int().min(1).max(100).default(20) }),
      request.query,
      "Query",
    );
    return reply.send({ attempts: await vulnDb.history(query.limit) });
  });

  /**
   * Enables or disables scanning, and sets the check interval.
   *
   * Enabling kicks off a backfill: everything already ingested needs matching, and
   * without it the feature would appear to do nothing until the next build arrived.
   * That runs detached so this request returns immediately — progress shows up in the
   * coverage figures.
   */
  fastify.patch("/settings", async (request, reply) => {
    const body = parseOrThrow(updateVulnSettingsSchema, request.body);
    const actor = actorOf(request);
    const { before, after } = await settings.updateVulnSettings(body, actor);

    await audit.record({
      actor,
      action: "vuln.settings_update",
      targetType: "setting",
      targetId: "vuln",
      metadata: { before, after },
    });

    if (!before.enabled && after.enabled) {
      vulnWorker.requestBackfillAfterEnable();
    }

    return reply.send(await status());
  });

  /**
   * Updates the vulnerability database now.
   *
   * Always 200, including when there is no route to the internet. That is the
   * requirement and it is also the right shape: being air-gapped is a state to report,
   * not a request that failed. The response carries the outcome and, when unreachable,
   * the exact URL that could not be contacted.
   */
  fastify.post("/update", async (request, reply) => {
    const actor = actorOf(request);
    const result = await vulnDb.update("manual", actor);

    await audit.record({
      actor,
      action: "vuln.db_update",
      targetType: "setting",
      targetId: "vuln",
      metadata: { outcome: result.outcome, message: result.message },
    });

    // A new database makes every component pending again, so kick the sweep.
    if (result.databaseChanged) vulnWorker.requestSweepAfterDbChange();

    return reply.send({
      outcome: result.outcome,
      message: result.message,
      attempt: result.attempt,
      status: await status(),
    });
  });

  /**
   * Installs a database from an uploaded archive — the air-gapped path.
   *
   * Streamed to a temp file and handed to `grype db import`, which verifies the archive
   * itself. The temp file is removed in a `finally`: these are ~141 MB and leaking one
   * per attempt would fill a disk quietly.
   */
  fastify.post(
    "/import",
    {
      config: {
        // Deliberately low. Importing is a rare, deliberate act and each one writes a
        // multi-hundred-megabyte file.
        rateLimit: { max: 5, timeWindow: "1 minute" },
      },
    },
    async (request, reply) => {
      if (!request.isMultipart()) {
        return reply.status(415).send({
          error: {
            code: "unsupported_media_type",
            message:
              "Expected multipart/form-data with a `database` file part containing the .tar.zst archive.",
          },
        });
      }

      const actor = actorOf(request);
      const dir = await mkdtemp(path.join(tmpdir(), "sbom-grype-db-"));

      try {
        let archivePath: string | undefined;
        let filename: string | undefined;
        let bytes = 0;

        /*
          The per-request limit overrides the global multipart one, which is sized for
          SBOMs (INGEST_MAX_SBOM_BYTES, 64 MiB by default) and rejects a ~145 MB database
          archive outright. Without this the air-gapped install path cannot accept the
          only file it exists to accept.
        */
        for await (const part of request.parts({
          limits: { fileSize: config.GRYPE_DB_MAX_UPLOAD_BYTES },
        })) {
          if (part.type !== "file") continue;

          if (part.fieldname === "database" && archivePath === undefined) {
            filename = part.filename;
            /*
              Streamed to disk rather than buffered. `toBuffer()` would hold the whole
              archive in memory — 145 MB today, and up to GRYPE_DB_MAX_UPLOAD_BYTES if
              someone uploads the wrong file — on a container whose normal working set is
              a few tens of MB. `pipeline` also propagates the multipart plugin's
              file-size error instead of silently truncating.
            */
            archivePath = path.join(
              dir,
              part.filename?.replace(/[^A-Za-z0-9._-]+/g, "_") || "vulnerability-db.tar.zst",
            );
            await pipeline(part.file, createWriteStream(archivePath));

            /*
              `truncated` is how @fastify/multipart reports hitting the limit: the stream
              ends normally and the flag is set afterwards. Not checking it would import a
              half-written archive and report grype's confusing decompression error rather
              than the size problem that caused it.
            */
            if (part.file.truncated) {
              throw new BadRequestError(
                `The uploaded archive exceeds the ${Math.floor(config.GRYPE_DB_MAX_UPLOAD_BYTES / (1024 * 1024))} MB limit ` +
                  "(GRYPE_DB_MAX_UPLOAD_BYTES). Check you uploaded the .tar.zst database archive and not something larger.",
              );
            }
            bytes = (await stat(archivePath)).size;
          } else {
            // Every file stream must be drained or the request never completes.
            await part.toBuffer();
          }
        }

        if (archivePath === undefined || bytes === 0) {
          throw new BadRequestError(
            "Missing `database` file part. Download the archive from the URL shown above and upload it here.",
          );
        }

        const result = await vulnDb.importArchive(archivePath, actor);

        await audit.record({
          actor,
          action: "vuln.db_import",
          targetType: "setting",
          targetId: "vuln",
          metadata: { outcome: result.outcome, message: result.message, filename: filename ?? null, bytes },
        });

        if (result.databaseChanged) vulnWorker.requestSweepAfterDbChange();

        return reply.send({
          outcome: result.outcome,
          message: result.message,
          attempt: result.attempt,
          status: await status(),
        });
      } finally {
        await rm(dir, { recursive: true, force: true }).catch(() => undefined);
      }
    },
  );

  /**
   * Runs a sweep now.
   *
   * Exists because "the database is current but coverage is not" is a real state after
   * a crash or a disabled period, and waiting up to an interval to watch it recover is
   * an unhelpful way to find out whether it works.
   */
  fastify.post("/sweep", async (request, reply) => {
    const outcome = await sweep.sweep({ reason: "admin", maxBatches: 50 });
    await audit.record({
      actor: actorOf(request),
      action: "vuln.sweep",
      targetType: "setting",
      targetId: "vuln",
      metadata: { status: outcome.status, componentsScanned: outcome.componentsScanned, remaining: outcome.remaining },
    });
    return reply.send({ ...outcome, status: outcome.status, scanStatus: await status() });
  });

  // -------------------------------------------------------------------------
  // Suppressions
  // -------------------------------------------------------------------------

  fastify.get("/suppressions", async (request, reply) => {
    return reply.send({
      suppressions: await vulnerabilities.listSuppressions(await requireScope(request)),
    });
  });

  fastify.post("/suppressions", async (request, reply) => {
    const body = parseOrThrow(createSuppressionSchema, request.body);
    const actor = actorOf(request);
    const created = await vulnerabilities.createSuppression(body, actor, await requireScope(request));

    await audit.record({
      actor,
      action: "vuln.suppression_create",
      targetType: "vulnerability",
      targetId: body.vulnerabilityId,
      metadata: {
        reason: body.reason,
        componentId: body.componentId ?? null,
        applicationId: body.applicationId ?? null,
        expiresAt: body.expiresAt ?? null,
        vexStatus: body.vexStatus,
        vexJustification: body.vexJustification ?? null,
      },
    });

    // Suppressions are applied when snapshots are built, so the counts have to be
    // rebuilt or the dashboards keep reporting a risk that was just accepted.
    vulnWorker.requestSummaryRefresh();

    return reply.status(201).send({ id: created.id });
  });

  /**
   * Applies a VEX status to a suppression made before the field existed.
   *
   * A PATCH rather than part of the create body, because these rows already exist and their
   * authors are not necessarily around. Whoever classifies one is making a claim to people
   * outside the organisation, which is why the transition is audited with both ends recorded.
   */
  fastify.patch("/suppressions/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(classifySuppressionSchema, request.body);
    const changed = await vulnerabilities.classifySuppression(id, body);
    if (!changed) throw new NotFoundError("Suppression");

    await audit.record({
      actor: actorOf(request),
      action: "vuln.suppression_classify",
      targetType: "vulnerability",
      targetId: id,
      metadata: {
        status: { from: changed.before.status, to: changed.after.status },
        justification: { from: changed.before.justification, to: changed.after.justification },
      },
    });

    // Deliberately no summary refresh: a VEX status changes what is published, never what is
    // counted. The suppression was already excluded from every figure before it was classified.
    return reply.status(204).send();
  });

  fastify.delete("/suppressions/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const removed = await vulnerabilities.removeSuppression(id);
    if (!removed) throw new NotFoundError("Suppression");

    await audit.record({
      actor: actorOf(request),
      action: "vuln.suppression_delete",
      targetType: "vulnerability",
      targetId: id,
    });

    vulnWorker.requestSummaryRefresh();
    return reply.status(204).send();
  });

  /**
   * Where the database lives and how big it is.
   *
   * Surfaced because the two most common operational surprises with this feature are
   * both about disk: the database is ~1.9 GB expanded, and in a container it has to be
   * on a mounted volume or a restart throws away a 141 MB download.
   */

  // -------------------------------------------------------------------------
  // Which vulnerability database is the authority
  // -------------------------------------------------------------------------

  /**
   * The provider, the connection, and what the last probe found.
   *
   * The API token is never in this payload. The screen shows whether one is stored, which
   * is the only thing an administrator needs in order to decide whether to replace it.
   */
  fastify.get("/provider", async (_request, reply) => {
    return reply.send({
      provider: await settings.vulnProvider(),
      xray: await settings.xraySettings(),
      /*
        Whether a token could be stored at all. Without SECRETS_KEY the save is refused, and
        an administrator deserves to know that before typing a credential into a form rather
        than after.
      */
      secretsKeyConfigured: config.SECRETS_KEY !== undefined,
    });
  });

  /**
   * Switches the active database.
   *
   * Nothing is deleted and nothing is migrated. Every component carries the provider that
   * assessed it, and the sweep's queue treats "assessed by someone else" as needing
   * re-assessment — so the estate re-scans itself and switching back undoes it.
   *
   * The figures read as not assessed in the meantime, which is the honest state: the
   * existing findings were produced by a database that is no longer the authority here.
   */
  fastify.put("/provider", async (request, reply) => {
    const body = parseOrThrow(setVulnProviderSchema, request.body, "Body");
    const before = await settings.vulnProvider();

    if (body.provider === "xray") {
      const credentials = await settings.xrayCredentials();
      if (!credentials) {
        throw new BadRequestError(
          "Configure and test the JFrog Xray connection before making it the active database.",
        );
      }

      /*
        Reachable, not merely stored.

        This used to check only that a connection existed, which let an administrator switch
        to an Xray that answers nothing -- and the estate then reads "not assessed" everywhere
        with the cause three screens away. That is the exact failure this provider is most
        likely to hit in a corporate network, and the one with the worst silent outcome, so
        the switch pays the cost of a round trip to prove the choice is usable.

        Only the switch *to* Xray is gated. Returning to the local database must always be
        possible, including from a broken Xray -- especially from a broken Xray.
      */
      const scanner = new XrayScanner(credentials, {
        logger: fastify.log,
        assessmentEpoch: new Date(),
      });
      const availability = await scanner.availability();
      if (!availability.available) {
        const reason = availability.attempts[0]?.reason ?? "The connection failed.";
        throw new BadRequestError(
          `Could not reach JFrog Xray at ${credentials.baseUrl}, so it cannot be made the active database. ${reason}`,
        );
      }
    }

    await settings.setVulnProvider(body.provider);

    await audit.record({
      actor: actorOf(request),
      action: "vuln.provider_change",
      targetType: "setting",
      targetId: "vuln.provider",
      metadata: { provider: { from: before, to: body.provider } },
    });

    return reply.send({ provider: body.provider, xray: await settings.xraySettings() });
  });

  /**
   * Saves the Xray connection.
   *
   * Saving anything advances the assessment epoch, because different credentials may reach a
   * different Xray holding different data — so every existing finding becomes of unknown
   * provenance and the estate is re-assessed rather than trusted.
   *
   * The token is encrypted before storage and never returned. It is also absent from the
   * audit row: the trail records that the connection changed and to which host, which is
   * what it exists to answer, and a credential copied into a table nobody prunes is not.
   */
  fastify.put("/provider/xray", async (request, reply) => {
    const body = parseOrThrow(updateXrayConnectionSchema, request.body, "Body");
    const before = await settings.xraySettings();

    await settings.setXrayConnection(body);

    await audit.record({
      actor: actorOf(request),
      action: "vuln.xray_connection_set",
      targetType: "setting",
      targetId: "vuln.provider",
      metadata: {
        baseUrl: { from: before.connection?.baseUrl ?? null, to: body.baseUrl },
        username: { from: before.connection?.username ?? null, to: body.username },
        tokenReplaced: body.token !== undefined && body.token !== "",
        allowSelfSignedCertificate: body.allowSelfSignedCertificate,
      },
    });

    return reply.send(await settings.xraySettings());
  });

  /**
   * Tests the connection and measures what this Xray actually covers.
   *
   * Two questions in one action, because the second is worthless without the first and an
   * administrator asking "does this work" means both. Reachability proves the URL and the
   * credentials; the coverage probe asks about a known-vulnerable package in each ecosystem
   * and reports the ones that answer nothing.
   *
   * That probe is the difference between a base-image figure that means something and one
   * that was fabricated: Xray answers an ecosystem it holds no data for exactly the way it
   * answers a clean package, and on a container image the operating-system packages are most
   * of the component list.
   *
   * 200 either way. A relay that refuses is the answer to the question that was asked, not a
   * failure of the request -- and a non-2xx would become an ApiError in the client, which
   * keeps the status and discards the body carrying the diagnosis.
   */
  fastify.post("/provider/xray/test", async (request, reply) => {
    const body = parseOrThrow(testXrayConnectionSchema, request.body ?? {}, "Body");

    /*
      Test what is on screen when it is supplied, falling back to what is stored. Without
      that, the only way to try a connection is to save it first -- which overwrites a
      working configuration with an unproven one and leaves nothing to fall back to.
    */
    let credentials: XrayCredentials | null;
    if (body.connection && body.connection.token) {
      credentials = {
        baseUrl: body.connection.baseUrl,
        username: body.connection.username,
        token: body.connection.token,
        allowSelfSigned: body.connection.allowSelfSignedCertificate,
      };
    } else {
      credentials = await settings.xrayCredentials();
      if (credentials && body.connection) {
        // A saved token with an edited URL: keep the credential, use the new address.
        credentials = {
          ...credentials,
          baseUrl: body.connection.baseUrl,
          username: body.connection.username,
          allowSelfSigned: body.connection.allowSelfSignedCertificate,
        };
      }
    }

    if (!credentials) {
      return reply.send({
        ok: false,
        code: "not_configured",
        summary: "No JFrog Xray connection is configured.",
        hint: "Enter the URL, user name and API token, then test again.",
        detail: null,
        version: null,
        coverage: null,
      } satisfies XrayDiagnosis);
    }

    const scanner = new XrayScanner(credentials, {
      logger: fastify.log,
      assessmentEpoch: new Date(),
    });

    const availability = await scanner.availability();
    if (!availability.available) {
      const reason = availability.attempts[0]?.reason ?? "The connection failed.";
      return reply.send({
        ok: false,
        code: "unreachable",
        summary: `Could not reach JFrog Xray at ${credentials.baseUrl}.`,
        hint: "Check the URL, the credentials, and whether this server is allowed to reach that host. A private certificate authority needs the checkbox below.",
        detail: reason,
        version: null,
        coverage: null,
      } satisfies XrayDiagnosis);
    }

    let coverage: XrayCoverage | null = null;
    let probeError: string | null = null;
    try {
      coverage = await scanner.probeCoverage();
      // Only stored when it describes the saved connection, not an unsaved experiment.
      if (!body.connection?.token) await settings.setXrayCoverage(coverage);
    } catch (error) {
      probeError = error instanceof Error ? error.message : String(error);
    }

    await audit.record({
      actor: actorOf(request),
      action: "vuln.xray_connection_test",
      targetType: "setting",
      targetId: "vuln.provider",
      // Never the credentials. The host and the outcome are what the trail is for.
      metadata: {
        baseUrl: credentials.baseUrl,
        ok: true,
        version: availability.version,
        covered: coverage?.covered.length ?? null,
        uncovered: coverage?.uncovered.length ?? null,
      },
    });

    return reply.send({
      ok: true,
      code: "ok",
      summary: `Connected to JFrog Xray ${availability.version}.`,
      hint: probeError
        ? "The connection works, but the coverage probe failed, so which ecosystems this server holds data for is unknown."
        : coverage && coverage.uncovered.length > 0
          ? `No data came back for ${coverage.uncovered.join(", ")}. Packages in those ecosystems will be reported as not assessed rather than as clean.`
          : null,
      detail: probeError,
      version: availability.version,
      coverage,
    } satisfies XrayDiagnosis);
  });

  fastify.get("/storage", async (_request, reply) => {
    return reply.send({
      cacheDir: path.resolve(config.GRYPE_DB_CACHE_DIR),
      listingUrl: (await vulnDb.status()).updates.listingUrl,
      batchSize: config.GRYPE_BATCH_SIZE,
    });
  });
}
