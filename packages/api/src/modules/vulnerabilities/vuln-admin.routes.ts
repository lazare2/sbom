import { createWriteStream } from "node:fs";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  createSuppressionSchema,
  idParamSchema,
  updateVulnSettingsSchema,
  type VulnScanStatus,
} from "@sbom/shared";
import { BadRequestError, NotFoundError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import type { Actor } from "../admin/audit.service.js";

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
    return {
      ...base,
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

  fastify.get("/suppressions", async (_request, reply) => {
    return reply.send({ suppressions: await vulnerabilities.listSuppressions() });
  });

  fastify.post("/suppressions", async (request, reply) => {
    const body = parseOrThrow(createSuppressionSchema, request.body);
    const actor = actorOf(request);
    const created = await vulnerabilities.createSuppression(body, actor);

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
      },
    });

    // Suppressions are applied when snapshots are built, so the counts have to be
    // rebuilt or the dashboards keep reporting a risk that was just accepted.
    vulnWorker.requestSummaryRefresh();

    return reply.status(201).send({ id: created.id });
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
  fastify.get("/storage", async (_request, reply) => {
    return reply.send({
      cacheDir: path.resolve(config.GRYPE_DB_CACHE_DIR),
      listingUrl: (await vulnDb.status()).updates.listingUrl,
      batchSize: config.GRYPE_BATCH_SIZE,
    });
  });
}
