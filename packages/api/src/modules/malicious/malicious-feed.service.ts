import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import { sql } from "drizzle-orm";
import type {
  MaliciousFeedAttempt,
  MaliciousFeedOutcome,
  MaliciousFeedTrigger,
  MaliciousMatchMode,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import type { MaliciousVersionRange } from "../../db/schema.js";
import type { Logger } from "../ingestion/ingestion.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import type { Actor } from "../admin/audit.service.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import { normalizeEcosystem, normalizePackageName } from "./matching.js";
import { readTarGz } from "./tar.js";

/**
 * Fetching and storing the malicious-package feed.
 *
 * The source is the OpenSSF `malicious-packages` repository (Apache-2.0), a pooled,
 * human-reviewed aggregation of malware reports from GitHub, Amazon Inspector, Checkmarx,
 * Datadog and others, published as OSV JSON. It was chosen over querying OSV.dev per package
 * -- which would be one request per component and unusable against a real estate -- and over
 * OSV's per-ecosystem bulk archives, whose npm bundle is 220 MB because it carries every
 * advisory rather than only the malicious ones. This archive is ~41 MB and contains nothing
 * else.
 *
 * ## Nothing here may break anything else
 *
 * The same rule the vulnerability database follows. A deployment with no route to the
 * internet is a legitimate deployment: an unreachable feed is recorded as `unreachable` with
 * the URL that failed and is never surfaced as an error anywhere in the platform. Ingestion,
 * search and every dashboard keep working exactly as they do with the feature switched off.
 */

/**
 * Reports upserted per statement.
 *
 * The archive holds ~236,000. One statement would exceed the parameter limit; one statement
 * per report would be a quarter of a million round trips. A thousand is comfortably inside
 * Postgres's 65,535-parameter ceiling at fourteen columns per row, and keeps the parsed
 * batch small enough that the whole feed never sits in memory at once.
 */
const UPSERT_BATCH = 1000;

/** Bounds a fetch that has stalled rather than failed. The archive is tens of megabytes. */
const FETCH_TIMEOUT_MS = 300_000;

interface OsvRange {
  type?: unknown;
  events?: Array<Record<string, unknown>>;
}

interface OsvAffected {
  package?: { ecosystem?: unknown; name?: unknown };
  versions?: unknown;
  ranges?: OsvRange[];
}

interface OsvReport {
  id?: unknown;
  summary?: unknown;
  details?: unknown;
  aliases?: unknown;
  published?: unknown;
  modified?: unknown;
  withdrawn?: unknown;
  affected?: OsvAffected[];
  references?: Array<{ type?: unknown; url?: unknown }>;
  database_specific?: { "malicious-packages-origins"?: Array<{ source?: unknown }> };
}

/** One report reduced to the row it becomes. */
export interface ParsedReport {
  id: string;
  ecosystem: string;
  packageName: string;
  normalizedName: string;
  summary: string | null;
  details: string | null;
  matchMode: MaliciousMatchMode;
  affectedVersions: string[];
  versionRanges: MaliciousVersionRange[] | null;
  aliases: string[];
  sources: string[];
  referenceUrl: string | null;
  publishedAt: Date | null;
  modifiedAt: Date | null;
  withdrawnAt: Date | null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function asDate(value: unknown): Date | null {
  const text = asString(value);
  if (text === null) return null;
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? null : date;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/**
 * Turn one OSV document into a row, or null when it describes nothing this platform can see.
 *
 * Null for an ecosystem with no purl equivalent -- VSCode extensions, for instance, which
 * Syft never reports -- rather than storing a row that could not match anything. A feed count
 * an administrator reads as coverage should not be padded with reports about package types
 * the scanner cannot observe.
 */
export function parseOsvReport(doc: OsvReport): ParsedReport | null {
  const id = asString(doc.id);
  if (id === null) return null;

  /*
   * One affected package per report.
   *
   * True of every one of the 236,015 reports in the feed, and structural rather than
   * incidental: the repository stores each report at a path that names its single package.
   * Taking the first is therefore exact today. If that ever changes, the extras would be
   * dropped silently, so the caller counts them and says so.
   */
  const affected = doc.affected?.[0];
  if (!affected?.package) return null;

  const rawEcosystem = asString(affected.package.ecosystem);
  const rawName = asString(affected.package.name);
  if (rawEcosystem === null || rawName === null) return null;

  const ecosystem = normalizeEcosystem(rawEcosystem);
  if (ecosystem === null) return null;

  const versions = asStringArray(affected.versions);
  const ranges: MaliciousVersionRange[] = (affected.ranges ?? []).map((range) => {
    const events = range.events ?? [];
    const pick = (key: string): string | null => {
      for (const event of events) {
        const value = event[key];
        if (typeof value === "string") return value;
      }
      return null;
    };
    return {
      type: asString(range.type) ?? "UNKNOWN",
      introduced: pick("introduced"),
      fixed: pick("fixed"),
      lastAffected: pick("last_affected"),
    };
  });

  /*
   * Which of the three matching shapes this report uses.
   *
   * The all-versions test comes FIRST, ahead of the explicit version list, and the order is
   * the point. Roughly nine thousand reports carry both, and where the range says "from
   * version 0 onwards" the package exists solely to carry a payload -- a typosquat, a
   * dependency-confusion stub. Its `versions` array is then just an inventory of what had
   * been published when somebody looked, and matching exactly against it would miss every
   * version the attacker pushed afterwards.
   */
  const allVersions =
    ranges.length > 0 &&
    ranges.some((r) => r.introduced === "0" && r.fixed === null && r.lastAffected === null);

  let matchMode: MaliciousMatchMode;
  if (allVersions) matchMode = "all_versions";
  else if (versions.length > 0) matchMode = "exact_versions";
  else if (ranges.length > 0) matchMode = "version_range";
  // No version information at all: the report names the package and nothing else, which is a
  // claim about the package rather than about a release of it.
  else matchMode = "all_versions";

  const sources = (doc.database_specific?.["malicious-packages-origins"] ?? [])
    .map((origin) => asString(origin.source))
    .filter((s): s is string => s !== null);

  const reference =
    doc.references?.find((r) => asString(r.url) !== null && r.type === "ADVISORY") ??
    doc.references?.find((r) => asString(r.url) !== null);

  return {
    id,
    ecosystem,
    packageName: rawName,
    normalizedName: normalizePackageName(ecosystem, rawName),
    summary: asString(doc.summary),
    details: asString(doc.details),
    matchMode,
    affectedVersions: matchMode === "exact_versions" ? versions : [],
    versionRanges: matchMode === "version_range" ? ranges : null,
    aliases: asStringArray(doc.aliases),
    sources: [...new Set(sources)],
    referenceUrl: reference ? asString(reference.url) : null,
    publishedAt: asDate(doc.published),
    modifiedAt: asDate(doc.modified),
    withdrawnAt: asDate(doc.withdrawn),
  };
}

export interface FeedUpdateResult {
  outcome: MaliciousFeedOutcome;
  message: string | null;
  reportsTotal: number | null;
  reportsChanged: number | null;
  reportsWithdrawn: number | null;
  feedBuiltAt: string | null;
}

export class MaliciousFeedService {
  /** Guards against two refreshes running at once in this process. */
  private running = false;

  constructor(
    private readonly deps: { db: Database; settings: SettingsService; logger: Logger },
  ) {}

  get isRefreshing(): boolean {
    return this.running;
  }

  /** Live reports installed, and the snapshot watermark. Null when nothing is installed. */
  async snapshot(): Promise<{ builtAt: Date | null; reportCount: number | null }> {
    const rows = await this.deps.db.execute<Row<{ built_at: Date | null; n: number }>>(sql`
      SELECT
        max(feed_built_at) AS built_at,
        (SELECT count(*)::int FROM malicious_package WHERE withdrawn_at IS NULL) AS n
      FROM malicious_feed_update
      WHERE outcome IN ('updated', 'unchanged')
    `);
    const row = rowsOf(rows)[0];
    if (!row?.built_at) return { builtAt: null, reportCount: null };
    return { builtAt: new Date(row.built_at), reportCount: Number(row.n) };
  }

  async history(limit: number): Promise<MaliciousFeedAttempt[]> {
    const rows = await this.deps.db.execute<Row<Record<string, unknown>>>(sql`
      SELECT id, started_at, finished_at, trigger, outcome, message, source_url,
             feed_built_at, reports_total, reports_changed, reports_withdrawn, actor_email
      FROM malicious_feed_update
      ORDER BY started_at DESC
      LIMIT ${limit}
    `);
    return rowsOf(rows).map(toAttempt);
  }

  async lastAttempt(): Promise<MaliciousFeedAttempt | null> {
    return (await this.history(1))[0] ?? null;
  }

  /** True when the configured interval has elapsed since the last successful refresh. */
  async isDue(): Promise<boolean> {
    const { intervalHours } = await this.deps.settings.getMaliciousSettings();
    const rows = await this.deps.db.execute<Row<{ due: boolean }>>(sql`
      SELECT COALESCE(
        max(started_at) < now() - make_interval(hours => ${Math.trunc(intervalHours)}),
        true
      ) AS due
      FROM malicious_feed_update
      WHERE outcome IN ('updated', 'unchanged')
    `);
    return rowsOf(rows)[0]?.due !== false;
  }

  /**
   * Fetch the feed and store it.
   *
   * Never throws for an operational failure. An unreachable host, a truncated download or a
   * malformed archive is recorded against the attempt and returned as an outcome, because
   * this runs on a timer with nothing to catch it and because an air-gapped install must be
   * able to see WHY its feed is stale rather than inferring it from an absence of findings.
   */
  async update(trigger: MaliciousFeedTrigger, actor: Actor | null): Promise<FeedUpdateResult> {
    if (this.running) {
      return {
        outcome: "failed",
        message: "A feed refresh is already running.",
        reportsTotal: null,
        reportsChanged: null,
        reportsWithdrawn: null,
        feedBuiltAt: null,
      };
    }

    const { feedUrl } = await this.deps.settings.getMaliciousSettings();
    this.running = true;
    const attemptId = await this.claim(trigger, feedUrl, actor);

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      let stream: Readable;
      try {
        const response = await fetch(feedUrl, { signal: controller.signal, redirect: "follow" });
        if (!response.ok || !response.body) {
          const result = this.failure("unreachable", `HTTP ${response.status} from ${feedUrl}`);
          await this.finish(attemptId, result);
          return result;
        }
        stream = Readable.fromWeb(response.body as never);
      } catch (err) {
        const result = this.failure(
          "unreachable",
          `Could not reach ${feedUrl}: ${err instanceof Error ? err.message : String(err)}`,
        );
        await this.finish(attemptId, result);
        return result;
      } finally {
        clearTimeout(timer);
      }

      const result = await this.ingest(stream);
      await this.finish(attemptId, result);
      return result;
    } catch (err) {
      const result = this.failure(
        "failed",
        err instanceof Error ? err.message : "Unknown error reading the feed",
      );
      await this.finish(attemptId, result);
      return result;
    } finally {
      this.running = false;
    }
  }

  /**
   * Install the feed from a local archive instead of the network.
   *
   * The air-gapped path, mirroring the vulnerability database's file import: somebody
   * downloads the same tarball on a connected machine and carries it in.
   */
  async importArchive(archivePath: string, actor: Actor | null): Promise<FeedUpdateResult> {
    if (this.running) {
      return {
        outcome: "failed",
        message: "A feed refresh is already running.",
        reportsTotal: null,
        reportsChanged: null,
        reportsWithdrawn: null,
        feedBuiltAt: null,
      };
    }
    this.running = true;
    const attemptId = await this.claim("import", archivePath, actor);
    try {
      const result = await this.ingest(createReadStream(archivePath));
      await this.finish(attemptId, result);
      return result;
    } catch (err) {
      const result = this.failure(
        "failed",
        err instanceof Error ? err.message : "Unknown error reading the archive",
      );
      await this.finish(attemptId, result);
      return result;
    } finally {
      this.running = false;
    }
  }

  /** Streams the archive, upserting as it goes so the whole feed is never held in memory. */
  private async ingest(source: Readable): Promise<FeedUpdateResult> {
    let total = 0;
    let changed = 0;
    let withdrawn = 0;
    let skippedEcosystem = 0;
    let unparseable = 0;
    let multiAffected = 0;
    let builtAt: Date | null = null;
    let batch: ParsedReport[] = [];

    const flush = async (): Promise<void> => {
      if (batch.length === 0) return;
      changed += await this.upsert(batch);
      batch = [];
    };

    for await (const entry of readTarGz(source)) {
      if (!entry.path.endsWith(".json")) continue;
      const parts = entry.path.split("/");
      // `<root>/osv/{malicious,withdrawn}/{ecosystem}/{package}/MAL-….json`
      if (parts[1] !== "osv" || (parts[2] !== "malicious" && parts[2] !== "withdrawn")) continue;

      let doc: OsvReport;
      try {
        doc = JSON.parse(entry.content.toString("utf8")) as OsvReport;
      } catch {
        unparseable += 1;
        continue;
      }

      if ((doc.affected?.length ?? 0) > 1) multiAffected += 1;

      const parsed = parseOsvReport(doc);
      if (parsed === null) {
        skippedEcosystem += 1;
        continue;
      }

      total += 1;
      if (parsed.withdrawnAt !== null) withdrawn += 1;
      if (parsed.modifiedAt && (builtAt === null || parsed.modifiedAt > builtAt)) {
        builtAt = parsed.modifiedAt;
      }

      batch.push(parsed);
      if (batch.length >= UPSERT_BATCH) await flush();
    }
    await flush();

    if (total === 0) {
      return this.failure("failed", "The archive contained no readable reports.");
    }

    if (multiAffected > 0) {
      // The one assumption in the parser, surfaced rather than trusted. See parseOsvReport.
      this.deps.logger.warn(
        { multiAffected },
        "malicious feed reports named more than one package; only the first was stored",
      );
    }

    /*
     * The watermark is the newest `modified` in the snapshot, not the wall clock.
     *
     * It decides which components need re-matching, so it has to describe the CONTENT. A
     * clock-based stamp would re-queue every component in the estate on every refresh, even
     * one that changed nothing.
     */
    const feedBuiltAt = builtAt ?? new Date();
    const notes = [
      skippedEcosystem > 0 ? `${skippedEcosystem} report(s) for ecosystems this platform does not scan` : null,
      unparseable > 0 ? `${unparseable} unreadable file(s)` : null,
    ].filter((n): n is string => n !== null);

    return {
      outcome: changed > 0 ? "updated" : "unchanged",
      message: notes.length > 0 ? `Skipped ${notes.join("; ")}.` : null,
      reportsTotal: total,
      reportsChanged: changed,
      reportsWithdrawn: withdrawn,
      feedBuiltAt: feedBuiltAt.toISOString(),
    };
  }

  /**
   * Upsert one batch, returning how many rows actually changed.
   *
   * Array columns are bound through `sql.param`, which is not optional styling. Interpolating
   * a JS array into a drizzle template expands it as a SQL value LIST -- `['a','b']` becomes
   * `($1, $2)` and an empty array becomes `()`, which is a syntax error. `sql.param` forces a
   * single bound parameter that the driver serialises as a real Postgres array.
   *
   * The `WHERE` on the conflict clause is what makes "changed" meaningful: without it every
   * refresh would report a quarter of a million updates and the outcome would always be
   * `updated`, which tells an administrator nothing.
   */
  private async upsert(batch: ParsedReport[]): Promise<number> {
    const values = batch.map(
      (r) => sql`(
        ${r.id}, ${r.ecosystem}, ${r.packageName}, ${r.normalizedName},
        ${r.summary}, ${r.details}, ${r.matchMode},
        ${sql.param(r.affectedVersions)}::text[], ${r.versionRanges === null ? null : JSON.stringify(r.versionRanges)}::jsonb,
        ${sql.param(r.aliases)}::text[], ${sql.param(r.sources)}::text[], ${r.referenceUrl},
        ${r.publishedAt?.toISOString() ?? null}::timestamptz,
        ${r.modifiedAt?.toISOString() ?? null}::timestamptz,
        ${r.withdrawnAt?.toISOString() ?? null}::timestamptz
      )`,
    );

    const result = await this.deps.db.execute<Row<{ id: string }>>(sql`
      INSERT INTO malicious_package (
        id, ecosystem, package_name, normalized_name, summary, details, match_mode,
        affected_versions, version_ranges, aliases, sources, reference_url,
        published_at, modified_at, withdrawn_at
      )
      VALUES ${sql.join(values, sql`, `)}
      ON CONFLICT (id) DO UPDATE SET
        ecosystem = excluded.ecosystem,
        package_name = excluded.package_name,
        normalized_name = excluded.normalized_name,
        summary = excluded.summary,
        details = excluded.details,
        match_mode = excluded.match_mode,
        affected_versions = excluded.affected_versions,
        version_ranges = excluded.version_ranges,
        aliases = excluded.aliases,
        sources = excluded.sources,
        reference_url = excluded.reference_url,
        published_at = excluded.published_at,
        modified_at = excluded.modified_at,
        withdrawn_at = excluded.withdrawn_at,
        updated_at = now()
      WHERE malicious_package.modified_at IS DISTINCT FROM excluded.modified_at
         OR malicious_package.withdrawn_at IS DISTINCT FROM excluded.withdrawn_at
         OR malicious_package.match_mode IS DISTINCT FROM excluded.match_mode
      RETURNING id
    `);
    return rowsOf(result).length;
  }

  private failure(outcome: MaliciousFeedOutcome, message: string): FeedUpdateResult {
    return {
      outcome,
      message,
      reportsTotal: null,
      reportsChanged: null,
      reportsWithdrawn: null,
      feedBuiltAt: null,
    };
  }

  private async claim(
    trigger: MaliciousFeedTrigger,
    sourceUrl: string,
    actor: Actor | null,
  ): Promise<string> {
    const rows = await this.deps.db.execute<Row<{ id: string }>>(sql`
      INSERT INTO malicious_feed_update (trigger, source_url, actor_user_id, actor_email)
      VALUES (${trigger}, ${sourceUrl}, ${actor?.id ?? null}::uuid, ${actor?.email ?? null})
      RETURNING id
    `);
    return rowsOf(rows)[0]!.id;
  }

  private async finish(id: string, result: FeedUpdateResult): Promise<void> {
    await this.deps.db.execute(sql`
      UPDATE malicious_feed_update SET
        finished_at = now(),
        outcome = ${result.outcome},
        message = ${result.message},
        feed_built_at = ${result.feedBuiltAt}::timestamptz,
        reports_total = ${result.reportsTotal},
        reports_changed = ${result.reportsChanged},
        reports_withdrawn = ${result.reportsWithdrawn}
      WHERE id = ${id}::uuid
    `);
  }

  /**
   * Clears the running flag left behind by a process that died mid-refresh.
   *
   * An attempt row with no `finished_at` after a restart describes a refresh nothing is
   * performing any more. Left alone it would make the admin page show a permanent spinner.
   */
  async reconcileInterrupted(): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ id: string }>>(sql`
      UPDATE malicious_feed_update
      SET finished_at = now(), outcome = 'failed',
          message = 'Interrupted: the server restarted while this refresh was running.'
      WHERE finished_at IS NULL
      RETURNING id
    `);
    return rowsOf(rows).length;
  }
}

function toAttempt(row: Record<string, unknown>): MaliciousFeedAttempt {
  return {
    id: String(row.id),
    startedAt: toIso(row.started_at as string)!,
    finishedAt: toIso(row.finished_at as string | null),
    trigger: String(row.trigger),
    outcome: (row.outcome as MaliciousFeedOutcome | null) ?? null,
    message: (row.message as string | null) ?? null,
    sourceUrl: (row.source_url as string | null) ?? null,
    feedBuiltAt: toIso(row.feed_built_at as string | null),
    reportsTotal: row.reports_total === null ? null : Number(row.reports_total),
    reportsChanged: row.reports_changed === null ? null : Number(row.reports_changed),
    reportsWithdrawn: row.reports_withdrawn === null ? null : Number(row.reports_withdrawn),
    actorEmail: (row.actor_email as string | null) ?? null,
  };
}
