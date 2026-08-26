import { and, desc, eq, inArray, sql } from "drizzle-orm";
import type {
  IngestSastRequest,
  IngestSastResponse,
  SastFinding,
  SastRunListEntry,
  SastRunSummary,
  SastSeverityCounts,
} from "@sbom/shared";
import { emptySastSeverityCounts } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { application, sastFinding, sastRun } from "../../db/schema.js";
import type { SastRunRow } from "../../db/schema.js";
import { NotFoundError } from "../../lib/errors.js";
import type { EnvironmentScope } from "../environments/environment.service.js";

export interface SastServiceDeps {
  db: Database;
}

/**
 * SAST runs and findings — see the "Static analysis (SAST)" section of the
 * schema for why this is not a mode of the vulnerability tables above it.
 *
 * Deliberately narrow next to `IngestionService`: there is no auto-create, no
 * alias redirect, and no concurrent-insert race to guard against. An unknown
 * `app_name` is a 404, not a new `pending_confirmation` application — sast-scan
 * runs against source a developer already checked out, so "an application
 * named this doesn't exist yet" is far more likely a typo in `SAST_APP_NAME`
 * than a repo nobody has registered.
 */
export class SastService {
  private readonly deps: SastServiceDeps;

  constructor(deps: SastServiceDeps) {
    this.deps = deps;
  }

  /**
   * Resolve `app_name` (case-insensitive) to an application within one estate.
   *
   * Application names are unique per environment, not globally (see the
   * `application_name_lower_uniq` index), so the estate the token/request
   * resolved to is part of the lookup, not an afterthought.
   */
  async ingest(
    input: IngestSastRequest,
    scope: EnvironmentScope,
    tokenName: string,
  ): Promise<IngestSastResponse> {
    const { db } = this.deps;

    const [app] = await db
      .select({ id: application.id, name: application.name })
      .from(application)
      .where(and(eq(application.environmentId, scope.id), sql`lower(${application.name}) = lower(${input.app_name})`))
      .limit(1);

    if (!app) {
      throw new NotFoundError(
        `No application named "${input.app_name}" in "${scope.name}". ` +
          "Create it first (or upload an SBOM for it) — unlike the SBOM ingest endpoint, " +
          "a SAST run never auto-creates one.",
      );
    }

    const counts = emptySastSeverityCounts();
    for (const f of input.findings) counts[f.severity] += 1;
    const highOrCritical = counts.high + counts.critical;

    const runId = await db.transaction(async (tx) => {
      const [run] = await tx
        .insert(sastRun)
        .values({
          applicationId: app.id,
          environmentId: scope.id,
          commitSha: input.commit_sha ?? null,
          branch: input.branch ?? null,
          ingestTokenName: tokenName,
          findingCount: input.findings.length,
          highOrCriticalCount: highOrCritical,
        })
        .returning({ id: sastRun.id });
      if (!run) throw new Error("failed to insert sast_run row");

      if (input.findings.length > 0) {
        await tx.insert(sastFinding).values(
          input.findings.map((f) => ({
            runId: run.id,
            ruleId: f.rule_id,
            severity: f.severity,
            category: f.category,
            cwe: f.cwe,
            message: f.message,
            remediation: f.remediation,
            file: f.file,
            line: f.line,
            col: f.col,
          })),
        );
      }

      return run.id;
    });

    return {
      runId,
      applicationId: app.id,
      applicationName: app.name,
      findingCount: input.findings.length,
      severityCounts: counts,
    };
  }

  /**
   * The most recent run for an application, with its findings inline, or
   * `null` if nothing has ever been ingested for it.
   *
   * Takes a bare `applicationId` rather than an `EnvironmentAccess` — callers
   * confirm the application is visible to the caller first (typically via
   * `applications.getById`, the same pattern `/scans/:id/components` uses),
   * so this stays a plain lookup rather than a second access check.
   */
  async getLatestForApplication(applicationId: string): Promise<SastRunSummary | null> {
    const { db } = this.deps;

    const [run] = await db
      .select()
      .from(sastRun)
      .where(eq(sastRun.applicationId, applicationId))
      .orderBy(desc(sastRun.createdAt))
      .limit(1);

    if (!run) return null;
    return this.summaryOf(run);
  }

  /**
   * One specific run of an application, by id.
   *
   * Scoped to the application rather than looked up by run id alone: the
   * caller has already been authorised for the application, and a bare run-id
   * lookup would let that authorisation be spent on a run belonging to a
   * different one.
   */
  async getRun(applicationId: string, runId: string): Promise<SastRunSummary | null> {
    const { db } = this.deps;

    const [run] = await db
      .select()
      .from(sastRun)
      .where(and(eq(sastRun.applicationId, applicationId), eq(sastRun.id, runId)))
      .limit(1);

    if (!run) return null;
    return this.summaryOf(run);
  }

  /**
   * An application's run history, newest first.
   *
   * Header rows only — no findings — so this stays one query no matter how
   * many runs are retained. Severity counts come from the denormalised columns
   * on `sast_run` rather than a per-run aggregate over `sast_finding`, which
   * is the reason those columns exist.
   */
  async listRuns(applicationId: string, limit = 30): Promise<SastRunListEntry[]> {
    const { db } = this.deps;

    const runs = await db
      .select()
      .from(sastRun)
      .where(eq(sastRun.applicationId, applicationId))
      .orderBy(desc(sastRun.createdAt))
      .limit(limit);

    if (runs.length === 0) return [];

    /*
     * Per-severity counts for the listed runs in one grouped query rather than
     * one query per run. `sast_run` denormalises the total and the
     * high-or-critical total, but not the full breakdown, and a history table
     * that shows a severity bar needs all four.
     */
    const runIds = runs.map((r) => r.id);
    const breakdown = await db
      .select({
        runId: sastFinding.runId,
        severity: sastFinding.severity,
        count: sql<number>`count(*)::int`,
      })
      .from(sastFinding)
      .where(inArray(sastFinding.runId, runIds))
      .groupBy(sastFinding.runId, sastFinding.severity);

    const countsByRun = new Map<string, SastSeverityCounts>();
    for (const row of breakdown) {
      const counts = countsByRun.get(row.runId) ?? emptySastSeverityCounts();
      counts[row.severity] = row.count;
      countsByRun.set(row.runId, counts);
    }

    return runs.map((run, index) => ({
      runId: run.id,
      commitSha: run.commitSha,
      branch: run.branch,
      createdAt: run.createdAt.toISOString(),
      findingCount: run.findingCount,
      severityCounts: countsByRun.get(run.id) ?? emptySastSeverityCounts(),
      // The list is ordered newest-first and unfiltered, so the first row is
      // the run the tab shows by default.
      isLatest: index === 0,
    }));
  }

  /** Shared by `getLatestForApplication` and `getRun`: a run row plus its findings. */
  private async summaryOf(run: SastRunRow): Promise<SastRunSummary> {
    const { db } = this.deps;

    const findingRows = await db
      .select()
      .from(sastFinding)
      .where(eq(sastFinding.runId, run.id))
      .orderBy(sastFinding.file, sastFinding.line);

    const severityCounts: SastSeverityCounts = emptySastSeverityCounts();
    const findings: SastFinding[] = findingRows.map((row) => {
      severityCounts[row.severity] += 1;
      return {
        id: row.id,
        ruleId: row.ruleId,
        severity: row.severity,
        category: row.category,
        cwe: row.cwe,
        message: row.message,
        remediation: row.remediation,
        file: row.file,
        line: row.line,
        col: row.col,
      };
    });

    return {
      runId: run.id,
      applicationId: run.applicationId,
      commitSha: run.commitSha,
      branch: run.branch,
      createdAt: run.createdAt.toISOString(),
      findingCount: findings.length,
      severityCounts,
      findings,
    };
  }
}
