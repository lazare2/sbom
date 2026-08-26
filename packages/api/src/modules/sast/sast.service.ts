import { and, desc, eq, sql } from "drizzle-orm";
import type {
  IngestSastRequest,
  IngestSastResponse,
  SastFinding,
  SastRunSummary,
  SastSeverityCounts,
} from "@sbom/shared";
import { emptySastSeverityCounts } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { application, sastFinding, sastRun } from "../../db/schema.js";
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
            cwe: f.cwe,
            message: f.message,
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
        cwe: row.cwe,
        message: row.message,
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
