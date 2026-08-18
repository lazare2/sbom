import { sql } from "drizzle-orm";
import { REPORT_SNAPSHOT_VERSION, type ReportSnapshot } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { SCOPE_GROUP_EXPR } from "../vulnerabilities/scope.js";
import { findingKey } from "./delta.js";

/**
 * Captures what the estate looks like right now, in the form the next report diffs against.
 *
 * Deliberately unfiltered by severity or scope. A snapshot is evidence rather than a view:
 * once written it is the only record of what was true, so a filter applied here would be
 * permanent and unrecoverable, and every question the report has not been asked yet would
 * become unanswerable. Filtering belongs in the renderer, which can be changed later.
 */
export class SnapshotService {
  constructor(private readonly deps: { db: Database }) {}

  async capture(): Promise<ReportSnapshot> {
    const { db } = this.deps;

    /*
      Inactive applications are included. They still exist, still carry findings, and the
      report needs to distinguish "this application was retired" from "this application was
      deleted" -- which is impossible if retirement removes it from the record.
    */
    const appRows = await db.execute<
      Row<{ id: string; name: string; status: string; last_scan_at: Date | null }>
    >(sql`
      SELECT a.id, a.name, a.status, a.last_scan_at
      FROM application a
      ORDER BY a.name
    `);

    const componentRows = await db.execute<
      Row<{
        id: number | string;
        name: string;
        version: string | null;
        ecosystem: string;
        kind: string;
        scope: string;
      }>
    >(sql`
      SELECT DISTINCT c.id, c.name, c.version, c.ecosystem, c.kind,
             ${SCOPE_GROUP_EXPR} AS scope
      FROM scan_component sc
      JOIN application a ON a.latest_scan_id = sc.scan_id
      JOIN component c ON c.id = sc.component_id
    `);

    const dependencyRows = await db.execute<
      Row<{ application_id: string; component_id: number | string }>
    >(sql`
      SELECT DISTINCT a.id AS application_id, sc.component_id
      FROM scan_component sc
      JOIN application a ON a.latest_scan_id = sc.scan_id
    `);

    /*
      Findings as they stand against the database installed right now. That is the whole
      reason this is stored: re-running this query next month answers with next month's
      database, so without a copy there is no way to tell a fix from a re-scored advisory.
    */
    const findingRows = await db.execute<
      Row<{ application_id: string; component_id: number | string; vulnerability_id: string; severity: string }>
    >(sql`
      SELECT DISTINCT a.id AS application_id, c.id AS component_id,
             v.id AS vulnerability_id, v.severity
      FROM component_vulnerability cv
      JOIN vulnerability v ON v.id = cv.vulnerability_id
      JOIN component c ON c.id = cv.component_id
      JOIN scan_component sc ON sc.component_id = c.id
      JOIN application a ON a.latest_scan_id = sc.scan_id
    `);

    const dbRow = await db.execute<Row<{ built_at: Date | null }>>(sql`
      SELECT db_built_at AS built_at
      FROM scan_vuln_summary
      ORDER BY db_built_at DESC NULLS LAST
      LIMIT 1
    `);

    const applications = rowsOf(appRows).map((r) => ({
      id: r.id,
      name: r.name,
      status: r.status,
      lastScanAt: r.last_scan_at ? new Date(r.last_scan_at).toISOString() : null,
    }));

    const components = rowsOf(componentRows).map((r) => ({
      id: Number(r.id),
      name: r.name,
      version: r.version,
      ecosystem: r.ecosystem,
      kind: r.kind,
      scope: r.scope === "os" ? ("os" as const) : ("app" as const),
    }));

    const dependencies: Record<string, number[]> = {};
    for (const row of rowsOf(dependencyRows)) {
      const list = dependencies[row.application_id] ?? [];
      list.push(Number(row.component_id));
      dependencies[row.application_id] = list;
    }
    // Sorted so two snapshots of an unchanged estate are byte-identical, which makes a
    // spurious diff impossible and the stored JSON compress better.
    for (const list of Object.values(dependencies)) list.sort((a, b) => a - b);

    const findings: string[] = [];
    const severities: Record<string, string> = {};
    const bySeverity: Record<string, number> = {};
    for (const row of rowsOf(findingRows)) {
      findings.push(findingKey(row.application_id, Number(row.component_id), row.vulnerability_id));
      severities[row.vulnerability_id] = row.severity;
      bySeverity[row.severity] = (bySeverity[row.severity] ?? 0) + 1;
    }
    findings.sort();

    const builtAt = rowsOf(dbRow)[0]?.built_at ?? null;

    return {
      version: REPORT_SNAPSHOT_VERSION,
      takenAt: new Date().toISOString(),
      vulnDbBuiltAt: builtAt ? new Date(builtAt).toISOString() : null,
      applications,
      components,
      dependencies,
      findings,
      severities,
      totals: {
        applications: applications.length,
        components: components.length,
        findings: findings.length,
        bySeverity,
      },
    };
  }
}
