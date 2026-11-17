import { sql } from "drizzle-orm";
import type { ProjectUrgencyCounts, TargetDates, VulnSeverity } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { PlanContext, PlanFinding } from "./action-plan.js";
import { AV_PATTERN } from "./attack-vector.js";
import { NOT_SUPPRESSED, SCOPE_GROUP_EXPR } from "./scope.js";

/**
 * The vulnerability data behind the developer view, read for many projects or for one.
 *
 * Both read the same rows as a project's vulnerability list - current build, every package,
 * accepted risks left out - so the status, the action plan and the list cannot disagree. The
 * urgency rules are `findingUrgency` in @sbom/shared; the SQL below is the same rule, and the
 * live check compares the two on every project.
 */

const FIXABLE = sql`cv.fix_state = 'fixed'`;
const REMOTE = sql`substring(upper(v.cvss_vector) from ${sql.raw(`'${AV_PATTERN}'`)}) = 'N'`;
const NOW = sql`(${FIXABLE} AND (v.known_exploited OR (v.severity = 'critical' AND ${REMOTE})))`;
const SOON = sql`(${FIXABLE} AND NOT ${NOW} AND v.severity IN ('critical', 'high'))`;

/**
 * When the vulnerability was first seen in this project: the later of when it was first found in
 * the package version and the project's first build containing that version. Over `cv`, `c`, `a`.
 * The (component_id, application_id) prefix of scan_component_search_idx answers the subquery.
 */
export const STARTED_AT = sql`greatest(cv.first_seen_at, (
  SELECT min(s2.created_at) FROM scan_component sc2 JOIN scan s2 ON s2.id = sc2.scan_id
   WHERE sc2.component_id = c.id AND sc2.application_id = a.id
))`;

/** Days allowed by the target-date rules (`targetFor` in @sbom/shared), or NULL for none. */
function targetDaysSql(t: TargetDates) {
  // LEAST ignores NULLs, and is NULL only when no rule applies.
  return sql`CASE WHEN NOT ${FIXABLE} THEN NULL ELSE LEAST(
    CASE WHEN v.known_exploited THEN ${t.usedInAttacksDays}::int END,
    CASE WHEN v.severity = 'critical' THEN ${t.criticalDays}::int END,
    CASE WHEN v.severity = 'high' THEN ${t.highDays}::int END
  ) END`;
}

/** Urgency counts per application, for the ids given (already access-checked by the caller). */
export async function urgencyCountsFor(
  db: Database,
  applicationIds: readonly string[],
  targets: TargetDates,
  /** Each project's previous visit by the caller, for "new since your last visit". */
  visits: ReadonlyMap<string, Date> = new Map(),
): Promise<Map<string, ProjectUrgencyCounts>> {
  const out = new Map<string, ProjectUrgencyCounts>();
  if (applicationIds.length === 0) return out;
  const ids = [...applicationIds];
  const since = ids.map((id) => visits.get(id)?.toISOString() ?? null);
  const days = targetDaysSql(targets);
  const rows = await db.execute<
    Row<{
      id: string;
      total: number | string;
      now: number | string;
      now_kev: number | string;
      soon: number | string;
      later: number | string;
      none: number | string;
      none_serious: number | string;
      late: number | string;
      new_since: number | string;
    }>
  >(sql`
    SELECT a.id,
           count(*)::int AS total,
           count(*) FILTER (WHERE ${NOW})::int AS now,
           count(*) FILTER (WHERE ${NOW} AND v.known_exploited)::int AS now_kev,
           count(*) FILTER (WHERE ${SOON})::int AS soon,
           count(*) FILTER (WHERE ${FIXABLE} AND NOT ${NOW} AND NOT ${SOON})::int AS later,
           count(*) FILTER (WHERE NOT ${FIXABLE})::int AS none,
           count(*) FILTER (WHERE NOT ${FIXABLE} AND v.severity IN ('critical', 'high'))::int AS none_serious,
           count(*) FILTER (WHERE ${STARTED_AT} + make_interval(days => ${days}) < now())::int AS late,
           count(*) FILTER (WHERE vis.since IS NOT NULL AND ${STARTED_AT} > vis.since)::int AS new_since
      FROM application a
      JOIN unnest(${sql.param(ids)}::uuid[], ${sql.param(since)}::timestamptz[]) AS vis(id, since) ON vis.id = a.id
      JOIN scan_component sc ON sc.scan_id = a.latest_scan_id
      JOIN component c ON c.id = sc.component_id
      JOIN component_vulnerability cv ON cv.component_id = c.id
      JOIN vulnerability v ON v.id = cv.vulnerability_id
     WHERE ${NOT_SUPPRESSED}
     GROUP BY a.id
  `);
  for (const r of rowsOf(rows)) {
    out.set(r.id, {
      total: Number(r.total),
      now: Number(r.now),
      nowUsedInAttacks: Number(r.now_kev),
      soon: Number(r.soon),
      later: Number(r.later),
      none: Number(r.none),
      noneSerious: Number(r.none_serious),
      late: Number(r.late),
      newSinceVisit: Number(r.new_since),
    });
  }
  return out;
}

/** The findings and build details one project's action plan is built from. */
export async function planInputFor(
  db: Database,
  applicationId: string,
): Promise<{ findings: PlanFinding[]; context: PlanContext; environmentId: string | null }> {
  const scans = await db.execute<
    Row<{ latest_scan_id: string | null; environment_id: string; os_pretty: string | null; os_name: string | null; os_version: string | null; image_ref: string | null }>
  >(sql`
    SELECT a.latest_scan_id, a.environment_id, s.os_pretty, s.os_name, s.os_version, s.image_ref
      FROM application a LEFT JOIN scan s ON s.id = a.latest_scan_id
     WHERE a.id = ${applicationId}::uuid
  `);
  const scan = rowsOf(scans)[0];
  if (!scan?.latest_scan_id) return { findings: [], context: { osPretty: null, imageRef: null }, environmentId: scan?.environment_id ?? null };

  const rows = await db.execute<
    Row<{
      component_id: number | string;
      name: string;
      version: string | null;
      ecosystem: string;
      purl: string | null;
      origin: string;
      vulnerability_id: string;
      severity: VulnSeverity;
      known_exploited: boolean;
      fix_state: string;
      fix_versions: string[] | null;
      cvss_vector: string | null;
      paths: string[] | null;
      pulled_in_by: string[] | null;
      started_at: string | Date;
    }>
  >(sql`
    SELECT c.id AS component_id, c.name, c.version, c.ecosystem, c.purl,
           ${SCOPE_GROUP_EXPR} AS origin,
           v.id AS vulnerability_id, v.severity, v.known_exploited, v.cvss_vector,
           cv.fix_state, cv.fix_versions, sc.paths, sc.pulled_in_by,
           ${STARTED_AT} AS started_at
      FROM application a
      JOIN scan_component sc ON sc.scan_id = a.latest_scan_id
      JOIN component c ON c.id = sc.component_id
      JOIN component_vulnerability cv ON cv.component_id = c.id
      JOIN vulnerability v ON v.id = cv.vulnerability_id
     WHERE a.id = ${applicationId}::uuid
       AND ${NOT_SUPPRESSED}
  `);
  return {
    findings: rowsOf(rows).map((r) => ({
      componentId: Number(r.component_id),
      name: r.name,
      version: r.version,
      ecosystem: r.ecosystem,
      purl: r.purl,
      origin: r.origin === "os" ? "os" : "app",
      vulnerabilityId: r.vulnerability_id,
      severity: r.severity,
      knownExploited: r.known_exploited === true,
      fixState: r.fix_state,
      fixVersions: r.fix_versions ?? [],
      cvssVector: r.cvss_vector,
      paths: r.paths ?? [],
      pulledInBy: r.pulled_in_by ?? [],
      startedAt: new Date(r.started_at).toISOString(),
    })),
    // The pretty name when the SBOM carried one, else "debian 12" from name and version.
    context: {
      osPretty: scan.os_pretty ?? (scan.os_name ? `${osLabel(scan.os_name)}${scan.os_version ? ` ${scan.os_version}` : ""}` : null),
      imageRef: scan.image_ref,
    },
    environmentId: scan.environment_id,
  };
}

/** "debian" -> "Debian", "rhel" -> "RHEL": the distribution id as people write it. */
function osLabel(id: string): string {
  if (id.length <= 4 && !/[aeiou]/i.test(id.slice(1))) return id.toUpperCase();
  return id.charAt(0).toUpperCase() + id.slice(1);
}
