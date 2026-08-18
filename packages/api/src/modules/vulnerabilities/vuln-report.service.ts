import { sql, type SQL } from "drizzle-orm";
import {
  EXPANDABLE_LIST_CAP,
  scopeIncludes,
  severitiesForBuckets,
  vulnSeverities,
  type SeverityCounts,
  type TopVulnerableApplication,
  type TopVulnerablePackage,
  type VulnerabilityReport,
  type VulnFilterState,
  type VulnScopeTotals,
  type VulnSeverity,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import { SCOPE_GROUP_EXPR, scopePredicate, severityBucketPredicate } from "./scope.js";

/**
 * Estate-wide vulnerability posture, filtered.
 *
 * Lives apart from `AnalyticsService` because it answers a different kind of question:
 * everything there counts SBOM contents, everything here counts what Grype matched
 * against them. Keeping it next to `scope.ts` also keeps the app/base-image split and the
 * queries that depend on it in the same directory.
 *
 * ## Where each figure comes from
 *
 * Two sources, and each figure has exactly one of them — never a fast estimate and a slow
 * exact version of the same number, because the first time those disagreed nobody would
 * be able to say which was right.
 *
 *   Severity counts, applicationsAffected, base-image exposure
 *     From `scan_vuln_summary.counts`, one jsonb row per application. It already holds
 *     all six severities for both halves of the split, so a severity filter over estate
 *     totals is arithmetic over one row per application rather than a join across
 *     millions of findings.
 *
 *   fixable, knownExploited, affectedPackages
 *     From the findings tables, because the snapshot stores them as flat scalars that are
 *     not severity-split. Under a severity filter a snapshot value would describe all
 *     severities while the count beside it described four — two numbers on one row that
 *     do not belong to each other. This query runs unconditionally, filter or not: the
 *     estate has always needed it for `affectedPackages` (a package in forty services is
 *     one affected package, not forty, so it cannot be summed from per-scan rows), and
 *     adding two counters to a join that was already happening costs nothing.
 *
 * ## What the filter does not do
 *
 * It never changes the rule that rankings are computed on one half of the split rather
 * than the sum. Measured on a realistic container SBOM, base-image packages were 2,817 of
 * 2,845 findings; a combined ranking is a base-image-age ranking whatever its heading
 * says. So the rankings follow `rankedScope` — application dependencies, unless the
 * filter asks for base image alone, in which case there is no application half left to
 * rank. Every per-row count describes that same half.
 *
 * ## Consistency with the snapshots
 *
 * Every query is restricted to applications that have a `scan_vuln_summary` row, which
 * the sweep only writes once every component in that scan has been matched. Without that
 * restriction the findings-side figures would include half-matched builds while the
 * snapshot-side ones did not, and the two would drift apart on exactly the estates where
 * it matters — the ones in the middle of a sweep.
 */

/** Every severity, for the unfiltered reference figures. */
const ALL_SEVERITIES: readonly VulnSeverity[] = vulnSeverities;

/**
 * Suppression exclusion, matching the sweep's own.
 *
 * Assumes `v` (vulnerability), `c` (component) and `a` (application) are in scope. Copied
 * in shape from `refreshScanSummaries` deliberately: if these two ever disagreed, an
 * accepted risk would be excluded from the snapshot figures and included in the
 * findings-side ones, and the report would contradict itself within a single panel.
 */
const NOT_SUPPRESSED: SQL = sql`NOT EXISTS (
  SELECT 1 FROM vulnerability_suppression sup
  WHERE sup.vulnerability_id = v.id
    AND (sup.expires_at IS NULL OR sup.expires_at > now())
    AND (sup.component_id IS NULL OR sup.component_id = c.id)
    AND (sup.application_id IS NULL OR sup.application_id = a.id)
)`;

/**
 * Sums selected severities out of one half of the snapshot's jsonb breakdown.
 *
 * The severity names are bound as parameters rather than interpolated. They arrive from a
 * validated enum so injection is not the live risk, but a query built by string
 * concatenation invites the next person to pass something less trustworthy through it.
 */
function jsonbSeveritySum(group: "app" | "os", severities: readonly VulnSeverity[]): SQL {
  if (severities.length === 0) return sql`0`;
  const key = group === "app" ? sql`'app'` : sql`'os'`;
  return sql.join(
    severities.map((severity) => sql`COALESCE((vs.counts->${key}->>${severity}::text)::int, 0)`),
    sql` + `,
  );
}

interface SnapshotRow {
  db_built_at: Date | string | null;
  apps_scanned: number | string;
  apps_pending: number | string;
  apps_affected: number | string;
}

interface TopApplicationRow {
  application_id: string;
  name: string;
  status: string;
  db_built_at: Date | string | null;
  app_findings: number | string;
  os_findings: number | string;
  ranked_critical: number | string;
  ranked_high: number | string;
  ranked_fixable: number | string;
  ranked_kev: number | string;
  ranked_packages: number | string;
}

export class VulnReportService {
  constructor(private readonly deps: { db: Database }) {}

  async report(filter: VulnFilterState, limit: number): Promise<VulnerabilityReport> {
    /*
     * With base image selected alone there is no application half to rank, so the
     * rankings switch to it. With anything else — including "all packages" — they stay on
     * application dependencies, for the reason in the class comment.
     */
    const rankedScope: "app" | "os" = filter.scope === "os" ? "os" : "app";

    const [meta, counts, findingSide, topVulnerableApplications, topVulnerablePackages, exposure] =
      await Promise.all([
        this.snapshotMeta(filter),
        this.severityCounts(filter),
        this.findingTotals(filter),
        this.topApplications(filter, rankedScope, limit),
        this.topPackages(filter, rankedScope, limit),
        scopeIncludes(filter.scope, "os") ? this.baseImageExposure(filter) : Promise.resolve(null),
      ]);

    const builtAt = meta.dbBuiltAt;
    const scopeTotals = (group: "app" | "os"): VulnScopeTotals | null =>
      scopeIncludes(filter.scope, group)
        ? {
            counts: counts.filtered[group],
            fixable: findingSide[group].fixable,
            knownExploited: findingSide[group].knownExploited,
            affectedPackages: findingSide[group].affectedPackages,
          }
        : null;

    return {
      dbBuiltAt: builtAt,
      dbAgeHours:
        builtAt === null
          ? null
          : Math.round(((Date.now() - new Date(builtAt).getTime()) / 3_600_000) * 10) / 10,
      applicationsScanned: meta.applicationsScanned,
      applicationsPending: meta.applicationsPending,
      filter,
      app: scopeTotals("app"),
      baseImage: scopeTotals("os"),
      applicationsAffected: meta.applicationsAffected,
      topVulnerableApplications,
      topVulnerablePackages,
      baseImageExposure: exposure,
      /*
       * Only when something was narrowed. Carrying it unconditionally would duplicate the
       * figures above and invite a reader to compare a number with itself.
       */
      unfiltered: filter.active
        ? { app: counts.unfiltered.app, baseImage: counts.unfiltered.os }
        : null,
    };
  }

  /**
   * Coverage and provenance, plus how many applications the filter actually reaches.
   *
   * `applicationsPending` is the honest qualifier on everything else: a partially swept
   * estate's totals are a floor, and a catch-up in progress would otherwise read as an
   * improvement in exposure.
   */
  private async snapshotMeta(filter: VulnFilterState): Promise<{
    dbBuiltAt: string | null;
    applicationsScanned: number;
    applicationsPending: number;
    applicationsAffected: number;
  }> {
    const severities = severitiesForBuckets(filter.severities);
    /*
     * "Reached by the filter" means at least one finding in a selected severity, on a
     * selected side of the split. Summing only the in-scope halves is what makes the
     * figure mean the same thing under every filter.
     */
    const inScope = sql.join(
      [
        ...(scopeIncludes(filter.scope, "app") ? [jsonbSeveritySum("app", severities)] : []),
        ...(scopeIncludes(filter.scope, "os") ? [jsonbSeveritySum("os", severities)] : []),
      ],
      sql` + `,
    );

    const rows = await this.deps.db.execute<Row<SnapshotRow>>(sql`
      WITH current_summaries AS (
        SELECT vs.*
        FROM scan_vuln_summary vs
        JOIN application a ON a.latest_scan_id = vs.scan_id
        WHERE a.status <> 'inactive'
      )
      SELECT
        (SELECT max(db_built_at) FROM current_summaries) AS db_built_at,
        (SELECT count(*) FROM current_summaries)::int AS apps_scanned,
        (SELECT count(*) FROM application a
          WHERE a.status <> 'inactive' AND a.latest_scan_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM scan_vuln_summary vs WHERE vs.scan_id = a.latest_scan_id)
        )::int AS apps_pending,
        (SELECT count(*) FROM current_summaries vs WHERE (${inScope}) > 0)::int AS apps_affected
    `);

    const row = rowsOf(rows)[0];
    return {
      dbBuiltAt: toIso(row?.db_built_at ?? null),
      applicationsScanned: Number(row?.apps_scanned ?? 0),
      applicationsPending: Number(row?.apps_pending ?? 0),
      applicationsAffected: Number(row?.apps_affected ?? 0),
    };
  }

  /**
   * Severity totals for both halves, filtered and unfiltered, in one pass.
   *
   * Both come from the same rows, so the filtered figures and the reference figures they
   * are compared against cannot be computed over different populations.
   */
  private async severityCounts(filter: VulnFilterState): Promise<{
    filtered: { app: SeverityCounts; os: SeverityCounts };
    unfiltered: { app: SeverityCounts; os: SeverityCounts };
  }> {
    const selected = new Set(severitiesForBuckets(filter.severities));

    const columns = (["app", "os"] as const).flatMap((group) =>
      ALL_SEVERITIES.map(
        (severity) =>
          sql`COALESCE(sum(${jsonbSeveritySum(group, [severity])}), 0)::int AS ${sql.identifier(
            `${group}_${severity}`,
          )}`,
      ),
    );

    const rows = await this.deps.db.execute<Row<Record<string, number | string>>>(sql`
      SELECT ${sql.join(columns, sql`, `)}
      FROM scan_vuln_summary vs
      JOIN application a ON a.latest_scan_id = vs.scan_id
      WHERE a.status <> 'inactive'
    `);

    const row = rowsOf(rows)[0] ?? {};
    const read = (group: "app" | "os", onlySelected: boolean): SeverityCounts => {
      const counts = {} as Record<VulnSeverity, number>;
      for (const severity of ALL_SEVERITIES) {
        counts[severity] =
          onlySelected && !selected.has(severity)
            ? 0
            : Number(row[`${group}_${severity}`] ?? 0);
      }
      return counts;
    };

    return {
      filtered: { app: read("app", true), os: read("os", true) },
      unfiltered: { app: read("app", false), os: read("os", false) },
    };
  }

  /**
   * Fix availability, known-exploited status and distinct affected packages.
   *
   * From the findings tables, for the reason in the class comment. Both halves come back
   * regardless of the scope filter — the extra `FILTER` clauses are free once the join has
   * been paid for, and computing them together means the two halves are always counted
   * over one population.
   */
  private async findingTotals(filter: VulnFilterState): Promise<
    Record<"app" | "os", { fixable: number; knownExploited: number; affectedPackages: number }>
  > {
    const rows = await this.deps.db.execute<
      Row<{
        scope_group: string;
        fixable: number | string;
        known_exploited: number | string;
        affected_packages: number | string;
      }>
    >(sql`
      SELECT
        ${SCOPE_GROUP_EXPR} AS scope_group,
        count(*) FILTER (WHERE cv.fix_state = 'fixed')::int AS fixable,
        count(*) FILTER (WHERE v.known_exploited)::int AS known_exploited,
        count(DISTINCT c.id)::int AS affected_packages
      FROM application a
      JOIN scan_vuln_summary vs ON vs.scan_id = a.latest_scan_id
      JOIN scan_component sc ON sc.scan_id = vs.scan_id
      JOIN component c ON c.id = sc.component_id
      JOIN component_vulnerability cv ON cv.component_id = c.id
      JOIN vulnerability v ON v.id = cv.vulnerability_id
      WHERE a.status <> 'inactive'
        AND ${severityBucketPredicate(filter.severities)}
        AND ${NOT_SUPPRESSED}
      GROUP BY 1
    `);

    const empty = { fixable: 0, knownExploited: 0, affectedPackages: 0 };
    const out: Record<"app" | "os", typeof empty> = { app: { ...empty }, os: { ...empty } };
    for (const row of rowsOf(rows)) {
      const group = row.scope_group === "os" ? "os" : "app";
      out[group] = {
        fixable: Number(row.fixable),
        knownExploited: Number(row.known_exploited),
        affectedPackages: Number(row.affected_packages),
      };
    }
    return out;
  }

  /**
   * Top vulnerable applications.
   *
   * Two paths producing identical row shapes. With no severity filter the per-scan
   * snapshot already holds every figure a row needs, which is one indexed row per
   * application. With a severity filter it does not — the snapshot's `fixable` and
   * `known_exploited` are not severity-split — so the ranking is computed over the
   * findings themselves. Slower, and correct: a row where the findings count is filtered
   * and the fixable count beside it is not would be worse than a slow page.
   */
  private async topApplications(
    filter: VulnFilterState,
    rankedScope: "app" | "os",
    limit: number,
  ): Promise<TopVulnerableApplication[]> {
    const rows =
      filter.severities.length === 0
        ? await this.topApplicationsFromSnapshot(rankedScope, limit)
        : await this.topApplicationsFromFindings(filter, rankedScope, limit);

    return rows.map((row) => ({
      applicationId: row.application_id,
      name: row.name,
      status: row.status,
      /*
       * Null, not zero, for a half the filter excluded. The merged "app / base image"
       * column renders null as an em dash: "not counted" and "counted, found none" are
       * different answers and a dash is the only one of the two that reads as neither.
       */
      findings: scopeIncludes(filter.scope, "app") ? Number(row.app_findings) : null,
      baseImageFindings: scopeIncludes(filter.scope, "os") ? Number(row.os_findings) : null,
      rankedBy: rankedScope,
      critical: Number(row.ranked_critical),
      high: Number(row.ranked_high),
      fixable: Number(row.ranked_fixable),
      knownExploited: Number(row.ranked_kev),
      affectedPackages: Number(row.ranked_packages),
      dbBuiltAt: toIso(row.db_built_at),
    }));
  }

  private async topApplicationsFromSnapshot(
    rankedScope: "app" | "os",
    limit: number,
  ): Promise<TopApplicationRow[]> {
    // Column set for the ranked half. The snapshot is symmetric, so this is a choice of
    // prefix rather than two separate queries.
    const ranked =
      rankedScope === "app"
        ? {
            findings: sql`vs.app_findings`,
            critical: sql`vs.app_critical`,
            high: sql`vs.app_high`,
            fixable: sql`vs.app_fixable`,
            kev: sql`vs.app_known_exploited`,
            packages: sql`vs.app_affected_packages`,
          }
        : {
            findings: sql`vs.os_findings`,
            critical: sql`vs.os_critical`,
            high: sql`vs.os_high`,
            fixable: sql`vs.os_fixable`,
            kev: sql`vs.os_known_exploited`,
            packages: sql`vs.os_affected_packages`,
          };

    const rows = await this.deps.db.execute<Row<TopApplicationRow>>(sql`
      SELECT
        a.id AS application_id, a.name, a.status, vs.db_built_at,
        vs.app_findings, vs.os_findings,
        ${ranked.critical} AS ranked_critical,
        ${ranked.high} AS ranked_high,
        ${ranked.fixable} AS ranked_fixable,
        ${ranked.kev} AS ranked_kev,
        ${ranked.packages} AS ranked_packages
      FROM scan_vuln_summary vs
      JOIN application a ON a.latest_scan_id = vs.scan_id
      WHERE a.status <> 'inactive' AND ${ranked.findings} > 0
      ORDER BY ${ranked.findings} DESC, ${ranked.critical} DESC, a.name ASC
      LIMIT ${limit}
    `);
    return rowsOf(rows);
  }

  private async topApplicationsFromFindings(
    filter: VulnFilterState,
    rankedScope: "app" | "os",
    limit: number,
  ): Promise<TopApplicationRow[]> {
    const rows = await this.deps.db.execute<Row<TopApplicationRow>>(sql`
      WITH matched AS (
        SELECT
          a.id AS application_id, a.name, a.status, vs.db_built_at,
          ${SCOPE_GROUP_EXPR} AS scope_group,
          c.id AS component_id, v.known_exploited, v.severity, cv.fix_state
        FROM application a
        JOIN scan_vuln_summary vs ON vs.scan_id = a.latest_scan_id
        JOIN scan_component sc ON sc.scan_id = vs.scan_id
        JOIN component c ON c.id = sc.component_id
        JOIN component_vulnerability cv ON cv.component_id = c.id
        JOIN vulnerability v ON v.id = cv.vulnerability_id
        WHERE a.status <> 'inactive'
          AND ${severityBucketPredicate(filter.severities)}
          AND ${NOT_SUPPRESSED}
      )
      SELECT
        application_id, name, status, db_built_at,
        count(*) FILTER (WHERE scope_group = 'app')::int AS app_findings,
        count(*) FILTER (WHERE scope_group = 'os')::int AS os_findings,
        count(*) FILTER (WHERE scope_group = ${rankedScope})::int AS ranked_findings,
        count(*) FILTER (WHERE scope_group = ${rankedScope} AND severity = 'critical')::int AS ranked_critical,
        count(*) FILTER (WHERE scope_group = ${rankedScope} AND severity = 'high')::int AS ranked_high,
        count(*) FILTER (WHERE scope_group = ${rankedScope} AND fix_state = 'fixed')::int AS ranked_fixable,
        count(*) FILTER (WHERE scope_group = ${rankedScope} AND known_exploited)::int AS ranked_kev,
        count(DISTINCT component_id) FILTER (WHERE scope_group = ${rankedScope})::int AS ranked_packages
      FROM matched
      GROUP BY application_id, name, status, db_built_at
      HAVING count(*) FILTER (WHERE scope_group = ${rankedScope}) > 0
      ORDER BY ranked_findings DESC, ranked_critical DESC, name ASC
      LIMIT ${limit}
    `);
    return rowsOf(rows);
  }

  /**
   * Top vulnerable packages in current use.
   *
   * "In use now" is what makes the list actionable: a package version no application
   * still ships is history, not work. Restricted to the ranked half rather than the
   * filter's full scope — with both halves in one list, distribution packages would take
   * every row and the ranking would stop naming anything a team can act on.
   */
  private async topPackages(
    filter: VulnFilterState,
    rankedScope: "app" | "os",
    limit: number,
  ): Promise<TopVulnerablePackage[]> {
    const rows = await this.deps.db.execute<
      Row<{
        component_id: number | string;
        name: string;
        version: string | null;
        ecosystem: string;
        base_image: boolean;
        findings: number | string;
        critical: number | string;
        high: number | string;
        kev: number | string;
        applications: number | string;
        application_list: string[] | null;
        fix_available: boolean;
        fix_versions: string[] | null;
      }>
    >(sql`
      SELECT
        c.id AS component_id, c.name, c.version, c.ecosystem,
        ${SCOPE_GROUP_EXPR} = 'os' AS base_image,
        count(DISTINCT v.id)::int AS findings,
        count(DISTINCT v.id) FILTER (WHERE v.severity = 'critical')::int AS critical,
        count(DISTINCT v.id) FILTER (WHERE v.severity = 'high')::int AS high,
        count(DISTINCT v.id) FILTER (WHERE v.known_exploited)::int AS kev,
        count(DISTINCT a.id)::int AS applications,
        -- Same joins, same WHERE, same grouping as the count directly above, so the
        -- expandable list on the row cannot disagree with the number it opens from.
        (array_agg(DISTINCT a.name ORDER BY a.name))[1:${sql.raw(String(EXPANDABLE_LIST_CAP))}] AS application_list,
        bool_or(cv.fix_state = 'fixed') AS fix_available,
        array_remove(array_agg(DISTINCT fv), NULL) AS fix_versions
      FROM component_vulnerability cv
      JOIN vulnerability v ON v.id = cv.vulnerability_id
      JOIN component c ON c.id = cv.component_id
      JOIN scan_component sc ON sc.component_id = c.id
      JOIN scan_vuln_summary vs ON vs.scan_id = sc.scan_id
      JOIN application a ON a.latest_scan_id = sc.scan_id
      LEFT JOIN LATERAL unnest(cv.fix_versions) AS fv ON TRUE
      WHERE a.status <> 'inactive'
        AND ${scopePredicate(rankedScope)}
        AND ${severityBucketPredicate(filter.severities)}
        AND ${NOT_SUPPRESSED}
      GROUP BY c.id, c.name, c.version, c.ecosystem, c.kind
      ORDER BY findings DESC, critical DESC, applications DESC, lower(c.name) ASC
      LIMIT ${limit}
    `);

    return rowsOf(rows).map((row) => ({
      componentId: Number(row.component_id),
      name: row.name,
      version: row.version,
      ecosystem: row.ecosystem,
      applicationList: row.application_list ?? [],
      baseImage: row.base_image === true,
      findings: Number(row.findings),
      critical: Number(row.critical),
      high: Number(row.high),
      knownExploited: Number(row.kev),
      applications: Number(row.applications),
      fixAvailable: row.fix_available === true,
      fixVersions: (row.fix_versions ?? []).slice(0, 5),
    }));
  }

  /**
   * Base-image exposure, grouped by distribution.
   *
   * The separate home for the 99% of findings that come from base packages. Grouped by
   * image rather than by application because that is the actionable unit: twelve services
   * on Debian 11 are one base-image upgrade, not twelve pieces of work.
   *
   * Read from the jsonb breakdown rather than the snapshot's integer columns so it can
   * follow a severity filter — the integer columns only carry critical and high.
   */
  private async baseImageExposure(
    filter: VulnFilterState,
  ): Promise<NonNullable<VulnerabilityReport["baseImageExposure"]>> {
    const severities = severitiesForBuckets(filter.severities);
    const selected = jsonbSeveritySum("os", severities);
    const critical = jsonbSeveritySum("os", severities.includes("critical") ? ["critical"] : []);
    const high = jsonbSeveritySum("os", severities.includes("high") ? ["high"] : []);

    const rows = await this.deps.db.execute<
      Row<{
        os_name: string | null;
        os_version: string | null;
        applications: number | string;
        findings: number | string;
        critical: number | string;
        high: number | string;
      }>
    >(sql`
      SELECT
        s.os_name, s.os_version,
        count(DISTINCT a.id)::int AS applications,
        COALESCE(sum(${selected}), 0)::int AS findings,
        COALESCE(sum(${critical}), 0)::int AS critical,
        COALESCE(sum(${high}), 0)::int AS high
      FROM application a
      JOIN scan s ON s.id = a.latest_scan_id
      JOIN scan_vuln_summary vs ON vs.scan_id = s.id
      WHERE a.status <> 'inactive'
      GROUP BY s.os_name, s.os_version
      HAVING COALESCE(sum(${selected}), 0) > 0
      ORDER BY findings DESC, applications DESC
      LIMIT 20
    `);

    return rowsOf(rows).map((row) => ({
      osName: row.os_name,
      osVersion: row.os_version,
      applications: Number(row.applications),
      findings: Number(row.findings),
      critical: Number(row.critical),
      high: Number(row.high),
    }));
  }
}
