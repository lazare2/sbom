import { sql, type SQL } from "drizzle-orm";
import {
  EXPANDABLE_LIST_CAP,
  type AnalyticsReport,
  type AttentionPackage,
  type AttentionSettings,
  type BuildDeltaPair,
  type FragmentationTrend,
  type ProjectProgress,
  type TeamFilter,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { ReadScope } from "../environments/environment.service.js";
import { filteredApplications } from "../inventory/team-filter.js";
import { APP_DEPENDENCY_PREDICATE, BASE_IMAGE_PREDICATE, NOT_SUPPRESSED } from "../vulnerabilities/scope.js";
import {
  attentionProjects,
  baselineBuild,
  buildCadence,
  buildDeltaSection,
  buildPairs,
  projectBuildDeltas,
  rollup,
  windowMovement,
  zeroPair,
  type BuildFact,
  type BuildPair,
  type CurrentRiskFacts,
} from "./progress.js";

/**
 * How many builds before the window are fetched per project.
 *
 * Enough to find the baseline and the previous distinct build behind a short run of identical
 * rebuilds, without reading a project's whole history. A longer run of byte-identical rebuilds
 * just before the window would leave its first in-window build unpaired, which costs one
 * comparison and is stated nowhere else because it changes no figure by more than that.
 */
const BUILDS_BEFORE_WINDOW = 6;

/** Rows in the package ranking and the fragmentation trend. */
const PACKAGE_LIMIT = 25;

const CAP = sql.raw(String(EXPANDABLE_LIST_CAP));

/**
 * The progress half of Analytics: how each project's vulnerabilities moved from build to build,
 * how often it builds, and which projects and packages need attention.
 *
 * Every query starts from the applications the reader may see in one estate, narrowed by the
 * team filter, never inactive. Findings are judged by today's database throughout and exclude
 * accepted risks through the shared predicate.
 */
export class ProgressService {
  constructor(private readonly deps: { db: Database }) {}

  async sections(args: {
    scope: ReadScope;
    filter: TeamFilter;
    periodStart: Date;
    now: Date;
    settings: AttentionSettings;
    vulnEnabled: boolean;
  }): Promise<Pick<AnalyticsReport, "progress" | "attention" | "buildDeltas">> {
    const { scope, filter, periodStart, now, settings, vulnEnabled } = args;
    const apps = filteredApplications(scope, filter);

    const projects = await this.projects(apps);
    const cadenceStart = new Date(now.getTime() - settings.cadenceWindowDays * 86_400_000);
    const cutoff = cadenceStart < periodStart ? cadenceStart : periodStart;
    const builds = await this.builds(apps, cutoff);

    const byApp = new Map<string, BuildFact[]>();
    for (const b of builds) {
      const list = byApp.get(b.applicationId) ?? [];
      list.push(b);
      byApp.set(b.applicationId, list);
    }

    // Pairs per project, and the comparable ones the findings query has to look at.
    const pairsByApp = new Map<string, BuildPair[]>();
    let identicalSkipped = 0;
    for (const p of projects) {
      const { pairs, identicalSkippedInWindow } = buildPairs(byApp.get(p.id) ?? [], periodStart);
      pairsByApp.set(p.id, pairs);
      identicalSkipped += identicalSkippedInWindow;
    }
    const wanted = [...pairsByApp.values()].flat().filter((p) => p.comparable && (p.inWindow || p.isLast));

    const [deltas, fixTimes, risk] = vulnEnabled
      ? await Promise.all([
          this.pairDeltas(wanted),
          this.fixTimes(wanted.filter((p) => p.inWindow)),
          this.currentRisk(apps, now),
        ])
      : [new Map<string, BuildDeltaPair>(), new Map<string, { mean: number; count: number }>(), new Map<string, CurrentRiskFacts>()];

    const progress: ProjectProgress[] = projects.map((p) => {
      const appBuilds = byApp.get(p.id) ?? [];
      const pairs = pairsByApp.get(p.id) ?? [];
      const movement = windowMovement(pairs, deltas);
      const baseline = baselineBuild(appBuilds, periodStart);
      const openCH = p.openCritical === null || p.openHigh === null ? null : p.openCritical + p.openHigh;
      const startCH = baseline?.criticalHigh ?? null;
      const timing = fixTimes.get(p.id);
      return {
        applicationId: p.id,
        name: p.name,
        status: p.status,
        squads: p.squads,
        tribes: p.tribes,
        builds: buildCadence(appBuilds, now, periodStart, settings.cadenceWindowDays),
        vulnerabilities: vulnEnabled
          ? {
              comparedBuilds: movement.compared,
              fixed: movement.fixed,
              introduced: movement.introduced,
              net: movement.introduced - movement.fixed,
              fixedCriticalHigh: movement.fixedCH,
              introducedCriticalHigh: movement.introducedCH,
              openCritical: p.openCritical,
              openHigh: p.openHigh,
              criticalHighAtStart: startCH,
              criticalHighChange: openCH !== null && startCH !== null ? openCH - startCH : null,
              meanDaysToFix: timing ? timing.mean : null,
              fixesTimed: timing?.count ?? 0,
            }
          : null,
      };
    });

    const flaggedProjects = attentionProjects(progress, risk, settings);
    const flagged = new Set(flaggedProjects.map((p) => p.applicationId));

    const [packages, fragmentationRising] = await Promise.all([
      vulnEnabled ? this.attentionPackages(apps) : Promise.resolve([]),
      this.fragmentationRising(
        apps,
        projects.flatMap((p) => {
          const baseline = baselineBuild(byApp.get(p.id) ?? [], periodStart);
          return baseline && p.latestScanId && baseline.scanId !== p.latestScanId
            ? [{ before: baseline.scanId, now: p.latestScanId }]
            : [];
        }),
      ),
    ]);

    return {
      progress: {
        projects: progress,
        squads: rollup(progress, "squads", flagged),
        tribes: rollup(progress, "tribes", flagged),
      },
      attention: { projects: flaggedProjects, packages, fragmentationRising },
      buildDeltas: vulnEnabled
        ? buildDeltaSection(
            projects.map((p) => projectBuildDeltas(p.id, p.name, pairsByApp.get(p.id) ?? [], deltas)),
            identicalSkipped,
          )
        : null,
    };
  }

  /** The projects in scope, with their squads, tribes and current open critical / high. */
  private async projects(apps: SQL) {
    const rows = await this.deps.db.execute<Row<ProjectRow>>(sql`
      SELECT a.id, a.name, a.status, a.latest_scan_id,
             coalesce((SELECT array_agg(s.name ORDER BY s.name) FROM squad_application sa
                        JOIN squad s ON s.id = sa.squad_id WHERE sa.application_id = a.id), '{}') AS squads,
             coalesce((SELECT array_agg(t.name ORDER BY t.name) FROM tribe_application ta
                        JOIN tribe t ON t.id = ta.tribe_id WHERE ta.application_id = a.id), '{}') AS tribes,
             vs.app_critical + vs.os_critical AS open_critical,
             vs.app_high + vs.os_high AS open_high
      FROM application a
      LEFT JOIN scan_vuln_summary vs ON vs.scan_id = a.latest_scan_id
      WHERE a.status <> 'inactive' AND ${apps}
      ORDER BY lower(a.name)
    `);
    return rowsOf(rows).map((r) => ({
      id: r.id,
      name: r.name,
      status: r.status,
      latestScanId: r.latest_scan_id,
      squads: r.squads ?? [],
      tribes: r.tribes ?? [],
      openCritical: r.open_critical === null ? null : Number(r.open_critical),
      openHigh: r.open_high === null ? null : Number(r.open_high),
    }));
  }

  /**
   * Builds since the cutoff, plus the few just before it.
   *
   * `criticalHigh` reads the summary's live columns, which move with every database update -
   * so a build's figure is what today's database says about it, the same basis as the pair
   * comparisons, never a mix of what was known then and what is known now.
   */
  private async builds(apps: SQL, cutoff: Date): Promise<BuildFact[]> {
    const rows = await this.deps.db.execute<Row<BuildRow>>(sql`
      WITH ranked AS (
        SELECT s.id, s.application_id, s.created_at, s.sbom_sha256, s.build_number,
               row_number() OVER (
                 PARTITION BY s.application_id, (s.created_at >= ${cutoff})
                 ORDER BY s.created_at DESC, s.id DESC
               ) AS rn
        FROM scan s
        JOIN application a ON a.id = s.application_id
        WHERE a.status <> 'inactive' AND ${apps}
      )
      SELECT r.id, r.application_id, r.created_at, r.sbom_sha256, r.build_number,
             (vs.scan_id IS NOT NULL) AS assessed,
             vs.app_critical + vs.app_high + vs.os_critical + vs.os_high AS critical_high
      FROM ranked r
      LEFT JOIN scan_vuln_summary vs ON vs.scan_id = r.id
      WHERE r.created_at >= ${cutoff} OR r.rn <= ${BUILDS_BEFORE_WINDOW}
    `);
    return rowsOf(rows).map((r) => ({
      applicationId: r.application_id,
      scanId: r.id,
      createdAt: new Date(r.created_at),
      sha: r.sbom_sha256,
      buildNumber: r.build_number,
      assessed: r.assessed === true,
      criticalHigh: r.critical_high === null ? null : Number(r.critical_high),
    }));
  }

  /**
   * Fixed / introduced / unchanged per build pair, both halves, keyed by the later build.
   *
   * A finding's identity is the package name within its ecosystem plus the advisory, so
   * upgrading 2.14.0 to 2.14.1 while still affected is *unchanged* rather than one fixed and one
   * introduced. Collapsing to that identity happens per build (`DISTINCT`), after the
   * accepted-risk rule has been applied to the exact component it names.
   */
  private async pairDeltas(pairs: readonly BuildPair[]): Promise<Map<string, BuildDeltaPair>> {
    const out = new Map<string, BuildDeltaPair>();
    if (pairs.length === 0) return out;

    const counts: SQL[] = [];
    for (const half of ["app", "os"] as const) {
      const isOs = half === "os" ? sql`is_os` : sql`NOT is_os`;
      for (const [movement, cond] of [
        ["fixed", sql`in_from AND NOT in_to`],
        ["introduced", sql`in_to AND NOT in_from`],
        ["unchanged", sql`in_from AND in_to`],
      ] as const) {
        counts.push(sql`count(*) FILTER (WHERE ${isOs} AND ${cond})::int AS ${sql.raw(`${half}_${movement}_total`)}`);
        counts.push(
          sql`count(*) FILTER (WHERE ${isOs} AND ${cond} AND severity = 'critical')::int AS ${sql.raw(`${half}_${movement}_critical`)}`,
        );
        counts.push(
          sql`count(*) FILTER (WHERE ${isOs} AND ${cond} AND severity = 'high')::int AS ${sql.raw(`${half}_${movement}_high`)}`,
        );
      }
    }

    const rows = await this.deps.db.execute<Row<Record<string, number | string>>>(sql`
      WITH ${keyedFindings(pairs)}
      SELECT to_scan, ${sql.join(counts, sql`, `)}
      FROM keyed
      GROUP BY to_scan
    `);

    for (const row of rowsOf(rows)) {
      const pair = zeroPair();
      for (const half of ["app", "os"] as const) {
        for (const movement of ["fixed", "introduced", "unchanged"] as const) {
          for (const level of ["total", "critical", "high"] as const) {
            pair[half][movement][level] = Number(row[`${half}_${movement}_${level}`] ?? 0);
          }
        }
      }
      out.set(String(row.to_scan), pair);
    }
    return out;
  }

  /**
   * Days to fix, per project: for every critical or high finding removed inside the window,
   * from the first build of this project that carried it to the build that removed it.
   */
  private async fixTimes(pairs: readonly BuildPair[]): Promise<Map<string, { mean: number; count: number }>> {
    const out = new Map<string, { mean: number; count: number }>();
    if (pairs.length === 0) return out;
    const rows = await this.deps.db.execute<Row<{ application_id: string; mean_days: number | string; fixes: number | string }>>(sql`
      WITH ${keyedFindings(pairs)},
      fixed AS (
        SELECT k.to_scan, k.n, k.e, k.vid FROM keyed k
        WHERE k.in_from AND NOT k.in_to AND k.severity IN ('critical', 'high')
      ),
      timed AS (
        SELECT s.application_id,
               extract(epoch FROM (s.created_at - fs.first_seen)) / 86400 AS days
        FROM fixed x
        JOIN scan s ON s.id = x.to_scan
        CROSS JOIN LATERAL (
          SELECT min(sc.created_at) AS first_seen
          FROM component c2
          JOIN component_vulnerability cv2 ON cv2.component_id = c2.id AND cv2.vulnerability_id = x.vid
          JOIN scan_component sc ON sc.component_id = c2.id AND sc.application_id = s.application_id
          WHERE lower(c2.name) = x.n AND c2.ecosystem = x.e AND sc.created_at < s.created_at
        ) fs
        WHERE fs.first_seen IS NOT NULL
      )
      SELECT application_id, avg(days) AS mean_days, count(*)::int AS fixes
      FROM timed GROUP BY application_id
    `);
    for (const r of rowsOf(rows)) {
      out.set(r.application_id, { mean: Math.round(Number(r.mean_days) * 10) / 10, count: Number(r.fixes) });
    }
    return out;
  }

  /**
   * What is open in each current build that a flag may name: known-exploited advisories, and
   * critical findings with a fix, with how long each has been open.
   *
   * "Open since" is the later of when this project first shipped the affected package and when
   * the finding was first recorded at all - an advisory published last week has not been
   * ignored for a year just because the package is old.
   */
  private async currentRisk(apps: SQL, now: Date): Promise<Map<string, CurrentRiskFacts>> {
    const [kevRows, critRows] = await Promise.all([
      this.deps.db.execute<Row<{ application_id: string; ids: string[]; n: number | string }>>(sql`
        SELECT a.id AS application_id,
               (array_agg(DISTINCT v.id ORDER BY v.id))[1:5] AS ids,
               count(DISTINCT v.id)::int AS n
        FROM application a
        JOIN scan_component sc ON sc.scan_id = a.latest_scan_id
        JOIN component c ON c.id = sc.component_id
        JOIN component_vulnerability cv ON cv.component_id = c.id
        JOIN vulnerability v ON v.id = cv.vulnerability_id AND v.known_exploited
        WHERE a.status <> 'inactive' AND ${apps} AND ${NOT_SUPPRESSED}
        GROUP BY a.id
      `),
      this.deps.db.execute<Row<{ application_id: string; vid: string; package: string; open_since: Date | string }>>(sql`
        WITH open_findings AS (
          SELECT a.id AS application_id, lower(c.name) AS n, c.ecosystem AS e, min(c.name) AS package,
                 v.id AS vid, min(cv.first_seen_at) AS known_since
          FROM application a
          JOIN scan_component sc ON sc.scan_id = a.latest_scan_id
          JOIN component c ON c.id = sc.component_id
          JOIN component_vulnerability cv ON cv.component_id = c.id AND cv.fix_state = 'fixed'
          JOIN vulnerability v ON v.id = cv.vulnerability_id AND v.severity = 'critical'
          WHERE a.status <> 'inactive' AND ${apps} AND ${NOT_SUPPRESSED}
          GROUP BY a.id, lower(c.name), c.ecosystem, v.id
        )
        SELECT o.application_id, o.vid, o.package,
               greatest(o.known_since, coalesce(fs.first_seen, o.known_since)) AS open_since
        FROM open_findings o
        CROSS JOIN LATERAL (
          SELECT min(sc.created_at) AS first_seen
          FROM component c2
          JOIN component_vulnerability cv2 ON cv2.component_id = c2.id AND cv2.vulnerability_id = o.vid
          JOIN scan_component sc ON sc.component_id = c2.id AND sc.application_id = o.application_id
          WHERE lower(c2.name) = o.n AND c2.ecosystem = o.e
        ) fs
      `),
    ]);

    const out = new Map<string, CurrentRiskFacts>();
    const entry = (id: string) => {
      let e = out.get(id);
      if (!e) {
        e = { knownExploited: null, criticalFixable: [] };
        out.set(id, e);
      }
      return e;
    };
    for (const r of rowsOf(kevRows)) {
      entry(r.application_id).knownExploited = { count: Number(r.n), ids: r.ids ?? [] };
    }
    for (const r of rowsOf(critRows)) {
      entry(r.application_id).criticalFixable.push({
        vulnerabilityId: r.vid,
        packageName: r.package,
        openDays: (now.getTime() - new Date(r.open_since).getTime()) / 86_400_000,
      });
    }
    return out;
  }

  /**
   * Application dependencies to upgrade first: critical or known-exploited advisories that have
   * a fixed version, ranked by how many applications one upgrade would clear.
   */
  private async attentionPackages(apps: SQL): Promise<AttentionPackage[]> {
    const rows = await this.deps.db.execute<Row<AttentionPackageRow>>(sql`
      SELECT lower(c.name) AS n, c.ecosystem, min(c.name) AS name,
             count(DISTINCT a.id)::int AS applications,
             (array_agg(DISTINCT a.name ORDER BY a.name))[1:${CAP}] AS application_list,
             count(DISTINCT v.id) FILTER (WHERE v.severity = 'critical')::int AS critical,
             count(DISTINCT v.id) FILTER (WHERE v.known_exploited)::int AS kev,
             count(DISTINCT coalesce(c.version, ''))::int AS versions,
             (array_agg(DISTINCT fv ORDER BY fv) FILTER (WHERE fv IS NOT NULL))[1:5] AS fix_versions
      FROM application a
      JOIN scan_component sc ON sc.scan_id = a.latest_scan_id
      JOIN component c ON c.id = sc.component_id
      JOIN component_vulnerability cv ON cv.component_id = c.id AND cv.fix_state = 'fixed'
      JOIN vulnerability v ON v.id = cv.vulnerability_id
      LEFT JOIN LATERAL unnest(cv.fix_versions) AS fv ON TRUE
      WHERE a.status <> 'inactive' AND ${apps} AND ${APP_DEPENDENCY_PREDICATE} AND ${NOT_SUPPRESSED}
        AND (v.severity = 'critical' OR v.known_exploited)
      GROUP BY lower(c.name), c.ecosystem
      ORDER BY applications DESC, kev DESC, critical DESC, lower(min(c.name)) ASC
      LIMIT ${PACKAGE_LIMIT}
    `);
    return rowsOf(rows).map((r) => {
      const apps = Number(r.applications);
      const critical = Number(r.critical);
      const kev = Number(r.kev);
      const what = [
        critical > 0 ? `${critical} critical advisor${critical === 1 ? "y" : "ies"}` : null,
        kev > 0 ? `${kev} known-exploited` : null,
      ]
        .filter(Boolean)
        .join(" and ");
      return {
        name: r.name,
        ecosystem: r.ecosystem,
        applications: apps,
        applicationList: r.application_list ?? [],
        critical,
        knownExploited: kev,
        versionsInUse: Number(r.versions),
        fixVersions: r.fix_versions ?? [],
        reason: `${what} with a fix available, in ${apps} application${apps === 1 ? "" : "s"} - one upgrade clears ${apps === 1 ? "it" : "all of them"}.`,
      };
    });
  }

  /**
   * Application dependencies now run in more versions than at the start of the window, across
   * the projects that had a build on both sides - so a project onboarded mid-window cannot read
   * as fragmentation.
   */
  private async fragmentationRising(
    apps: SQL,
    pairs: Array<{ before: string; now: string }>,
  ): Promise<FragmentationTrend[]> {
    if (pairs.length === 0) return [];
    const rows = await this.deps.db.execute<Row<FragmentationRow>>(sql`
      WITH counted AS (
        SELECT sc.scan_id = ANY(${sql.param(pairs.map((p) => p.now))}::uuid[]) AS is_now,
               lower(c.name) AS n, c.ecosystem AS e, c.name, c.version, sc.application_id
        FROM scan_component sc
        JOIN component c ON c.id = sc.component_id
        JOIN application a ON a.id = sc.application_id
        WHERE sc.scan_id = ANY(${sql.param([...pairs.map((p) => p.now), ...pairs.map((p) => p.before)])}::uuid[])
          AND ${apps} AND ${APP_DEPENDENCY_PREDICATE}
      )
      SELECT min(name) AS name, e AS ecosystem,
             count(DISTINCT coalesce(version, '')) FILTER (WHERE NOT is_now)::int AS v_before,
             count(DISTINCT coalesce(version, '')) FILTER (WHERE is_now)::int AS v_now,
             count(DISTINCT application_id) FILTER (WHERE is_now)::int AS applications
      FROM counted
      GROUP BY n, e
      HAVING count(DISTINCT coalesce(version, '')) FILTER (WHERE is_now) > 1
         AND count(DISTINCT coalesce(version, '')) FILTER (WHERE is_now)
           > count(DISTINCT coalesce(version, '')) FILTER (WHERE NOT is_now)
      ORDER BY (count(DISTINCT coalesce(version, '')) FILTER (WHERE is_now)
              - count(DISTINCT coalesce(version, '')) FILTER (WHERE NOT is_now)) DESC,
               applications DESC, lower(min(name)) ASC
      LIMIT ${PACKAGE_LIMIT}
    `);
    return rowsOf(rows).map((r) => ({
      name: r.name,
      ecosystem: r.ecosystem,
      versionsAtStart: Number(r.v_before),
      versionsNow: Number(r.v_now),
      applications: Number(r.applications),
    }));
  }
}

/**
 * The CTEs both finding queries share: every (package name, advisory) in each build of each
 * pair, tagged with the side it was on. `keyed` has one row per pair and identity.
 */
function keyedFindings(pairs: readonly BuildPair[]): SQL {
  const from = sql.param(pairs.map((p) => p.from.scanId));
  const to = sql.param(pairs.map((p) => p.to.scanId));
  return sql`
    pairs AS (
      SELECT * FROM unnest(${from}::uuid[], ${to}::uuid[]) AS p(from_scan, to_scan)
    ),
    involved AS (
      SELECT from_scan AS scan_id FROM pairs UNION SELECT to_scan FROM pairs
    ),
    f AS (
      SELECT DISTINCT sc.scan_id, lower(c.name) AS n, c.ecosystem AS e, v.id AS vid, v.severity,
             ${BASE_IMAGE_PREDICATE} AS is_os
      FROM involved i
      JOIN scan_component sc ON sc.scan_id = i.scan_id
      JOIN component c ON c.id = sc.component_id
      JOIN component_vulnerability cv ON cv.component_id = c.id
      JOIN vulnerability v ON v.id = cv.vulnerability_id
      JOIN application a ON a.id = sc.application_id
      WHERE ${NOT_SUPPRESSED}
    ),
    sides AS (
      SELECT p.to_scan, f.n, f.e, f.vid, f.severity, f.is_os, true AS in_from, false AS in_to
      FROM pairs p JOIN f ON f.scan_id = p.from_scan
      UNION ALL
      SELECT p.to_scan, f.n, f.e, f.vid, f.severity, f.is_os, false, true
      FROM pairs p JOIN f ON f.scan_id = p.to_scan
    ),
    keyed AS (
      SELECT to_scan, n, e, vid, min(severity) AS severity, bool_or(is_os) AS is_os,
             bool_or(in_from) AS in_from, bool_or(in_to) AS in_to
      FROM sides
      GROUP BY to_scan, n, e, vid
    )`;
}

interface ProjectRow {
  id: string;
  name: string;
  status: string;
  latest_scan_id: string | null;
  squads: string[] | null;
  tribes: string[] | null;
  open_critical: number | string | null;
  open_high: number | string | null;
}

interface BuildRow {
  id: string;
  application_id: string;
  created_at: Date | string;
  sbom_sha256: string;
  build_number: string | null;
  assessed: boolean;
  critical_high: number | string | null;
}

interface AttentionPackageRow {
  name: string;
  ecosystem: string;
  applications: number | string;
  application_list: string[] | null;
  critical: number | string;
  kev: number | string;
  versions: number | string;
  fix_versions: string[] | null;
}

interface FragmentationRow {
  name: string;
  ecosystem: string;
  v_before: number | string;
  v_now: number | string;
  applications: number | string;
}
