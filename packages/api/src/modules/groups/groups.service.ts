import { sql, type SQL } from "drizzle-orm";
import type {
  ApplicationGroupDetail,
  ApplicationGroupSummary,
  GroupAdvisory,
  GroupMember,
  GroupVulnCounts,
  ListGroupAdvisoriesQuery,
  ListGroupsQuery,
  Paginated,
  SeverityCounts,
} from "@sbom/shared";
import { EMPTY_SEVERITY_COUNTS, EXPANDABLE_LIST_CAP, vulnSeverities } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { NotFoundError } from "../../lib/errors.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { direction, directionNullsLast, orderBy } from "../../lib/sorting.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import { NOT_SUPPRESSED } from "../vulnerabilities/scope.js";

/**
 * Reads over named sets of applications.
 *
 * ## The counting rule, and why it is not the dashboard's
 *
 * Everything here counts **distinct advisories**; the dashboard sums **findings**. Both are
 * right, and they answer different questions — see the note on `schemas/group.ts`. The
 * consequence for this file is that none of these queries can use `scan_vuln_summary`, which
 * is pre-aggregated per scan and cannot be summed without counting a shared base image once
 * per member. They join `scan_component` live instead.
 *
 * That is affordable because of the shape of the question: a group page reads one group, so
 * the join is bounded by that group's members rather than by the estate. The one operation
 * that would not be affordable is ranking every group by advisories at once, which is why
 * the list query computes its counts per page rather than over the whole table.
 *
 * ## What counts as a member for aggregation
 *
 * Membership and assessability are deliberately separate numbers. `applicationCount` is every
 * member; `assessedApplicationCount` is those whose current build has actually been matched
 * against the database. A group of twenty whose members were never scanned must not report
 * three advisories as though that were the whole picture, so both travel together and the UI
 * shows the denominator.
 *
 * Inactive applications are excluded from the aggregate but still listed as members, matching
 * how the dashboard already treats them: they are part of the record, not part of the current
 * risk position.
 */
export class GroupsService {
  constructor(private readonly deps: { db: Database; settings: SettingsService }) {}

  /**
   * The members whose current build can carry findings.
   *
   * Every aggregate in this file starts here, so "which applications does this group's number
   * describe" has exactly one answer. Inline rather than a view because it takes the group id
   * as a parameter and is only ever used as a CTE.
   */
  private membersCte(groupId: string): SQL {
    return sql`
      SELECT a.id, a.latest_scan_id
      FROM application_group_member m
      JOIN application a ON a.id = m.application_id
      WHERE m.group_id = ${groupId}::uuid
        AND a.status <> 'inactive'
        AND a.latest_scan_id IS NOT NULL
    `;
  }

  async list(query: ListGroupsQuery): Promise<Paginated<ApplicationGroupSummary>> {
    const { db } = this.deps;
    const vulnEnabled = await this.deps.settings.vulnScanningEnabled();
    const offset = offsetOf(query);

    const conditions: SQL[] = [];
    if (query.search) {
      conditions.push(sql`g.name ILIKE ${"%" + escapeLike(query.search) + "%"}`);
    }
    const where = conditions.length > 0 ? sql`WHERE ${sql.join(conditions, sql` AND `)}` : sql``;

    /*
      Member counts come from a correlated subquery rather than a GROUP BY over the join,
      because a group with no members must still appear in the list. A plain join would drop
      it, and an empty group is usually a mistake worth seeing rather than one worth hiding.
    */
    const rows = await db.execute<Row<GroupListRow>>(sql`
      SELECT
        g.id, g.name, g.description, g.created_at,
        (SELECT count(*) FROM application_group_member m WHERE m.group_id = g.id) AS application_count,
        /*
          A capped name preview, aggregated here rather than fetched per row. The admin list
          shows membership without opening each group; doing that from the detail endpoint
          would be one request per row. Same shape as the dashboard's application_list.
        */
        COALESCE(
          (SELECT array_agg(a.name ORDER BY lower(a.name))
           FROM (
             SELECT a2.name
             FROM application_group_member m2
             JOIN application a2 ON a2.id = m2.application_id
             WHERE m2.group_id = g.id
             ORDER BY lower(a2.name)
             LIMIT ${EXPANDABLE_LIST_CAP}
           ) a),
          ARRAY[]::text[]
        ) AS member_names,
        count(*) OVER () AS total
      FROM application_group g
      ${where}
      ${this.orderByClause(query)}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `);

    const pageRows = rowsOf(rows);
    /*
      Advisory counts for this page only, in one query rather than one per row. The list can
      show hundreds of groups and each count is a live join over its members' components; the
      page bound is what keeps that from becoming a scan of the whole findings table.
    */
    const counts = vulnEnabled
      ? await this.advisoryCountsFor(pageRows.map((r) => r.id))
      : new Map<string, GroupVulnCounts>();

    const items = pageRows.map((row) => ({
      id: row.id,
      name: row.name,
      description: row.description,
      applicationCount: Number(row.application_count),
      memberNames: row.member_names ?? [],
      vulnerabilities: counts.get(row.id) ?? null,
      createdAt: toIso(row.created_at)!,
    }));

    return paginate(items, totalFromRows(pageRows), query);
  }

  private orderByClause(query: ListGroupsQuery): SQL {
    const dir = direction(query.sortDir);
    const nulls = directionNullsLast(query.sortDir);
    const byName = sql`lower(g.name) ASC`;

    switch (query.sortBy) {
      case "applicationCount":
        return orderBy(
          [sql`(SELECT count(*) FROM application_group_member m WHERE m.group_id = g.id) ${dir}`, byName],
          sql`g.id`,
        );
      case "advisoryCount":
        /*
          Sorts on member count, not on advisories, and says so in the UI.

          Ordering by the real figure would mean computing it for every group in the table
          before the LIMIT can be applied — the exact whole-estate join this file is shaped
          to avoid. Member count is the honest available proxy, and a silent fallback to
          name order would be worse: the header would look like it did nothing.
        */
        return orderBy(
          [sql`(SELECT count(*) FROM application_group_member m WHERE m.group_id = g.id) ${nulls}`, byName],
          sql`g.id`,
        );
      case "createdAt":
        return orderBy([sql`g.created_at ${dir}`, byName], sql`g.id`);
      case "name":
      default:
        return orderBy([sql`lower(g.name) ${dir}`], sql`g.id`);
    }
  }

  /**
   * Distinct advisories per group, for a bounded set of groups.
   *
   * `count(DISTINCT v.id)` rather than `count(*)`: a CVE present in six members' images
   * produces six finding rows here, and collapsing them is the entire difference between this
   * number and the dashboard's.
   */
  private async advisoryCountsFor(groupIds: string[]): Promise<Map<string, GroupVulnCounts>> {
    if (groupIds.length === 0) return new Map();

    const severityColumns = vulnSeverities.map(
      (s) => sql`count(DISTINCT v.id) FILTER (WHERE v.severity = ${s}) AS ${sql.raw(`sev_${s}`)}`,
    );

    const rows = await this.deps.db.execute<Row<GroupCountRow>>(sql`
      WITH member AS (
        SELECT m.group_id, a.id AS application_id, a.latest_scan_id
        FROM application_group_member m
        JOIN application a ON a.id = m.application_id
        WHERE m.group_id = ANY(${sql.param(groupIds)}::uuid[])
          AND a.status <> 'inactive'
          AND a.latest_scan_id IS NOT NULL
      ),
      /*
        Assessed is counted from the summary table rather than from the presence of findings:
        a build that was matched and came back clean is assessed, and inferring it from
        findings would count exactly those members as unassessed.
      */
      assessed AS (
        SELECT mem.group_id, count(*) AS n
        FROM member mem
        WHERE EXISTS (SELECT 1 FROM scan_vuln_summary vs WHERE vs.scan_id = mem.latest_scan_id)
        GROUP BY mem.group_id
      ),
      finding AS (
        SELECT mem.group_id, mem.application_id, v.id AS vuln_id, v.severity
        FROM member mem
        JOIN scan_component sc ON sc.scan_id = mem.latest_scan_id
        JOIN component c ON c.id = sc.component_id
        JOIN component_vulnerability cv ON cv.component_id = c.id
        JOIN vulnerability v ON v.id = cv.vulnerability_id
        JOIN application a ON a.id = mem.application_id
        WHERE ${NOT_SUPPRESSED}
      )
      SELECT
        g.id AS group_id,
        COALESCE(ass.n, 0) AS assessed_count,
        count(DISTINCT f.vuln_id) AS advisories,
        count(DISTINCT f.application_id) AS affected_count,
        ${sql.join(severityColumns, sql`, `)}
      FROM application_group g
      LEFT JOIN assessed ass ON ass.group_id = g.id
      LEFT JOIN finding f ON f.group_id = g.id
      LEFT JOIN vulnerability v ON v.id = f.vuln_id
      WHERE g.id = ANY(${sql.param(groupIds)}::uuid[])
      GROUP BY g.id, ass.n
    `);

    const out = new Map<string, GroupVulnCounts>();
    for (const row of rowsOf(rows)) {
      const assessed = Number(row.assessed_count ?? 0);
      /*
        No assessed member means no basis for a number at all, and null is what the client
        renders as "not assessed". Returning zero here would report a group whose every
        member is awaiting its first sweep as having nothing wrong with it.
      */
      if (assessed === 0) continue;

      const bySeverity = { ...EMPTY_SEVERITY_COUNTS } as SeverityCounts;
      for (const severity of vulnSeverities) {
        bySeverity[severity] = Number(row[`sev_${severity}`] ?? 0);
      }

      out.set(row.group_id, {
        advisories: Number(row.advisories ?? 0),
        bySeverity,
        assessedApplicationCount: assessed,
        affectedApplicationCount: Number(row.affected_count ?? 0),
      });
    }
    return out;
  }

  async getById(id: string): Promise<ApplicationGroupDetail> {
    const { db } = this.deps;

    const rows = await db.execute<Row<GroupListRow & { updated_at: Date | string }>>(sql`
      SELECT
        g.id, g.name, g.description, g.created_at, g.updated_at,
        (SELECT count(*) FROM application_group_member m WHERE m.group_id = g.id) AS application_count
      FROM application_group g
      WHERE g.id = ${id}::uuid
    `);
    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("Group");

    const vulnEnabled = await this.deps.settings.vulnScanningEnabled();
    const counts = vulnEnabled ? (await this.advisoryCountsFor([id])).get(id) ?? null : null;

    return {
      id: row.id,
      name: row.name,
      description: row.description,
      applicationCount: Number(row.application_count),
      memberNames: row.member_names ?? [],
      vulnerabilities: counts,
      createdAt: toIso(row.created_at)!,
      updatedAt: toIso(row.updated_at)!,
      members: await this.listMembers(id, vulnEnabled),
    };
  }

  /**
   * The group's applications, each with its own distinct advisory count.
   *
   * Per member rather than only in total, because "how bad is this group" is immediately
   * followed by "which of them is the problem", and a group page that cannot answer the
   * second sends the reader to open every application in turn.
   */
  private async listMembers(groupId: string, vulnEnabled: boolean): Promise<GroupMember[]> {
    const advisoryColumn = vulnEnabled
      ? sql`(
          SELECT count(DISTINCT v.id)
          FROM scan_component sc
          JOIN component c ON c.id = sc.component_id
          JOIN component_vulnerability cv ON cv.component_id = c.id
          JOIN vulnerability v ON v.id = cv.vulnerability_id
          WHERE sc.scan_id = a.latest_scan_id AND ${NOT_SUPPRESSED}
        )`
      : sql`NULL`;

    const rows = await this.deps.db.execute<Row<MemberRow>>(sql`
      SELECT
        a.id, a.name, a.status, a.last_scan_at, a.latest_scan_id,
        /*
          Gated on the summary row, not on the count: a matched-and-clean build is a genuine
          zero, while a build the sweep has not reached has no number at all. COALESCE here
          would merge the two and print a clean bill of health for an unassessed member.
        */
        CASE WHEN EXISTS (SELECT 1 FROM scan_vuln_summary vs WHERE vs.scan_id = a.latest_scan_id)
             THEN ${advisoryColumn} ELSE NULL END AS advisories
      FROM application_group_member m
      JOIN application a ON a.id = m.application_id
      WHERE m.group_id = ${groupId}::uuid
      ORDER BY lower(a.name) ASC, a.id
    `);

    return rowsOf(rows).map((r) => ({
      id: r.id,
      name: r.name,
      status: r.status,
      lastScanAt: toIso(r.last_scan_at),
      latestScanId: r.latest_scan_id,
      advisories: r.advisories === null || r.advisories === undefined ? null : Number(r.advisories),
    }));
  }

  /**
   * The group's advisories, each with how much of the group it reaches.
   *
   * The spread is the reason this list exists rather than a per-application one. The same
   * advisory in one of eight images is a single rebuild; in eight of eight it is a base image
   * nobody has updated. Severity does not distinguish those and a flat CVE list presents them
   * identically.
   */
  async listAdvisories(
    groupId: string,
    query: ListGroupAdvisoriesQuery,
  ): Promise<Paginated<GroupAdvisory>> {
    await this.requireExists(groupId);
    if (!(await this.deps.settings.vulnScanningEnabled())) {
      return paginate([], 0, query);
    }

    const conditions: SQL[] = [];
    if (query.search) {
      conditions.push(sql`v.id ILIKE ${"%" + escapeLike(query.search) + "%"}`);
    }
    if (query.severity) {
      conditions.push(sql`v.severity = ${query.severity}`);
    }
    const extra = conditions.length > 0 ? sql`AND ${sql.join(conditions, sql` AND `)}` : sql``;

    const rows = await this.deps.db.execute<Row<AdvisoryRow>>(sql`
      WITH member AS (${this.membersCte(groupId)})
      SELECT
        v.id AS vulnerability_id,
        v.severity,
        v.cvss_base_score,
        count(DISTINCT mem.id) AS affected_members,
        count(DISTINCT c.id) AS affected_packages,
        bool_or(cv.fix_state = 'fixed') AS fixable,
        count(*) OVER () AS total
      FROM member mem
      JOIN application a ON a.id = mem.id
      JOIN scan_component sc ON sc.scan_id = mem.latest_scan_id
      JOIN component c ON c.id = sc.component_id
      JOIN component_vulnerability cv ON cv.component_id = c.id
      JOIN vulnerability v ON v.id = cv.vulnerability_id
      WHERE ${NOT_SUPPRESSED} ${extra}
      GROUP BY v.id, v.severity, v.cvss_base_score
      ${this.advisoryOrderBy(query)}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    const pageRows = rowsOf(rows);
    const items = pageRows.map((r) => ({
      vulnerabilityId: r.vulnerability_id,
      severity: r.severity,
      cvssScore:
        r.cvss_base_score === null || r.cvss_base_score === undefined
          ? null
          : Number(r.cvss_base_score),
      affectedMembers: Number(r.affected_members),
      affectedPackages: Number(r.affected_packages),
      fixable: r.fixable === true,
    }));

    return paginate(items, totalFromRows(pageRows), query);
  }

  private advisoryOrderBy(query: ListGroupAdvisoriesQuery): SQL {
    const dir = direction(query.sortDir);
    // Severity rank, not alphabetical: "critical" before "high" before "low" is the only
    // ordering a reader expects, and text order gives critical, high, low, medium, negligible.
    const bySeverityRank = sql`array_position(${sql.param([...vulnSeverities])}::text[], v.severity)`;

    switch (query.sortBy) {
      case "severity":
        return orderBy([sql`${bySeverityRank} ${dir}`, sql`count(DISTINCT mem.id) DESC`], sql`v.id`);
      case "vulnerabilityId":
        return orderBy([sql`v.id ${dir}`], sql`v.id`);
      case "affectedMembers":
      default:
        return orderBy(
          [sql`count(DISTINCT mem.id) ${dir}`, sql`${bySeverityRank} ASC`],
          sql`v.id`,
        );
    }
  }

  /** Groups an application belongs to, for its detail page and the applications list chips. */
  async listForApplication(applicationId: string): Promise<Array<{ id: string; name: string }>> {
    const rows = await this.deps.db.execute<Row<{ id: string; name: string }>>(sql`
      SELECT g.id, g.name
      FROM application_group_member m
      JOIN application_group g ON g.id = m.group_id
      WHERE m.application_id = ${applicationId}::uuid
      ORDER BY lower(g.name) ASC
    `);
    return rowsOf(rows);
  }

  /**
   * A group's name, or null when the id names nothing.
   *
   * Exists for the dashboard and analytics filter label, which is printed verbatim on screen
   * and on the PDF cover. Null rather than throwing: a stale bookmark pointing at a deleted
   * group should render "Group: unknown" beside figures for the whole estate, not 404 a page
   * that is otherwise perfectly answerable.
   */
  async nameById(id: string): Promise<string | null> {
    const rows = await this.deps.db.execute<Row<{ name: string }>>(
      sql`SELECT name FROM application_group WHERE id = ${id}::uuid`,
    );
    return rowsOf(rows)[0]?.name ?? null;
  }

  private async requireExists(id: string): Promise<void> {
    const rows = await this.deps.db.execute<Row<{ id: string }>>(
      sql`SELECT id FROM application_group WHERE id = ${id}::uuid`,
    );
    if (rowsOf(rows).length === 0) throw new NotFoundError("Group");
  }
}

/**
 * Escapes LIKE metacharacters so a search for `100%` matches that text rather than everything.
 *
 * Same treatment the component search already applies. Without it a user's literal `_` is a
 * single-character wildcard and the result set is quietly wrong rather than empty.
 */
function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (ch) => `\\${ch}`);
}

interface GroupListRow {
  id: string;
  name: string;
  description: string | null;
  created_at: Date | string;
  application_count: number | string;
  member_names: string[] | null;
  total?: number | string;
}

interface GroupCountRow extends Record<string, unknown> {
  group_id: string;
  assessed_count: number | string | null;
  advisories: number | string | null;
  affected_count: number | string | null;
}

interface MemberRow {
  id: string;
  name: string;
  status: "active" | "inactive" | "pending_confirmation";
  last_scan_at: Date | string | null;
  latest_scan_id: string | null;
  advisories: number | string | null;
}

interface AdvisoryRow {
  vulnerability_id: string;
  severity: string;
  cvss_base_score: number | string | null;
  affected_members: number | string;
  affected_packages: number | string;
  fixable: boolean | null;
  total?: number | string;
}
