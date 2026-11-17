import { sql } from "drizzle-orm";
import {
  ENDING_SOON_DAYS,
  PROJECT_STATUS_RANK,
  projectStatus,
  projectStatuses,
  type MyProject,
  type MyTeam,
  type MyTeamsResponse,
  type ProjectStatus,
  type TeamAcceptedRisk,
  type TeamLateAction,
  type TeamTrendPoint,
} from "@sbom/shared";
import type { AppContext } from "../../context.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { applicationInScope, type ReadAccess, type ReadScope } from "../environments/environment.service.js";
import { EMPTY_URGENCY_COUNTS } from "../platform/registry.js";
import { SQUAD_APPLICATIONS } from "../squads/reach.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const TREND_WEEKS = 4;

/**
 * My teams: for each squad a team lead leads, its projects by status, late actions, accepted
 * risks (those ending soon first) and the trend of the last four weeks.
 *
 * Every number comes from the same place as on the project pages - the status from the same
 * counts as My projects and the action plan, the late actions from the action plans themselves -
 * so the two views cannot disagree.
 */
export class TeamsService {
  constructor(private readonly ctx: AppContext) {}

  async myTeams(user: { id: string; role: string }, scope: ReadScope, access: ReadAccess): Promise<MyTeamsResponse> {
    const { db } = this.ctx;
    const led = await db.execute<Row<{ id: string; name: string }>>(sql`
      SELECT s.id, s.name FROM squad s
       WHERE EXISTS (SELECT 1 FROM squad_member sm WHERE sm.squad_id = s.id AND sm.user_id = ${user.id}::uuid AND sm.is_lead)
       ORDER BY lower(s.name)
    `);
    let squads = rowsOf(led);
    let viewAs: MyTeamsResponse["viewAs"] = "lead";
    if (squads.length === 0 && user.role === "admin") {
      squads = rowsOf(await db.execute<Row<{ id: string; name: string }>>(sql`SELECT id, name FROM squad ORDER BY lower(name)`));
      viewAs = "admin";
    }

    const teams: MyTeam[] = [];
    for (const squad of squads) teams.push(await this.team(squad, scope, access));
    return { teams, viewAs, generatedAt: new Date().toISOString() };
  }

  private async team(squad: { id: string; name: string }, scope: ReadScope, access: ReadAccess): Promise<MyTeam> {
    const { db } = this.ctx;
    const stale = await this.ctx.settings.staleInterval();
    // The squad's projects, inside what the lead may read in the selected environment.
    const rows = await db.execute<
      Row<{ id: string; name: string; last_scan_at: string | Date | null; is_stale: boolean }>
    >(sql`
      SELECT a.id, a.name, a.last_scan_at,
             (a.last_scan_at IS NOT NULL AND a.last_scan_at < now() - ${stale}) AS is_stale
        FROM application a
       WHERE a.status <> 'inactive'
         AND ${applicationInScope("a", scope)}
         AND (EXISTS (SELECT 1 FROM ${SQUAD_APPLICATIONS} sa WHERE sa.squad_id = ${squad.id}::uuid AND sa.application_id = a.id)
              OR EXISTS (SELECT 1 FROM squad_group sg JOIN application_group_member gm ON gm.group_id = sg.group_id
                          WHERE sg.squad_id = ${squad.id}::uuid AND gm.application_id = a.id))
       ORDER BY lower(a.name)
    `);
    const list = rowsOf(rows);
    const ids = list.map((r) => r.id);

    const counts = await this.ctx.modules.urgencyCounts(this.ctx, ids);
    const projects: MyProject[] = list.map((r) => {
      const lastBuildAt = r.last_scan_at === null ? null : new Date(r.last_scan_at).toISOString();
      const c = counts?.get(r.id) ?? { ...EMPTY_URGENCY_COUNTS };
      const { status, reason } = projectStatus({
        counts: c,
        hasBuild: lastBuildAt !== null,
        stale: r.is_stale === true,
        daysSinceBuild: lastBuildAt ? Math.max(0, Math.floor((Date.now() - new Date(lastBuildAt).getTime()) / DAY_MS)) : null,
        scanningOff: counts === null,
      });
      return { applicationId: r.id, name: r.name, status, reason, lastBuildAt, counts: c, via: [`squad ${squad.name}`] };
    });
    projects.sort(
      (a, b) => PROJECT_STATUS_RANK[a.status] - PROJECT_STATUS_RANK[b.status] || b.counts.late - a.counts.late || a.name.localeCompare(b.name),
    );
    const statusCounts = Object.fromEntries(projectStatuses.map((s) => [s, 0])) as Record<ProjectStatus, number>;
    for (const p of projects) statusCounts[p.status] += 1;

    // Late actions straight from each project's action plan, so they match the project page.
    const lateActions: TeamLateAction[] = [];
    for (const p of projects.filter((x) => x.counts.late > 0)) {
      const items = await this.ctx.modules.actionPlan(this.ctx, p.applicationId, access);
      for (const item of items) {
        if (!item.late || !item.dueAt) continue;
        lateActions.push({
          applicationId: p.applicationId,
          applicationName: p.name,
          title: item.title,
          urgency: item.urgency,
          dueAt: item.dueAt,
          dueRule: item.dueRule ?? "",
          clears: item.clears,
        });
      }
    }
    lateActions.sort((a, b) => a.dueAt.localeCompare(b.dueAt));

    return {
      squadId: squad.id,
      name: squad.name,
      projects,
      statusCounts,
      lateActions,
      acceptedRisks: await this.acceptedRisks(ids),
      trend: await this.trend(ids),
    };
  }

  /** Accepted risks on these projects that still apply, ending soonest first. */
  private async acceptedRisks(ids: readonly string[]): Promise<TeamAcceptedRisk[]> {
    if (ids.length === 0) return [];
    const rows = await this.ctx.db.execute<
      Row<{
        id: string;
        vulnerability_id: string;
        application_id: string;
        application_name: string;
        package_label: string | null;
        reason: string;
        expires_at: string | Date | null;
        created_by_email: string | null;
        created_at: string | Date;
      }>
    >(sql`
      SELECT sup.id, sup.vulnerability_id, sup.application_id, a.name AS application_name,
             CASE WHEN c.id IS NULL THEN NULL ELSE c.name || ' ' || coalesce(c.version, '') END AS package_label,
             sup.reason, sup.expires_at, sup.created_by_email, sup.created_at
        FROM vulnerability_suppression sup
        JOIN application a ON a.id = sup.application_id
        LEFT JOIN component c ON c.id = sup.component_id
       WHERE sup.application_id = ANY(${sql.param([...ids])}::uuid[])
         AND (sup.expires_at IS NULL OR sup.expires_at > now())
       ORDER BY sup.expires_at ASC NULLS LAST, sup.created_at DESC
    `);
    const soon = Date.now() + ENDING_SOON_DAYS * DAY_MS;
    return rowsOf(rows).map((r) => {
      const expiresAt = r.expires_at === null ? null : new Date(r.expires_at).toISOString();
      return {
        id: r.id,
        vulnerabilityId: r.vulnerability_id,
        applicationId: r.application_id,
        applicationName: r.application_name,
        packageLabel: r.package_label?.trim() || null,
        reason: r.reason,
        expiresAt,
        endingSoon: expiresAt !== null && new Date(expiresAt).getTime() <= soon,
        acceptedBy: r.created_by_email,
        acceptedAt: new Date(r.created_at).toISOString(),
      };
    });
  }

  /**
   * Critical and high in the build each project had at the end of each of the last four weeks,
   * plus now - from the per-build summaries (accepted risks already left out of those).
   */
  private async trend(ids: readonly string[]): Promise<TeamTrendPoint[]> {
    const points = Array.from({ length: TREND_WEEKS + 1 }, (_, i) => new Date(Date.now() - (TREND_WEEKS - i) * 7 * DAY_MS));
    if (ids.length === 0) return points.map((p) => ({ weekEnding: p.toISOString(), critical: 0, high: 0, projectsCounted: 0 }));
    const rows = await this.ctx.db.execute<
      Row<{ point: string | Date; critical: number | string; high: number | string; projects: number | string }>
    >(sql`
      SELECT pt.point,
             coalesce(sum(coalesce((vs.counts->'app'->>'critical')::int, 0) + coalesce((vs.counts->'os'->>'critical')::int, 0)), 0) AS critical,
             coalesce(sum(coalesce((vs.counts->'app'->>'high')::int, 0) + coalesce((vs.counts->'os'->>'high')::int, 0)), 0) AS high,
             count(cur.id) AS projects
        FROM unnest(${sql.param(points.map((p) => p.toISOString()))}::timestamptz[]) AS pt(point)
        CROSS JOIN unnest(${sql.param([...ids])}::uuid[]) AS app(id)
        LEFT JOIN LATERAL (
          SELECT s.id FROM scan s
           WHERE s.application_id = app.id AND s.created_at <= pt.point
           ORDER BY s.created_at DESC LIMIT 1
        ) cur ON TRUE
        LEFT JOIN scan_vuln_summary vs ON vs.scan_id = cur.id
       GROUP BY pt.point
       ORDER BY pt.point
    `);
    return rowsOf(rows).map((r) => ({
      weekEnding: new Date(r.point).toISOString(),
      critical: Number(r.critical),
      high: Number(r.high),
      projectsCounted: Number(r.projects),
    }));
  }
}
