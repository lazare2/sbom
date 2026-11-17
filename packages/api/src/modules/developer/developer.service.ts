import { sql } from "drizzle-orm";
import {
  PROJECT_STATUS_RANK,
  projectStatus,
  type ActionPlanResponse,
  type MyProject,
  type MyProjectsResponse,
  type ProjectUrgencyCounts,
} from "@sbom/shared";
import type { AppContext } from "../../context.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { applicationInScope, type ReadAccess, type ReadScope } from "../environments/environment.service.js";
import { SQUAD_APPLICATIONS } from "../squads/reach.js";
import { EMPTY_URGENCY_COUNTS } from "../platform/registry.js";
import { isLeadOf } from "../squads/leads.js";

const DAY_MS = 24 * 60 * 60 * 1000;

function daysSince(iso: string | null): number | null {
  if (!iso) return null;
  return Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / DAY_MS));
}

/**
 * The developer view: a person's own projects with a status in words, and one project's plan.
 *
 * "Own" means reached through the person's squads or granted to them directly (an application or
 * a group). It is always inside what they may read - the selected environment and their
 * visibility - so an administrator's unrestricted access does not turn every project into theirs.
 */
export class DeveloperService {
  constructor(private readonly ctx: AppContext) {}

  async myProjects(userId: string, scope: ReadScope): Promise<MyProjectsResponse> {
    const { db } = this.ctx;
    const stale = await this.ctx.settings.staleInterval();
    const rows = await db.execute<
      Row<{
        id: string;
        name: string;
        last_scan_at: string | Date | null;
        is_stale: boolean;
        squads: string[] | null;
        direct: boolean;
      }>
    >(sql`
      SELECT * FROM (
        SELECT a.id, a.name, a.last_scan_at,
               (a.last_scan_at IS NOT NULL AND a.last_scan_at < now() - ${stale}) AS is_stale,
               (SELECT array_agg(DISTINCT s.name ORDER BY s.name)
                  FROM squad_member sm JOIN squad s ON s.id = sm.squad_id
                 WHERE sm.user_id = ${userId}::uuid
                   AND (EXISTS (SELECT 1 FROM ${SQUAD_APPLICATIONS} sa
                                 WHERE sa.squad_id = sm.squad_id AND sa.application_id = a.id)
                        OR EXISTS (SELECT 1 FROM squad_group sg
                                     JOIN application_group_member gm ON gm.group_id = sg.group_id
                                    WHERE sg.squad_id = sm.squad_id AND gm.application_id = a.id))
               ) AS squads,
               (EXISTS (SELECT 1 FROM user_application ua
                         WHERE ua.user_id = ${userId}::uuid AND ua.application_id = a.id)
                OR EXISTS (SELECT 1 FROM user_group ug
                             JOIN application_group_member gm ON gm.group_id = ug.group_id
                            WHERE ug.user_id = ${userId}::uuid AND gm.application_id = a.id)
               ) AS direct
          FROM application a
         WHERE a.status <> 'inactive'
           AND ${applicationInScope("a", scope)}
      ) mine
      WHERE mine.squads IS NOT NULL OR mine.direct
    `);
    const list = rowsOf(rows);

    const membership = await db.execute<Row<{ any: boolean }>>(sql`
      SELECT (EXISTS (SELECT 1 FROM squad_member WHERE user_id = ${userId}::uuid)
           OR EXISTS (SELECT 1 FROM user_application WHERE user_id = ${userId}::uuid)
           OR EXISTS (SELECT 1 FROM user_group WHERE user_id = ${userId}::uuid)) AS any
    `);

    const visits = await this.visitsOf(userId, list.map((r) => r.id));
    const counts = await this.ctx.modules.urgencyCounts(this.ctx, list.map((r) => r.id), visits);
    const projects: MyProject[] = list.map((r) => {
      const lastBuildAt = r.last_scan_at === null ? null : new Date(r.last_scan_at).toISOString();
      const c: ProjectUrgencyCounts = counts?.get(r.id) ?? { ...EMPTY_URGENCY_COUNTS };
      const { status, reason } = projectStatus({
        counts: c,
        hasBuild: lastBuildAt !== null,
        stale: r.is_stale === true,
        daysSinceBuild: daysSince(lastBuildAt),
        scanningOff: counts === null,
      });
      const via = [...(r.squads ?? []).map((s) => `squad ${s}`), ...(r.direct ? ["granted to you"] : [])];
      return { applicationId: r.id, name: r.name, status, reason, lastBuildAt, counts: c, via };
    });
    projects.sort(
      (a, b) =>
        PROJECT_STATUS_RANK[a.status] - PROJECT_STATUS_RANK[b.status] ||
        b.counts.now - a.counts.now ||
        b.counts.soon - a.counts.soon ||
        a.name.localeCompare(b.name),
    );
    return { projects, hasMembership: rowsOf(membership)[0]?.any === true };
  }

  /**
   * One project's status and action plan. 404 when it is outside the caller's access.
   *
   * Records the visit. "New" is measured from the visit before this one; `since` lets the page
   * keep measuring from the same point while it is open, rather than every refresh clearing the
   * marks it has just shown.
   */
  async actionPlan(
    applicationId: string,
    user: { id: string; role: string },
    access: ReadAccess,
    since?: Date,
  ): Promise<ActionPlanResponse> {
    const app = await this.ctx.applications.getById(applicationId, access);
    const stored = (await this.visitsOf(user.id, [applicationId])).get(applicationId) ?? null;
    const previous = since ?? stored;
    const visits = new Map<string, Date>(previous ? [[applicationId, previous]] : []);

    const counts = await this.ctx.modules.urgencyCounts(this.ctx, [applicationId], visits);
    const c = counts?.get(applicationId) ?? { ...EMPTY_URGENCY_COUNTS };
    const { status, reason } = projectStatus({
      counts: c,
      hasBuild: app.lastScanAt !== null,
      stale: app.isStale,
      daysSinceBuild: daysSince(app.lastScanAt),
      scanningOff: counts === null,
    });
    // The registry checks access again before asking any module; cheap, and it keeps the rule
    // in one place for every caller.
    const items = await this.ctx.modules.actionPlan(this.ctx, applicationId, access, previous);
    const canAcceptRisk = user.role === "admin" || (await isLeadOf(this.ctx.db, user.id, applicationId));
    const targets = await this.ctx.settings.getTargetDates();

    await this.ctx.db.execute(sql`
      INSERT INTO project_visit (user_id, application_id, visited_at)
      VALUES (${user.id}::uuid, ${applicationId}::uuid, now())
      ON CONFLICT (user_id, application_id) DO UPDATE SET visited_at = now()
    `);

    return {
      applicationId,
      name: app.name,
      previousVisitAt: previous?.toISOString() ?? null,
      canAcceptRisk,
      targets,
      status,
      reason,
      counts: c,
      lastBuildAt: app.lastScanAt,
      items,
    };
  }

  /** The caller's previous visit to each project, where there was one. */
  private async visitsOf(userId: string, applicationIds: readonly string[]): Promise<Map<string, Date>> {
    if (applicationIds.length === 0) return new Map();
    const rows = await this.ctx.db.execute<Row<{ application_id: string; visited_at: string | Date }>>(sql`
      SELECT application_id, visited_at FROM project_visit
       WHERE user_id = ${userId}::uuid AND application_id = ANY(${sql.param([...applicationIds])}::uuid[])
    `);
    return new Map(rowsOf(rows).map((r) => [r.application_id, new Date(r.visited_at)]));
  }
}
