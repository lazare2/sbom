import type { FastifyInstance } from "fastify";
import { advisorySearchQuerySchema, EMPTY_SEVERITY_COUNTS, idParamSchema, type FindResults, SUPPORT_LIST_AS_OF, supportStatus, targetDatesSchema } from "@sbom/shared";
import { sql } from "drizzle-orm";
import { rowsOf, type Row } from "../../lib/rows.js";
import { z } from "zod";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import { readAccess, requireScope } from "../environments/scope.js";
import { applicationInScope } from "../environments/environment.service.js";
import type { PlatformModule } from "../platform/module.js";
import { DeveloperService } from "./developer.service.js";
import { renderTeamsPdf } from "./teams-pdf.js";
import { TeamsService } from "./teams.service.js";

/** `since`: keep measuring "new" from this point while the page stays open. */
const actionPlanQuerySchema = z.object({ since: z.string().datetime().optional() });
const findQuerySchema = z.object({ q: z.string().trim().min(1).max(128) });

async function developerRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.addHook("preHandler", fastify.requireAuth);
  const developer = fastify.ctx.modules.services<DeveloperService>("developer");

  fastify.get("/my-projects", async (request, reply) => {
    return reply.send(await developer.myProjects(getUser(request).id, await requireScope(request)));
  });

  const teams = new TeamsService(fastify.ctx);

  /**
   * One search box for a project, a package or a CVE. Each part answers within what the caller
   * may read in the selected environment, exactly as its own page would.
   */
  fastify.get("/find", async (request, reply) => {
    const { q } = parseOrThrow(findQuerySchema, request.query, "Query");
    const scope = await requireScope(request);
    const { db, components, vulnerabilities, settings } = fastify.ctx;
    const like = `%${q.toLowerCase()}%`;
    const projects = await db.execute<Row<{ id: string; name: string }>>(sql`
      SELECT a.id, a.name FROM application a
       WHERE a.status <> 'inactive' AND ${applicationInScope("a", scope)} AND lower(a.name) LIKE ${like}
       ORDER BY (lower(a.name) = ${q.toLowerCase()}) DESC, lower(a.name) LIMIT 10
    `);
    const packages = q.length >= 2 ? await components.suggest({ q, limit: 10 }, [scope]) : [];
    let advisories: FindResults["advisories"] = null;
    if (await settings.vulnScanningEnabled()) {
      const found = q.length >= 3
        ? await vulnerabilities.searchAdvisories(
            advisorySearchQuerySchema.parse({ q, scope: "all", currentOnly: "false", pageSize: 10 }),
            scope,
          )
        : { items: [] };
      advisories = found.items.map((a) => ({
        vulnerabilityId: a.vulnerabilityId,
        aliases: a.aliases,
        severity: a.severity,
        currentApplications: a.currentApplications,
      }));
    }
    const body: FindResults = {
      query: q,
      projects: rowsOf(projects).map((r) => ({ applicationId: r.id, name: r.name })),
      packages: packages.map((p) => ({ name: p.name, ecosystem: p.ecosystem, versionCount: p.versionCount })),
      advisories,
    };
    return reply.send(body);
  });

  fastify.get("/my-teams", async (request, reply) => {
    const user = getUser(request);
    return reply.send(await teams.myTeams({ id: user.id, role: user.role }, await requireScope(request), await readAccess(request)));
  });

  fastify.get("/my-teams/pdf", async (request, reply) => {
    const user = getUser(request);
    const report = await teams.myTeams({ id: user.id, role: user.role }, await requireScope(request), await readAccess(request));
    const pdf = await renderTeamsPdf(report);
    return reply
      .type("application/pdf")
      .header("content-disposition", `attachment; filename="my-teams-${report.generatedAt.slice(0, 10)}.pdf"`)
      .send(pdf);
  });

  fastify.get("/applications/:id/action-plan", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const { since } = parseOrThrow(actionPlanQuerySchema, request.query, "Query");
    const user = getUser(request);
    return reply.send(
      await developer.actionPlan(id, { id: user.id, role: user.role }, await readAccess(request), since ? new Date(since) : undefined),
    );
  });
}

/** Target dates: days to fix, by rule. Mounted behind requireAdmin by the module frame. */
async function developerAdminRoutes(fastify: FastifyInstance): Promise<void> {
  const { settings, audit } = fastify.ctx;

  fastify.get("/targets", async (_request, reply) => {
    return reply.send({ targets: await settings.getTargetDates() });
  });

  fastify.put("/targets", async (request, reply) => {
    const body = parseOrThrow(targetDatesSchema, request.body);
    const user = getUser(request);
    const actor = { id: user.id, email: user.email, ...(request.apiToken ? { viaToken: request.apiToken.name } : {}) };
    const { before, after } = await settings.updateTargetDates(body, actor);
    // Recorded because it changes which actions are late, on every project, with no build changing.
    await audit.record({ actor, action: "settings.update", targetType: "setting", targetId: "targets", metadata: { before, after } });
    return reply.send({ targets: after });
  });
}

/**
 * The developer view: "My projects" and each project's action plan.
 *
 * Always on. What it says about vulnerabilities comes from the modules that report them (through
 * the action plan and project urgency hooks), so with vulnerability scanning off it still lists
 * a person's projects and says plainly that nothing is checked.
 */
export const developerModule: PlatformModule = {
  id: "developer",
  name: "Developer view",
  description: "My projects with a status in plain words, and an action plan for each project.",

  services: (ctx) => new DeveloperService(ctx),

  /**
   * A line for a base image or runtime past - or near - the end of its security support, from
   * the list shipped with the release (shared/support.ts). Not a vulnerability: no fix will come
   * for what is found in it after that date, so it is a thing to do in its own right.
   */
  actionPlan: {
    async actions(ctx, request) {
      const rows = await ctx.db.execute<Row<{ os_name: string | null; os_version: string | null; runtimes: unknown }>>(sql`
        SELECT s.os_name, s.os_version, s.runtimes
          FROM application a JOIN scan s ON s.id = a.latest_scan_id
         WHERE a.id = ${request.applicationId}::uuid
      `);
      const row = rowsOf(rows)[0];
      if (!row) return [];
      const runtimes = Array.isArray(row.runtimes) ? (row.runtimes as Array<{ name: string; version: string | null }>) : [];
      return supportStatus({ osName: row.os_name, osVersion: row.os_version, runtimes })
        .filter((s) => s.ended || s.endsSoon)
        .map((s) => ({
          key: `end-of-life:${s.label}`,
          kind: "end-of-life" as const,
          title: s.ended ? `Move off ${s.label}: its security support ended` : `Plan the move off ${s.label}: its security support ends soon`,
          reason: `${s.label} gets security fixes until ${s.endsOn}${s.ended ? "; nothing found in it after that will be fixed" : ""}. From the support list shipped with this release (as of ${SUPPORT_LIST_AS_OF}).`,
          urgency: s.ended ? ("soon" as const) : ("later" as const),
          // After the vulnerability lines of the same urgency.
          priority: (s.ended ? 1 : 2) * 100_000 + 50_000,
          clears: 0,
          counts: { ...EMPTY_SEVERITY_COUNTS },
          usedInAttacks: 0,
          remote: 0,
          where: s.kind === "os" ? "Your Dockerfile's FROM line: a newer release of the distribution." : "The runtime version in your Dockerfile or build.",
          vulnerabilityIds: [],
        }));
    },
  },

  routes: [
    { prefix: "", access: "user", plugin: developerRoutes },
    { prefix: "/admin/developer", access: "admin", plugin: developerAdminRoutes },
  ],

  routeDocs: {
    "GET /api/v1/find": {
      summary: "One search box: projects, packages and vulnerabilities (CVE, GHSA) matching the text.",
      tag: "Developer view",
      auth: "user",
      notes: "Ten of each at most, within what the caller may read in the selected environment.",
    },
    "GET /api/v1/my-teams": {
      summary: "For each squad the caller leads: projects by status, late actions, accepted risks and the four-week trend.",
      tag: "Developer view",
      auth: "user",
      notes:
        "Only squads the caller leads; an administrator who leads none sees every squad. Projects are " +
        "limited to the selected environment and what the caller may read. Numbers match My projects " +
        "and each project's action plan.",
    },
    "GET /api/v1/my-teams/pdf": {
      summary: "The same as a PDF.",
      tag: "Developer view",
      auth: "user",
    },
    "GET /api/v1/admin/developer/targets": {
      summary: "Target dates: days to fix a vulnerability used in real attacks, a critical one and a high one.",
      tag: "Developer view",
      auth: "admin",
    },
    "PUT /api/v1/admin/developer/targets": {
      summary: "Change the target dates. Applies at once to every project's action plan and status.",
      tag: "Developer view",
      auth: "admin",
      body: targetDatesSchema,
      notes:
        "criticalDays is the same value as criticalFixDays in the needs-attention settings: " +
        "changing it here changes it there.",
    },
    "GET /api/v1/my-projects": {
      summary: "The caller's own projects - through their squads or granted to them - most urgent first.",
      tag: "Developer view",
      auth: "user",
      notes:
        "Each project has a status (fix-now, fix-soon, no-recent-build, nothing-to-do) and the " +
        "reason in words. Only projects in the selected environment that the caller may read.",
    },
    "GET /api/v1/applications/:id/action-plan": {
      summary: "One project's status and its action plan: one line per thing to do.",
      tag: "Developer view",
      auth: "user",
      notes:
        "Every vulnerability in the current build (accepted risks left out) is in exactly one line: " +
        "a package upgrade, the base-image rebuild, or the closing 'no fix yet' line.",
    },
  },
};
