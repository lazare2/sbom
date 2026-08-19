import type { FastifyInstance } from "fastify";
import { normalizeVulnFilter, topComponentsQuerySchema, vulnFilterQuerySchema } from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";

/**
 * Estate-wide analytics. Read-only and available to every authenticated user,
 * matching the access model for the rest of the read API.
 */
export async function dashboardRoutes(fastify: FastifyInstance): Promise<void> {
  const { dashboard, analytics, settings , groups } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  /**
   * Resolves the filter, looking up the selected group's name.
   *
   * The lookup happens here rather than inside `normalizeVulnFilter` because that function is
   * pure and shared with the client. One extra query only when a group is actually selected.
   */
  async function resolveFilter(rawQuery: unknown) {
    const query = parseOrThrow(vulnFilterQuerySchema, rawQuery, "Query");
    const groupName = query.group ? await groups.nameById(query.group) : null;
    return normalizeVulnFilter(query, groupName);
  }

  /**
   * Vulnerability posture for the overview page.
   *
   * Returns `{ vulnerabilities: null }` when scanning is disabled rather than 409, unlike
   * the dedicated vulnerability routes. The difference is intentional: the overview page
   * loads this on every visit and has to render *something* either way, so a null it can
   * branch on is more useful than an error it has to catch. What it must never do is
   * render a zero — that is the client's obligation and the reason this is null-or-object
   * rather than a zero-filled struct.
   *
   * Delegates to the analytics service so the overview cards and the report's
   * vulnerability section are the same numbers from the same query.
   *
   * Accepts the same `scope` and `severity` filter the analytics page uses, so a filter
   * set on one dashboard produces identical figures on the other. The filter is echoed
   * back on the payload rather than left for the client to remember, which is what lets
   * the page state what it is showing without reconstructing it from its own URL.
   */
  fastify.get("/vulnerabilities", async (request, reply) => {
    if (!(await settings.vulnScanningEnabled())) {
      return reply.send({ vulnerabilities: null });
    }
    const filter = await resolveFilter(request.query);
    return reply.send({ vulnerabilities: await analytics.vulnerabilities(filter, 10) });
  });

  fastify.get("/stats", async (_request, reply) => {
    return reply.send(await dashboard.stats());
  });

  fastify.get("/ecosystems", async (_request, reply) => {
    return reply.send({ ecosystems: await dashboard.ecosystems() });
  });

  /**
   * OS and runtime counts across current builds. Doubles as the option source
   * for the applications list's platform filters.
   */
  fastify.get("/platforms", async (_request, reply) => {
    return reply.send(await dashboard.platforms());
  });

  fastify.get("/top-components", async (request, reply) => {
    const query = parseOrThrow(topComponentsQuerySchema, request.query, "Query");
    return reply.send({ components: await dashboard.topComponents(query) });
  });
}
