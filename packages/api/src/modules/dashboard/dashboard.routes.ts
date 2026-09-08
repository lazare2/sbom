import { readAccess, requireScope } from "../environments/scope.js";
import type { ReadAccess } from "../environments/environment.service.js";
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
  async function resolveFilter(rawQuery: unknown, access: ReadAccess) {
    const query = parseOrThrow(vulnFilterQuerySchema, rawQuery, "Query");
    // A group the caller cannot reach resolves to no name, and the filter falls back to
    // the whole estate rather than labelling itself with another estate's group.
    const groupName = query.group ? await groups.nameById(query.group, access) : null;
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
    const filter = await resolveFilter(request.query, await readAccess(request));
    return reply.send({
      vulnerabilities: await analytics.vulnerabilities(filter, 10, await requireScope(request)),
    });
  });

  /**
   * Malicious packages across the estate, or null.
   *
   * Null whenever detection is off or no feed has been installed -- never a block of zeros.
   * A zeroed panel here would read as "no malicious packages found", which is the strongest
   * and most dangerous claim this platform could make without having looked.
   */
  fastify.get("/malicious", async (request, reply) => {
    return reply.send({
      malicious: await fastify.ctx.malicious.summary(await requireScope(request)),
    });
  });

  fastify.get("/stats", async (request, reply) => {
    return reply.send(await dashboard.stats(await requireScope(request)));
  });

  fastify.get("/ecosystems", async (request, reply) => {
    return reply.send({ ecosystems: await dashboard.ecosystems(await requireScope(request)) });
  });

  /**
   * OS and runtime counts across current builds. Doubles as the option source
   * for the applications list's platform filters.
   */
  fastify.get("/platforms", async (request, reply) => {
    return reply.send(await dashboard.platforms(await requireScope(request)));
  });

  fastify.get("/top-components", async (request, reply) => {
    const query = parseOrThrow(topComponentsQuerySchema, request.query, "Query");
    return reply.send({
      components: await dashboard.topComponents(query, await requireScope(request)),
    });
  });
}
