import { requireScope } from "../environments/scope.js";
import type { FastifyInstance } from "fastify";
import { analyticsReportQuerySchema, coverageQuerySchema } from "@sbom/shared";
import { getUser } from "../../plugins/auth.plugin.js";
import { parseOrThrow } from "../../lib/validate.js";
import { renderReportPdf } from "../reports/pdf.js";

/**
 * Estate analytics and its printable form.
 *
 * Read-only and open to every authenticated user. Every figure describes the applications the
 * caller can see in the selected estate - access is applied before the squad / tribe / group
 * narrowing, so the narrowing can only ever take applications away.
 */
export async function analyticsRoutes(fastify: FastifyInstance): Promise<void> {
  const { analytics } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/report", async (request, reply) => {
    const { periodDays, ...filter } = parseOrThrow(analyticsReportQuerySchema, request.query, "Query");
    const report = await analytics.report({
      periodDays,
      filter,
      generatedBy: getUser(request).email,
      scope: await requireScope(request),
    });
    return reply.send(report);
  });

  fastify.get("/coverage", async (request, reply) => {
    const query = parseOrThrow(coverageQuerySchema, request.query, "Query");
    return reply.send(await analytics.coverage(query.limit, await requireScope(request)));
  });

  fastify.get("/report.pdf", async (request, reply) => {
    const { periodDays, ...filter } = parseOrThrow(analyticsReportQuerySchema, request.query, "Query");
    const report = await analytics.report({
      periodDays,
      filter,
      generatedBy: getUser(request).email,
      scope: await requireScope(request),
    });

    const pdf = await renderReportPdf(report);

    // Date-stamped filename so a folder of these sorts chronologically and two
    // downloads never silently overwrite each other.
    const stamp = report.meta.generatedAt.slice(0, 10);
    const filename = `sbom-estate-report-${stamp}.pdf`;

    return reply
      .header("Content-Type", "application/pdf")
      // `inline` so a browser previews it in a tab; the download attribute on the
      // UI's link is what forces a save when that is what the user asked for.
      .header("Content-Disposition", `inline; filename="${filename}"`)
      .header("Content-Length", String(pdf.length))
      // Regenerated from live data on every request, and the response embeds the
      // generation time - a cached copy would be a report that lies about its own
      // freshness.
      .header("Cache-Control", "no-store")
      .send(pdf);
  });
}
