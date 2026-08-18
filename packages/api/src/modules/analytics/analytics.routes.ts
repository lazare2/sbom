import type { FastifyInstance } from "fastify";
import {
  analyticsQuerySchema,
  coverageQuerySchema,
  normalizeVulnFilter,
  vulnFilterQuerySchema,
} from "@sbom/shared";
import { getUser } from "../../plugins/auth.plugin.js";
import { parseOrThrow } from "../../lib/validate.js";
import { renderReportPdf } from "../reports/pdf.js";

/**
 * Estate analytics and its printable form.
 *
 * Read-only and open to every authenticated user, matching the rest of the read
 * API: there is no per-application access model in this phase, so a report that
 * spans the estate is no more sensitive than the applications list it summarises.
 *
 * Both routes call `analytics.report()`. The JSON and the PDF are two renderings
 * of one payload rather than two query paths, which is what stops the printed
 * artifact and the screen from disagreeing about a figure.
 *
 * That is also why the PDF accepts the vulnerability filter. A screen showing four
 * critical findings next to a Download button that produced a report about four thousand
 * would be the precise drift this shape exists to prevent — so the filter travels with
 * the request, and the PDF prints what it was narrowed by.
 */
export async function analyticsRoutes(fastify: FastifyInstance): Promise<void> {
  const { analytics } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/report", async (request, reply) => {
    const query = parseOrThrow(analyticsQuerySchema, request.query, "Query");
    const report = await analytics.report({
      periodDays: query.periodDays,
      generatedBy: getUser(request).email,
      vulnFilter: normalizeVulnFilter(parseOrThrow(vulnFilterQuerySchema, request.query, "Query")),
    });
    return reply.send(report);
  });

  /**
   * Scan coverage on its own.
   *
   * The overview asks "which applications is nobody scanning" on every page load, and
   * answering it from the full report would mean computing churn, fragmentation and the
   * package rankings to display none of them. Same method as the report uses, so the two
   * can never disagree about which applications are stale.
   */
  fastify.get("/coverage", async (request, reply) => {
    const query = parseOrThrow(coverageQuerySchema, request.query, "Query");
    return reply.send(await analytics.coverage(query.limit));
  });

  /**
   * The same report as a PDF.
   *
   * A distinct URL ending in `.pdf` rather than content negotiation on `/report`:
   * this link is meant to be pasted into a browser, wired into a scheduled
   * `curl`, and saved to disk, and all three of those work better when the path
   * itself says what comes back.
   */
  fastify.get("/report.pdf", async (request, reply) => {
    const query = parseOrThrow(analyticsQuerySchema, request.query, "Query");
    const report = await analytics.report({
      periodDays: query.periodDays,
      generatedBy: getUser(request).email,
      vulnFilter: normalizeVulnFilter(parseOrThrow(vulnFilterQuerySchema, request.query, "Query")),
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
      // generation time — a cached copy would be a report that lies about its own
      // freshness.
      .header("Cache-Control", "no-store")
      .send(pdf);
  });
}
