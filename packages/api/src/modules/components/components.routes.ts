import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  bulkSearchBodySchema,
  bulkSearchQuerySchema,
  componentSearchQuerySchema,
  componentSuggestQuerySchema,
  idParamSchema,
} from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import { renderBulkXlsx } from "./bulk-xlsx.js";

/**
 * Rows the Excel export will include on its Matches sheet.
 *
 * A spreadsheet is the one consumer that wants the whole result set rather than a
 * page of it, but "whole" still needs a ceiling — a 1000-entry list against a
 * large estate could otherwise build a workbook in memory that nobody can open.
 * Exceeding it is stated on the sheet rather than silently trimmed.
 */
const XLSX_MATCH_CAP = 20_000;

/** Global cross-application component search. Read-only, any authenticated user. */
export async function componentRoutes(fastify: FastifyInstance): Promise<void> {
  const { components, bulkSearch } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/search", async (request, reply) => {
    const query = parseOrThrow(componentSearchQuerySchema, request.query, "Query");
    return reply.send(await components.search(query));
  });

  fastify.get(
    "/suggest",
    {
      // Fires on keystrokes, so it gets a higher ceiling than the default but is
      // still bounded — a held-down key should not become a load generator.
      config: { rateLimit: { max: 600, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      const query = parseOrThrow(componentSuggestQuerySchema, request.query, "Query");
      return reply.send({ suggestions: await components.suggest(query) });
    },
  );

  fastify.get("/ecosystems", async (_request, reply) => {
    return reply.send({ ecosystems: await components.listEcosystems() });
  });

  /** Every known version of a package, with how many applications ship each. */
  fastify.get("/versions", async (request, reply) => {
    const { name } = parseOrThrow(
      z.object({ name: z.string().trim().min(1).max(255) }),
      request.query,
      "Query",
    );
    return reply.send({ name, versions: await components.listVersions(name) });
  });

  // --- bulk package list search --------------------------------------------

  /**
   * Search a pasted list of packages.
   *
   * POST rather than GET because a list of several hundred packages does not fit
   * in a request line — nginx caps it around 8 KB. The response carries a
   * `queryId` for the saved list, which is what gives the results an address
   * despite the body-bearing request.
   */
  fastify.post("/bulk-search", async (request, reply) => {
    const body = parseOrThrow(bulkSearchBodySchema, request.body, "Body");
    const { input, ...query } = body;
    return reply.send(
      await bulkSearch.submit({ input, query, userId: getUser(request).id }),
    );
  });

  /**
   * Re-run a saved list.
   *
   * Recomputed on every open rather than served from a cache: which applications
   * ship a package changes with every scan, and a stored answer behind a permanent
   * link would be stale data wearing a current URL.
   */
  fastify.get("/bulk-search/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseOrThrow(bulkSearchQuerySchema, request.query, "Query");
    const result = await bulkSearch.rerun({ queryId: id, query });
    // The raw text goes back too, so opening a shared link repopulates the input
    // box — including the lines that failed to parse, which are the ones the
    // recipient will want to fix.
    return reply.send({ ...result, input: await bulkSearch.savedInput(id) });
  });

  /** Recently used lists, so a colleague's audit is one click away rather than a re-paste. */
  fastify.get("/bulk-search", async (request, reply) => {
    const { limit } = parseOrThrow(
      z.object({ limit: z.coerce.number().int().min(1).max(50).default(10) }),
      request.query,
      "Query",
    );
    return reply.send({ lists: await bulkSearch.recentLists(limit) });
  });

  /**
   * The results as a real .xlsx workbook.
   *
   * A GET on the saved list, which is the payoff for persisting it: the download
   * is a plain link the browser handles, with no need to re-post the body or
   * synthesise a blob URL on the client.
   */
  fastify.get("/bulk-search/:id/export.xlsx", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseOrThrow(bulkSearchQuerySchema, request.query, "Query");

    const result = await bulkSearch.rerun({ queryId: id, query });
    const { entries } = bulkSearch.parse(await bulkSearch.savedInput(id));
    const matches = await bulkSearch.allMatches(entries, query, XLSX_MATCH_CAP);

    const user = getUser(request);
    const workbook = await renderBulkXlsx({
      result,
      matches: matches.items,
      matchesTruncated: matches.truncated,
      generatedAt: new Date(),
      generatedBy: user.email,
      listUrl: `${fastify.ctx.config.PUBLIC_URL}/search/list/${id}`,
      vulnScanningEnabled: await fastify.ctx.settings.vulnScanningEnabled(),
    });

    const stamp = new Date().toISOString().slice(0, 10);
    return reply
      .header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
      // `attachment`: a browser cannot render a workbook inline, so offering to
      // preview it would just be a failed navigation.
      .header("Content-Disposition", `attachment; filename="package-list-${stamp}.xlsx"`)
      .header("Content-Length", String(workbook.length))
      .header("Cache-Control", "no-store")
      .send(workbook);
  });
}
