import { readAccess } from "../environments/scope.js";
import type { FastifyInstance, FastifyReply } from "fastify";
import {
  EXPORT_MEDIA_TYPES,
  exportFilename,
  exportQuerySchema,
  supportsFlavour,
  type ExportQuery,
} from "@sbom/shared";
import { idParamSchema } from "@sbom/shared";
import { AppError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validate.js";
import { renderCycloneDx } from "./cyclonedx.render.js";
import { renderSpdx } from "./spdx.render.js";
import { renderVex } from "./vex.render.js";
import type { ExportDocument, VexDocument } from "./export.types.js";

/**
 * Machine-readable exports of the inventory.
 *
 * Read-only and session-authenticated, like every other read path. Deliberately *not*
 * admin-only: an export is the same information the caller can already page through in the
 * UI, in a shape a tool can read, and gating it behind admin would push people back to
 * copying tables out of the browser.
 *
 * The raw upload stays where it was, at `/scans/:id/raw`. That endpoint answers "what did
 * the pipeline produce"; these answer "what does the platform hold". Merging them would mean
 * one URL whose bytes changed meaning depending on a query parameter.
 */
export async function exportRoutes(fastify: FastifyInstance): Promise<void> {
  const { exports } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/applications/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseQuery(request.query);
    return send(reply, await exports.forApplication(id, query.flavour, await readAccess(request)), query);
  });

  fastify.get("/scans/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseQuery(request.query);
    return send(reply, await exports.forScan(id, query.flavour, await readAccess(request)), query);
  });

  fastify.get("/groups/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseQuery(request.query);
    return send(reply, await exports.forGroup(id, query.flavour, await readAccess(request)), query);
  });

  /*
    VEX is its own document rather than a format option, because it answers a different
    question. The SBOM says what is in the product; the VEX says what the organisation
    believes about it. They are published together and updated on different schedules -- an
    assessment changes when somebody investigates, an inventory only when the build changes --
    which is exactly the arrangement the format was designed for.

    Always CycloneDX: SPDX 2.3 has nowhere to put an analysis, so there is no choice to offer.
  */
  fastify.get("/applications/:id/vex", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return sendVex(reply, await exports.vexForApplication(id, await readAccess(request)));
  });

  fastify.get("/scans/:id/vex", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return sendVex(reply, await exports.vexForScan(id, await readAccess(request)));
  });

  fastify.get("/groups/:id/vex", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return sendVex(reply, await exports.vexForGroup(id, await readAccess(request)));
  });
}

/**
 * Rejects the one combination that cannot be honoured, rather than downgrading it.
 *
 * SPDX 2.3 has nowhere to put a finding. Silently serving the inventory instead would hand
 * back a document that looks like the one that was asked for and is missing the entire
 * reason it was asked for -- and the caller would have no way to tell, because a package
 * list with no findings is exactly what a clean estate also looks like.
 */
function parseQuery(raw: unknown): ExportQuery {
  const query = parseOrThrow(exportQuerySchema, raw, "Query");
  if (!supportsFlavour(query.format, query.flavour)) {
    throw new AppError({
      statusCode: 400,
      code: "export_flavour_unsupported",
      message:
        "SPDX 2.3 has no representation for vulnerability findings. Request format=cyclonedx for an enriched export, or flavour=inventory for SPDX.",
    });
  }
  return query;
}

function send(reply: FastifyReply, doc: ExportDocument, query: ExportQuery): FastifyReply {
  const body = query.format === "spdx" ? renderSpdx(doc) : renderCycloneDx(doc);
  const filename = exportFilename({
    subject: doc.subject.name,
    format: query.format,
    flavour: query.flavour,
  });

  /*
    Serialised here rather than handed to Fastify's serialiser so the Content-Type can be the
    format's own media type. `application/vnd.cyclonedx+json` is what makes a downloaded file
    recognisable to the tools that consume it; a generic `application/json` would still parse
    but tells the consumer nothing about which of the two formats it is holding.
  */
  const json = JSON.stringify(body, null, 2);
  return reply
    .header("Content-Type", `${EXPORT_MEDIA_TYPES[query.format]}; charset=utf-8`)
    .header("Content-Disposition", `attachment; filename="${filename}"`)
    .header("Content-Length", String(Buffer.byteLength(json, "utf8")))
    .send(json);
}

function sendVex(reply: FastifyReply, doc: VexDocument): FastifyReply {
  const json = JSON.stringify(renderVex(doc), null, 2);
  const stem = exportFilename({
    subject: doc.subject.name,
    format: "cyclonedx",
    flavour: "inventory",
  }).replace(/-cyclonedx\.json$/, "-vex.json");

  return reply
    .header("Content-Type", `${EXPORT_MEDIA_TYPES.cyclonedx}; charset=utf-8`)
    .header("Content-Disposition", `attachment; filename="${stem}"`)
    .header("Content-Length", String(Buffer.byteLength(json, "utf8")))
    .send(json);
}
