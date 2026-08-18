import type { FastifyInstance } from "fastify";
import { generateReportSchema, idParamSchema } from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";

/**
 * The management report: generate, list, read.
 *
 * Registered inside the admin scope, so every route here inherits `requireAdmin`. That is a
 * stricter rule than the rest of the read API, which any authenticated user may call, and it
 * is deliberate: generating a report is a write that files a permanent record and moves
 * nothing else — but the history it writes into is the audit trail for what management was
 * told, and an ad-hoc run appearing in it should be attributable to a named person.
 */
export async function reportRoutes(fastify: FastifyInstance): Promise<void> {
  const { reports, audit } = fastify.ctx;

  fastify.get("/", async (_request, reply) => {
    return reply.send({ items: await reports.list() });
  });

  fastify.get("/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return reply.send(await reports.get(id));
  });

  /**
   * Generate a report now.
   *
   * Defaults to `adhoc`, which is what the button sends. An ad-hoc run is compared against
   * the last monthly report but never becomes the baseline for the next one, so pressing
   * this cannot quietly shorten next month's reporting period.
   */
  fastify.post("/", async (request, reply) => {
    const body = parseOrThrow(generateReportSchema, request.body ?? {}, "Body");
    const user = getUser(request);

    const result = await reports.generate({
      kind: body.kind,
      actor: { id: user.id, email: user.email },
    });

    await audit.record({
      actor: { id: user.id, email: user.email },
      action: "report.generate",
      targetType: "report_run",
      targetId: result.run.id,
      metadata: {
        kind: result.run.kind,
        period: result.run.periodLabel,
        // Recorded because it is the difference between "generated" and "already existed",
        // and a scheduler retry landing here should not read as a second report.
        alreadyExisted: result.alreadyExisted,
      },
    });

    // 200 rather than 201 when the monthly guard returned the existing run: nothing was
    // created, and a CI caller checking for 201 should be able to tell the two apart.
    return reply.status(result.alreadyExisted ? 200 : 201).send({
      run: result.run,
      delta: result.delta,
      alreadyExisted: result.alreadyExisted,
    });
  });
}
