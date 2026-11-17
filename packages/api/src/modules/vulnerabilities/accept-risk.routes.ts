import { sql } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import { acceptRiskSchema, idParamSchema } from "@sbom/shared";
import { ForbiddenError } from "../../lib/errors.js";
import { rowsOf, type Row } from "../../lib/rows.js";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import { readAccess } from "../environments/scope.js";
import { isLeadOf } from "../squads/leads.js";

/**
 * "Accept risk" for team leads: one project of a squad they lead, a reason, an end date.
 *
 * Decided alone - there is no request step and developers cannot ask (a product decision). An
 * administrator may use this too; their wider, estate-wide option stays on the admin routes.
 *
 * The result is an ordinary accepted risk (`vulnerability_suppression`), so every count, list,
 * export and VEX document already honours it, and it stops applying when its end date passes.
 */
export async function acceptRiskRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.addHook("preHandler", fastify.requireAuth);
  const { vulnerabilities, applications, audit, vulnWorker, db } = fastify.ctx;

  fastify.post("/applications/:id/accepted-risks", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(acceptRiskSchema, request.body);
    const user = getUser(request);

    // Outside the caller's access is a 404, exactly as reading the project would be.
    await applications.getById(id, await readAccess(request));
    if (user.role !== "admin" && !(await isLeadOf(db, user.id, id))) {
      throw new ForbiddenError("Only a team lead of this project's squad, or an administrator, can accept a risk here.");
    }

    const env = await db.execute<Row<{ environment_id: string }>>(sql`
      SELECT environment_id FROM application WHERE id = ${id}::uuid
    `);
    const environmentId = rowsOf(env)[0]!.environment_id;
    const actor = {
      id: user.id,
      email: user.email,
      ...(request.apiToken ? { viaToken: request.apiToken.name } : {}),
    };
    const created = await vulnerabilities.createSuppression(
      {
        vulnerabilityId: body.vulnerabilityId,
        ...(body.componentId !== undefined ? { componentId: body.componentId } : {}),
        applicationId: id,
        reason: body.reason,
        expiresAt: body.expiresAt,
        vexStatus: body.vexStatus,
        ...(body.vexJustification ? { vexJustification: body.vexJustification } : {}),
      },
      actor,
      environmentId,
    );

    await audit.record({
      actor,
      action: "vuln.suppression_create",
      targetType: "vulnerability",
      targetId: body.vulnerabilityId,
      metadata: {
        reason: body.reason,
        componentId: body.componentId ?? null,
        applicationId: id,
        expiresAt: body.expiresAt,
        vexStatus: body.vexStatus,
        vexJustification: body.vexJustification ?? null,
        acceptedAs: user.role === "admin" ? "administrator" : "team lead",
      },
    });

    // Snapshots exclude accepted risks, so the dashboards are rebuilt as on the admin route.
    vulnWorker.requestSummaryRefresh();
    return reply.status(201).send(created);
  });
}
