import { sql } from "drizzle-orm";
import type { FastifyInstance } from "fastify";

/**
 * Liveness and readiness, kept separate on purpose.
 *
 * `/health` answers "is this process up" and must never touch the database — a
 * DB blip should not make an orchestrator kill an otherwise healthy container.
 * `/health/ready` answers "can this instance serve traffic" and does check.
 */
export async function healthRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.get("/health", { config: { rateLimit: false } }, async () => ({
    status: "ok",
    uptimeSeconds: Math.round(process.uptime()),
  }));

  fastify.get("/health/ready", { config: { rateLimit: false } }, async (_request, reply) => {
    const checks: Record<string, "ok" | "error"> = {};

    try {
      await fastify.ctx.db.execute(sql`select 1`);
      checks.database = "ok";
    } catch (err) {
      fastify.log.error({ err }, "readiness: database check failed");
      checks.database = "error";
    }

    const ready = Object.values(checks).every((v) => v === "ok");
    return reply.status(ready ? 200 : 503).send({ status: ready ? "ready" : "unready", checks });
  });
}
