import type { FastifyInstance } from "fastify";
import fp from "fastify-plugin";
import { buildContext, type AppContext, type BuildContextOverrides } from "../context.js";

declare module "fastify" {
  interface FastifyInstance {
    /** Application services. See src/context.ts for the dependency graph. */
    ctx: AppContext;
  }
}

/**
 * Builds the service graph and hangs it off the Fastify instance, so route
 * modules receive their dependencies from `fastify.ctx` instead of importing
 * singletons. That is what lets a test build an app with a fake blob store.
 */
export const contextPlugin = fp<BuildContextOverrides>(
  async (fastify: FastifyInstance, overrides) => {
    const ctx = buildContext(fastify.log, overrides);
    fastify.decorate("ctx", ctx);
  },
  { name: "app-context" },
);
