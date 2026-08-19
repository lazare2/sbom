import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import multipart from "@fastify/multipart";
import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance } from "fastify";
import { getConfig, type Config } from "./config.js";
import type { BuildContextOverrides } from "./context.js";
import { sha256Hex } from "./lib/crypto.js";
import { adminRoutes } from "./modules/admin/admin.routes.js";
import { analyticsRoutes } from "./modules/analytics/analytics.routes.js";
import { applicationRoutes } from "./modules/applications/applications.routes.js";
import { groupRoutes } from "./modules/groups/groups.routes.js";
import { attributeRoutes } from "./modules/attributes/attributes.routes.js";
import { authRoutes } from "./modules/auth/auth.routes.js";
import { componentRoutes } from "./modules/components/components.routes.js";
import { dashboardRoutes } from "./modules/dashboard/dashboard.routes.js";
import { healthRoutes } from "./modules/health/health.routes.js";
import { ingestionRoutes } from "./modules/ingestion/ingestion.routes.js";
import { manualUploadRoutes } from "./modules/ingestion/manual-upload.routes.js";
import {
  vulnerabilityRoutes,
  vulnStatusRoutes,
} from "./modules/vulnerabilities/vulnerability.routes.js";
import { reportRoutes } from "./modules/reports/reports.routes.js";
import { scanRoutes } from "./modules/scans/scans.routes.js";
import { authPlugin } from "./plugins/auth.plugin.js";
import { contextPlugin } from "./plugins/context.plugin.js";
import { errorHandlerPlugin } from "./plugins/error-handler.plugin.js";

export interface BuildAppOptions extends BuildContextOverrides {
  config?: Config;
}

/**
 * Builds the Fastify instance without starting it, so tests can drive it through
 * `app.inject()` and the server bootstrap can own listening and shutdown.
 */
export async function buildApp(options: BuildAppOptions = {}): Promise<FastifyInstance> {
  const config = options.config ?? getConfig();

  const app = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      // Never log a credential, a session cookie, or a reset link.
      redact: {
        paths: [
          "req.headers.authorization",
          "req.headers.cookie",
          "res.headers['set-cookie']",
          "body.password",
          "body.newPassword",
          "body.currentPassword",
          "body.token",
        ],
        censor: "[redacted]",
      },
      ...(config.isProduction ? {} : { transport: undefined }),
    },
    // Sits behind nginx in the compose deployment, so trust the proxy's
    // X-Forwarded-* headers — otherwise every client IP logs as the proxy's and
    // rate limiting buckets the whole organisation together.
    trustProxy: true,
    // Ingest SBOMs are large; the multipart plugin enforces the real limit per
    // file, this is the JSON-body ceiling for the rest of the API.
    bodyLimit: 1024 * 1024,
  });

  // --- security & parsing ---------------------------------------------------
  await app.register(helmet, {
    // The API serves JSON only — the SPA is served by nginx (or Vite in dev),
    // which owns its own CSP. Enabling one here would only apply to error pages.
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "same-site" },
  });

  await app.register(cors, {
    // In the compose deployment the SPA is same-origin behind nginx and CORS is
    // unused. In development the Vite dev server is on another port, so the
    // public URL has to be allowed explicitly — with credentials, since auth is
    // a cookie.
    origin: [config.PUBLIC_URL, ...config.CORS_ORIGINS],
    credentials: true,
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
  });

  await app.register(cookie, {
    secret: config.SESSION_SECRET,
    parseOptions: { path: "/" },
  });

  await app.register(multipart, {
    limits: {
      fileSize: config.INGEST_MAX_SBOM_BYTES,
      files: 1,
      // app_name, commit_sha, build_number, pipeline_id, image_ref, branch, plus
      // room for CI templates that add fields we don't read yet.
      fields: 20,
      fieldSize: 8192,
    },
  });

  await app.register(rateLimit, {
    global: true,
    max: 300,
    timeWindow: "1 minute",
    // Health checks and the ingest endpoint set their own limits.
    allowList: () => false,
  });

  // --- application wiring --------------------------------------------------
  await app.register(errorHandlerPlugin);
  await app.register(contextPlugin, {
    ...(options.db ? { db: options.db } : {}),
    ...(options.blobStore ? { blobStore: options.blobStore } : {}),
    ...(options.scanner ? { scanner: options.scanner } : {}),
    config,
  });
  await app.register(authPlugin);

  // --- routes ---------------------------------------------------------------
  await app.register(healthRoutes);

  await app.register(
    async (api) => {
      await api.register(authRoutes, { prefix: "/auth" });

      // Read APIs. Each of these applies `requireAuth` to its own scope, so a
      // session is required; the ingest scope below is deliberately separate so
      // its bearer-token auth and these session guards can never cross over.
      await api.register(applicationRoutes, { prefix: "/applications" });
      // Manual SBOM upload. Session-authenticated like the reads above, but a
      // write, so it lives in its own scope under the same prefix rather than in
      // the read-only applications plugin.
      await api.register(manualUploadRoutes, { prefix: "/applications" });
      await api.register(groupRoutes, { prefix: "/groups" });
      await api.register(scanRoutes, { prefix: "/scans" });
      await api.register(componentRoutes, { prefix: "/components" });
      await api.register(attributeRoutes, { prefix: "/attribute-definitions" });
      await api.register(dashboardRoutes, { prefix: "/dashboard" });
      await api.register(analyticsRoutes, { prefix: "/analytics" });

      /*
       * Vulnerability reads, in two scopes on purpose.
       *
       * `vulnerabilityRoutes` refuses with 409 `vuln_scanning_disabled` when the
       * feature is off, so an unscanned estate can never be rendered as one with zero
       * vulnerabilities. `vulnStatusRoutes` stays readable in that state, because the
       * SPA has to be able to tell "disabled" from "broken" to decide what to show.
       */
      await api.register(vulnerabilityRoutes, { prefix: "" });
      await api.register(vulnStatusRoutes, { prefix: "/vuln-status" });

      // Write APIs. Guarded as a whole scope by `requireAdmin`, so a route
      // added to that file is protected whether or not its author thought about it.
      await api.register(adminRoutes, { prefix: "/admin" });
      // Inside the admin prefix but its own plugin, because it applies `requireAdmin`
      // itself: registering it as part of `adminRoutes` would work today and silently stop
      // working the day someone splits that file.
      await api.register(
        async (scoped) => {
          scoped.addHook("preHandler", scoped.requireAdmin);
          await scoped.register(reportRoutes);
        },
        { prefix: "/admin/reports" },
      );

      await api.register(
        async (scoped) => {
          // The ingest endpoint authenticates with a shared CI bearer token, not
          // a user session, and is bucketed per token rather than per IP: CI
          // runners commonly share a NAT address, so IP buckets would make one
          // busy runner throttle everyone else's builds.
          scoped.addHook("onRoute", (route) => {
            route.config = {
              ...route.config,
              rateLimit: {
                ...(typeof route.config?.rateLimit === "object" ? route.config.rateLimit : {}),
                keyGenerator: (request) => {
                  const header = request.headers.authorization;
                  return header ? `ingest:${sha256Hex(header)}` : `ingest-anon:${request.ip}`;
                },
              },
            };
          });
          await scoped.register(ingestionRoutes);
        },
        { prefix: "" },
      );
    },
    { prefix: "/api/v1" },
  );

  return app;
}
