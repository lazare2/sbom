import { buildApp } from "./app.js";
import { getConfig } from "./config.js";
import { closeDb } from "./db/client.js";
import { runModuleStartupChecks, startModuleJobs, stopModuleJobs } from "./modules/platform/lifecycle.js";

/** Expired sessions are swept hourly. */
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

async function main(): Promise<void> {
  const config = getConfig();
  const app = await buildApp({ config });

  // --- fail fast on a broken environment ----------------------------------
  // Better to refuse to start than to accept a scan and discover at write time
  // that the blob volume is read-only.
  await app.ctx.blobStore.verify();

  // --- configuration warnings ---------------------------------------------
  if (!app.ctx.ingestTokens.hasEnvTokens()) {
    app.log.warn(
      "No INGEST_TOKENS configured. CI/CD can only authenticate with tokens created through the admin API.",
    );
  }

  // --- modules -------------------------------------------------------------
  // Each module's background jobs and start-up checks, from the module list. See lifecycle.ts.
  await startModuleJobs(app.ctx, app.log);
  // Cheap and idempotent: it does nothing at all until an administrator enables report
  // delivery, and the database prevents a restart from resending a report already sent.
  app.ctx.reportScheduler.start();

  await runModuleStartupChecks(app.ctx, app.log);

  // --- housekeeping --------------------------------------------------------
  const cleanup = setInterval(() => {
    void (async () => {
      try {
        const sessionsRemoved = await app.ctx.sessions.deleteExpired();
        if (sessionsRemoved > 0) {
          app.log.info({ sessionsRemoved }, "expired session cleanup");
        }
      } catch (err) {
        app.log.error({ err }, "session cleanup failed");
      }
    })();
  }, CLEANUP_INTERVAL_MS);
  cleanup.unref();

  // --- graceful shutdown ---------------------------------------------------
  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ signal }, "shutting down");
    clearInterval(cleanup);
    // Stops new sweeps from starting. An in-flight one is left to finish: its writes
    // are idempotent upserts, and killing a grype subprocess mid-batch would just mean
    // the next start re-does that batch.
    stopModuleJobs(app.ctx);
    app.ctx.reportScheduler.stop();
    try {
      // Closes the server first so in-flight ingests finish before the pool goes
      // away - a half-committed scan would be worse than a slow shutdown.
      await app.close();
      await closeDb();
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, "error during shutdown");
      process.exit(1);
    }
  };

  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.on(signal, () => void shutdown(signal));
  }

  process.on("unhandledRejection", (reason) => {
    app.log.error({ err: reason }, "unhandled promise rejection");
  });

  await app.listen({ port: config.API_PORT, host: config.API_HOST });
  app.log.info(
    {
      port: config.API_PORT,
      env: config.NODE_ENV,
      blobStore: app.ctx.blobStore.name,
      authProviders: app.ctx.providers.all().map((p) => p.name),
    },
    "sbom api listening",
  );
}

main().catch((err: unknown) => {
  // The logger may not exist yet (e.g. config validation failed), so this is the
  // one place a bare console write is correct.
  console.error("failed to start server:", err);
  process.exit(1);
});
