import { buildApp } from "./app.js";
import { getConfig } from "./config.js";
import { closeDb } from "./db/client.js";

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

  // --- vulnerability scanning ----------------------------------------------
  /*
   * Started unconditionally. The worker's own first action on each heartbeat is to
   * check whether scanning is enabled, so on a deployment that has never turned it on
   * this costs one settings read per minute and nothing else. Starting it conditionally
   * would mean an admin enabling the feature had to restart the service for the
   * schedule to begin, which is exactly the kind of hidden requirement nobody discovers
   * until it matters.
   */
  /*
   * Close out any update claim left open by the previous run before the worker starts.
   * A killed process leaves a row with no finish time, which otherwise blocks the admin
   * panel's Update button for an hour while reporting an update that is not running.
   */
  const reconciled = await app.ctx.vulnDb.reconcileInterruptedUpdates().catch((err: unknown) => {
    app.log.warn({ err }, "could not reconcile interrupted vulnerability database updates");
    return 0;
  });
  if (reconciled > 0) {
    app.log.info({ reconciled }, "marked interrupted vulnerability database updates as failed");
  }

  app.ctx.vulnWorker.start();
  // Cheap and idempotent: it does nothing at all until an administrator enables report
  // delivery, and the database prevents a restart from resending a report already sent.
  app.ctx.reportScheduler.start();

  const scanning = await app.ctx.settings.vulnScanningEnabled();
  if (scanning) {
    const availability = await app.ctx.scanner.availability();
    if (!availability.available) {
      // Reported, not fatal. Everything except vulnerability data still works, and
      // refusing to boot over an optional feature would be a worse outcome than saying
      // clearly that it is unavailable.
      app.log.warn(
        { attempts: availability.attempts },
        "vulnerability scanning is enabled but the grype binary was not found — scanning is unavailable",
      );
    } else {
      app.log.info(
        { version: availability.version, resolvedBy: availability.resolvedBy, path: availability.path },
        "vulnerability scanner ready",
      );
    }
  } else {
    app.log.info("vulnerability scanning is disabled (enable it under Admin -> Vulnerability scanning)");
  }

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
    app.ctx.vulnWorker.stop();
    app.ctx.reportScheduler.stop();
    try {
      // Closes the server first so in-flight ingests finish before the pool goes
      // away — a half-committed scan would be worse than a slow shutdown.
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
