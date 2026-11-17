import type { FastifyBaseLogger } from "fastify";
import type { AppContext } from "../../context.js";

/**
 * Starts every module's background jobs.
 *
 * Every job is started whether or not its module is switched on: the job's own first action on
 * each heartbeat is to check the switch, so an administrator turning a module on never has to
 * restart the service.
 *
 * Before starting, each job closes out work a killed process left marked as running, which
 * otherwise shows the admin panel a spinner that never stops. A failure there is logged and the
 * job starts anyway; one module's problem never keeps another's jobs from running.
 */
export async function startModuleJobs(ctx: AppContext, log: FastifyBaseLogger): Promise<void> {
  for (const module of ctx.modules.list) {
    for (const job of module.jobs ?? []) {
      if (job.reconcile) {
        const reconciled = await job.reconcile(ctx).catch((err: unknown) => {
          log.warn({ err, module: module.id }, `could not reconcile interrupted ${job.name}`);
          return 0;
        });
        if (reconciled > 0) {
          log.info({ reconciled, module: module.id }, `marked interrupted ${job.name} as failed`);
        }
      }
      job.start(ctx);
    }
  }
}

/** Stops every module's jobs. Work already in flight is left to finish. */
export function stopModuleJobs(ctx: AppContext): void {
  for (const module of ctx.modules.list) {
    for (const job of module.jobs ?? []) job.stop(ctx);
  }
}

/** Each module's start-up check. Reported, never fatal. */
export async function runModuleStartupChecks(ctx: AppContext, log: FastifyBaseLogger): Promise<void> {
  for (const module of ctx.modules.list) {
    await module.startupCheck?.(ctx).catch((err: unknown) => {
      log.warn({ err, module: module.id }, "module start-up check failed");
    });
  }
}
