import type { PlatformModule } from "../platform/module.js";
import { updateVulnSettings, vulnAdminRoutes } from "./vuln-admin.routes.js";
import { vulnerabilityRoutes, vulnStatusRoutes } from "./vulnerability.routes.js";

/**
 * Vulnerability scanning: Grype, Trivy, OSV and JFrog Xray matched against every stored SBOM.
 *
 * The switch is the existing `vuln.enabled` setting, so turning the module off and on here is
 * the same as doing it on its own settings page, and an installation upgraded from a version
 * without modules keeps its state.
 */
export const vulnerabilitiesModule: PlatformModule = {
  id: "vulnerabilities",
  name: "Vulnerabilities",
  description:
    "Checks every package against the vulnerability databases, keeps the results up to date and shows what to fix.",

  toggle: {
    enabled: (ctx) => ctx.settings.vulnScanningEnabled(),
    setEnabled: (ctx, enabled, actor) => updateVulnSettings(ctx, { enabled }, actor),
    settingsPath: "/admin/scanners/vulnerabilities",
  },

  routes: [
    /*
      Two scopes on purpose. `vulnerabilityRoutes` refuses with 409 `vuln_scanning_disabled`
      when the feature is off, so an unscanned estate can never be rendered as one with zero
      vulnerabilities. `vulnStatusRoutes` stays readable in that state, because the web
      interface has to tell "disabled" from "broken" to decide what to show.
    */
    { prefix: "", access: "user", plugin: vulnerabilityRoutes },
    { prefix: "/vuln-status", access: "user", plugin: vulnStatusRoutes },
    { prefix: "/admin/vuln", access: "admin", plugin: vulnAdminRoutes },
  ],

  jobs: [
    {
      name: "vulnerability updates and sweeps",
      /*
        A killed process leaves an update row with no finish time, which otherwise blocks the
        admin panel's Update button for an hour while reporting an update that is not running.
      */
      reconcile: (ctx) => ctx.vulnDb.reconcileInterruptedUpdates(),
      /*
        Started whether or not scanning is on. The worker's first action on each heartbeat is
        to check the switch, so a deployment that never turns it on pays one settings read a
        minute - and an administrator turning it on does not have to restart anything.
      */
      start: (ctx) => ctx.vulnWorker.start(),
      // Stops new sweeps from starting. An in-flight one is left to finish: its writes are
      // idempotent upserts, and killing a scanner mid-batch only means the next start redoes it.
      stop: (ctx) => ctx.vulnWorker.stop(),
    },
  ],

  async startupCheck(ctx) {
    if (!(await ctx.settings.vulnScanningEnabled())) {
      ctx.logger.info("vulnerability scanning is disabled (enable it under Admin -> Modules)");
      return;
    }
    const availability = await ctx.scanner.availability();
    if (!availability.available) {
      // Reported, not fatal. Everything except vulnerability data still works.
      ctx.logger.warn(
        { attempts: availability.attempts },
        "vulnerability scanning is enabled but the grype binary was not found - scanning is unavailable",
      );
    } else {
      ctx.logger.info(
        { version: availability.version, resolvedBy: availability.resolvedBy, path: availability.path },
        "vulnerability scanner ready",
      );
    }
  },
};
