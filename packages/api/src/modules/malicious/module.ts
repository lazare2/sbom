import type { PlatformModule } from "../platform/module.js";
import { maliciousAdminRoutes } from "./malicious-admin.routes.js";
import { maliciousRoutes, maliciousStatusRoutes } from "./malicious.routes.js";

/**
 * Malicious-package detection: the OpenSSF malicious-packages feed matched against every
 * stored SBOM, with optional mail alerts.
 *
 * The switch is the existing `malicious.enabled` setting, so turning it off and on here is the
 * same as on its own settings page, and an installation upgraded from a version without modules
 * keeps its state.
 */
export const maliciousModule: PlatformModule = {
  id: "malicious",
  name: "Malicious packages",
  description:
    "Checks every package against the OpenSSF list of known malicious packages and can send an alert when one turns up.",

  toggle: {
    enabled: async (ctx) => (await ctx.settings.getMaliciousSettings()).enabled,
    // Through the admin service, which writes the audit entry and fetches the feed on enable.
    setEnabled: async (ctx, enabled, actor) => {
      await ctx.adminMalicious.updateSettings({ enabled }, actor);
    },
    settingsPath: "/admin/scanners/malicious",
  },

  routes: [
    /*
      Split the same way as vulnerabilities, for the same reason: the findings route refuses
      with 409 while detection is off so an unchecked estate can never render as a clean one,
      while the status route stays readable so the interface can say which it is.
    */
    { prefix: "/malicious", access: "user", plugin: maliciousRoutes },
    { prefix: "/malicious-status", access: "user", plugin: maliciousStatusRoutes },
    { prefix: "/admin/malicious", access: "admin", plugin: maliciousAdminRoutes },
  ],

  jobs: [
    {
      name: "malicious feed refresh and matching",
      /*
        An attempt row with no finish time describes a refresh nothing is performing, and left
        alone it shows the admin page a spinner that never stops.
      */
      reconcile: (ctx) => ctx.maliciousFeed.reconcileInterrupted(),
      // Idempotent and inert until an administrator switches detection on.
      start: (ctx) => ctx.maliciousWorker.start(),
      stop: (ctx) => ctx.maliciousWorker.stop(),
    },
  ],
};
