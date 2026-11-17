import { analyticsRoutes } from "../analytics/analytics.routes.js";
import { inventoryRoutes } from "../inventory/inventory.routes.js";
import type { PlatformModule } from "../platform/module.js";
import { settingToggle } from "../platform/toggles.js";
import { reportRoutes } from "../reports/reports.routes.js";

/**
 * Reports and analytics: the Analytics progress report, the Inventory, and the monthly report.
 *
 * Off: the Analytics and Inventory addresses answer `module_disabled`, the menu leaves them out
 * and no monthly report is generated or sent. Past monthly reports, their PDFs and every setting
 * stay; the admin page for the monthly report stays reachable.
 */
export const reportingModule: PlatformModule = {
  id: "reports",
  name: "Reports and analytics",
  description: "The Analytics progress report, the Inventory, and the monthly report sent by email.",

  toggle: settingToggle("reports", "/admin/reports"),

  routes: [
    { prefix: "/analytics", access: "user", plugin: analyticsRoutes, gated: true },
    { prefix: "/inventory", access: "user", plugin: inventoryRoutes, gated: true },
    { prefix: "/admin/reports", access: "admin", plugin: reportRoutes },
  ],

  jobs: [
    {
      name: "monthly report",
      // Cheap and idempotent: it does nothing until delivery is enabled and the module is on,
      // and the database prevents a restart from resending a report already sent.
      start: (ctx) => ctx.reportScheduler.start(),
      stop: (ctx) => ctx.reportScheduler.stop(),
    },
  ],
};
