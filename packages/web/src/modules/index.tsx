import { AdminMaliciousPage } from "../pages/admin/AdminMaliciousPage.tsx";
import { AdminVulnerabilitiesPage } from "../pages/admin/AdminVulnerabilitiesPage.tsx";
import { MaliciousPage } from "../pages/MaliciousPage.tsx";
import { AdvisoryDetailPage, VulnerabilitiesPage } from "../pages/VulnerabilitiesPage.tsx";
import type { WebModule } from "./types.ts";

/**
 * Every module the web interface knows, in menu order. The ids match the server's list.
 *
 * Adding a module is adding it here; Layout.tsx, main.tsx and the admin layouts read this list
 * and name no module themselves.
 */
export const WEB_MODULES: readonly WebModule[] = [
  {
    id: "vulnerabilities",
    nav: [{ to: "/vulnerabilities", label: "Vulnerabilities" }],
    routes: [
      { path: "/vulnerabilities", element: <VulnerabilitiesPage /> },
      { path: "/vulnerabilities/:vulnerabilityId", element: <AdvisoryDetailPage /> },
    ],
    // Each page renders its own "not assessed" state, which says more than a generic one.
    pagesExplainDisabled: true,
    adminPages: [
      { path: "vulnerabilities", label: "Vulnerabilities", element: <AdminVulnerabilitiesPage />, section: "scanners" },
    ],
    adminRedirects: [{ from: "vulnerabilities", to: "/admin/scanners/vulnerabilities" }],
  },
  {
    id: "malicious",
    nav: [{ to: "/malicious", label: "Malicious packages" }],
    routes: [{ path: "/malicious", element: <MaliciousPage /> }],
    pagesExplainDisabled: true,
    adminPages: [
      { path: "malicious", label: "Malicious packages", element: <AdminMaliciousPage />, section: "scanners" },
    ],
    adminRedirects: [{ from: "malicious", to: "/admin/scanners/malicious" }],
  },
];
