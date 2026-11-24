import { lazy } from "react";
import type { WebModule } from "./types.ts";

/*
  Every page is loaded only when it is first opened: each `lazy` import becomes its own file in
  the build, so signing in does not download the Analytics charts or the admin screens.
*/
const MyProjectsPage = lazy(() => import("../pages/MyProjectsPage.tsx").then((m) => ({ default: m.MyProjectsPage })));
const MyTeamsPage = lazy(() => import("../pages/MyTeamsPage.tsx").then((m) => ({ default: m.MyTeamsPage })));
const FindPage = lazy(() => import("../pages/FindPage.tsx").then((m) => ({ default: m.FindPage })));
const PackagePage = lazy(() => import("../pages/PackagePage.tsx").then((m) => ({ default: m.PackagePage })));
const VulnerabilitiesPage = lazy(() =>
  import("../pages/VulnerabilitiesPage.tsx").then((m) => ({ default: m.VulnerabilitiesPage })),
);
const AdvisoryDetailPage = lazy(() =>
  import("../pages/VulnerabilitiesPage.tsx").then((m) => ({ default: m.AdvisoryDetailPage })),
);
const MaliciousPage = lazy(() => import("../pages/MaliciousPage.tsx").then((m) => ({ default: m.MaliciousPage })));
const AdminVulnerabilitiesPage = lazy(() =>
  import("../pages/admin/AdminVulnerabilitiesPage.tsx").then((m) => ({ default: m.AdminVulnerabilitiesPage })),
);
const AdminMaliciousPage = lazy(() =>
  import("../pages/admin/AdminMaliciousPage.tsx").then((m) => ({ default: m.AdminMaliciousPage })),
);
const InventoryPage = lazy(() => import("../pages/InventoryPage.tsx").then((m) => ({ default: m.InventoryPage })));
const AnalyticsPage = lazy(() => import("../pages/AnalyticsPage.tsx").then((m) => ({ default: m.AnalyticsPage })));
const AdminReportsPage = lazy(() =>
  import("../pages/admin/AdminReportsPage.tsx").then((m) => ({ default: m.AdminReportsPage })),
);
const GroupsPage = lazy(() => import("../pages/GroupsPage.tsx").then((m) => ({ default: m.GroupsPage })));
const AdminDirectoryPage = lazy(() =>
  import("../pages/admin/AdminDirectoryPage.tsx").then((m) => ({ default: m.AdminDirectoryPage })),
);
const GroupDetailPage = lazy(() => import("../pages/GroupDetailPage.tsx").then((m) => ({ default: m.GroupDetailPage })));

/**
 * Every module the web interface knows, in menu order. The ids match the server's list.
 *
 * Adding a module is adding it here; Layout.tsx, main.tsx and the admin layouts read this list
 * and name no module themselves.
 */
export const WEB_MODULES: readonly WebModule[] = [
  {
    // Always on: the server has no switch for it, so it is always in the enabled list.
    id: "developer",
    nav: [
      { to: "/my-teams", label: "My teams", section: "you", visibleTo: (u) => u.isTeamLead === true || u.role === "admin" },
      { to: "/my-projects", label: "My projects", section: "you" },
    ],
    routes: [
      { path: "/my-projects", element: <MyProjectsPage /> },
      { path: "/my-teams", element: <MyTeamsPage /> },
      { path: "/find", element: <FindPage /> },
      { path: "/packages/:ecosystem/:name", element: <PackagePage /> },
    ],
  },
  {
    id: "organisation",
    nav: [{ to: "/groups", label: "Groups", section: "estate" }],
    routes: [
      { path: "/groups", element: <GroupsPage /> },
      { path: "/groups/:id", element: <GroupDetailPage /> },
    ],
  },
  {
    id: "vulnerabilities",
    nav: [{ to: "/vulnerabilities", label: "Vulnerabilities", section: "estate" }],
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
    nav: [{ to: "/malicious", label: "Malicious packages", section: "estate" }],
    routes: [{ path: "/malicious", element: <MaliciousPage /> }],
    pagesExplainDisabled: true,
    adminPages: [
      { path: "malicious", label: "Malicious packages", element: <AdminMaliciousPage />, section: "scanners" },
    ],
    adminRedirects: [{ from: "malicious", to: "/admin/scanners/malicious" }],
  },
  {
    id: "reports",
    nav: [
      { to: "/inventory", label: "Inventory", section: "reports" },
      { to: "/analytics", label: "Analytics", section: "reports" },
    ],
    routes: [
      { path: "/inventory", element: <InventoryPage /> },
      { path: "/analytics", element: <AnalyticsPage /> },
    ],
    // The monthly report's settings and past reports stay reachable while the module is off.
    adminPages: [{ path: "reports", label: "Monthly report", element: <AdminReportsPage /> }],
  },
  {
    id: "directory",
    // Set up and tested while the module is off, so its page is always reachable.
    adminPages: [{ path: "directory", label: "Directory", element: <AdminDirectoryPage /> }],
  },
];
