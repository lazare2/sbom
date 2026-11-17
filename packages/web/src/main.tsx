import { lazy, StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { AuthProvider } from "./auth/AuthProvider.tsx";
import { RequireAdmin, RequireAuth } from "./auth/RequireAuth.tsx";
import { Layout } from "./components/Layout.tsx";
import { EnvironmentProvider } from "./environments/EnvironmentProvider.tsx";
import { EmptyState, Card, LoadingBlock } from "./components/ui.tsx";
import { ChangePasswordPage } from "./pages/ChangePasswordPage.tsx";
import { LoginPage } from "./pages/LoginPage.tsx";
import { AdminLayout } from "./pages/admin/AdminLayout.tsx";
import { WEB_MODULES } from "./modules/index.tsx";
import { ModuleGate } from "./modules/ModuleGate.tsx";
import { UnauthenticatedError } from "./lib/api.ts";
import "./index.css";

// Each page is its own file in the build, downloaded the first time it is opened.
const ApiAccessPage = lazy(() => import("./pages/ApiAccessPage.tsx").then((m) => ({ default: m.ApiAccessPage })));
const ApplicationDetailPage = lazy(() => import("./pages/ApplicationDetailPage.tsx").then((m) => ({ default: m.ApplicationDetailPage })));
const ApplicationsPage = lazy(() => import("./pages/ApplicationsPage.tsx").then((m) => ({ default: m.ApplicationsPage })));
const ComponentSearchPage = lazy(() => import("./pages/ComponentSearchPage.tsx").then((m) => ({ default: m.ComponentSearchPage })));
const DashboardPage = lazy(() => import("./pages/DashboardPage.tsx").then((m) => ({ default: m.DashboardPage })));
const ScanDetailPage = lazy(() => import("./pages/ScanDetailPage.tsx").then((m) => ({ default: m.ScanDetailPage })));
const ScanDiffPage = lazy(() => import("./pages/ScanDiffPage.tsx").then((m) => ({ default: m.ScanDiffPage })));
const AdminApplicationsPage = lazy(() => import("./pages/admin/AdminApplicationsPage.tsx").then((m) => ({ default: m.AdminApplicationsPage })));
const AdminGroupsPage = lazy(() => import("./pages/admin/AdminGroupsPage.tsx").then((m) => ({ default: m.AdminGroupsPage })));
const AdminAttributesPage = lazy(() => import("./pages/admin/AdminAttributesPage.tsx").then((m) => ({ default: m.AdminAttributesPage })));
const AdminAuditPage = lazy(() => import("./pages/admin/AdminAuditPage.tsx").then((m) => ({ default: m.AdminAuditPage })));
const AdminErrorsPage = lazy(() => import("./pages/admin/AdminErrorsPage.tsx").then((m) => ({ default: m.AdminErrorsPage })));
const AdminPendingPage = lazy(() => import("./pages/admin/AdminPendingPage.tsx").then((m) => ({ default: m.AdminPendingPage })));
const AdminConfigurationPage = lazy(() => import("./pages/admin/AdminConfigurationPage.tsx").then((m) => ({ default: m.AdminConfigurationPage })));
const AdminTokensPage = lazy(() => import("./pages/admin/AdminTokensPage.tsx").then((m) => ({ default: m.AdminTokensPage })));
const AdminEnvironmentsPage = lazy(() => import("./pages/admin/AdminEnvironmentsPage.tsx").then((m) => ({ default: m.AdminEnvironmentsPage })));
const AdminAuthenticationPage = lazy(() => import("./pages/admin/AdminAuthenticationPage.tsx").then((m) => ({ default: m.AdminAuthenticationPage })));
const AdminUsersPage = lazy(() => import("./pages/admin/AdminUsersPage.tsx").then((m) => ({ default: m.AdminUsersPage })));
const AdminSquadsPage = lazy(() => import("./pages/admin/AdminSquadsPage.tsx").then((m) => ({ default: m.AdminSquadsPage })));
const AdminTribesPage = lazy(() => import("./pages/admin/AdminTribesPage.tsx").then((m) => ({ default: m.AdminTribesPage })));
const AdminAccessLayout = lazy(() => import("./pages/admin/AdminSections.tsx").then((m) => ({ default: m.AdminAccessLayout })));
const AdminScannersLayout = lazy(() => import("./pages/admin/AdminSections.tsx").then((m) => ({ default: m.AdminScannersLayout })));
const MovedTo = lazy(() => import("./pages/admin/AdminSections.tsx").then((m) => ({ default: m.MovedTo })));
const AdminModulesPage = lazy(() => import("./pages/admin/AdminModulesPage.tsx").then((m) => ({ default: m.AdminModulesPage })));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Data changes only when CI posts a new scan, so a short stale window
      // avoids refetching the same tables on every navigation.
      staleTime: 30 * 1000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        // A 401 means the session is gone; retrying cannot fix it and would just
        // delay the redirect to the login page.
        if (error instanceof UnauthenticatedError) return false;
        return failureCount < 2;
      },
    },
  },
});

/** Every module's scanner settings page, in module order: the tabs under Administration -> Scanners. */
const SCANNER_PAGES = WEB_MODULES.flatMap((m) => m.adminPages ?? []).filter((p) => p.section === "scanners");

function NotFoundPage() {
  return (
    <Card>
      <EmptyState title="Page not found" hint="The link may be out of date, or the record may have been removed." />
    </Card>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Suspense fallback={<LoadingBlock />}>
          <Routes>
            {/* Unauthenticated */}
            <Route path="/login" element={<LoginPage />} />

            {/*
              Changing your own password, signed in but outside the application shell.

              Deliberately NOT inside the Layout route below, and this is the whole point of
              the screen working at all. An account whose password was issued by an
              administrator is refused every authenticated route except whoami, change-password
              and logout -- and the shell's own EnvironmentProvider fetches the environment
              list, which is one of the refused ones. Nested inside it, this page rendered as
              that refusal's error banner and a Retry button that could never succeed: the
              account was permanently unable to reach the only form that would release it.

              The same nesting locked out an account with no environment grants yet, which
              stops at the provider's "No environments" state before any page renders.

              So this route depends on the session and nothing else.
            */}
            <Route
              path="/change-password"
              element={
                <RequireAuth>
                  <ChangePasswordPage />
                </RequireAuth>
              }
            />

            {/* Authenticated */}
            {/*
              Inside RequireAuth: the environment list is itself an authenticated read, and
              an account with a temporary password is still held on the change-password
              screen. Outside the Layout it wraps, so the header switcher and every page
              below it read the same selection.
            */}
            <Route
              element={
                <RequireAuth>
                  <EnvironmentProvider>
                    <Layout />
                  </EnvironmentProvider>
                </RequireAuth>
              }
            >
              <Route path="/" element={<DashboardPage />} />
              <Route path="/applications" element={<ApplicationsPage />} />
              <Route path="/applications/:id" element={<ApplicationDetailPage />} />
              <Route path="/applications/:id/diff" element={<ScanDiffPage />} />
              <Route path="/scans/:id" element={<ScanDetailPage />} />
              <Route path="/search" element={<ComponentSearchPage />} />
              {/*
                A saved package list. Its own route rather than a query param
                because this is the shareable form of a bulk search - the list
                itself travels in a POST body and has no other address.
              */}
              <Route path="/search/list/:id" element={<ComponentSearchPage mode="list" />} />
              {/*
                Each module's pages, from the module list. Mounted whether or not the module is
                on, so a bookmarked or pasted link explains itself rather than 404ing: either the
                page shows its own "not enabled" state, or ModuleGate shows one.
              */}
              {WEB_MODULES.flatMap((m) =>
                (m.routes ?? []).map((r) => (
                  <Route
                    key={`${m.id}:${r.path}`}
                    path={r.path}
                    element={m.pagesExplainDisabled ? r.element : <ModuleGate id={m.id}>{r.element}</ModuleGate>}
                  />
                )),
              )}
              <Route path="/api-access" element={<ApiAccessPage />} />

              {/*
                Nested under RequireAuth so an admin with a temporary password is
                still held on the change-password screen - the admin panel must
                not be the one way around that gate.
              */}
              <Route
                path="/admin"
                element={
                  <RequireAdmin>
                    <AdminLayout />
                  </RequireAdmin>
                }
              >
                <Route index element={<Navigate to="/admin/applications" replace />} />
                <Route path="applications" element={<AdminApplicationsPage />} />
                <Route path="pending" element={<AdminPendingPage />} />
                <Route path="access" element={<AdminAccessLayout />}>
                  <Route index element={<Navigate to="/admin/access/users" replace />} />
                  <Route path="users" element={<AdminUsersPage />} />
                  <Route path="tribes" element={<AdminTribesPage />} />
                  <Route path="squads" element={<AdminSquadsPage />} />
                  <Route path="groups" element={<AdminGroupsPage />} />
                </Route>
                {/* Where these lived before Access grouped them. Kept as redirects: bookmarked. */}
                <Route path="users" element={<MovedTo to="/admin/access/users" />} />
                <Route path="squads" element={<MovedTo to="/admin/access/squads" />} />
                <Route path="groups" element={<MovedTo to="/admin/access/groups" />} />
                <Route path="authentication" element={<AdminAuthenticationPage />} />
                <Route path="environments" element={<AdminEnvironmentsPage />} />
                <Route path="attributes" element={<AdminAttributesPage />} />
                <Route path="tokens" element={<AdminTokensPage />} />
                <Route path="configuration" element={<AdminConfigurationPage />} />
                {/*
                  The old single-field Settings page became the Configuration tab. Kept as a
                  redirect rather than removed: this URL has been bookmarked and linked to,
                  and a 404 on a path that worked yesterday reads as a broken deployment.
                */}
                <Route path="settings" element={<Navigate to="/admin/configuration" replace />} />
                <Route path="modules" element={<AdminModulesPage />} />
                {/* Each module's settings: scanners grouped under one tab, others on their own. */}
                <Route path="scanners" element={<AdminScannersLayout />}>
                  <Route index element={<Navigate to={`/admin/scanners/${SCANNER_PAGES[0]?.path ?? ""}`} replace />} />
                  {SCANNER_PAGES.map((p) => (
                    <Route key={p.path} path={p.path} element={p.element} />
                  ))}
                </Route>
                {WEB_MODULES.flatMap((m) => m.adminPages ?? [])
                  .filter((p) => p.section === undefined)
                  .map((p) => (
                    <Route key={p.path} path={p.path} element={p.element} />
                  ))}
                {WEB_MODULES.flatMap((m) => m.adminRedirects ?? []).map((r) => (
                  <Route key={r.from} path={r.from} element={<MovedTo to={r.to} />} />
                ))}
                <Route path="audit" element={<AdminAuditPage />} />
                <Route path="errors" element={<AdminErrorsPage />} />
              </Route>

              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
          </Suspense>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
