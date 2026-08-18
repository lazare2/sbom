import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { AuthProvider } from "./auth/AuthProvider.tsx";
import { RequireAdmin, RequireAuth } from "./auth/RequireAuth.tsx";
import { Layout } from "./components/Layout.tsx";
import { EmptyState, Card } from "./components/ui.tsx";
import { AnalyticsPage } from "./pages/AnalyticsPage.tsx";
import { ApplicationDetailPage } from "./pages/ApplicationDetailPage.tsx";
import { ApplicationsPage } from "./pages/ApplicationsPage.tsx";
import { ChangePasswordPage } from "./pages/ChangePasswordPage.tsx";
import { ComponentSearchPage } from "./pages/ComponentSearchPage.tsx";
import { DashboardPage } from "./pages/DashboardPage.tsx";
import { LoginPage } from "./pages/LoginPage.tsx";
import { ScanDetailPage } from "./pages/ScanDetailPage.tsx";
import { ScanDiffPage } from "./pages/ScanDiffPage.tsx";
import { AdminApplicationsPage } from "./pages/admin/AdminApplicationsPage.tsx";
import { AdminAttributesPage } from "./pages/admin/AdminAttributesPage.tsx";
import { AdminAuditPage } from "./pages/admin/AdminAuditPage.tsx";
import { AdminLayout } from "./pages/admin/AdminLayout.tsx";
import { AdminPendingPage } from "./pages/admin/AdminPendingPage.tsx";
import { AdminReportsPage } from "./pages/admin/AdminReportsPage.tsx";
import { AdminSettingsPage } from "./pages/admin/AdminSettingsPage.tsx";
import { AdminTokensPage } from "./pages/admin/AdminTokensPage.tsx";
import { AdminUsersPage } from "./pages/admin/AdminUsersPage.tsx";
import { AdminVulnerabilitiesPage } from "./pages/admin/AdminVulnerabilitiesPage.tsx";
import { AdvisoryDetailPage, VulnerabilitiesPage } from "./pages/VulnerabilitiesPage.tsx";
import { UnauthenticatedError } from "./lib/api.ts";
import "./index.css";

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
          <Routes>
            {/* Unauthenticated */}
            <Route path="/login" element={<LoginPage />} />

            {/* Authenticated */}
            <Route
              element={
                <RequireAuth>
                  <Layout />
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
                because this is the shareable form of a bulk search — the list
                itself travels in a POST body and has no other address.
              */}
              <Route path="/search/list/:id" element={<ComponentSearchPage mode="list" />} />
              {/*
                Vulnerability routes stay mounted whether or not scanning is enabled. Each
                page renders an explicit "not assessed" state instead of disappearing, so a
                bookmarked or pasted link explains itself rather than 404ing.
              */}
              <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
              <Route path="/vulnerabilities/:vulnerabilityId" element={<AdvisoryDetailPage />} />
              <Route path="/analytics" element={<AnalyticsPage />} />
              <Route path="/change-password" element={<ChangePasswordPage />} />

              {/*
                Nested under RequireAuth so an admin with a temporary password is
                still held on the change-password screen — the admin panel must
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
                <Route path="users" element={<AdminUsersPage />} />
                <Route path="attributes" element={<AdminAttributesPage />} />
                <Route path="tokens" element={<AdminTokensPage />} />
                <Route path="reports" element={<AdminReportsPage />} />
                <Route path="settings" element={<AdminSettingsPage />} />
                <Route path="vulnerabilities" element={<AdminVulnerabilitiesPage />} />
                <Route path="audit" element={<AdminAuditPage />} />
              </Route>

              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
