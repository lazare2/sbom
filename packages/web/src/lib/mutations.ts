import { useMutation, useQueryClient, type QueryClient } from "@tanstack/react-query";
import type {
  ApplicationDetail,
  ApplicationGroupDetail,
  CreateGroupRequest,
  UpdateGroupRequest,
  AttributeDefinition,
  AttributeDefinitionInput,
  BulkSearchBody,
  BulkSearchResult,
  ConfirmApplicationRequest,
  CreateApplicationRequest,
  CreateIngestTokenResponse,
  CreateSuppression,
  CreateUserRequest,
  ManualUploadResponse,
  MergeApplicationRequest,
  MergeApplicationResponse,
  UpdateApplicationRequest,
  UpdateAttributeDefinitionInput,
  UpdateUserRequest,
  UpdateVulnSettings,
  UserCredentialResponse,
  UserSummary,
  VulnScanStatus,
  PlatformSettings,
  ReportRunSummary,
  ReportSettings,
  UpdatePlatformSettings,
  UpdateReportSettings,
} from "@sbom/shared";
import { api } from "./api.ts";
import { queryKeys } from "./queries.ts";

/**
 * Admin write hooks.
 *
 * Every one of these invalidates broadly rather than surgically patching the
 * cache. An admin write is rare and its effects are wide — a merge rewrites two
 * applications' scan history and the global package search at once — so
 * refetching is both cheaper to reason about and impossible to get subtly wrong.
 */

function invalidateApplications(qc: QueryClient): Promise<unknown> {
  return Promise.all([
    qc.invalidateQueries({ queryKey: ["applications"] }),
    // Package search rows carry application name and status, and the dashboard
    // counts applications by status. Both go stale on any application write.
    qc.invalidateQueries({ queryKey: ["components"] }),
    qc.invalidateQueries({ queryKey: ["dashboard"] }),
    qc.invalidateQueries({ queryKey: ["admin", "audit-log"] }),
  ]);
}

// --- manual SBOM upload -----------------------------------------------------

export interface UploadSbomVars {
  applicationId: string;
  file: File;
  buildNumber?: string;
  commitSha?: string;
  branch?: string;
  imageRef?: string;
  note?: string;
  /** Re-submit an SBOM this application already holds, after a 409. */
  allowDuplicate?: boolean;
}

/**
 * Uploads an SBOM by hand for one application.
 *
 * Invalidates the whole world rather than patching the cache, and that breadth is
 * correct rather than lazy: this scan becomes the application's current build, so
 * its component list, its removed-packages view, every global package search that
 * might now hit it, the dashboard counts and the analytics report are all stale in
 * one stroke. It is exactly as wide-reaching as a CI push — the difference is only
 * that a CI push happens while nobody is looking at a cache.
 */
export function useUploadSbom() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ applicationId, file, ...fields }: UploadSbomVars) => {
      const form = new FormData();
      form.append("sbom", file, file.name);
      // Empty strings are dropped rather than sent: the server treats an empty
      // multipart field as absent, but not sending it at all keeps the request
      // readable in a network log and the row unambiguous.
      if (fields.buildNumber) form.append("build_number", fields.buildNumber);
      if (fields.commitSha) form.append("commit_sha", fields.commitSha);
      if (fields.branch) form.append("branch", fields.branch);
      if (fields.imageRef) form.append("image_ref", fields.imageRef);
      if (fields.note) form.append("note", fields.note);
      if (fields.allowDuplicate) form.append("allow_duplicate", "true");

      return api.upload<ManualUploadResponse>(`/applications/${applicationId}/scans`, form);
    },
    onSuccess: (result) => {
      void invalidateApplications(qc);
      void qc.invalidateQueries({ queryKey: ["scans"] });
      void qc.invalidateQueries({ queryKey: ["analytics"] });
      void qc.invalidateQueries({ queryKey: queryKeys.application(result.applicationId) });
    },
  });
}

// --- bulk package list search ----------------------------------------------

/**
 * Submits a pasted package list.
 *
 * Registers the list and returns its id, which the caller navigates to. The POST
 * response is seeded into the cache under the GET's key so the results render
 * immediately without a second round trip — the extra request would otherwise be
 * the price of making every search shareable, and it does not have to be.
 */
export function useSubmitPackageList() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkSearchBody) => api.post<BulkSearchResult>("/components/bulk-search", body),
    onSuccess: (result, body) => {
      const params = {
        scope: body.scope,
        view: body.view,
        includeInactive: body.includeInactive || undefined,
        page: 1,
        pageSize: 100,
      };
      // `input` is not in the POST response but is in the GET's, and the caller
      // already has it — so the seeded entry matches the GET shape exactly rather
      // than being a near-miss that forces a refetch.
      qc.setQueryData(queryKeys.bulkSearch(result.queryId, params), { ...result, input: body.input });
      void qc.invalidateQueries({ queryKey: queryKeys.bulkSearchLists });
    },
  });
}

// --- users -----------------------------------------------------------------

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateUserRequest) => api.post<UserCredentialResponse>("/admin/users", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin"] });
    },
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; body: UpdateUserRequest }) =>
      api.patch<{ user: UserSummary }>(`/admin/users/${vars.id}`, vars.body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin"] });
    },
  });
}

export function useResetUserPassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; password?: string }) =>
      api.post<UserCredentialResponse>(`/admin/users/${vars.id}/reset-password`, {
        ...(vars.password ? { password: vars.password } : {}),
        mustChangePassword: true,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin"] });
    },
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/admin/users/${id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin"] });
    },
  });
}

// --- applications ----------------------------------------------------------

export function useCreateApplication() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateApplicationRequest) =>
      api.post<{ application: ApplicationDetail }>("/admin/applications", body),
    onSuccess: () => void invalidateApplications(qc),
  });
}

export function useUpdateApplication() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; body: UpdateApplicationRequest }) =>
      api.patch<{ application: ApplicationDetail }>(`/admin/applications/${vars.id}`, vars.body),
    onSuccess: () => void invalidateApplications(qc),
  });
}

export function useDeleteApplication() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<{ scansDeleted: number }>(`/admin/applications/${id}`),
    onSuccess: () => void invalidateApplications(qc),
  });
}

export function useConfirmApplication() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; body: ConfirmApplicationRequest }) =>
      api.post<{ application: ApplicationDetail }>(`/admin/applications/${vars.id}/confirm`, vars.body),
    onSuccess: () => void invalidateApplications(qc),
  });
}

export function useMergeApplication() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; body: MergeApplicationRequest }) =>
      api.post<MergeApplicationResponse>(`/admin/applications/${vars.id}/merge`, vars.body),
    // A merge moves scans between applications, so every cached scan list,
    // component page and search result may now be attributed to the wrong app.
    onSuccess: () => {
      void invalidateApplications(qc);
      void qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}

export function useAddAlias() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; aliasName: string }) =>
      api.post<{ aliasName: string }>(`/admin/applications/${vars.id}/aliases`, {
        aliasName: vars.aliasName,
      }),
    onSuccess: () => void invalidateApplications(qc),
  });
}

export function useRemoveAlias() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; aliasName: string }) =>
      api.delete<void>(`/admin/applications/${vars.id}/aliases/${encodeURIComponent(vars.aliasName)}`),
    onSuccess: () => void invalidateApplications(qc),
  });
}

// --- attribute definitions --------------------------------------------------

function invalidateAttributes(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: queryKeys.attributeDefinitions });
  // Definitions drive the filter dropdowns and the application list's columns.
  void qc.invalidateQueries({ queryKey: ["applications"] });
  void qc.invalidateQueries({ queryKey: ["admin", "audit-log"] });
}

export function useCreateAttributeDefinition() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AttributeDefinitionInput) =>
      api.post<{ definition: AttributeDefinition }>("/admin/attribute-definitions", body),
    onSuccess: () => invalidateAttributes(qc),
  });
}

export function useUpdateAttributeDefinition() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; body: UpdateAttributeDefinitionInput }) =>
      api.patch<{ definition: AttributeDefinition }>(`/admin/attribute-definitions/${vars.id}`, vars.body),
    onSuccess: () => invalidateAttributes(qc),
  });
}

export function useDeleteAttributeDefinition() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; purge: boolean }) =>
      api.delete<{ valuesPurged: number }>(
        `/admin/attribute-definitions/${vars.id}${vars.purge ? "?purge=true" : ""}`,
      ),
    onSuccess: () => invalidateAttributes(qc),
  });
}

// --- ingest tokens ----------------------------------------------------------

export function useCreateIngestToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.post<CreateIngestTokenResponse>("/admin/ingest-tokens", { name }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.ingestTokens });
      void qc.invalidateQueries({ queryKey: ["admin", "audit-log"] });
    },
  });
}

export function useRevokeIngestToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/admin/ingest-tokens/${id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.ingestTokens });
      void qc.invalidateQueries({ queryKey: ["admin", "audit-log"] });
    },
  });
}

// --- vulnerability scanning -------------------------------------------------

/**
 * Invalidates everything vulnerability data reaches.
 *
 * Wide on purpose. Enabling scanning, installing a database or accepting a risk changes
 * the nav (a whole section appears or disappears), the overview cards, the analytics
 * report, and every per-application and per-scan view at once. Anything narrower would
 * leave part of the UI asserting the previous state.
 */
function invalidateVulnerabilities(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: ["vuln"] });
  void qc.invalidateQueries({ queryKey: ["admin", "vuln"] });
  void qc.invalidateQueries({ queryKey: ["dashboard"] });
  void qc.invalidateQueries({ queryKey: ["analytics"] });
  void qc.invalidateQueries({ queryKey: ["applications"] });
  void qc.invalidateQueries({ queryKey: ["scans"] });
  void qc.invalidateQueries({ queryKey: ["admin", "audit-log"] });
}

/**
 * Saves the platform settings.
 *
 * Invalidates broadly on purpose: the stale threshold changes which applications the list,
 * the overview and the analytics report each call stale, so a narrow invalidation would
 * leave two of the three showing the old answer.
 */
export function useUpdatePlatformSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdatePlatformSettings) =>
      api.patch<{ settings: PlatformSettings }>("/admin/settings", body),
    onSuccess: (result) => {
      qc.setQueryData(queryKeys.platformSettings, result);
      void qc.invalidateQueries();
    },
  });
}

/**
 * Saves report delivery settings.
 *
 * A full replace rather than a patch: the form edits every field at once, and a partial
 * update would let two administrators with the page open overwrite each other's changes one
 * field at a time without either seeing a conflict.
 */
export function useUpdateReportSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateReportSettings) =>
      api.put<ReportSettings>("/admin/reports/settings", body),
    onSuccess: (result) => {
      qc.setQueryData(queryKeys.reportSettings, result);
    },
  });
}

export function useTestReportEmail() {
  return useMutation({
    mutationFn: (recipient: string) =>
      api.post<{ sent: boolean }>("/admin/reports/settings/test", { recipient }),
  });
}

/**
 * Generates a report now.
 *
 * Ad-hoc by default, which is what the button sends. An ad-hoc run is compared against the
 * last monthly report but never becomes the baseline for the next one, so pressing this
 * cannot shorten next month's reporting period.
 */
export function useGenerateReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (kind: "monthly" | "adhoc") =>
      api.post<{ run: ReportRunSummary; alreadyExisted: boolean }>("/admin/reports", { kind }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.reportRuns });
    },
  });
}

export function useSendReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.post<{ sent: boolean; recipients: string[]; error?: string }>(
        `/admin/reports/${id}/send`,
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.reportRuns });
    },
  });
}

export function useUpdateVulnSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateVulnSettings) => api.patch<VulnScanStatus>("/admin/vuln/settings", body),
    onSuccess: (status) => {
      // Seeded so the panel reflects the new state immediately; the invalidation behind
      // it refreshes everything else.
      qc.setQueryData(queryKeys.vulnAdminStatus, status);
      invalidateVulnerabilities(qc);
    },
  });
}

export interface VulnDbActionResult {
  outcome: string;
  message: string;
  status: VulnScanStatus;
}

/**
 * Runs a database update now.
 *
 * Resolves rather than rejects when there is no route to the internet: the endpoint
 * answers 200 with `outcome: "unreachable"` and the exact URL in the message, because
 * being air-gapped is a state to report and not a request that failed. The caller renders
 * the outcome; it does not need a catch.
 */
export function useUpdateVulnDb() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<VulnDbActionResult>("/admin/vuln/update"),
    onSuccess: (result) => {
      qc.setQueryData(queryKeys.vulnAdminStatus, result.status);
      invalidateVulnerabilities(qc);
    },
  });
}

/** Installs a database from an uploaded archive — the air-gapped path. */
export function useImportVulnDb() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => {
      const form = new FormData();
      form.append("database", file, file.name);
      return api.upload<VulnDbActionResult>("/admin/vuln/import", form);
    },
    onSuccess: (result) => {
      qc.setQueryData(queryKeys.vulnAdminStatus, result.status);
      invalidateVulnerabilities(qc);
    },
  });
}

export function useRunVulnSweep() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api.post<{ status: string; message: string; componentsScanned: number; remaining: number }>(
        "/admin/vuln/sweep",
      ),
    onSuccess: () => invalidateVulnerabilities(qc),
  });
}

export function useCreateSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateSuppression) => api.post<{ id: string }>("/admin/vuln/suppressions", body),
    onSuccess: () => invalidateVulnerabilities(qc),
  });
}

export function useDeleteSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/admin/vuln/suppressions/${id}`),
    onSuccess: () => invalidateVulnerabilities(qc),
  });
}

// --- own password -----------------------------------------------------------

export function useChangePassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { currentPassword: string; newPassword: string }) =>
      api.post<{ message: string }>("/auth/change-password", vars),
    onSuccess: () => {
      // `mustChangePassword` lives on the session user, and clearing it is what
      // unlocks the rest of the app — so this refetch is load-bearing, not
      // cosmetic.
      void qc.invalidateQueries({ queryKey: queryKeys.me });
    },
  });
}

// --- application groups -----------------------------------------------------

/**
 * Group writes invalidate applications and the dashboard as well as groups.
 *
 * Not over-cautious. A group's membership decides which applications carry which chips, what
 * the `?group=` filter returns, and — because the dashboard and analytics accept a group
 * scope — what every aggregate on those pages describes. Invalidating only `["groups"]` would
 * leave a stale scoped dashboard on screen showing figures for a membership that no longer
 * exists, which is the one failure mode this feature can produce that looks like data rather
 * than like a bug.
 */
function invalidateGroups(qc: QueryClient): Promise<unknown> {
  return Promise.all([
    qc.invalidateQueries({ queryKey: ["groups"] }),
    qc.invalidateQueries({ queryKey: ["applications"] }),
    qc.invalidateQueries({ queryKey: ["dashboard"] }),
    qc.invalidateQueries({ queryKey: ["analytics"] }),
    qc.invalidateQueries({ queryKey: ["admin", "audit-log"] }),
  ]);
}

export function useCreateGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateGroupRequest) =>
      api.post<{ group: ApplicationGroupDetail }>("/admin/groups", body),
    onSuccess: () => invalidateGroups(qc),
  });
}

export function useUpdateGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: UpdateGroupRequest & { id: string }) =>
      api.patch<{ group: ApplicationGroupDetail }>(`/admin/groups/${id}`, body),
    onSuccess: () => invalidateGroups(qc),
  });
}

/**
 * Replaces the whole membership, matching the endpoint.
 *
 * The caller sends the complete resulting set rather than a delta, so a retry after a dropped
 * response leaves the group in the same state instead of applying an addition twice.
 */
export function useSetGroupMembers() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, applicationIds }: { id: string; applicationIds: string[] }) =>
      api.put<{ group: ApplicationGroupDetail }>(`/admin/groups/${id}/members`, { applicationIds }),
    onSuccess: () => invalidateGroups(qc),
  });
}

export function useDeleteGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.delete<{ deleted: true; memberCount: number }>(`/admin/groups/${id}`),
    onSuccess: () => invalidateGroups(qc),
  });
}
