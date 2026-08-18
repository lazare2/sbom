import { useQuery, type UseQueryOptions } from "@tanstack/react-query";
import type {
  AdvisoryImpact,
  AdvisorySummary,
  AnalyticsReport,
  ApplicationDetail,
  ApplicationSummary,
  AttributeDefinition,
  AuditLogEntry,
  BulkSearchResult,
  ComponentRef,
  ComponentSearchHit,
  ComponentSuggestion,
  DashboardStats,
  EcosystemBreakdownEntry,
  IngestTokenSummary,
  NameMatchMode,
  Paginated,
  PlatformBreakdown,
  RemovedComponent,
  SavedPackageList,
  ScanDiff,
  ScanSummary,
  SessionUser,
  SortDirection,
  SuppressionSummary,
  TopComponentEntry,
  UserSummary,
  VulnBreakdown,
  VulnDbUpdateAttempt,
  VulnerabilityFinding,
  VulnerabilityReport,
  VulnScanStatus,
  PlatformSettings,
  ReportRunSummary,
  ReportSettings,
} from "@sbom/shared";
import type { componentSearchSort } from "@sbom/shared";
import { api, toQueryString } from "./api.ts";

/**
 * Query keys are structured as [entity, scope, params] so an invalidation can
 * target a whole entity or one exact request.
 */
export const queryKeys = {
  me: ["auth", "me"] as const,
  attributeDefinitions: ["attribute-definitions"] as const,
  applications: (params: Record<string, unknown>) => ["applications", "list", params] as const,
  application: (id: string) => ["applications", "detail", id] as const,
  applicationComponents: (id: string, params: Record<string, unknown>) =>
    ["applications", id, "components", params] as const,
  applicationEcosystems: (id: string) => ["applications", id, "ecosystems"] as const,
  applicationScans: (id: string, params: Record<string, unknown>) =>
    ["applications", id, "scans", params] as const,
  attributeValues: (key: string) => ["applications", "attribute-values", key] as const,
  scan: (id: string) => ["scans", "detail", id] as const,
  scanComponents: (id: string, params: Record<string, unknown>) => ["scans", id, "components", params] as const,
  componentSearch: (params: Record<string, unknown>) => ["components", "search", params] as const,
  componentSuggest: (q: string) => ["components", "suggest", q] as const,
  componentEcosystems: ["components", "ecosystems"] as const,
  componentVersions: (name: string) => ["components", "versions", name] as const,
  recentScans: (limit: number) => ["scans", "recent", limit] as const,
  applicationDiff: (id: string, params: Record<string, unknown>) =>
    ["applications", id, "diff", params] as const,
  applicationRemoved: (id: string, params: Record<string, unknown>) =>
    ["applications", id, "removed", params] as const,
  dashboardStats: ["dashboard", "stats"] as const,
  dashboardEcosystems: ["dashboard", "ecosystems"] as const,
  dashboardPlatforms: ["dashboard", "platforms"] as const,
  dashboardTopComponents: (params: Record<string, unknown>) =>
    ["dashboard", "top-components", params] as const,
  analyticsReport: (periodDays: number, vulnFilter: Record<string, string>) =>
    ["analytics", "report", periodDays, vulnFilter] as const,
  bulkSearch: (id: string, params: Record<string, unknown>) =>
    ["components", "bulk-search", id, params] as const,
  bulkSearchLists: ["components", "bulk-search", "recent"] as const,
  users: (params: Record<string, unknown>) => ["admin", "users", params] as const,
  auditLog: (params: Record<string, unknown>) => ["admin", "audit-log", params] as const,
  ingestTokens: ["admin", "ingest-tokens"] as const,
  // --- vulnerabilities ---
  vulnStatus: ["vuln", "status"] as const,
  platformSettings: ["admin", "settings"] as const,
  reportSettings: ["admin", "reports", "settings"] as const,
  reportRuns: ["admin", "reports", "list"] as const,
  vulnAdminStatus: ["admin", "vuln", "status"] as const,
  vulnHistory: (limit: number) => ["admin", "vuln", "history", limit] as const,
  vulnSuppressions: ["admin", "vuln", "suppressions"] as const,
  dashboardVulnerabilities: (vulnFilter: Record<string, string>) =>
    ["dashboard", "vulnerabilities", vulnFilter] as const,
  advisorySearch: (params: Record<string, unknown>) => ["vuln", "advisories", params] as const,
  advisoryImpact: (id: string) => ["vuln", "advisory", id] as const,
  applicationVulnerabilities: (id: string, params: Record<string, unknown>) =>
    ["applications", id, "vulnerabilities", params] as const,
  scanVulnerabilities: (id: string, params: Record<string, unknown>) =>
    ["scans", id, "vulnerabilities", params] as const,
};

// --- auth ------------------------------------------------------------------

export interface ScanDetailResponse extends ScanSummary {
  applicationName: string;
  applicationStatus: string;
  specVersion: string | null;
  serialNumber: string | null;
  ingestTokenName: string | null;
  sbomSha256: string;
  /** Free-text reason recorded with a manual upload. Null for CI scans. */
  uploadNote: string | null;
  previousScanId: string | null;
  nextScanId: string | null;
}

export interface ApplicationComponentsResponse extends Paginated<ComponentRef> {
  scanId: string | null;
}

export interface ComponentSearchResponse extends Paginated<ComponentSearchHit> {
  truncated: boolean;
  matchedComponents: number;
}

export interface EcosystemCount {
  ecosystem: string;
  count: number;
}

export interface ComponentVersionUsage {
  componentId: string;
  version: string | null;
  ecosystem: string;
  currentApplications: number;
  totalApplications: number;
}

// --- hooks -----------------------------------------------------------------

export function useAttributeDefinitions(includeInactive = false) {
  return useQuery({
    queryKey: [...queryKeys.attributeDefinitions, includeInactive],
    queryFn: () =>
      api.get<{ definitions: AttributeDefinition[] }>(
        `/attribute-definitions${includeInactive ? "?includeInactive=true" : ""}`,
      ),
    // Near-static during a session: these change only when an admin edits them,
    // and that edit invalidates this key explicitly.
    staleTime: 10 * 60 * 1000,
    select: (data) => data.definitions,
  });
}

export function useApplications(params: Record<string, unknown>) {
  return useQuery({
    queryKey: queryKeys.applications(params),
    queryFn: () => api.get<Paginated<ApplicationSummary>>(`/applications${toQueryString(params)}`),
    // Keeps the previous page visible while the next one loads, so paging and
    // filtering don't flash an empty table.
    placeholderData: (previous) => previous,
  });
}

export function useApplication(id: string | undefined) {
  return useQuery({
    queryKey: queryKeys.application(id ?? ""),
    queryFn: () => api.get<ApplicationDetail>(`/applications/${id}`),
    enabled: Boolean(id),
  });
}

export function useApplicationComponents(id: string | undefined, params: Record<string, unknown>) {
  return useQuery({
    queryKey: queryKeys.applicationComponents(id ?? "", params),
    queryFn: () =>
      api.get<ApplicationComponentsResponse>(`/applications/${id}/components${toQueryString(params)}`),
    enabled: Boolean(id),
    placeholderData: (previous) => previous,
  });
}

export function useApplicationEcosystems(id: string | undefined) {
  return useQuery({
    queryKey: queryKeys.applicationEcosystems(id ?? ""),
    queryFn: () => api.get<{ ecosystems: EcosystemCount[] }>(`/applications/${id}/ecosystems`),
    enabled: Boolean(id),
    select: (data) => data.ecosystems,
  });
}

export function useApplicationScans(id: string | undefined, params: Record<string, unknown>) {
  return useQuery({
    queryKey: queryKeys.applicationScans(id ?? "", params),
    queryFn: () => api.get<Paginated<ScanSummary>>(`/applications/${id}/scans${toQueryString(params)}`),
    enabled: Boolean(id),
    placeholderData: (previous) => previous,
  });
}

export function useAttributeValues(key: string) {
  return useQuery({
    queryKey: queryKeys.attributeValues(key),
    queryFn: () => api.get<{ values: string[] }>(`/applications/attribute-values/${key}`),
    staleTime: 5 * 60 * 1000,
    select: (data) => data.values,
  });
}

export function useScan(id: string | undefined) {
  return useQuery({
    queryKey: queryKeys.scan(id ?? ""),
    queryFn: () => api.get<ScanDetailResponse>(`/scans/${id}`),
    enabled: Boolean(id),
  });
}

export function useScanComponents(id: string | undefined, params: Record<string, unknown>) {
  return useQuery({
    queryKey: queryKeys.scanComponents(id ?? "", params),
    queryFn: () => api.get<Paginated<ComponentRef>>(`/scans/${id}/components${toQueryString(params)}`),
    enabled: Boolean(id),
    placeholderData: (previous) => previous,
  });
}

export function useComponentSearch(
  params: Record<string, unknown>,
  options: { enabled?: boolean } = {},
) {
  return useQuery({
    queryKey: queryKeys.componentSearch(params),
    queryFn: () => api.get<ComponentSearchResponse>(`/components/search${toQueryString(params)}`),
    enabled: options.enabled ?? true,
    placeholderData: (previous) => previous,
  });
}

export function useComponentSuggestions(q: string) {
  return useQuery({
    queryKey: queryKeys.componentSuggest(q),
    queryFn: () => api.get<{ suggestions: ComponentSuggestion[] }>(`/components/suggest?q=${encodeURIComponent(q)}`),
    // The endpoint requires 2+ characters; asking sooner would just 400.
    enabled: q.trim().length >= 2,
    select: (data) => data.suggestions,
    staleTime: 60 * 1000,
  });
}

export function useComponentEcosystems() {
  return useQuery({
    queryKey: queryKeys.componentEcosystems,
    queryFn: () => api.get<{ ecosystems: EcosystemCount[] }>("/components/ecosystems"),
    staleTime: 5 * 60 * 1000,
    select: (data) => data.ecosystems,
  });
}

export function useComponentVersions(name: string | undefined) {
  return useQuery({
    queryKey: queryKeys.componentVersions(name ?? ""),
    queryFn: () =>
      api.get<{ name: string; versions: ComponentVersionUsage[] }>(
        `/components/versions?name=${encodeURIComponent(name ?? "")}`,
      ),
    enabled: Boolean(name),
    select: (data) => data.versions,
  });
}

export function useRecentScans(limit = 15) {
  return useQuery({
    queryKey: queryKeys.recentScans(limit),
    queryFn: () =>
      api.get<{ scans: Array<ScanSummary & { applicationName: string }> }>(`/scans/recent?limit=${limit}`),
    select: (data) => data.scans,
  });
}

// --- diff ------------------------------------------------------------------

export interface RemovedComponentsResponse extends Paginated<RemovedComponent> {
  latestScanId: string | null;
}

export function useApplicationDiff(
  id: string | undefined,
  params: Record<string, unknown>,
  options: { enabled?: boolean } = {},
) {
  return useQuery({
    queryKey: queryKeys.applicationDiff(id ?? "", params),
    queryFn: () => api.get<ScanDiff>(`/applications/${id}/diff${toQueryString(params)}`),
    enabled: Boolean(id) && (options.enabled ?? true),
    // A diff against a fixed pair of scans can never change: scans are
    // append-only and their component sets are immutable once written.
    staleTime: 5 * 60 * 1000,
    // "No earlier build to compare with" is a 400 that retrying cannot fix.
    retry: false,
  });
}

export function useRemovedComponents(id: string | undefined, params: Record<string, unknown>) {
  return useQuery({
    queryKey: queryKeys.applicationRemoved(id ?? "", params),
    queryFn: () =>
      api.get<RemovedComponentsResponse>(`/applications/${id}/removed-components${toQueryString(params)}`),
    enabled: Boolean(id),
    placeholderData: (previous) => previous,
  });
}

// --- dashboard -------------------------------------------------------------

export function useDashboardStats() {
  return useQuery({
    queryKey: queryKeys.dashboardStats,
    queryFn: () => api.get<DashboardStats>("/dashboard/stats"),
    staleTime: 60 * 1000,
  });
}

/**
 * OS and runtime counts across current builds.
 *
 * Serves both the dashboard card and the applications-list filter dropdowns, so
 * the two can never disagree about which platforms exist.
 */
export function usePlatformBreakdown() {
  return useQuery({
    queryKey: queryKeys.dashboardPlatforms,
    queryFn: () => api.get<PlatformBreakdown>("/dashboard/platforms"),
    staleTime: 5 * 60 * 1000,
  });
}

export function useDashboardEcosystems() {
  return useQuery({
    queryKey: queryKeys.dashboardEcosystems,
    queryFn: () => api.get<{ ecosystems: EcosystemBreakdownEntry[] }>("/dashboard/ecosystems"),
    staleTime: 5 * 60 * 1000,
    select: (data) => data.ecosystems,
  });
}

export function useTopComponents(params: { limit?: number; groupByName?: boolean }) {
  const query = { limit: params.limit, groupByName: params.groupByName ? "true" : undefined };
  return useQuery({
    queryKey: queryKeys.dashboardTopComponents(query),
    queryFn: () => api.get<{ components: TopComponentEntry[] }>(`/dashboard/top-components${toQueryString(query)}`),
    staleTime: 5 * 60 * 1000,
    select: (data) => data.components,
  });
}

// --- bulk package list search ----------------------------------------------

/** The saved-list response, which also echoes back the text that was submitted. */
export interface BulkSearchResponse extends BulkSearchResult {
  input: string;
}

export interface BulkSearchOptions {
  scope: "current" | "historical" | "all";
  view: "rollup" | "matches";
  includeInactive: boolean;
  /** Exact by default here, unlike the single search — see bulkOptionsSchema. */
  match: NameMatchMode;
  sortBy: (typeof componentSearchSort)["fields"][number];
  sortDir: SortDirection;
  page: number;
}

function bulkParams(options: BulkSearchOptions): Record<string, unknown> {
  return {
    scope: options.scope,
    view: options.view,
    includeInactive: options.includeInactive || undefined,
    match: options.match,
    sortBy: options.sortBy,
    sortDir: options.sortDir,
    page: options.page,
    pageSize: 100,
  };
}

/**
 * Results for a saved list.
 *
 * Always a GET against the stored list, never the POST response — which is why
 * submitting navigates to `/search/list/:id` first. One read path means a freshly
 * submitted list and a link opened by a colleague render through identical code,
 * so the shared case cannot rot while the fresh one keeps working.
 */
export function useBulkSearch(id: string | undefined, options: BulkSearchOptions) {
  const params = bulkParams(options);
  return useQuery({
    queryKey: queryKeys.bulkSearch(id ?? "", params),
    queryFn: () => api.get<BulkSearchResponse>(`/components/bulk-search/${id}${toQueryString(params)}`),
    enabled: Boolean(id),
    placeholderData: (previous) => previous,
    // A list against a moving estate: worth refetching on navigation rather than
    // showing a result that predates the last few scans.
    staleTime: 30 * 1000,
    retry: false,
  });
}

/** Recently submitted lists, so a colleague's audit is one click rather than a re-paste. */
export function useRecentPackageLists() {
  return useQuery({
    queryKey: queryKeys.bulkSearchLists,
    queryFn: () => api.get<{ lists: SavedPackageList[] }>("/components/bulk-search?limit=8"),
    select: (data) => data.lists,
    staleTime: 60 * 1000,
  });
}

/** Excel workbook for a saved list. A plain link, so the browser does the download. */
export function bulkSearchXlsxUrl(id: string, options: BulkSearchOptions): string {
  const params = { scope: options.scope, includeInactive: options.includeInactive || undefined };
  return `/api/v1/components/bulk-search/${id}/export.xlsx${toQueryString(params)}`;
}

// --- analytics -------------------------------------------------------------

/**
 * The whole report in one request.
 *
 * Deliberately not ten separate hooks. The PDF is rendered from a single
 * `analytics.report()` call, and if the page assembled itself from independent
 * requests then a scan arriving mid-load would give the screen a mix of two
 * moments — and the printed report a third. One payload, one instant.
 */
export function useAnalyticsReport(periodDays: number, vulnFilter: Record<string, string> = {}) {
  return useQuery({
    queryKey: queryKeys.analyticsReport(periodDays, vulnFilter),
    queryFn: () =>
      api.get<AnalyticsReport>(`/analytics/report${toQueryString({ periodDays, ...vulnFilter })}`),
    // Heavier than the dashboard's aggregates — the churn section compares two
    // builds per application — so it is cached longer. Changing the period is a
    // different key and refetches immediately.
    staleTime: 5 * 60 * 1000,
    placeholderData: (previous) => previous,
  });
}

/**
 * URL for the PDF of a given window. Used as a plain link, so the browser downloads it.
 *
 * Carries the vulnerability filter so the printed report matches the screen it was
 * downloaded from. A Download button that quietly produced a different report than the one
 * on display is the exact drift the single-payload design exists to prevent.
 */
export function analyticsReportPdfUrl(
  periodDays: number,
  vulnFilter: Record<string, string> = {},
): string {
  return `/api/v1/analytics/report.pdf${toQueryString({ periodDays, ...vulnFilter })}`;
}

// --- admin -----------------------------------------------------------------

export function useUsers(params: Record<string, unknown>) {
  return useQuery({
    queryKey: queryKeys.users(params),
    queryFn: () => api.get<Paginated<UserSummary>>(`/admin/users${toQueryString(params)}`),
    placeholderData: (previous) => previous,
  });
}

export function useAuditLog(params: Record<string, unknown>) {
  return useQuery({
    queryKey: queryKeys.auditLog(params),
    queryFn: () => api.get<Paginated<AuditLogEntry>>(`/admin/audit-log${toQueryString(params)}`),
    placeholderData: (previous) => previous,
  });
}

export function useIngestTokens() {
  return useQuery({
    queryKey: queryKeys.ingestTokens,
    queryFn: () => api.get<{ tokens: IngestTokenSummary[] }>("/admin/ingest-tokens"),
    select: (data) => data.tokens,
  });
}

// --- vulnerabilities --------------------------------------------------------

/**
 * Whether vulnerability data exists at all.
 *
 * The gate every other vulnerability view depends on, and the reason it has its own
 * endpoint outside the gated scope: with scanning off, the app has to render *no*
 * vulnerability UI rather than empty vulnerability UI. Nav items, tabs and dashboard
 * cards all branch on this.
 *
 * Kept fresh for a minute at a time: an admin enabling scanning should see the UI appear
 * without a reload, but this is fetched on nearly every page and does not need to be
 * revalidated on each one.
 */
export interface VulnStatusResponse {
  enabled: boolean;
  scannerAvailable: boolean | null;
  database: {
    present: boolean;
    builtAt: string | null;
    schemaVersion: string | null;
    valid: boolean;
    error: string | null;
    ageHours: number | null;
    path: string | null;
  } | null;
  coverage: { scanned: number; pending: number; sweeping: boolean; lastSweepFinishedAt: string | null } | null;
}

export function usePlatformSettings() {
  return useQuery({
    queryKey: queryKeys.platformSettings,
    queryFn: () => api.get<{ settings: PlatformSettings }>("/admin/settings"),
  });
}

/** Delivery settings for the monthly report. */
export function useReportSettings() {
  return useQuery({
    queryKey: queryKeys.reportSettings,
    queryFn: () => api.get<ReportSettings>("/admin/reports/settings"),
  });
}

/**
 * Report history.
 *
 * Polled while a generation is in flight would be over-engineering: generating walks the
 * estate once and the mutation invalidates this on completion, so the table updates when
 * there is something new to show.
 */
export function useReportRuns() {
  return useQuery({
    queryKey: queryKeys.reportRuns,
    queryFn: () => api.get<{ items: ReportRunSummary[] }>("/admin/reports"),
  });
}

export function useVulnStatus() {
  return useQuery({
    queryKey: queryKeys.vulnStatus,
    queryFn: () => api.get<VulnStatusResponse>("/vuln-status"),
    staleTime: 60_000,
  });
}

/** Full scanner and database state, for the admin panel. */
export function useVulnAdminStatus(options: { refetchWhileBusy?: boolean } = {}) {
  return useQuery({
    queryKey: queryKeys.vulnAdminStatus,
    queryFn: () => api.get<VulnScanStatus>("/admin/vuln/status"),
    /*
     * Polls only while something is actually happening. A sweep or a 141 MB download
     * takes minutes and an administrator watching a static page cannot tell progress
     * from a hang — but polling a settled page every few seconds would spawn a grype
     * subprocess on the server each time, since the status reads the binary and the
     * database directly.
     */
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      const busy = data.updates.inProgress || data.coverage.sweeping || data.coverage.pending > 0;
      return busy && options.refetchWhileBusy !== false ? 4_000 : false;
    },
  });
}

export function useVulnHistory(limit = 20) {
  return useQuery({
    queryKey: queryKeys.vulnHistory(limit),
    queryFn: () => api.get<{ attempts: VulnDbUpdateAttempt[] }>(`/admin/vuln/history?limit=${limit}`),
    select: (data) => data.attempts,
  });
}

export function useVulnSuppressions() {
  return useQuery({
    queryKey: queryKeys.vulnSuppressions,
    queryFn: () => api.get<{ suppressions: SuppressionSummary[] }>("/admin/vuln/suppressions"),
    select: (data) => data.suppressions,
  });
}

/**
 * Estate vulnerability posture for the overview page.
 *
 * `vulnerabilities` is null when scanning is disabled — deliberately null rather than a
 * zeroed object, so a caller cannot accidentally render "0 vulnerabilities" for an estate
 * that was never assessed.
 */
export function useDashboardVulnerabilities(
  enabled: boolean,
  vulnFilter: Record<string, string> = {},
) {
  return useQuery({
    queryKey: queryKeys.dashboardVulnerabilities(vulnFilter),
    queryFn: () =>
      api.get<{ vulnerabilities: VulnerabilityReport | null }>(
        `/dashboard/vulnerabilities${toQueryString(vulnFilter)}`,
      ),
    select: (data) => data.vulnerabilities,
    // Keeps the previous figures on screen while a filter change is in flight, so the
    // block does not collapse to a spinner on every chip click.
    placeholderData: (previous) => previous,
    enabled,
  });
}

export function useAdvisorySearch(params: Record<string, unknown>, enabled = true) {
  return useQuery({
    queryKey: queryKeys.advisorySearch(params),
    queryFn: () => api.get<Paginated<AdvisorySummary>>(`/vulnerabilities${toQueryString(params)}`),
    placeholderData: (previous) => previous,
    enabled,
  });
}

export function useAdvisoryImpact(vulnerabilityId: string | undefined) {
  return useQuery({
    queryKey: queryKeys.advisoryImpact(vulnerabilityId ?? ""),
    queryFn: () => api.get<AdvisoryImpact>(`/vulnerabilities/${encodeURIComponent(vulnerabilityId!)}`),
    enabled: Boolean(vulnerabilityId),
  });
}

export interface FindingsResponse extends Paginated<VulnerabilityFinding> {
  breakdown: VulnBreakdown;
}

export function useApplicationVulnerabilities(
  id: string | undefined,
  params: Record<string, unknown>,
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.applicationVulnerabilities(id ?? "", params),
    queryFn: () => api.get<FindingsResponse>(`/applications/${id}/vulnerabilities${toQueryString(params)}`),
    enabled: Boolean(id) && enabled,
    placeholderData: (previous) => previous,
  });
}

export function useScanVulnerabilities(
  id: string | undefined,
  params: Record<string, unknown>,
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.scanVulnerabilities(id ?? "", params),
    queryFn: () => api.get<FindingsResponse>(`/scans/${id}/vulnerabilities${toQueryString(params)}`),
    enabled: Boolean(id) && enabled,
    placeholderData: (previous) => previous,
  });
}

export type MeResponse = { user: SessionUser };
export type { UseQueryOptions };
