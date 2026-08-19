import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import type { ScanSummary, SortDirection } from "@sbom/shared";
import { componentListSort, removedComponentSort, scanHistorySort } from "@sbom/shared";
import { useServerSort } from "../lib/useSort.ts";
import { useAuth } from "../auth/AuthProvider.tsx";
import {
  useApplication,
  useApplicationComponents,
  useApplicationDiff,
  useApplicationEcosystems,
  useApplicationScans,
  useAttributeDefinitions,
  useRemovedComponents,
} from "../lib/queries.ts";
import { formatBytes, formatDateTime, formatNumber, formatRelative, shortImageRef, shortSha } from "../lib/format.ts";
import { readBool, readEnum, readNumber, readString, useUrlState } from "../lib/useUrlState.ts";
import { useDebounced } from "../lib/useDebounced.ts";
import { DiffView, LastSeen, PackageLink } from "../components/DiffView.tsx";
import { PlatformChips } from "../components/Platform.tsx";
import { ApplicationFormModal } from "./admin/ApplicationFormModal.tsx";
import { UploadSbomModal } from "./UploadSbomModal.tsx";
import { useDeleteScan } from "../lib/mutations.ts";
import { DeleteScanModal } from "../components/DeleteScanModal.tsx";
import {
  BreakdownTiles,
  DEFAULT_FINDINGS_FILTERS,
  FindingsCard,
  FindingsTable,
  findingsParams,
  useFindingsSort,
  type FindingsFilters,
} from "../components/Findings.tsx";
import { ScanningDisabledNotice } from "../components/Severity.tsx";
import { useApplicationVulnerabilities, useVulnStatus } from "../lib/queries.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
  EcosystemBadge,
  EmptyState,
  ErrorBanner,
  Field,
  LoadingBlock,
  Mono,
  Pagination,
  PageHeader,
  ScanSourceBadge,
  Select,
  StatusBadge,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../components/ui.tsx";

const TABS = ["components", "history", "removed", "changes", "vulnerabilities"] as const;
const COMPONENT_SORTS = componentListSort.fields;
const DIRECTIONS = ["asc", "desc"] as const;

const DEFAULTS = {
  tab: "components" as (typeof TABS)[number],
  q: "",
  ecosystem: "",
  sortBy: componentListSort.defaultField,
  sortDir: componentListSort.defaultDirection,
  /** Removed-components table: its own sort, so switching tabs does not carry one onto the other. */
  removedSortBy: removedComponentSort.defaultField,
  removedSortDir: removedComponentSort.defaultDirection,
  /** Scan history table. */
  scanSortBy: scanHistorySort.defaultField,
  scanSortDir: scanHistorySort.defaultDirection,
  page: 1,
  historyPage: 1,
  removedPage: 1,
  ignoreVersion: false,
};

const urlSpec = {
  defaults: DEFAULTS,
  parse: (params: URLSearchParams) => ({
    tab: readEnum(params, "tab", TABS, "components"),
    q: readString(params, "q"),
    ecosystem: readString(params, "ecosystem"),
    sortBy: readEnum(params, "sortBy", COMPONENT_SORTS, componentListSort.defaultField),
    sortDir: readEnum(params, "sortDir", DIRECTIONS, componentListSort.defaultDirection),
    removedSortBy: readEnum(params, "removedSortBy", removedComponentSort.fields, removedComponentSort.defaultField),
    removedSortDir: readEnum(params, "removedSortDir", DIRECTIONS, removedComponentSort.defaultDirection),
    scanSortBy: readEnum(params, "scanSortBy", scanHistorySort.fields, scanHistorySort.defaultField),
    scanSortDir: readEnum(params, "scanSortDir", DIRECTIONS, scanHistorySort.defaultDirection),
    page: readNumber(params, "page", 1),
    historyPage: readNumber(params, "historyPage", 1),
    removedPage: readNumber(params, "removedPage", 1),
    ignoreVersion: readBool(params, "ignoreVersion"),
  }),
};

export function ApplicationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { state, setState } = useUrlState(urlSpec);
  const { isAdmin } = useAuth();
  const [editing, setEditing] = useState(false);

  const { data: app, isLoading, error, refetch } = useApplication(id);
  const { data: definitions } = useAttributeDefinitions();
  const { data: vulnStatus } = useVulnStatus();
  const vulnEnabled = vulnStatus?.enabled === true;

  if (isLoading) return <LoadingBlock label="Loading application" />;
  if (error) return <ErrorBanner error={error} onRetry={() => void refetch()} />;
  if (!app) return null;

  const attributeEntries = (definitions ?? [])
    .filter((d) => d.isActive)
    .map((d) => ({ label: d.label, value: app.attributes[d.key] }));

  return (
    <>
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-2">
            {app.name}
            <StatusBadge status={app.status} />
            {app.isStale ? (
              <Badge tone="warn" title="No scan received recently — the component list may be out of date.">
                Stale
              </Badge>
            ) : null}
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span>
              Last scan{" "}
              <span title={formatDateTime(app.lastScanAt)}>
                {app.lastScanAt ? formatRelative(app.lastScanAt) : "never"}
              </span>
            </span>
            {/* Singular matters now that a freshly registered application reaches
                exactly one scan the moment someone uploads an SBOM by hand. */}
            <span>
              {formatNumber(app.scanCount)} scan{app.scanCount === 1 ? "" : "s"} retained
            </span>
            {app.latestComponentCount !== null ? (
              <span>{formatNumber(app.latestComponentCount)} components in current build</span>
            ) : null}
          </span>
        }
        actions={
          isAdmin && app.status !== "pending_confirmation" ? (
            <Button size="sm" onClick={() => setEditing(true)}>
              Edit application
            </Button>
          ) : isAdmin ? (
            <Link
              to="/admin/pending"
              className="inline-flex items-center rounded-md border border-border-strong bg-bg-raised px-3 py-1.5 text-sm font-medium text-text-base hover:bg-bg-subtle"
            >
              Resolve this record
            </Link>
          ) : undefined
        }
      />

      {app.status === "pending_confirmation" ? (
        <div
          role="note"
          className="mb-4 rounded-lg border border-warn bg-warn-subtle px-4 py-3 text-xs text-warn"
        >
          <strong className="font-semibold">Unconfirmed application.</strong> This was created
          automatically because a scan arrived with an <Mono>app_name</Mono> that matched no existing
          application. The SBOM data below is real and complete; an administrator still needs to confirm,
          merge, or delete this record.
        </div>
      ) : null}

      <div className="mb-4 grid gap-4 lg:grid-cols-[2fr_1fr]">
        <Card>
          <CardHeader title="Attributes" />
          <dl className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-3">
            {attributeEntries.length === 0 ? (
              <p className="col-span-full text-xs text-text-muted">No attributes defined.</p>
            ) : (
              attributeEntries.map((entry) => (
                <Field key={entry.label} label={entry.label}>
                  {entry.value === null || entry.value === undefined || entry.value === "" ? (
                    <span className="text-text-faint">Not set</span>
                  ) : (
                    String(entry.value)
                  )}
                </Field>
              ))
            )}
          </dl>
        </Card>

        <Card>
          <CardHeader title="Record" />
          <dl className="grid grid-cols-2 gap-4 p-4">
            <div className="col-span-2">
              {/*
                Chips link into the filtered applications list, so "Alpine 3.20"
                answers "what else runs this" in one click. Derived from the
                current build only — a historical build's platform belongs on
                that scan's own page.
              */}
              <Field label="Runs on">
                <PlatformChips platform={app.platform} linkFilters />
              </Field>
            </div>
            <Field label="First seen">{formatDateTime(app.createdAt)}</Field>
            <Field label="Updated">{formatDateTime(app.updatedAt)}</Field>
            <div className="col-span-2">
              <Field label="CI aliases">
                {app.aliases.length === 0 ? (
                  <span className="text-text-faint">None</span>
                ) : (
                  <span className="flex flex-wrap gap-1">
                    {app.aliases.map((alias) => (
                      <Badge key={alias} tone="info" title="Scans arriving under this app_name are redirected here.">
                        {alias}
                      </Badge>
                    ))}
                  </span>
                )}
              </Field>
            </div>
          </dl>
        </Card>
      </div>

      <div role="tablist" aria-label="Application views" className="mb-3 flex gap-1 border-b border-border-base">
        <TabButton
          active={state.tab === "components"}
          onClick={() => setState({ tab: "components", page: 1 })}
          label="Current components"
        />
        <TabButton
          active={state.tab === "changes"}
          onClick={() => setState({ tab: "changes" })}
          label="Latest build changes"
        />
        {vulnEnabled ? (
          <TabButton
            active={state.tab === "vulnerabilities"}
            onClick={() => setState({ tab: "vulnerabilities" })}
            label="Vulnerabilities"
          />
        ) : null}
        <TabButton
          active={state.tab === "removed"}
          onClick={() => setState({ tab: "removed", removedPage: 1 })}
          label="No longer used"
        />
        <TabButton
          active={state.tab === "history"}
          onClick={() => setState({ tab: "history" })}
          label={`Scan history (${formatNumber(app.scanCount)})`}
        />
      </div>

      {state.tab === "components" ? (
        <ComponentsTab
          applicationId={app.id}
          hasScan={app.latestScanId !== null}
          state={state}
          setState={setState}
        />
      ) : state.tab === "changes" ? (
        <ChangesTab applicationId={app.id} />
      ) : state.tab === "vulnerabilities" ? (
        <VulnerabilitiesTab applicationId={app.id} enabled={vulnEnabled} isAdmin={isAdmin} />
      ) : state.tab === "removed" ? (
        <RemovedTab applicationId={app.id} state={state} setState={setState} />
      ) : (
        <HistoryTab
          applicationId={app.id}
          applicationName={app.name}
          isAdmin={isAdmin}
          page={state.historyPage}
          sortBy={state.scanSortBy}
          sortDir={state.scanSortDir}
          setState={setState}
        />
      )}

      <ApplicationFormModal open={editing} existing={app} onClose={() => setEditing(false)} />
    </>
  );
}

function TabButton({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`-mb-px border-b-2 px-3 py-2 text-sm transition-colors ${
        active
          ? "border-accent font-medium text-accent"
          : "border-transparent text-text-muted hover:text-text-base"
      }`}
    >
      {label}
    </button>
  );
}

type DetailState = ReturnType<typeof urlSpec.parse>;

function ComponentsTab({
  applicationId,
  hasScan,
  state,
  setState,
}: {
  applicationId: string;
  hasScan: boolean;
  state: DetailState;
  setState: (patch: Partial<DetailState>) => void;
}) {
  const [searchInput, setSearchInput] = useState(state.q);
  const debounced = useDebounced(searchInput, 300);

  useEffect(() => {
    if (debounced !== state.q) setState({ q: debounced });
  }, [debounced, state.q, setState]);

  useEffect(() => {
    setSearchInput(state.q);
  }, [state.q]);

  const params = useMemo(
    () => ({
      search: state.q || undefined,
      ecosystem: state.ecosystem || undefined,
      sortBy: state.sortBy,
      sortDir: state.sortDir,
      page: state.page,
      pageSize: 100,
    }),
    [state],
  );

  const { data, isLoading, isFetching, error, refetch } = useApplicationComponents(applicationId, params);
  const { data: ecosystems } = useApplicationEcosystems(applicationId);

  const sort = useServerSort(componentListSort, state, setState);

  if (!hasScan) {
    return (
      <Card>
        <EmptyState
          title="No scans yet"
          hint="This application has been registered but CI has not posted an SBOM for it. Components appear here after the first scan."
        />
      </Card>
    );
  }

  return (
    <>
      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}
      <Card>
        <CardHeader
          title="Components in the current build"
          subtitle={data ? `${formatNumber(data.total)} matching` : undefined}
          actions={
            <>
              <div className="w-52">
                <TextInput
                  value={searchInput}
                  onChange={setSearchInput}
                  placeholder="Filter packages…"
                  ariaLabel="Filter components by name"
                />
              </div>
              <Select
                value={state.ecosystem}
                onChange={(v) => setState({ ecosystem: v })}
                ariaLabel="Filter by ecosystem"
                options={[
                  { value: "", label: "All ecosystems" },
                  ...(ecosystems ?? []).map((e) => ({
                    value: e.ecosystem,
                    label: `${e.ecosystem} (${e.count})`,
                  })),
                ]}
              />
            </>
          }
        />

        {isLoading ? (
          <LoadingBlock label="Loading components" />
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="No components match" hint="Try clearing the filter or ecosystem selection." />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th onSort={() => sort.toggle("name")} sorted={sort.stateOf("name")}>
                      Package
                    </Th>
                    <Th onSort={() => sort.toggle("version")} sorted={sort.stateOf("version")} width="180px">
                      Version
                    </Th>
                    <Th onSort={() => sort.toggle("ecosystem")} sorted={sort.stateOf("ecosystem")} width="120px">
                      Ecosystem
                    </Th>
                    <Th onSort={() => sort.toggle("purl")} sorted={sort.stateOf("purl")}>
                      Package URL
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((c) => (
                    <Tr key={c.id}>
                      <Td>
                        {/* Cross-links into global search: "who else ships this?" */}
                        <Link
                          to={`/search?name=${encodeURIComponent(c.name)}&match=exact`}
                          className="font-medium text-accent hover:underline"
                          title={`Find every application using ${c.name}`}
                        >
                          {c.name}
                        </Link>
                      </Td>
                      <Td className="nums font-mono text-xs text-text-muted">
                        {c.version ?? <span className="text-text-faint">unknown</span>}
                      </Td>
                      <Td>
                        <span className="rounded bg-neutral-subtle px-1.5 py-0.5 font-mono text-[11px] text-text-muted">
                          {c.ecosystem}
                        </span>
                      </Td>
                      <Td className="max-w-[520px] truncate" title={c.purl ?? undefined}>
                        {c.purl ? <Mono>{c.purl}</Mono> : <span className="text-text-faint">—</span>}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
            <Pagination
              page={data.page}
              pageSize={data.pageSize}
              total={data.total}
              totalPages={data.totalPages}
              onPageChange={(page) => setState({ page })}
              isFetching={isFetching}
            />
          </>
        )}
      </Card>
    </>
  );
}

/**
 * What the most recent build changed, against the build before it.
 *
 * The empty parameters are the point: with no `fromScanId` or `toScanId` the
 * API compares the latest scan with its immediate predecessor, which is the
 * question ninety percent of visitors have.
 */
function ChangesTab({ applicationId }: { applicationId: string }) {
  const { data, isLoading, error } = useApplicationDiff(applicationId, {});

  if (isLoading) return <LoadingBlock label="Comparing builds" />;

  // A 400 here is expected and informative — an application with a single scan
  // has nothing to compare against — so it is rendered as an explanation rather
  // than as a failure with a retry button.
  if (error) {
    return (
      <Card>
        <EmptyState
          title="Nothing to compare"
          hint={error instanceof Error ? error.message : "This application has fewer than two scans."}
        />
      </Card>
    );
  }

  if (!data) return null;
  return <DiffView diff={data} />;
}

/**
 * Everything this application has ever shipped that its current build does not.
 *
 * This is the requirement that justifies retaining scan history indefinitely:
 * "package X was used before (last seen in build #N, on date D) but is not
 * present in the current build."
 */
function RemovedTab({
  applicationId,
  state,
  setState,
}: {
  applicationId: string;
  state: DetailState;
  setState: (patch: Partial<DetailState>) => void;
}) {
  const [searchInput, setSearchInput] = useState("");
  const debounced = useDebounced(searchInput, 300);

  const params = useMemo(
    () => ({
      search: debounced || undefined,
      ignoreVersion: state.ignoreVersion ? "true" : undefined,
      sortBy: state.removedSortBy,
      sortDir: state.removedSortDir,
      page: state.removedPage,
      pageSize: 50,
    }),
    [debounced, state.ignoreVersion, state.removedSortBy, state.removedSortDir, state.removedPage],
  );

  const { data, isLoading, isFetching, error, refetch } = useRemovedComponents(applicationId, params);
  /*
    Its own sort keys in the URL (`removedSortBy`), not shared with the current-components
    table. The two tables are on sibling tabs with different columns, and one shared key
    would mean opening this tab silently re-sorted the other.
  */
  const sort = useServerSort(
    removedComponentSort,
    { sortBy: state.removedSortBy, sortDir: state.removedSortDir },
    (patch) =>
      setState({
        ...(patch.sortBy ? { removedSortBy: patch.sortBy } : {}),
        ...(patch.sortDir ? { removedSortDir: patch.sortDir } : {}),
      }),
  );

  return (
    <>
      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}
      <Card>
        <CardHeader
          title="Packages no longer in the current build"
          subtitle={
            data
              ? `${formatNumber(data.total)} package${data.total === 1 ? "" : "s"} shipped at some point but absent from the latest scan`
              : undefined
          }
          actions={
            <>
              <div className="w-52">
                <TextInput
                  value={searchInput}
                  onChange={setSearchInput}
                  placeholder="Filter packages…"
                  ariaLabel="Filter removed packages by name"
                />
              </div>
              <Checkbox
                checked={state.ignoreVersion}
                onChange={(v) => setState({ ignoreVersion: v, removedPage: 1 })}
                label="Hide version upgrades"
              />
            </>
          }
        />

        <div className="border-b border-border-base px-4 py-2 text-xs text-text-muted">
          {state.ignoreVersion
            ? "Showing only packages with no remaining version — a package that was merely upgraded is hidden."
            : "Showing every package-and-version that has left, including versions replaced by an upgrade. Useful when tracking one known-bad release."}
        </div>

        {isLoading ? (
          <LoadingBlock label="Loading history" />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title={data?.latestScanId ? "Nothing has been dropped" : "No scans yet"}
            hint={
              data?.latestScanId
                ? "Every package this application has ever shipped is still in its current build."
                : "This view compares scan history against the current build, so it needs at least one scan."
            }
          />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th onSort={() => sort.toggle("name")} sorted={sort.stateOf("name")}>
                      Package
                    </Th>
                    <Th onSort={() => sort.toggle("version")} sorted={sort.stateOf("version")} width="180px">
                      Version
                    </Th>
                    <Th onSort={() => sort.toggle("ecosystem")} sorted={sort.stateOf("ecosystem")} width="120px">
                      Ecosystem
                    </Th>
                    <Th onSort={() => sort.toggle("lastSeenAt")} sorted={sort.stateOf("lastSeenAt")} width="220px">
                      Last seen in
                    </Th>
                    <Th onSort={() => sort.toggle("purl")} sorted={sort.stateOf("purl")}>
                      Package URL
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((c) => (
                    <Tr key={c.id}>
                      <Td>
                        <PackageLink name={c.name} />
                      </Td>
                      <Td className="nums font-mono text-xs text-text-muted">{c.version ?? "unknown"}</Td>
                      <Td>
                        <EcosystemBadge ecosystem={c.ecosystem} />
                      </Td>
                      <Td>
                        <LastSeen
                          scanId={c.lastSeenScanId}
                          buildNumber={c.lastSeenBuildNumber}
                          at={c.lastSeenAt}
                        />
                      </Td>
                      <Td className="max-w-[420px] truncate" title={c.purl ?? undefined}>
                        {c.purl ? <Mono>{c.purl}</Mono> : <span className="text-text-faint">—</span>}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
            <Pagination
              page={data.page}
              pageSize={data.pageSize}
              total={data.total}
              totalPages={data.totalPages}
              onPageChange={(removedPage) => setState({ removedPage })}
              isFetching={isFetching}
            />
          </>
        )}
      </Card>
    </>
  );
}

/**
 * Findings for this application's current build.
 *
 * Computed live against today's database rather than read from a record frozen at scan
 * time, which is why an application scanned months ago still shows a CVE published this
 * morning.
 */
function VulnerabilitiesTab({
  applicationId,
  enabled,
  isAdmin,
}: {
  applicationId: string;
  enabled: boolean;
  isAdmin: boolean;
}) {
  const [filters, setFilters] = useState<FindingsFilters>(DEFAULT_FINDINGS_FILTERS);
  const params = useMemo(() => findingsParams(filters), [filters]);
  const findingsSort = useFindingsSort(filters, (patch) => setFilters((f) => ({ ...f, ...patch })));
  const { data, isLoading, isFetching, error, refetch } = useApplicationVulnerabilities(
    applicationId,
    params,
    enabled,
  );

  if (!enabled) return <ScanningDisabledNotice what="Vulnerability findings" isAdmin={isAdmin} />;

  return (
    <>
      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}
      <FindingsCard
        title="Vulnerabilities in the current build"
        subtitle="Matched against the installed vulnerability database. Application dependencies and base-image packages are counted separately — the base image usually contributes far more findings, and it is fixed by a rebuild rather than a dependency change."
        filters={filters}
        onChange={(patch) => setFilters((prev) => ({ ...prev, ...patch }))}
      >
        {data ? <BreakdownTiles breakdown={data.breakdown} /> : null}
        <FindingsTable
          sort={findingsSort}
          data={data}
          isLoading={isLoading}
          isFetching={isFetching}
          applicationId={applicationId}
          onPageChange={(page) => setFilters((prev) => ({ ...prev, page }))}
        />
      </FindingsCard>
    </>
  );
}

function HistoryTab({
  applicationId,
  applicationName,
  isAdmin,
  page,
  sortBy,
  sortDir,
  setState,
}: {
  applicationId: string;
  applicationName: string;
  isAdmin: boolean;
  page: number;
  sortBy: (typeof scanHistorySort)["fields"][number];
  sortDir: SortDirection;
  setState: (patch: Partial<DetailState>) => void;
}) {
  const params = useMemo(() => ({ page, pageSize: 50, sortBy, sortDir }), [page, sortBy, sortDir]);
  const { data, isLoading, isFetching, error, refetch } = useApplicationScans(applicationId, params);
  const [uploading, setUploading] = useState(false);
  /*
    The build queued for deletion, held as the whole row rather than its id.

    The confirmation has to name what it is about to destroy — the date, the build
    number, how many components it recorded — and after the delete succeeds that row
    is gone from the refetched list. Keeping a copy is what lets the dialog describe
    the build rather than say "this scan".
  */
  const [deleteTarget, setDeleteTarget] = useState<ScanSummary | null>(null);
  const deleteScan = useDeleteScan();
  const sort = useServerSort(
    scanHistorySort,
    { sortBy, sortDir },
    (patch) =>
      setState({
        ...(patch.sortBy ? { scanSortBy: patch.sortBy } : {}),
        ...(patch.sortDir ? { scanSortDir: patch.sortDir } : {}),
      }),
  );

  return (
    <>
      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}
      <Card>
        <CardHeader
          title="Scan history"
          subtitle="Every build that submitted an SBOM. Nothing is trimmed automatically — select a build to see the components it shipped."
          actions={
            <Button size="sm" variant="primary" onClick={() => setUploading(true)}>
              Upload SBOM
            </Button>
          }
        />
        {isLoading ? (
          <LoadingBlock label="Loading scan history" />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No scans recorded"
            hint="Nothing has posted an SBOM for this application yet. A CI pipeline will populate this automatically, or you can upload one now with the button above."
          />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th onSort={() => sort.toggle("scannedAt")} sorted={sort.stateOf("scannedAt")} width="170px">
                      Scanned
                    </Th>
                    <Th onSort={() => sort.toggle("buildNumber")} sorted={sort.stateOf("buildNumber")} width="110px">
                      Build
                    </Th>
                    <Th onSort={() => sort.toggle("commitSha")} sorted={sort.stateOf("commitSha")} width="130px">
                      Commit
                    </Th>
                    <Th onSort={() => sort.toggle("branch")} sorted={sort.stateOf("branch")} width="160px">
                      Branch
                    </Th>
                    <Th
                      onSort={() => sort.toggle("componentCount")}
                      sorted={sort.stateOf("componentCount")}
                      align="right"
                      width="110px"
                    >
                      Components
                    </Th>
                    <Th onSort={() => sort.toggle("imageRef")} sorted={sort.stateOf("imageRef")}>
                      Image
                    </Th>
                    {/* Tool name and version as one cell; not a single orderable value. */}
                    <Th width="120px">Syft</Th>
                    <Th align="right" width="90px">
                      SBOM
                    </Th>
                    {/* Unlabelled: a "Delete" heading over a column of buttons reads as
                        an instruction rather than a description of what is below it. */}
                    {isAdmin ? <Th width="80px" /> : null}
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((scan) => (
                    <Tr key={scan.id}>
                      <Td title={formatDateTime(scan.createdAt)}>
                        {/*
                          Timestamp and badges on separate lines. Inline, the date
                          wrapped mid-string to make room for them — "Aug 12, 2026,
                          11:51" / "AM current manual" — and a second badge made
                          that worse rather than rarer.
                        */}
                        <Link
                          to={`/scans/${scan.id}`}
                          className="block whitespace-nowrap text-accent hover:underline"
                        >
                          {formatDateTime(scan.createdAt)}
                        </Link>
                        {scan.isLatest || scan.source === "manual" ? (
                          <span className="mt-0.5 flex flex-wrap gap-1">
                            {scan.isLatest ? (
                              <Badge tone="ok" title="This scan is the application's current state.">
                                current
                              </Badge>
                            ) : null}
                            {/*
                              Only manual uploads are badged. CI is the overwhelming
                              default and labelling it too would be noise on every
                              row, but a hand-uploaded build that looked identical
                              to a pipeline's would misrepresent where the data came
                              from.
                            */}
                            <ScanSourceBadge
                              source={scan.source}
                              uploadedByEmail={scan.uploadedByEmail}
                            />
                          </span>
                        ) : null}
                      </Td>
                      <Td className="nums text-text-muted">{scan.buildNumber ?? "—"}</Td>
                      <Td>
                        <Mono title={scan.commitSha ?? undefined}>{shortSha(scan.commitSha)}</Mono>
                      </Td>
                      <Td className="truncate text-text-muted" title={scan.branch ?? undefined}>
                        {scan.branch ?? "—"}
                      </Td>
                      <Td align="right" className="nums text-text-muted">
                        {formatNumber(scan.componentCount)}
                      </Td>
                      <Td className="max-w-[360px] truncate" title={scan.imageRef ?? undefined}>
                        <Mono>{shortImageRef(scan.imageRef)}</Mono>
                      </Td>
                      <Td className="text-text-muted">{scan.toolVersion ?? "—"}</Td>
                      <Td align="right" className="nums text-text-faint">
                        {formatBytes(scan.sbomSizeBytes)}
                      </Td>
                      {isAdmin ? (
                        <Td align="right">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => {
                              // Clears a failure left over from a previous attempt, so the
                              // dialog does not open already showing someone else's error.
                              deleteScan.reset();
                              setDeleteTarget(scan);
                            }}
                            title={
                              scan.isLatest
                                ? "Delete this build. It is the application's current state, so the build before it becomes current."
                                : "Delete this build from the history."
                            }
                          >
                            Delete
                          </Button>
                        </Td>
                      ) : null}
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
            <Pagination
              page={data.page}
              pageSize={data.pageSize}
              total={data.total}
              totalPages={data.totalPages}
              onPageChange={(historyPage) => setState({ historyPage })}
              isFetching={isFetching}
            />
          </>
        )}
      </Card>

      <UploadSbomModal
        open={uploading}
        onClose={() => setUploading(false)}
        applicationId={applicationId}
        applicationName={applicationName}
      />

      <DeleteScanModal
        scan={deleteTarget}
        applicationName={applicationName}
        isOnlyScan={deleteTarget !== null && (data?.total ?? 0) <= 1}
        busy={deleteScan.isPending}
        error={deleteScan.error}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => {
          if (!deleteTarget) return;
          deleteScan.mutate(
            { scanId: deleteTarget.id, applicationId },
            { onSuccess: () => setDeleteTarget(null) },
          );
        }}
      />
    </>
  );
}
