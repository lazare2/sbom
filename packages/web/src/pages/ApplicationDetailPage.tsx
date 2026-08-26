import { useEffect, useMemo, useState, type ReactNode } from "react";
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
import { ComponentLocationCell } from "../components/ComponentLocationCell.tsx";
import { ExportMenu } from "../components/ExportMenu.tsx";
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
import { ScanningDisabledNotice, SeverityBadge, SeverityBar } from "../components/Severity.tsx";
import {
  useApplicationSast,
  useApplicationSastRuns,
  useApplicationVulnerabilities,
  useVulnStatus,
} from "../lib/queries.ts";
import {
  EMPTY_SEVERITY_COUNTS,
  type SastCategory,
  type SastSeverity,
  type SeverityCounts,
} from "@sbom/shared";
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

const TABS = ["components", "history", "removed", "changes", "vulnerabilities", "sast"] as const;
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
          /*
            Export is offered to every signed-in user, not just admins: it is the same
            inventory the page below already shows, in a shape a tool can read. Gating it
            would push people back to copying tables out of the browser.
          */
          <span className="flex flex-wrap items-center gap-2">
            <ExportMenu subject={app.name} kind="applications" id={app.id} />
            {isAdmin && app.status !== "pending_confirmation" ? (
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
            ) : null}
          </span>
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
          active={state.tab === "sast"}
          onClick={() => setState({ tab: "sast" })}
          label="Static analysis"
        />
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
      ) : state.tab === "sast" ? (
        <SastTab applicationId={app.id} />
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
                    <Th width="320px">Location</Th>
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
                      <Td>
                        <ComponentLocationCell
                          location={c.location}
                          extracted={data.locationsExtractedAt != null}
                          dependantsExtracted={data.dependenciesExtractedAt != null}
                        />
                      </Td>
                      <Td className="max-w-[380px] truncate" title={c.purl ?? undefined}>
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
                      {/*
                        The size doubles as the download rather than earning its own column:
                        the cell already exists to describe the artifact, so making it the
                        handle for it adds an action without adding width.

                        Deliberately not beside Delete. That column is admin-only, and anyone
                        who can see a build should be able to take its SBOM — putting the two
                        together would either hide this from non-admins or give the column
                        different contents per role. It also keeps the destructive button
                        alone, instead of one click away from a harmless one.

                        A plain anchor, not a router Link: the response carries
                        Content-Disposition, so the browser has to handle the navigation
                        rather than the SPA intercepting it. Same reason as ScanDetailPage.
                      */}
                      <Td align="right" className="nums">
                        <a
                          href={`/api/v1/scans/${scan.id}/raw`}
                          download
                          className="text-accent hover:underline"
                          title="Download the SBOM exactly as this build uploaded it."
                        >
                          {formatBytes(scan.sbomSizeBytes)}
                        </a>
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
/** Highest first, same convention as Severity.tsx's SEVERITY_ORDER. */
const SAST_SEVERITY_ORDER: SastSeverity[] = ["critical", "high", "medium", "low"];

const SAST_CATEGORY_LABEL: Record<SastCategory, string> = {
  secrets: "Secrets",
  ast: "Code patterns",
  taint: "Taint",
};

/**
 * What each detection method actually does, shown as the category filter's
 * tooltip. Three very different techniques share this tab, and "why did this
 * one get found and that one not" is otherwise guesswork.
 */
const SAST_CATEGORY_HINT: Record<SastCategory, string> = {
  secrets: "Line-by-line regex: credentials committed to source.",
  ast: "Parsed syntax tree: dangerous calls, matched by name rather than by text.",
  taint: "Untrusted input followed through a function into a dangerous call.",
};

/**
 * sast-scan findings for one run — see "Static analysis (SAST)" in the
 * top-level README.
 *
 * Unlike the Vulnerabilities tab above, this is not live against the current
 * build: it is whatever sast-scan's CI job last posted to `POST /api/v1/sast`,
 * which only moves when that pipeline runs. The run selector is there so that
 * is never mistaken for the findings themselves having changed — two
 * applications differing here may just have differently-recent pipelines.
 */
function SastTab({ applicationId }: { applicationId: string }) {
  const [selectedRunId, setSelectedRunId] = useState<string | undefined>(undefined);
  const [severityFilter, setSeverityFilter] = useState<Set<SastSeverity>>(new Set());
  const [categoryFilter, setCategoryFilter] = useState<Set<SastCategory>>(new Set());
  const [searchInput, setSearchInput] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const search = useDebounced(searchInput, 200);

  const { data, isLoading, isFetching, error, refetch } = useApplicationSast(
    applicationId,
    selectedRunId,
  );
  const { data: runsData } = useApplicationSastRuns(applicationId);

  const run = data?.run ?? null;
  const runs = runsData?.runs ?? [];

  const visible = useMemo(() => {
    if (!run) return [];
    const needle = search.trim().toLowerCase();
    return run.findings.filter((f) => {
      if (severityFilter.size > 0 && !severityFilter.has(f.severity)) return false;
      if (categoryFilter.size > 0 && !categoryFilter.has(f.category)) return false;
      if (needle) {
        const haystack = `${f.file} ${f.ruleId} ${f.message} cwe-${f.cwe}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }, [run, severityFilter, categoryFilter, search]);

  /** Grouped by file, because that is the unit someone actually opens to fix. */
  const byFile = useMemo(() => {
    const groups = new Map<string, typeof visible>();
    for (const f of visible) {
      const existing = groups.get(f.file);
      if (existing) existing.push(f);
      else groups.set(f.file, [f]);
    }
    for (const items of groups.values()) {
      items.sort(
        (a, b) =>
          SAST_SEVERITY_ORDER.indexOf(a.severity) - SAST_SEVERITY_ORDER.indexOf(b.severity) ||
          a.line - b.line,
      );
    }
    return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [visible]);

  if (isLoading) return <LoadingBlock label="Loading SAST findings" />;
  if (error) return <ErrorBanner error={error} onRetry={() => void refetch()} />;

  if (!run) {
    return (
      <EmptyState
        title="No SAST run yet"
        hint={
          <>
            Nothing has been posted to <Mono>POST /api/v1/sast</Mono> for this application. Wire
            up <Mono>ci-templates/gitlab/sast-scan.gitlab-ci.yml</Mono> or{" "}
            <Mono>ci-templates/jenkins/vars/sastScan.groovy</Mono> — see{" "}
            <Mono>sast-scan/README.md</Mono>.
          </>
        }
      />
    );
  }

  const counts: SeverityCounts = { ...EMPTY_SEVERITY_COUNTS, ...run.severityCounts };
  const categoryCounts = run.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.category] = (acc[f.category] ?? 0) + 1;
    return acc;
  }, {});

  const toggle = <T,>(set: Set<T>, value: T): Set<T> => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    return next;
  };

  const filtersActive =
    severityFilter.size > 0 || categoryFilter.size > 0 || search.trim().length > 0;

  return (
    <Card>
      <CardHeader
        title={`${formatNumber(run.findingCount)} finding${run.findingCount === 1 ? "" : "s"}`}
        subtitle={
          <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span title={formatDateTime(run.createdAt)}>Run {formatRelative(run.createdAt)}</span>
            {run.commitSha ? <span>{shortSha(run.commitSha)}</span> : null}
            {run.branch ? <span>{run.branch}</span> : null}
            {runs.length > 1 && runs[0]?.runId !== run.runId ? (
              <Badge tone="warn" title="You are looking at an older run, not the most recent one.">
                Historical run
              </Badge>
            ) : null}
          </span>
        }
        actions={
          <>
            {runs.length > 1 ? (
              <div className="w-64">
                <Select
                  value={selectedRunId ?? runs[0]?.runId ?? ""}
                  onChange={(v) => {
                    setSelectedRunId(v);
                    setExpanded(new Set());
                  }}
                  ariaLabel="Choose which SAST run to view"
                  options={runs.map((r) => ({
                    value: r.runId,
                    label: `${formatDateTime(r.createdAt)} — ${r.findingCount} finding${
                      r.findingCount === 1 ? "" : "s"
                    }${r.commitSha ? ` (${shortSha(r.commitSha)})` : ""}${
                      r.isLatest ? " · latest" : ""
                    }`,
                  }))}
                />
              </div>
            ) : null}
            {run.findingCount > 0 ? <SeverityBar counts={counts} className="w-40" /> : null}
          </>
        }
      />

      {run.findingCount === 0 ? (
        <EmptyState title="Clean run" hint="No findings in this scan." />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2 border-b border-border-base px-4 py-3">
            <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by severity">
              {SAST_SEVERITY_ORDER.filter((s) => (run.severityCounts[s] ?? 0) > 0).map((s) => (
                <FilterChip
                  key={s}
                  active={severityFilter.has(s)}
                  onClick={() => setSeverityFilter(toggle(severityFilter, s))}
                  label={`${s} ${run.severityCounts[s]}`}
                />
              ))}
            </div>

            <span className="h-4 w-px bg-border-base" aria-hidden="true" />

            <div
              className="flex flex-wrap gap-1"
              role="group"
              aria-label="Filter by detection method"
            >
              {(Object.keys(SAST_CATEGORY_LABEL) as SastCategory[])
                .filter((c) => (categoryCounts[c] ?? 0) > 0)
                .map((c) => (
                  <FilterChip
                    key={c}
                    active={categoryFilter.has(c)}
                    onClick={() => setCategoryFilter(toggle(categoryFilter, c))}
                    label={`${SAST_CATEGORY_LABEL[c]} ${categoryCounts[c]}`}
                    title={SAST_CATEGORY_HINT[c]}
                  />
                ))}
            </div>

            <div className="ml-auto w-56">
              <TextInput
                value={searchInput}
                onChange={setSearchInput}
                placeholder="Filter by file, rule, CWE…"
                ariaLabel="Filter findings"
              />
            </div>
          </div>

          {filtersActive ? (
            <div className="border-b border-border-base px-4 py-2 text-xs text-text-muted">
              Showing {formatNumber(visible.length)} of {formatNumber(run.findingCount)} findings.{" "}
              <button
                type="button"
                className="text-accent hover:underline"
                onClick={() => {
                  setSeverityFilter(new Set());
                  setCategoryFilter(new Set());
                  setSearchInput("");
                }}
              >
                Clear filters
              </button>
            </div>
          ) : null}

          {visible.length === 0 ? (
            <EmptyState
              title="No findings match these filters"
              hint="Clear a filter to widen the search."
            />
          ) : (
            <div className={isFetching ? "opacity-60 transition-opacity" : undefined}>
              {byFile.map(([file, items]) => (
                <div key={file}>
                  <div className="flex items-baseline gap-2 border-b border-border-base bg-bg-subtle px-4 py-2">
                    <span className="font-mono text-xs font-medium text-text-base">{file}</span>
                    <span className="text-xs text-text-muted">
                      {items.length} finding{items.length === 1 ? "" : "s"}
                    </span>
                  </div>
                  <ul>
                    {items.map((f) => {
                      const isOpen = expanded.has(f.id);
                      return (
                        <li key={f.id} className="border-b border-border-base last:border-b-0">
                          <button
                            type="button"
                            aria-expanded={isOpen}
                            onClick={() => setExpanded(toggle(expanded, f.id))}
                            className="flex w-full flex-wrap items-center gap-2 px-4 py-2 text-left hover:bg-bg-subtle"
                          >
                            <SeverityBadge severity={f.severity} />
                            <span className="font-mono text-xs text-text-base">{f.ruleId}</span>
                            <span className="nums font-mono text-xs text-text-muted">
                              :{f.line}
                            </span>
                            <span className="truncate text-xs text-text-muted">{f.message}</span>
                            <span className="ml-auto flex items-center gap-2">
                              <Badge tone="neutral" title={SAST_CATEGORY_HINT[f.category]}>
                                {SAST_CATEGORY_LABEL[f.category]}
                              </Badge>
                              <span className="nums text-xs text-text-faint">CWE-{f.cwe}</span>
                              <span className="text-xs text-text-faint" aria-hidden="true">
                                {isOpen ? "▾" : "▸"}
                              </span>
                            </span>
                          </button>

                          {isOpen ? (
                            <div className="space-y-3 border-t border-border-base bg-bg-subtle px-4 py-3">
                              <DetailBlock label="What was found">{f.message}</DetailBlock>
                              <DetailBlock label="How to fix it">
                                {f.remediation || (
                                  <span className="text-text-faint">
                                    This rule ships no guidance — likely from a custom rules file.
                                  </span>
                                )}
                              </DetailBlock>
                              <div className="flex flex-wrap gap-x-8 gap-y-3">
                                <DetailBlock label="Location">
                                  <Mono>
                                    {f.file}:{f.line}:{f.col}
                                  </Mono>
                                </DetailBlock>
                                <DetailBlock label="Reference">
                                  <a
                                    className="text-accent hover:underline"
                                    href={`https://cwe.mitre.org/data/definitions/${f.cwe}.html`}
                                    target="_blank"
                                    rel="noreferrer noopener"
                                  >
                                    CWE-{f.cwe} on cwe.mitre.org
                                  </a>
                                </DetailBlock>
                              </div>
                            </div>
                          ) : null}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </Card>
  );
}

/**
 * A label/value pair inside an expanded finding.
 *
 * Not ui.tsx's `Field`, which truncates its value to a single line and emits
 * dt/dd expecting a `dl` ancestor. The remediation here is a paragraph and has
 * to wrap, which is the whole reason the row expands.
 */
function DetailBlock({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-[11px] font-medium uppercase tracking-wide text-text-faint">
        {label}
      </div>
      <div className="mt-0.5 max-w-3xl text-xs leading-relaxed text-text-muted">{children}</div>
    </div>
  );
}

/**
 * A toggle chip for the filter rows above.
 *
 * Local to this tab rather than added to ui.tsx: the other pages here filter
 * with selects and checkboxes, and promoting a one-off into the shared kit
 * before a second caller exists is how a component library grows things nobody
 * asked for.
 */
function FilterChip({
  active,
  onClick,
  label,
  title,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      title={title}
      className={`rounded-full border px-2.5 py-0.5 text-xs capitalize transition-colors ${
        active
          ? "border-accent bg-accent text-white"
          : "border-border-base bg-bg-base text-text-muted hover:border-accent"
      }`}
    >
      {label}
    </button>
  );
}
