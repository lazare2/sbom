import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import type { ApplicationStatus, ApplicationSummary, PlatformBreakdown } from "@sbom/shared";
import { applicationSort, sortDirections } from "@sbom/shared";
import { useServerSort } from "../lib/useSort.ts";
import {
  useApplications,
  useAttributeDefinitions,
  useAttributeValues,
  usePlatformBreakdown,
  useVulnStatus,
} from "../lib/queries.ts";
import { osLabel, PlatformChips, runtimeLabel } from "../components/Platform.tsx";
import { CriticalHighBadges } from "../components/Severity.tsx";
import { formatDateTime, formatNumber, formatRelative, humanizeKey } from "../lib/format.ts";
import { readBool, readEnum, readEnumList, readNumber, readString, useUrlState } from "../lib/useUrlState.ts";
import { useDebounced } from "../lib/useDebounced.ts";
import {
  Badge,
  Button,
  Card,
  Checkbox,
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Pagination,
  PageHeader,
  Select,
  StatusBadge,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../components/ui.tsx";

const ALL_STATUSES = ["active", "inactive", "pending_confirmation"] as const;
// From the shared declaration, so the headers and the API's validation cannot disagree
// about which columns are sortable.
const SORT_FIELDS = applicationSort.fields;
const DIRECTIONS = sortDirections;


/**
 * Default status filter mirrors the API's own default: active plus unconfirmed.
 * Inactive applications are excluded until asked for, but unconfirmed ones are
 * visible to everyone — a scan from an unrecognised repo should be discoverable
 * immediately rather than waiting on an admin.
 */
const DEFAULTS = {
  search: "",
  status: ["active", "pending_confirmation"] as ApplicationStatus[],
  squad: "",
  owner: "",
  severity: "",
  /**
   * Platform filters, matched against each application's CURRENT build. Held as
   * one combined string per axis (`alpine|3.20`) so a single select can offer
   * both "any Alpine" and "Alpine 3.20" without needing two controls.
   */
  os: "",
  runtime: "",
  staleOnly: false,
  sortBy: applicationSort.defaultField,
  sortDir: applicationSort.defaultDirection,
  /** Which attribute `sortBy=attribute` refers to. */
  sortAttribute: "",
  page: 1,
};

const urlSpec = {
  defaults: DEFAULTS,
  parse: (params: URLSearchParams) => ({
    search: readString(params, "search"),
    status: readEnumList(params, "status", ALL_STATUSES, DEFAULTS.status),
    squad: readString(params, "squad"),
    owner: readString(params, "owner"),
    severity: readString(params, "severity"),
    // Accepts either `?os=alpine` (from a chip link elsewhere in the app) or
    // `?os=alpine|3.20` (from the select). Both have to work, because the chips
    // on the detail pages deliberately link to the looser form.
    os: readString(params, "os") + (params.get("osVersion") ? `|${params.get("osVersion")}` : ""),
    runtime:
      readString(params, "runtime") +
      (params.get("runtimeVersion") ? `|${params.get("runtimeVersion")}` : ""),
    staleOnly: readBool(params, "staleOnly"),
    sortBy: readEnum(params, "sortBy", SORT_FIELDS, applicationSort.defaultField),
    sortDir: readEnum(params, "sortDir", DIRECTIONS, applicationSort.defaultDirection),
    sortAttribute: readString(params, "sortAttribute"),
    page: readNumber(params, "page", 1),
  }),
};

/** Splits `alpine|3.20` into the two query parameters the API takes. */
function splitPlatformValue(value: string): { name?: string; version?: string } {
  if (!value) return {};
  const [name, version] = value.split("|");
  return version ? { name, version } : { name };
}

export function ApplicationsPage() {
  const { state, setState, reset } = useUrlState(urlSpec);

  // Local mirror so typing stays instant while the request is debounced.
  const [searchInput, setSearchInput] = useState(state.search);
  const debouncedSearch = useDebounced(searchInput, 300);

  useEffect(() => {
    if (debouncedSearch !== state.search) setState({ search: debouncedSearch });
  }, [debouncedSearch, state.search, setState]);

  // Keeps the input in sync when the URL changes from outside (back button, reset).
  useEffect(() => {
    setSearchInput(state.search);
  }, [state.search]);

  const queryParams = useMemo(() => {
    const os = splitPlatformValue(state.os);
    const runtime = splitPlatformValue(state.runtime);
    return {
      search: state.search || undefined,
      status: state.status,
      squad: state.squad || undefined,
      owner: state.owner || undefined,
      severity: state.severity || undefined,
      os: os.name,
      osVersion: os.version,
      runtime: runtime.name,
      runtimeVersion: runtime.version,
      staleOnly: state.staleOnly || undefined,
      sortBy: state.sortBy,
      sortDir: state.sortDir,
      page: state.page,
      pageSize: 50,
    };
  }, [state]);

  const { data, isLoading, isFetching, error, refetch } = useApplications(queryParams);
  const { data: definitions } = useAttributeDefinitions();
  const squads = useAttributeValues("squad");
  const owners = useAttributeValues("owner");
  const severities = useAttributeValues("severity");
  // Filter options come from what actually exists in current builds, so the
  // dropdown never offers a distro nothing runs, nor omits one that something does.
  const platforms = usePlatformBreakdown();

  /*
    The findings column exists only while scanning is on. Hidden rather than shown empty:
    a permanently blank column reads as a broken feature, whereas its absence matches a
    platform that is deliberately inventory-only.

    Strict `=== true` because this is undefined while the status request is in flight. An
    optimistic `!== false` would render the column, then remove it a moment later and shift
    every other column sideways as the answer arrives.
  */
  const vulnStatus = useVulnStatus();
  const showFindings = vulnStatus.data?.enabled === true;

  function toggleStatus(status: ApplicationStatus) {
    const next = state.status.includes(status)
      ? state.status.filter((s) => s !== status)
      : [...state.status, status];
    // Never allow an empty status set: it would show nothing and read as a bug.
    setState({ status: next.length > 0 ? next : DEFAULTS.status });
  }

  const sort = useServerSort(applicationSort, state, setState);

  /*
    Attribute columns share one sort field and are distinguished by `sortAttribute`, so
    they need their own toggle: `useServerSort` compares on `sortBy` alone and would treat
    a click on Owner while sorted by Squad as "same column, reverse it".
  */
  function sortByAttribute(key: string) {
    const active = state.sortBy === "attribute" && state.sortAttribute === key;
    if (active) {
      setState({ sortDir: state.sortDir === "asc" ? "desc" : "asc" });
    } else {
      setState({ sortBy: "attribute", sortAttribute: key, sortDir: "asc" });
    }
  }

  const attributeSortState = (key: string) =>
    state.sortBy === "attribute" && state.sortAttribute === key ? state.sortDir : false;

  // Falls back to a humanised key rather than the raw key, so the filter labels
  // never flash as lower_snake_case while the definitions request is in flight.
  const labelFor = (key: string) => definitions?.find((d) => d.key === key)?.label ?? humanizeKey(key);

  const hasFilters =
    state.search !== "" ||
    state.squad !== "" ||
    state.owner !== "" ||
    state.severity !== "" ||
    state.os !== "" ||
    state.runtime !== "" ||
    state.staleOnly ||
    state.status.length !== DEFAULTS.status.length ||
    !state.status.every((s) => DEFAULTS.status.includes(s));

  return (
    <>
      <PageHeader
        title="Applications"
        subtitle={
          data
            ? `${formatNumber(data.total)} application${data.total === 1 ? "" : "s"}`
            : "Loading inventory…"
        }
      />

      <Card className="mb-4">
        <div className="flex flex-wrap items-end gap-3 p-3">
          <div className="min-w-[220px] flex-1">
            <label htmlFor="app-search" className="mb-1 block text-[11px] font-medium text-text-muted">
              Search by name
            </label>
            <TextInput
              id="app-search"
              value={searchInput}
              onChange={setSearchInput}
              placeholder="payments-api"
            />
          </div>

          <div>
            <label htmlFor="f-squad" className="mb-1 block text-[11px] font-medium text-text-muted">
              {labelFor("squad")}
            </label>
            <Select
              id="f-squad"
              value={state.squad}
              onChange={(v) => setState({ squad: v })}
              options={[{ value: "", label: "Any" }, ...(squads.data ?? []).map((v) => ({ value: v, label: v }))]}
            />
          </div>

          <div>
            <label htmlFor="f-owner" className="mb-1 block text-[11px] font-medium text-text-muted">
              {labelFor("owner")}
            </label>
            <Select
              id="f-owner"
              value={state.owner}
              onChange={(v) => setState({ owner: v })}
              options={[{ value: "", label: "Any" }, ...(owners.data ?? []).map((v) => ({ value: v, label: v }))]}
            />
          </div>

          <div>
            <label htmlFor="f-severity" className="mb-1 block text-[11px] font-medium text-text-muted">
              {labelFor("severity")}
            </label>
            <Select
              id="f-severity"
              value={state.severity}
              onChange={(v) => setState({ severity: v })}
              options={[
                { value: "", label: "Any" },
                ...(severities.data ?? []).map((v) => ({ value: v, label: v })),
              ]}
            />
          </div>

          <div>
            <label htmlFor="f-os" className="mb-1 block text-[11px] font-medium text-text-muted">
              Operating system
            </label>
            <Select
              id="f-os"
              value={state.os}
              onChange={(v) => setState({ os: v })}
              options={osFilterOptions(platforms.data)}
            />
          </div>

          <div>
            <label htmlFor="f-runtime" className="mb-1 block text-[11px] font-medium text-text-muted">
              Runtime
            </label>
            <Select
              id="f-runtime"
              value={state.runtime}
              onChange={(v) => setState({ runtime: v })}
              options={runtimeFilterOptions(platforms.data)}
            />
          </div>

          {hasFilters ? (
            <Button size="sm" variant="ghost" onClick={reset}>
              Clear filters
            </Button>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border-base px-3 py-2">
          <span className="text-[11px] font-medium text-text-muted">Show</span>
          {ALL_STATUSES.map((status) => (
            <Checkbox
              key={status}
              checked={state.status.includes(status)}
              onChange={() => toggleStatus(status)}
              label={status === "pending_confirmation" ? "Unconfirmed" : status === "active" ? "Active" : "Inactive"}
            />
          ))}
          <span aria-hidden="true" className="text-border-strong">
            |
          </span>
          <Checkbox
            checked={state.staleOnly}
            onChange={(v) => setState({ staleOnly: v })}
            label="Stale only"
          />
        </div>
      </Card>

      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}

      <Card>
        {isLoading ? (
          <LoadingBlock label="Loading applications" />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No applications match these filters"
            hint={
              hasFilters
                ? "Try clearing the filters. Applications appear here automatically the first time CI posts a scan for them."
                : "Applications appear here automatically the first time CI posts a scan for them."
            }
          />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th onSort={() => sort.toggle("name")} sorted={sort.stateOf("name")}>
                      Application
                    </Th>
                    <Th onSort={() => sort.toggle("status")} sorted={sort.stateOf("status")} width="130px">
                      Status
                    </Th>
                    <Th onSort={() => sortByAttribute("squad")} sorted={attributeSortState("squad")}>
                      {labelFor("squad")}
                    </Th>
                    <Th onSort={() => sortByAttribute("owner")} sorted={attributeSortState("owner")}>
                      {labelFor("owner")}
                    </Th>
                    <Th
                      onSort={() => sortByAttribute("severity")}
                      sorted={attributeSortState("severity")}
                      width="100px"
                    >
                      {labelFor("severity")}
                    </Th>
                    <Th onSort={() => sort.toggle("platform")} sorted={sort.stateOf("platform")} width="240px">
                      Runs on
                    </Th>
                    <Th
                      onSort={() => sort.toggle("componentCount")}
                      sorted={sort.stateOf("componentCount")}
                      align="right"
                      width="110px"
                    >
                      Components
                    </Th>
                    {showFindings ? (
                      <Th
                        onSort={() => sort.toggle("vulnFindings")}
                        sorted={sort.stateOf("vulnFindings")}
                        align="right"
                        width="170px"
                      >
                        Findings
                      </Th>
                    ) : null}
                    <Th
                      onSort={() => sort.toggle("scanCount")}
                      sorted={sort.stateOf("scanCount")}
                      align="right"
                      width="80px"
                    >
                      Scans
                    </Th>
                    <Th onSort={() => sort.toggle("lastScanAt")} sorted={sort.stateOf("lastScanAt")} width="150px">
                      Last scan
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((app) => (
                    <Tr key={app.id}>
                      <Td>
                        <Link
                          to={`/applications/${app.id}`}
                          className="font-medium text-accent hover:underline"
                        >
                          {app.name}
                        </Link>
                      </Td>
                      <Td>
                        <div className="flex flex-wrap items-center gap-1">
                          <StatusBadge status={app.status} />
                          {app.isStale ? (
                            <Badge
                              tone="warn"
                              title="No scan received recently. The dependency list may not reflect what is deployed."
                            >
                              Stale
                            </Badge>
                          ) : null}
                        </div>
                      </Td>
                      <Td className="text-text-muted">{String(app.attributes.squad ?? "—")}</Td>
                      <Td className="text-text-muted">{String(app.attributes.owner ?? "—")}</Td>
                      <Td>
                        <SeverityCell value={app.attributes.severity} />
                      </Td>
                      <Td>
                        <PlatformChips platform={app.platform} />
                      </Td>
                      <Td align="right" className="nums text-text-muted">
                        {formatNumber(app.latestComponentCount)}
                      </Td>
                      {showFindings ? (
                        <Td align="right">
                          <FindingsCell app={app} />
                        </Td>
                      ) : null}
                      <Td align="right" className="nums text-text-muted">
                        {formatNumber(app.scanCount)}
                      </Td>
                      <Td className="text-text-muted" title={formatDateTime(app.lastScanAt)}>
                        {app.lastScanAt ? formatRelative(app.lastScanAt) : <span className="text-text-faint">never</span>}
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
 * Builds the OS filter options: one "any version" entry per distro, then each
 * distinct version under it.
 *
 * Both levels matter. "Any Alpine" answers "are we consistent on Alpine at all";
 * "Alpine 3.19" answers "who is behind". Offering only the versions would make
 * the first question require selecting five options one at a time.
 */
function osFilterOptions(
  data: PlatformBreakdown | undefined,
): Array<{ value: string; label: string }> {
  const options = [{ value: "", label: "Any" }];
  if (!data) return options;

  const byName = new Map<string, { total: number; versions: Array<{ version: string | null; count: number }> }>();
  for (const entry of data.operatingSystems) {
    if (!entry.name) continue;
    const existing = byName.get(entry.name) ?? { total: 0, versions: [] };
    existing.total += entry.applications;
    if (entry.version) existing.versions.push({ version: entry.version, count: entry.applications });
    byName.set(entry.name, existing);
  }

  for (const [name, info] of [...byName.entries()].sort((a, b) => b[1].total - a[1].total)) {
    options.push({ value: name, label: `${osLabel(name)} — any (${info.total})` });
    for (const v of info.versions.sort((a, b) => b.count - a.count)) {
      options.push({ value: `${name}|${v.version}`, label: `  ${osLabel(name)} ${v.version} (${v.count})` });
    }
  }
  return options;
}

function runtimeFilterOptions(
  data: PlatformBreakdown | undefined,
): Array<{ value: string; label: string }> {
  const options = [{ value: "", label: "Any" }];
  if (!data) return options;

  const byName = new Map<string, { total: number; versions: Array<{ version: string | null; count: number }> }>();
  for (const entry of data.runtimes) {
    const existing = byName.get(entry.name) ?? { total: 0, versions: [] };
    existing.total += entry.applications;
    if (entry.version) existing.versions.push({ version: entry.version, count: entry.applications });
    byName.set(entry.name, existing);
  }

  for (const [name, info] of [...byName.entries()].sort((a, b) => b[1].total - a[1].total)) {
    options.push({ value: name, label: `${runtimeLabel(name)} — any (${info.total})` });
    for (const v of info.versions.sort((a, b) => b.count - a.count)) {
      options.push({
        value: `${name}|${v.version}`,
        label: `  ${runtimeLabel(name)} ${v.version} (${v.count})`,
      });
    }
  }
  return options;
}

/**
 * Findings of the application's current build: the total, then the split beneath it.
 *
 * Three states that are not zero, and keeping them apart is the entire point of this cell:
 *
 *   - never scanned            -> em dash. There is no build to assess.
 *   - scanned, not yet matched -> "not assessed". Every scan ingested before scanning was
 *                                 switched on is in this state, as is anything awaiting the
 *                                 next sweep.
 *   - matched, nothing found   -> "0", with "clean" beneath it. A real result.
 *
 * Rendering either of the first two as `0` would report a clean bill of health that nobody
 * issued, against an estate nobody looked at. That is the worst thing this page could say, and
 * it is one `?? 0` away at all times.
 *
 * The split is shown rather than the total alone because the total is not actionable on its
 * own: base-image packages outnumber application dependencies by around a hundred to one, so
 * two applications with identical totals can be a neglected lockfile and a stale base image,
 * which are different problems with different owners.
 */
function FindingsCell({ app }: { app: ApplicationSummary }) {
  const counts = app.vulnerabilities;

  if (counts === null) {
    return app.latestScanId === null ? (
      <span className="text-text-faint">—</span>
    ) : (
      <span
        className="text-xs text-text-faint"
        title="This build has not been matched against the vulnerability database yet. This is not the same as having no findings."
      >
        not assessed
      </span>
    );
  }

  return (
    <div className="flex flex-col items-end gap-0.5">
      <div className="flex items-center gap-1.5">
        <span className="nums font-medium">{formatNumber(counts.total)}</span>
        <CriticalHighBadges critical={counts.critical} high={counts.high} />
      </div>
      {counts.total === 0 ? (
        <span className="text-[11px] text-text-faint">clean</span>
      ) : (
        <span className="nums text-[11px] text-text-faint">
          {formatNumber(counts.app)} app · {formatNumber(counts.os)} image
        </span>
      )}
    </div>
  );
}

/** Severity is a known select attribute, so it gets meaningful colour. */
function SeverityCell({ value }: { value: unknown }) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-text-faint">—</span>;
  }
  const text = String(value);
  const tone =
    text === "critical" ? "danger" : text === "high" ? "warn" : text === "medium" ? "info" : "neutral";
  return <Badge tone={tone}>{text}</Badge>;
}
