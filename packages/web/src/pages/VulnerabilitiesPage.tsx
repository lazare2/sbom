import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import type { AdvisoryDetail, AdvisoryImpact, AdvisorySummary, VulnSeverity } from "@sbom/shared";
import { useAdvisoryImpact, useAdvisorySearch, useVulnStatus } from "../lib/queries.ts";
import { ComponentLocationCell, OriginBadge } from "../components/ComponentLocationCell.tsx";
import {
  AdvisoryApplicationsCell,
  AdvisoryPackagesCell,
} from "../components/ExpandableCounts.tsx";
import { useDebounced } from "../lib/useDebounced.ts";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import { readBool, readEnum, readNumber, readString, useUrlState } from "../lib/useUrlState.ts";
import { SEVERITY_ORDER, SeverityBadge, ScanningDisabledNotice } from "../components/Severity.tsx";
import { advisorySort, sortDirections } from "@sbom/shared";
import { useServerSort } from "../lib/useSort.ts";
import { advisoryHeadline, cweName, cweUrl, decodeCvss, groupReferences, REFERENCE_KIND_LABELS } from "../lib/advisory.ts";
import { ExportTableButton, exportDate, exportList, fetchAllPages, type ExportColumn } from "../components/ExportTable.tsx";
import { useAuth } from "../auth/AuthProvider.tsx";
import {
  Badge,
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
  Select,
  StatusBadge,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
  NAME_COLUMN_MIN_WIDTH,
} from "../components/ui.tsx";

const SCOPES = ["app", "os", "all"] as const;


const DEFAULTS = {
  q: "",
  scope: "app" as (typeof SCOPES)[number],
  severity: "" as VulnSeverity | "",
  fixable: false,
  knownExploited: false,
  currentOnly: true,
  sortBy: advisorySort.defaultField,
  sortDir: advisorySort.defaultDirection,
  page: 1,
};

const urlSpec = {
  defaults: DEFAULTS,
  parse: (params: URLSearchParams) => ({
    q: readString(params, "q"),
    scope: readEnum(params, "scope", SCOPES, "app"),
    severity: readEnum(params, "severity", ["", ...SEVERITY_ORDER] as const, ""),
    fixable: readBool(params, "fixable"),
    knownExploited: readBool(params, "knownExploited"),
    // Defaults true, so the URL carries `currentOnly=false` when it is turned off.
    currentOnly: params.get("currentOnly") !== "false",
    sortBy: readEnum(params, "sortBy", advisorySort.fields, advisorySort.defaultField),
    sortDir: readEnum(params, "sortDir", sortDirections, advisorySort.defaultDirection),
    page: readNumber(params, "page", 1),
  }),
};

/**
 * Estate-wide advisory search: "who is affected by CVE-2021-44228?"
 *
 * The view the whole feature exists for, and the reason findings are keyed on the package
 * rather than the build: the answer is computed against today's database across every
 * retained scan, so a CVE published this morning immediately lists the applications that
 * have been shipping the affected version for months.
 */
export function VulnerabilitiesPage() {
  const { state, setState } = useUrlState(urlSpec);
  const sort = useServerSort(advisorySort, state, setState);
  const { isAdmin } = useAuth();
  const { data: status, isLoading: statusLoading } = useVulnStatus();

  const [searchInput, setSearchInput] = useState(state.q);
  const debounced = useDebounced(searchInput, 300);

  useEffect(() => {
    if (debounced !== state.q) setState({ q: debounced, page: 1 });
  }, [debounced, state.q, setState]);
  useEffect(() => {
    setSearchInput(state.q);
  }, [state.q]);

  const params = useMemo(
    () => ({
      q: state.q || undefined,
      scope: state.scope,
      severity: state.severity || undefined,
      fixable: state.fixable ? "true" : undefined,
      knownExploited: state.knownExploited ? "true" : undefined,
      currentOnly: state.currentOnly ? undefined : "false",
      sortBy: state.sortBy,
      sortDir: state.sortDir,
      page: state.page,
      pageSize: 50,
    }),
    [state],
  );

  const enabled = status?.enabled === true;
  const { data, isLoading, isFetching, error, refetch } = useAdvisorySearch(params, enabled);

  if (statusLoading) return <LoadingBlock label="Loading" />;

  if (!enabled) {
    return (
      <>
        <PageHeader title="Vulnerabilities" />
        <ScanningDisabledNotice what="Vulnerability findings" isAdmin={isAdmin} />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        subtitle={
          <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span>Advisories affecting packages in this estate, newest database first.</span>
            {status?.database?.builtAt ? (
              <span title={formatDateTime(status.database.builtAt)}>
                Database updated {formatRelative(status.database.builtAt)}
              </span>
            ) : null}
            {status?.coverage && status.coverage.pending > 0 ? (
              <Badge tone="info" title="A sweep is still matching packages, so counts may rise.">
                {formatNumber(status.coverage.pending)} packages pending
              </Badge>
            ) : null}
          </span>
        }
        actions={
          <ExportTableButton
            title="Advisories"
            filename="advisories"
            fetchRows={(progress) => fetchAllPages<AdvisorySummary>("/vulnerabilities", params, progress)}
            columns={ADVISORY_EXPORT_COLUMNS}
          />
        }
      />

      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}

      <Card>
        <CardHeader
          title={data ? `${formatNumber(data.total)} advisories` : "Advisories"}
          subtitle="Search by CVE, GHSA or package name. A CVE number finds the advisory even when Grype reports it under a GHSA id."
          actions={
            <>
              <div className="w-60">
                <TextInput
                  value={searchInput}
                  onChange={setSearchInput}
                  placeholder="CVE-2021-44228, GHSA-…, or a package"
                  ariaLabel="Search advisories"
                />
              </div>
              <Select
                value={state.scope}
                onChange={(scope) => setState({ scope: scope as (typeof SCOPES)[number], page: 1 })}
                ariaLabel="Package scope"
                options={[
                  { value: "app", label: "Application dependencies" },
                  { value: "os", label: "Base image and runtimes" },
                  { value: "all", label: "Everything" },
                ]}
              />
              <Select
                value={state.severity}
                onChange={(severity) => setState({ severity: severity as VulnSeverity | "", page: 1 })}
                ariaLabel="Severity"
                options={[
                  { value: "", label: "Any severity" },
                  ...SEVERITY_ORDER.map((s) => ({ value: s, label: s[0]!.toUpperCase() + s.slice(1) })),
                ]}
              />
              <Checkbox
                checked={state.fixable}
                onChange={(fixable) => setState({ fixable, page: 1 })}
                label="Fix available"
              />
              <Checkbox
                checked={state.knownExploited}
                onChange={(knownExploited) => setState({ knownExploited, page: 1 })}
                label="Known exploited"
              />
              <Checkbox
                checked={!state.currentOnly}
                onChange={(all) => setState({ currentOnly: !all, page: 1 })}
                label="Include dropped packages"
              />
            </>
          }
        />

        <div className="border-b border-border-base px-4 py-2 text-xs text-text-muted">
          {state.currentOnly
            ? "Showing advisories against packages in some application's current build - what is shipping now."
            : "Including packages an application shipped at some point but no longer does. Useful when checking historical exposure."}
        </div>

        {isLoading ? (
          <LoadingBlock label="Searching advisories" />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No advisories match"
            hint={
              state.q
                ? `Nothing in this estate is affected by anything matching "${state.q}".`
                : "Nothing matches these filters."
            }
          />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th onSort={() => sort.toggle("severity")} sorted={sort.stateOf("severity")} width="105px">
                      Severity
                    </Th>
                    <Th
                      onSort={() => sort.toggle("vulnerability")}
                      sorted={sort.stateOf("vulnerability")}
                      width="200px"
                    >
                      Advisory
                    </Th>
                    {/* Free prose. There is no ordering of it a reader would find useful. */}
                    <Th>Description</Th>
                    <Th onSort={() => sort.toggle("packages")} sorted={sort.stateOf("packages")} align="right" width="100px">
                      Packages
                    </Th>
                    <Th
                      onSort={() => sort.toggle("applications")}
                      sorted={sort.stateOf("applications")}
                      align="right"
                      width="100px"
                    >
                      Apps now
                    </Th>
                    <Th
                      onSort={() => sort.toggle("historicalApplications")}
                      sorted={sort.stateOf("historicalApplications")}
                      align="right"
                      width="110px"
                    >
                      Apps dropped
                    </Th>
                    <Th onSort={() => sort.toggle("fixAvailable")} sorted={sort.stateOf("fixAvailable")} width="90px">
                      Fix
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((advisory) => (
                    <Tr key={advisory.vulnerabilityId}>
                      <Td>
                        <SeverityBadge severity={advisory.severity} />
                      </Td>
                      <Td>
                        <div className="flex flex-col gap-0.5">
                          <Link
                            to={`/vulnerabilities/${encodeURIComponent(advisory.vulnerabilityId)}`}
                            className="font-mono text-xs text-accent hover:underline"
                          >
                            {advisory.vulnerabilityId}
                          </Link>
                          {advisory.aliases.length > 0 ? (
                            <span className="font-mono text-[11px] text-text-faint">
                              {advisory.aliases.slice(0, 2).join(", ")}
                            </span>
                          ) : null}
                          {advisory.knownExploited ? (
                            <Badge tone="danger" title="On CISA's Known Exploited Vulnerabilities list.">
                              exploited
                            </Badge>
                          ) : null}
                        </div>
                      </Td>
                      <Td className="max-w-[520px] text-text-muted" title={advisory.description ?? undefined}>
                        {/* The title where there is one, else the first sentence: two lines at most. */}
                        <span className="line-clamp-2">{advisoryHeadline(advisory) ?? " - "}</span>
                      </Td>
                      <AdvisoryPackagesCell advisory={advisory} />
                      <AdvisoryApplicationsCell advisory={advisory} />
                      <AdvisoryApplicationsCell advisory={advisory} historical />
                      <Td>
                        {advisory.fixAvailable ? (
                          <Badge tone="ok">available</Badge>
                        ) : (
                          <span className="text-xs text-text-faint">none</span>
                        )}
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
 * One advisory's blast radius.
 *
 * The page someone opens the morning a CVE is announced. Currently-affected applications
 * sort first, because "what do we need to fix" comes before "what did we used to ship".
 */
export function AdvisoryDetailPage() {
  const { vulnerabilityId } = useParams<{ vulnerabilityId: string }>();
  const { isAdmin } = useAuth();
  const { data: status } = useVulnStatus();
  const { data, isLoading, error, refetch } = useAdvisoryImpact(vulnerabilityId);

  if (status && !status.enabled) {
    return (
      <>
        <PageHeader title={vulnerabilityId ?? "Advisory"} />
        <ScanningDisabledNotice what="Vulnerability findings" isAdmin={isAdmin} />
      </>
    );
  }

  if (isLoading) return <LoadingBlock label="Loading advisory" />;
  if (error) return <ErrorBanner error={error} onRetry={() => void refetch()} />;
  if (!data) return null;

  const { advisory } = data;
  const current = data.applications.filter((a) => a.current);
  const historical = data.applications.filter((a) => !a.current);

  return (
    <>
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-2">
            <Mono>{advisory.vulnerabilityId}</Mono>
            <SeverityBadge severity={advisory.severity} />
            {advisory.knownExploited ? (
              <Badge tone="danger" title="On CISA's Known Exploited Vulnerabilities list.">
                known exploited
              </Badge>
            ) : null}
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span>
              {formatNumber(current.length)} application{current.length === 1 ? "" : "s"} affected now
            </span>
            <span>{formatNumber(advisory.affectedPackages)} package versions</span>
            {advisory.fixAvailable ? <span className="text-ok">A fix is available</span> : null}
          </span>
        }
        actions={
          <Link to="/vulnerabilities" className="text-sm text-accent hover:underline">
            ← All advisories
          </Link>
        }
      />

      <AdvisoryAboutCard advisory={advisory} />

      <ImpactTable
        title="Affected now"
        subtitle="The affected package is in these applications' current builds."
        rows={current}
        advisoryId={data.advisory.vulnerabilityId}
        emptyHint="No application currently ships an affected package version."
      />

      {historical.length > 0 ? (
        <div className="mt-4">
          <ImpactTable
            title="Previously affected"
            subtitle="These applications shipped an affected version at some point but their current build does not."
            rows={historical}
            advisoryId={data.advisory.vulnerabilityId}
            emptyHint=""
          />
        </div>
      ) : null}

      {data.truncated ? (
        <p className="mt-3 text-xs text-warn">
          Only the first 500 applications are listed - this advisory affects more than that.
        </p>
      ) : null}
    </>
  );
}

function ImpactTable({
  title,
  subtitle,
  rows,
  advisoryId,
  emptyHint,
}: {
  title: string;
  subtitle: string;
  rows: AdvisoryImpact["applications"];
  advisoryId: string;
  emptyHint: string;
}) {
  return (
    <Card>
      <CardHeader
        title={title}
        subtitle={subtitle}
        actions={
          rows.length > 0 ? (
            <ExportTableButton
              title={title}
              filename={`${advisoryId}-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}
              rows={rows}
              columns={[
                { header: "Application", value: (r) => r.applicationName, width: 36 },
                { header: "Status", value: (r) => r.applicationStatus, width: 14 },
                { header: "In current build", value: (r) => (r.current ? "yes" : "no"), width: 14 },
                {
                  header: "Affected packages",
                  value: (r) => exportList(r.packages.map((p) => `${p.name} ${p.version ?? "unknown"}`)),
                  width: 40,
                },
                { header: "Ecosystems", value: (r) => exportList([...new Set(r.packages.map((p) => p.ecosystem))]), width: 14 },
                {
                  header: "Fixed in",
                  value: (r) => exportList([...new Set(r.packages.flatMap((p) => p.fixVersions))]),
                  width: 20,
                },
                {
                  header: "Locations",
                  value: (r) => exportList(r.packages.flatMap((p) => p.location.paths ?? [])),
                  width: 50,
                },
                { header: "Last seen", value: (r) => exportDate(r.lastSeenAt), width: 18 },
              ]}
            />
          ) : undefined
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="None" hint={emptyHint} />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th minWidth={NAME_COLUMN_MIN_WIDTH}>Application</Th>
                <Th width="110px">Status</Th>
                <Th>Affected packages</Th>
                <Th width="160px">Fixed in</Th>
                <Th width="170px">Last seen</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <Tr key={row.applicationId}>
                  <Td>
                    <Link
                      to={`/applications/${row.applicationId}?tab=vulnerabilities`}
                      className="font-medium text-accent hover:underline"
                    >
                      {row.applicationName}
                    </Link>
                  </Td>
                  <Td>
                    <StatusBadge status={row.applicationStatus} />
                  </Td>
                  <Td>
                    <span className="flex flex-col gap-1.5">
                      {row.packages.map((pkg) => (
                        <span key={pkg.componentId}>
                          <span className="whitespace-nowrap">
                            <span className="text-text-base">{pkg.name}</span>{" "}
                            <Mono>{pkg.version ?? "unknown"}</Mono>{" "}
                            <EcosystemBadge ecosystem={pkg.ecosystem} />{" "}
                            <OriginBadge origin={pkg.location.origin} />
                          </span>
                          {/* Stacked rather than wrapped now that each package carries a
                              path: side by side, two long paths become unreadable. */}
                          <ComponentLocationCell location={pkg.location} compact />
                        </span>
                      ))}
                    </span>
                  </Td>
                  <Td>
                    {row.packages.some((p) => p.fixVersions.length > 0) ? (
                      <Mono>
                        {row.packages.flatMap((p) => p.fixVersions).slice(0, 2).join(", ")}
                      </Mono>
                    ) : (
                      <span className="text-xs text-text-faint">no fix</span>
                    )}
                  </Td>
                  <Td>
                    <Link
                      to={`/scans/${row.lastSeenScanId}`}
                      className="text-xs text-accent hover:underline"
                      title={formatDateTime(row.lastSeenAt)}
                    >
                      {formatRelative(row.lastSeenAt)}
                    </Link>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </Card>
  );
}

/** One row per advisory, as the advisory list shows it. */
const ADVISORY_EXPORT_COLUMNS: ExportColumn<AdvisorySummary>[] = [
  { header: "Severity", value: (a) => a.severity, width: 10 },
  { header: "Advisory", value: (a) => a.vulnerabilityId, width: 22 },
  { header: "Aliases", value: (a) => exportList(a.aliases), width: 22 },
  { header: "CVSS", value: (a) => a.cvssBaseScore, width: 7 },
  { header: "EPSS", value: (a) => a.epssScore, width: 8 },
  { header: "Known exploited", value: (a) => (a.knownExploited ? "yes" : "no"), width: 14 },
  { header: "Summary", value: (a) => a.summary, width: 40 },
  { header: "Description", value: (a) => a.description, width: 60 },
  { header: "Weaknesses (CWE)", value: (a) => exportList(a.cwes), width: 18 },
  { header: "Packages", value: (a) => a.affectedPackages, width: 10 },
  { header: "Package versions", value: (a) => exportList(a.affectedPackageList), width: 40 },
  { header: "Apps now", value: (a) => a.currentApplications, width: 10 },
  { header: "Applications now", value: (a) => exportList(a.currentApplicationList), width: 40 },
  { header: "Apps dropped", value: (a) => a.historicalApplications, width: 12 },
  { header: "Fix available", value: (a) => (a.fixAvailable ? "yes" : "no"), width: 12 },
  { header: "References", value: (a) => exportList(a.urls), width: 50 },
];

/**
 * What the advisory is, in the order a reader needs it: what it is called, what it does, how
 * it is exploited, how likely that is, what class of flaw it is, and where to read more.
 *
 * Every line is drawn from the advisory's own data. The plain-language exploitability
 * sentence is a translation of the CVSS vector beside it, so a reader can check one against
 * the other.
 */
function AdvisoryAboutCard({ advisory }: { advisory: AdvisoryDetail }) {
  const cvss = decodeCvss(advisory.cvssVector);
  const references = groupReferences(advisory.urls);

  return (
    <Card className="mb-4">
      <CardHeader title="About this vulnerability" />
      <div className="space-y-5 p-4">
        <section>
          {advisory.summary ? (
            <h3 className="mb-1.5 text-sm font-semibold text-text-base">{advisory.summary}</h3>
          ) : null}
          {advisory.description ? (
            // pre-line: NVD separates the affected release lines with newlines, and running
            // them together into one sentence makes them unreadable.
            <p className="max-w-[90ch] text-sm leading-relaxed whitespace-pre-line text-text-base">
              {advisory.description}
            </p>
          ) : (
            <p className="text-sm text-text-faint">The vulnerability database carries no description for this advisory.</p>
          )}
        </section>

        <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Field label="Severity">
            <SeverityBadge severity={advisory.severity} />
          </Field>
          <Field label="CVSS base score">
            {advisory.cvssBaseScore === null ? " - " : `${advisory.cvssBaseScore.toFixed(1)}${cvss ? ` (CVSS ${cvss.version})` : ""}`}
          </Field>
          <Field label="Chance of exploitation (EPSS)">
            {/* Shown as a percentage because a raw 0.99999 reads as a score rather than a
                probability, and this one genuinely means "almost certainly exploited". */}
            {advisory.epssScore === null ? (
              " - "
            ) : (
              <span title="Estimated probability of exploitation in the wild in the next 30 days.">
                {(advisory.epssScore * 100).toFixed(2)}% in 30 days
                {advisory.epssPercentile !== null ? (
                  <span className="block text-[11px] text-text-faint">
                    higher than {Math.floor(advisory.epssPercentile * 100)}% of all CVEs
                  </span>
                ) : null}
              </span>
            )}
          </Field>
          <Field label="Also known as">
            {advisory.aliases.length > 0 ? <Mono>{advisory.aliases.join(", ")}</Mono> : " - "}
          </Field>
        </dl>

        {advisory.knownExploited ? (
          <p className="rounded-md border border-danger/40 bg-danger-subtle px-3 py-2 text-xs text-danger">
            On CISA's Known Exploited Vulnerabilities catalogue: attackers are already using this in
            the wild. Treat it as urgent regardless of its score.
          </p>
        ) : null}

        {cvss ? (
          <section>
            <h3 className="mb-1.5 text-xs font-medium text-text-muted">How it can be exploited</h3>
            <p className="mb-2 max-w-[90ch] text-sm text-text-base">{cvss.sentence}</p>
            <div className="flex flex-wrap gap-1.5">
              {cvss.metrics.map((metric) => (
                <Badge key={metric.label} tone={metric.severe ? "warn" : "neutral"}>
                  {metric.label}: {metric.value}
                </Badge>
              ))}
            </div>
            <p className="mt-1.5">
              <Mono title="The CVSS vector these are read from">{advisory.cvssVector}</Mono>
            </p>
          </section>
        ) : null}

        {advisory.cwes.length > 0 ? (
          <section>
            <h3 className="mb-1.5 text-xs font-medium text-text-muted">Type of weakness</h3>
            <ul className="flex flex-col gap-0.5 text-sm">
              {advisory.cwes.map((cwe) => (
                <li key={cwe}>
                  <a href={cweUrl(cwe)} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">
                    <span className="font-mono text-xs">{cwe}</span>
                    {cweName(cwe) ? <span className="ml-2">{cweName(cwe)}</span> : null}
                  </a>
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        {references.length > 0 ? (
          <section>
            <h3 className="mb-1.5 text-xs font-medium text-text-muted">References</h3>
            <div className="grid gap-3 sm:grid-cols-2">
              {references.map(([kind, urls]) => (
                <div key={kind} className="min-w-0">
                  <div className="mb-0.5 text-[11px] font-semibold tracking-wide text-text-faint uppercase">
                    {REFERENCE_KIND_LABELS[kind]}
                  </div>
                  <ul className="flex flex-col gap-0.5">
                    {urls.map((url) => (
                      <li key={url} className="min-w-0">
                        <a
                          href={url}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="block truncate text-xs text-accent hover:underline"
                          title={url}
                        >
                          {url}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </section>
        ) : null}

        {advisory.dataSource ? (
          <p className="text-[11px] text-text-faint">
            Reported by{" "}
            {/^https?:\/\//.test(advisory.dataSource) ? (
              <a href={advisory.dataSource} target="_blank" rel="noreferrer noopener" className="hover:underline">
                {advisory.dataSource}
              </a>
            ) : (
              advisory.dataSource
            )}
          </p>
        ) : null}
      </div>
    </Card>
  );
}
