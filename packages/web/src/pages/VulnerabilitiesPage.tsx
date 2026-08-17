import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import type { AdvisoryImpact, VulnSeverity } from "@sbom/shared";
import { useAdvisoryImpact, useAdvisorySearch, useVulnStatus } from "../lib/queries.ts";
import { useDebounced } from "../lib/useDebounced.ts";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import { readBool, readEnum, readNumber, readString, useUrlState } from "../lib/useUrlState.ts";
import { SEVERITY_ORDER, SeverityBadge, ScanningDisabledNotice } from "../components/Severity.tsx";
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
} from "../components/ui.tsx";

const SCOPES = ["app", "os", "all"] as const;
const SORTS = ["severity", "applications", "packages", "vulnerability"] as const;

const DEFAULTS = {
  q: "",
  scope: "app" as (typeof SCOPES)[number],
  severity: "" as VulnSeverity | "",
  fixable: false,
  knownExploited: false,
  currentOnly: true,
  sortBy: "severity" as (typeof SORTS)[number],
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
    sortBy: readEnum(params, "sortBy", SORTS, "severity"),
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
            ? "Showing advisories against packages in some application's current build — what is shipping now."
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
                    <Th width="105px">Severity</Th>
                    <Th width="200px">Advisory</Th>
                    <Th>Description</Th>
                    <Th align="right" width="100px">
                      Packages
                    </Th>
                    <Th align="right" width="100px">
                      Apps now
                    </Th>
                    <Th align="right" width="110px">
                      Apps dropped
                    </Th>
                    <Th width="90px">Fix</Th>
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
                      <Td className="max-w-[520px] truncate text-text-muted" title={advisory.description ?? undefined}>
                        {advisory.description ?? "—"}
                      </Td>
                      <Td align="right" className="nums text-text-muted">
                        {formatNumber(advisory.affectedPackages)}
                      </Td>
                      <Td align="right" className="nums font-medium text-text-base">
                        {formatNumber(advisory.currentApplications)}
                      </Td>
                      <Td align="right" className="nums text-text-faint">
                        {formatNumber(advisory.historicalApplications)}
                      </Td>
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

      <Card className="mb-4">
        <CardHeader title="Advisory" />
        <dl className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
          <Field label="Severity">{advisory.severity}</Field>
          <Field label="CVSS base score">{advisory.cvssBaseScore?.toFixed(1) ?? "—"}</Field>
          <Field label="EPSS">
            {/* Shown as a percentage because a raw 0.99999 reads as a score rather than a
                probability, and this one genuinely means "almost certainly exploited". */}
            {advisory.epssScore === null ? "—" : `${(advisory.epssScore * 100).toFixed(1)}%`}
          </Field>
          <Field label="Also known as">
            {advisory.aliases.length > 0 ? <Mono>{advisory.aliases.join(", ")}</Mono> : "—"}
          </Field>
          {advisory.description ? (
            <div className="col-span-2 sm:col-span-4">
              <Field label="Description">
                <span className="text-text-base">{advisory.description}</span>
              </Field>
            </div>
          ) : null}
          {advisory.urls.length > 0 ? (
            <div className="col-span-2 sm:col-span-4">
              <Field label="References">
                <span className="flex flex-col gap-0.5">
                  {advisory.urls.slice(0, 4).map((url) => (
                    <a
                      key={url}
                      href={url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="truncate text-xs text-accent hover:underline"
                    >
                      {url}
                    </a>
                  ))}
                </span>
              </Field>
            </div>
          ) : null}
        </dl>
      </Card>

      <ImpactTable
        title="Affected now"
        subtitle="The affected package is in these applications' current builds."
        rows={current}
        emptyHint="No application currently ships an affected package version."
      />

      {historical.length > 0 ? (
        <div className="mt-4">
          <ImpactTable
            title="Previously affected"
            subtitle="These applications shipped an affected version at some point but their current build does not."
            rows={historical}
            emptyHint=""
          />
        </div>
      ) : null}

      {data.truncated ? (
        <p className="mt-3 text-xs text-warn">
          Only the first 500 applications are listed — this advisory affects more than that.
        </p>
      ) : null}
    </>
  );
}

function ImpactTable({
  title,
  subtitle,
  rows,
  emptyHint,
}: {
  title: string;
  subtitle: string;
  rows: AdvisoryImpact["applications"];
  emptyHint: string;
}) {
  return (
    <Card>
      <CardHeader title={title} subtitle={subtitle} />
      {rows.length === 0 ? (
        <EmptyState title="None" hint={emptyHint} />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Application</Th>
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
                    <span className="flex flex-wrap gap-x-3 gap-y-1">
                      {row.packages.map((pkg) => (
                        <span key={pkg.componentId} className="whitespace-nowrap">
                          <span className="text-text-base">{pkg.name}</span>{" "}
                          <Mono>{pkg.version ?? "unknown"}</Mono>{" "}
                          <EcosystemBadge ecosystem={pkg.ecosystem} />
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
