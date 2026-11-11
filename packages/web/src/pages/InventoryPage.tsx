import { Link } from "react-router";
import type {
  EcosystemBreakdownEntry,
  FragmentationEntry,
  InventoryOsEntry,
  InventoryPackageEntry,
  InventoryReport,
  InventoryRuntimeEntry,
  TopProjectEntry,
} from "@sbom/shared";
import { ApplicationsCell } from "../components/ExpandableCounts.tsx";
import { ExportTableButton, exportDate, exportList } from "../components/ExportTable.tsx";
import { osLabel, runtimeLabel } from "../components/Platform.tsx";
import { CriticalHighBadges, ScanningDisabledNotice } from "../components/Severity.tsx";
import { ShareBar, StatTile } from "../components/StatTile.tsx";
import {
  readTeamFilterParams,
  TEAM_FILTER_URL_DEFAULTS,
  TeamFilterBanner,
  TeamFilterBar,
  teamFilterQuery,
} from "../components/TeamFilter.tsx";
import { useAuth } from "../auth/AuthProvider.tsx";
import { formatDateTime, formatNumber } from "../lib/format.ts";
import { useInventoryReport } from "../lib/queries.ts";
import { useClientSort } from "../lib/useSort.ts";
import { useUrlState } from "../lib/useUrlState.ts";
import {
  Badge,
  Card,
  CardHeader,
  EcosystemBadge,
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Mono,
  PageHeader,
  Table,
  TableWrap,
  Td,
  Th,
  Tr,
} from "../components/ui.tsx";

/**
 * What the estate is made of.
 *
 * Which packages, distributions and runtimes are in use, and what is known against them -
 * always over what the reader can see, in the selected environment, optionally narrowed to some
 * squads, tribes or groups. The progress questions (what got fixed, who needs attention) are
 * Analytics; this page is the state of things as they stand.
 */

const urlSpec = {
  defaults: { ...TEAM_FILTER_URL_DEFAULTS },
  parse: (params: URLSearchParams) => readTeamFilterParams(params),
};

const searchHref = (name: string, ecosystem: string) =>
  `/search?name=${encodeURIComponent(name)}&match=exact&ecosystem=${encodeURIComponent(ecosystem)}`;

export function InventoryPage() {
  const { state, setState } = useUrlState(urlSpec);
  const { isAdmin } = useAuth();
  const query = useInventoryReport({ ...teamFilterQuery(state), limit: 25 });

  return (
    <>
      <PageHeader
        title="Inventory"
        subtitle={
          query.data ? (
            <>
              What {query.data.environmentName} is made of: the packages, base images and runtimes in each
              application's current build, and what is known against them. Built {formatDateTime(query.data.generatedAt)}
              {query.isFetching ? <span className="ml-2 text-text-faint">updating…</span> : null}
            </>
          ) : (
            "What the estate is made of, and what is known against it."
          )
        }
      />

      <Card className="mb-4">
        <div className="p-3">
          <TeamFilterBar filter={state} onChange={(next) => setState(next)} />
        </div>
      </Card>

      {query.isLoading ? (
        <LoadingBlock label="Building inventory" />
      ) : query.error ? (
        <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />
      ) : query.data ? (
        <InventoryBody report={query.data} isAdmin={isAdmin} />
      ) : null}
    </>
  );
}

function InventoryBody({ report, isAdmin }: { report: InventoryReport; isAdmin: boolean }) {
  const { totals } = report;
  return (
    <>
      <TeamFilterBanner label={report.filterLabel} />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Applications" value={totals.applications} hint="With a current build" to="/applications" />
        <StatTile label="Packages in use" value={totals.packages} hint="Application dependencies, by name" />
        <StatTile label="Base images" value={totals.operatingSystems} hint="Distribution and version pairs" />
        <StatTile
          label="Runtimes"
          value={totals.runtimes}
          hint={
            totals.unknownPlatform > 0
              ? `${formatNumber(totals.unknownPlatform)} application${totals.unknownPlatform === 1 ? "" : "s"} with no platform detected`
              : "Runtime and version pairs"
          }
        />
      </div>

      {!report.vulnScanningEnabled ? (
        <div className="mt-4">
          <ScanningDisabledNotice what="Vulnerability columns" isAdmin={isAdmin} />
        </div>
      ) : null}

      <div className="mt-4">
        <PackagesCard
          title="Most used packages"
          subtitle="Application dependencies in the most applications' current builds - the blast radius if one turns out to be a problem. Base-image packages are counted under base images below."
          filename="most-used-packages"
          rows={report.mostUsedPackages}
          initialSort="applications"
          showVulns={report.vulnScanningEnabled}
          empty="No application dependencies in current builds."
        />
      </div>

      {report.vulnScanningEnabled ? (
        <div className="mt-4">
          <PackagesCard
            title="Most vulnerable packages"
            subtitle="Application dependencies with the most critical, then high, advisories against the versions in current builds. Distinct advisories, accepted risks left out - one upgrade here usually clears several applications."
            filename="most-vulnerable-packages"
            rows={report.mostVulnerablePackages}
            initialSort="critical"
            showVulns
            empty="No advisories against any application dependency in current builds."
          />
        </div>
      ) : null}

      <div className="mt-4">
        <OperatingSystemsCard rows={report.operatingSystems} showVulns={report.vulnScanningEnabled} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <RuntimesCard rows={report.runtimes} />
        <EcosystemCard rows={report.ecosystems} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <FragmentationCard rows={report.fragmentation} />
        <LargestApplicationsCard rows={report.largestApplications} />
      </div>
    </>
  );
}

/** Size, not risk: a big image costs more to review and patch, but is not automatically worse. */
function LargestApplicationsCard({ rows }: { rows: TopProjectEntry[] }) {
  // Reduced over every row, not read off the first: the headers are sortable.
  const max = rows.reduce((m, r) => Math.max(m, r.packages), 0);
  const sort = useClientSort(
    rows,
    { application: "text", platform: "text", packages: "number" } as const,
    { sortBy: "packages" },
    (r, f) => (f === "application" ? r.name : f === "platform" ? r.platform : r.packages),
    (r) => r.applicationId,
  );
  return (
    <Card>
      <CardHeader
        title="Largest applications"
        subtitle="Most packages in the current build. A size ranking, not a risk ranking - a big image costs more to review and patch, but is not automatically in worse shape."
        actions={
          <ExportTableButton
            title="Largest applications"
            filename="largest-applications"
            rows={sort.rows}
            columns={[
              { header: "Application", value: (p) => p.name, width: 36 },
              { header: "Runs on", value: (p) => p.platform, width: 32 },
              { header: "Packages", value: (p) => p.packages, width: 10 },
              { header: "Build received", value: (p) => exportDate(p.scanAt), width: 18 },
            ]}
          />
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="No builds yet" hint="Applications appear here once they report an SBOM." />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("application")} sorted={sort.stateOf("application")}>
                  Application
                </Th>
                <Th onSort={() => sort.toggle("platform")} sorted={sort.stateOf("platform")}>
                  Runs on
                </Th>
                <Th onSort={() => sort.toggle("packages")} sorted={sort.stateOf("packages")} align="right">
                  Packages
                </Th>
                <Th width="130px">Share</Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((p) => (
                <Tr key={p.applicationId}>
                  <Td>
                    <Link to={`/applications/${p.applicationId}`} className="font-medium text-accent hover:underline">
                      {p.name}
                    </Link>
                  </Td>
                  <Td>
                    <Mono>{p.platform ?? "not detected"}</Mono>
                  </Td>
                  <Td align="right" className="nums">
                    {formatNumber(p.packages)}
                  </Td>
                  <Td>
                    <ShareBar value={p.packages} max={max} />
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

// ---------------------------------------------------------------------------
// packages
// ---------------------------------------------------------------------------

type PackageSortField = "name" | "applications" | "versions" | "advisories" | "critical" | "vulnerableApplications" | "fixable";

function PackagesCard({
  title,
  subtitle,
  filename,
  rows,
  initialSort,
  showVulns,
  empty,
}: {
  title: string;
  subtitle: string;
  filename: string;
  rows: InventoryPackageEntry[];
  initialSort: PackageSortField;
  showVulns: boolean;
  empty: string;
}) {
  const v = (r: InventoryPackageEntry) => (r.vulnerabilities?.assessed ? r.vulnerabilities : null);
  const sort = useClientSort(
    rows,
    {
      name: "text",
      applications: "number",
      versions: "number",
      advisories: "number",
      critical: "number",
      vulnerableApplications: "number",
      fixable: "number",
    } as const,
    { sortBy: initialSort },
    (r, f) =>
      f === "name"
        ? r.name
        : f === "applications"
          ? r.applications
          : f === "versions"
            ? r.versions
            : f === "advisories"
              ? (v(r)?.advisories ?? null)
              : f === "critical"
                ? (v(r) ? v(r)!.critical * 10_000 + v(r)!.high : null)
                : f === "vulnerableApplications"
                  ? (v(r)?.vulnerableApplications ?? null)
                  : (v(r)?.fixable ?? null),
    (r) => `${r.name}|${r.ecosystem}`,
  );

  return (
    <Card>
      <CardHeader
        title={title}
        subtitle={subtitle}
        actions={
          <ExportTableButton
            title={title}
            filename={filename}
            rows={sort.rows}
            columns={[
              { header: "Package", value: (r) => r.name, width: 32 },
              { header: "Ecosystem", value: (r) => r.ecosystem, width: 12 },
              { header: "Applications", value: (r) => r.applications, width: 12 },
              { header: "Application names", value: (r) => exportList(r.applicationList), width: 40 },
              { header: "Versions in use", value: (r) => r.versions, width: 10 },
              { header: "Sample versions", value: (r) => exportList(r.versionSample), width: 30 },
              ...(showVulns
                ? [
                    { header: "Advisories", value: (r: InventoryPackageEntry) => v(r)?.advisories ?? null, width: 10 },
                    { header: "Critical", value: (r: InventoryPackageEntry) => v(r)?.critical ?? null, width: 10 },
                    { header: "High", value: (r: InventoryPackageEntry) => v(r)?.high ?? null, width: 10 },
                    { header: "Known exploited", value: (r: InventoryPackageEntry) => v(r)?.knownExploited ?? null, width: 10 },
                    { header: "With a fix", value: (r: InventoryPackageEntry) => v(r)?.fixable ?? null, width: 10 },
                    {
                      header: "Vulnerable applications",
                      value: (r: InventoryPackageEntry) => v(r)?.vulnerableApplications ?? null,
                      width: 12,
                    },
                  ]
                : []),
            ]}
          />
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="Nothing to list" hint={empty} />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th minWidth="220px" onSort={() => sort.toggle("name")} sorted={sort.stateOf("name")}>
                  Package
                </Th>
                <Th align="right" width="90px" onSort={() => sort.toggle("applications")} sorted={sort.stateOf("applications")}>
                  Apps
                </Th>
                <Th width="220px" onSort={() => sort.toggle("versions")} sorted={sort.stateOf("versions")}>
                  Versions in use
                </Th>
                {showVulns ? (
                  <>
                    <Th width="110px" align="right" onSort={() => sort.toggle("advisories")} sorted={sort.stateOf("advisories")}>
                      Advisories
                    </Th>
                    <Th width="150px" onSort={() => sort.toggle("critical")} sorted={sort.stateOf("critical")}>
                      Critical / high
                    </Th>
                    <Th width="100px" align="right" onSort={() => sort.toggle("fixable")} sorted={sort.stateOf("fixable")}>
                      With a fix
                    </Th>
                    <Th
                      width="130px"
                      align="right"
                      onSort={() => sort.toggle("vulnerableApplications")}
                      sorted={sort.stateOf("vulnerableApplications")}
                    >
                      Vulnerable apps
                    </Th>
                  </>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((r) => {
                const vulns = v(r);
                return (
                  <Tr key={`${r.name}|${r.ecosystem}`}>
                    <Td>
                      <Link to={searchHref(r.name, r.ecosystem)} className="font-medium text-accent hover:underline">
                        {r.name}
                      </Link>{" "}
                      <EcosystemBadge ecosystem={r.ecosystem} />
                    </Td>
                    <ApplicationsCell count={r.applications} names={r.applicationList} what="ship this package" />
                    <Td>
                      <span className="nums mr-1.5 font-medium">{formatNumber(r.versions)}</span>
                      <Mono>
                        {r.versionSample.slice(0, 3).join(", ")}
                        {r.versions > 3 ? ", …" : ""}
                      </Mono>
                    </Td>
                    {showVulns ? (
                      vulns ? (
                        <>
                          <Td align="right" className="nums">
                            {vulns.advisories > 0 ? formatNumber(vulns.advisories) : <span className="text-text-faint">0</span>}
                          </Td>
                          <Td>
                            <span className="inline-flex flex-wrap gap-1">
                              <CriticalHighBadges critical={vulns.critical} high={vulns.high} />
                              {vulns.knownExploited > 0 ? (
                                <Badge tone="danger" title="On CISA's Known Exploited Vulnerabilities list">
                                  {vulns.knownExploited} KEV
                                </Badge>
                              ) : null}
                              {vulns.critical === 0 && vulns.high === 0 && vulns.knownExploited === 0 ? (
                                <span className="text-text-faint">-</span>
                              ) : null}
                            </span>
                          </Td>
                          <Td align="right" className="nums text-text-muted">
                            {formatNumber(vulns.fixable)}
                          </Td>
                          <Td align="right" className="nums">
                            {formatNumber(vulns.vulnerableApplications)} of {formatNumber(r.applications)}
                          </Td>
                        </>
                      ) : (
                        <>
                          <Td align="right" className="text-xs text-text-faint">
                            <span title="The versions in use have not been matched against the vulnerability database yet.">
                              not assessed yet
                            </span>
                          </Td>
                          <Td>{""}</Td>
                          <Td>{""}</Td>
                          <Td>{""}</Td>
                        </>
                      )
                    ) : null}
                  </Tr>
                );
              })}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// base images
// ---------------------------------------------------------------------------

function osHref(r: InventoryOsEntry): string {
  return `/applications?os=${encodeURIComponent(r.name)}${r.version ? `&osVersion=${encodeURIComponent(r.version)}` : ""}`;
}

function OperatingSystemsCard({ rows, showVulns }: { rows: InventoryOsEntry[]; showVulns: boolean }) {
  // Assessable is a property of the active database, not of one row: every row carries
  // figures or none does.
  const withVulns = showVulns && rows.some((r) => r.vulnerabilities !== null);
  const sort = useClientSort(
    rows,
    {
      os: "text",
      applications: "number",
      findings: "number",
      average: "number",
      critical: "number",
      high: "number",
      fixable: "number",
    } as const,
    { sortBy: "applications" },
    (r, f) =>
      f === "os"
        ? `${osLabel(r.name)} ${r.version ?? ""}`
        : f === "applications"
          ? r.applications
          : f === "findings"
            ? (r.vulnerabilities?.findings ?? null)
            : f === "average"
              ? (r.vulnerabilities?.averageFindings ?? null)
              : f === "critical"
                ? (r.vulnerabilities?.critical ?? null)
                : f === "high"
                  ? (r.vulnerabilities?.high ?? null)
                  : (r.vulnerabilities?.fixable ?? null),
    (r) => `${r.name}|${r.version ?? ""}`,
  );

  return (
    <Card>
      <CardHeader
        title="Base images"
        subtitle={
          withVulns
            ? "Distributions in current builds, by how many applications run them, with the base-image findings of those applications. Findings are package and advisory pairs per application, so the average per application is the figure to compare - twelve services on one old distribution are one base-image upgrade."
            : "Distributions in current builds, by how many applications run them."
        }
        actions={
          <ExportTableButton
            title="Base images"
            filename="base-images"
            rows={sort.rows}
            columns={[
              { header: "Distribution", value: (r) => osLabel(r.name), width: 18 },
              { header: "Version", value: (r) => r.version, width: 12 },
              { header: "Release", value: (r) => r.pretty, width: 30 },
              { header: "Applications", value: (r) => r.applications, width: 12 },
              { header: "Application names", value: (r) => exportList(r.applicationList), width: 40 },
              ...(withVulns
                ? [
                    { header: "Assessed applications", value: (r: InventoryOsEntry) => r.vulnerabilities?.assessedApplications ?? null, width: 12 },
                    { header: "Findings", value: (r: InventoryOsEntry) => r.vulnerabilities?.findings ?? null, width: 10 },
                    { header: "Average per application", value: (r: InventoryOsEntry) => r.vulnerabilities?.averageFindings ?? null, width: 12 },
                    { header: "Critical", value: (r: InventoryOsEntry) => r.vulnerabilities?.critical ?? null, width: 10 },
                    { header: "High", value: (r: InventoryOsEntry) => r.vulnerabilities?.high ?? null, width: 10 },
                    { header: "With a fix", value: (r: InventoryOsEntry) => r.vulnerabilities?.fixable ?? null, width: 10 },
                    { header: "Known exploited", value: (r: InventoryOsEntry) => r.vulnerabilities?.knownExploited ?? null, width: 10 },
                  ]
                : []),
            ]}
          />
        }
      />
      {showVulns && !withVulns && rows.length > 0 ? (
        <p className="border-b border-border-base px-4 py-2 text-[11px] text-text-faint">
          The active vulnerability database holds no data for operating-system packages, so base-image findings are not
          shown rather than shown as zero.
        </p>
      ) : null}
      {rows.length === 0 ? (
        <EmptyState title="No distribution detected" hint="Scratch and distroless images report no operating system." />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th minWidth="200px" onSort={() => sort.toggle("os")} sorted={sort.stateOf("os")}>
                  Distribution
                </Th>
                <Th align="right" width="90px" onSort={() => sort.toggle("applications")} sorted={sort.stateOf("applications")}>
                  Apps
                </Th>
                {withVulns ? (
                  <>
                    <Th align="right" width="100px" onSort={() => sort.toggle("findings")} sorted={sort.stateOf("findings")}>
                      Findings
                    </Th>
                    <Th align="right" width="120px" onSort={() => sort.toggle("average")} sorted={sort.stateOf("average")}>
                      Per app
                    </Th>
                    <Th align="right" width="90px" onSort={() => sort.toggle("critical")} sorted={sort.stateOf("critical")}>
                      Critical
                    </Th>
                    <Th align="right" width="80px" onSort={() => sort.toggle("high")} sorted={sort.stateOf("high")}>
                      High
                    </Th>
                    <Th align="right" width="100px" onSort={() => sort.toggle("fixable")} sorted={sort.stateOf("fixable")}>
                      With a fix
                    </Th>
                  </>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((r) => {
                const vulns = r.vulnerabilities;
                const partial = vulns !== null && vulns.assessedApplications < r.applications;
                return (
                  <Tr key={`${r.name}|${r.version ?? ""}`}>
                    <Td>
                      <Link to={osHref(r)} className="font-medium text-accent hover:underline" title={r.pretty ?? undefined}>
                        {osLabel(r.name)}
                      </Link>{" "}
                      {r.version ? <Mono>{r.version}</Mono> : null}
                    </Td>
                    <ApplicationsCell count={r.applications} names={r.applicationList} what="run this distribution" />
                    {withVulns ? (
                      vulns && vulns.assessedApplications > 0 ? (
                        <>
                          <Td align="right" className="nums">
                            {formatNumber(vulns.findings)}
                          </Td>
                          <Td align="right" className="nums">
                            <span className="font-medium">{vulns.averageFindings}</span>
                            {partial ? (
                              <span
                                className="ml-1 text-[11px] text-text-faint"
                                title={`Averaged over the ${vulns.assessedApplications} application(s) already matched.`}
                              >
                                ({vulns.assessedApplications} of {r.applications})
                              </span>
                            ) : null}
                          </Td>
                          <Td align="right" className="nums">
                            {vulns.critical > 0 ? <Badge tone="danger">{formatNumber(vulns.critical)}</Badge> : <span className="text-text-faint">0</span>}
                          </Td>
                          <Td align="right" className="nums">
                            {vulns.high > 0 ? <Badge tone="warn">{formatNumber(vulns.high)}</Badge> : <span className="text-text-faint">0</span>}
                          </Td>
                          <Td align="right" className="nums text-text-muted">
                            {formatNumber(vulns.fixable)}
                          </Td>
                        </>
                      ) : (
                        <>
                          <Td align="right" className="text-xs text-text-faint">
                            not assessed yet
                          </Td>
                          <Td>{""}</Td>
                          <Td>{""}</Td>
                          <Td>{""}</Td>
                          <Td>{""}</Td>
                        </>
                      )
                    ) : null}
                  </Tr>
                );
              })}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// runtimes, ecosystems, fragmentation - moved here from Analytics
// ---------------------------------------------------------------------------

function RuntimesCard({ rows }: { rows: InventoryRuntimeEntry[] }) {
  const sort = useClientSort(
    rows,
    { runtime: "text", applications: "number" } as const,
    { sortBy: "applications" },
    (r, f) => (f === "runtime" ? `${runtimeLabel(r.name)} ${r.version ?? ""}` : r.applications),
    (r) => `${r.name}|${r.version ?? ""}`,
  );
  return (
    <Card>
      <CardHeader
        title="Language runtimes"
        subtitle="Observed in each application's current build. An application appears once per runtime it ships."
        actions={
          <ExportTableButton
            title="Language runtimes"
            filename="runtimes"
            rows={sort.rows}
            columns={[
              { header: "Runtime", value: (r) => runtimeLabel(r.name), width: 18 },
              { header: "Version", value: (r) => r.version, width: 14 },
              { header: "Applications", value: (r) => r.applications, width: 12 },
              { header: "Application names", value: (r) => exportList(r.applicationList), width: 40 },
            ]}
          />
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="No runtime detected" />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("runtime")} sorted={sort.stateOf("runtime")}>
                  Runtime
                </Th>
                <Th align="right" width="90px" onSort={() => sort.toggle("applications")} sorted={sort.stateOf("applications")}>
                  Apps
                </Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((r) => (
                <Tr key={`${r.name}|${r.version ?? ""}`}>
                  <Td>
                    <Link
                      to={`/applications?runtime=${encodeURIComponent(r.name)}${r.version ? `&runtimeVersion=${encodeURIComponent(r.version)}` : ""}`}
                      className="font-medium text-accent hover:underline"
                    >
                      {runtimeLabel(r.name)}
                    </Link>{" "}
                    {r.version ? <Mono>{r.version}</Mono> : null}
                  </Td>
                  <ApplicationsCell count={r.applications} names={r.applicationList} what="ship this runtime" />
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </Card>
  );
}

function EcosystemCard({ rows: all }: { rows: EcosystemBreakdownEntry[] }) {
  const rows = all.slice(0, 12);
  // Reduced over every row, not read off the first: the headers are sortable.
  const max = rows.reduce((m, r) => Math.max(m, r.components), 0);
  const sort = useClientSort(
    rows,
    { ecosystem: "text", components: "number", applications: "number" } as const,
    { sortBy: "components" },
    (r, f) => (f === "ecosystem" ? r.ecosystem : f === "components" ? r.components : r.applications),
    (r) => r.ecosystem,
  );
  return (
    <Card>
      <CardHeader
        title="Ecosystem mix"
        subtitle="Distinct application dependencies in current builds, by package manager. Base-image packages are counted under base images."
        actions={
          <ExportTableButton
            title="Ecosystem mix"
            filename="ecosystem-mix"
            rows={sort.rows}
            columns={[
              { header: "Ecosystem", value: (e) => e.ecosystem, width: 14 },
              { header: "Packages", value: (e) => e.components, width: 10 },
              { header: "Applications", value: (e) => e.applications, width: 12 },
              { header: "Application names", value: (e) => exportList(e.applicationList), width: 40 },
            ]}
          />
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="No components yet" />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("ecosystem")} sorted={sort.stateOf("ecosystem")}>
                  Ecosystem
                </Th>
                <Th onSort={() => sort.toggle("components")} sorted={sort.stateOf("components")} align="right">
                  Packages
                </Th>
                <Th onSort={() => sort.toggle("applications")} sorted={sort.stateOf("applications")} align="right">
                  Apps
                </Th>
                <Th width="130px">Share</Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((e) => (
                <Tr key={e.ecosystem}>
                  <Td>
                    <Link to={`/search?ecosystem=${encodeURIComponent(e.ecosystem)}`} className="hover:underline">
                      <EcosystemBadge ecosystem={e.ecosystem} />
                    </Link>
                  </Td>
                  <Td align="right" className="nums">
                    {formatNumber(e.components)}
                  </Td>
                  <ApplicationsCell count={e.applications} names={e.applicationList} what="ship a package from this ecosystem" />
                  <Td>
                    <ShareBar value={e.components} max={max} />
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

function FragmentationCard({ rows }: { rows: FragmentationEntry[] }) {
  const sort = useClientSort(
    rows,
    { package: "text", count: "number", applications: "number" } as const,
    { sortBy: "count" },
    (r, f) => (f === "package" ? r.name : f === "count" ? r.versions : r.applications),
    (r) => `${r.name}|${r.ecosystem}`,
  );
  return (
    <Card>
      <CardHeader
        title="Version fragmentation"
        subtitle="Packages run in several versions at once. Each extra version multiplies the cost of the next upgrade - work that can actually be finished."
        actions={
          <ExportTableButton
            title="Version fragmentation"
            filename="version-fragmentation"
            rows={sort.rows}
            columns={[
              { header: "Package", value: (r) => r.name, width: 32 },
              { header: "Ecosystem", value: (r) => r.ecosystem, width: 12 },
              { header: "Versions in use", value: (r) => r.versions, width: 14 },
              { header: "Example versions", value: (r) => exportList(r.examples), width: 40 },
              { header: "Applications", value: (r) => r.applications, width: 12 },
            ]}
          />
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="No fragmentation" hint="Every deployed package is on a single version." />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("package")} sorted={sort.stateOf("package")}>
                  Package
                </Th>
                <Th>Versions in use</Th>
                <Th onSort={() => sort.toggle("count")} sorted={sort.stateOf("count")} align="right">
                  Count
                </Th>
                <Th onSort={() => sort.toggle("applications")} sorted={sort.stateOf("applications")} align="right">
                  Apps
                </Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((f) => (
                <Tr key={`${f.name}|${f.ecosystem}`}>
                  <Td>
                    <Link to={searchHref(f.name, f.ecosystem)} className="font-medium text-accent hover:underline">
                      {f.name}
                    </Link>{" "}
                    <EcosystemBadge ecosystem={f.ecosystem} />
                  </Td>
                  <Td>
                    <Mono>
                      {f.examples.join(", ")}
                      {f.versions > f.examples.length ? ", …" : ""}
                    </Mono>
                  </Td>
                  <Td align="right" className="nums">
                    <Badge tone={f.versions >= 4 ? "warn" : "neutral"}>{formatNumber(f.versions)}</Badge>
                  </Td>
                  <Td align="right" className="nums">
                    {formatNumber(f.applications)}
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
