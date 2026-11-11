import { Fragment, useState } from "react";
import { Link } from "react-router";
import type {
  PackageAdvisoryCounts,
  PackageApplicationEntry,
  PackageSearchRow,
  PackageVersionEntry,
  packageSearchSort,
} from "@sbom/shared";
import { usePackageDetail } from "../lib/queries.ts";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import type { SortControl } from "../lib/useSort.ts";
import { useClientSort } from "../lib/useSort.ts";
import { exportDate, ExportTableButton, type ExportColumn } from "./ExportTable.tsx";
import { CriticalHighBadges } from "./Severity.tsx";
import {
  Badge,
  EcosystemBadge,
  ErrorBanner,
  LoadingBlock,
  NAME_COLUMN_MIN_WIDTH,
  StatusBadge,
  Table,
  TableWrap,
  Td,
  Th,
  Tr,
} from "./ui.tsx";

type PackageSortField = (typeof packageSearchSort)["fields"][number];

const rowKey = (r: PackageSearchRow) => `${r.environmentId}|${r.name.toLowerCase()}|${r.ecosystem}`;

function versionsText(versions: Array<string | null>): string {
  return versions.map((v) => v ?? "unknown").join(", ");
}

/** Export columns for the package table. */
export const PACKAGE_EXPORT_COLUMNS: ExportColumn<PackageSearchRow>[] = [
  { header: "Package", value: (r) => r.name, width: 32 },
  { header: "Ecosystem", value: (r) => r.ecosystem, width: 12 },
  { header: "Kind", value: (r) => r.kind, width: 10 },
  { header: "Environment", value: (r) => r.environmentName, width: 14 },
  { header: "Applications using it now", value: (r) => r.currentApplications, width: 14 },
  { header: "Applications that dropped it", value: (r) => r.historicalApplications, width: 14 },
  { header: "Versions in use", value: (r) => r.versionsInUse, width: 10 },
  { header: "Versions ever used", value: (r) => r.versionsEver, width: 10 },
  { header: "Sample of versions in use", value: (r) => r.versionSample.join(", "), width: 40 },
  { header: "Advisories (current use)", value: (r) => (r.vulnerabilities?.assessed ? r.vulnerabilities.advisories : null), width: 12 },
  { header: "Critical", value: (r) => (r.vulnerabilities?.assessed ? r.vulnerabilities.critical : null), width: 10 },
  { header: "High", value: (r) => (r.vulnerabilities?.assessed ? r.vulnerabilities.high : null), width: 10 },
  { header: "Known exploited", value: (r) => (r.vulnerabilities?.assessed ? r.vulnerabilities.knownExploited : null), width: 10 },
  {
    header: "Vulnerable applications",
    value: (r) => (r.vulnerabilities?.assessed ? r.vulnerabilities.vulnerableApplications : null),
    width: 12,
  },
];

/**
 * One row per package; a row opens into where it is used.
 *
 * Usage first and vulnerabilities after, because that is the question this page answers:
 * which applications ship this package. The advisory columns are context for that answer -
 * a package with nothing against it is still listed, and still drills down to every
 * application that uses it.
 */
export function PackagesTable({
  rows,
  sort,
  showEnvironment,
  showVulns,
  includeInactive,
  initiallyOpen,
}: {
  rows: readonly PackageSearchRow[];
  sort: SortControl<PackageSortField>;
  showEnvironment: boolean;
  showVulns: boolean;
  includeInactive: boolean;
  /** Opens the only row of a one-package result, which is what the reader came for. */
  initiallyOpen: boolean;
}) {
  const [open, setOpen] = useState<Set<string>>(
    () => new Set(initiallyOpen && rows.length === 1 ? [rowKey(rows[0]!)] : []),
  );
  const toggle = (key: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const columnCount = 5 + (showEnvironment ? 1 : 0) + (showVulns ? 2 : 0);

  return (
    <TableWrap>
      <Table>
        <thead>
          <tr>
            <Th minWidth="240px" onSort={() => sort.toggle("name")} sorted={sort.stateOf("name")}>
              Package
            </Th>
            <Th width="110px" onSort={() => sort.toggle("ecosystem")} sorted={sort.stateOf("ecosystem")}>
              Ecosystem
            </Th>
            {showEnvironment ? (
              <Th width="130px" onSort={() => sort.toggle("environment")} sorted={sort.stateOf("environment")}>
                Environment
              </Th>
            ) : null}
            <Th
              align="right"
              width="110px"
              onSort={() => sort.toggle("currentApplications")}
              sorted={sort.stateOf("currentApplications")}
            >
              Used by now
            </Th>
            <Th
              align="right"
              width="110px"
              onSort={() => sort.toggle("historicalApplications")}
              sorted={sort.stateOf("historicalApplications")}
            >
              Dropped by
            </Th>
            <Th width="200px" onSort={() => sort.toggle("versionsInUse")} sorted={sort.stateOf("versionsInUse")}>
              Versions in use
            </Th>
            {showVulns ? (
              <>
                <Th width="170px" onSort={() => sort.toggle("advisories")} sorted={sort.stateOf("advisories")}>
                  Advisories
                </Th>
                <Th
                  align="right"
                  width="120px"
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
          {rows.map((row) => {
            const key = rowKey(row);
            const isOpen = open.has(key);
            const v = row.vulnerabilities;
            return (
              <Fragment key={key}>
                <Tr>
                  <Td>
                    <button
                      type="button"
                      onClick={() => toggle(key)}
                      aria-expanded={isOpen}
                      className="inline-flex items-center gap-1.5 text-left font-medium text-accent hover:underline"
                      title={isOpen ? "Hide where it is used" : "Show versions and applications"}
                    >
                      <span aria-hidden="true" className="w-3 text-text-faint">
                        {isOpen ? "▾" : "▸"}
                      </span>
                      {row.name}
                    </button>
                    {row.kind !== "library" ? (
                      <span className="ml-1.5">
                        <Badge tone="info" title="Part of the base image rather than an application dependency.">
                          {row.kind === "os" ? "operating system" : "runtime"}
                        </Badge>
                      </span>
                    ) : null}
                  </Td>
                  <Td>
                    <EcosystemBadge ecosystem={row.ecosystem} />
                  </Td>
                  {showEnvironment ? <Td className="text-xs text-text-muted">{row.environmentName}</Td> : null}
                  <Td align="right" className="nums">
                    {row.currentApplications > 0 ? (
                      <span className="font-medium">{formatNumber(row.currentApplications)}</span>
                    ) : (
                      <span className="text-text-faint">0</span>
                    )}
                  </Td>
                  <Td align="right" className="nums text-text-muted">
                    {row.historicalApplications > 0 ? formatNumber(row.historicalApplications) : <span className="text-text-faint">0</span>}
                  </Td>
                  <Td className="text-xs" title={row.versionSample.join(", ")}>
                    {row.versionsInUse > 0 ? (
                      <>
                        <span className="nums font-medium">{formatNumber(row.versionsInUse)}</span>
                        <span className="ml-1.5 font-mono text-text-faint">
                          {row.versionSample.slice(0, 2).join(", ")}
                          {row.versionsInUse > 2 ? ", …" : ""}
                        </span>
                      </>
                    ) : (
                      <span className="text-text-faint">none now · {formatNumber(row.versionsEver)} before</span>
                    )}
                  </Td>
                  {showVulns ? (
                    <>
                      <Td>
                        <AdvisoryCell summary={v} inUse={row.currentApplications > 0} />
                      </Td>
                      <Td align="right" className="nums">
                        {v && v.assessed && row.currentApplications > 0 ? (
                          <span className={v.vulnerableApplications > 0 ? "font-medium" : "text-text-faint"}>
                            {formatNumber(v.vulnerableApplications)} of {formatNumber(row.currentApplications)}
                          </span>
                        ) : (
                          <span className="text-text-faint">-</span>
                        )}
                      </Td>
                    </>
                  ) : null}
                </Tr>
                {isOpen ? (
                  <tr>
                    <td colSpan={columnCount} className="border-b border-border-base bg-bg-subtle px-3 py-3">
                      <PackageDetailPanel
                        name={row.name}
                        ecosystem={row.ecosystem}
                        environmentId={row.environmentId}
                        environmentName={row.environmentName}
                        includeInactive={includeInactive}
                      />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            );
          })}
        </tbody>
      </Table>
    </TableWrap>
  );
}

function AdvisoryCell({
  summary,
  inUse,
}: {
  summary: PackageSearchRow["vulnerabilities"];
  inUse: boolean;
}) {
  if (!summary || !inUse) return <span className="text-text-faint">-</span>;
  if (!summary.assessed) {
    return (
      <span className="text-xs text-text-faint" title="The versions in use have not been matched against the vulnerability database yet.">
        not assessed yet
      </span>
    );
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <AdvisoryCounts counts={summary} />
      {summary.unassessedVersions > 0 ? (
        <span className="text-[11px] text-text-faint" title="Some versions in use are still waiting for the scanner.">
          +{summary.unassessedVersions} unassessed
        </span>
      ) : null}
    </span>
  );
}

function AdvisoryCounts({ counts }: { counts: PackageAdvisoryCounts }) {
  if (counts.advisories === 0) {
    return <span className="text-xs text-text-faint">none known</span>;
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span className="nums font-medium" title="Distinct advisories">
        {formatNumber(counts.advisories)}
      </span>
      <CriticalHighBadges critical={counts.critical} high={counts.high} />
      {counts.knownExploited > 0 ? (
        <Badge tone="danger" title="On CISA's Known Exploited Vulnerabilities list">
          {counts.knownExploited} KEV
        </Badge>
      ) : null}
    </span>
  );
}

const APP_EXPORT_COLUMNS: ExportColumn<PackageApplicationEntry>[] = [
  { header: "Application", value: (a) => a.applicationName, width: 36 },
  {
    header: "Status",
    value: (a) => (a.applicationStatus === "pending_confirmation" ? "Unconfirmed" : a.applicationStatus === "active" ? "Active" : "Inactive"),
    width: 14,
  },
  { header: "Usage", value: (a) => (a.usage === "current" ? "Uses it now" : "Dropped it"), width: 14 },
  { header: "Versions", value: (a) => versionsText(a.versions), width: 30 },
  { header: "Advisories", value: (a) => a.vulnerabilities?.advisories ?? null, width: 12 },
  { header: "Critical", value: (a) => a.vulnerabilities?.critical ?? null, width: 10 },
  { header: "High", value: (a) => a.vulnerabilities?.high ?? null, width: 10 },
  { header: "Known exploited", value: (a) => a.vulnerabilities?.knownExploited ?? null, width: 10 },
  { header: "Last seen in build", value: (a) => a.lastSeenBuildNumber, width: 14 },
  { header: "Last seen", value: (a) => exportDate(a.lastSeenAt), width: 18 },
];

/**
 * Where one package is used, in one estate.
 *
 * Fetched when the row opens, not with the search: a search for a common substring can list
 * hundreds of packages, and nobody opens more than a few.
 */
function PackageDetailPanel({
  name,
  ecosystem,
  environmentId,
  environmentName,
  includeInactive,
}: {
  name: string;
  ecosystem: string;
  environmentId: string;
  environmentName: string;
  includeInactive: boolean;
}) {
  const { data, isLoading, error, refetch } = usePackageDetail({
    name,
    ecosystem,
    environment: environmentId,
    includeInactive: includeInactive || undefined,
  });

  const versionSort = useClientSort(
    data?.versions,
    { version: "text", currentApplications: "number", historicalApplications: "number", advisories: "number" } as const,
    { sortBy: "currentApplications" },
    (v, f) =>
      f === "version"
        ? v.version
        : f === "currentApplications"
          ? v.currentApplications
          : f === "historicalApplications"
            ? v.historicalApplications
            : (v.vulnerabilities?.advisories ?? null),
    (v) => v.version ?? "",
  );
  const appSort = useClientSort(
    data?.applications,
    { applicationName: "text", usage: "text", versions: "text", advisories: "number", lastSeenAt: "date" } as const,
    { sortBy: "usage", sortDir: "asc" },
    (a, f) =>
      f === "applicationName"
        ? a.applicationName
        : f === "usage"
          ? a.usage
          : f === "versions"
            ? versionsText(a.versions)
            : f === "advisories"
              ? (a.vulnerabilities?.advisories ?? null)
              : new Date(a.lastSeenAt),
    (a) => a.applicationName.toLowerCase(),
  );

  if (isLoading) return <LoadingBlock label="Loading where it is used" />;
  if (error) return <ErrorBanner error={error} onRetry={() => void refetch()} />;
  if (!data) return null;

  const slug = `${name}-${environmentName}`.replace(/[^A-Za-z0-9._-]+/g, "-");
  const showVulns = data.vulnScanningEnabled;

  return (
    <div className="grid gap-3 xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
      <section className="min-w-0 rounded-md border border-border-base bg-bg-raised">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-base px-3 py-2">
          <h3 className="text-xs font-semibold text-text-base">
            Versions <span className="font-normal text-text-faint">· {data.versions.length}</span>
          </h3>
          <ExportTableButton
            title={`${name} versions`}
            filename={`versions-${slug}`}
            rows={versionSort.rows}
            columns={[
              { header: "Version", value: (v: PackageVersionEntry) => v.version, width: 22 },
              { header: "Applications using it now", value: (v) => v.currentApplications, width: 14 },
              { header: "Applications that moved off it", value: (v) => v.historicalApplications, width: 14 },
              { header: "Advisories", value: (v) => v.vulnerabilities?.advisories ?? null, width: 12 },
              { header: "Critical", value: (v) => v.vulnerabilities?.critical ?? null, width: 10 },
              { header: "High", value: (v) => v.vulnerabilities?.high ?? null, width: 10 },
            ]}
          />
        </div>
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => versionSort.toggle("version")} sorted={versionSort.stateOf("version")}>
                  Version
                </Th>
                <Th
                  align="right"
                  width="90px"
                  onSort={() => versionSort.toggle("currentApplications")}
                  sorted={versionSort.stateOf("currentApplications")}
                >
                  Now
                </Th>
                <Th
                  align="right"
                  width="100px"
                  onSort={() => versionSort.toggle("historicalApplications")}
                  sorted={versionSort.stateOf("historicalApplications")}
                >
                  Moved off
                </Th>
                {showVulns ? (
                  <Th width="150px" onSort={() => versionSort.toggle("advisories")} sorted={versionSort.stateOf("advisories")}>
                    Advisories
                  </Th>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {versionSort.rows.map((v) => (
                <Tr key={v.version ?? "\u0000"}>
                  <Td className="nums font-mono text-xs">{v.version ?? <span className="text-text-faint">unknown</span>}</Td>
                  <Td align="right" className="nums">
                    {v.currentApplications > 0 ? (
                      <span className="font-medium">{v.currentApplications}</span>
                    ) : (
                      <Badge tone="neutral" title="No application ships this version any more.">
                        removed
                      </Badge>
                    )}
                  </Td>
                  <Td align="right" className="nums text-text-muted">
                    {v.historicalApplications}
                  </Td>
                  {showVulns ? (
                    <Td>
                      {v.vulnerabilities ? (
                        <AdvisoryCounts counts={v.vulnerabilities} />
                      ) : v.currentApplications > 0 && !v.assessed ? (
                        <span className="text-xs text-text-faint">not assessed yet</span>
                      ) : (
                        <span className="text-text-faint">-</span>
                      )}
                    </Td>
                  ) : null}
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      </section>

      <section className="min-w-0 rounded-md border border-border-base bg-bg-raised">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-base px-3 py-2">
          <h3 className="text-xs font-semibold text-text-base">
            Applications{" "}
            <span className="font-normal text-text-faint">
              · {data.applications.filter((a) => a.usage === "current").length} now,{" "}
              {data.applications.filter((a) => a.usage === "historical").length} dropped
            </span>
          </h3>
          <ExportTableButton
            title={`${name} applications`}
            filename={`applications-${slug}`}
            rows={appSort.rows}
            columns={APP_EXPORT_COLUMNS}
          />
        </div>
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th
                  minWidth={NAME_COLUMN_MIN_WIDTH}
                  onSort={() => appSort.toggle("applicationName")}
                  sorted={appSort.stateOf("applicationName")}
                >
                  Application
                </Th>
                <Th width="110px" onSort={() => appSort.toggle("usage")} sorted={appSort.stateOf("usage")}>
                  Usage
                </Th>
                <Th onSort={() => appSort.toggle("versions")} sorted={appSort.stateOf("versions")}>
                  Version
                </Th>
                {showVulns ? (
                  <Th width="150px" onSort={() => appSort.toggle("advisories")} sorted={appSort.stateOf("advisories")}>
                    Advisories
                  </Th>
                ) : null}
                <Th width="170px" onSort={() => appSort.toggle("lastSeenAt")} sorted={appSort.stateOf("lastSeenAt")}>
                  Last seen in
                </Th>
              </tr>
            </thead>
            <tbody>
              {appSort.rows.map((a) => (
                <Tr key={a.applicationId}>
                  <Td>
                    <Link to={`/applications/${a.applicationId}`} className="font-medium text-accent hover:underline">
                      {a.applicationName}
                    </Link>
                    {a.applicationStatus !== "active" ? (
                      <span className="ml-1.5">
                        <StatusBadge status={a.applicationStatus} />
                      </span>
                    ) : null}
                  </Td>
                  <Td>
                    {a.usage === "current" ? (
                      <Badge tone="ok" title="The latest build ships this package.">
                        uses now
                      </Badge>
                    ) : (
                      <Badge tone="warn" title="An earlier build shipped it; the latest ships no version of it.">
                        dropped
                      </Badge>
                    )}
                  </Td>
                  <Td className="nums font-mono text-xs text-text-muted">
                    {/* One per line and unbroken: a distro version wraps at its hyphens into nonsense. */}
                    {a.versions.map((v) => (
                      <span key={v ?? "\u0000"} className="block whitespace-nowrap">
                        {v ?? "unknown"}
                      </span>
                    ))}
                  </Td>
                  {showVulns ? (
                    <Td>
                      {a.vulnerabilities ? (
                        a.vulnerabilities.advisories > 0 ? (
                          <Link
                            to={`/applications/${a.applicationId}?tab=vulnerabilities`}
                            className="hover:underline"
                            title="Open this application's findings"
                          >
                            <AdvisoryCounts counts={a.vulnerabilities} />
                          </Link>
                        ) : (
                          <Badge tone="ok" title="No known advisories against the version this application ships.">
                            not vulnerable
                          </Badge>
                        )
                      ) : a.usage === "current" ? (
                        <span className="text-xs text-text-faint">not assessed yet</span>
                      ) : (
                        <span className="text-text-faint">-</span>
                      )}
                    </Td>
                  ) : null}
                  <Td>
                    <Link
                      to={`/scans/${a.lastSeenScanId}`}
                      className="text-accent hover:underline"
                      title={formatDateTime(a.lastSeenAt)}
                    >
                      {a.lastSeenBuildNumber ? `build ${a.lastSeenBuildNumber}` : "scan"}
                    </Link>
                    <span className="ml-1.5 text-xs text-text-faint">{formatRelative(a.lastSeenAt)}</span>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      </section>
    </div>
  );
}
