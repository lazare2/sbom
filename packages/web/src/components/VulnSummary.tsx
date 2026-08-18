import { Link } from "react-router";
import {
  bucketize,
  dashboardSeverityBuckets,
  SEVERITY_BUCKET_LABELS,
  totalOf,
  type DashboardSeverityBucket,
  type SeverityCounts,
  type VulnerabilityReport,
  type VulnScopeTotals,
} from "@sbom/shared";
import { SEVERITY_ORDER } from "@sbom/shared";
import { formatNumber, formatRelative } from "../lib/format.ts";
import { useAdvisorySearch } from "../lib/queries.ts";
import { useClientSort } from "../lib/useSort.ts";
import { AdvisoryApplicationsCell, AdvisoryPackagesCell } from "./AdvisoryPackages.tsx";
import { SeverityBar, SeverityBadge } from "./Severity.tsx";
import {
  Badge,
  Card,
  CardHeader,
  EmptyState,
  LoadingBlock,
  Mono,
  Table,
  TableWrap,
  Td,
  Th,
  Tr,
} from "./ui.tsx";

/**
 * Vulnerability summary blocks shared by the overview page and the analytics page.
 *
 * Shared because they are the same figures, and a headline count that differed between the
 * two would make both suspect. The analytics page adds the period selector and the PDF
 * around them; the overview shows them as a compact strip.
 */

/** Only the four named severities link anywhere — `other` is two severities at once. */
const BUCKET_SEVERITY_PARAM: Record<DashboardSeverityBucket, string | null> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  other: null,
};

const BUCKET_EMPHASIS: Record<DashboardSeverityBucket, string> = {
  critical: "text-danger",
  high: "text-warn",
  medium: "text-text-base",
  low: "text-text-muted",
  other: "text-text-faint",
};

/**
 * One half of the split, with its own severity breakdown.
 *
 * The two halves are the headline figures and the combined total above them is deliberately
 * smaller. Both are here because a combined total is what gets asked for and what gets
 * quoted — but measured on a realistic container SBOM, base-image packages were 2,817 of
 * 2,845 findings, so a single number is mostly a statement about base-image age. Giving the
 * split the visual weight is what keeps the quotable number from being the misleading one.
 */
function ScopePanel({
  label,
  hint,
  totals,
  scopeParam,
  scale,
  excluded,
}: {
  label: string;
  hint: string;
  totals: VulnScopeTotals | null;
  scopeParam: "app" | "os";
  /** Shared scale so the two bars are comparable rather than each filling its own width. */
  scale: number;
  excluded: boolean;
}) {
  /*
   * Excluded by the filter is not the same as counted and found nothing, so it never
   * renders as 0 — the same rule that makes the whole report null rather than zero-filled
   * when scanning is off, applied one level down.
   */
  if (totals === null) {
    return (
      <div className="rounded-lg border border-dashed border-border-base bg-bg-subtle px-4 py-3">
        <p className="text-xs font-medium text-text-muted">{label}</p>
        <p className="mt-1 text-sm text-text-faint">
          {excluded ? "Excluded by the current filter" : "Not counted"}
        </p>
        <p className="mt-0.5 text-[11px] text-text-faint">
          Nothing here was counted, so this is not a statement that there are none.
        </p>
      </div>
    );
  }

  const sum = totalOf(totals.counts);
  const buckets = bucketize(totals.counts);

  return (
    <div className="rounded-lg border border-border-base bg-bg-raised px-4 py-3">
      <div className="flex items-baseline justify-between gap-2">
        <Link
          to={`/vulnerabilities?scope=${scopeParam}`}
          className="text-xs font-medium text-text-muted hover:text-accent hover:underline"
        >
          {label}
        </Link>
        <p className="nums text-2xl font-semibold text-text-base">{formatNumber(sum)}</p>
      </div>

      <SeverityBar counts={totals.counts} total={scale} className="mt-2" />

      <div className="mt-2.5 grid grid-cols-5 gap-1">
        {dashboardSeverityBuckets.map((bucket) => {
          const severity = BUCKET_SEVERITY_PARAM[bucket];
          const body = (
            <>
              <span className="block text-[10px] font-medium tracking-wide text-text-faint uppercase">
                {SEVERITY_BUCKET_LABELS[bucket]}
              </span>
              <span className={`nums block text-sm font-semibold ${BUCKET_EMPHASIS[bucket]}`}>
                {formatNumber(buckets[bucket])}
              </span>
            </>
          );
          return severity === null ? (
            <span
              key={bucket}
              className="block rounded px-1 py-0.5"
              title="Negligible, plus advisories no upstream feed has rated. Unrated is a real answer, not a gap."
            >
              {body}
            </span>
          ) : (
            <Link
              key={bucket}
              to={`/vulnerabilities?scope=${scopeParam}&severity=${severity}`}
              className="block rounded px-1 py-0.5 transition-colors hover:bg-bg-subtle"
            >
              {body}
            </Link>
          );
        })}
      </div>

      <p className="mt-2.5 text-xs text-text-muted">
        {formatNumber(totals.fixable)} with a fix available
        {totals.knownExploited > 0 ? (
          <>
            {" · "}
            <span className="font-medium text-danger">
              {formatNumber(totals.knownExploited)} known exploited
            </span>
          </>
        ) : null}
      </p>
      <p className="mt-0.5 text-[11px] text-text-faint">
        across {formatNumber(totals.affectedPackages)} package
        {totals.affectedPackages === 1 ? "" : "s"} · {hint}
      </p>
    </div>
  );
}

/**
 * The totals block: one combined figure, then the split that explains it.
 *
 * Replaces the older tile strip. Tiles could only carry one number each, which meant the
 * severity split had to live in a separate card further down the page — and a reader who
 * saw "38 critical" in a tile had no way to tell whether that was the estate's dependency
 * problem or its base image without scrolling.
 */
export function VulnBreakdownBlock({ report }: { report: VulnerabilityReport }) {
  const appTotal = report.app === null ? null : totalOf(report.app.counts);
  const osTotal = report.baseImage === null ? null : totalOf(report.baseImage.counts);
  const grandTotal = (appTotal ?? 0) + (osTotal ?? 0);
  const scale = Math.max(appTotal ?? 0, osTotal ?? 0, 1);

  return (
    <>
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <p className="text-sm text-text-muted">
          <span className="nums text-lg font-semibold text-text-base">{formatNumber(grandTotal)}</span>{" "}
          {grandTotal === 1 ? "vulnerability finding" : "vulnerability findings"} in total
        </p>
        {report.dbBuiltAt ? (
          <span className="text-xs text-text-faint">
            database built {formatRelative(report.dbBuiltAt)}
          </span>
        ) : null}
        <span className="text-xs text-text-faint">
          {formatNumber(report.applicationsAffected)} application
          {report.applicationsAffected === 1 ? "" : "s"} affected
        </span>
        {report.applicationsPending > 0 ? (
          // A partially-swept estate's totals are a floor, and saying so stops someone
          // reading a catch-up in progress as an improvement.
          <Badge tone="info" title="A sweep is still running, so these counts may rise.">
            {formatNumber(report.applicationsPending)} not matched yet
          </Badge>
        ) : null}
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <ScopePanel
          label="Application dependencies"
          hint="fixed by changing a version"
          totals={report.app}
          scopeParam="app"
          scale={scale}
          excluded={report.filter.scope === "os"}
        />
        <ScopePanel
          label="Base image and runtimes"
          hint="fixed by rebuilding on a newer image"
          totals={report.baseImage}
          scopeParam="os"
          scale={scale}
          excluded={report.filter.scope === "app"}
        />
      </div>

      {report.unfiltered ? <UnfilteredReference unfiltered={report.unfiltered} /> : null}
    </>
  );
}

/**
 * What the figures above were narrowed from.
 *
 * Small and out of the way, but present whenever a filter is active. Without it a filtered
 * dashboard gives no sense of scale — "12 critical" could be all of them or a twentieth,
 * and those call for different reactions.
 */
function UnfilteredReference({
  unfiltered,
}: {
  unfiltered: { app: SeverityCounts; baseImage: SeverityCounts };
}) {
  const rows: Array<[string, SeverityCounts]> = [
    ["Application dependencies", unfiltered.app],
    ["Base image and runtimes", unfiltered.baseImage],
  ];
  return (
    <div className="mt-3 rounded-lg border border-border-base bg-bg-subtle px-3 py-2">
      <p className="text-[11px] font-medium tracking-wide text-text-faint uppercase">
        Unfiltered, for reference
      </p>
      <div className="mt-1 flex flex-wrap gap-x-6 gap-y-1">
        {rows.map(([label, counts]) => (
          <p key={label} className="text-xs text-text-muted">
            {label}{" "}
            <span className="nums font-semibold text-text-base">{formatNumber(totalOf(counts))}</span>
            <span className="text-text-faint">
              {" ("}
              {dashboardSeverityBuckets
                .map((bucket) => `${SEVERITY_BUCKET_LABELS[bucket]} ${bucketize(counts)[bucket]}`)
                .join(" · ")}
              {")"}
            </span>
          </p>
        ))}
      </div>
    </div>
  );
}

/**
 * The advisories reaching the most applications.
 *
 * Fetches its own slice rather than taking it from the report prop, because it asks a
 * different question from the cards around it: those rank applications and packages, this
 * ranks the advisories themselves. It is the estate advisory table from the vulnerabilities
 * tab, held to its widest-reaching ten.
 *
 * Scoped to application dependencies in a current build. Unscoped, the list would be base-image
 * OS packages to the last row -- measured on a realistic container SBOM, 2,817 of 2,845 findings
 * came from the base image -- and a "top advisories" card that never shows a dependency anyone
 * chose is a card nobody can act on.
 */
export function TopAdvisoriesCard() {
  const query = useAdvisorySearch({
    page: 1,
    pageSize: 10,
    // Blast radius first: this surface answers "where are we most exposed", which is the
    // question a glance is for. The full table on the vulnerabilities tab stays
    // severity-first, because triage reads in a different order.
    sortBy: "applications",
    sortDir: "desc",
    scope: "app",
    currentOnly: "true",
  });
  const rows = query.data?.items ?? [];
  /* Same capped-ranking caveat as the cards above -- see the note there. */
  const capNote =
    rows.length > 0
      ? ` Sorting reorders these ${rows.length} rows; it does not rank every advisory.`
      : "";
  const sort = useClientSort(
    rows,
    { severity: "number", advisory: "text", packages: "number", applications: "number" } as const,
    { sortBy: "applications" },
    (row, field) =>
      field === "severity"
        ? // Ranked, not alphabetical: "critical" must not sort between "high" and "low".
          SEVERITY_ORDER[row.severity]
        : field === "advisory"
          ? row.vulnerabilityId
          : field === "packages"
            ? row.affectedPackages
            : row.currentApplications,
    (row) => row.vulnerabilityId,
  );

  return (
    <Card>
      <CardHeader
        title={`Vulnerabilities${rows.length > 0 ? ` · top ${rows.length}` : ""}`}
        subtitle={`Advisories against application dependencies in some current build, by how many applications they reach. Expand a package count to see the versions behind it.${capNote}`}
      />
      {query.isLoading ? (
        <LoadingBlock />
      ) : rows.length === 0 ? (
        <EmptyState
          title="No advisory affects an application dependency"
          hint="Base-image findings are reported separately."
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th
                  onSort={() => sort.toggle("severity")}
                  sorted={sort.stateOf("severity")}
                  width="105px"
                >
                  Severity
                </Th>
                <Th
                  onSort={() => sort.toggle("advisory")}
                  sorted={sort.stateOf("advisory")}
                  width="190px"
                >
                  Advisory
                </Th>
                <Th
                  onSort={() => sort.toggle("packages")}
                  sorted={sort.stateOf("packages")}
                  align="right"
                  width="100px"
                >
                  Packages
                </Th>
                <Th
                  onSort={() => sort.toggle("applications")}
                  sorted={sort.stateOf("applications")}
                  align="right"
                  width="90px"
                >
                  Apps
                </Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((advisory) => (
                <Tr key={advisory.vulnerabilityId}>
                  <Td>
                    <SeverityBadge severity={advisory.severity} />
                  </Td>
                  <Td>
                    <Link
                      to={`/vulnerabilities/${encodeURIComponent(advisory.vulnerabilityId)}`}
                      className="font-mono text-xs text-accent hover:underline"
                    >
                      {advisory.vulnerabilityId}
                    </Link>
                    {advisory.knownExploited ? (
                      <Badge tone="danger" title="On CISA's Known Exploited Vulnerabilities list.">
                        exploited
                      </Badge>
                    ) : null}
                  </Td>
                  <AdvisoryPackagesCell advisory={advisory} />
                  <AdvisoryApplicationsCell advisory={advisory} />
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </Card>
  );
}

/** The worst applications by findings, sortable within that ranked set. */
export function TopVulnerableApplicationsCard({ report }: { report: VulnerabilityReport }) {
  const rows = report.topVulnerableApplications;
  const rankedByBaseImage = rows[0]?.rankedBy === "os";
  const max = rows.reduce(
    (acc, row) => Math.max(acc, (rankedByBaseImage ? row.baseImageFindings : row.findings) ?? 0),
    0,
  );
  /*
    The server sends its worst N by findings, not a window onto the estate, and sorting
    reorders exactly those N rows. That distinction has to survive into the UI: sorted
    ascending this table shows the *least vulnerable of the worst N*, which reads as "our
    safest applications" and is the precise opposite of the truth. Hence the count in the
    title and the note in the subtitle — the sort is honest only while its scope is visible.
  */
  const capNote =
    rows.length > 0
      ? ` Sorting reorders these ${rows.length} rows; it does not rank the whole estate.`
      : "";
  const sort = useClientSort(
    rows,
    {
      application: "text",
      findings: "number",
      critical: "number",
      high: "number",
      fixable: "number",
    } as const,
    // Findings descending is the order the server ranked by, so the table opens exactly
    // as it did before it became sortable.
    { sortBy: "findings" },
    (row, field) =>
      field === "application"
        ? row.name
        : field === "findings"
          ? // The ranked half, matching the server's ORDER BY. Null stays null rather than
            // collapsing to 0 so an unscanned application sorts last in both directions
            // instead of impersonating a clean one.
            (rankedByBaseImage ? row.baseImageFindings : row.findings)
          : field === "critical"
            ? row.critical
            : field === "high"
              ? row.high
              : row.fixable,
    (row) => row.applicationId,
  );

  return (
    <Card>
      <CardHeader
        title={`Vulnerable Applications${rows.length > 0 ? ` · top ${rows.length}` : ""}`}
        subtitle={
          rankedByBaseImage
            ? `Ranked by base-image findings, because the filter excluded application dependencies. Every count on a row is base-image only.${capNote}`
            : `Ranked by findings in their own dependencies. Base-image findings are shown alongside but do not affect the order — including them would rank base-image age instead.${capNote}`
        }
      />
      {rows.length === 0 ? (
        <EmptyState
          title={
            report.applicationsScanned === 0
              ? "Nothing matched yet"
              : report.filter.active
                ? "No application has a finding matching this filter"
                : "No application dependency has a known vulnerability"
          }
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("application")} sorted={sort.stateOf("application")}>
                  Application
                </Th>
                {/*
                  One column, not two. The two numbers are read as a pair — "38 of its own,
                  28 from the image" — and two separate columns invited them to be added
                  together, which is the one thing the split exists to prevent. Sorting it
                  sorts the ranked half alone, for the same reason: a sort that silently
                  used the sum would rank base-image age, which is what the split prevents.
                */}
                <Th
                  onSort={() => sort.toggle("findings")}
                  sorted={sort.stateOf("findings")}
                  width="170px"
                >
                  Findings (app / base image)
                </Th>
                <Th
                  onSort={() => sort.toggle("critical")}
                  sorted={sort.stateOf("critical")}
                  align="right"
                  width="70px"
                >
                  Crit
                </Th>
                <Th
                  onSort={() => sort.toggle("high")}
                  sorted={sort.stateOf("high")}
                  align="right"
                  width="70px"
                >
                  High
                </Th>
                <Th
                  onSort={() => sort.toggle("fixable")}
                  sorted={sort.stateOf("fixable")}
                  align="right"
                  width="90px"
                >
                  Fixable
                </Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((row) => {
                const ranked = (rankedByBaseImage ? row.baseImageFindings : row.findings) ?? 0;
                return (
                  <Tr key={row.applicationId}>
                    <Td>
                      <Link
                        to={`/applications/${row.applicationId}?tab=vulnerabilities`}
                        className="font-medium text-accent hover:underline"
                      >
                        {row.name}
                      </Link>
                    </Td>
                    <Td>
                      <span className="flex items-center gap-2">
                        <span
                          className="nums w-20 text-right whitespace-nowrap"
                          title={
                            rankedByBaseImage
                              ? "Base-image findings; application dependencies were excluded by the filter."
                              : "Findings in the application's own dependencies, then findings from its base image and runtimes."
                          }
                        >
                          {/* The ranked half is the emphasised one, so the pair cannot be
                              misread as a single combined figure. */}
                          <span
                            className={
                              rankedByBaseImage ? "text-text-faint" : "font-medium text-text-base"
                            }
                          >
                            {row.findings === null ? "—" : formatNumber(row.findings)}
                          </span>
                          <span className="text-text-faint"> / </span>
                          <span
                            className={
                              rankedByBaseImage ? "font-medium text-text-base" : "text-text-faint"
                            }
                          >
                            {row.baseImageFindings === null
                              ? "—"
                              : formatNumber(row.baseImageFindings)}
                          </span>
                        </span>
                        <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-neutral-subtle">
                          <span
                            className="block h-full bg-warn"
                            style={{ width: max > 0 ? `${(ranked / max) * 100}%` : "0%" }}
                          />
                        </span>
                      </span>
                    </Td>
                    <Td
                      align="right"
                      className={`nums ${row.critical > 0 ? "text-danger" : "text-text-muted"}`}
                    >
                      {formatNumber(row.critical)}
                    </Td>
                    <Td align="right" className="nums text-text-muted">
                      {formatNumber(row.high)}
                    </Td>
                    <Td align="right" className="nums text-text-muted">
                      {formatNumber(row.fixable)}
                    </Td>
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

/** The worst packages in current use by advisory count, sortable within that ranked set. */
export function TopVulnerablePackagesCard({ report }: { report: VulnerabilityReport }) {
  const rows = report.topVulnerablePackages;
  const baseImageList = rows[0]?.baseImage === true;
  /* Same capped-ranking caveat as the applications card above. */
  const capNote =
    rows.length > 0
      ? ` Sorting reorders these ${rows.length} rows; it does not rank every package in use.`
      : "";
  const sort = useClientSort(
    rows,
    {
      package: "text",
      version: "text",
      findings: "number",
      critical: "number",
      applications: "number",
      fixedIn: "text",
    } as const,
    // Advisory count descending — the order the server ranked by.
    { sortBy: "findings" },
    (row, field) =>
      field === "package"
        ? row.name
        : field === "version"
          ? row.version
          : field === "findings"
            ? row.findings
            : field === "critical"
              ? row.critical
              : field === "applications"
                ? row.applications
                : // Undefined when there is no published fix, which sorts last in both
                  // directions — so this column answers "what can we actually fix" rather
                  // than burying the fixable rows among the ones with nowhere to go.
                  row.fixVersions[0],
    (row) => row.componentId,
  );

  return (
    <Card>
      <CardHeader
        title={`Vulnerable Packages${rows.length > 0 ? ` · top ${rows.length}` : ""}`}
        subtitle={`${
          baseImageList
            ? "Base-image packages present in some current build"
            : "Application dependencies present in some current build"
        }, by number of distinct advisories against that exact version. The application count is the blast radius of fixing it.${capNote}`}
      />
      {rows.length === 0 ? (
        <EmptyState
          title={
            report.filter.active
              ? "No package in current use has a finding matching this filter"
              : "No package in current use has a known vulnerability"
          }
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("package")} sorted={sort.stateOf("package")}>
                  Package
                </Th>
                <Th onSort={() => sort.toggle("version")} sorted={sort.stateOf("version")} width="150px">
                  Version
                </Th>
                <Th
                  onSort={() => sort.toggle("findings")}
                  sorted={sort.stateOf("findings")}
                  align="right"
                  width="100px"
                >
                  Advisories
                </Th>
                <Th
                  onSort={() => sort.toggle("critical")}
                  sorted={sort.stateOf("critical")}
                  align="right"
                  width="70px"
                >
                  Crit
                </Th>
                <Th
                  onSort={() => sort.toggle("applications")}
                  sorted={sort.stateOf("applications")}
                  align="right"
                  width="80px"
                >
                  Apps
                </Th>
                <Th onSort={() => sort.toggle("fixedIn")} sorted={sort.stateOf("fixedIn")} width="150px">
                  Fixed in
                </Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((row) => (
                <Tr key={row.componentId}>
                  <Td>
                    <Link
                      to={`/search?name=${encodeURIComponent(row.name)}&match=exact`}
                      className="font-medium text-accent hover:underline"
                    >
                      {row.name}
                    </Link>
                    {row.knownExploited > 0 ? (
                      <Badge tone="danger" title="Has an advisory on CISA's known-exploited list.">
                        exploited
                      </Badge>
                    ) : null}
                  </Td>
                  <Td>
                    <Mono>{row.version ?? "unknown"}</Mono>
                  </Td>
                  <Td align="right" className="nums font-medium text-text-base">
                    {formatNumber(row.findings)}
                  </Td>
                  <Td
                    align="right"
                    className={`nums ${row.critical > 0 ? "text-danger" : "text-text-muted"}`}
                  >
                    {formatNumber(row.critical)}
                  </Td>
                  <Td align="right" className="nums text-text-muted">
                    {formatNumber(row.applications)}
                  </Td>
                  <Td>
                    {row.fixVersions.length > 0 ? (
                      <Mono title={row.fixVersions.join(", ")}>{row.fixVersions[0]}</Mono>
                    ) : (
                      <span className="text-xs text-text-faint">
                        {row.fixAvailable ? "yes" : "no fix"}
                      </span>
                    )}
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

/**
 * Base-image exposure, grouped by distribution.
 *
 * Grouped by image rather than by application because that is the unit of work: twelve
 * services on one old base image are a single upgrade, not twelve tasks.
 *
 * Renders nothing when the filter excluded base-image packages. An empty table would read
 * as "no base image has a vulnerability", which is a far stronger claim than "we did not
 * look" — the section is dropped and the filter banner explains why.
 */
export function BaseImageExposureCard({ report }: { report: VulnerabilityReport }) {
  const rows = report.baseImageExposure;
  if (rows === null) return null;

  return (
    <Card>
      <CardHeader
        title="Base image exposure"
        subtitle="Findings from distribution packages and language runtimes. Usually the largest number here, and usually fixed by rebuilding on a newer image rather than by changing any dependency."
      />
      {rows.length === 0 ? (
        <EmptyState
          title={
            report.filter.active
              ? "No base-image package has a finding matching this filter"
              : "No base-image package has a known vulnerability"
          }
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Base image</Th>
                <Th align="right" width="120px">
                  Applications
                </Th>
                <Th align="right" width="110px">
                  Findings
                </Th>
                <Th align="right" width="90px">
                  Crit
                </Th>
                <Th align="right" width="90px">
                  High
                </Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <Tr key={`${row.osName ?? "unknown"}-${row.osVersion ?? ""}`}>
                  <Td>
                    <Link
                      to={`/applications?os=${encodeURIComponent(row.osName ?? "")}${
                        row.osVersion ? `&osVersion=${encodeURIComponent(row.osVersion)}` : ""
                      }`}
                      className="font-medium text-accent hover:underline"
                    >
                      {[row.osName ?? "unknown", row.osVersion].filter(Boolean).join(" ")}
                    </Link>
                  </Td>
                  <Td align="right" className="nums text-text-muted">
                    {formatNumber(row.applications)}
                  </Td>
                  <Td align="right" className="nums text-text-base">
                    {formatNumber(row.findings)}
                  </Td>
                  <Td
                    align="right"
                    className={`nums ${row.critical > 0 ? "text-danger" : "text-text-muted"}`}
                  >
                    {formatNumber(row.critical)}
                  </Td>
                  <Td align="right" className="nums text-text-muted">
                    {formatNumber(row.high)}
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
