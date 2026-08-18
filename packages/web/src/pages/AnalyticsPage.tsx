import type { ReactNode } from "react";
import { Link } from "react-router";
import type { AnalyticsReport } from "@sbom/shared";
import { useClientSort } from "../lib/useSort.ts";
import { osLabel, PlatformTable, runtimeLabel } from "../components/Platform.tsx";
import { ApplicationsCell } from "../components/ExpandableCounts.tsx";
import {
  BaseImageExposureCard,
  TopAdvisoriesCard,
  TopVulnerableApplicationsCard,
  TopVulnerablePackagesCard,
  VulnBreakdownBlock,
} from "../components/VulnSummary.tsx";
import {
  fromVulnFilter,
  readVulnFilterParams,
  toVulnFilter,
  VULN_FILTER_URL_DEFAULTS,
  VulnFilterBanner,
  VulnFilterControl,
  vulnFilterQuery,
} from "../components/VulnFilter.tsx";
import { ScanningDisabledNotice } from "../components/Severity.tsx";
import { useAuth } from "../auth/AuthProvider.tsx";
import { formatDate, formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import { analyticsReportPdfUrl, useAnalyticsReport } from "../lib/queries.ts";
import { readNumber, useUrlState } from "../lib/useUrlState.ts";
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
 * Estate analytics.
 *
 * The same payload the PDF is rendered from, shown interactively. Two properties
 * are load-bearing:
 *
 *   1. Every count that can be filtered for is a link. A metric you cannot drill
 *      into is trivia — "9 stale applications" only becomes work once you can see
 *      which nine.
 *   2. The window is in the URL, and the PDF link carries the same window. What
 *      you print is what you are looking at.
 *
 * The inventory sections are not vulnerability rankings: coverage gaps, version spread
 * and churn measure what they can actually measure, and each says so in its own subtitle
 * rather than leaving the reader to assume.
 *
 * The vulnerability sections are the exception and come from Grype. When scanning is
 * disabled they are replaced by an explicit notice, never by zeros — an unassessed estate
 * rendered as a clean one is the worst failure this page could have.
 */

const PERIODS = [
  { days: 7, label: "7 days" },
  { days: 30, label: "30 days" },
  { days: 90, label: "90 days" },
  { days: 365, label: "12 months" },
] as const;

/*
 * The vulnerability filter shares this page's URL with the reporting window, so one link
 * carries both. `scope` and `severity` use the same names the /vulnerabilities page uses,
 * which is what lets a drill-down from a filtered figure arrive pre-filtered.
 */
const urlSpec = {
  defaults: { periodDays: 30, ...VULN_FILTER_URL_DEFAULTS },
  parse: (params: URLSearchParams) => ({
    periodDays: readNumber(params, "periodDays", 30),
    ...readVulnFilterParams(params),
  }),
};

export function AnalyticsPage() {
  const { state, setState } = useUrlState(urlSpec);
  const { isAdmin } = useAuth();
  const vulnFilter = toVulnFilter(state);
  const filterParams = vulnFilterQuery(vulnFilter);
  const query = useAnalyticsReport(state.periodDays, filterParams);

  if (query.isLoading) return <LoadingBlock label="Building report" />;
  if (query.error) return <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return null;

  const report = query.data;

  return (
    <>
      <PageHeader
        title="Analytics"
        subtitle={
          <>
            Generated {formatDateTime(report.meta.generatedAt)}
            {report.meta.generatedBy ? ` by ${report.meta.generatedBy}` : null} · window opens{" "}
            {formatDate(report.meta.periodStart)}
            {query.isFetching ? <span className="ml-2 text-text-faint">updating…</span> : null}
          </>
        }
        actions={
          <>
            <div
              role="group"
              aria-label="Reporting window"
              className="flex overflow-hidden rounded-md border border-border-strong"
            >
              {PERIODS.map((p) => (
                <button
                  key={p.days}
                  type="button"
                  onClick={() => setState({ periodDays: p.days })}
                  aria-pressed={state.periodDays === p.days}
                  className={`px-2.5 py-1.5 text-xs font-medium transition-colors ${
                    state.periodDays === p.days
                      ? "bg-accent text-white"
                      : "bg-bg-raised text-text-muted hover:bg-bg-subtle hover:text-text-base"
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
            {/*
              A plain anchor, not a fetch: the endpoint returns a PDF and the
              browser already knows how to save one. Routing it through the JSON
              client would mean buffering it into memory and synthesising a blob
              URL for no gain. `download` names the file rather than opening a tab.
            */}
            <a
              href={analyticsReportPdfUrl(state.periodDays, filterParams)}
              download
              className="inline-flex items-center justify-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
            >
              Download PDF
            </a>
          </>
        }
      />

      <CoverageBanner report={report} />

      <Totals report={report} />

      {/*
        Vulnerability sections, immediately after the totals.
        `null` means scanning is disabled — rendered as an explicit notice rather than
        omitted, so a reader cannot mistake a report with no findings section for an estate
        with no findings.
      */}
      <section className="mt-5">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-text-base">Vulnerabilities</h2>
          {/*
            The control lives here rather than in the page toolbar, because this section is
            the whole extent of what it changes. Severity means nothing for churn, coverage
            or platform mix, and a filter in the page header would imply otherwise.
          */}
          {report.vulnerabilities ? (
            <VulnFilterControl
              filter={vulnFilter}
              onChange={(next) => setState(fromVulnFilter(next))}
            />
          ) : null}
        </div>
        {report.vulnerabilities ? (
          <>
            <VulnFilterBanner label={report.vulnerabilities.filter.label} />
            <VulnBreakdownBlock report={report.vulnerabilities} />
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <TopVulnerableApplicationsCard report={report.vulnerabilities} />
              <TopVulnerablePackagesCard report={report.vulnerabilities} />
            </div>
            <div className="mt-4">
              <TopAdvisoriesCard />
            </div>
            <div className="mt-4">
              <BaseImageExposureCard report={report.vulnerabilities} />
            </div>
          </>
        ) : (
          <ScanningDisabledNotice what="Vulnerability figures" isAdmin={isAdmin} />
        )}
      </section>

      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        <TopPackagesCard report={report} />
        <TopProjectsCard report={report} />
      </div>

      <div className="mt-4">
        <ChurnCard report={report} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <FragmentationCard report={report} />
        <NewPackagesCard report={report} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <CoverageGapsCard report={report} />
        <EcosystemCard report={report} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <PlatformTable
          title="Operating systems"
          subtitle="Observed in each application's current build. Expand a count to see which."
          what="run this operating system"
          rows={report.platforms.operatingSystems.map((e) => ({
            key: `${e.name ?? ""}|${e.version ?? ""}`,
            label: osLabel(e.name) ?? "not detected",
            version: e.version,
            applications: e.applications,
            applicationList: e.applicationList,
            href: `/applications?os=${encodeURIComponent(e.name ?? "")}${
              e.version ? `&osVersion=${encodeURIComponent(e.version)}` : ""
            }`,
          }))}
          note={
            report.platforms.unknown > 0
              ? `${formatNumber(report.platforms.unknown)} application${
                  report.platforms.unknown === 1 ? "" : "s"
                } reported neither an OS nor a runtime — expected for scratch and distroless images.`
              : undefined
          }
        />
        <PlatformTable
          title="Language runtimes"
          subtitle="Observed in each application's current build. Expand a count to see which."
          what="ship this runtime"
          rows={report.platforms.runtimes.map((e) => ({
            key: `${e.name}|${e.version ?? ""}`,
            label: runtimeLabel(e.name),
            version: e.version,
            applications: e.applications,
            applicationList: e.applicationList,
            href: `/applications?runtime=${encodeURIComponent(e.name)}${
              e.version ? `&runtimeVersion=${encodeURIComponent(e.version)}` : ""
            }`,
          }))}
          note="An application appears once per runtime it ships, so these can sum to more than the application total."
        />
      </div>

      <Methodology report={report} />
    </>
  );
}

// ---------------------------------------------------------------------------
// building blocks
// ---------------------------------------------------------------------------

function Tile({
  label,
  value,
  hint,
  to,
  tone,
}: {
  label: string;
  value: number | string;
  hint?: string;
  to?: string;
  tone?: "warn" | "ok" | "danger";
}) {
  const toneClass =
    tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : tone === "ok" ? "text-ok" : "text-text-base";

  const body = (
    <>
      <p className="text-[11px] font-medium uppercase tracking-wide text-text-faint">{label}</p>
      <p className={`nums mt-1 text-2xl font-semibold ${toneClass}`}>
        {typeof value === "number" ? formatNumber(value) : value}
      </p>
      {hint ? <p className="mt-0.5 text-xs text-text-muted">{hint}</p> : null}
    </>
  );

  if (!to) return <div className="rounded-lg border border-border-base bg-bg-raised px-4 py-3">{body}</div>;
  return (
    <Link
      to={to}
      className="block rounded-lg border border-border-base bg-bg-raised px-4 py-3 transition-colors hover:border-border-strong hover:bg-bg-subtle"
    >
      {body}
    </Link>
  );
}

function ShareBar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.max(1, Math.round((value / max) * 100)) : 0;
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-neutral-subtle">
        <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
      <span className="nums w-9 text-right text-xs text-text-muted">{pct}%</span>
    </div>
  );
}

/**
 * The qualifier on every other number on this page, placed above them.
 *
 * Not a footnote: totals over an inventory with blind spots get read as complete
 * unless the gap is stated where the totals are, and by the time someone scrolls
 * to a methodology note they have already believed the figure.
 */
function CoverageBanner({ report }: { report: AnalyticsReport }) {
  const { coverage, meta } = report;
  const complete = coverage.coveragePct >= 100 && coverage.neverScanned === 0;

  return (
    <div
      className={`mb-4 rounded-lg border px-4 py-3 ${
        complete ? "border-ok bg-ok-subtle" : "border-warn bg-warn-subtle"
      }`}
    >
      <p className={`text-sm font-medium ${complete ? "text-ok" : "text-warn"}`}>
        {coverage.coveragePct}% scan coverage — {formatNumber(coverage.covered)} of{" "}
        {formatNumber(coverage.eligible)} active applications reported a build in the last{" "}
        {meta.staleThresholdDays} days
      </p>
      <p className="mt-1 text-xs text-text-muted">
        {complete ? (
          <>Every active application is reporting, so the figures below describe the whole estate.</>
        ) : (
          <>
            Everything below describes only what has been scanned.{" "}
            <Link to="/applications?staleOnly=true" className="text-accent hover:underline">
              {formatNumber(coverage.stale)} stale
            </Link>{" "}
            and {formatNumber(coverage.neverScanned)} never-scanned application
            {coverage.neverScanned === 1 ? "" : "s"} contribute nothing to any count on this page.
          </>
        )}
      </p>
    </div>
  );
}

function Totals({ report }: { report: AnalyticsReport }) {
  const { totals, coverage, meta } = report;
  return (
    <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile
          label="Applications"
          value={totals.applications}
          hint={`${formatNumber(totals.activeApplications)} active, ${formatNumber(totals.inactiveApplications)} inactive`}
          to="/applications"
        />
        <Tile
          label="Packages in use"
          value={totals.packagesInUse}
          hint={`${formatNumber(totals.distinctPackages)} known across all history`}
          to="/search"
        />
        <Tile
          label="Scans in window"
          value={totals.scansInPeriod}
          hint={`${formatNumber(totals.scans)} received in total`}
        />
        <Tile
          label="Last scan"
          value={totals.latestScanAt ? formatRelative(totals.latestScanAt) : "never"}
          hint={totals.latestScanAt ? formatDate(totals.latestScanAt) : "no builds received"}
        />
      </div>

      <div className="mt-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile
          label="Stale"
          value={coverage.stale}
          hint={`Active, no build in ${meta.staleThresholdDays} days`}
          tone={coverage.stale > 0 ? "warn" : "ok"}
          to="/applications?staleOnly=true"
        />
        <Tile
          label="Never scanned"
          value={coverage.neverScanned}
          hint="Registered, no SBOM received"
          tone={coverage.neverScanned > 0 ? "warn" : "ok"}
        />
        <Tile
          label="Unconfirmed"
          value={coverage.pendingConfirmation}
          hint="Auto-created, awaiting triage"
          tone={coverage.pendingConfirmation > 0 ? "warn" : "ok"}
          to="/applications?status=pending_confirmation"
        />
        <Tile
          label="Scan coverage"
          value={`${coverage.coveragePct}%`}
          hint="Confidence interval on everything else"
          tone={coverage.coveragePct >= 90 ? "ok" : "warn"}
        />
      </div>
    </>
  );
}

function TopPackagesCard({ report }: { report: AnalyticsReport }) {
  const rows = report.topPackages;
  /*
    Reduced over every row, not read off rows[0]. The bars are relative to the largest
    value, and taking it from the first row silently assumed the array was still in the
    server's descending order — which stopped being true the moment these headers became
    sortable. Sorting by name would then scale every bar to whatever package happened to
    sort first.
  */
  const max = rows.reduce((m, r) => Math.max(m, r.applications), 0);
  const sort = useClientSort(
    rows,
    { package: "text", version: "text", applications: "number" } as const,
    { sortBy: "applications" },
    (r, f) => (f === "package" ? r.name : f === "version" ? r.version : r.applications),
    (r) => `${r.componentId}:${r.version ?? ""}`,
  );

  return (
    <Card>
      <CardHeader
        title={`Top ${rows.length} most widely deployed packages`}
        subtitle="Present in the most applications' current builds — the blast radius if one turns out to be a problem. Operating systems and runtimes are excluded and shown separately."
      />
      {rows.length === 0 ? (
        <EmptyState title="No package data yet" hint="Counts appear once the first SBOM is ingested." />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("package")} sorted={sort.stateOf("package")}>
                  Package
                </Th>
                <Th onSort={() => sort.toggle("version")} sorted={sort.stateOf("version")}>
                  Version
                </Th>
                <Th onSort={() => sort.toggle("applications")} sorted={sort.stateOf("applications")} align="right">
                  Apps
                </Th>
                {/* A rendering of the Apps column. Sorting it would duplicate that header. */}
                <Th width="130px">Share</Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((c) => (
                <Tr key={`${c.componentId}-${c.version ?? ""}`}>
                  <Td>
                    <Link
                      to={`/search?name=${encodeURIComponent(c.name)}&match=exact&scope=all`}
                      className="font-medium text-accent hover:underline"
                    >
                      {c.name}
                    </Link>{" "}
                    <EcosystemBadge ecosystem={c.ecosystem} />
                  </Td>
                  <Td>
                    <Mono>{c.version ?? "—"}</Mono>
                  </Td>
                  <ApplicationsCell
                    count={c.applications}
                    names={c.applicationList}
                    what="ship this package"
                  />
                  <Td>
                    <ShareBar value={c.applications} max={max} />
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

function TopProjectsCard({ report }: { report: AnalyticsReport }) {
  const rows = report.topProjects;
  // Order-independent: see TopPackagesCard.
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
        title={`Top ${rows.length} applications by package count`}
        subtitle="Largest current builds. A size ranking, not a risk ranking — a big image costs more to review and patch, but is not automatically in worse shape."
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
                    <Link
                      to={`/applications/${p.applicationId}`}
                      className="font-medium text-accent hover:underline"
                    >
                      {p.name}
                    </Link>
                  </Td>
                  <Td title={p.scanAt ? `Build received ${formatDate(p.scanAt)}` : undefined}>
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

/**
 * Churn plus the activity trend.
 *
 * The two belong together: "1,400 packages upgraded" means one thing over a week
 * of steady builds and something else entirely over a week where one application
 * rebuilt forty times.
 */
function ChurnCard({ report }: { report: AnalyticsReport }) {
  const v = report.velocity;
  const max = report.activity.reduce((m, b) => Math.max(m, b.scans), 0);
  const daily = report.meta.periodDays <= 45;

  return (
    <Card>
      <CardHeader
        title={`Dependency churn, last ${report.meta.periodDays} days`}
        subtitle="Each application's current build against its last build from before the window. Counted by package name, so a version bump is one upgrade rather than one addition plus one removal."
      />

      {/*
        With nothing to compare against, the three package figures are all zero —
        and zero reads as "nothing changed" rather than "nothing was measured".
        Those mean opposite things to someone judging whether churn is under
        control, so the tiles are replaced rather than shown.
      */}
      {v.applicationsCompared === 0 ? (
        <div className="p-4">
          <div className="grid grid-cols-2 gap-3">
            <Tile
              label="Scans received"
              value={v.scans}
              hint={`${formatNumber(v.applicationsScanned)} applications reported`}
            />
            <Tile
              label="First-time scans"
              value={v.applicationsWithoutBaseline}
              hint="No earlier build to compare"
            />
          </div>
          <p className="mt-3 text-xs text-warn">
            {v.applicationsWithoutBaseline > 0 ? (
              <>
                No application has a build from before this window, so there is nothing to compare against
                and no churn figures can be produced. Try a shorter window, or wait for the retained history
                to grow past it.
              </>
            ) : (
              <>No application reported a build inside this window, so there is no churn to report.</>
            )}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-3 p-4 lg:grid-cols-4">
          <Tile
            label="Scans received"
            value={v.scans}
            hint={`${formatNumber(v.applicationsScanned)} applications reported`}
          />
          <Tile label="Packages added" value={v.packagesAdded} hint="New to that application" />
          <Tile label="Packages removed" value={v.packagesRemoved} hint="No longer shipped" />
          <Tile label="Packages upgraded" value={v.packagesUpgraded} hint="Version changed" />
        </div>
      )}

      <div className="border-t border-border-base px-4 py-3">
        <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-text-faint">
          {daily ? "Scans per day" : "Scans per week"}
          {max > 0 ? <span className="ml-2 normal-case text-text-muted">peak {formatNumber(max)}</span> : null}
        </p>
        {report.activity.length === 0 ? (
          <p className="text-xs text-text-muted">No activity data for this window.</p>
        ) : (
          <>
            {/*
              Buckets come back gap-filled from the server, so a quiet week is a
              zero-height bar rather than an absent one. `items-end` on a fixed
              height is what makes the bars grow upward from the axis.
            */}
            <div className="flex h-20 items-end gap-px" role="img" aria-label={`${daily ? "Daily" : "Weekly"} scan volume`}>
              {report.activity.map((b) => (
                <div
                  key={b.bucketStart}
                  title={`${formatDate(b.bucketStart)}: ${formatNumber(b.scans)} scan${
                    b.scans === 1 ? "" : "s"
                  }, ${formatNumber(b.applications)} application${b.applications === 1 ? "" : "s"}`}
                  className="min-w-px flex-1 rounded-t bg-accent"
                  style={{ height: max > 0 ? `${Math.max(b.scans > 0 ? 2 : 0, (b.scans / max) * 100)}%` : 0 }}
                />
              ))}
            </div>
            <div className="mt-1 flex justify-between text-[11px] text-text-faint">
              <span>{formatDate(report.activity[0]?.bucketStart ?? null)}</span>
              <span>{formatDate(report.activity[report.activity.length - 1]?.bucketStart ?? null)}</span>
            </div>
          </>
        )}
      </div>

      {v.applicationsCompared > 0 ? (
        <div className="border-t border-border-base px-4 py-2.5 text-xs text-text-muted">
          {formatNumber(v.applicationsCompared)} application{v.applicationsCompared === 1 ? "" : "s"} had builds
          on both sides of the window and are included in the package figures.
          {v.applicationsWithoutBaseline > 0 ? (
            <>
              {" "}
              {formatNumber(v.applicationsWithoutBaseline)} were scanned for the first time during it and are
              excluded — every package in a first build would otherwise register as an addition.
            </>
          ) : null}
          {v.applicationsUnchanged > 0 ? (
            <>
              {" "}
              A further {formatNumber(v.applicationsUnchanged)} application
              {v.applicationsUnchanged === 1 ? " has" : "s have"} not built inside the window at all and{" "}
              {v.applicationsUnchanged === 1 ? "is" : "are"} unchanged by definition —{" "}
              <Link to="/applications?staleOnly=true" className="text-accent hover:underline">
                see coverage gaps
              </Link>
              .
            </>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}

function FragmentationCard({ report }: { report: AnalyticsReport }) {
  const rows = report.fragmentation;
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
        subtitle="Packages the estate runs several versions of at once. Each extra version multiplies the cost of the next upgrade — the section that names work that can actually be finished."
      />
      {rows.length === 0 ? (
        <EmptyState
          title="No fragmentation"
          hint="Every deployed package is on a single version across the estate."
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("package")} sorted={sort.stateOf("package")}>
                  Package
                </Th>
                {/* The list of versions. `Count` is the orderable form of the same thing. */}
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
                    <Link
                      to={`/search?name=${encodeURIComponent(f.name)}&match=exact&scope=all`}
                      className="font-medium text-accent hover:underline"
                    >
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

function NewPackagesCard({ report }: { report: AnalyticsReport }) {
  const rows = report.newPackages;
  const sort = useClientSort(
    rows,
    { package: "text", version: "text", firstSeen: "date", applications: "number" } as const,
    { sortBy: "firstSeen" },
    (r, f) =>
      f === "package" ? r.name : f === "version" ? r.version : f === "firstSeen" ? r.firstSeenAt : r.applications,
    (r) => r.componentId,
  );
  return (
    <Card>
      <CardHeader
        title={`New to the estate, last ${report.meta.periodDays} days`}
        subtitle="First seen inside the window and still deployed. The supply-chain review queue: what is in our images now that was not here before."
      />
      {rows.length === 0 ? (
        <EmptyState
          title="Nothing new"
          hint="No package currently deployed first appeared inside this window."
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("package")} sorted={sort.stateOf("package")}>
                  Package
                </Th>
                <Th onSort={() => sort.toggle("version")} sorted={sort.stateOf("version")}>
                  Version
                </Th>
                <Th onSort={() => sort.toggle("firstSeen")} sorted={sort.stateOf("firstSeen")}>
                  First seen
                </Th>
                <Th onSort={() => sort.toggle("applications")} sorted={sort.stateOf("applications")} align="right">
                  Apps
                </Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((p) => (
                <Tr key={p.componentId}>
                  <Td>
                    <Link
                      to={`/search?name=${encodeURIComponent(p.name)}&match=exact&scope=all`}
                      className="font-medium text-accent hover:underline"
                    >
                      {p.name}
                    </Link>{" "}
                    <EcosystemBadge ecosystem={p.ecosystem} />
                  </Td>
                  <Td>
                    <Mono>{p.version ?? "—"}</Mono>
                  </Td>
                  <Td title={p.firstSeenAt}>{formatDate(p.firstSeenAt)}</Td>
                  <Td align="right" className="nums">
                    {formatNumber(p.applications)}
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

function CoverageGapsCard({ report }: { report: AnalyticsReport }) {
  const rows = report.coverage.worstOffenders;
  const sort = useClientSort(
    rows,
    { application: "text", lastScanAt: "date", daysSinceScan: "number" } as const,
    { sortBy: "daysSinceScan" },
    (r, f) => (f === "application" ? r.name : f === "lastScanAt" ? r.lastScanAt : r.daysSinceScan),
    (r) => r.applicationId,
  );
  return (
    <Card>
      <CardHeader
        title="Coverage gaps"
        subtitle="Active applications the inventory cannot see, longest-silent first. Never-scanned applications sort above stale ones."
        actions={
          rows.length > 0 ? (
            <Link to="/applications?staleOnly=true" className="text-xs text-accent hover:underline">
              See all
            </Link>
          ) : undefined
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="Full coverage" hint="No active application is stale or unscanned." />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("application")} sorted={sort.stateOf("application")}>
                  Application
                </Th>
                <Th onSort={() => sort.toggle("lastScanAt")} sorted={sort.stateOf("lastScanAt")}>
                  Last build
                </Th>
                <Th onSort={() => sort.toggle("daysSinceScan")} sorted={sort.stateOf("daysSinceScan")} align="right">
                  Silent for
                </Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((a) => (
                <Tr key={a.applicationId}>
                  <Td>
                    <Link
                      to={`/applications/${a.applicationId}`}
                      className="font-medium text-accent hover:underline"
                    >
                      {a.name}
                    </Link>
                  </Td>
                  <Td>{a.lastScanAt ? formatDate(a.lastScanAt) : <Badge tone="danger">never</Badge>}</Td>
                  <Td align="right" className="nums">
                    {a.daysSinceScan === null ? "—" : `${formatNumber(a.daysSinceScan)}d`}
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

function EcosystemCard({ report }: { report: AnalyticsReport }) {
  const rows = report.ecosystems.slice(0, 12);
  // Order-independent: see TopPackagesCard.
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
      <CardHeader title="Ecosystem mix" subtitle="Distinct packages in current builds, by package manager." />
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
                    <Link
                      to={`/search?ecosystem=${encodeURIComponent(e.ecosystem)}`}
                      className="hover:underline"
                    >
                      <EcosystemBadge ecosystem={e.ecosystem} />
                    </Link>
                  </Td>
                  <Td align="right" className="nums">
                    {formatNumber(e.components)}
                  </Td>
                  <ApplicationsCell
                    count={e.applications}
                    names={e.applicationList}
                    what="ship a package from this ecosystem"
                  />
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


/**
 * Definitions, at the bottom.
 *
 * Present because these figures get compared against other tools' differently
 * defined ones, and the first item is here because it is the single most likely
 * thing for a reader to assume wrongly.
 */
function Methodology({ report }: { report: AnalyticsReport }) {
  const items: Array<[string, ReactNode]> = [
    /*
     * Conditional, because the flat claim below is correct with scanning off and false
     * with it on — and a methodology note contradicting the tables above it discredits
     * both.
     */
    report.vulnerabilities === null
      ? ([
          "No vulnerability data",
          "Vulnerability scanning is disabled, so nothing here has been matched against a vulnerability database. Nothing on this page ranks anything by vulnerability — a package near the top of a list is widely deployed, not known-bad.",
        ] as [string, ReactNode])
      : ([
          "Vulnerability data",
          "Findings come from Grype matching this estate's packages against its database. Severity, CVSS, EPSS and known-exploited status are reported as the upstream feeds state them — the platform computes no risk score of its own. Accepted risks are excluded from every figure.",
        ] as [string, ReactNode]),
    ...(report.vulnerabilities === null
      ? []
      : ([
          [
            "App dependencies vs base image",
            "Totalled separately as well as together, but every ranking is computed on one of them rather than the sum — application dependencies, unless the filter excludes them. On a typical image, distribution packages and runtimes are around 99% of all findings, so a ranking on the combined figure would order applications by base-image age and hide everything a team chose.",
          ],
          [
            "Severity buckets",
            "Grype reports six severities. The four named ones are shown individually and “Other” folds negligible together with advisories no upstream feed has rated, so the buckets always sum to the total. Unrated is a real answer rather than a gap — promoting those to low would invent an assessment nobody made.",
          ],
          [
            "What the filter reaches",
            "The scope and severity filter narrows this section only. Coverage, churn, fragmentation, platform and package figures have no severity to filter on and always describe the whole estate. When a filter is active, the unfiltered totals are shown beneath the split so the filtered figures can be read against the whole.",
          ],
        ] as Array<[string, ReactNode]>)),
    [
      "Current build",
      "Every “in use” figure counts each application’s most recent scan. Earlier scans are retained in full and searchable, but excluded from these counts.",
    ],
    [
      "Inactive applications",
      "Excluded everywhere. A decommissioned service inflating a number being used to size an upgrade is worse than omitting it.",
    ],
    [
      "Packages vs platform",
      "Package rankings cover libraries and OS packages. The base distribution and the language runtimes are excluded from them and reported under the platform tables instead.",
    ],
    [
      "Staleness",
      `An active application is stale when its newest build is older than ${report.meta.staleThresholdDays} days. That is a signal about the pipeline, not about the application.`,
    ],
  ];

  return (
    <Card className="mt-4">
      <CardHeader title="How to read this page" />
      <dl className="divide-y divide-border-base">
        {items.map(([term, body]) => (
          <div key={term} className="grid gap-1 px-4 py-2.5 sm:grid-cols-[180px_1fr] sm:gap-4">
            <dt className="text-xs font-semibold text-text-base">{term}</dt>
            <dd className="text-xs text-text-muted">{body}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
