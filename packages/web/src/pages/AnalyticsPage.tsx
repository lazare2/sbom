import { useState, type ReactNode } from "react";
import { Link } from "react-router";
import type {
  AnalyticsReport,
  AttentionFlagKind,
  AttentionPackage,
  AttentionProject,
  BuildDeltaCounts,
  BuildDeltaSide,
  FragmentationTrend,
  ProgressRollup,
  ProjectBuildDeltas,
  ProjectProgress,
} from "@sbom/shared";
import { ApplicationsCell } from "../components/ExpandableCounts.tsx";
import { ExportTableButton, exportDate, exportList } from "../components/ExportTable.tsx";
import { CriticalHighBadges } from "../components/Severity.tsx";
import { StatTile } from "../components/StatTile.tsx";
import {
  readTeamFilterParams,
  TEAM_FILTER_URL_DEFAULTS,
  TeamFilterBanner,
  TeamFilterBar,
  teamFilterQuery,
} from "../components/TeamFilter.tsx";
import { formatDate, formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import { analyticsReportPdfUrl, useAnalyticsReport } from "../lib/queries.ts";
import { useClientSort } from "../lib/useSort.ts";
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
  NAME_COLUMN_MIN_WIDTH,
} from "../components/ui.tsx";

/**
 * Analytics: how the estate is moving.
 *
 * Which projects are fixing more than they introduce, how often each one builds, which need
 * attention and why, what each build did to the findings of the one before, and which packages
 * to upgrade first. Always over what the reader can see, in the selected environment, and
 * optionally narrowed to squads, tribes or groups - the narrowing applies to every section.
 *
 * The same payload the PDF and the monthly email are rendered from, so the window and the
 * filter in the URL are what the download carries too.
 */

const PERIODS = [
  { days: 7, label: "7 days" },
  { days: 30, label: "30 days" },
  { days: 90, label: "90 days" },
  { days: 365, label: "12 months" },
] as const;

const urlSpec = {
  defaults: { periodDays: 30, ...TEAM_FILTER_URL_DEFAULTS },
  parse: (params: URLSearchParams) => ({
    periodDays: readNumber(params, "periodDays", 30),
    ...readTeamFilterParams(params),
  }),
};

export function AnalyticsPage() {
  const { state, setState } = useUrlState(urlSpec);
  const { periodDays, ...filter } = state;
  const filterParams = teamFilterQuery(filter);
  const query = useAnalyticsReport(periodDays, filterParams);
  const report = query.data;

  return (
    <>
      <PageHeader
        title="Analytics"
        subtitle={
          report ? (
            <>
              Progress in {report.meta.environmentName} · generated {formatDateTime(report.meta.generatedAt)} · window
              opens {formatDate(report.meta.periodStart)}
              {query.isFetching ? <span className="ml-2 text-text-faint">updating…</span> : null}
            </>
          ) : (
            "How the estate is moving: fixes, new findings, build pace and what needs attention."
          )
        }
        actions={
          <>
            <div role="group" aria-label="Reporting window" className="flex overflow-hidden rounded-md border border-border-strong">
              {PERIODS.map((p) => (
                <button
                  key={p.days}
                  type="button"
                  onClick={() => setState({ periodDays: p.days })}
                  aria-pressed={periodDays === p.days}
                  className={`px-2.5 py-1.5 text-xs font-medium transition-colors ${
                    periodDays === p.days
                      ? "bg-accent text-white"
                      : "bg-bg-raised text-text-muted hover:bg-bg-subtle hover:text-text-base"
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
            {/* A plain anchor: the endpoint returns a PDF and the browser knows how to save one. */}
            <a
              href={analyticsReportPdfUrl(periodDays, filterParams)}
              download
              className="inline-flex items-center justify-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
            >
              Download PDF
            </a>
          </>
        }
      />

      <Card className="mb-4">
        <div className="p-3">
          <TeamFilterBar filter={filter} onChange={(next) => setState(next)} />
        </div>
      </Card>

      {query.isLoading ? (
        <LoadingBlock label="Building report" />
      ) : query.error ? (
        <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />
      ) : report ? (
        <AnalyticsBody report={report} />
      ) : null}
    </>
  );
}

function AnalyticsBody({ report }: { report: AnalyticsReport }) {
  const vulns = report.meta.vulnScanningEnabled;
  return (
    <>
      <TeamFilterBanner label={report.meta.filterLabel} />
      <CoverageBanner report={report} />
      <Headline report={report} />

      {vulns ? (
        <p className="mt-3 rounded-md border border-border-base bg-bg-raised px-4 py-2 text-xs text-text-muted">
          Every build is judged by <strong className="font-medium text-text-base">today's vulnerability database</strong>,
          so "introduced" means a change to a project's dependencies or base image brought a finding in. An advisory
          published between two builds is counted as unchanged, not against the team. Accepted risks are left out
          everywhere.
        </p>
      ) : (
        <p className="mt-3 rounded-md border border-border-base bg-bg-raised px-4 py-2 text-xs text-text-muted">
          Vulnerability scanning is switched off, so this page shows build activity only.
        </p>
      )}

      <div className="mt-4">
        <AttentionCard report={report} />
      </div>

      <div className="mt-4">
        <ProgressCard report={report} />
      </div>

      {report.buildDeltas ? (
        <div className="mt-4">
          <BuildDeltaCard report={report} />
        </div>
      ) : null}

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        {vulns ? <AttentionPackagesCard rows={report.attention.packages} /> : null}
        <FragmentationRisingCard rows={report.attention.fragmentationRising} periodDays={report.meta.periodDays} />
      </div>

      <div className="mt-4">
        <ChurnCard report={report} />
      </div>

      <div className="mt-4">
        <NewPackagesCard report={report} />
      </div>

      <p className="mt-4 text-xs text-text-muted">
        Looking for the most-used packages, base images, runtimes, ecosystem mix or version fragmentation? They are on the{" "}
        <Link to="/inventory" className="text-accent hover:underline">
          Inventory
        </Link>{" "}
        page.
      </p>

      <Methodology report={report} />
    </>
  );
}

// ---------------------------------------------------------------------------
// headline
// ---------------------------------------------------------------------------

function Headline({ report }: { report: AnalyticsReport }) {
  const { totals, attention, progress, meta } = report;
  let fixed = 0;
  let introduced = 0;
  let compared = 0;
  for (const p of progress.projects) {
    if (!p.vulnerabilities) continue;
    fixed += p.vulnerabilities.fixed;
    introduced += p.vulnerabilities.introduced;
    compared += p.vulnerabilities.comparedBuilds;
  }
  const net = introduced - fixed;
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatTile
        label="Builds in window"
        value={totals.scansInPeriod}
        hint={`${formatNumber(totals.applications)} applications, ${formatNumber(totals.scans)} builds in total`}
      />
      <StatTile
        label="Need attention"
        value={attention.projects.length}
        hint="Projects with at least one flag"
        tone={attention.projects.length > 0 ? "warn" : "ok"}
      />
      {meta.vulnScanningEnabled ? (
        <>
          <StatTile
            label="Fixed / introduced"
            value={`${formatNumber(fixed)} / ${formatNumber(introduced)}`}
            hint={`Across ${formatNumber(compared)} build-to-build comparisons`}
          />
          <StatTile
            label="Net change"
            value={net > 0 ? `+${formatNumber(net)}` : formatNumber(net)}
            hint="Findings introduced minus fixed"
            tone={net > 0 ? "danger" : "ok"}
          />
        </>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// needs attention
// ---------------------------------------------------------------------------

const FLAG_LABEL: Record<AttentionFlagKind, string> = {
  known_exploited: "Known exploited",
  critical_fix_overdue: "Critical fix overdue",
  build_overdue: "Build overdue",
  vulnerabilities_rising: "Vulnerabilities rising",
};

const FLAG_TONE: Record<AttentionFlagKind, "danger" | "warn" | "info"> = {
  known_exploited: "danger",
  critical_fix_overdue: "danger",
  vulnerabilities_rising: "warn",
  build_overdue: "info",
};

function AttentionCard({ report }: { report: AnalyticsReport }) {
  const all = report.attention.projects;
  const [kind, setKind] = useState<AttentionFlagKind | "all">("all");
  const rows = kind === "all" ? all : all.filter((p) => p.flags.some((f) => f.kind === kind));
  const counts = Object.fromEntries(
    (Object.keys(FLAG_LABEL) as AttentionFlagKind[]).map((k) => [k, all.filter((p) => p.flags.some((f) => f.kind === k)).length]),
  ) as Record<AttentionFlagKind, number>;

  return (
    <Card>
      <CardHeader
        title="Projects that need attention"
        subtitle="Every flag says why it was raised. Thresholds are set by an administrator under Admin → Configuration."
        actions={
          <ExportTableButton
            title="Needs attention"
            filename="needs-attention"
            rows={rows.flatMap((p) => p.flags.map((f) => ({ p, f })))}
            columns={[
              { header: "Project", value: (r) => r.p.name, width: 30 },
              { header: "Squads", value: (r) => exportList(r.p.squads), width: 20 },
              { header: "Tribes", value: (r) => exportList(r.p.tribes), width: 20 },
              { header: "Flag", value: (r) => FLAG_LABEL[r.f.kind], width: 20 },
              { header: "Reason", value: (r) => r.f.reason, width: 90 },
            ]}
          />
        }
      />
      {all.length > 0 ? (
        <div className="flex flex-wrap gap-1 border-b border-border-base px-4 py-2" role="group" aria-label="Show flag">
          {(["all", ...(Object.keys(FLAG_LABEL) as AttentionFlagKind[])] as const).map((k) => (
            <button
              key={k}
              type="button"
              aria-pressed={kind === k}
              onClick={() => setKind(k)}
              className={`rounded-md px-2 py-1 text-xs transition-colors ${
                kind === k ? "bg-accent-subtle font-medium text-accent" : "text-text-muted hover:bg-bg-subtle hover:text-text-base"
              }`}
            >
              {k === "all" ? `All (${all.length})` : `${FLAG_LABEL[k]} (${counts[k]})`}
            </button>
          ))}
        </div>
      ) : null}
      {rows.length === 0 ? (
        <EmptyState title="Nothing flagged" hint="No project in this view meets any of the attention thresholds." />
      ) : (
        <ul className="divide-y divide-border-base">
          {rows.map((p) => (
            <AttentionRow key={p.applicationId} project={p} />
          ))}
        </ul>
      )}
    </Card>
  );
}

function AttentionRow({ project }: { project: AttentionProject }) {
  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Link to={`/applications/${project.applicationId}`} className="font-medium text-accent hover:underline">
          {project.name}
        </Link>
        {project.squads.map((s) => (
          <Badge key={s} tone="neutral">
            {s}
          </Badge>
        ))}
      </div>
      <ul className="mt-1.5 space-y-1">
        {project.flags.map((f) => (
          <li key={f.kind} className="flex flex-wrap items-start gap-2 text-xs">
            <Badge tone={FLAG_TONE[f.kind]}>{FLAG_LABEL[f.kind]}</Badge>
            <span className="min-w-0 flex-1 text-text-muted">{f.reason}</span>
          </li>
        ))}
      </ul>
    </li>
  );
}

// ---------------------------------------------------------------------------
// progress
// ---------------------------------------------------------------------------

type ProgressView = "projects" | "squads" | "tribes";

function signed(n: number): string {
  return n > 0 ? `+${formatNumber(n)}` : formatNumber(n);
}

function NetCell({ value }: { value: number | null }) {
  if (value === null) return <span className="text-text-faint">-</span>;
  return (
    <span className={`nums font-medium ${value > 0 ? "text-danger" : value < 0 ? "text-ok" : "text-text-muted"}`}>
      {signed(value)}
    </span>
  );
}

function ProgressCard({ report }: { report: AnalyticsReport }) {
  const [view, setView] = useState<ProgressView>("projects");
  return (
    <Card>
      <CardHeader
        title="Progress"
        subtitle={
          report.meta.vulnScanningEnabled
            ? `Findings fixed and introduced by builds in the last ${report.meta.periodDays} days, what is open now against the start of the window, how often each project builds, and the average days a critical or high finding stayed before a build removed it.`
            : "How often each project builds and when it last did."
        }
        actions={
          <div role="group" aria-label="Group by" className="flex overflow-hidden rounded-md border border-border-strong">
            {(["projects", "squads", "tribes"] as const).map((v) => (
              <button
                key={v}
                type="button"
                aria-pressed={view === v}
                onClick={() => setView(v)}
                className={`px-2.5 py-1 text-xs font-medium capitalize transition-colors ${
                  view === v ? "bg-accent text-white" : "bg-bg-raised text-text-muted hover:bg-bg-subtle hover:text-text-base"
                }`}
              >
                {v}
              </button>
            ))}
          </div>
        }
      />
      {view === "projects" ? (
        <ProjectProgressTable rows={report.progress.projects} vulns={report.meta.vulnScanningEnabled} />
      ) : (
        <RollupTable
          rows={report.progress[view]}
          noun={view === "squads" ? "squad" : "tribe"}
          vulns={report.meta.vulnScanningEnabled}
        />
      )}
    </Card>
  );
}

function ProjectProgressTable({ rows, vulns }: { rows: ProjectProgress[]; vulns: boolean }) {
  const sort = useClientSort(
    rows,
    {
      name: "text",
      fixed: "number",
      introduced: "number",
      net: "number",
      open: "number",
      change: "number",
      builds: "number",
      cadence: "number",
      lastBuild: "number",
      fixDays: "number",
    } as const,
    { sortBy: vulns ? "fixed" : "builds" },
    (p, f) => {
      const v = p.vulnerabilities;
      switch (f) {
        case "name":
          return p.name;
        case "fixed":
          return v?.fixed ?? null;
        case "introduced":
          return v?.introduced ?? null;
        case "net":
          return v?.net ?? null;
        case "open":
          return v?.openCritical == null ? null : v.openCritical * 100_000 + (v.openHigh ?? 0);
        case "change":
          return v?.criticalHighChange ?? null;
        case "builds":
          return p.builds.inWindow;
        case "cadence":
          return p.builds.averageDaysBetweenBuilds;
        case "lastBuild":
          return p.builds.daysSinceLastBuild;
        default:
          return v?.meanDaysToFix ?? null;
      }
    },
    (p) => p.name.toLowerCase(),
  );

  if (rows.length === 0) return <EmptyState title="No applications" hint="Nothing in scope for this filter." />;

  return (
    <>
      <div className="flex justify-end border-b border-border-base px-4 py-2">
        <ExportTableButton
          title="Progress by project"
          filename="progress-by-project"
          rows={sort.rows}
          columns={[
            { header: "Project", value: (p) => p.name, width: 32 },
            { header: "Squads", value: (p) => exportList(p.squads), width: 20 },
            { header: "Tribes", value: (p) => exportList(p.tribes), width: 20 },
            { header: "Builds compared", value: (p) => p.vulnerabilities?.comparedBuilds ?? null, width: 10 },
            { header: "Fixed", value: (p) => p.vulnerabilities?.fixed ?? null, width: 10 },
            { header: "Introduced", value: (p) => p.vulnerabilities?.introduced ?? null, width: 10 },
            { header: "Net", value: (p) => p.vulnerabilities?.net ?? null, width: 10 },
            { header: "Critical/high fixed", value: (p) => p.vulnerabilities?.fixedCriticalHigh ?? null, width: 12 },
            { header: "Critical/high introduced", value: (p) => p.vulnerabilities?.introducedCriticalHigh ?? null, width: 12 },
            { header: "Open critical", value: (p) => p.vulnerabilities?.openCritical ?? null, width: 10 },
            { header: "Open high", value: (p) => p.vulnerabilities?.openHigh ?? null, width: 10 },
            { header: "Critical+high at start", value: (p) => p.vulnerabilities?.criticalHighAtStart ?? null, width: 12 },
            { header: "Critical+high change", value: (p) => p.vulnerabilities?.criticalHighChange ?? null, width: 12 },
            { header: "Mean days to fix", value: (p) => p.vulnerabilities?.meanDaysToFix ?? null, width: 12 },
            { header: "Builds in window", value: (p) => p.builds.inWindow, width: 10 },
            { header: "Average days between builds", value: (p) => p.builds.averageDaysBetweenBuilds, width: 12 },
            { header: "Last build", value: (p) => exportDate(p.builds.lastBuildAt), width: 18 },
          ]}
        />
      </div>
      <TableWrap>
        <Table>
          <thead>
            <tr>
              <Th minWidth={NAME_COLUMN_MIN_WIDTH} onSort={() => sort.toggle("name")} sorted={sort.stateOf("name")}>
                Project
              </Th>
              {vulns ? (
                <>
                  <Th align="right" width="80px" onSort={() => sort.toggle("fixed")} sorted={sort.stateOf("fixed")}>
                    Fixed
                  </Th>
                  <Th align="right" width="100px" onSort={() => sort.toggle("introduced")} sorted={sort.stateOf("introduced")}>
                    Introduced
                  </Th>
                  <Th align="right" width="80px" onSort={() => sort.toggle("net")} sorted={sort.stateOf("net")}>
                    Net
                  </Th>
                  <Th width="120px" onSort={() => sort.toggle("open")} sorted={sort.stateOf("open")}>
                    Open now
                  </Th>
                  <Th align="right" width="110px" onSort={() => sort.toggle("change")} sorted={sort.stateOf("change")}>
                    C+H change
                  </Th>
                </>
              ) : null}
              <Th align="right" width="80px" onSort={() => sort.toggle("builds")} sorted={sort.stateOf("builds")}>
                Builds
              </Th>
              <Th align="right" width="120px" onSort={() => sort.toggle("cadence")} sorted={sort.stateOf("cadence")}>
                Built every
              </Th>
              <Th width="120px" onSort={() => sort.toggle("lastBuild")} sorted={sort.stateOf("lastBuild")}>
                Last build
              </Th>
              {vulns ? (
                <Th align="right" width="110px" onSort={() => sort.toggle("fixDays")} sorted={sort.stateOf("fixDays")}>
                  Days to fix
                </Th>
              ) : null}
            </tr>
          </thead>
          <tbody>
            {sort.rows.map((p) => {
              const v = p.vulnerabilities;
              return (
                <Tr key={p.applicationId}>
                  <Td>
                    <Link to={`/applications/${p.applicationId}`} className="font-medium text-accent hover:underline">
                      {p.name}
                    </Link>
                    {p.squads.length > 0 ? <span className="ml-1.5 text-[11px] text-text-faint">{p.squads.join(", ")}</span> : null}
                  </Td>
                  {vulns ? (
                    <>
                      <Td align="right" className="nums" title={v ? `${v.fixedCriticalHigh} critical or high` : undefined}>
                        {v && v.comparedBuilds > 0 ? formatNumber(v.fixed) : <span className="text-text-faint">-</span>}
                      </Td>
                      <Td align="right" className="nums" title={v ? `${v.introducedCriticalHigh} critical or high` : undefined}>
                        {v && v.comparedBuilds > 0 ? formatNumber(v.introduced) : <span className="text-text-faint">-</span>}
                      </Td>
                      <Td align="right">
                        <NetCell value={v && v.comparedBuilds > 0 ? v.net : null} />
                      </Td>
                      <Td>
                        {v?.openCritical == null ? (
                          <span className="text-xs text-text-faint">not assessed</span>
                        ) : v.openCritical + (v.openHigh ?? 0) === 0 ? (
                          <span className="text-text-faint">none</span>
                        ) : (
                          <CriticalHighBadges critical={v.openCritical} high={v.openHigh ?? 0} />
                        )}
                      </Td>
                      <Td
                        align="right"
                        title={
                          v?.criticalHighAtStart != null
                            ? `${v.criticalHighAtStart} critical and high in the last build before the window`
                            : "No assessed build before the window to compare with"
                        }
                      >
                        <NetCell value={v?.criticalHighChange ?? null} />
                      </Td>
                    </>
                  ) : null}
                  <Td align="right" className="nums">
                    {formatNumber(p.builds.inWindow)}
                  </Td>
                  <Td
                    align="right"
                    className="nums text-text-muted"
                    title={`${p.builds.cadenceBuilds} build(s) in the cadence window`}
                  >
                    {p.builds.averageDaysBetweenBuilds === null ? <span className="text-text-faint">-</span> : `${p.builds.averageDaysBetweenBuilds} d`}
                  </Td>
                  <Td className="text-xs" title={p.builds.lastBuildAt ? formatDateTime(p.builds.lastBuildAt) : undefined}>
                    {p.builds.lastBuildAt ? formatRelative(p.builds.lastBuildAt) : <span className="text-text-faint">never</span>}
                  </Td>
                  {vulns ? (
                    <Td align="right" className="nums" title={v && v.fixesTimed > 0 ? `over ${v.fixesTimed} fix(es)` : undefined}>
                      {v?.meanDaysToFix == null ? <span className="text-text-faint">-</span> : `${v.meanDaysToFix} d`}
                    </Td>
                  ) : null}
                </Tr>
              );
            })}
          </tbody>
        </Table>
      </TableWrap>
    </>
  );
}

function RollupTable({ rows, noun, vulns }: { rows: ProgressRollup[]; noun: string; vulns: boolean }) {
  const label = (r: ProgressRollup) => r.name ?? `No ${noun}`;
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-base px-4 py-2">
        <span className="text-[11px] text-text-faint">
          A project on two {noun}s counts in both. Days to fix is weighted by fixes, not by project.
        </span>
        <ExportTableButton
          title={`Progress by ${noun}`}
          filename={`progress-by-${noun}`}
          rows={rows}
          columns={[
            { header: noun[0]!.toUpperCase() + noun.slice(1), value: label, width: 26 },
            { header: "Applications", value: (r) => r.applications, width: 12 },
            { header: "Fixed", value: (r) => r.vulnerabilities?.fixed ?? null, width: 10 },
            { header: "Introduced", value: (r) => r.vulnerabilities?.introduced ?? null, width: 10 },
            { header: "Net", value: (r) => r.vulnerabilities?.net ?? null, width: 10 },
            { header: "Open critical", value: (r) => r.vulnerabilities?.openCritical ?? null, width: 10 },
            { header: "Open high", value: (r) => r.vulnerabilities?.openHigh ?? null, width: 10 },
            { header: "Critical+high change", value: (r) => r.vulnerabilities?.criticalHighChange ?? null, width: 12 },
            { header: "Mean days to fix", value: (r) => r.vulnerabilities?.meanDaysToFix ?? null, width: 12 },
            { header: "Builds in window", value: (r) => r.buildsInWindow, width: 10 },
            { header: "Average days between builds", value: (r) => r.averageDaysBetweenBuilds, width: 12 },
            { header: "Flagged applications", value: (r) => r.flaggedApplications, width: 12 },
          ]}
        />
      </div>
      {rows.length === 0 ? (
        <EmptyState title="No applications" />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th minWidth="200px">{noun[0]!.toUpperCase() + noun.slice(1)}</Th>
                <Th align="right" width="70px">
                  Apps
                </Th>
                {vulns ? (
                  <>
                    <Th align="right" width="80px">
                      Fixed
                    </Th>
                    <Th align="right" width="100px">
                      Introduced
                    </Th>
                    <Th align="right" width="80px">
                      Net
                    </Th>
                    <Th width="120px">Open now</Th>
                    <Th align="right" width="110px">
                      C+H change
                    </Th>
                    <Th align="right" width="100px">
                      Days to fix
                    </Th>
                  </>
                ) : null}
                <Th align="right" width="80px">
                  Builds
                </Th>
                <Th align="right" width="110px">
                  Built every
                </Th>
                <Th align="right" width="90px">
                  Flagged
                </Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const v = r.vulnerabilities;
                return (
                  <Tr key={r.name ?? "\u0000"}>
                    <Td className={r.name === null ? "text-text-faint italic" : "font-medium"}>{label(r)}</Td>
                    <Td align="right" className="nums">
                      {formatNumber(r.applications)}
                    </Td>
                    {vulns ? (
                      <>
                        <Td align="right" className="nums">
                          {v ? formatNumber(v.fixed) : "-"}
                        </Td>
                        <Td align="right" className="nums">
                          {v ? formatNumber(v.introduced) : "-"}
                        </Td>
                        <Td align="right">
                          <NetCell value={v?.net ?? null} />
                        </Td>
                        <Td>{v ? <CriticalHighBadges critical={v.openCritical} high={v.openHigh} /> : null}</Td>
                        <Td align="right">
                          <NetCell value={v?.criticalHighChange ?? null} />
                        </Td>
                        <Td align="right" className="nums">
                          {v?.meanDaysToFix == null ? <span className="text-text-faint">-</span> : `${v.meanDaysToFix} d`}
                        </Td>
                      </>
                    ) : null}
                    <Td align="right" className="nums">
                      {formatNumber(r.buildsInWindow)}
                    </Td>
                    <Td align="right" className="nums text-text-muted">
                      {r.averageDaysBetweenBuilds === null ? "-" : `${r.averageDaysBetweenBuilds} d`}
                    </Td>
                    <Td align="right" className="nums">
                      {r.flaggedApplications > 0 ? (
                        <Badge tone="warn">{formatNumber(r.flaggedApplications)}</Badge>
                      ) : (
                        <span className="text-text-faint">0</span>
                      )}
                    </Td>
                  </Tr>
                );
              })}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// build to build
// ---------------------------------------------------------------------------

function DeltaCell({ counts, tone }: { counts: BuildDeltaCounts | undefined; tone: "ok" | "danger" | "muted" }) {
  if (!counts) return <span className="text-text-faint">-</span>;
  const color = counts.total === 0 ? "text-text-faint" : tone === "ok" ? "text-ok" : tone === "danger" ? "text-danger" : "text-text-base";
  return (
    <span className="inline-flex flex-wrap items-center justify-end gap-1">
      <span className={`nums font-medium ${color}`}>{counts.total}</span>
      {counts.critical > 0 || counts.high > 0 ? (
        <span className="text-[11px] text-text-faint">
          {counts.critical > 0 ? `${counts.critical}C` : ""}
          {counts.critical > 0 && counts.high > 0 ? " " : ""}
          {counts.high > 0 ? `${counts.high}H` : ""}
        </span>
      ) : null}
    </span>
  );
}

const sideCells = (side: BuildDeltaSide | undefined) => [
  <DeltaCell key="f" counts={side?.fixed} tone="ok" />,
  <DeltaCell key="i" counts={side?.introduced} tone="danger" />,
  <DeltaCell key="u" counts={side?.unchanged} tone="muted" />,
];

function BuildDeltaCard({ report }: { report: AnalyticsReport }) {
  const section = report.buildDeltas!;
  const [half, setHalf] = useState<"app" | "os">("app");
  const rows = section.projects.filter((p) => p.average !== null || p.last !== null);
  const sort = useClientSort(
    rows,
    { name: "text", pairs: "number", avgFixed: "number", avgIntroduced: "number", lastIntroduced: "number" } as const,
    { sortBy: "avgIntroduced" },
    (p, f) =>
      f === "name"
        ? p.name
        : f === "pairs"
          ? p.comparedBuilds
          : f === "avgFixed"
            ? (p.average?.[half].fixed.total ?? null)
            : f === "avgIntroduced"
              ? (p.average?.[half].introduced.total ?? null)
              : (p.last?.[half].introduced.total ?? null),
    (p) => p.name.toLowerCase(),
  );
  const exportSide = (prefix: string, pick: (p: ProjectBuildDeltas) => BuildDeltaSide | undefined) =>
    (["fixed", "introduced", "unchanged"] as const).flatMap((m) =>
      (["total", "critical", "high"] as const).map((l) => ({
        header: `${prefix} ${m} ${l === "total" ? "(all)" : l}`,
        value: (p: ProjectBuildDeltas) => pick(p)?.[m][l] ?? null,
        width: 12,
      })),
    );

  return (
    <Card>
      <CardHeader
        title="Build to build"
        subtitle={`What each build did to the findings of the build before it: fixed, introduced and unchanged, on average per build in the last ${report.meta.periodDays} days and for the latest build. Byte-identical rebuilds are skipped (${formatNumber(section.identicalRebuildsSkipped)} in this window). A finding is a package name with an advisory, so an upgrade that leaves a package affected counts as unchanged.`}
        actions={
          <>
            <div role="group" aria-label="Packages" className="flex overflow-hidden rounded-md border border-border-strong">
              {(
                [
                  ["app", "App dependencies"],
                  ["os", "Base image"],
                ] as const
              ).map(([v, l]) => (
                <button
                  key={v}
                  type="button"
                  aria-pressed={half === v}
                  onClick={() => setHalf(v)}
                  className={`px-2.5 py-1 text-xs font-medium transition-colors ${
                    half === v ? "bg-accent text-white" : "bg-bg-raised text-text-muted hover:bg-bg-subtle hover:text-text-base"
                  }`}
                >
                  {l}
                </button>
              ))}
            </div>
            <ExportTableButton
              title="Build to build"
              filename="build-to-build"
              rows={sort.rows}
              columns={[
                { header: "Project", value: (p) => p.name, width: 30 },
                { header: "Build pairs averaged", value: (p) => p.comparedBuilds, width: 12 },
                ...exportSide("App avg", (p) => p.average?.app),
                ...exportSide("App last", (p) => p.last?.app),
                ...exportSide("Base image avg", (p) => p.average?.os),
                ...exportSide("Base image last", (p) => p.last?.os),
                { header: "Last build", value: (p) => p.last?.buildNumber ?? null, width: 12 },
                { header: "Last build date", value: (p) => exportDate(p.last?.at ?? null), width: 18 },
              ]}
            />
          </>
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="Nothing to compare yet" hint="A project needs two matched builds before one can be compared with the other." />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <th colSpan={2} className="border-b border-border-base bg-bg-subtle" />
                <th colSpan={3} className="border-b border-l border-border-base bg-bg-subtle px-3 py-1 text-center text-[11px] font-semibold text-text-muted">
                  Average per build, this window
                </th>
                <th colSpan={3} className="border-b border-l border-border-base bg-bg-subtle px-3 py-1 text-center text-[11px] font-semibold text-text-muted">
                  Latest build
                </th>
              </tr>
              <tr>
                <Th minWidth={NAME_COLUMN_MIN_WIDTH} onSort={() => sort.toggle("name")} sorted={sort.stateOf("name")}>
                  Project
                </Th>
                <Th align="right" width="70px" onSort={() => sort.toggle("pairs")} sorted={sort.stateOf("pairs")}>
                  Pairs
                </Th>
                <Th align="right" width="100px" onSort={() => sort.toggle("avgFixed")} sorted={sort.stateOf("avgFixed")}>
                  Fixed
                </Th>
                <Th align="right" width="110px" onSort={() => sort.toggle("avgIntroduced")} sorted={sort.stateOf("avgIntroduced")}>
                  Introduced
                </Th>
                <Th align="right" width="110px">
                  Unchanged
                </Th>
                <Th align="right" width="100px">
                  Fixed
                </Th>
                <Th align="right" width="110px" onSort={() => sort.toggle("lastIntroduced")} sorted={sort.stateOf("lastIntroduced")}>
                  Introduced
                </Th>
                <Th align="right" width="110px">
                  Unchanged
                </Th>
              </tr>
            </thead>
            <tbody>
              {section.estateAverage ? (
                <tr className="bg-accent-subtle/40">
                  <Td className="text-xs font-semibold text-text-base" title="The mean of the projects' own averages - every project weighs the same.">
                    Estate average
                  </Td>
                  <Td align="right" className="nums text-text-muted">
                    {formatNumber(section.comparedBuilds)}
                  </Td>
                  {sideCells(section.estateAverage[half]).map((cell, i) => (
                    <Td key={i} align="right">
                      {cell}
                    </Td>
                  ))}
                  <Td align="right">{""}</Td>
                  <Td align="right">{""}</Td>
                  <Td align="right">{""}</Td>
                </tr>
              ) : null}
              {sort.rows.map((p) => (
                <Tr key={p.applicationId}>
                  <Td>
                    <Link to={`/applications/${p.applicationId}`} className="font-medium text-accent hover:underline">
                      {p.name}
                    </Link>
                  </Td>
                  <Td align="right" className="nums text-text-muted">
                    {formatNumber(p.comparedBuilds)}
                  </Td>
                  {sideCells(p.average?.[half]).map((cell, i) => (
                    <Td key={`a${i}`} align="right">
                      {cell}
                    </Td>
                  ))}
                  {sideCells(p.last?.[half]).map((cell, i) => (
                    <Td key={`l${i}`} align="right">
                      {i === 0 && p.last ? (
                        <span title={`Build ${p.last.buildNumber ?? ""} on ${formatDate(p.last.at)}`}>{cell}</span>
                      ) : (
                        cell
                      )}
                    </Td>
                  ))}
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

function AttentionPackagesCard({ rows }: { rows: AttentionPackage[] }) {
  return (
    <Card>
      <CardHeader
        title="Packages to upgrade first"
        subtitle="Application dependencies with critical or known-exploited advisories that have a fixed version, by how many applications one upgrade would clear."
        actions={
          <ExportTableButton
            title="Packages to upgrade first"
            filename="packages-to-upgrade"
            rows={rows}
            columns={[
              { header: "Package", value: (r) => r.name, width: 30 },
              { header: "Ecosystem", value: (r) => r.ecosystem, width: 12 },
              { header: "Applications", value: (r) => r.applications, width: 12 },
              { header: "Application names", value: (r) => exportList(r.applicationList), width: 40 },
              { header: "Critical advisories", value: (r) => r.critical, width: 12 },
              { header: "Known exploited", value: (r) => r.knownExploited, width: 12 },
              { header: "Affected versions in use", value: (r) => r.versionsInUse, width: 12 },
              { header: "Fixed in", value: (r) => exportList(r.fixVersions), width: 30 },
            ]}
          />
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="Nothing urgent" hint="No application dependency carries a critical or known-exploited advisory with a fix." />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Package</Th>
                <Th align="right" width="70px">
                  Apps
                </Th>
                <Th width="130px">Advisories</Th>
                <Th>Fixed in</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <Tr key={`${r.name}|${r.ecosystem}`}>
                  <Td>
                    <Link
                      to={`/search?name=${encodeURIComponent(r.name)}&match=exact&ecosystem=${encodeURIComponent(r.ecosystem)}`}
                      className="font-medium text-accent hover:underline"
                    >
                      {r.name}
                    </Link>{" "}
                    <EcosystemBadge ecosystem={r.ecosystem} />
                  </Td>
                  <ApplicationsCell count={r.applications} names={r.applicationList} what="ship an affected version" />
                  <Td>
                    <span className="inline-flex flex-wrap gap-1">
                      <CriticalHighBadges critical={r.critical} high={0} />
                      {r.knownExploited > 0 ? <Badge tone="danger">{r.knownExploited} KEV</Badge> : null}
                    </span>
                  </Td>
                  <Td>
                    <Mono>{r.fixVersions.length > 0 ? r.fixVersions.join(", ") : "-"}</Mono>
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

function FragmentationRisingCard({ rows, periodDays }: { rows: FragmentationTrend[]; periodDays: number }) {
  return (
    <Card>
      <CardHeader
        title="Fragmentation getting worse"
        subtitle={`Application dependencies now run in more versions than ${periodDays} days ago, across projects that built on both sides of the window.`}
        actions={
          <ExportTableButton
            title="Fragmentation getting worse"
            filename="fragmentation-rising"
            rows={rows}
            columns={[
              { header: "Package", value: (r) => r.name, width: 30 },
              { header: "Ecosystem", value: (r) => r.ecosystem, width: 12 },
              { header: "Versions at start", value: (r) => r.versionsAtStart, width: 12 },
              { header: "Versions now", value: (r) => r.versionsNow, width: 12 },
              { header: "Applications", value: (r) => r.applications, width: 12 },
            ]}
          />
        }
      />
      {rows.length === 0 ? (
        <EmptyState title="No spread" hint="No package moved into more versions during the window." />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Package</Th>
                <Th align="right" width="120px">
                  Versions
                </Th>
                <Th align="right" width="70px">
                  Apps
                </Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <Tr key={`${r.name}|${r.ecosystem}`}>
                  <Td>
                    <Link
                      to={`/search?name=${encodeURIComponent(r.name)}&match=exact&ecosystem=${encodeURIComponent(r.ecosystem)}`}
                      className="font-medium text-accent hover:underline"
                    >
                      {r.name}
                    </Link>{" "}
                    <EcosystemBadge ecosystem={r.ecosystem} />
                  </Td>
                  <Td align="right" className="nums">
                    {r.versionsAtStart} → <span className="font-medium text-warn">{r.versionsNow}</span>
                  </Td>
                  <Td align="right" className="nums">
                    {formatNumber(r.applications)}
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
// how to read
// ---------------------------------------------------------------------------

function Methodology({ report }: { report: AnalyticsReport }) {
  const s = report.meta.attentionSettings;
  const overdue =
    s.buildOverdueMode === "fixed"
      ? `After ${s.fixedDays} days without a build.`
      : `Once a project has gone ${s.useMultiplier ? `${s.multiplier} times` : "longer than"} its own average gap between builds over the last ${s.cadenceWindowDays} days - never sooner than ${s.minimumDays} days. With fewer than ${s.minimumBuilds} builds in that time there is no usable average, and the fixed ${s.fixedDays}-day limit applies.`;
  const items: Array<[string, ReactNode]> = [
    [
      "Today's knowledge",
      "Builds are compared using today's vulnerability database. Fixed means a later build no longer carries a finding the earlier one did; introduced means it carries one the earlier did not. A newly published advisory appears in both builds and counts as unchanged.",
    ],
    [
      "Finding identity",
      "A package name within its ecosystem, plus an advisory. An upgrade from one affected version to another leaves the finding unchanged.",
    ],
    [
      "Identical rebuilds",
      "Skipped in build-to-build comparisons, because they cannot have changed anything. Still counted as builds for the build pace.",
    ],
    ["Build overdue", overdue],
    [
      "Critical fix overdue",
      `A critical finding with a fixed version, open in the current build for more than ${s.criticalFixDays} days - counted from the later of when the project first shipped the package and when the finding was first recorded.`,
    ],
    [
      "Days to fix",
      "For critical and high findings removed inside the window: days from the first build of the project that carried the finding to the build that removed it.",
    ],
    [
      "Scope",
      "Applications you can see in this environment, never inactive ones, narrowed by the squad, tribe and group filter when one is set. Accepted risks are excluded everywhere.",
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
        {coverage.coveragePct}% scan coverage - {formatNumber(coverage.covered)} of{" "}
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
        With nothing to compare against, the three package figures are all zero -
        and zero reads as "nothing changed" rather than "nothing was measured".
        Those mean opposite things to someone judging whether churn is under
        control, so the tiles are replaced rather than shown.
      */}
      {v.applicationsCompared === 0 ? (
        <div className="p-4">
          <div className="grid grid-cols-2 gap-3">
            <StatTile
              label="Scans received"
              value={v.scans}
              hint={`${formatNumber(v.applicationsScanned)} applications reported`}
            />
            <StatTile
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
          <StatTile
            label="Scans received"
            value={v.scans}
            hint={`${formatNumber(v.applicationsScanned)} applications reported`}
          />
          <StatTile label="Packages added" value={v.packagesAdded} hint="New to that application" />
          <StatTile label="Packages removed" value={v.packagesRemoved} hint="No longer shipped" />
          <StatTile label="Packages upgraded" value={v.packagesUpgraded} hint="Version changed" />
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
              excluded - every package in a first build would otherwise register as an addition.
            </>
          ) : null}
          {v.applicationsUnchanged > 0 ? (
            <>
              {" "}
              A further {formatNumber(v.applicationsUnchanged)} application
              {v.applicationsUnchanged === 1 ? " has" : "s have"} not built inside the window at all and{" "}
              {v.applicationsUnchanged === 1 ? "is" : "are"} unchanged by definition -{" "}
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
        actions={
          <ExportTableButton
            title="New packages"
            filename="new-packages"
            rows={sort.rows}
            columns={[
              { header: "Package", value: (p) => p.name, width: 32 },
              { header: "Ecosystem", value: (p) => p.ecosystem, width: 12 },
              { header: "Version", value: (p) => p.version, width: 16 },
              { header: "First seen", value: (p) => exportDate(p.firstSeenAt), width: 18 },
              { header: "Applications", value: (p) => p.applications, width: 12 },
            ]}
          />
        }
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
                    <Mono>{p.version ?? " - "}</Mono>
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
