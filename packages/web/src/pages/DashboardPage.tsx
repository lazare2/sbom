import { Link } from "react-router";
import { useAuth } from "../auth/AuthProvider.tsx";
import { useClientSort } from "../lib/useSort.ts";
import { TopVulnerableApplicationsCard, VulnBreakdownBlock } from "../components/VulnSummary.tsx";
import {
  fromVulnFilter,
  readVulnFilterParams,
  toVulnFilter,
  VULN_FILTER_URL_DEFAULTS,
  VulnFilterBanner,
  VulnFilterControl,
  vulnFilterQuery,
} from "../components/VulnFilter.tsx";
import { useUrlState } from "../lib/useUrlState.ts";
import { formatDate, formatNumber, formatRelative } from "../lib/format.ts";
import {
  useCoverageGaps,
  useDashboardStats,
  useDashboardVulnerabilities,
  useRecentScans,
  useVulnStatus,
} from "../lib/queries.ts";
import {
  Badge,
  Card,
  CardHeader,
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
 * A tile whose whole surface is a link into a pre-filtered list.
 *
 * The number is not the point — "14 stale applications" is only useful if the
 * next click shows you which fourteen. Every counter here that can be filtered
 * for is a link, and the ones that cannot be are rendered plainly rather than
 * as dead links that look clickable.
 */
function StatTile({
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
  tone?: "warn" | "danger" | "ok";
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

  if (!to) {
    return <div className="rounded-lg border border-border-base bg-bg-raised px-4 py-3">{body}</div>;
  }

  return (
    <Link
      to={to}
      className="block rounded-lg border border-border-base bg-bg-raised px-4 py-3 transition-colors hover:border-border-strong hover:bg-bg-subtle"
    >
      {body}
    </Link>
  );
}

/** Horizontal proportion bar. Cheaper and more legible than a chart library. */
function ShareBar({ value, total }: { value: number; total: number }) {
  const pct = total > 0 ? Math.max(1, Math.round((value / total) * 100)) : 0;
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-24 overflow-hidden rounded-full bg-neutral-subtle">
        <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
      <span className="nums w-9 text-right text-xs text-text-muted">{pct}%</span>
    </div>
  );
}


/*
 * The overview had no URL state before the vulnerability filter existed. It has some now
 * for the same reason every other filtered view here does: a narrowed dashboard is exactly
 * the kind of thing someone pastes into a ticket, and state held in React would open on an
 * unfiltered page and make the message meaningless.
 */
const urlSpec = {
  defaults: VULN_FILTER_URL_DEFAULTS,
  parse: readVulnFilterParams,
};

export function DashboardPage() {
  const { isAdmin } = useAuth();
  const { state, setState } = useUrlState(urlSpec);
  const stats = useDashboardStats();
  const recent = useRecentScans(8);

  /*
    Client-side: the endpoint returns the last few scans in one response, so there is no
    second page for a server sort to reach.
  */
  const recentSort = useClientSort(
    recent.data,
    { application: "text", build: "text", branch: "text", packages: "number", received: "date" } as const,
    { sortBy: "received" },
    (scan, f) =>
      f === "application"
        ? (scan.applicationName ?? "")
        : f === "build"
          ? scan.buildNumber
          : f === "branch"
            ? scan.branch
            : f === "packages"
              ? scan.componentCount
              : scan.createdAt,
    (scan) => scan.id,
  );
  const vulnStatus = useVulnStatus();
  const vulnEnabled = vulnStatus.data?.enabled === true;
  const vulnFilter = toVulnFilter(state);
  // Only fetched when the feature is on; the endpoint would return null anyway, and this
  // keeps a deployment that does not use it from issuing the request at all.
  const vulns = useDashboardVulnerabilities(vulnEnabled, vulnFilterQuery(vulnFilter));

  if (stats.isLoading) return <LoadingBlock label="Loading dashboard" />;
  if (stats.error) return <ErrorBanner error={stats.error} onRetry={() => void stats.refetch()} />;
  if (!stats.data) return null;

  const s = stats.data;

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle={
          s.scans.latestAt
            ? `Last scan received ${formatRelative(s.scans.latestAt)}`
            : "No scans have been received yet"
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          label="Applications"
          value={s.applications.total}
          hint={`${formatNumber(s.applications.active)} active, ${formatNumber(s.applications.inactive)} inactive`}
          to="/applications"
        />
        <StatTile
          label="Packages in use"
          value={s.components.inCurrentUse}
          hint={`${formatNumber(s.components.distinct)} known across all history`}
          to="/search"
        />
        <StatTile
          label="Scans"
          value={s.scans.total}
          hint={`${formatNumber(s.scans.last24h)} in the last 24h, ${formatNumber(s.scans.last7d)} in 7 days`}
        />
        <StatTile
          label="Awaiting confirmation"
          value={s.applications.pendingConfirmation}
          hint={
            s.applications.pendingConfirmation > 0
              ? "Scans arrived under an unrecognised name"
              : "Nothing to triage"
          }
          tone={s.applications.pendingConfirmation > 0 ? "warn" : undefined}
          to={isAdmin ? "/admin/pending" : "/applications?status=pending_confirmation"}
        />
      </div>

      {/* Second row: the two counters that mean something is wrong. */}
      <div className="mt-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          label="Stale"
          value={s.applications.stale}
          hint={`Active, but no scan in ${s.staleThresholdDays} days`}
          tone={s.applications.stale > 0 ? "warn" : "ok"}
          to="/applications?staleOnly=true"
        />
        <StatTile
          label="Never scanned"
          value={s.applications.neverScanned}
          hint="Registered, no SBOM received"
          tone={s.applications.neverScanned > 0 ? "warn" : "ok"}
        />
      </div>

      {/*
        Vulnerability strip, above the inventory panels because it is the part of this page
        that prompts action. Rendered only when scanning is on — an empty version of it
        would read as "no vulnerabilities" for an estate nobody has assessed.
      */}
      {vulnEnabled && vulns.data ? (
        <section className="mt-5">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-text-base">Vulnerabilities</h2>
            {/* Scoped to this section, matching the analytics page — see VulnFilter.tsx. */}
            <VulnFilterControl
              filter={vulnFilter}
              onChange={(next) => setState(fromVulnFilter(next))}
            />
          </div>
          <VulnFilterBanner
            label={vulns.data.filter.label}
            groupScoped={vulns.data.filter.group !== null}
          />
          <VulnBreakdownBlock report={vulns.data} />
          {/*
            Applications only. The package and advisory rankings answer "what should we fix
            centrally", which is an analysis question and lives on the analytics page; this
            page answers "whose estate needs attention today".
          */}
          <div className="mt-4">
            <TopVulnerableApplicationsCard report={vulns.data} />
          </div>
          <p className="mt-2 text-xs text-text-faint">
            <Link to="/analytics" className="text-accent hover:underline">
              Analytics
            </Link>{" "}
            ranks the packages and advisories behind these findings, and separates base-image
            exposure from application dependencies.
          </p>
        </section>
      ) : null}

      {/*
        The one ranked list the overview keeps besides vulnerabilities, because it is a work
        queue rather than an analysis: an application nobody is scanning is invisible to
        every other number on this page, and burying that on a page people open occasionally
        is how an estate quietly stops being covered.
      */}
      <NeedsAttentionCard />



      {/* --- recent activity ------------------------------------------------ */}
      <Card className="mt-4">
        <CardHeader title="Recent scans" subtitle="The last builds to report an SBOM." />
        {recent.isLoading ? (
          <LoadingBlock />
        ) : !recent.data || recent.data.length === 0 ? (
          <EmptyState
            title="No scans yet"
            hint="Point a CI pipeline at POST /api/v1/scans to see builds appear here."
          />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th onSort={() => recentSort.toggle("application")} sorted={recentSort.stateOf("application")}>
                    Application
                  </Th>
                  <Th onSort={() => recentSort.toggle("build")} sorted={recentSort.stateOf("build")}>
                    Build
                  </Th>
                  <Th onSort={() => recentSort.toggle("branch")} sorted={recentSort.stateOf("branch")}>
                    Branch
                  </Th>
                  <Th
                    onSort={() => recentSort.toggle("packages")}
                    sorted={recentSort.stateOf("packages")}
                    align="right"
                  >
                    Packages
                  </Th>
                  <Th onSort={() => recentSort.toggle("received")} sorted={recentSort.stateOf("received")}>
                    Received
                  </Th>
                </tr>
              </thead>
              <tbody>
                {recentSort.rows.map((scan) => (
                  <Tr key={scan.id}>
                    <Td>
                      <Link
                        to={`/applications/${scan.applicationId}`}
                        className="font-medium text-accent hover:underline"
                      >
                        {scan.applicationName}
                      </Link>
                      {scan.isLatest ? (
                        <>
                          {" "}
                          <Badge tone="ok">current</Badge>
                        </>
                      ) : null}
                    </Td>
                    <Td>
                      <Link to={`/scans/${scan.id}`} className="text-accent hover:underline">
                        {scan.buildNumber ? `build ${scan.buildNumber}` : "view scan"}
                      </Link>
                    </Td>
                    <Td>
                      <Mono>{scan.branch ?? "—"}</Mono>
                    </Td>
                    <Td align="right" className="nums">
                      {formatNumber(scan.componentCount)}
                    </Td>
                    <Td title={scan.createdAt}>{formatRelative(scan.createdAt)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>
    </>
  );
}

/**
 * Applications the inventory cannot see, plus the queue of ones it has not been told about.
 *
 * Deliberately the only non-vulnerability table on this page. Every other figure here is
 * computed from applications that *do* report, so an application that stopped reporting
 * silently improves them — this is the row that says the numbers above are incomplete.
 */
function NeedsAttentionCard() {
  const { user } = useAuth();
  const coverage = useCoverageGaps(8);
  const data = coverage.data;
  const gaps = data?.worstOffenders ?? [];
  const pending = data?.pendingConfirmation ?? 0;

  return (
    <Card className="mt-5">
      <CardHeader
        title="Needs attention"
        subtitle="Active applications that have gone quiet, longest-silent first. Never-scanned applications sort above stale ones."
        actions={
          gaps.length > 0 ? (
            <Link to="/applications?staleOnly=true" className="text-xs text-accent hover:underline">
              See all
            </Link>
          ) : undefined
        }
      />
      {coverage.isLoading ? (
        <LoadingBlock />
      ) : coverage.error ? (
        <ErrorBanner error={coverage.error} onRetry={() => void coverage.refetch()} />
      ) : gaps.length === 0 ? (
        <EmptyState
          title="Full coverage"
          hint="No active application is stale or unscanned."
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Application</Th>
                <Th>Last build</Th>
                <Th align="right">Silent for</Th>
              </tr>
            </thead>
            <tbody>
              {gaps.map((a) => (
                <Tr key={a.applicationId}>
                  <Td>
                    <Link
                      to={`/applications/${a.applicationId}`}
                      className="font-medium text-accent hover:underline"
                    >
                      {a.name}
                    </Link>
                  </Td>
                  <Td>
                    {a.lastScanAt ? formatDate(a.lastScanAt) : <Badge tone="danger">never</Badge>}
                  </Td>
                  <Td align="right" className="nums">
                    {a.daysSinceScan === null ? "—" : `${formatNumber(a.daysSinceScan)}d`}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}

      {/*
        Shown to everyone, because an estate with unconfirmed applications is incomplete for
        every reader. Only admins get the link: they are the only ones the queue is
        actionable for, and a link that answers 403 is worse than no link.
      */}
      {pending > 0 ? (
        <div className="border-t border-border-base px-4 py-3 text-xs text-text-muted">
          {formatNumber(pending)} application{pending === 1 ? "" : "s"} awaiting confirmation —
          registered by a build under a name nobody has matched to an application yet.
          {user?.role === "admin" ? (
            <>
              {" "}
              <Link to="/admin/pending" className="text-accent hover:underline">
                Review the queue
              </Link>
            </>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
