import { Link } from "react-router";
import { useAuth } from "../auth/AuthProvider.tsx";
import {
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
import { useUrlState } from "../lib/useUrlState.ts";
import { formatNumber, formatRelative } from "../lib/format.ts";
import {
  useDashboardEcosystems,
  useDashboardStats,
  usePlatformBreakdown,
  useDashboardVulnerabilities,
  useRecentScans,
  useVulnStatus,
  useTopComponents,
} from "../lib/queries.ts";
import { osLabel, runtimeLabel } from "../components/Platform.tsx";
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

/**
 * Counts of applications by OS or runtime, newest-first by application count.
 *
 * Every row links into the filtered applications list. That link is the point:
 * "3 applications on Node 18" is only actionable once you can see which three.
 */
function PlatformCard({
  title,
  subtitle,
  rows,
  loading,
  unknown,
}: {
  title: string;
  subtitle: string;
  rows: Array<{
    key: string;
    label: string;
    version: string | null;
    applications: number;
    href: string;
  }>;
  loading: boolean;
  /** Applications whose current build revealed neither an OS nor a runtime. */
  unknown?: number;
}) {
  const max = rows[0]?.applications ?? 0;

  return (
    <Card>
      <CardHeader title={title} subtitle={subtitle} />
      {loading ? (
        <LoadingBlock />
      ) : rows.length === 0 ? (
        <EmptyState
          title="Nothing detected yet"
          hint="Platform data is read from each SBOM. Scans ingested before this existed need `npm run db:backfill:platform`."
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th width="140px">Version</Th>
                <Th align="right" width="80px">
                  Apps
                </Th>
                <Th width="140px">Share</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <Tr key={row.key}>
                  <Td>
                    <Link to={row.href} className="font-medium text-accent hover:underline">
                      {row.label}
                    </Link>
                  </Td>
                  <Td>
                    <Mono>{row.version ?? "—"}</Mono>
                  </Td>
                  <Td align="right" className="nums">
                    {formatNumber(row.applications)}
                  </Td>
                  <Td>
                    <ShareBar value={row.applications} total={max} />
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}
      {unknown && unknown > 0 ? (
        <div className="border-t border-border-base px-4 py-2 text-xs text-text-muted">
          {formatNumber(unknown)} application{unknown === 1 ? "" : "s"} reported no OS or runtime —
          normal for scratch and distroless images.
        </div>
      ) : null}
    </Card>
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
  const ecosystems = useDashboardEcosystems();
  const platforms = usePlatformBreakdown();
  const top = useTopComponents({ limit: 10 });
  const recent = useRecentScans(8);
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
  const maxEcosystem = ecosystems.data?.[0]?.components ?? 0;

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
          <VulnFilterBanner label={vulns.data.filter.label} />
          <VulnBreakdownBlock report={vulns.data} />
          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <TopVulnerableApplicationsCard report={vulns.data} />
            <TopVulnerablePackagesCard report={vulns.data} />
          </div>
        </section>
      ) : null}

      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        {/* --- most widely used packages ------------------------------------ */}
        <Card>
          <CardHeader
            title="Most widely deployed packages"
            subtitle="Across every active application's current build. This is the blast radius if one of them turns out to be a problem."
          />
          {top.isLoading ? (
            <LoadingBlock />
          ) : !top.data || top.data.length === 0 ? (
            <EmptyState title="No package data yet" hint="Counts appear once the first SBOM is ingested." />
          ) : (
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th>Package</Th>
                    <Th>Version</Th>
                    <Th align="right">Apps</Th>
                  </tr>
                </thead>
                <tbody>
                  {top.data.map((c) => (
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
                      <Td align="right" className="nums">
                        {formatNumber(c.applications)}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
        </Card>

        {/* --- ecosystem mix ------------------------------------------------ */}
        <Card>
          <CardHeader
            title="Ecosystem mix"
            subtitle="Distinct packages currently deployed, by package type."
          />
          {ecosystems.isLoading ? (
            <LoadingBlock />
          ) : !ecosystems.data || ecosystems.data.length === 0 ? (
            <EmptyState title="No components yet" />
          ) : (
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th>Ecosystem</Th>
                    <Th align="right">Packages</Th>
                    <Th align="right">Apps</Th>
                    <Th>Share</Th>
                  </tr>
                </thead>
                <tbody>
                  {ecosystems.data.slice(0, 12).map((e) => (
                    <Tr key={e.ecosystem}>
                      <Td>
                        <EcosystemBadge ecosystem={e.ecosystem} />
                      </Td>
                      <Td align="right" className="nums">
                        {formatNumber(e.components)}
                      </Td>
                      <Td align="right" className="nums">
                        {formatNumber(e.applications)}
                      </Td>
                      <Td>
                        <ShareBar value={e.components} total={maxEcosystem} />
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
        </Card>
      </div>

      {/* --- runtime platforms ---------------------------------------------- */}
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <PlatformCard
          title="Operating systems"
          subtitle="What each application's current build is running on. Click a row to see which."
          rows={(platforms.data?.operatingSystems ?? []).map((entry) => ({
            key: `${entry.name}|${entry.version ?? ""}`,
            label: osLabel(entry.name) ?? "unknown",
            version: entry.version,
            applications: entry.applications,
            href: `/applications?os=${encodeURIComponent(entry.name ?? "")}${
              entry.version ? `&osVersion=${encodeURIComponent(entry.version)}` : ""
            }`,
          }))}
          loading={platforms.isLoading}
          unknown={platforms.data?.unknown ?? 0}
        />

        <PlatformCard
          title="Language runtimes"
          subtitle="An application appears once per runtime it ships, so an image with both Node and Python counts in each."
          rows={(platforms.data?.runtimes ?? []).map((entry) => ({
            key: `${entry.name}|${entry.version ?? ""}`,
            label: runtimeLabel(entry.name),
            version: entry.version,
            applications: entry.applications,
            href: `/applications?runtime=${encodeURIComponent(entry.name)}${
              entry.version ? `&runtimeVersion=${encodeURIComponent(entry.version)}` : ""
            }`,
          }))}
          loading={platforms.isLoading}
        />
      </div>

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
                  <Th>Application</Th>
                  <Th>Build</Th>
                  <Th>Branch</Th>
                  <Th align="right">Packages</Th>
                  <Th>Received</Th>
                </tr>
              </thead>
              <tbody>
                {recent.data.map((scan) => (
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
