import { Link, useSearchParams } from "react-router";
import { SeverityBadge } from "../components/Severity.tsx";
import { Badge, Card, CardHeader, EmptyState, ErrorBanner, LoadingBlock, PageHeader } from "../components/ui.tsx";
import { useFind } from "../lib/queries.ts";

export const packagePath = (ecosystem: string, name: string) =>
  `/packages/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}`;

/** The one search box's results: projects, packages and vulnerabilities, side by side. */
export function FindPage() {
  const [params] = useSearchParams();
  const q = params.get("q") ?? "";
  const { data, isLoading, error } = useFind(q);

  return (
    <>
      <PageHeader title={`Search: ${q}`} subtitle="Projects, packages and vulnerabilities you can see in this environment." />
      {isLoading ? <LoadingBlock /> : null}
      {error ? <ErrorBanner error={error} /> : null}
      {data ? (
        <div className="grid gap-4 lg:grid-cols-3">
          <Card>
            <CardHeader title={`Projects (${data.projects.length})`} />
            {data.projects.length === 0 ? (
              <EmptyState title="No project matches" />
            ) : (
              <ul className="divide-y divide-border-base">
                {data.projects.map((p) => (
                  <li key={p.applicationId} className="px-4 py-2 text-sm">
                    <Link to={`/applications/${p.applicationId}`} className="font-medium text-accent hover:underline">{p.name}</Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card>
            <CardHeader title={`Packages (${data.packages.length})`} subtitle="Open one for its versions, its projects and the version to use." />
            {data.packages.length === 0 ? (
              <EmptyState title="No package matches" hint={q.length < 2 ? "Type at least 2 characters." : undefined} />
            ) : (
              <ul className="divide-y divide-border-base">
                {data.packages.map((p) => (
                  <li key={`${p.ecosystem}:${p.name}`} className="flex items-center gap-2 px-4 py-2 text-sm">
                    <Link to={packagePath(p.ecosystem, p.name)} className="font-mono text-accent hover:underline">{p.name}</Link>
                    <Badge tone="neutral">{p.ecosystem}</Badge>
                    <span className="text-xs text-text-muted">{p.versionCount} {p.versionCount === 1 ? "version" : "versions"}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card>
            <CardHeader title={data.advisories === null ? "Vulnerabilities" : `Vulnerabilities (${data.advisories.length})`} subtitle="CVE and GHSA ids found in your projects' builds." />
            {data.advisories === null ? (
              <EmptyState title="Vulnerability scanning is switched off" />
            ) : data.advisories.length === 0 ? (
              <EmptyState title="Not found in any build here" hint={q.length < 3 ? "Type at least 3 characters." : undefined} />
            ) : (
              <ul className="divide-y divide-border-base">
                {data.advisories.map((a) => (
                  <li key={a.vulnerabilityId} className="flex flex-wrap items-center gap-2 px-4 py-2 text-sm">
                    <SeverityBadge severity={a.severity as Parameters<typeof SeverityBadge>[0]["severity"]} />
                    <Link to={`/vulnerabilities/${encodeURIComponent(a.vulnerabilityId)}`} className="font-mono text-xs text-accent hover:underline">
                      {a.vulnerabilityId}
                    </Link>
                    {a.aliases.length > 0 ? <span className="font-mono text-[11px] text-text-faint">{a.aliases.slice(0, 2).join(", ")}</span> : null}
                    <span className="text-xs text-text-muted">{a.currentApplications} in use now</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      ) : null}
    </>
  );
}
