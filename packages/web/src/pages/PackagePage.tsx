import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";
import { PackageDetailPanel } from "../components/PackageResults.tsx";
import { SeverityBadge } from "../components/Severity.tsx";
import { Badge, Button, Card, CardHeader, ErrorBanner, LoadingBlock, PageHeader, TextInput } from "../components/ui.tsx";
import { useEnvironment } from "../environments/EnvironmentProvider.tsx";
import { usePackageRecommendation, useVersionCheck } from "../lib/queries.ts";

/**
 * One package: the recommended version (the same one every action plan names), "is this version
 * safe to add?", every version in use and every project using it - so a package is two clicks
 * from all its projects: search, then this page.
 */
export function PackagePage() {
  const { ecosystem = "", name: rawName = "" } = useParams<{ ecosystem: string; name: string }>();
  const name = decodeURIComponent(rawName);
  const { current } = useEnvironment();
  const rec = usePackageRecommendation(ecosystem, name);

  return (
    <>
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono">{name}</span> <Badge tone="neutral">{ecosystem}</Badge>
          </span>
        }
        subtitle={`Every version in use in ${current.name}, and every project that uses it.`}
        actions={<Link to="/search" className="text-sm text-accent hover:underline">← Package search</Link>}
      />

      <div className="mb-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Recommended version" subtitle="The same version every project's action plan names." />
          <div className="p-4 text-sm">
            {rec.isLoading ? (
              <LoadingBlock />
            ) : rec.error ? (
              <ErrorBanner error={rec.error} />
            ) : rec.data?.recommendedVersion ? (
              <>
                <div className="font-mono text-xl font-semibold text-text-base">{rec.data.recommendedVersion}</div>
                <p className="mt-1 text-text-muted">
                  The lowest version that clears all {rec.data.clears} known {rec.data.clears === 1 ? "advisory" : "advisories"} with a
                  fix, in every version used here, and not older than the newest version already in use.
                  {rec.data.withoutFix > 0 ? ` ${rec.data.withoutFix} more have no fix yet; no version clears those.` : ""}
                </p>
              </>
            ) : (
              <p className="text-text-muted">
                No recommendation: nothing with a fix is known against the versions used here
                {rec.data && rec.data.withoutFix > 0 ? ` (${rec.data.withoutFix} without a fix yet)` : ""}.
              </p>
            )}
          </div>
        </Card>
        <VersionCheckCard ecosystem={ecosystem} name={name} />
      </div>

      <PackageDetailPanel name={name} ecosystem={ecosystem} environmentId={current.id} environmentName={current.name} includeInactive={false} />
    </>
  );
}

/** "Is this version safe to add?" */
export function VersionCheckCard({ ecosystem, name }: { ecosystem: string; name: string }) {
  const [draft, setDraft] = useState("");
  const [asked, setAsked] = useState<string | null>(null);
  const check = useVersionCheck(ecosystem, name, asked);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (draft.trim()) setAsked(draft.trim());
  }

  const r = check.data;
  return (
    <Card>
      <CardHeader title="Is this version safe to add?" subtitle="Checked against the vulnerability database, as a build would be." />
      <form onSubmit={submit} className="flex items-center gap-2 p-4">
        <TextInput value={draft} onChange={setDraft} placeholder="Version, e.g. 4.17.21" ariaLabel="Version to check" />
        <Button type="submit" variant="primary" disabled={!draft.trim() || check.isFetching}>
          {check.isFetching ? "Checking…" : "Check"}
        </Button>
      </form>
      <div className="px-4 pb-4 text-sm">
        {check.error ? <ErrorBanner error={check.error} /> : null}
        {r ? (
          r.status === "no_known" ? (
            <p>
              <Badge tone="ok">No known vulnerabilities</Badge>{" "}
              <span className="text-text-muted">
                in {r.name} {r.version}, in the database of {r.databaseBuiltAt ? new Date(r.databaseBuiltAt).toLocaleDateString() : "today"}.
                That is what is known today, not a promise.
              </span>
            </p>
          ) : r.status === "vulnerable" ? (
            <>
              <p>
                <Badge tone="danger">{r.advisories.length} known</Badge>{" "}
                <span className="text-text-muted">
                  in {r.name} {r.version}.
                  {r.recommendedVersion ? ` The recommended version is ${r.recommendedVersion}.` : ""}
                </span>
              </p>
              <ul className="mt-2 space-y-1">
                {r.advisories.slice(0, 10).map((a) => (
                  <li key={a.vulnerabilityId} className="flex items-center gap-2">
                    <SeverityBadge severity={a.severity} />
                    <Link to={`/vulnerabilities/${encodeURIComponent(a.vulnerabilityId)}`} className="font-mono text-xs text-accent hover:underline">
                      {a.vulnerabilityId}
                    </Link>
                    <span className="text-xs text-text-muted">{a.fixedIn ? `fixed in ${a.fixedIn}` : "no fix yet"}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="text-text-muted">
              <Badge tone="neutral">Not checked</Badge> {r.message}
            </p>
          )
        ) : null}
      </div>
    </Card>
  );
}
