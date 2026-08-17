import { Link, useParams, useSearchParams } from "react-router";
import { DiffView } from "../components/DiffView.tsx";
import { useApplication, useApplicationDiff, useApplicationScans } from "../lib/queries.ts";
import { formatDateTime } from "../lib/format.ts";
import { Card, EmptyState, ErrorBanner, LoadingBlock, PageHeader, Select } from "../components/ui.tsx";

/**
 * Compare any two builds of one application.
 *
 * The scan pair lives in the URL rather than in component state, so a specific
 * comparison — "here is exactly what changed between build 41 and build 47" —
 * can be pasted into a ticket and open the same for the next reader.
 */
export function ScanDiffPage() {
  const { id } = useParams<{ id: string }>();
  const [params, setParams] = useSearchParams();

  const from = params.get("from") ?? "";
  const to = params.get("to") ?? "";

  const app = useApplication(id);
  // Enough history to populate both selectors. Beyond a hundred builds, the
  // useful comparisons are reached from a specific scan's page anyway.
  const scans = useApplicationScans(id, { page: 1, pageSize: 100, sortDir: "desc" });

  const diff = useApplicationDiff(id, {
    ...(from ? { fromScanId: from } : {}),
    ...(to ? { toScanId: to } : {}),
  });

  function setPair(patch: { from?: string; to?: string }) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(patch)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    setParams(next, { replace: true });
  }

  if (app.isLoading) return <LoadingBlock label="Loading application" />;
  if (app.error) return <ErrorBanner error={app.error} onRetry={() => void app.refetch()} />;
  if (!app.data) return null;

  const options = (scans.data?.items ?? []).map((s) => ({
    value: s.id,
    label: `${s.buildNumber ? `build ${s.buildNumber}` : "build"} — ${formatDateTime(s.createdAt)}${
      s.isLatest ? " (current)" : ""
    }`,
  }));

  return (
    <>
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-2">
            <Link to={`/applications/${app.data.id}`} className="text-accent hover:underline">
              {app.data.name}
            </Link>
            <span className="text-text-faint">/</span>
            <span>Compare builds</span>
          </span>
        }
        subtitle="Defaults to the latest build against the one before it. Choose any two to compare."
      />

      <Card className="mb-4">
        <div className="flex flex-wrap items-end gap-3 px-4 py-3">
          <div>
            <label htmlFor="diff-from" className="mb-1 block text-xs font-medium text-text-muted">
              From (earlier build)
            </label>
            <Select
              id="diff-from"
              value={from}
              onChange={(v) => setPair({ from: v })}
              options={[{ value: "", label: "Automatic — the build before 'to'" }, ...options]}
            />
          </div>
          <div>
            <label htmlFor="diff-to" className="mb-1 block text-xs font-medium text-text-muted">
              To (later build)
            </label>
            <Select
              id="diff-to"
              value={to}
              onChange={(v) => setPair({ to: v })}
              options={[{ value: "", label: "Automatic — the current build" }, ...options]}
            />
          </div>
        </div>
      </Card>

      {diff.isLoading ? (
        <LoadingBlock label="Comparing builds" />
      ) : diff.error ? (
        <Card>
          <EmptyState
            title="Nothing to compare"
            hint={diff.error instanceof Error ? diff.error.message : "Choose two different builds."}
          />
        </Card>
      ) : diff.data ? (
        <DiffView diff={diff.data} />
      ) : null}
    </>
  );
}
