import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { BULK_SEARCH_MAX_ENTRIES, type BulkRollupRow } from "@sbom/shared";
import { ComponentHitsTable } from "../components/ComponentHitsTable.tsx";
import { formatNumber, formatRelative } from "../lib/format.ts";
import { useSubmitPackageList } from "../lib/mutations.ts";
import {
  bulkSearchXlsxUrl,
  useBulkSearch,
  useRecentPackageLists,
  type BulkSearchOptions,
} from "../lib/queries.ts";
import { readBool, readEnum, readNumber, useUrlState } from "../lib/useUrlState.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
  EcosystemBadge,
  EmptyState,
  ErrorBanner,
  FormError,
  LoadingBlock,
  Mono,
  Pagination,
  Table,
  TableWrap,
  Td,
  Textarea,
  Th,
  Tr,
} from "../components/ui.tsx";

/**
 * Bulk package list search.
 *
 * Answers a different question from the single search: not "who ships X" but "of
 * these N packages, which are in the estate at all". That inverts what matters —
 * if three of forty are present, the answer is mostly about the thirty-seven that
 * are not — so the default view is one row per submitted line, misses included.
 *
 * Submitting navigates to `/search/list/:id`. The list has to travel in a POST
 * body (several hundred packages will not fit in a URL), and persisting it is what
 * gives the results an address to share; making that the only read path means a
 * fresh search and a colleague's link render through identical code.
 */

const SCOPES = ["current", "historical", "all"] as const;
const VIEWS = ["rollup", "matches"] as const;

const SCOPE_LABELS: Record<(typeof SCOPES)[number], string> = {
  current: "Currently used",
  historical: "Previously used, not now",
  all: "Both",
};

const PLACEHOLDER = `logaas
@wb-track/shared-front
cnapp-ui
keyv@6.0.0`;

const urlSpec = {
  defaults: { scope: "current" as const, view: "rollup" as const, includeInactive: false, page: 1 },
  parse: (params: URLSearchParams) => ({
    scope: readEnum(params, "scope", SCOPES, "current"),
    view: readEnum(params, "view", VIEWS, "rollup"),
    includeInactive: readBool(params, "includeInactive"),
    page: readNumber(params, "page", 1),
  }),
};

export function BulkPackageSearch() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { state, setState } = useUrlState(urlSpec);
  const options: BulkSearchOptions = state;

  const [text, setText] = useState("");
  const submit = useSubmitPackageList();
  const query = useBulkSearch(id, options);
  const recent = useRecentPackageLists();

  // Repopulate the box from a shared link, including the lines that failed to
  // parse — those are the ones the recipient will want to fix.
  useEffect(() => {
    if (query.data?.input) setText(query.data.input);
  }, [query.data?.input]);

  function run() {
    const input = text.trim();
    if (input === "") return;
    submit.mutate(
      { input, ...options, page: 1, pageSize: 100 },
      {
        onSuccess: (result) => {
          navigate(`/search/list/${result.queryId}?${new URLSearchParams(urlParams(options))}`);
        },
      },
    );
  }

  const result = query.data;

  return (
    <>
      <Card className="mb-4">
        <CardHeader
          title="Paste a package list"
          subtitle={`One package per line, with or without a version. Accepts name@version, pip pins (django==4.2.1), purls, maven coordinates, and tab- or comma-separated columns. Up to ${formatNumber(BULK_SEARCH_MAX_ENTRIES)} packages.`}
          actions={
            <>
              <Button variant="primary" onClick={run} disabled={submit.isPending || text.trim() === ""}>
                {submit.isPending ? "Searching…" : "Search list"}
              </Button>
              {text !== "" ? (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setText("");
                    navigate("/search?mode=list");
                  }}
                >
                  Clear
                </Button>
              ) : null}
            </>
          }
        />
        <div className="p-3">
          <Textarea
            id="bulk-input"
            value={text}
            onChange={setText}
            rows={8}
            placeholder={PLACEHOLDER}
          />
          <FormError error={submit.error} />
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-border-base px-3 py-2">
          <span className="text-[11px] font-medium text-text-muted">Usage</span>
          <div role="radiogroup" aria-label="Usage scope" className="flex flex-wrap gap-1">
            {SCOPES.map((scope) => (
              <button
                key={scope}
                type="button"
                role="radio"
                aria-checked={state.scope === scope}
                onClick={() => setState({ scope })}
                className={`rounded-md px-2 py-1 text-xs transition-colors ${
                  state.scope === scope
                    ? "bg-accent-subtle font-medium text-accent"
                    : "text-text-muted hover:bg-bg-subtle hover:text-text-base"
                }`}
              >
                {SCOPE_LABELS[scope]}
              </button>
            ))}
          </div>
          <span aria-hidden="true" className="text-border-strong">
            |
          </span>
          <Checkbox
            checked={state.includeInactive}
            onChange={(v) => setState({ includeInactive: v })}
            label="Include inactive applications"
          />
        </div>

        {/*
          Scope narrows the matching applications, not the found/not-found verdict.
          Said out loud because the opposite assumption would make a "not found" row
          mean something much weaker than it does.
        */}
        <p className="border-t border-border-base px-3 py-2 text-[11px] text-text-faint">
          Usage narrows which applications are listed. Whether a package exists at all is always
          reported against the full retained history, so “not found” means never seen — not merely
          absent today.
        </p>
      </Card>

      {recent.data && recent.data.length > 0 && !id ? (
        <Card className="mb-4">
          <CardHeader title="Recent lists" subtitle="Lists searched recently, by anyone." />
          <div className="flex flex-wrap gap-2 p-3">
            {recent.data.map((list) => (
              <Link
                key={list.id}
                to={`/search/list/${list.id}`}
                className="rounded-md border border-border-base px-2 py-1.5 text-xs text-text-muted transition-colors hover:border-accent hover:text-accent"
                title={`${list.entryCount} packages · last opened ${formatRelative(list.lastAccessedAt)}`}
              >
                <span className="font-medium">{list.entryCount} packages</span>
                <span className="ml-1.5 text-text-faint">{list.preview.join(", ")}…</span>
              </Link>
            ))}
          </div>
        </Card>
      ) : null}

      {query.error ? <ErrorBanner error={query.error} onRetry={() => void query.refetch()} /> : null}

      {!id ? (
        <Card>
          <EmptyState
            title="Search a list of packages"
            hint="Paste one package per line above. Every submitted list gets a shareable link, and the results download as an Excel workbook."
          />
        </Card>
      ) : query.isLoading ? (
        <LoadingBlock label="Searching the list" />
      ) : result ? (
        <>
          <ParseNotices result={result} />

          <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Tile label="Packages searched" value={result.parse.entries} />
            <Tile
              label="In a current build"
              value={result.summary.inCurrentUse}
              tone={result.summary.inCurrentUse > 0 ? "warn" : "ok"}
            />
            {/*
              "No match", not "not found anywhere": a pinned version that misses
              counts here even though the package itself is deployed, so the
              stronger wording would overclaim.
            */}
            <Tile label="No match" value={result.summary.notFound} tone="ok" />
            <Tile label="Applications affected" value={result.summary.applicationsAffected} />
          </div>

          <Card>
            <CardHeader
              title="Results"
              subtitle={
                state.view === "rollup"
                  ? "One row per package you submitted. Click a package to open it in the single search."
                  : `${formatNumber(result.matches?.total ?? 0)} application–package pair${
                      (result.matches?.total ?? 0) === 1 ? "" : "s"
                    }`
              }
              actions={
                <>
                  <div className="flex overflow-hidden rounded-md border border-border-strong">
                    {VIEWS.map((view) => (
                      <button
                        key={view}
                        type="button"
                        onClick={() => setState({ view, page: 1 })}
                        aria-pressed={state.view === view}
                        className={`px-2.5 py-1 text-xs font-medium transition-colors ${
                          state.view === view
                            ? "bg-accent text-white"
                            : "bg-bg-raised text-text-muted hover:bg-bg-subtle hover:text-text-base"
                        }`}
                      >
                        {view === "rollup" ? "By package" : "By application"}
                      </button>
                    ))}
                  </div>
                  {/*
                    A plain link, not a fetch: the endpoint is a GET on the saved
                    list, which is the payoff for persisting it — no re-posting the
                    body and no synthesised blob URL.
                  */}
                  <a
                    href={bulkSearchXlsxUrl(id, options)}
                    className="inline-flex items-center justify-center rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
                  >
                    Download Excel
                  </a>
                </>
              }
            />

            {state.view === "rollup" ? (
              <RollupTable rows={result.rollup} />
            ) : !result.matches || result.matches.items.length === 0 ? (
              <EmptyState
                title="No matches"
                hint={
                  state.scope === "current"
                    ? "No application currently ships any package on this list. Try “Previously used, not now”."
                    : "No application matched any package on this list in this scope."
                }
              />
            ) : (
              <>
                <ComponentHitsTable hits={result.matches.items} />
                <Pagination
                  page={result.matches.page}
                  pageSize={result.matches.pageSize}
                  total={result.matches.total}
                  totalPages={result.matches.totalPages}
                  onPageChange={(page) => setState({ page })}
                  isFetching={query.isFetching}
                />
              </>
            )}
          </Card>
        </>
      ) : null}
    </>
  );
}

function urlParams(options: BulkSearchOptions): Record<string, string> {
  const params: Record<string, string> = {};
  if (options.scope !== "current") params.scope = options.scope;
  if (options.view !== "rollup") params.view = options.view;
  if (options.includeInactive) params.includeInactive = "true";
  return params;
}

function Tile({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "warn" | "ok";
}) {
  const toneClass = tone === "warn" ? "text-warn" : tone === "ok" ? "text-ok" : "text-text-base";
  return (
    <div className="rounded-lg border border-border-base bg-bg-raised px-4 py-3">
      <p className="text-[11px] font-medium uppercase tracking-wide text-text-faint">{label}</p>
      <p className={`nums mt-1 text-2xl font-semibold ${toneClass}`}>{formatNumber(value)}</p>
    </div>
  );
}

/**
 * What the parser made of the input.
 *
 * Shown above the results, not tucked away: a line that was skipped is a package
 * that was *not searched*, and a reader who does not know that will read the
 * verdict as covering their whole list.
 */
function ParseNotices({ result }: { result: { parse: BulkRollupResultParse } }) {
  const { parse } = result;
  const notes: string[] = [];
  if (parse.duplicatesCollapsed > 0) {
    notes.push(
      `${formatNumber(parse.duplicatesCollapsed)} duplicate${parse.duplicatesCollapsed === 1 ? "" : "s"} collapsed`,
    );
  }
  if (parse.constraintsDropped > 0) {
    notes.push(
      `${formatNumber(parse.constraintsDropped)} version range${
        parse.constraintsDropped === 1 ? "" : "s"
      } matched across all versions`,
    );
  }

  if (parse.problems.length === 0 && notes.length === 0 && !parse.truncated) return null;

  return (
    <div className="mb-4 space-y-2">
      {parse.truncated ? (
        <div role="alert" className="rounded-lg border border-warn bg-warn-subtle px-4 py-2.5 text-xs text-warn">
          The list was cut at {formatNumber(BULK_SEARCH_MAX_ENTRIES)} packages. Everything past that was not
          searched — split the list and run it in batches.
        </div>
      ) : null}

      {parse.problems.length > 0 ? (
        <div className="rounded-lg border border-warn bg-warn-subtle px-4 py-2.5">
          <p className="text-xs font-medium text-warn">
            {formatNumber(parse.problems.length)} line
            {parse.problems.length === 1 ? " was" : "s were"} not understood and{" "}
            {parse.problems.length === 1 ? "was" : "were"} not searched
          </p>
          <ul className="mt-1.5 space-y-0.5">
            {parse.problems.slice(0, 8).map((problem) => (
              <li key={problem.line} className="text-xs text-text-muted">
                <span className="text-text-faint">line {problem.line}:</span>{" "}
                <Mono>{problem.raw}</Mono> — {problem.reason}
              </li>
            ))}
            {parse.problems.length > 8 ? (
              <li className="text-xs text-text-faint">
                …and {formatNumber(parse.problems.length - 8)} more
              </li>
            ) : null}
          </ul>
        </div>
      ) : null}

      {notes.length > 0 ? (
        <p className="text-xs text-text-muted">{notes.join(" · ")}.</p>
      ) : null}
    </div>
  );
}

type BulkRollupResultParse = {
  entries: number;
  duplicatesCollapsed: number;
  constraintsDropped: number;
  truncated: boolean;
  problems: Array<{ line: number; raw: string; reason: string }>;
};

/**
 * One row per submitted package.
 *
 * Four verdicts, not two. "Other version" has to be distinguishable from "not
 * found": for an advisory audit, *we have this package but not the version named*
 * is a different and far more interesting answer than *we do not have it*.
 */
function RollupTable({ rows }: { rows: readonly BulkRollupRow[] }) {
  if (rows.length === 0) {
    return <EmptyState title="Nothing to search" hint="No line in the list parsed as a package." />;
  }

  return (
    <TableWrap>
      <Table>
        <thead>
          <tr>
            <Th width="50px" align="right">
              #
            </Th>
            <Th>Package</Th>
            <Th width="150px">Version asked</Th>
            <Th width="130px">Result</Th>
            <Th>Versions present</Th>
            {/* Application counts, deliberately not reusing the verdict words. */}
            <Th width="90px" align="right">
              Apps now
            </Th>
            <Th width="110px" align="right">
              Apps dropped
            </Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <Tr key={row.line}>
              <Td align="right" className="nums text-xs text-text-faint">
                {row.line}
              </Td>
              <Td>
                <Link
                  to={`/search?name=${encodeURIComponent(row.name)}&match=exact&scope=all`}
                  className="font-medium text-accent hover:underline"
                >
                  {row.name}
                </Link>
                {row.ecosystems.map((eco) => (
                  <span key={eco} className="ml-1.5">
                    <EcosystemBadge ecosystem={eco} />
                  </span>
                ))}
              </Td>
              <Td>
                {row.version === null ? (
                  <span className="text-xs text-text-faint">any</span>
                ) : (
                  <>
                    <Mono>{row.version}</Mono>
                    {row.versionKind === "version-ignored" ? (
                      <span
                        className="ml-1 text-[11px] text-warn"
                        title="Not a single version — a range, wildcard or tag. Matched across every version instead, so this row may over-report."
                      >
                        (ignored)
                      </span>
                    ) : null}
                  </>
                )}
              </Td>
              <Td>
                <Verdict row={row} />
              </Td>
              <Td>
                {row.versionsFound.length === 0 ? (
                  <span className="text-xs text-text-faint">—</span>
                ) : (
                  <Mono>
                    {row.versionsFound.join(", ")}
                    {row.versionsTruncated ? ", …" : ""}
                  </Mono>
                )}
              </Td>
              <Td align="right" className="nums">
                {row.currentApplications > 0 ? (
                  <span className="font-medium">{formatNumber(row.currentApplications)}</span>
                ) : (
                  <span className="text-text-faint">0</span>
                )}
              </Td>
              <Td align="right" className="nums text-text-muted">
                {row.historicalApplications > 0 ? formatNumber(row.historicalApplications) : (
                  <span className="text-text-faint">0</span>
                )}
              </Td>
            </Tr>
          ))}
        </tbody>
      </Table>
    </TableWrap>
  );
}

/**
 * The verdict for one submitted package.
 *
 * `warn` for "in use" rather than `danger`: it is the row that needs attention,
 * but red would assert that the package is *bad*, and this platform has no
 * vulnerability data to justify that claim.
 *
 * "Not found" gets no badge at all. In a forty-package audit most rows are misses,
 * and leaving them unbadged is what makes the handful that matter visible at a
 * glance.
 */
function Verdict({ row }: { row: BulkRollupRow }) {
  if (row.found && row.currentApplications > 0) {
    return (
      <Badge tone="warn" title="Present in at least one application's latest build.">
        in use
      </Badge>
    );
  }
  if (row.found) {
    return (
      <Badge tone="neutral" title="Was shipped at some point, but no current build contains it.">
        removed
      </Badge>
    );
  }
  if (row.nameFound) {
    return (
      <Badge
        tone="info"
        title="This package is in the estate, but not at the version you asked for. The versions present are listed to the right."
      >
        other version
      </Badge>
    );
  }
  return (
    <span className="text-xs text-text-faint" title="Never seen in any scan, current or historical.">
      not found
    </span>
  );
}
