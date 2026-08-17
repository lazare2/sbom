import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import {
  BULK_MATCH_CAP_PER_ENTRY,
  BULK_SEARCH_MAX_ENTRIES,
  componentSearchSort,
  sortDirections,
  type BulkRollupRow,
  type NameMatchMode,
} from "@sbom/shared";
import { useClientSort, useServerSort } from "../lib/useSort.ts";
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

const MATCHES = ["exact", "contains"] as const;
const SORT_FIELDS = componentSearchSort.fields;

const urlSpec = {
  defaults: {
    scope: "current" as const,
    view: "rollup" as const,
    includeInactive: false,
    // Exact by default, the opposite of the single search. A pasted list is an audit:
    // 200 names in, 200 verdicts out. See bulkOptionsSchema for the full reasoning.
    match: "exact" as (typeof MATCHES)[number],
    sortBy: componentSearchSort.defaultField,
    sortDir: componentSearchSort.defaultDirection,
    page: 1,
  },
  parse: (params: URLSearchParams) => ({
    scope: readEnum(params, "scope", SCOPES, "current"),
    view: readEnum(params, "view", VIEWS, "rollup"),
    includeInactive: readBool(params, "includeInactive"),
    match: readEnum(params, "match", MATCHES, "exact"),
    sortBy: readEnum(params, "sortBy", SORT_FIELDS, componentSearchSort.defaultField),
    sortDir: readEnum(params, "sortDir", sortDirections, componentSearchSort.defaultDirection),
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
  // Server-side: the matches view is paginated at 100 rows.
  const sort = useServerSort(componentSearchSort, state, setState);
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
            checked={state.match === "exact"}
            onChange={(v) => setState({ match: v ? "exact" : "contains" })}
            label="Exact name match"
          />
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
          absent today.{" "}
          {state.match === "exact"
            ? "Each line matches one package, by exact name."
            : `Each line matches every package whose name contains it, up to ${BULK_MATCH_CAP_PER_ENTRY} per line.`}
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
              <RollupTable rows={result.rollup} match={state.match} />
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
                <ComponentHitsTable hits={result.matches.items} sort={sort} />
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
  if (options.match !== "exact") params.match = options.match;
  if (options.sortBy !== componentSearchSort.defaultField) params.sortBy = options.sortBy;
  if (options.sortDir !== componentSearchSort.defaultDirection) params.sortDir = options.sortDir;
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
/*
  Defaults to `line` ascending — the order the list was pasted in. That is the whole point
  of the rollup: someone checking their own 200-line list against the results should be able
  to read down both in step. Any other default would break that on first load, so the other
  orders are available but never assumed.
*/
const ROLLUP_COLUMNS = {
  line: "number",
  package: "text",
  versionAsked: "text",
  result: "text",
  currentApplications: "number",
  historicalApplications: "number",
} as const;

function RollupTable({ rows, match }: { rows: readonly BulkRollupRow[]; match: NameMatchMode }) {
  const sort = useClientSort(
    rows,
    ROLLUP_COLUMNS,
    { sortBy: "line", sortDir: "asc" },
    (row, field) => {
      switch (field) {
        case "package":
          return row.name;
        case "versionAsked":
          return row.version;
        /*
          Ranked so the interesting verdicts come first in the natural direction: a package
          present at a different version is the answer an advisory audit is looking for, and
          alphabetising "found" / "not found" / "other version" would scatter them.
        */
        case "result":
          return row.found ? 3 : row.nameFound ? 2 : 1;
        case "currentApplications":
          return row.currentApplications;
        case "historicalApplications":
          return row.historicalApplications;
        case "line":
        default:
          return row.line;
      }
    },
    (row) => row.line,
  );

  if (rows.length === 0) {
    return <EmptyState title="Nothing to search" hint="No line in the list parsed as a package." />;
  }

  return (
    <TableWrap>
      <Table>
        <thead>
          <tr>
            <Th onSort={() => sort.toggle("line")} sorted={sort.stateOf("line")} width="50px" align="right">
              #
            </Th>
            <Th onSort={() => sort.toggle("package")} sorted={sort.stateOf("package")}>
              Package
            </Th>
            <Th onSort={() => sort.toggle("versionAsked")} sorted={sort.stateOf("versionAsked")} width="150px">
              Version asked
            </Th>
            <Th onSort={() => sort.toggle("result")} sorted={sort.stateOf("result")} width="130px">
              Result
            </Th>
            {/* A list of versions, not one orderable value. */}
            <Th>Versions present</Th>
            {/* Application counts, deliberately not reusing the verdict words. */}
            <Th
              onSort={() => sort.toggle("currentApplications")}
              sorted={sort.stateOf("currentApplications")}
              width="90px"
              align="right"
            >
              Apps now
            </Th>
            <Th
              onSort={() => sort.toggle("historicalApplications")}
              sorted={sort.stateOf("historicalApplications")}
              width="110px"
              align="right"
            >
              Apps dropped
            </Th>
          </tr>
        </thead>
        <tbody>
          {sort.rows.map((row) => (
            <Tr key={row.line}>
              <Td align="right" className="nums text-xs text-text-faint">
                {row.line}
              </Td>
              <Td>
                {/*
                  The link searches the term the way this row matched it, so following it
                  cannot show a different set of packages than the row just claimed.
                */}
                <Link
                  to={`/search?name=${encodeURIComponent(row.name)}&match=${match}&scope=all`}
                  className="font-medium text-accent hover:underline"
                >
                  {row.name}
                </Link>
                {row.ecosystems.map((eco) => (
                  <span key={eco} className="ml-1.5">
                    <EcosystemBadge ecosystem={eco} />
                  </span>
                ))}
                <MatchedNames row={row} />
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
 * The packages one input line matched, when it matched more than one.
 *
 * Renders nothing in the ordinary case. `exact` mode matches a single name, and showing
 * "1 package" next to that name on every row would be noise; the disclosure only earns its
 * place when the count is the actual answer.
 *
 * A `<details>` rather than component state: the row is inside a table that can hold a
 * thousand rows, and native disclosure keeps each one at zero React state while still being
 * keyboard-operable and searchable by the browser's own find.
 */
function MatchedNames({ row }: { row: BulkRollupRow }) {
  if (row.matchedNameCount <= 1) return null;

  return (
    <details className="mt-1">
      <summary className="cursor-pointer text-[11px] text-text-muted hover:text-accent">
        {formatNumber(row.matchedNameCount)}
        {row.matchedNamesTruncated ? "+" : ""} packages matched
        {row.matchedNamesTruncated ? (
          <span
            className="ml-1 text-warn"
            title={`Stopped at ${BULK_MATCH_CAP_PER_ENTRY} packages for this line. Narrow the term, or search it on its own for the full list.`}
          >
            (partial)
          </span>
        ) : null}
      </summary>
      <div className="mt-1 flex flex-wrap gap-1">
        {row.matchedNames.map((name) => (
          <Link
            key={name}
            to={`/search?name=${encodeURIComponent(name)}&match=exact&scope=all`}
            className="rounded border border-border-base px-1.5 py-0.5 font-mono text-[11px] text-text-muted hover:border-accent hover:text-accent"
          >
            {name}
          </Link>
        ))}
      </div>
    </details>
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
