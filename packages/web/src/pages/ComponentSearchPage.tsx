import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import {
  useComponentEcosystems,
  useComponentSearch,
  useComponentSuggestions,
  useComponentVersions,
} from "../lib/queries.ts";
import { formatNumber } from "../lib/format.ts";
import { readBool, readEnum, readNumber, readString, useUrlState } from "../lib/useUrlState.ts";
import { useDebounced } from "../lib/useDebounced.ts";
import { ComponentHitsTable } from "../components/ComponentHitsTable.tsx";
import { BulkPackageSearch } from "./BulkPackageSearch.tsx";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Pagination,
  PageHeader,
  Select,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../components/ui.tsx";

const SCOPES = ["current", "historical", "all"] as const;
const MATCHES = ["contains", "exact"] as const;

const DEFAULTS = {
  name: "",
  version: "",
  ecosystem: "",
  scope: "current" as (typeof SCOPES)[number],
  match: "contains" as (typeof MATCHES)[number],
  includeInactive: false,
  page: 1,
};

const urlSpec = {
  defaults: DEFAULTS,
  parse: (params: URLSearchParams) => ({
    name: readString(params, "name"),
    version: readString(params, "version"),
    ecosystem: readString(params, "ecosystem"),
    scope: readEnum(params, "scope", SCOPES, "current"),
    match: readEnum(params, "match", MATCHES, "contains"),
    includeInactive: readBool(params, "includeInactive"),
    page: readNumber(params, "page", 1),
  }),
};

const SCOPE_LABELS: Record<(typeof SCOPES)[number], string> = {
  current: "Currently used",
  historical: "Previously used, not now",
  all: "Both",
};

const SCOPE_HINTS: Record<(typeof SCOPES)[number], string> = {
  current: "Applications whose latest scan contains this package.",
  historical:
    "Applications that shipped this package in an earlier build but not in their current one — it was removed or upgraded away.",
  all: "Every application that has ever shipped this package, labelled by whether it still does.",
};

/**
 * Global cross-application package search.
 *
 * The scope selector is the point of the page: "who ships log4j today" and "who
 * used to ship it" are different questions, and the second one is the reason the
 * platform keeps full scan history.
 */
/**
 * Package search, in two modes.
 *
 * "One package" answers who ships X. "A list" answers which of these N packages
 * are here at all. They share the scope semantics and the result table, so they
 * live on one page behind a toggle rather than as two features a user has to know
 * to look for separately.
 */
export function ComponentSearchPage({ mode }: { mode?: SearchMode } = {}) {
  const [searchParams, setSearchParams] = useSearchParams();
  // A saved list forces list mode: the route only exists in that shape.
  const active: SearchMode = mode ?? (searchParams.get("mode") === "list" ? "list" : "single");

  return (
    <>
      <PageHeader
        title="Package search"
        subtitle={
          active === "single"
            ? "Find every application that uses a package, now or at any point in its retained history."
            : "Check a whole list of packages against the estate at once — which are deployed, which were removed, and which were never here."
        }
        actions={
          <div role="group" aria-label="Search mode" className="flex overflow-hidden rounded-md border border-border-strong">
            {(["single", "list"] as const).map((candidate) => (
              <button
                key={candidate}
                type="button"
                aria-pressed={active === candidate}
                onClick={() => {
                  // Dropping every other param on purpose: a name and a pasted
                  // list are not the same query, and carrying filters across
                  // would silently apply one mode's state to the other.
                  const next = new URLSearchParams();
                  if (candidate === "list") next.set("mode", "list");
                  setSearchParams(next);
                }}
                className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                  active === candidate
                    ? "bg-accent text-white"
                    : "bg-bg-raised text-text-muted hover:bg-bg-subtle hover:text-text-base"
                }`}
              >
                {candidate === "single" ? "One package" : "A list"}
              </button>
            ))}
          </div>
        }
      />
      {active === "list" ? <BulkPackageSearch /> : <SinglePackageSearch />}
    </>
  );
}

export type SearchMode = "single" | "list";

function SinglePackageSearch() {
  const { state, setState, reset } = useUrlState(urlSpec);

  const [nameInput, setNameInput] = useState(state.name);
  const debouncedName = useDebounced(nameInput, 350);

  useEffect(() => {
    if (debouncedName !== state.name) setState({ name: debouncedName });
  }, [debouncedName, state.name, setState]);
  useEffect(() => {
    setNameInput(state.name);
  }, [state.name]);

  const hasQuery = state.name.trim().length > 0;

  const params = useMemo(
    () => ({
      name: state.name,
      version: state.version || undefined,
      ecosystem: state.ecosystem || undefined,
      scope: state.scope,
      match: state.match,
      includeInactive: state.includeInactive || undefined,
      page: state.page,
      pageSize: 50,
    }),
    [state],
  );

  const { data, isLoading, isFetching, error, refetch } = useComponentSearch(params, { enabled: hasQuery });
  const { data: ecosystems } = useComponentEcosystems();
  const { data: suggestions } = useComponentSuggestions(nameInput === state.name ? "" : nameInput);
  const { data: versions } = useComponentVersions(
    state.match === "exact" && hasQuery ? state.name : undefined,
  );

  return (
    <>
      <Card className="mb-4">
        <div className="flex flex-wrap items-end gap-3 p-3">
          <div className="min-w-[240px] flex-1">
            <label htmlFor="pkg-name" className="mb-1 block text-[11px] font-medium text-text-muted">
              Package name
            </label>
            <TextInput
              id="pkg-name"
              value={nameInput}
              onChange={setNameInput}
              placeholder="log4j-core"
              autoFocus
            />
            {/* Typeahead only while the debounce is still pending, so it does not
                linger over results the user has already committed to. */}
            {suggestions && suggestions.length > 0 ? (
              <div className="mt-1 flex flex-wrap gap-1">
                {suggestions.slice(0, 6).map((s) => (
                  <button
                    key={`${s.name}:${s.ecosystem}`}
                    type="button"
                    onClick={() => {
                      setNameInput(s.name);
                      setState({ name: s.name, match: "exact" });
                    }}
                    className="rounded border border-border-base px-1.5 py-0.5 text-[11px] text-text-muted hover:border-accent hover:text-accent"
                  >
                    {s.name}
                    <span className="ml-1 text-text-faint">{s.ecosystem}</span>
                  </button>
                ))}
              </div>
            ) : null}
          </div>

          <div className="w-40">
            <label htmlFor="pkg-version" className="mb-1 block text-[11px] font-medium text-text-muted">
              Version (optional)
            </label>
            <TextInput
              id="pkg-version"
              value={state.version}
              onChange={(v) => setState({ version: v })}
              placeholder="2.14.1"
            />
          </div>

          <div>
            <label htmlFor="pkg-match" className="mb-1 block text-[11px] font-medium text-text-muted">
              Name match
            </label>
            <Select
              id="pkg-match"
              value={state.match}
              onChange={(v) => setState({ match: v })}
              options={[
                { value: "contains", label: "Contains" },
                { value: "exact", label: "Exact" },
              ]}
            />
          </div>

          <div>
            <label htmlFor="pkg-eco" className="mb-1 block text-[11px] font-medium text-text-muted">
              Ecosystem
            </label>
            <Select
              id="pkg-eco"
              value={state.ecosystem}
              onChange={(v) => setState({ ecosystem: v })}
              options={[
                { value: "", label: "All" },
                ...(ecosystems ?? []).map((e) => ({ value: e.ecosystem, label: `${e.ecosystem} (${e.count})` })),
              ]}
            />
          </div>

          {hasQuery ? (
            <Button size="sm" variant="ghost" onClick={reset}>
              Clear
            </Button>
          ) : null}
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
                title={SCOPE_HINTS[scope]}
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

        <p className="border-t border-border-base px-3 py-2 text-[11px] text-text-faint">
          {SCOPE_HINTS[state.scope]}
        </p>
      </Card>

      {/* Version breakdown, shown for an exact-name search: which version is where. */}
      {versions && versions.length > 1 ? (
        <Card className="mb-4">
          <CardHeader
            title="Versions in use"
            subtitle={`${versions.length} distinct versions of ${state.name} across the estate`}
          />
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th width="220px">Version</Th>
                  <Th width="120px">Ecosystem</Th>
                  <Th align="right" width="140px">
                    Current apps
                  </Th>
                  <Th align="right" width="150px">
                    Ever used by
                  </Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {versions.map((v) => (
                  <Tr key={v.componentId}>
                    <Td className="nums font-mono text-xs">{v.version ?? "unknown"}</Td>
                    <Td>
                      <span className="rounded bg-neutral-subtle px-1.5 py-0.5 font-mono text-[11px] text-text-muted">
                        {v.ecosystem}
                      </span>
                    </Td>
                    <Td align="right" className="nums">
                      {v.currentApplications > 0 ? (
                        <span className="font-medium text-text-base">{formatNumber(v.currentApplications)}</span>
                      ) : (
                        <span className="text-text-faint">0</span>
                      )}
                    </Td>
                    <Td align="right" className="nums text-text-muted">
                      {formatNumber(v.totalApplications)}
                    </Td>
                    <Td>
                      {v.currentApplications === 0 && v.totalApplications > 0 ? (
                        <Badge tone="neutral" title="No application currently ships this version.">
                          fully removed
                        </Badge>
                      ) : null}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        </Card>
      ) : null}

      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}

      {!hasQuery ? (
        <Card>
          <EmptyState
            title="Search for a package"
            hint="Type a package name above. Switch to “Previously used, not now” to find applications that dropped a dependency — that view is powered by full scan history, not just the latest build."
          />
        </Card>
      ) : (
        <Card>
          <CardHeader
            title="Results"
            subtitle={
              data
                ? `${formatNumber(data.total)} application–package pair${data.total === 1 ? "" : "s"}` +
                  (data.matchedComponents > 0 ? ` · ${formatNumber(data.matchedComponents)} distinct packages matched` : "")
                : undefined
            }
          />

          {data?.truncated ? (
            <div
              role="note"
              className="border-b border-border-base bg-warn-subtle px-4 py-2 text-xs text-warn"
            >
              This search matched more distinct packages than can be reported at once. Narrow it with a more
              specific name, an exact match, or an ecosystem filter.
            </div>
          ) : null}

          {isLoading ? (
            <LoadingBlock label="Searching" />
          ) : !data || data.items.length === 0 ? (
            <EmptyState
              title="No matches"
              hint={
                state.scope === "current"
                  ? "No application currently ships a package matching this. Try “Previously used, not now”, or a Contains match."
                  : state.scope === "historical"
                    ? "No application has dropped a package matching this. Try “Currently used”."
                    : "No application has ever shipped a package matching this."
              }
            />
          ) : (
            <>
              <ComponentHitsTable hits={data.items} />
              <Pagination
                page={data.page}
                pageSize={data.pageSize}
                total={data.total}
                totalPages={data.totalPages}
                onPageChange={(page) => setState({ page })}
                isFetching={isFetching}
              />
            </>
          )}
        </Card>
      )}
    </>
  );
}
