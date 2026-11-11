import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { packageSearchSort, sortDirections, type ComponentSearchHit, type PackageSearchRow } from "@sbom/shared";
import { useServerSort } from "../lib/useSort.ts";
import {
  useComponentEcosystems,
  useComponentSuggestions,
  useEnvironments,
  usePackageSearch,
} from "../lib/queries.ts";
import { formatNumber } from "../lib/format.ts";
import {
  readBool,
  readEnum,
  readNumber,
  readString,
  readStringList,
  useUrlState,
} from "../lib/useUrlState.ts";
import { useDebounced } from "../lib/useDebounced.ts";
import { COMPONENT_HIT_EXPORT_COLUMNS } from "../components/ComponentHitsTable.tsx";
import { PACKAGE_EXPORT_COLUMNS, PackagesTable } from "../components/PackageResults.tsx";
import { ExportTableButton, fetchAllPages } from "../components/ExportTable.tsx";
import { BulkPackageSearch } from "./BulkPackageSearch.tsx";
import {
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
  TextInput,
} from "../components/ui.tsx";

const SCOPES = ["current", "historical", "all"] as const;
const MATCHES = ["contains", "exact"] as const;

/**
 * Sort defaults come from the shared declaration rather than being restated, so the URL
 * omits them exactly when the server would have chosen them anyway.
 */
const SORT_FIELDS = packageSearchSort.fields;
const SORT_DIRECTIONS = sortDirections;

const DEFAULTS = {
  name: "",
  version: "",
  ecosystem: "",
  scope: "current" as (typeof SCOPES)[number],
  match: "contains" as (typeof MATCHES)[number],
  includeInactive: false,
  /*
    Empty means every estate the account can reach, which is what the page opens on. That is
    the one place on the platform where crossing environments is correct: "where does log4j
    appear" is a question about the deployment, and answering it one estate at a time invites
    someone to check production, find nothing, and stop.
  */
  environments: [] as string[],
  sortBy: packageSearchSort.defaultField,
  sortDir: packageSearchSort.defaultDirection,
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
    environments: readStringList(params, "environments"),
    sortBy: readEnum(params, "sortBy", SORT_FIELDS, packageSearchSort.defaultField),
    sortDir: readEnum(params, "sortDir", SORT_DIRECTIONS, packageSearchSort.defaultDirection),
    page: readNumber(params, "page", 1),
  }),
};

const SCOPE_LABELS: Record<(typeof SCOPES)[number], string> = {
  current: "Currently used",
  historical: "Previously used, not now",
  all: "Both",
};

/*
  Package-level wording. An application that upgraded from 1.0 to 1.1 still uses the package,
  so "previously used" means it ships no version of it any more - not that one version went away.
*/
const SCOPE_HINTS: Record<(typeof SCOPES)[number], string> = {
  current: "Packages some application's latest build ships, in any version.",
  historical:
    "Packages some application shipped in an earlier build and ships no version of now - it was removed, not just upgraded.",
  all: "Every package any application has ever shipped, counting both who uses it now and who dropped it.",
};

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
            : "Check a whole list of packages against the estate at once - which are deployed, which were removed, and which were never here."
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
      // Omitted rather than sent empty: the API reads an absent selection as every estate.
      environments: state.environments.length > 0 ? state.environments : undefined,
      sortBy: state.sortBy,
      sortDir: state.sortDir,
      page: state.page,
      pageSize: 50,
    }),
    [state],
  );

  const { data, isLoading, isFetching, error, refetch } = usePackageSearch(params, { enabled: hasQuery });
  // Server-side: the result set is paginated, so the ordering has to be decided by the query.
  const sort = useServerSort(packageSearchSort, state, setState);
  const { data: ecosystems } = useComponentEcosystems();
  const { data: suggestions } = useComponentSuggestions(nameInput === state.name ? "" : nameInput);
  const { data: environmentList } = useEnvironments();
  /*
    The estate column appears only when the reader can see more than one estate. With one, every
    row would repeat the same name; with several, the same package legitimately appears once per
    estate and the column is what tells those rows apart.
  */
  const showEnvironment = (environmentList?.environments.length ?? 0) > 1;

  /*
    The per-application rows, for a spreadsheet. The package table is the reading view; this is
    the one a ticket wants when it asks for every application and version, and it uses the
    per-pair search so its scope semantics are the ones its columns describe.
  */
  const usageExportParams = useMemo(
    () => ({
      name: state.name,
      version: state.version || undefined,
      ecosystem: state.ecosystem || undefined,
      scope: state.scope,
      match: state.match,
      includeInactive: state.includeInactive || undefined,
      environments: state.environments.length > 0 ? state.environments : undefined,
    }),
    [state],
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
          {/*
            A checkbox rather than the Contains/Exact dropdown this replaced. Both modes
            existed and worked, but as a two-value select in a row of other selects it read
            as one more filter and went unnoticed - people searched "react", got
            reactive-element and reactor, and concluded the search was fuzzy with no way to
            narrow it. A checkbox states the mode instead of hiding it behind a click.
          */}
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

        <EnvironmentFilter
          selected={state.environments}
          onChange={(environments) => setState({ environments })}
        />

        <p className="border-t border-border-base px-3 py-2 text-[11px] text-text-faint">
          {SCOPE_HINTS[state.scope]}{" "}
          {state.match === "exact"
            ? `Only packages named exactly "${state.name || "…"}" (case-insensitive).`
            : "Any package whose name contains what you typed."}
        </p>
      </Card>

      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}

      {!hasQuery ? (
        <Card>
          <EmptyState
            title="Search for a package"
            hint="Type a package name above to see every application that uses it, which versions are in use, and what is known against them. Switch to “Previously used, not now” to find applications that dropped a dependency - that view is powered by full scan history, not just the latest build."
          />
        </Card>
      ) : (
        <Card>
          <CardHeader
            title="Packages"
            subtitle={
              data
                ? `${formatNumber(data.total)} package${data.total === 1 ? "" : "s"} matched. Open one to see its versions and every application that uses it.`
                : undefined
            }
            actions={
              data && data.total > 0 ? (
                <>
                  <ExportTableButton
                    title="Packages"
                    label="Export packages"
                    filename={`packages-${state.name.trim().replace(/[^A-Za-z0-9._-]+/g, "-")}`}
                    fetchRows={(progress) => fetchAllPages<PackageSearchRow>("/components/packages", params, progress)}
                    columns={PACKAGE_EXPORT_COLUMNS}
                  />
                  <ExportTableButton
                    title="Every application and version"
                    label="Export every application"
                    filename={`package-usage-${state.name.trim().replace(/[^A-Za-z0-9._-]+/g, "-")}`}
                    fetchRows={(progress) =>
                      fetchAllPages<ComponentSearchHit>("/components/search", usageExportParams, progress)
                    }
                    columns={COMPONENT_HIT_EXPORT_COLUMNS}
                  />
                </>
              ) : undefined
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

          {data && !data.vulnScanningEnabled ? (
            <p className="border-b border-border-base px-4 py-2 text-[11px] text-text-faint">
              Vulnerability scanning is switched off, so advisory columns are not shown.
            </p>
          ) : data && data.total > 0 ? (
            <p className="border-b border-border-base px-4 py-2 text-[11px] text-text-faint">
              Advisories are distinct, counted over the versions in current builds only, with accepted risks left
              out. A package with none is still listed with every application that uses it.
            </p>
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
              <PackagesTable
                // Re-keyed per query so a new search starts with its rows closed again.
                key={JSON.stringify(params)}
                rows={data.items}
                sort={sort}
                showEnvironment={showEnvironment}
                showVulns={data.vulnScanningEnabled}
                includeInactive={state.includeInactive}
                initiallyOpen={data.total === 1}
              />
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

/**
 * Which estates this search covers.
 *
 * Rendered only where there is more than one. With a single environment the control would
 * offer a choice that changes nothing, and an unticked box would read as excluding the only
 * estate there is.
 *
 * "All" is the absence of a selection rather than every box ticked, and the difference is
 * not cosmetic: a search saved as "all" keeps covering an estate created next month,
 * whereas one that enumerated today's estates quietly stops being a whole-deployment
 * search the moment somebody adds one.
 */
function EnvironmentFilter({
  selected,
  onChange,
}: {
  selected: string[];
  onChange: (environments: string[]) => void;
}) {
  const { data } = useEnvironments();
  const environments = data?.environments ?? [];
  if (environments.length < 2) return null;

  const searchingAll = selected.length === 0;

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-t border-border-base px-3 py-2">
      <span className="text-[11px] font-medium text-text-muted">Environments</span>
      <button
        type="button"
        aria-pressed={searchingAll}
        onClick={() => onChange([])}
        className={`rounded-md px-2 py-1 text-xs transition-colors ${
          searchingAll
            ? "bg-accent-subtle font-medium text-accent"
            : "text-text-muted hover:bg-bg-subtle hover:text-text-base"
        }`}
      >
        All
      </button>
      {environments.map((environment) => {
        const on = selected.includes(environment.id);
        return (
          <button
            key={environment.id}
            type="button"
            aria-pressed={on}
            onClick={() =>
              onChange(
                on
                  ? selected.filter((id) => id !== environment.id)
                  : [...selected, environment.id],
              )
            }
            className={`rounded-md px-2 py-1 text-xs transition-colors ${
              on
                ? "bg-accent-subtle font-medium text-accent"
                : "text-text-muted hover:bg-bg-subtle hover:text-text-base"
            }`}
          >
            {environment.name}
          </button>
        );
      })}
      <span className="text-[11px] text-text-faint">
        {searchingAll
          ? "Searching every environment you can see. Each result says which one it is in."
          : `Searching ${selected.length} of ${environments.length}.`}
      </span>
    </div>
  );
}
