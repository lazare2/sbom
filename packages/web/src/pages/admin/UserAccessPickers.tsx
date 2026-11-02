import { useMemo, useState } from "react";
import type {
  ApplicationAccessPreview,
  ApplicationGroupSummary,
  ApplicationSummary,
  SquadSummary,
} from "@sbom/shared";
import { formatNumber } from "../../lib/format.ts";
import { Badge, Checkbox, ErrorBanner, LoadingBlock, TextInput } from "../../components/ui.tsx";

/**
 * The three panels the access dialog is built from.
 *
 * Lifted out of AdminUsersPage because that file had grown past fifteen hundred lines and
 * these are the parts most likely to be read on their own - the question "why does this
 * person see that application" is answered by the last of them.
 */

/**
 * One searchable, scrollable list of applications to grant.
 *
 * The search term goes to the server (see `useGrantableScope`), so it searches the estate
 * rather than the page of it already fetched. That matters more than it looks: the list is
 * capped, and a browser-side filter would fail to find an application exactly when there are
 * enough of them to need searching.
 */
export function ApplicationPicker({
  applications,
  selected,
  onToggle,
  search,
  onSearch,
  loading,
  truncated,
  searching,
}: {
  applications: ApplicationSummary[];
  selected: string[];
  onToggle: (id: string, on: boolean) => void;
  search: string;
  onSearch: (value: string) => void;
  loading: boolean;
  truncated: boolean;
  searching: boolean;
}) {
  /*
    Already-selected first, ordered against the list as fetched rather than against the live
    selection. Sorting on the live selection would move a row to the top the instant it was
    ticked, so the next click would land on whatever slid into its place.
  */
  const ordered = useMemo(() => {
    const chosen = new Set(selected);
    return [...applications].sort((a, b) => {
      const am = chosen.has(a.id) ? 0 : 1;
      const bm = chosen.has(b.id) ? 0 : 1;
      if (am !== bm) return am - bm;
      return a.name.localeCompare(b.name);
    });
    // Deliberately not keyed on `selected`; see above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applications]);

  return (
    <div className="space-y-1.5">
      <TextInput
        value={search}
        onChange={onSearch}
        placeholder="Search applications by name…"
        ariaLabel="Search applications"
      />

      <div className="max-h-[42vh] min-h-[8rem] overflow-y-auto rounded-md border border-border-base p-2">
        {loading && ordered.length === 0 ? (
          <LoadingBlock label="Loading applications" />
        ) : ordered.length === 0 ? (
          <p className="p-2 text-[11px] text-text-faint">
            {searching
              ? "No application in the selected environments matches that name."
              : "No applications in the selected environments."}
          </p>
        ) : (
          <div className="flex flex-col gap-1">
            {ordered.map((application) => (
              <Checkbox
                key={application.id}
                checked={selected.includes(application.id)}
                onChange={(on) => onToggle(application.id, on)}
                label={application.name}
              />
            ))}
          </div>
        )}
      </div>

      {/*
        Stated rather than silently trimmed. A list that stops at the cap without saying so
        lets an administrator conclude an application does not exist because they could not
        find it - which is also why the search is served rather than filtered here.
      */}
      {truncated ? (
        <p className="text-[11px] text-warn">
          More applications exist than are listed. Search by name to find a specific one, or
          grant a group instead.
        </p>
      ) : null}

      <p className="text-[11px] text-text-faint">
        For a service that is in no group - which is how every application starts, since CI
        registers it before anyone files it.
      </p>
    </div>
  );
}

/**
 * The same, for groups.
 *
 * A list rather than the wrapped row of checkboxes this replaced. Every squad gets a group, so
 * this is the axis that grows without bound, and a flex-wrap of fifty boxes is unreadable long
 * before the estate is fully filed. Filtered in the browser, because unlike applications the
 * group list is fetched whole.
 */
export function GroupPicker({
  groups,
  selected,
  onToggle,
  search,
  onSearch,
  loading,
}: {
  groups: ApplicationGroupSummary[];
  selected: string[];
  onToggle: (id: string, on: boolean) => void;
  search: string;
  onSearch: (value: string) => void;
  loading: boolean;
}) {
  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const chosen = new Set(selected);
    return [...groups]
      .filter((group) => needle === "" || group.name.toLowerCase().includes(needle))
      .sort((a, b) => {
        const am = chosen.has(a.id) ? 0 : 1;
        const bm = chosen.has(b.id) ? 0 : 1;
        if (am !== bm) return am - bm;
        return a.name.localeCompare(b.name);
      });
    // Same reasoning as above: ordering is not keyed on the live selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups, search]);

  return (
    <div className="space-y-1.5">
      <TextInput
        value={search}
        onChange={onSearch}
        placeholder="Search groups by name…"
        ariaLabel="Search groups"
      />

      <div className="max-h-[42vh] min-h-[8rem] overflow-y-auto rounded-md border border-border-base p-2">
        {loading && visible.length === 0 ? (
          <LoadingBlock label="Loading groups" />
        ) : visible.length === 0 ? (
          <p className="p-2 text-[11px] text-text-faint">
            {groups.length === 0
              ? "No groups exist in the selected environments yet."
              : "No group matches that name."}
          </p>
        ) : (
          <div className="flex flex-col gap-1">
            {visible.map((group) => (
              <Checkbox
                key={group.id}
                checked={selected.includes(group.id)}
                onChange={(on) => onToggle(group.id, on)}
                /*
                  The member count is the difference between granting something and granting
                  nothing, and an empty group looks identical to a full one without it.
                */
                label={`${group.name} (${group.applicationCount})`}
              />
            ))}
          </div>
        )}
      </div>

      <p className="text-[11px] text-text-faint">
        A group grant follows the group: applications added to it later become visible without
        anyone revisiting this screen.
      </p>
    </div>
  );
}

/**
 * The squads an account is on, as a searchable list.
 *
 * Replaces a wrapped row of checkboxes that became unreadable past a dozen squads: names ran
 * into each other, nothing said which tribe a squad belonged to, and finding one meant
 * scanning the whole block. Now each squad is one row with its tribes and what it brings, the
 * search matches tribe names as well as squad names, and the current selection is listed above
 * the list as removable chips so it stays visible while the list is filtered to something else.
 *
 * Filtered in the browser: the squad list is fetched whole, like groups.
 */
export function SquadPicker({
  squads,
  selected,
  onChange,
  loading,
}: {
  squads: SquadSummary[];
  selected: string[];
  onChange: (ids: string[]) => void;
  loading: boolean;
}) {
  const [search, setSearch] = useState("");
  const [selectedOnly, setSelectedOnly] = useState(false);
  const chosen = new Set(selected);

  /*
    Selected first, ordered against the selection the list loaded with rather than the live
    one - the same reason as the application picker: re-sorting on every tick would move the
    row under the pointer and the next click would land on a different squad.
  */
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const initial = useMemo(() => new Set(selected), [squads]);
  const ordered = useMemo(
    () =>
      [...squads].sort((a, b) => {
        const am = initial.has(a.id) ? 0 : 1;
        const bm = initial.has(b.id) ? 0 : 1;
        if (am !== bm) return am - bm;
        return a.name.localeCompare(b.name);
      }),
    [squads, initial],
  );

  const needle = search.trim().toLowerCase();
  const visible = ordered.filter(
    (squad) =>
      (!selectedOnly || chosen.has(squad.id)) &&
      (needle === "" ||
        squad.name.toLowerCase().includes(needle) ||
        squad.tribes.some((t) => t.name.toLowerCase().includes(needle))),
  );
  const selectedSquads = squads.filter((s) => chosen.has(s.id)).sort((a, b) => a.name.localeCompare(b.name));

  const toggle = (id: string, on: boolean) =>
    onChange(on ? [...selected.filter((x) => x !== id), id] : selected.filter((x) => x !== id));
  const visibleIds = visible.map((s) => s.id);
  const allVisibleChosen = visibleIds.length > 0 && visibleIds.every((id) => chosen.has(id));

  if (!loading && squads.length === 0) {
    return (
      <p className="text-[11px] text-text-faint">
        No squads exist yet. Create them under Administration → Squads to grant a team its
        applications in one place.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-[220px] flex-1">
          <TextInput
            value={search}
            onChange={setSearch}
            placeholder="Search squads or tribes…"
            ariaLabel="Search squads or tribes"
          />
        </div>
        <Checkbox checked={selectedOnly} onChange={setSelectedOnly} label="Selected only" />
      </div>

      <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
        <span className="text-text-muted">
          {selectedSquads.length === 0
            ? "Not on any squad."
            : `On ${selectedSquads.length} squad${selectedSquads.length === 1 ? "" : "s"}:`}
        </span>
        {selectedSquads.map((squad) => (
          <span
            key={squad.id}
            className="inline-flex items-center gap-0.5 rounded bg-info-subtle py-0.5 pr-0.5 pl-1.5 font-medium text-info"
          >
            {squad.name}
            <button
              type="button"
              onClick={() => toggle(squad.id, false)}
              aria-label={`Remove from ${squad.name}`}
              title={`Remove from ${squad.name}`}
              className="rounded px-1 leading-none hover:bg-info hover:text-white"
            >
              ×
            </button>
          </span>
        ))}
        {selectedSquads.length > 1 ? (
          <button type="button" onClick={() => onChange([])} className="text-text-muted underline hover:text-text-base">
            Clear all
          </button>
        ) : null}
      </div>

      <div className="overflow-hidden rounded-md border border-border-base">
        <div className="flex items-center justify-between gap-2 border-b border-border-base bg-bg-subtle px-3 py-1.5 text-[11px] text-text-muted">
          <span>
            {visible.length === squads.length
              ? `${squads.length} squad${squads.length === 1 ? "" : "s"}`
              : `${visible.length} of ${squads.length} squads`}
          </span>
          {visible.length > 0 ? (
            <button
              type="button"
              className="text-accent hover:underline"
              onClick={() =>
                onChange(
                  allVisibleChosen
                    ? selected.filter((id) => !visibleIds.includes(id))
                    : [...new Set([...selected, ...visibleIds])],
                )
              }
            >
              {allVisibleChosen ? "Deselect shown" : "Select shown"}
            </button>
          ) : null}
        </div>
        <ul className="max-h-[38vh] min-h-[6rem] divide-y divide-border-base overflow-y-auto" aria-label="Squads">
          {loading && squads.length === 0 ? (
            <li>
              <LoadingBlock label="Loading squads" />
            </li>
          ) : visible.length === 0 ? (
            <li className="px-3 py-3 text-[11px] text-text-faint">
              {selectedOnly && selected.length === 0 ? "No squad is selected." : "No squad or tribe matches that search."}
            </li>
          ) : (
            visible.map((squad) => {
              const on = chosen.has(squad.id);
              return (
                <li key={squad.id}>
                  <label
                    className={`flex cursor-pointer items-center gap-3 px-3 py-2 select-none hover:bg-bg-subtle ${
                      on ? "bg-accent-subtle" : ""
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={on}
                      onChange={(e) => toggle(squad.id, e.target.checked)}
                      className="size-3.5 shrink-0 accent-[var(--accent)]"
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-text-base">{squad.name}</span>
                      <span className="block truncate text-[11px] text-text-faint">
                        {squad.tribes.length > 0
                          ? `Tribe${squad.tribes.length === 1 ? "" : "s"}: ${squad.tribes.map((t) => t.name).join(", ")}`
                          : "No tribe"}
                      </span>
                    </span>
                    {/*
                      What ticking it brings. An empty squad looks exactly like a full one without
                      the counts, and the difference is the whole decision.
                    */}
                    <span className="shrink-0 text-right text-[11px] text-text-muted">
                      <span className="nums block">
                        {formatNumber(squad.reachableApplicationCount)} app
                        {squad.reachableApplicationCount === 1 ? "" : "s"}
                      </span>
                      <span className="nums block text-text-faint">
                        {formatNumber(squad.memberCount)} member{squad.memberCount === 1 ? "" : "s"}
                      </span>
                    </span>
                  </label>
                </li>
              );
            })
          )}
        </ul>
      </div>
    </div>
  );
}

/**
 * What the ticked boxes actually come to.
 *
 * The question an administrator opens this dialog to answer is not "which boxes are ticked" -
 * that is visible on the left - but "what will this person see when they sign in". That is the
 * intersection of two axes, drawn partly from groups whose membership changes without anybody
 * opening this screen, so it cannot be read off the checkboxes.
 *
 * Every row carries *why* it is reachable, because that is what decides whether a grant can be
 * removed: dropping a direct grant on an application the account also reaches through a group
 * changes nothing, while removing it from the group takes it from everyone else too.
 */
export function ReachablePanel({
  preview,
  loading,
  isAdmin,
  error,
}: {
  preview: ApplicationAccessPreview | null;
  loading: boolean;
  isAdmin: boolean;
  error?: unknown;
}) {
  if (isAdmin) {
    /*
      Not a list. An administrator reaches every application in every estate by role, so
      listing the estate here would imply these grants produced it, and an empty list would be
      flatly wrong. One sentence is the only honest rendering.
    */
    return (
      <div className="rounded-md border border-dashed border-border-base bg-bg-subtle p-3">
        <h4 className="text-xs font-medium text-text-muted">Will reach</h4>
        <p className="mt-1 text-sm text-text-base">Everything, by role.</p>
        <p className="mt-1 text-[11px] text-text-faint">
          Administrators reach every environment, group and application, including ones created
          later. The choices on the left are stored, and take effect only if this account is
          changed to a read-only user.
        </p>
      </div>
    );
  }

  const rows = preview?.reachable ?? [];
  const total = preview?.reachableApplicationCount ?? 0;

  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between gap-2">
        <h4 className="text-xs font-medium text-text-muted">Will reach</h4>
        {/*
          The server's count, not this list's length. Groups overlap with each other and with
          direct grants, so "two groups and one application" does not say whether three
          services were granted or thirty.
        */}
        <span className="nums text-[11px] text-text-muted">
          {formatNumber(total)} {total === 1 ? "application" : "applications"}
        </span>
      </div>

      <div className="max-h-[42vh] min-h-[8rem] overflow-y-auto rounded-md border border-border-base">
        {error ? (
          <div className="p-2">
            <ErrorBanner error={error} />
          </div>
        ) : loading && rows.length === 0 ? (
          <LoadingBlock label="Scoring access" />
        ) : rows.length === 0 ? (
          <p className="p-3 text-[11px] text-text-faint">
            Nothing yet. Tick a squad, a group or an application and this fills in.
          </p>
        ) : (
          <ul className="divide-y divide-border-base">
            {rows.map((row) => (
              <li key={row.id} className="flex items-start justify-between gap-2 px-2.5 py-1.5">
                <span className="text-xs text-text-base">{row.name}</span>
                <span className="flex shrink-0 flex-wrap justify-end gap-1">
                  {row.direct ? <Badge tone="accent">direct</Badge> : null}
                  {row.viaGroups.map((group) => (
                    <Badge key={group} tone="neutral" title={`Reached through the group ${group}`}>
                      {group}
                    </Badge>
                  ))}
                  {/* A different tone, because the remedy differs: leaving the squad, not
                      unticking anything on this screen. */}
                  {row.viaSquads.map((squad) => (
                    <Badge key={`squad-${squad}`} tone="info" title={`Reached through the squad ${squad}`}>
                      squad: {squad}
                    </Badge>
                  ))}
                  {row.viaTribes.map((tribe) => (
                    <Badge
                      key={`tribe-${tribe}`}
                      tone="info"
                      title={`Assigned to the tribe ${tribe}, which one of this account's squads is under`}
                    >
                      tribe: {tribe}
                    </Badge>
                  ))}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/*
        The list is capped and the count is not, so the two disagreeing is the truncation
        rather than an inconsistency. Saying so is what stops a reader treating the shorter
        list as the whole answer.
      */}
      {rows.length > 0 && total > rows.length ? (
        <p className="text-[11px] text-text-faint">
          Showing the first {formatNumber(rows.length)} of {formatNumber(total)} by name.
        </p>
      ) : null}
    </div>
  );
}
