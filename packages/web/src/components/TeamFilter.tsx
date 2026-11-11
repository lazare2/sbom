import type { TeamFilter } from "@sbom/shared";
import { useAttributeValues, useGroups } from "../lib/queries.ts";
import { readStringList } from "../lib/useUrlState.ts";
import { Button } from "./ui.tsx";
import { MultiSelect } from "./MultiSelect.tsx";

/**
 * Narrowing an estate-level page to some squads, tribes or groups.
 *
 * Shared by Inventory and Analytics so the same link parameters mean the same thing on both,
 * and match the advisory list's: `squad`, `tribe` and `group`, by name, repeatable.
 */

export const TEAM_FILTER_URL_DEFAULTS: TeamFilter = { squad: [], tribe: [], group: [] };

export function readTeamFilterParams(params: URLSearchParams): TeamFilter {
  return {
    squad: readStringList(params, "squad"),
    tribe: readStringList(params, "tribe"),
    group: readStringList(params, "group"),
  };
}

/** The filter as query parameters; empty kinds are omitted so the URL stays short. */
export function teamFilterQuery(filter: TeamFilter): Record<string, string[] | undefined> {
  return {
    squad: filter.squad.length > 0 ? filter.squad : undefined,
    tribe: filter.tribe.length > 0 ? filter.tribe : undefined,
    group: filter.group.length > 0 ? filter.group : undefined,
  };
}

/** Attribute values can hold several names, comma-separated; offer each name once. */
function names(values: string[] | undefined): string[] {
  return [...new Set((values ?? []).flatMap((v) => v.split(",").map((s) => s.trim())).filter(Boolean))].sort(
    (a, b) => a.localeCompare(b),
  );
}

export function TeamFilterBar({
  filter,
  onChange,
}: {
  filter: TeamFilter;
  onChange: (next: TeamFilter) => void;
}) {
  // Offered from what the reader can see in this estate, so no option leads to an empty page
  // for a reason the reader cannot discover.
  const squads = useAttributeValues("squad");
  const tribes = useAttributeValues("tribe");
  const groups = useGroups({ pageSize: 200 });
  const active = filter.squad.length + filter.tribe.length + filter.group.length > 0;

  return (
    <div className="flex flex-wrap items-end gap-3">
      <div className="w-48">
        <span className="mb-1 block text-[11px] font-medium text-text-muted">Squad</span>
        <MultiSelect
          label="Squads"
          options={names(squads.data)}
          selected={filter.squad}
          onChange={(squad) => onChange({ ...filter, squad })}
        />
      </div>
      <div className="w-48">
        <span className="mb-1 block text-[11px] font-medium text-text-muted">Tribe</span>
        <MultiSelect
          label="Tribes"
          options={names(tribes.data)}
          selected={filter.tribe}
          onChange={(tribe) => onChange({ ...filter, tribe })}
        />
      </div>
      <div className="w-48">
        <span className="mb-1 block text-[11px] font-medium text-text-muted">Group</span>
        <MultiSelect
          label="Groups"
          options={(groups.data?.items ?? []).map((g) => g.name).sort((a, b) => a.localeCompare(b))}
          selected={filter.group}
          onChange={(group) => onChange({ ...filter, group })}
        />
      </div>
      {active ? (
        <Button size="sm" variant="ghost" onClick={() => onChange(TEAM_FILTER_URL_DEFAULTS)}>
          Clear
        </Button>
      ) : null}
    </div>
  );
}

/** States what a filtered page describes, above the figures it qualifies. */
export function TeamFilterBanner({ label }: { label: string | null }) {
  if (!label) return null;
  return (
    <div role="note" className="mb-4 rounded-lg border border-accent bg-accent-subtle px-4 py-2 text-xs text-accent">
      Showing only applications in {label}. Every figure on this page describes that subset of what you can see.
    </div>
  );
}
