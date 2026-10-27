import { useState } from "react";
import type { TribeDetail, TribeSummary } from "@sbom/shared";
import { formatNumber } from "../../lib/format.ts";
import { useDeleteTribe, useSetTribeApplications, useSetTribeSquads } from "../../lib/mutations.ts";
import { useEnvironments, useGrantableScope, useSquads, useTribe, useTribes } from "../../lib/queries.ts";
import { useDebounced } from "../../lib/useDebounced.ts";
import { TeamChecklist, TribeFormModal } from "../../components/TeamForms.tsx";
import { ApplicationPicker } from "./UserAccessPickers.tsx";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  ConfirmDeleteModal,
  EmptyState,
  ErrorBanner,
  FormError,
  LoadingBlock,
  Modal,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";

/**
 * Tribes: the level above squads. Tribe -> squad -> user.
 *
 * A tribe has no members of its own. Its people are the members of its squads, and a squad can
 * sit under several tribes. Projects assigned to a tribe directly are visible to every member of
 * every squad under it, on top of what their squads reach, and show the tribe in their "Tribe"
 * attribute.
 */
export function AdminTribesPage() {
  const tribes = useTribes();
  const [editing, setEditing] = useState<TribeSummary | "new" | null>(null);
  const [managing, setManaging] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<TribeSummary | null>(null);
  const remove = useDeleteTribe();
  const [search, setSearch] = useState("");

  const all = tribes.data?.tribes ?? [];
  const needle = search.trim().toLowerCase();
  const list = needle === "" ? all : all.filter((t) => t.name.toLowerCase().includes(needle));

  return (
    <>
      <Card>
        <CardHeader
          title="Tribes"
          subtitle="Groups of squads. Projects assigned to a tribe are visible to everyone in its squads, and show the tribe in their Tribe attribute."
          actions={
            <Button variant="primary" size="sm" onClick={() => setEditing("new")}>
              New tribe
            </Button>
          }
        />

        <div className="border-b border-border-base px-4 py-3">
          <div className="w-full max-w-xs">
            <TextInput value={search} onChange={setSearch} placeholder="Search tribes by name…" ariaLabel="Search tribes" />
          </div>
        </div>

        {tribes.isLoading ? (
          <LoadingBlock label="Loading tribes" />
        ) : tribes.error ? (
          <div className="p-4">
            <ErrorBanner error={tribes.error} onRetry={() => void tribes.refetch()} />
          </div>
        ) : all.length === 0 ? (
          <EmptyState
            title="No tribes yet"
            hint="Create one per tribe in the organisation, put its squads under it, and assign the projects that belong to the tribe as a whole."
          />
        ) : list.length === 0 ? (
          <EmptyState title="No tribe matches that search" hint={`Nothing is named like "${search.trim()}".`} />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Tribe</Th>
                  <Th>Email</Th>
                  <Th align="right">Squads</Th>
                  <Th align="right">People</Th>
                  <Th align="right">Projects</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {list.map((tribe) => (
                  <Tr key={tribe.id}>
                    <Td>
                      <span className="font-medium text-text-base">{tribe.name}</span>
                      {tribe.description ? (
                        <div className="text-xs text-text-muted">{tribe.description}</div>
                      ) : null}
                    </Td>
                    <Td>{tribe.email ?? <span className="text-text-faint">-</span>}</Td>
                    <Td align="right" className="nums">
                      {tribe.squadCount === 0 ? (
                        <Badge tone="warn" title="No squads, so nobody sees this tribe's projects yet.">
                          0
                        </Badge>
                      ) : (
                        formatNumber(tribe.squadCount)
                      )}
                    </Td>
                    <Td align="right" className="nums">
                      {formatNumber(tribe.memberCount)}
                    </Td>
                    <Td align="right" className="nums">
                      {formatNumber(tribe.applicationCount)}
                    </Td>
                    <Td align="right">
                      <div className="flex flex-wrap justify-end gap-1.5">
                        <Button size="sm" variant="primary" onClick={() => setManaging(tribe.id)}>
                          Squads & projects
                        </Button>
                        <Button size="sm" onClick={() => setEditing(tribe)}>
                          Edit
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            remove.reset();
                            setDeleteTarget(tribe);
                          }}
                        >
                          Delete
                        </Button>
                      </div>
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>

      <TribeFormModal
        key={editing === "new" ? "new" : (editing?.id ?? "none")}
        target={editing}
        onClose={() => setEditing(null)}
        onSaved={(tribe, created) => {
          if (created) setManaging(tribe.id);
        }}
      />

      {managing ? <ManageTribeModal tribeId={managing} onClose={() => setManaging(null)} /> : null}

      <ConfirmDeleteModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        confirmWord={deleteTarget?.name ?? ""}
        title="Delete tribe"
        busy={remove.isPending}
        onConfirm={() => {
          if (!deleteTarget) return;
          remove.mutate(deleteTarget.id, { onSuccess: () => setDeleteTarget(null) });
        }}
      >
        <FormError error={remove.error} />
        <p>
          Deletes <strong className="text-text-base">{deleteTarget?.name}</strong>. Its{" "}
          {deleteTarget?.squadCount ?? 0} squads stay as they are. Their members lose only the{" "}
          {deleteTarget?.applicationCount ?? 0} projects assigned to this tribe, and those projects
          lose it from their Tribe attribute.
        </p>
      </ConfirmDeleteModal>
    </>
  );
}

// ---------------------------------------------------------------------------

/** The tribe's squads, and the projects assigned to it. Two tabs, saved separately. */
function ManageTribeModal({ tribeId, onClose }: { tribeId: string; onClose: () => void }) {
  const tribe = useTribe(tribeId);
  const [tab, setTab] = useState<"squads" | "projects">("squads");
  const detail = tribe.data?.tribe ?? null;

  return (
    <Modal open onClose={onClose} wide title={detail ? `${detail.name}: squads and projects` : "Tribe"}>
      {tribe.isLoading || !detail ? (
        tribe.error ? <ErrorBanner error={tribe.error} /> : <LoadingBlock label="Loading tribe" />
      ) : (
        <div className="space-y-3 text-sm">
          <div role="tablist" aria-label="Tribe settings" className="flex gap-1 rounded-md bg-bg-subtle p-1">
            {(
              [
                ["squads", `Squads (${detail.squadCount})`],
                ["projects", `Projects (${detail.applicationCount})`],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={tab === id}
                onClick={() => setTab(id)}
                className={`flex-1 rounded px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  tab === id ? "bg-bg-raised text-text-base shadow-sm" : "text-text-muted hover:text-text-base"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          {tab === "squads" ? (
            <SquadsEditor key={detail.updatedAt + detail.squadCount} tribe={detail} onDone={onClose} />
          ) : (
            <ProjectsEditor key={detail.updatedAt + detail.applicationCount} tribe={detail} onDone={onClose} />
          )}
        </div>
      )}
    </Modal>
  );
}

const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));

function SquadsEditor({ tribe, onDone }: { tribe: TribeDetail; onDone: () => void }) {
  const save = useSetTribeSquads();
  const squads = useSquads();
  const [selected, setSelected] = useState<string[]>(tribe.squads.map((s) => s.id));
  const dirty = !sameSet(selected, tribe.squads.map((s) => s.id));

  return (
    <div className="space-y-2">
      <FormError error={save.error} />
      <p className="text-[11px] text-text-muted">
        Everyone on a ticked squad sees this tribe's projects. A squad can be under several tribes.
      </p>
      <TeamChecklist
        items={squads.data?.squads ?? []}
        selected={selected}
        onChange={setSelected}
        noun="squad"
        loading={squads.isLoading}
      />
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] text-text-faint">
          {selected.length} {selected.length === 1 ? "squad" : "squads"} selected
        </span>
        <div className="flex gap-2">
          <Button onClick={onDone} disabled={save.isPending}>
            Close
          </Button>
          <Button
            variant="primary"
            disabled={!dirty || save.isPending}
            onClick={() => save.mutate({ id: tribe.id, squadIds: selected })}
          >
            {save.isPending ? "Saving…" : "Save squads"}
          </Button>
        </div>
      </div>
    </div>
  );
}

function ProjectsEditor({ tribe, onDone }: { tribe: TribeDetail; onDone: () => void }) {
  const save = useSetTribeApplications();
  const environments = useEnvironments();
  // Every estate: a tribe is platform-wide, like a squad.
  const environmentIds = (environments.data?.environments ?? []).map((e) => e.id);
  const [search, setSearch] = useState("");
  const debounced = useDebounced(search, 250);
  const grantable = useGrantableScope(environmentIds, debounced);
  const [appIds, setAppIds] = useState<string[]>(tribe.applications.map((a) => a.id));
  const dirty = !sameSet(appIds, tribe.applications.map((a) => a.id));

  return (
    <div className="space-y-2">
      <FormError error={save.error} />
      {grantable.error ? (
        <ErrorBanner error={grantable.error} />
      ) : (
        <ApplicationPicker
          applications={grantable.applications}
          selected={appIds}
          onToggle={(id, on) => setAppIds(on ? [...appIds, id] : appIds.filter((x) => x !== id))}
          search={search}
          onSearch={setSearch}
          loading={grantable.isLoading}
          truncated={grantable.truncated}
          searching={grantable.searching}
        />
      )}
      {tribe.applications.length > 0 ? (
        <p className="text-[11px] text-text-faint">
          Currently assigned: {tribe.applications.map((a) => `${a.name} (${a.environmentName})`).join(", ")}.
        </p>
      ) : null}
      <div className="flex items-center justify-end gap-2">
        <Button onClick={onDone} disabled={save.isPending}>
          Close
        </Button>
        <Button
          variant="primary"
          disabled={!dirty || save.isPending}
          onClick={() => save.mutate({ id: tribe.id, applicationIds: appIds })}
        >
          {save.isPending ? "Saving…" : "Save projects"}
        </Button>
      </div>
    </div>
  );
}
