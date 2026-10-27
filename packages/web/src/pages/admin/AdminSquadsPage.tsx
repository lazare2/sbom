import { useMemo, useState } from "react";
import type { SquadDetail, SquadSummary, UserSummary } from "@sbom/shared";
import { displayName, formatNumber } from "../../lib/format.ts";
import {
  useDeleteSquad,
  useSetSquadAccess,
  useSetSquadMembers,
  useUpdateSquadSettings,
} from "../../lib/mutations.ts";
import {
  useEnvironments,
  useGrantableScope,
  useSquad,
  useSquadSettings,
  useSquads,
  useUsers,
} from "../../lib/queries.ts";
import { useDebounced } from "../../lib/useDebounced.ts";
import { SquadFormModal } from "../../components/TeamForms.tsx";
import { ApplicationPicker, GroupPicker } from "./UserAccessPickers.tsx";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
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
 * Squads: teams of people, granted applications together.
 *
 * The screen for the way access is meant to be given. Rather than ticking the same twelve
 * services on each new colleague's account, the team is granted them once here, and a person
 * reaches them by being on the team. Taking somebody off the squad takes the access away with
 * nothing else to revisit.
 *
 * A member reaches the squad's applications *in addition to* whatever their own account grants,
 * and the estates those applications live in come with them, so a squad owning a production
 * service is enough on its own. It never opens the rest of that estate.
 */
export function AdminSquadsPage() {
  const squads = useSquads();
  const [editing, setEditing] = useState<SquadSummary | "new" | null>(null);
  const [managing, setManaging] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<SquadSummary | null>(null);
  const remove = useDeleteSquad();
  const [search, setSearch] = useState("");

  const all = squads.data?.squads ?? [];
  const needle = search.trim().toLowerCase();
  const list = needle === "" ? all : all.filter((s) => s.name.toLowerCase().includes(needle));

  return (
    <>
      <Card>
        <CardHeader
          title="Squads"
          subtitle="Teams of people granted applications together. Adding someone to a squad gives them everything the squad is granted; removing them takes it away."
          actions={
            <Button variant="primary" size="sm" onClick={() => setEditing("new")}>
              New squad
            </Button>
          }
        />

        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-base px-4 py-3">
          <div className="w-full max-w-xs">
            <TextInput value={search} onChange={setSearch} placeholder="Search squads by name…" ariaLabel="Search squads" />
          </div>
          <RequireTribeSwitch />
        </div>

        {squads.isLoading ? (
          <LoadingBlock label="Loading squads" />
        ) : squads.error ? (
          <div className="p-4">
            <ErrorBanner error={squads.error} onRetry={() => void squads.refetch()} />
          </div>
        ) : all.length === 0 ? (
          <EmptyState
            title="No squads yet"
            hint="Create one per team, grant it the groups and applications the team owns, and add its people. New colleagues then need only to be put on their squad."
          />
        ) : list.length === 0 ? (
          <EmptyState title="No squad matches that search" hint={`Nothing is named like "${search.trim()}".`} />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Squad</Th>
                  <Th>Tribes</Th>
                  <Th>Email</Th>
                  <Th align="right">Members</Th>
                  <Th align="right">Groups</Th>
                  <Th align="right">Applications</Th>
                  {/* The figure that matters; the two counts beside it overlap. */}
                  <Th align="right">Reaches</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {list.map((squad) => (
                  <Tr key={squad.id}>
                    <Td>
                      <span className="font-medium text-text-base">{squad.name}</span>
                      {squad.description ? (
                        <div className="text-xs text-text-muted">{squad.description}</div>
                      ) : null}
                    </Td>
                    <Td>
                      {squad.tribes.length === 0 ? (
                        <span className="text-text-faint">-</span>
                      ) : (
                        <span className="flex flex-wrap gap-1">
                          {squad.tribes.map((t) => (
                            <Badge key={t.id} tone="info">
                              {t.name}
                            </Badge>
                          ))}
                        </span>
                      )}
                    </Td>
                    <Td>
                      {squad.email ?? <span className="text-text-faint">-</span>}
                    </Td>
                    <Td align="right" className="nums">
                      {formatNumber(squad.memberCount)}
                    </Td>
                    <Td align="right" className="nums">
                      {formatNumber(squad.groupCount)}
                    </Td>
                    <Td align="right" className="nums">
                      {formatNumber(squad.applicationCount)}
                    </Td>
                    <Td align="right" className="nums">
                      {squad.reachableApplicationCount === 0 ? (
                        <Badge tone="warn" title="Granted nothing yet, so its members gain nothing from it.">
                          0
                        </Badge>
                      ) : (
                        formatNumber(squad.reachableApplicationCount)
                      )}
                    </Td>
                    <Td align="right">
                      <div className="flex flex-wrap justify-end gap-1.5">
                        <Button size="sm" variant="primary" onClick={() => setManaging(squad.id)}>
                          Members & access
                        </Button>
                        <Button size="sm" onClick={() => setEditing(squad)}>
                          Edit
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            remove.reset();
                            setDeleteTarget(squad);
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

      <SquadFormModal
        key={editing === "new" ? "new" : (editing?.id ?? "none")}
        target={editing}
        onClose={() => setEditing(null)}
        // Straight on to members and access: a new squad with neither does nothing.
        onSaved={(squad, created) => {
          if (created) setManaging(squad.id);
        }}
      />

      {managing ? <ManageSquadModal squadId={managing} onClose={() => setManaging(null)} /> : null}

      <ConfirmDeleteModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        confirmWord={deleteTarget?.name ?? ""}
        title="Delete squad"
        busy={remove.isPending}
        onConfirm={() => {
          if (!deleteTarget) return;
          remove.mutate(deleteTarget.id, { onSuccess: () => setDeleteTarget(null) });
        }}
      >
        <FormError error={remove.error} />
        <p>
          Deletes <strong className="text-text-base">{deleteTarget?.name}</strong>. Its{" "}
          {deleteTarget?.memberCount ?? 0} members keep their accounts and their own grants, but
          lose what this squad gave them immediately.
        </p>
      </ConfirmDeleteModal>
    </>
  );
}

// ---------------------------------------------------------------------------

/**
 * Whether every squad must sit under a tribe. Off by default, so squads can be set up before the
 * tribes are; turning it on applies to new squads and to any squad whose tribes are next edited.
 */
function RequireTribeSwitch() {
  const settings = useSquadSettings();
  const save = useUpdateSquadSettings();
  const on = settings.data?.settings.requireTribe === true;
  return (
    <div className="flex items-center gap-2">
      <Checkbox
        label="Every squad must belong to a tribe"
        checked={on}
        disabled={settings.isLoading || save.isPending}
        onChange={(next) => save.mutate({ requireTribe: next })}
      />
      {save.error ? <span className="text-xs text-danger">Could not save</span> : null}
    </div>
  );
}

// ---------------------------------------------------------------------------

/**
 * Who is on the squad, and what it is granted.
 *
 * Two tabs saved separately, because they are two endpoints and two decisions: moving a person
 * and changing what the team owns are different events in the audit log, and one save button
 * over both would make a partial failure impossible to report.
 */
function ManageSquadModal({ squadId, onClose }: { squadId: string; onClose: () => void }) {
  const squad = useSquad(squadId);
  const [tab, setTab] = useState<"members" | "access">("members");
  const detail = squad.data?.squad ?? null;

  return (
    <Modal open onClose={onClose} wide title={detail ? `${detail.name}: members and access` : "Squad"}>
      {squad.isLoading || !detail ? (
        squad.error ? <ErrorBanner error={squad.error} /> : <LoadingBlock label="Loading squad" />
      ) : (
        <div className="space-y-3 text-sm">
          <div role="tablist" aria-label="Squad settings" className="flex gap-1 rounded-md bg-bg-subtle p-1">
            {(
              [
                ["members", `Members (${detail.memberCount})`],
                [
                  "access",
                  `Access (${detail.reachableApplicationCount} ${detail.reachableApplicationCount === 1 ? "application" : "applications"})`,
                ],
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
          {/* Keyed on the squad's data so a save that comes back resets the editor to it. */}
          {tab === "members" ? (
            <MembersEditor key={detail.updatedAt + detail.memberCount} squad={detail} onDone={onClose} />
          ) : (
            <AccessEditor key={detail.updatedAt + detail.reachableApplicationCount} squad={detail} onDone={onClose} />
          )}
        </div>
      )}
    </Modal>
  );
}

function MembersEditor({ squad, onDone }: { squad: SquadDetail; onDone: () => void }) {
  const save = useSetSquadMembers();
  const [selected, setSelected] = useState<string[]>(squad.members.map((m) => m.id));
  const [search, setSearch] = useState("");
  const debounced = useDebounced(search, 250);
  // Searched on the server, so a colleague beyond the first page is still findable.
  const users = useUsers({ search: debounced || undefined, pageSize: 50, sortBy: "lastName", sortDir: "asc" });

  /*
    The current members are always listed, even when the search would not return them, so
    unticking somebody never depends on first finding them again.
  */
  const rows = useMemo(() => {
    const byId = new Map<string, Pick<UserSummary, "id" | "email" | "firstName" | "lastName" | "role">>();
    for (const m of squad.members) byId.set(m.id, m);
    for (const u of users.data?.items ?? []) byId.set(u.id, u);
    const chosen = new Set(squad.members.map((m) => m.id));
    return [...byId.values()]
      .filter((u) => chosen.has(u.id) || debounced === "" || (users.data?.items ?? []).some((x) => x.id === u.id))
      .sort((a, b) => Number(chosen.has(b.id)) - Number(chosen.has(a.id)));
  }, [squad.members, users.data, debounced]);

  const dirty =
    selected.length !== squad.members.length || selected.some((id) => !squad.members.some((m) => m.id === id));

  return (
    <div className="space-y-2">
      <FormError error={save.error} />
      <TextInput value={search} onChange={setSearch} placeholder="Search people by name or email…" ariaLabel="Search people" />
      <div className="max-h-[45vh] min-h-[10rem] overflow-y-auto rounded-md border border-border-base p-2">
        {users.isLoading && rows.length === 0 ? (
          <LoadingBlock label="Loading people" />
        ) : rows.length === 0 ? (
          <p className="p-2 text-[11px] text-text-faint">Nobody matches that search.</p>
        ) : (
          <div className="flex flex-col gap-1">
            {rows.map((u) => (
              <div key={u.id} className="flex items-center justify-between gap-2">
                <Checkbox
                  checked={selected.includes(u.id)}
                  onChange={(on) =>
                    setSelected(on ? [...selected, u.id] : selected.filter((id) => id !== u.id))
                  }
                  label={displayName(u) ? `${displayName(u)} - ${u.email}` : u.email}
                />
                {u.role === "admin" ? (
                  <Badge tone="accent" title="Administrators already reach everything; membership is recorded for when that changes.">
                    admin
                  </Badge>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] text-text-faint">
          {selected.length} {selected.length === 1 ? "member" : "members"} selected
        </span>
        <div className="flex gap-2">
          <Button onClick={onDone} disabled={save.isPending}>
            Close
          </Button>
          <Button
            variant="primary"
            disabled={!dirty || save.isPending}
            onClick={() => save.mutate({ id: squad.id, userIds: selected })}
          >
            {save.isPending ? "Saving…" : "Save members"}
          </Button>
        </div>
      </div>
    </div>
  );
}

function AccessEditor({ squad, onDone }: { squad: SquadDetail; onDone: () => void }) {
  const save = useSetSquadAccess();
  const environments = useEnvironments();
  // Every estate: a squad is platform-wide, and may own services in test and production.
  const environmentIds = (environments.data?.environments ?? []).map((e) => e.id);
  const [appSearch, setAppSearch] = useState("");
  const [groupSearch, setGroupSearch] = useState("");
  const debouncedAppSearch = useDebounced(appSearch, 250);
  const grantable = useGrantableScope(environmentIds, debouncedAppSearch);
  const [tab, setTab] = useState<"groups" | "applications">("groups");
  const [groupIds, setGroupIds] = useState<string[]>(squad.groups.map((g) => g.id));
  const [appIds, setAppIds] = useState<string[]>(squad.applications.map((a) => a.id));

  const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));
  const dirty =
    !sameSet(groupIds, squad.groups.map((g) => g.id)) ||
    !sameSet(appIds, squad.applications.map((a) => a.id));

  return (
    <div className="space-y-2">
      <FormError error={save.error} />
      <div role="tablist" aria-label="What to grant" className="flex gap-1 rounded-md bg-bg-subtle p-1">
        {(
          [
            ["groups", `Groups (${groupIds.length})`],
            ["applications", `Individual applications (${appIds.length})`],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={`flex-1 rounded px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
              tab === id ? "bg-bg-raised text-text-base shadow-sm" : "text-text-muted hover:text-text-base"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {grantable.error ? (
        <ErrorBanner error={grantable.error} />
      ) : tab === "groups" ? (
        <GroupPicker
          groups={grantable.groups}
          selected={groupIds}
          onToggle={(id, on) => setGroupIds(on ? [...groupIds, id] : groupIds.filter((x) => x !== id))}
          search={groupSearch}
          onSearch={setGroupSearch}
          loading={grantable.isLoading}
        />
      ) : (
        <ApplicationPicker
          applications={grantable.applications}
          selected={appIds}
          onToggle={(id, on) => setAppIds(on ? [...appIds, id] : appIds.filter((x) => x !== id))}
          search={appSearch}
          onSearch={setAppSearch}
          loading={grantable.isLoading}
          truncated={grantable.truncated}
          searching={grantable.searching}
        />
      )}

      {squad.groups.length + squad.applications.length > 0 ? (
        <p className="text-[11px] text-text-faint">
          Currently granted:{" "}
          {[...squad.groups.map((g) => `${g.name} (group, ${g.environmentName})`), ...squad.applications.map((a) => `${a.name} (${a.environmentName})`)].join(", ")}
          .
        </p>
      ) : null}

      <div className="flex items-center justify-end gap-2">
        <Button onClick={onDone} disabled={save.isPending}>
          Close
        </Button>
        <Button
          variant="primary"
          disabled={!dirty || save.isPending}
          onClick={() => save.mutate({ id: squad.id, body: { groupIds, applicationIds: appIds } })}
        >
          {save.isPending ? "Saving…" : "Save access"}
        </Button>
      </div>
    </div>
  );
}
