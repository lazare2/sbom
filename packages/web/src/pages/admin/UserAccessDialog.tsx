import { useMemo, useState } from "react";
import type { UserSummary } from "@sbom/shared";
import { Badge, Button, Checkbox, ErrorBanner, FormError, LoadingBlock, Modal, TextInput } from "../../components/ui.tsx";
import { formatNumber } from "../../lib/format.ts";
import {
  useSetSquadLead,
  useSetUserApplicationAccess,
  useSetUserEnvironments,
  useSetUserSquads,
} from "../../lib/mutations.ts";
import {
  useApplicationAccessPreview,
  useEnvironments,
  useGrantableScope,
  useSquads,
  useUserApplicationAccess,
  useUserEnvironments,
  useUserSquads,
} from "../../lib/queries.ts";
import { useDebounced } from "../../lib/useDebounced.ts";
import { ApplicationPicker, GroupPicker, SquadPicker } from "./UserAccessPickers.tsx";

type Tab = "squads" | "projects" | "groups" | "reach";

const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((x) => b.includes(x));
const changes = (a: readonly string[], b: readonly string[]) =>
  a.filter((x) => !b.includes(x)).length + b.filter((x) => !a.includes(x)).length;

/**
 * Giving one person access, in tabs.
 *
 * What decides the meaning of everything else - the environments, and "all projects" versus
 * "only what I grant" - stays at the top, always in view. Below, one tab per way of granting
 * (squads, projects, groups), each with its own search and a count in its name, and a last tab
 * with the full list of what the person will reach, scored live from the boxes as they stand
 * and searchable, with how each project is reached and what saving would take away.
 *
 * Same rules and the same saves as before: environments first, then the grants, then squads,
 * then any team-lead changes - every one of them audited by the server as it was.
 */
export function UserAccessDialog({ target, onClose }: { target: UserSummary | null; onClose: () => void }) {
  const environments = useEnvironments();
  const grantedEnvironments = useUserEnvironments(target?.id ?? null);
  const access = useUserApplicationAccess(target?.id ?? null);
  const squads = useSquads();
  const userSquads = useUserSquads(target?.id ?? null);
  const saveEnvironments = useSetUserEnvironments();
  const saveAccess = useSetUserApplicationAccess();
  const saveSquads = useSetUserSquads();
  const saveLead = useSetSquadLead();

  const [tab, setTab] = useState<Tab>("squads");
  const [envIds, setEnvIds] = useState<string[] | null>(null);
  const [restricted, setRestricted] = useState<boolean | null>(null);
  const [groupIds, setGroupIds] = useState<string[] | null>(null);
  const [appIds, setAppIds] = useState<string[] | null>(null);
  const [squadIds, setSquadIds] = useState<string[] | null>(null);
  const [leadIds, setLeadIds] = useState<string[] | null>(null);
  const [appSearch, setAppSearch] = useState("");
  const [groupSearch, setGroupSearch] = useState("");
  const debouncedAppSearch = useDebounced(appSearch, 250);

  // Saved state, and the boxes as they stand (saved state until something is touched).
  const savedEnvs = grantedEnvironments.data?.environmentIds ?? [];
  const savedRestricted = access.data?.restricted ?? false;
  const savedGroups = access.data?.groupIds ?? [];
  const savedApps = access.data?.applicationIds ?? [];
  const savedSquads = userSquads.data?.squads.map((s) => s.id) ?? [];
  const savedLeads = userSquads.data?.squads.filter((s) => s.isLead).map((s) => s.id) ?? [];
  const currentEnvs = envIds ?? savedEnvs;
  const currentRestricted = restricted ?? savedRestricted;
  const currentGroups = groupIds ?? savedGroups;
  const currentApps = appIds ?? savedApps;
  const currentSquads = squadIds ?? savedSquads;
  // A lead mark only means something on a squad the person is on.
  const currentLeads = (leadIds ?? savedLeads).filter((id) => currentSquads.includes(id));

  const grantable = useGrantableScope(currentEnvs, debouncedAppSearch);
  const allEnvironments = environments.data?.environments ?? [];
  const isAdmin = target?.role === "admin";
  const loading = grantedEnvironments.isLoading || access.isLoading || userSquads.isLoading;
  const saving = saveEnvironments.isPending || saveAccess.isPending || saveSquads.isPending || saveLead.isPending;

  const unsaved =
    changes(currentEnvs, savedEnvs) +
    (currentRestricted !== savedRestricted ? 1 : 0) +
    changes(currentGroups, savedGroups) +
    changes(currentApps, savedApps) +
    changes(currentSquads, savedSquads) +
    changes(currentLeads, savedLeads.filter((id) => currentSquads.includes(id)));

  // What the boxes reach now, and what the saved grants reach: the difference is what saving takes away.
  const preview = useApplicationAccessPreview(
    target?.id ?? null,
    {
      restricted: currentRestricted,
      groupIds: currentGroups,
      applicationIds: currentApps,
      environmentIds: currentEnvs,
      squadIds: currentSquads,
    },
    !loading,
  );
  const savedPreview = useApplicationAccessPreview(
    target?.id ?? null,
    {
      restricted: savedRestricted,
      groupIds: savedGroups,
      applicationIds: savedApps,
      environmentIds: savedEnvs,
      squadIds: savedSquads,
    },
    !loading && unsaved > 0,
  );
  const reachNow = preview.data?.reachableApplicationCount ?? 0;
  const lost = useMemo(() => {
    if (unsaved === 0 || !preview.data || !savedPreview.data) return [];
    const now = new Set(preview.data.reachable.map((r) => r.id));
    return savedPreview.data.reachable.filter((r) => !now.has(r.id)).map((r) => r.name);
  }, [unsaved, preview.data, savedPreview.data]);

  const blocked = preview.data?.blockedByEnvironment ?? [];
  const blockedTotal = blocked.reduce((sum, gap) => sum + gap.applicationCount, 0);

  const toggle = (list: string[], id: string, on: boolean) => (on ? [...list, id] : list.filter((x) => x !== id));

  function reset() {
    setEnvIds(null);
    setRestricted(null);
    setGroupIds(null);
    setAppIds(null);
    setSquadIds(null);
    setLeadIds(null);
    setAppSearch("");
    setGroupSearch("");
    setTab("squads");
    saveEnvironments.reset();
    saveAccess.reset();
    saveSquads.reset();
    saveLead.reset();
  }

  function close() {
    if (unsaved > 0 && !saving && !window.confirm(`Close without saving ${unsaved} ${unsaved === 1 ? "change" : "changes"}?`)) return;
    reset();
    onClose();
  }

  /*
    Saved in this order, as before: environments first, so a group grant landing next is checked
    against the estates the account will have; then the grants; then squads; then lead marks,
    which need the memberships to exist.
  */
  async function save() {
    if (!target) return;
    if (!sameSet(currentEnvs, savedEnvs)) await saveEnvironments.mutateAsync({ id: target.id, environmentIds: currentEnvs });
    if (currentRestricted !== savedRestricted || !sameSet(currentGroups, savedGroups) || !sameSet(currentApps, savedApps)) {
      await saveAccess.mutateAsync({
        id: target.id,
        body: { restricted: currentRestricted, groupIds: currentGroups, applicationIds: currentApps },
      });
    }
    if (!sameSet(currentSquads, savedSquads)) await saveSquads.mutateAsync({ id: target.id, squadIds: currentSquads });
    for (const squadId of currentSquads) {
      const was = savedLeads.includes(squadId);
      const is = currentLeads.includes(squadId);
      if (was !== is) await saveLead.mutateAsync({ id: squadId, userId: target.id, isLead: is });
    }
    reset();
    onClose();
  }

  const tabs: Array<[Tab, string]> = [
    ["squads", `Squads (${currentSquads.length})`],
    ["projects", `Projects (${currentApps.length})`],
    ["groups", `Groups (${currentGroups.length})`],
    ["reach", isAdmin ? "Has access to (everything)" : `Has access to (${preview.data ? formatNumber(reachNow) : "…"})`],
  ];

  return (
    <Modal
      open={target !== null}
      onClose={close}
      wide
      title={target ? `Access for ${target.email}` : "Access"}
      footer={
        <>
          <span className="mr-auto text-xs text-text-muted">
            {unsaved > 0 ? (
              <Badge tone="warn">
                {unsaved} unsaved {unsaved === 1 ? "change" : "changes"}
              </Badge>
            ) : (
              "No changes"
            )}
          </span>
          <Button onClick={close} disabled={saving}>
            Cancel
          </Button>
          <Button variant="primary" disabled={unsaved === 0 || saving} onClick={() => void save()}>
            {saving ? "Saving…" : "Save access"}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm">
        <FormError error={saveEnvironments.error ?? saveAccess.error ?? saveSquads.error ?? saveLead.error} />
        {loading ? (
          <LoadingBlock label="Loading access" />
        ) : (
          <>
            {isAdmin ? (
              <div className="rounded-md border border-accent/40 bg-accent-subtle p-2.5 text-[11px] text-accent">
                This is an administrator, and administrators reach every environment, group and project - including ones
                created later. The choices below are stored and take effect only if the account becomes a read-only user.
              </div>
            ) : null}

            {/* Always in view: these decide what every tab below means. */}
            <section className="grid gap-3 rounded-md border border-border-base bg-bg-subtle p-3 sm:grid-cols-2">
              <div>
                <h3 className="mb-1.5 text-xs font-medium text-text-muted">Environments</h3>
                <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                  {allEnvironments.map((environment) => (
                    <Checkbox
                      key={environment.id}
                      checked={currentEnvs.includes(environment.id)}
                      onChange={(on) => setEnvIds(toggle(currentEnvs, environment.id, on))}
                      label={environment.name}
                    />
                  ))}
                </div>
                {currentEnvs.length === 0 ? (
                  <p className="mt-1.5 text-[11px] text-warn">With no environments this person sees only what their squads grant.</p>
                ) : null}
              </div>
              <div>
                <h3 className="mb-1.5 text-xs font-medium text-text-muted">In those environments</h3>
                <div className="flex flex-col gap-1.5">
                  <Checkbox
                    checked={!currentRestricted}
                    onChange={() => setRestricted(false)}
                    label="All projects, including ones added later"
                  />
                  <Checkbox
                    checked={currentRestricted}
                    onChange={() => setRestricted(true)}
                    label="Only the projects and groups I grant"
                  />
                </div>
              </div>
            </section>

            <div role="tablist" aria-label="How access is given" className="flex flex-wrap gap-1 border-b border-border-base">
              {tabs.map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={tab === id}
                  onClick={() => setTab(id)}
                  className={`-mb-px border-b-2 px-3 py-2 text-sm transition-colors ${
                    tab === id ? "border-accent font-medium text-accent" : "border-transparent text-text-muted hover:text-text-base"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="min-h-[18rem]">
              {tab === "squads" ? (
                <div className="space-y-2">
                  <p className="text-[11px] text-text-muted">
                    The usual way to give access: a squad brings its projects, and the environments they live in. A team
                    lead may also accept a risk on the squad's projects.
                  </p>
                  <SquadPicker squads={squads.data?.squads ?? []} selected={currentSquads} onChange={setSquadIds} loading={squads.isLoading} />
                  {currentSquads.length > 0 ? (
                    <div className="rounded-md border border-border-base p-2.5">
                      <h4 className="mb-1.5 text-xs font-medium text-text-muted">Team lead of</h4>
                      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                        {(squads.data?.squads ?? [])
                          .filter((s) => currentSquads.includes(s.id))
                          .sort((a, b) => a.name.localeCompare(b.name))
                          .map((s) => (
                            <Checkbox
                              key={s.id}
                              checked={currentLeads.includes(s.id)}
                              onChange={(on) => setLeadIds(toggle(currentLeads, s.id, on))}
                              label={s.name}
                            />
                          ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              ) : tab === "projects" || tab === "groups" ? (
                !currentRestricted ? (
                  <div className="rounded-md border border-dashed border-border-base bg-bg-subtle p-4 text-sm text-text-muted">
                    This person sees <strong className="text-text-base">all projects</strong> in the ticked environments, so
                    there is nothing to pick here. Choose "Only the projects and groups I grant" above to give access project by
                    project.
                  </div>
                ) : grantable.error ? (
                  <ErrorBanner error={grantable.error} />
                ) : tab === "projects" ? (
                  <ApplicationPicker
                    applications={grantable.applications}
                    selected={currentApps}
                    onToggle={(id, on) => setAppIds(toggle(currentApps, id, on))}
                    search={appSearch}
                    onSearch={setAppSearch}
                    loading={grantable.isLoading}
                    truncated={grantable.truncated}
                    searching={grantable.searching}
                  />
                ) : (
                  <GroupPicker
                    groups={grantable.groups}
                    selected={currentGroups}
                    onToggle={(id, on) => setGroupIds(toggle(currentGroups, id, on))}
                    search={groupSearch}
                    onSearch={setGroupSearch}
                    loading={grantable.isLoading}
                  />
                )
              ) : (
                <ReachTab
                  preview={preview.data ?? null}
                  loading={preview.isLoading}
                  error={preview.error}
                  isAdmin={isAdmin}
                  lost={lost}
                />
              )}
            </div>

            {/* Warnings that matter whichever tab is open. */}
            {currentRestricted && currentGroups.length === 0 && currentApps.length === 0 && currentSquads.length === 0 ? (
              <div className="rounded-md border border-warn/40 bg-warn-subtle p-2.5 text-[11px] text-warn">
                Nothing is granted, so this person will see no projects at all. That is a real state, but rarely the intended one.
              </div>
            ) : null}
            {preview.data && preview.data.emptyGroups.length > 0 ? (
              <p className="text-[11px] text-danger">
                {preview.data.emptyGroups.map((g) => g.name).join(", ")} {preview.data.emptyGroups.length === 1 ? "contains" : "contain"} no
                projects, so granting {preview.data.emptyGroups.length === 1 ? "it" : "them"} reaches nothing.
              </p>
            ) : null}
            {blocked.length > 0 ? (
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-danger">
                <span>
                  {blockedTotal} granted {blockedTotal === 1 ? "project sits" : "projects sit"} in{" "}
                  {blocked.map((gap) => gap.environmentName).join(", ")}, which this person cannot reach.
                </span>
                <Button size="sm" onClick={() => setEnvIds([...new Set([...currentEnvs, ...blocked.map((gap) => gap.environmentId)])])}>
                  {blocked.length === 1 ? "Also grant that environment" : "Also grant those environments"}
                </Button>
              </div>
            ) : null}
          </>
        )}
      </div>
    </Modal>
  );
}

/**
 * The full list of projects the person will reach with the boxes as they stand, searchable,
 * each with how it is reached - and, before saving, what the change takes away.
 */
function ReachTab({
  preview,
  loading,
  error,
  isAdmin,
  lost,
}: {
  preview: import("@sbom/shared").ApplicationAccessPreview | null;
  loading: boolean;
  error: unknown;
  isAdmin: boolean;
  lost: string[];
}) {
  const [search, setSearch] = useState("");
  if (isAdmin) {
    return (
      <div className="rounded-md border border-dashed border-border-base bg-bg-subtle p-4 text-sm">
        <p className="font-medium text-text-base">Everything, by role.</p>
        <p className="mt-1 text-[11px] text-text-muted">Administrators reach every project in every environment, including ones created later.</p>
      </div>
    );
  }
  if (error) return <ErrorBanner error={error} />;
  if (loading && !preview) return <LoadingBlock label="Working out what this person will see" />;

  const rows = preview?.reachable ?? [];
  const total = preview?.reachableApplicationCount ?? 0;
  const needle = search.trim().toLowerCase();
  const visible = needle === "" ? rows : rows.filter((r) => r.name.toLowerCase().includes(needle));

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-[220px] flex-1">
          <TextInput value={search} onChange={setSearch} placeholder="Is a project in? Type its name…" ariaLabel="Search the projects this person will see" />
        </div>
        <span className="nums text-xs text-text-muted">
          {needle ? `${visible.length} of ` : ""}
          {formatNumber(total)} {total === 1 ? "project" : "projects"}
        </span>
      </div>
      {lost.length > 0 ? (
        <div className="rounded-md border border-warn/40 bg-warn-subtle p-2.5 text-[11px] text-warn">
          Saving takes away {lost.length} {lost.length === 1 ? "project" : "projects"}: {lost.slice(0, 8).join(", ")}
          {lost.length > 8 ? ` and ${lost.length - 8} more` : ""}.
        </div>
      ) : null}
      <div className="max-h-[46vh] overflow-y-auto rounded-md border border-border-base">
        {rows.length === 0 ? (
          <p className="p-3 text-[11px] text-text-faint">Nothing yet. Tick a squad, a project or a group and this fills in.</p>
        ) : visible.length === 0 ? (
          <p className="p-3 text-[11px] text-text-muted">
            <strong>{search}</strong> is not among the projects this person will see.
          </p>
        ) : (
          <ul className="divide-y divide-border-base">
            {visible.map((row) => (
              <li key={row.id} className="flex items-start justify-between gap-2 px-2.5 py-1.5">
                <span className="text-xs text-text-base">{row.name}</span>
                <span className="flex shrink-0 flex-wrap justify-end gap-1">
                  {row.direct ? <Badge tone="accent">granted directly</Badge> : null}
                  {row.viaGroups.map((group) => (
                    <Badge key={group} tone="neutral" title={`Reached through the group ${group}`}>
                      group: {group}
                    </Badge>
                  ))}
                  {row.viaSquads.map((squad) => (
                    <Badge key={`squad-${squad}`} tone="info" title={`Reached through the squad ${squad}`}>
                      squad: {squad}
                    </Badge>
                  ))}
                  {row.viaTribes.map((tribe) => (
                    <Badge key={`tribe-${tribe}`} tone="info" title={`Assigned to the tribe ${tribe}, which one of this person's squads is under`}>
                      tribe: {tribe}
                    </Badge>
                  ))}
                  {!row.direct && row.viaGroups.length === 0 && row.viaSquads.length === 0 && row.viaTribes.length === 0 ? (
                    <Badge tone="neutral" title="All projects in the ticked environments">
                      environment
                    </Badge>
                  ) : null}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
      {rows.length > 0 && total > rows.length ? (
        <p className="text-[11px] text-text-faint">
          Showing the first {formatNumber(rows.length)} of {formatNumber(total)} by name; the search covers those.
        </p>
      ) : null}
    </div>
  );
}
