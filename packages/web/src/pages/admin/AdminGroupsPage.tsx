import { useMemo, useState } from "react";
import { Link } from "react-router";
import type { ApplicationGroupSummary, ApplicationSummary } from "@sbom/shared";
import { useApplications, useGroup, useGroups } from "../../lib/queries.ts";
import {
  useCreateGroup,
  useDeleteGroup,
  useSetGroupMembers,
  useUpdateGroup,
} from "../../lib/mutations.ts";
import { formatNumber, formatRelative } from "../../lib/format.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Modal,
  StatusBadge,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";

/**
 * Group administration: create, rename, set membership, delete.
 *
 * Membership is edited here and only here — ingest never writes to these tables. A pipeline
 * declaring its own groups would be self-maintaining, but any holder of an ingest token could
 * then create one, and a typo would silently become a real group holding half the membership
 * with nothing on screen to say it was a mistake.
 *
 * ## Why the editing is shaped this way
 *
 * The first version put the member checklist in a card below the table and the row actions in
 * three identical ghost buttons. Both were wrong for the same reason: the thing an admin comes
 * to this page to do was the least visible thing on it. So membership is now the row's primary
 * action, the editor is a modal that cannot fall below the fold, and every row shows who is
 * actually in the group without opening anything.
 *
 * The other half of the problem was a Save button that is disabled until something changes —
 * correct behaviour, because an empty save writes an audit entry for a change that never
 * happened, but indistinguishable from a broken button. It now sits next to a running count of
 * what will be added and removed, so its state is explained rather than merely enforced.
 */
export function AdminGroupsPage() {
  const groups = useGroups({ pageSize: 200 });
  const [editingMembers, setEditingMembers] = useState<ApplicationGroupSummary | null>(null);
  const [editingDetails, setEditingDetails] = useState<ApplicationGroupSummary | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<ApplicationGroupSummary | null>(null);

  return (
    <>
      <Card>
        <CardHeader
          title="Groups"
          subtitle="Named sets of applications. One application can belong to as many as you like."
        />

        {groups.error ? (
          <ErrorBanner error={groups.error} onRetry={groups.refetch} />
        ) : groups.isLoading ? (
          <LoadingBlock />
        ) : !groups.data || groups.data.items.length === 0 ? (
          <EmptyState
            title="No groups yet"
            hint="Create one, then choose which applications belong to it."
          />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Group</Th>
                  <Th>Applications</Th>
                  <Th width="260px">Actions</Th>
                </tr>
              </thead>
              <tbody>
                {groups.data.items.map((group) => (
                  <Tr key={group.id}>
                    <Td>
                      <Link
                        to={`/groups/${group.id}`}
                        className="font-medium text-accent hover:underline"
                      >
                        {group.name}
                      </Link>
                      {group.description ? (
                        <p className="mt-0.5 text-[11px] text-text-faint">{group.description}</p>
                      ) : null}
                    </Td>
                    <Td>
                      <MemberPreview group={group} />
                    </Td>
                    <Td>
                      <div className="flex flex-wrap items-center gap-1">
                        {/*
                          Primary, and first. Choosing who is in a group is the reason this
                          page exists; renaming it is an occasional chore. Three ghost buttons
                          of equal weight made the common action the hardest to find.
                        */}
                        <Button size="sm" variant="primary" onClick={() => setEditingMembers(group)}>
                          Edit members
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setEditingDetails(group)}>
                          Rename
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setDeleting(group)}>
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

        <div className="border-t border-border-base p-3">
          <Button size="sm" variant="primary" onClick={() => setCreating(true)}>
            New group
          </Button>
        </div>
      </Card>

      {creating ? <GroupDetailsModal onClose={() => setCreating(false)} /> : null}
      {editingDetails ? (
        <GroupDetailsModal group={editingDetails} onClose={() => setEditingDetails(null)} />
      ) : null}
      {editingMembers ? (
        <MemberModal group={editingMembers} onClose={() => setEditingMembers(null)} />
      ) : null}
      {deleting ? <DeleteModal group={deleting} onClose={() => setDeleting(null)} /> : null}
    </>
  );
}

/**
 * Who is actually in the group, without opening anything.
 *
 * A bare count answers "how many" and leaves "which" — the question an admin checking their
 * work is actually asking — one click away for every row. Capped because a twenty-member group
 * would otherwise own the table's height; the overflow is stated rather than silently trimmed.
 */
function MemberPreview({ group }: { group: ApplicationGroupSummary }) {
  const CAP = 4;

  if (group.applicationCount === 0) {
    return <span className="text-xs text-text-faint">No applications yet</span>;
  }

  // From the list payload, not a per-group fetch. Reading this from the detail endpoint would
  // issue one request per row -- two hundred on a full page -- for a four-name preview.
  const shown = group.memberNames.slice(0, CAP);
  const rest = group.applicationCount - shown.length;

  return (
    <div className="flex flex-wrap items-center gap-1">
      {shown.map((name) => (
        <span
          key={name}
          className="rounded bg-neutral-subtle px-1.5 py-0.5 text-[11px] text-text-muted"
        >
          {name}
        </span>
      ))}
      {rest > 0 ? <span className="text-[11px] text-text-faint">+{rest} more</span> : null}
    </div>
  );
}

/** Create when `group` is absent, rename when present. */
function GroupDetailsModal({
  group,
  onClose,
}: {
  group?: ApplicationGroupSummary;
  onClose: () => void;
}) {
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const create = useCreateGroup();
  const update = useUpdateGroup();
  const pending = create.isPending || update.isPending;
  const error = create.error ?? update.error;

  function submit() {
    const trimmed = name.trim();
    if (trimmed === "") return;
    const body = { name: trimmed, description: description.trim() };
    if (group) update.mutate({ id: group.id, ...body }, { onSuccess: onClose });
    else create.mutate(body, { onSuccess: onClose });
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={group ? `Rename ${group.name}` : "New group"}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} disabled={pending || name.trim() === ""}>
            {group ? "Save" : "Create group"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <div>
          <label htmlFor="gm-name" className="mb-1 block text-[11px] font-medium text-text-muted">
            Name
          </label>
          <TextInput id="gm-name" value={name} onChange={setName} placeholder="Checkout Platform" autoFocus />
        </div>
        <div>
          <label htmlFor="gm-desc" className="mb-1 block text-[11px] font-medium text-text-muted">
            Description <span className="text-text-faint">(optional)</span>
          </label>
          <TextInput
            id="gm-desc"
            value={description}
            onChange={setDescription}
            placeholder="What this group is for"
          />
        </div>
        {!group ? (
          <p className="text-[11px] text-text-faint">
            You can choose its applications straight after creating it.
          </p>
        ) : null}
        {error ? <ErrorBanner error={error} /> : null}
      </div>
    </Modal>
  );
}

/**
 * The membership editor.
 *
 * Loads the group fresh rather than trusting the list's copy: the list carries counts but not
 * member ids, and inferring the ticked set from anything but the server's own answer is how a
 * save silently drops a member somebody else just added.
 *
 * Members sort to the top. An admin opening this is checking or amending an existing set, and
 * a plain alphabetical list buries the three applications they care about among fifty they do
 * not. Sorting is computed once when the data arrives rather than on every tick, so a row does
 * not jump out from under the cursor mid-click.
 */
function MemberModal({
  group,
  onClose,
}: {
  group: ApplicationGroupSummary;
  onClose: () => void;
}) {
  const detail = useGroup(group.id);
  const applications = useApplications({
    pageSize: 200,
    status: ["active", "inactive", "pending_confirmation"],
  });
  const setMembers = useSetGroupMembers();

  const [search, setSearch] = useState("");
  const [selectedOnly, setSelectedOnly] = useState(false);
  const [selected, setSelected] = useState<Set<string> | null>(null);

  const original = useMemo(
    () => new Set(detail.data?.members.map((m) => m.id) ?? []),
    [detail.data],
  );
  const current = selected ?? original;

  /*
    Ordering is keyed on the ORIGINAL membership, not the live selection. Sorting by `current`
    would move a row to the top of the list the instant it was ticked, so the next click would
    land on whatever slid into its place.
  */
  const ordered = useMemo(() => {
    const items = [...(applications.data?.items ?? [])];
    return items.sort((a, b) => {
      const am = original.has(a.id) ? 0 : 1;
      const bm = original.has(b.id) ? 0 : 1;
      if (am !== bm) return am - bm;
      return a.name.localeCompare(b.name);
    });
  }, [applications.data, original]);

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return ordered.filter(
      (a) => (!selectedOnly || current.has(a.id)) && (needle === "" || a.name.toLowerCase().includes(needle)),
    );
  }, [ordered, search, selectedOnly, current]);

  const added = [...current].filter((id) => !original.has(id));
  const removed = [...original].filter((id) => !current.has(id));
  const dirty = added.length > 0 || removed.length > 0;

  function toggle(id: string) {
    const next = new Set(current);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  }

  const loading = detail.isLoading || applications.isLoading;

  return (
    <Modal
      open
      wide
      onClose={onClose}
      title={`Applications in ${group.name}`}
      footer={
        <>
          {/*
            The change summary sits beside the button rather than anywhere else on screen,
            because its job is to explain why that button is enabled or disabled. "Nothing to
            save yet" reads as a state; a greyed button on its own reads as a fault.
          */}
          <span className="mr-auto text-xs text-text-muted">
            {dirty ? (
              <>
                {added.length > 0 ? (
                  <span className="font-medium text-ok">+{added.length} to add</span>
                ) : null}
                {added.length > 0 && removed.length > 0 ? " · " : null}
                {removed.length > 0 ? (
                  <span className="font-medium text-danger">−{removed.length} to remove</span>
                ) : null}
              </>
            ) : (
              <span className="text-text-faint">Nothing to save yet</span>
            )}
          </span>
          <Button onClick={onClose} disabled={setMembers.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            disabled={!dirty || setMembers.isPending}
            onClick={() =>
              setMembers.mutate(
                { id: group.id, applicationIds: [...current] },
                { onSuccess: onClose },
              )
            }
          >
            {setMembers.isPending ? "Saving…" : "Save membership"}
          </Button>
        </>
      }
    >
      {loading ? (
        <LoadingBlock />
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-[200px] flex-1">
              <label htmlFor="mm-search" className="mb-1 block text-[11px] font-medium text-text-muted">
                Search applications
              </label>
              <TextInput id="mm-search" value={search} onChange={setSearch} placeholder="payments" autoFocus />
            </div>
            <Button
              size="sm"
              variant={selectedOnly ? "primary" : "secondary"}
              onClick={() => setSelectedOnly(!selectedOnly)}
            >
              {selectedOnly ? "Showing selected" : `Show selected (${current.size})`}
            </Button>
          </div>

          <div className="flex items-center justify-between gap-2 text-xs">
            <span className="text-text-muted">
              {formatNumber(current.size)} selected of {formatNumber(ordered.length)} applications
            </span>
            {/*
              Bulk actions act on what is VISIBLE, and say so. Acting on the whole estate from
              behind a filter is how someone adds two hundred applications while looking at
              five, and the label is the only thing standing between those two outcomes.
            */}
            <span className="flex gap-2">
              <button
                type="button"
                className="text-accent hover:underline"
                onClick={() => setSelected(new Set([...current, ...visible.map((a) => a.id)]))}
              >
                Select shown ({visible.length})
              </button>
              <button
                type="button"
                className="text-accent hover:underline"
                onClick={() => {
                  const next = new Set(current);
                  for (const a of visible) next.delete(a.id);
                  setSelected(next);
                }}
              >
                Clear shown
              </button>
            </span>
          </div>

          {setMembers.error ? <ErrorBanner error={setMembers.error} /> : null}

          <div className="max-h-[46vh] overflow-y-auto rounded border border-border-base">
            {visible.length === 0 ? (
              <EmptyState
                title="No applications match"
                hint={selectedOnly ? "Nothing selected yet." : "Try a shorter search."}
              />
            ) : (
              <ul>
                {visible.map((app) => (
                  <MemberRow
                    key={app.id}
                    app={app}
                    checked={current.has(app.id)}
                    wasMember={original.has(app.id)}
                    onToggle={() => toggle(app.id)}
                  />
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </Modal>
  );
}

/**
 * One application, with enough context to tell it apart from its neighbours.
 *
 * Status and last-scan are here because names alone are not always enough: `payments-api` and
 * `payments-api-v2` are one careless click apart, and an inactive application in a product
 * group is usually a mistake worth seeing before saving rather than after.
 *
 * The row is a single clickable label rather than a checkbox with text beside it, so the whole
 * strip is a target instead of a twelve-pixel box.
 */
function MemberRow({
  app,
  checked,
  wasMember,
  onToggle,
}: {
  app: ApplicationSummary;
  checked: boolean;
  wasMember: boolean;
  onToggle: () => void;
}) {
  // Marks only what this session has changed, so a reader can see their own edits at a glance
  // without comparing against a list they no longer have on screen.
  const change = checked === wasMember ? null : checked ? "added" : "removed";

  return (
    <li className="border-b border-border-base last:border-b-0">
      <label className="flex cursor-pointer items-center gap-2.5 px-3 py-2 hover:bg-bg-subtle">
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggle}
          className="size-4 shrink-0 accent-accent"
        />
        <span className="min-w-0 flex-1 truncate text-sm text-text-base">{app.name}</span>
        {change === "added" ? (
          <Badge tone="ok">Adding</Badge>
        ) : change === "removed" ? (
          <Badge tone="danger">Removing</Badge>
        ) : null}
        {app.status !== "active" ? <StatusBadge status={app.status} /> : null}
        <span className="shrink-0 text-[11px] text-text-faint">
          {app.lastScanAt ? formatRelative(app.lastScanAt) : "never scanned"}
        </span>
      </label>
    </li>
  );
}

function DeleteModal({
  group,
  onClose,
}: {
  group: ApplicationGroupSummary;
  onClose: () => void;
}) {
  const remove = useDeleteGroup();

  return (
    <Modal
      open
      onClose={onClose}
      title={`Delete ${group.name}?`}
      footer={
        <>
          <Button onClick={onClose} disabled={remove.isPending}>
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={remove.isPending}
            onClick={() => remove.mutate(group.id, { onSuccess: onClose })}
          >
            Delete group
          </Button>
        </>
      }
    >
      {/*
        Said plainly, because "delete" on something that contains things is the one place a
        reader may reasonably fear the contents go with it. They do not — only the membership
        rows are removed — and one sentence is cheaper than the hesitation.
      */}
      <p className="text-sm text-text-muted">
        The {formatNumber(group.applicationCount)} application
        {group.applicationCount === 1 ? "" : "s"} in this group{" "}
        {group.applicationCount === 1 ? "is" : "are"} not deleted — only the group itself and
        its membership.
      </p>
      {remove.error ? <ErrorBanner error={remove.error} /> : null}
    </Modal>
  );
}
