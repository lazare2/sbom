import { useState } from "react";
import type { UserSummary } from "@sbom/shared";
import { sortDirections, userSort } from "@sbom/shared";
import { useServerSort } from "../../lib/useSort.ts";
import { useAuth } from "../../auth/AuthProvider.tsx";
import { formatDate, formatRelative } from "../../lib/format.ts";
import {
  useCreateUser,
  useDeleteUser,
  useResetUserPassword,
  useSetUserApplicationAccess,
  useSetUserEnvironments,
  useUpdateUser,
} from "../../lib/mutations.ts";
import {
  useEnvironments,
  useGrantableScope,
  useUserApplicationAccess,
  useUserEnvironments,
  useUsers,
} from "../../lib/queries.ts";
import { readEnum, readNumber, readString, useUrlState } from "../../lib/useUrlState.ts";
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
  FormRow,
  LoadingBlock,
  Modal,
  Pagination,
  SecretReveal,
  Select,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";

const ROLES = ["", "admin", "user"] as const;

const spec = {
  defaults: {
    search: "",
    role: "" as (typeof ROLES)[number],
    sortBy: userSort.defaultField,
    sortDir: userSort.defaultDirection,
    page: 1,
  },
  parse: (p: URLSearchParams) => ({
    search: readString(p, "search"),
    role: readEnum(p, "role", ROLES, ""),
    sortBy: readEnum(p, "sortBy", userSort.fields, userSort.defaultField),
    sortDir: readEnum(p, "sortDir", sortDirections, userSort.defaultDirection),
    page: readNumber(p, "page", 1),
  }),
};

export function AdminUsersPage() {
  const { user: me } = useAuth();
  const { state, setState } = useUrlState(spec);

  const [createOpen, setCreateOpen] = useState(false);
  const [resetTarget, setResetTarget] = useState<UserSummary | null>(null);
  const [accessTarget, setAccessTarget] = useState<UserSummary | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<UserSummary | null>(null);
  /** Shown once, after a create or reset. Cleared when the modal closes. */
  const [issued, setIssued] = useState<{ email: string; password: string } | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const query = {
    search: state.search || undefined,
    role: state.role || undefined,
    sortBy: state.sortBy,
    sortDir: state.sortDir,
    page: state.page,
    pageSize: 25,
  };
  const users = useUsers(query);
  const sort = useServerSort(userSort, state, setState);

  const updateUser = useUpdateUser();
  const deleteUser = useDeleteUser();

  async function changeRole(u: UserSummary, role: "admin" | "user") {
    setActionError(null);
    try {
      await updateUser.mutateAsync({ id: u.id, body: { role } });
    } catch (err) {
      setActionError(err);
    }
  }

  async function toggleActive(u: UserSummary) {
    setActionError(null);
    try {
      await updateUser.mutateAsync({ id: u.id, body: { isActive: !u.isActive } });
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <Card>
        <CardHeader
          title="Accounts"
          subtitle="Sign-in identifiers are usernames, not mailboxes — the platform never sends email. Passwords are issued here and handed over directly."
          actions={
            <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
              New account
            </Button>
          }
        />

        <div className="flex flex-wrap items-center gap-2 border-b border-border-base px-4 py-2.5">
          <div className="w-56">
            <TextInput
              value={state.search}
              onChange={(v) => setState({ search: v })}
              placeholder="Search by identifier…"
              ariaLabel="Search accounts"
            />
          </div>
          <Select
            value={state.role}
            ariaLabel="Filter by role"
            onChange={(v) => setState({ role: v })}
            options={[
              { value: "", label: "All roles" },
              { value: "admin", label: "Admins" },
              { value: "user", label: "Users" },
            ]}
          />
        </div>

        {actionError ? (
          <div className="px-4 pt-3">
            <FormError error={actionError} />
          </div>
        ) : null}

        {users.isLoading ? (
          <LoadingBlock label="Loading accounts" />
        ) : users.error ? (
          <div className="p-4">
            <ErrorBanner error={users.error} onRetry={() => void users.refetch()} />
          </div>
        ) : !users.data || users.data.items.length === 0 ? (
          <EmptyState title="No accounts match" hint="Try clearing the filters." />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th onSort={() => sort.toggle("email")} sorted={sort.stateOf("email")}>
                      Identifier
                    </Th>
                    <Th onSort={() => sort.toggle("role")} sorted={sort.stateOf("role")}>
                      Role
                    </Th>
                    <Th onSort={() => sort.toggle("isActive")} sorted={sort.stateOf("isActive")}>
                      Status
                    </Th>
                    {/* Not sortable: the grants are per user and not part of the list query. */}
                    <Th>Access</Th>
                    <Th onSort={() => sort.toggle("lastLoginAt")} sorted={sort.stateOf("lastLoginAt")}>
                      Last sign-in
                    </Th>
                    <Th
                      onSort={() => sort.toggle("activeSessions")}
                      sorted={sort.stateOf("activeSessions")}
                      align="right"
                    >
                      Sessions
                    </Th>
                    <Th onSort={() => sort.toggle("createdAt")} sorted={sort.stateOf("createdAt")}>
                      Created
                    </Th>
                    <Th />
                  </tr>
                </thead>
                <tbody>
                  {users.data.items.map((u) => {
                    const isSelf = u.id === me?.id;
                    return (
                      <Tr key={u.id}>
                        <Td>
                          <span className="font-medium text-text-base">{u.email}</span>
                          {isSelf ? (
                            <>
                              {" "}
                              <Badge tone="info">you</Badge>
                            </>
                          ) : null}
                          {u.mustChangePassword ? (
                            <>
                              {" "}
                              <Badge
                                tone="warn"
                                title="An administrator issued this password. It must be changed at next sign-in."
                              >
                                temp password
                              </Badge>
                            </>
                          ) : null}
                        </Td>
                        <Td>
                          <Badge tone={u.role === "admin" ? "accent" : "neutral"}>{u.role}</Badge>
                        </Td>
                        <Td>
                          {u.isActive ? (
                            <Badge tone="ok">Active</Badge>
                          ) : (
                            <Badge tone="danger">Deactivated</Badge>
                          )}
                        </Td>
                        <Td>
                          <AccessCell
                            user={u}
                            onEdit={() => {
                              setActionError(null);
                              setAccessTarget(u);
                            }}
                          />
                        </Td>
                        <Td title={u.lastLoginAt ?? ""}>{formatRelative(u.lastLoginAt)}</Td>
                        <Td align="right" className="nums">
                          {u.activeSessions}
                        </Td>
                        <Td title={u.createdAt}>{formatDate(u.createdAt)}</Td>
                        <Td align="right">
                          <div className="flex flex-wrap justify-end gap-1.5">
                            <Button
                              size="sm"
                              onClick={() => {
                                setIssued(null);
                                setActionError(null);
                                setResetTarget(u);
                              }}
                            >
                              Reset password
                            </Button>
                            {/* Self-service role and status changes are refused by
                                the API; hiding the buttons avoids offering an
                                action that can only fail. */}
                            {!isSelf ? (
                              <>
                                <Button
                                  size="sm"
                                  onClick={() => void changeRole(u, u.role === "admin" ? "user" : "admin")}
                                  disabled={updateUser.isPending}
                                >
                                  {u.role === "admin" ? "Make user" : "Make admin"}
                                </Button>
                                <Button
                                  size="sm"
                                  onClick={() => void toggleActive(u)}
                                  disabled={updateUser.isPending}
                                >
                                  {u.isActive ? "Deactivate" : "Reactivate"}
                                </Button>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => {
                                    setActionError(null);
                                    setDeleteTarget(u);
                                  }}
                                >
                                  Delete
                                </Button>
                              </>
                            ) : null}
                          </div>
                        </Td>
                      </Tr>
                    );
                  })}
                </tbody>
              </Table>
            </TableWrap>

            <Pagination
              page={users.data.page}
              pageSize={users.data.pageSize}
              total={users.data.total}
              totalPages={users.data.totalPages}
              onPageChange={(p) => setState({ page: p })}
              isFetching={users.isFetching}
            />
          </>
        )}
      </Card>

      <UserAccessModal target={accessTarget} onClose={() => setAccessTarget(null)} />

      <CreateUserModal
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          setIssued(null);
        }}
        issued={issued}
        onIssued={setIssued}
      />

      <ResetPasswordModal
        target={resetTarget}
        onClose={() => {
          setResetTarget(null);
          setIssued(null);
        }}
        issued={issued}
        onIssued={setIssued}
      />

      <ConfirmDeleteModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        confirmWord={deleteTarget?.email ?? ""}
        title="Delete account"
        busy={deleteUser.isPending}
        onConfirm={() => {
          if (!deleteTarget) return;
          setActionError(null);
          deleteUser.mutate(deleteTarget.id, {
            onSuccess: () => setDeleteTarget(null),
            onError: (err) => setActionError(err),
          });
        }}
      >
        <FormError error={actionError} />
        <p>
          Deletes <strong className="text-text-base">{deleteTarget?.email}</strong> and signs out all of
          their sessions immediately.
        </p>
        <p>
          Their entries in the audit log are kept, so any changes they made remain traceable.
          Deactivating instead blocks sign-in while leaving the account in place.
        </p>
      </ConfirmDeleteModal>
    </>
  );
}

// ---------------------------------------------------------------------------

function CreateUserModal({
  open,
  onClose,
  issued,
  onIssued,
}: {
  open: boolean;
  onClose: () => void;
  issued: { email: string; password: string } | null;
  onIssued: (v: { email: string; password: string }) => void;
}) {
  const createUser = useCreateUser();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"admin" | "user">("user");
  const [password, setPassword] = useState("");
  const [useOwnPassword, setUseOwnPassword] = useState(false);
  const environments = useEnvironments();
  const allEnvironments = environments.data?.environments ?? [];
  /*
    Null means "leave it to the platform", which grants every environment that exists at the
    moment of creation. Kept distinct from an array holding those same ids so the request
    omits the field entirely unless the admin actually narrowed it -- the server default is
    then the one behaviour, rather than something this form re-implements and can drift from.
  */
  const [environmentIds, setEnvironmentIds] = useState<string[] | null>(null);
  const chosenEnvironments = environmentIds ?? allEnvironments.map((e) => e.id);

  function reset() {
    setEmail("");
    setRole("user");
    setPassword("");
    setUseOwnPassword(false);
    setEnvironmentIds(null);
    createUser.reset();
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      const result = await createUser.mutateAsync({
        email,
        role,
        mustChangePassword: true,
        ...(useOwnPassword && password ? { password } : {}),
        ...(environmentIds === null ? {} : { environmentIds }),
      });
      onIssued({ email: result.user.email, password: result.temporaryPassword });
    } catch {
      // Rendered from the mutation's error state.
    }
  }

  return (
    <Modal
      open={open}
      onClose={() => {
        reset();
        onClose();
      }}
      title={issued ? "Account created" : "New account"}
      footer={
        issued ? (
          <Button
            variant="primary"
            onClick={() => {
              reset();
              onClose();
            }}
          >
            Done
          </Button>
        ) : (
          <>
            <Button
              onClick={() => {
                reset();
                onClose();
              }}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              type="submit"
              form="create-user-form"
              disabled={!email || createUser.isPending || (useOwnPassword && password.length < 12)}
            >
              {createUser.isPending ? "Creating…" : "Create account"}
            </Button>
          </>
        )
      }
    >
      {issued ? (
        <div className="space-y-3">
          <SecretReveal
            label={`Password for ${issued.email}`}
            value={issued.password}
            note="Shown once and never again — it is stored only as a hash. Hand it over directly; the user must change it at first sign-in."
          />
        </div>
      ) : (
        <form id="create-user-form" onSubmit={submit} className="space-y-3" noValidate>
          <FormError error={createUser.error} />

          <FormRow
            label="Sign-in identifier"
            htmlFor="new-user-email"
            hint="Usually a work email, but nothing is ever sent to it — any unique identifier works."
          >
            <TextInput
              id="new-user-email"
              value={email}
              onChange={setEmail}
              placeholder="person@company.com"
              autoFocus
              required
            />
          </FormRow>

          <FormRow label="Role" htmlFor="new-user-role">
            <Select
              id="new-user-role"
              value={role}
              onChange={(v) => setRole(v as "admin" | "user")}
              options={[
                { value: "user", label: "User — read everything" },
                { value: "admin", label: "Admin — read everything and manage" },
              ]}
            />
          </FormRow>

          {/*
            Hidden for administrators, who reach every environment by role. Offering a
            checklist that the role overrides would be a control that does nothing, and the
            reasonable reading of an unticked box would be that access was withheld.
          */}
          {role === "user" ? (
            <FormRow
              label="Environments"
              hint="Which estates this account can see. All of them by default."
            >
              <div className="flex flex-col gap-1.5">
                {allEnvironments.map((environment) => (
                  <Checkbox
                    key={environment.id}
                    checked={chosenEnvironments.includes(environment.id)}
                    onChange={(checked) =>
                      setEnvironmentIds(
                        checked
                          ? [...chosenEnvironments, environment.id]
                          : chosenEnvironments.filter((id) => id !== environment.id),
                      )
                    }
                    label={environment.name}
                  />
                ))}
                {chosenEnvironments.length === 0 ? (
                  <span className="text-[11px] text-warn">
                    With none ticked the account will be able to sign in and see nothing.
                  </span>
                ) : null}
              </div>
            </FormRow>
          ) : null}

          <label className="flex cursor-pointer items-center gap-2 text-sm text-text-muted select-none">
            <input
              type="checkbox"
              checked={useOwnPassword}
              onChange={(e) => setUseOwnPassword(e.target.checked)}
              className="size-3.5 accent-[var(--accent)]"
            />
            Set the password myself instead of generating one
          </label>

          {useOwnPassword ? (
            <FormRow
              label="Initial password"
              htmlFor="new-user-password"
              hint="At least 12 characters. The user must change it at first sign-in either way."
            >
              <TextInput
                id="new-user-password"
                type="text"
                value={password}
                onChange={setPassword}
                autoComplete="off"
              />
            </FormRow>
          ) : null}
        </form>
      )}
    </Modal>
  );
}

function ResetPasswordModal({
  target,
  onClose,
  issued,
  onIssued,
}: {
  target: UserSummary | null;
  onClose: () => void;
  issued: { email: string; password: string } | null;
  onIssued: (v: { email: string; password: string }) => void;
}) {
  const resetPassword = useResetUserPassword();

  async function run() {
    if (!target) return;
    try {
      const result = await resetPassword.mutateAsync({ id: target.id });
      onIssued({ email: result.user.email, password: result.temporaryPassword });
    } catch {
      // Rendered from the mutation's error state.
    }
  }

  return (
    <Modal
      open={target !== null}
      onClose={() => {
        resetPassword.reset();
        onClose();
      }}
      title="Reset password"
      footer={
        issued ? (
          <Button
            variant="primary"
            onClick={() => {
              resetPassword.reset();
              onClose();
            }}
          >
            Done
          </Button>
        ) : (
          <>
            <Button
              onClick={() => {
                resetPassword.reset();
                onClose();
              }}
            >
              Cancel
            </Button>
            <Button variant="primary" onClick={() => void run()} disabled={resetPassword.isPending}>
              {resetPassword.isPending ? "Generating…" : "Generate new password"}
            </Button>
          </>
        )
      }
    >
      {issued ? (
        <SecretReveal
          label={`New password for ${issued.email}`}
          value={issued.password}
          note="Shown once. All of their existing sessions have been signed out, and they must change this at next sign-in."
        />
      ) : (
        <div className="space-y-3 text-sm text-text-muted">
          <FormError error={resetPassword.error} />
          <p>
            Generates a new password for{" "}
            <strong className="text-text-base">{target?.email}</strong> and shows it once.
          </p>
          <p>
            Every one of their active sessions is signed out immediately
            {target && target.activeSessions > 0 ? ` (${target.activeSessions} right now)` : ""}, and
            they will be required to choose their own password when they next sign in.
          </p>
        </div>
      )}
    </Modal>
  );
}

/**
 * What this account can reach, in the list.
 *
 * An administrator is shown as reaching everything rather than as a list of ticked boxes,
 * because that is what the role means: an admin gains an environment created tomorrow,
 * whereas a user granted every environment today does not. Rendering the two identically
 * would hide a difference that only shows up weeks later, when a new estate is invisible to
 * half the people who expected to see it.
 *
 * The grants themselves are not in the list payload and are deliberately not fetched per
 * row — twenty-five rows would mean twenty-five requests to render a column. They are read
 * when the editor opens.
 */
function AccessCell({ user, onEdit }: { user: UserSummary; onEdit: () => void }) {
  if (user.role === "admin") {
    return (
      <span
        className="text-xs text-text-muted"
        title="Administrators reach every environment, group and application, including ones created later."
      >
        Everything
      </span>
    );
  }

  return (
    <div className="flex items-center gap-1.5">
      {/*
        Whether the account is narrowed is worth a badge; *what* it is narrowed to is not,
        because it cannot be rendered honestly here. The grants are not in the list payload
        and fetching them per row would mean twenty-five requests to draw one column — and a
        count of groups would be the misleading half of the answer anyway, since groups
        overlap and say nothing about how many applications they reach.
      */}
      {user.applicationAccessRestricted ? (
        <Badge tone="warn" title="This account sees only the groups and applications granted to it.">
          Restricted
        </Badge>
      ) : null}
      <Button size="sm" variant="ghost" onClick={onEdit}>
        {user.applicationAccessRestricted ? "Review…" : "Choose…"}
      </Button>
    </div>
  );
}

/**
 * Everything one account may see, on one screen.
 *
 * Two restrictions with a strict order between them, and the screen is laid out to make that
 * order legible rather than to be tidy. Environments come first because they decide which
 * estates exist for this account at all; groups and applications narrow within those. Ticking
 * a group from an estate the account has not been granted would grant nothing — the two
 * compose by intersection — so only groups from granted estates are offered.
 *
 * They were briefly two separate modals. That was worse for one specific reason: an
 * administrator asking "what can this person see" had to open both and hold the intersection
 * in their head, and the intersection is exactly where the surprising answers live.
 */
function UserAccessModal({ target, onClose }: { target: UserSummary | null; onClose: () => void }) {
  const environments = useEnvironments();
  const grantedEnvironments = useUserEnvironments(target?.id ?? null);
  const access = useUserApplicationAccess(target?.id ?? null);
  const saveEnvironments = useSetUserEnvironments();
  const saveAccess = useSetUserApplicationAccess();

  const [envIds, setEnvIds] = useState<string[] | null>(null);
  const [restricted, setRestricted] = useState<boolean | null>(null);
  const [groupIds, setGroupIds] = useState<string[] | null>(null);
  const [appIds, setAppIds] = useState<string[] | null>(null);

  // Server state is the starting point; local state exists only once something is changed.
  const currentEnvs = envIds ?? grantedEnvironments.data?.environmentIds ?? [];
  const currentRestricted = restricted ?? access.data?.restricted ?? false;
  const currentGroups = groupIds ?? access.data?.groupIds ?? [];
  const currentApps = appIds ?? access.data?.applicationIds ?? [];

  const grantable = useGrantableScope(currentEnvs);
  const allEnvironments = environments.data?.environments ?? [];
  const isAdmin = target?.role === "admin";

  const loading = grantedEnvironments.isLoading || access.isLoading;
  const saving = saveEnvironments.isPending || saveAccess.isPending;
  const dirty = envIds !== null || restricted !== null || groupIds !== null || appIds !== null;

  function toggle(list: string[], id: string, on: boolean): string[] {
    return on ? [...list, id] : list.filter((entry) => entry !== id);
  }

  function close() {
    setEnvIds(null);
    setRestricted(null);
    setGroupIds(null);
    setAppIds(null);
    saveEnvironments.reset();
    saveAccess.reset();
    onClose();
  }

  /*
    Two endpoints, saved in this order deliberately. Environments are widened or narrowed
    first, so that a group grant landing immediately afterwards is checked against the estates
    the account will actually have, rather than the ones it had a moment ago.
  */
  async function save() {
    if (!target) return;
    await saveEnvironments.mutateAsync({ id: target.id, environmentIds: currentEnvs });
    await saveAccess.mutateAsync({
      id: target.id,
      body: {
        restricted: currentRestricted,
        groupIds: currentGroups,
        applicationIds: currentApps,
      },
    });
    close();
  }

  return (
    <Modal
      open={target !== null}
      onClose={close}
      wide
      title={target ? `Access for ${target.email}` : "Access"}
      footer={
        <>
          <Button onClick={close} disabled={saving}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!dirty || saving} onClick={() => void save()}>
            {saving ? "Saving…" : "Save access"}
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-sm">
        <FormError error={saveEnvironments.error ?? saveAccess.error} />

        {loading ? (
          <LoadingBlock label="Loading access" />
        ) : (
          <>
            {/*
              Stated once, at the top, rather than repeated as a disabled state on every
              control below. An admin screen whose every checkbox is greyed out reads as
              broken; one sentence explaining that the role already grants everything reads
              as an answer.
            */}
            {isAdmin ? (
              <div className="rounded-md border border-accent/40 bg-accent-subtle p-2.5 text-[11px] text-accent">
                This is an administrator, and administrators reach every environment, group and
                application — including ones created later. The choices below are stored and
                take effect only if the account is changed to a read-only user.
              </div>
            ) : null}

            <section>
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
                <p className="mt-1.5 text-[11px] text-warn">
                  With no environments this account can sign in and see nothing at all.
                </p>
              ) : null}
            </section>

            <section className="border-t border-border-base pt-3">
              <h3 className="mb-1.5 text-xs font-medium text-text-muted">
                Within those environments
              </h3>
              <div className="flex flex-col gap-1.5">
                <Checkbox
                  checked={!currentRestricted}
                  onChange={() => setRestricted(false)}
                  label="Everything, including applications added later"
                />
                <Checkbox
                  checked={currentRestricted}
                  onChange={() => setRestricted(true)}
                  label="Only the groups and applications selected below"
                />
              </div>

              {currentRestricted ? (
                <div className="mt-3 space-y-3">
                  {grantable.isLoading ? (
                    <LoadingBlock label="Loading groups" />
                  ) : grantable.error ? (
                    /*
                      Shown instead of the pickers, never alongside an empty one. An empty
                      picker after a failed load says "there is nothing to grant", which is a
                      claim about the estate rather than about the request -- and an
                      administrator who believes it stops looking.
                    */
                    <ErrorBanner error={grantable.error} />
                  ) : (
                    <>
                      <div>
                        <p className="mb-1 text-[11px] font-medium text-text-muted">Groups</p>
                        {grantable.groups.length === 0 ? (
                          <p className="text-[11px] text-text-faint">
                            No groups exist in the selected environments yet.
                          </p>
                        ) : (
                          <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                            {grantable.groups.map((group) => (
                              <Checkbox
                                key={group.id}
                                checked={currentGroups.includes(group.id)}
                                onChange={(on) => setGroupIds(toggle(currentGroups, group.id, on))}
                                label={`${group.name} (${group.applicationCount})`}
                              />
                            ))}
                          </div>
                        )}
                        {/*
                          The reason to prefer a group, said where the choice is made. A group
                          grant follows its membership; the list below does not.
                        */}
                        <p className="mt-1 text-[11px] text-text-faint">
                          A group grant follows the group: applications added to it later become
                          visible without anyone revisiting this screen.
                        </p>
                      </div>

                      <div>
                        <p className="mb-1 text-[11px] font-medium text-text-muted">
                          Individual applications
                        </p>
                        <div className="max-h-48 overflow-y-auto rounded-md border border-border-base p-2">
                          {grantable.applications.length === 0 ? (
                            <p className="text-[11px] text-text-faint">
                              No applications in the selected environments.
                            </p>
                          ) : (
                            <div className="flex flex-col gap-1">
                              {grantable.applications.map((application) => (
                                <Checkbox
                                  key={application.id}
                                  checked={currentApps.includes(application.id)}
                                  onChange={(on) =>
                                    setAppIds(toggle(currentApps, application.id, on))
                                  }
                                  label={application.name}
                                />
                              ))}
                            </div>
                          )}
                        </div>
                        <p className="mt-1 text-[11px] text-text-faint">
                          For a service that is in no group — which is how every application
                          starts, since CI registers it before anyone files it.
                        </p>
                        {/*
                          Stated rather than silently trimmed. A list that stops at the cap
                          without saying so lets an administrator conclude an application does
                          not exist because they could not find it.
                        */}
                        {grantable.truncated ? (
                          <p className="mt-1 text-[11px] text-warn">
                            More applications exist than are listed here. Grant a group instead,
                            or narrow the environments above.
                          </p>
                        ) : null}
                      </div>

                      {currentGroups.length === 0 && currentApps.length === 0 ? (
                        <div className="rounded-md border border-warn/40 bg-warn-subtle p-2.5 text-[11px] text-warn">
                          Nothing is selected, so this account will see no applications at all.
                          That is a real state, but it is rarely the intended one.
                        </div>
                      ) : null}
                    </>
                  )}
                </div>
              ) : null}
            </section>

            {/*
              The count, not the two list lengths. Groups overlap with each other and with
              directly granted applications, so "two groups and one application" does not tell
              an administrator whether they have granted three services or thirty — and a
              number they have to reconcile themselves is how somebody concludes a save failed.
            */}
            {currentRestricted && access.data ? (
              <p className="border-t border-border-base pt-3 text-[11px] text-text-muted">
                Currently reaches{" "}
                <strong className="text-text-base">
                  {access.data.visibleApplicationCount ?? 0}
                </strong>{" "}
                {access.data.visibleApplicationCount === 1 ? "application" : "applications"}.
                Saving recalculates this.
              </p>
            ) : null}
          </>
        )}
      </div>
    </Modal>
  );
}
