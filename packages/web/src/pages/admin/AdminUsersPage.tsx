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
  useSetUserEnvironments,
  useUpdateUser,
} from "../../lib/mutations.ts";
import { useEnvironments, useUserEnvironments, useUsers } from "../../lib/queries.ts";
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
  const [environmentTarget, setEnvironmentTarget] = useState<UserSummary | null>(null);
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
                    <Th>Environments</Th>
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
                          <EnvironmentAccessCell
                            user={u}
                            onEdit={() => {
                              setActionError(null);
                              setEnvironmentTarget(u);
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

      <UserEnvironmentsModal
        target={environmentTarget}
        onClose={() => setEnvironmentTarget(null)}
      />

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
function EnvironmentAccessCell({ user, onEdit }: { user: UserSummary; onEdit: () => void }) {
  if (user.role === "admin") {
    return (
      <span
        className="text-xs text-text-muted"
        title="Administrators reach every environment, including ones created later."
      >
        All environments
      </span>
    );
  }
  return (
    <Button size="sm" variant="ghost" onClick={onEdit}>
      Choose…
    </Button>
  );
}

/**
 * The per-user environment checklist.
 *
 * Saves the complete set rather than a delta, matching the API. Two administrators editing
 * the same account at once would otherwise each apply their own change to a set the other
 * had already altered, and whichever saved second would silently restore what the first
 * removed.
 *
 * Granting nothing is permitted and is a real state — an account can exist before anyone
 * has decided what it should reach — but it is called out, because a user in that state is
 * refused every page on the platform and reports it as the platform being broken.
 */
function UserEnvironmentsModal({
  target,
  onClose,
}: {
  target: UserSummary | null;
  onClose: () => void;
}) {
  const environments = useEnvironments();
  const granted = useUserEnvironments(target?.id ?? null);
  const save = useSetUserEnvironments();
  const [selected, setSelected] = useState<string[] | null>(null);

  // Server state is the starting point; local state only exists once something is ticked.
  const current = selected ?? granted.data?.environmentIds ?? [];
  const all = environments.data?.environments ?? [];
  const dirty =
    granted.data !== undefined &&
    selected !== null &&
    (selected.length !== granted.data.environmentIds.length ||
      selected.some((id) => !granted.data.environmentIds.includes(id)));

  function toggle(id: string, checked: boolean) {
    setSelected(checked ? [...current, id] : current.filter((e) => e !== id));
  }

  function close() {
    setSelected(null);
    save.reset();
    onClose();
  }

  return (
    <Modal
      open={target !== null}
      onClose={close}
      title={target ? `Environments for ${target.email}` : "Environments"}
      footer={
        <>
          <Button onClick={close} disabled={save.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            disabled={!dirty || save.isPending}
            onClick={() => {
              if (!target || selected === null) return;
              save.mutate({ id: target.id, environmentIds: selected }, { onSuccess: close });
            }}
          >
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm">
        <FormError error={save.error} />

        {granted.isLoading || environments.isLoading ? (
          <LoadingBlock label="Loading access" />
        ) : (
          <>
            <div className="flex flex-col gap-2">
              {all.map((environment) => (
                <Checkbox
                  key={environment.id}
                  checked={current.includes(environment.id)}
                  onChange={(checked) => toggle(environment.id, checked)}
                  label={environment.name}
                />
              ))}
            </div>

            {current.length === 0 ? (
              <div className="rounded-md border border-warn/40 bg-warn-subtle p-2.5 text-[11px] text-warn">
                With no environments, this account can sign in and see nothing — every page
                will report that it has no access. That is a valid state, but it is rarely the
                intended one.
              </div>
            ) : null}

            <p className="text-[11px] text-text-faint">
              Applies to read-only accounts. Administrators reach every environment regardless
              of what is ticked here, and these choices take effect if the account is later
              made read-only.
            </p>
          </>
        )}
      </div>
    </Modal>
  );
}
