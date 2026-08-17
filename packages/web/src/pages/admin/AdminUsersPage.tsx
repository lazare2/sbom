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
  useUpdateUser,
} from "../../lib/mutations.ts";
import { useUsers } from "../../lib/queries.ts";
import { readEnum, readNumber, readString, useUrlState } from "../../lib/useUrlState.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
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

  function reset() {
    setEmail("");
    setRole("user");
    setPassword("");
    setUseOwnPassword(false);
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
