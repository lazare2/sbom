import { useState } from "react";
import type { AccessRequest, UserSummary } from "@sbom/shared";
import { sortDirections, userSort } from "@sbom/shared";
import { useServerSort } from "../../lib/useSort.ts";
import { useAuth } from "../../auth/AuthProvider.tsx";
import { formatDate, formatRelative } from "../../lib/format.ts";
import {
  useCreateUser,
  useDeleteUser,
  useResetUserPassword,
  useSetSignInMethod,
  useSettleAccessRequest,
  useSetUserApplicationAccess,
  useSetUserEnvironments,
  useUpdateUser,
} from "../../lib/mutations.ts";
import {
  useAccessRequests,
  useApplicationAccessPreview,
  useEnvironments,
  useGrantableScope,
  useUserApplicationAccess,
  useUserEnvironments,
  useOidcEnabled,
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
  /*
    The access request this create was started from, if any.

    Held so the request can be resolved with the id of the account that answered it, which is
    what makes "who did we let in off the back of this" answerable later. Null for an ordinary
    create from the New account button.
  */
  const [createFrom, setCreateFrom] = useState<AccessRequest | null>(null);
  const [resetTarget, setResetTarget] = useState<UserSummary | null>(null);
  const [accessTarget, setAccessTarget] = useState<UserSummary | null>(null);
  const [methodTarget, setMethodTarget] = useState<UserSummary | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<UserSummary | null>(null);
  /** Shown once, after a create or reset. Cleared when the modal closes. */
  const [issued, setIssued] = useState<{ email: string; password: string } | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  /*
    Confirmation for a create that produced no credential to display.

    A directory account has no password, so the modal has nothing to show and closes -- which,
    on a paginated table where the new row may be several pages away, would otherwise leave an
    administrator with no evidence anything happened at all. Dismissed by hand rather than on a
    timer: it is the only acknowledgement of the action, and acknowledgements that vanish on
    their own get missed by exactly the people who looked away to check something.
  */
  const [notice, setNotice] = useState<string | null>(null);

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
  const settle = useSettleAccessRequest();

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

  /**
   * What happens once an account exists, however it was created.
   *
   * Two jobs, and both are about not losing the thread. A directory account yields no
   * credential, so without the notice the modal would close on silence. And a create started
   * from the queue has to close the request it answered -- the queue does drain itself when
   * that person next signs in, but leaving the row open until then means an administrator who
   * looks before that sees work they have already done.
   */
  function onCreated(created: { id: string; email: string; hadPassword: boolean }) {
    if (!created.hadPassword) {
      setNotice(
        `Created ${created.email}. They sign in with their organisation account, so there is no password to hand over.`,
      );
    }
    if (createFrom) {
      // Fire and forget, deliberately. The account is the thing that mattered and it exists;
      // a failure to tidy the queue must not be reported as a failure to create the user.
      settle.mutate({ id: createFrom.id, action: "resolve", userId: created.id });
      setCreateFrom(null);
    }
  }

  return (
    <>
      <AccessRequestsCard
        onCreateAccount={(request) => {
          setNotice(null);
          setCreateFrom(request);
          setCreateOpen(true);
        }}
      />

      <Card>
        <CardHeader
          title="Accounts"
          subtitle="Sign-in identifiers are usernames, not mailboxes — the platform never sends email. Passwords are issued here and handed over directly."
          actions={
            <Button
              variant="primary"
              size="sm"
              onClick={() => {
                // Cleared, or a create started from the queue and cancelled would silently
                // resolve the next request made from this button.
                setCreateFrom(null);
                setNotice(null);
                setCreateOpen(true);
              }}
            >
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

        {notice ? (
          <div className="px-4 pt-3">
            <div
              role="status"
              className="flex items-start justify-between gap-3 rounded-md border border-ok bg-ok-subtle px-3 py-2 text-xs text-ok"
            >
              <span>{notice}</span>
              <button
                type="button"
                onClick={() => setNotice(null)}
                className="shrink-0 font-medium underline"
              >
                Dismiss
              </button>
            </div>
          </div>
        ) : null}

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
                          {/*
                            How this account signs in, on the row rather than hidden in a
                            dialog. "Why can this colleague not use single sign-on" was a
                            real question with no answer on any screen -- the account had
                            been created before the box existed, and nothing said so.
                          */}
                          {" "}
                          <Badge
                            tone={u.authProvider === "local" ? "neutral" : "info"}
                            title={
                              u.authProvider === "local"
                                ? "Signs in with a password issued here."
                                : "Signs in through the organisation directory. No password is held."
                            }
                          >
                            {u.authProvider === "local" ? "password" : "SSO"}
                          </Badge>
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
                            {/* Hidden rather than disabled for a directory account: there is
                                no password to reset and the API refuses it, so offering the
                                button at all would be an action that can only fail. */}
                            {u.authProvider === "local" ? (
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
                            ) : null}
                            <Button
                              size="sm"
                              onClick={() => {
                                setIssued(null);
                                setActionError(null);
                                setMethodTarget(u);
                              }}
                            >
                              Sign-in method
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

      {/*
        Keyed on where the create came from, so the form's initial state is seeded by its
        initialiser rather than patched by an effect after the fact. An effect would have to
        decide whether to overwrite what somebody had already typed, and both answers to that
        are wrong in one case or the other.
      */}
      <CreateUserModal
        key={createFrom?.id ?? "blank"}
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          setCreateFrom(null);
          setIssued(null);
        }}
        prefill={createFrom}
        onCreated={onCreated}
        issued={issued}
        onIssued={setIssued}
      />

      <SignInMethodModal
        target={methodTarget}
        onClose={() => {
          setMethodTarget(null);
          setIssued(null);
        }}
        issued={issued}
        onIssued={setIssued}
        onConverted={(email, method) =>
          setNotice(
            method === "directory"
              ? `${email} now signs in with their organisation account. Their password no longer works and their sessions have been ended.`
              : `${email} now signs in with a password. Hand over the one shown in the dialog.`,
          )
        }
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
  prefill,
  onCreated,
  issued,
  onIssued,
}: {
  open: boolean;
  onClose: () => void;
  /**
   * The access request this create answers, when it was started from the queue.
   *
   * Seeds the identifier and ticks the directory box, because the alternative is reading an
   * address off the screen and typing it back in — and a typo there creates an account that
   * the person it was meant for can never sign in to, with nothing on either screen to show
   * why. The provider already told us the exact string; this uses it.
   */
  prefill: AccessRequest | null;
  onCreated: (created: { id: string; email: string; hadPassword: boolean }) => void;
  issued: { email: string; password: string } | null;
  onIssued: (v: { email: string; password: string }) => void;
}) {
  const createUser = useCreateUser();
  const [email, setEmail] = useState(prefill?.email ?? "");
  const [role, setRole] = useState<"admin" | "user">("user");
  const [password, setPassword] = useState("");
  const [useOwnPassword, setUseOwnPassword] = useState(false);
  const [directory, setDirectory] = useState(prefill !== null);
  const sso = useOidcEnabled();
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
    // Back to where this instance started, which is the prefilled state when it was opened
    // from a request -- not blank. Clearing to blank would discard the address on a cancel.
    setEmail(prefill?.email ?? "");
    setRole("user");
    setPassword("");
    setUseOwnPassword(false);
    setDirectory(prefill !== null);
    setEnvironmentIds(null);
    createUser.reset();
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      const result = await createUser.mutateAsync({
        email,
        role,
        authProvider: directory ? "oidc" : "local",
        // Meaningless for a directory account, which gets no password to change. The server
        // forces it off regardless; sending false keeps the request honest about intent.
        mustChangePassword: !directory,
        ...(!directory && useOwnPassword && password ? { password } : {}),
        ...(environmentIds === null ? {} : { environmentIds }),
      });
      /*
        Two outcomes, and the modal used to handle only one.

        A local account yields a password that is shown once and never again, so the modal
        stays open on it -- auto-dismissing a credential somebody has to copy would lose it for
        good. A directory account yields nothing, and the old code simply did not call
        `onIssued`, which left the modal sitting on the filled-in form with no error and no
        acknowledgement. The account had been created; nothing said so.

        So the no-credential path closes, and the page it closes onto says what happened.
      */
      if (result.temporaryPassword !== undefined) {
        onIssued({ email: result.user.email, password: result.temporaryPassword });
        onCreated({ id: result.user.id, email: result.user.email, hadPassword: true });
      } else {
        onCreated({ id: result.user.id, email: result.user.email, hadPassword: false });
        reset();
        onClose();
      }
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
              disabled={
                !email ||
                createUser.isPending ||
                (!directory && useOwnPassword && password.length < 12)
              }
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

          {/*
            Offered only where single sign-on is actually configured. A choice that cannot
            work is worse than an absent one: it produces an account nobody can sign in to,
            and nothing on this screen would say why.
          */}
          {sso.data?.enabled ? (
            <label className="flex cursor-pointer items-center gap-2 text-sm text-text-muted select-none">
              <input
                type="checkbox"
                checked={directory}
                onChange={(e) => setDirectory(e.target.checked)}
                className="size-3.5 accent-[var(--accent)]"
              />
              Signs in with their organisation account
            </label>
          ) : null}

          {directory ? (
            <p className="text-xs text-text-faint">
              No password is created. They sign in through the organisation provider, and the
              account is matched to their identity the first time they do. Grant projects as
              usual afterwards.
            </p>
          ) : (
            <label className="flex cursor-pointer items-center gap-2 text-sm text-text-muted select-none">
              <input
                type="checkbox"
                checked={useOwnPassword}
                onChange={(e) => setUseOwnPassword(e.target.checked)}
                className="size-3.5 accent-[var(--accent)]"
              />
              Set the password myself instead of generating one
            </label>
          )}

          {!directory && useOwnPassword ? (
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

function SignInMethodModal({
  target,
  onClose,
  issued,
  onIssued,
  onConverted,
}: {
  target: UserSummary | null;
  onClose: () => void;
  issued: { email: string; password: string } | null;
  onIssued: (v: { email: string; password: string }) => void;
  onConverted: (email: string, method: "local" | "directory") => void;
}) {
  const convert = useSetSignInMethod();
  const sso = useOidcEnabled();

  const toDirectory = target?.authProvider === "local";
  const method = toDirectory ? "directory" : "local";

  /*
    Converting to the directory needs one to exist. The server refuses it too -- an account
    with no password and no provider cannot sign in at all -- but a disabled button that says
    why is better than a request that comes back as an error.
  */
  const blocked = toDirectory && sso.data?.enabled !== true;

  async function run() {
    if (!target) return;
    try {
      const result = await convert.mutateAsync({ id: target.id, method });
      if (result.temporaryPassword !== undefined) {
        onIssued({ email: result.user.email, password: result.temporaryPassword });
      } else {
        // Nothing to hand over, so the dialog has no second step to show. Same reasoning as
        // creating a directory account: it closes, and the page says what happened.
        onConverted(result.user.email, method);
        convert.reset();
        onClose();
        return;
      }
      onConverted(result.user.email, method);
    } catch {
      // Rendered from the mutation's error state.
    }
  }

  return (
    <Modal
      open={target !== null}
      onClose={() => {
        convert.reset();
        onClose();
      }}
      title={issued ? "Password issued" : "Change sign-in method"}
      footer={
        issued ? (
          <Button
            variant="primary"
            onClick={() => {
              convert.reset();
              onClose();
            }}
          >
            Done
          </Button>
        ) : (
          <>
            <Button
              onClick={() => {
                convert.reset();
                onClose();
              }}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={() => void run()}
              disabled={convert.isPending || blocked}
            >
              {convert.isPending
                ? "Changing…"
                : toDirectory
                  ? "Switch to organisation account"
                  : "Switch to a password"}
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
        <div className="space-y-3 text-sm text-text-muted">
          <FormError error={convert.error} />

          <p>
            <strong className="text-text-base">{target?.email}</strong> currently signs in{" "}
            {toDirectory ? "with a password issued here." : "through the organisation directory."}
          </p>

          {toDirectory ? (
            <>
              <p>
                Switching to the organisation account{" "}
                <strong className="text-text-base">discards their password</strong>. They sign in
                through the provider from then on, and the account is matched to their directory
                identity the first time they do — by the address above, so it has to be the one
                the directory knows them by.
              </p>
              <p>
                Their groups, projects and environments are untouched. Every session they have
                open now is ended, because the credential they were admitted on no longer applies.
              </p>
              {blocked ? (
                <p className="text-danger">
                  Single sign-on is not switched on, so this account would have no way to sign in.
                  Configure it on the Authentication page first.
                </p>
              ) : null}
            </>
          ) : (
            <>
              <p>
                Switching back to a password{" "}
                <strong className="text-text-base">issues a new one</strong>, shown once on the
                next screen, which they must change at first sign-in. The link to their directory
                identity is cleared.
              </p>
              <p>
                Their grants are untouched, and their open sessions are ended. This is the way back
                in if the directory itself is the thing that has broken.
              </p>
            </>
          )}
        </div>
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
      // A directory account is created with no password, so there is no credential to
      // hand over and nothing for the modal to show.
      if (result.temporaryPassword !== undefined) {
        onIssued({ email: result.user.email, password: result.temporaryPassword });
      }
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

  /*
    Scored against the boxes as they stand rather than against the last save. Both axes are
    sent, including the environment ticks, because the answer is their intersection and
    scoring the application axis alone reports applications the account cannot open.
  */
  const preview = useApplicationAccessPreview(
    target?.id ?? null,
    {
      restricted: currentRestricted,
      groupIds: currentGroups,
      applicationIds: currentApps,
      environmentIds: currentEnvs,
    },
    !loading,
  );

  const blocked = preview.data?.blockedByEnvironment ?? [];
  const blockedTotal = blocked.reduce((sum, gap) => sum + gap.applicationCount, 0);

  function toggle(list: string[], id: string, on: boolean): string[] {
    return on ? [...list, id] : list.filter((entry) => entry !== id);
  }

  /*
    Widens the estate rather than expanding the group into direct application grants. A direct
    grant follows nothing -- an application added to the group next month would not appear, and
    nobody could later tell which of the account's direct grants were deliberate and which were
    expanded here -- so granting the environment is the change that leaves the group doing the
    job it was granted for.
  */
  function grantBlockedEnvironments() {
    setEnvIds([...new Set([...currentEnvs, ...blocked.map((gap) => gap.environmentId)])]);
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
              an administrator whether they have granted three services or thirty.

              Scored live, and across both axes. The stored figure only moved after the write,
              which made a grant that was working and a grant that had failed look identical
              until the modal was reopened; and it ignored the environment axis, so it could
              report twelve applications to an account that could open none of them.
            */}
            {preview.data ? (
              <div className="space-y-2 border-t border-border-base pt-3 text-[11px] text-text-muted">
                <p>
                  Will reach{" "}
                  <strong className="text-text-base">
                    {preview.data.reachableApplicationCount}
                  </strong>{" "}
                  {preview.data.reachableApplicationCount === 1 ? "application" : "applications"}.
                </p>

                {/*
                  An empty group is worth its own line because the grant looks identical to a
                  working one: a box is ticked, a row is written, and the reach is zero. Without
                  saying so, the next thing anybody investigates is permissions, when the fix is
                  group membership.
                */}
                {preview.data.emptyGroups.length > 0 ? (
                  <p className="text-danger">
                    {preview.data.emptyGroups.map((group) => group.name).join(", ")}{" "}
                    {preview.data.emptyGroups.length === 1 ? "contains" : "contain"} no
                    applications, so granting{" "}
                    {preview.data.emptyGroups.length === 1 ? "it" : "them"} reaches nothing. Add
                    applications to the group, or grant them directly.
                  </p>
                ) : null}

                {blocked.length > 0 ? (
                  <div className="space-y-1.5 text-danger">
                    <p>
                      {blockedTotal}{" "}
                      {blockedTotal === 1 ? "granted application sits" : "granted applications sit"}{" "}
                      in {blocked.map((gap) => gap.environmentName).join(", ")}, which this
                      account cannot reach. The two restrictions compose by intersection, so
                      those stay invisible however they are granted.
                    </p>
                    <Button size="sm" onClick={grantBlockedEnvironments}>
                      {blocked.length === 1
                        ? "Also grant that environment"
                        : "Also grant those environments"}
                    </Button>
                  </div>
                ) : null}
              </div>
            ) : null}
          </>
        )}
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------

/**
 * People the directory authenticated who have no account here.
 *
 * Pre-provisioning is the security posture and stays that way: an identity the directory
 * vouches for is still refused until somebody creates an account. What this fixes is the other
 * half of that -- the refusal used to leave no trace, so whether an administrator ever heard
 * about it depended on the refused person speaking up. Modelled on applications awaiting
 * confirmation, for the same reason: an event the platform cannot act on by itself should
 * become a row somebody drains, not a dead end.
 *
 * Only single sign-on feeds this. A failed password login would mean writing a string typed in
 * by somebody who proved nothing, which would turn this into an unauthenticated write endpoint
 * -- and deduplication cannot bound that, because the string would be theirs to vary. Every row
 * here came out of a token the provider signed.
 *
 * Lives on this page rather than behind a tab of its own because the resolution is "create an
 * account", which is here. The badge on the admin nav is what makes it findable without one.
 */
function AccessRequestsCard({
  onCreateAccount,
}: {
  onCreateAccount: (request: AccessRequest) => void;
}) {
  const requests = useAccessRequests("pending");
  const settle = useSettleAccessRequest();
  const [error, setError] = useState<unknown>(null);

  const data = requests.data;
  const pending = data?.requests ?? [];

  // Nothing at all while the first load is in flight. A placeholder above the Accounts table
  // would push it down the page on every visit to say nothing.
  if (requests.isLoading) return null;
  if (requests.error) {
    return (
      <Card>
        <CardHeader title="Access requests" />
        <div className="p-4 pt-0">
          <ErrorBanner error={requests.error} onRetry={() => void requests.refetch()} />
        </div>
      </Card>
    );
  }

  /*
    Only dismissal happens from here. Resolution is a side effect of creating the account,
    because a button that marked a request resolved without producing anything would be a
    button for lying to the next administrator who reads the queue.
  */
  function dismiss(request: AccessRequest) {
    setError(null);
    settle.mutate(
      { id: request.id, action: "dismiss" },
      { onError: (err) => setError(err) },
    );
  }

  return (
    <Card className="mb-4">
      <CardHeader
        title={
          pending.length > 0 ? `Access requests (${pending.length})` : "Access requests"
        }
        subtitle="Recorded when somebody signs in through your organisation's directory and this platform has no account for them."
      />

      {error ? (
        <div className="px-4 pt-3">
          <FormError error={error} />
        </div>
      ) : null}

      {pending.length === 0 ? (
        <div className="px-4 pb-4 text-xs">
          {/*
            Two readings of an empty queue, and they must not look alike.

            With sign-on enabled, empty means nobody has been turned away -- a real clean
            state. With it switched off, nothing can ever arrive here, and the same empty list
            would read as reassurance when in fact nothing is being watched.
          */}
          {data?.signOnEnabled ? (
            <p className="text-text-faint">Nobody is waiting for an account.</p>
          ) : (
            <p className="text-warn">
              Single sign-on is switched off, so refused sign-ins are not recorded here. This
              list being empty does not mean nobody has tried.
            </p>
          )}
        </div>
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <Tr>
                <Th>Person</Th>
                <Th align="right">Attempts</Th>
                <Th>First tried</Th>
                <Th>Last tried</Th>
                <Th />
              </Tr>
            </thead>
            <tbody>
              {pending.map((request) => (
                <Tr key={request.id}>
                  <Td>
                    <div className="font-medium text-text-base">
                      {/*
                        Either may be absent: `email` arrives only where that claim was
                        consented to, and some directories send no name. Falling back through
                        both and then saying so plainly beats rendering an empty cell that
                        reads as a bug.
                      */}
                      {request.displayName ?? request.email ?? "Unidentified directory account"}
                    </div>
                    {request.displayName && request.email ? (
                      <div className="text-xs text-text-muted">{request.email}</div>
                    ) : null}
                    {request.email === null ? (
                      <div className="text-xs text-warn">
                        The provider sent no address — ask them for it before creating an account.
                      </div>
                    ) : null}
                  </Td>
                  <Td align="right">
                    {/* Toned once it stops being a single attempt: somebody who has tried
                        repeatedly has been locked out long enough to keep trying. */}
                    <Badge tone={request.attempts > 1 ? "warn" : "neutral"}>
                      {request.attempts}
                    </Badge>
                  </Td>
                  <Td title={formatDate(request.firstSeenAt)}>
                    {formatRelative(request.firstSeenAt)}
                  </Td>
                  <Td title={formatDate(request.lastSeenAt)}>
                    {formatRelative(request.lastSeenAt)}
                  </Td>
                  <Td align="right">
                    <div className="flex justify-end gap-1.5">
                      <Button
                        size="sm"
                        variant="primary"
                        /* Without an address there is nothing to match the account against,
                           so creating one here would produce something they still could not
                           sign in to. */
                        disabled={request.email === null || settle.isPending}
                        onClick={() => onCreateAccount(request)}
                      >
                        Create account
                      </Button>
                      <Button
                        size="sm"
                        disabled={settle.isPending}
                        onClick={() => dismiss(request)}
                      >
                        Dismiss
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
  );
}
