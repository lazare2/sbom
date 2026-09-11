import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useAuth } from "../auth/AuthProvider.tsx";
import { useChangePassword } from "../lib/mutations.ts";
import { Button, Card, CardHeader, FormError, FormRow, PageHeader, TextInput } from "../components/ui.tsx";

const MIN_LENGTH = 12;

/**
 * Change your own password.
 *
 * Serves two situations with one form. Normally it is a voluntary action
 * reachable from the header. When `mustChangePassword` is set — an admin issued
 * this credential, so someone other than its owner has seen it — the router
 * pins the user here and the API refuses every other authenticated route until
 * it clears.
 *
 * Rendered outside the application shell in both cases, because in the forced one it
 * cannot afford to depend on anything the shell loads: the environment list the layout
 * fetches is among the routes refused while the flag is set, so a version of this page
 * nested inside it showed that refusal instead of the form, with no way forward.
 */
export function ChangePasswordPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const changePassword = useChangePassword();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [done, setDone] = useState(false);

  const forced = user?.mustChangePassword === true;

  const tooShort = newPassword.length > 0 && newPassword.length < MIN_LENGTH;
  const mismatch = confirmPassword.length > 0 && confirmPassword !== newPassword;
  const sameAsCurrent = newPassword.length > 0 && newPassword === currentPassword;

  const canSubmit =
    currentPassword.length > 0 &&
    newPassword.length >= MIN_LENGTH &&
    confirmPassword === newPassword &&
    !sameAsCurrent &&
    !changePassword.isPending;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    try {
      await changePassword.mutateAsync({ currentPassword, newPassword });
      setDone(true);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch {
      // Surfaced from the mutation's error state.
    }
  }

  /*
    Into the application, once the change has actually taken effect.

    Keyed on `forced` going false rather than on the submission succeeding, because those are
    not the same moment: the mutation invalidates the session query, and until the refetch
    lands `mustChangePassword` is still set — so navigating on success alone would race the
    refetch and be bounced straight back here by the router.

    This page no longer sits inside the application shell, so there is no navigation on screen
    to fall back on. Without this, a person who successfully changed their password would be
    left looking at a confirmation message with nowhere to go.
  */
  useEffect(() => {
    if (!done || forced) return;
    const timer = setTimeout(() => navigate("/", { replace: true }), 1200);
    return () => clearTimeout(timer);
  }, [done, forced, navigate]);

  return (
    /* Its own container in both cases now — there is no surrounding layout to provide one. */
    <div className="mx-auto max-w-lg px-4 py-10">
      <PageHeader
        title={forced ? "Change your password" : "Change password"}
        subtitle={
          forced
            ? `This password was issued by an administrator, so it is known to someone other than you. Choose your own before continuing as ${user?.email ?? ""}.`
            : `Signed in as ${user?.email ?? ""}`
        }
      />

      <Card>
        <CardHeader
          title="New password"
          subtitle={`At least ${MIN_LENGTH} characters. Length matters more than punctuation — a memorable phrase beats a short password with symbols in it.`}
        />

        <form onSubmit={handleSubmit} className="space-y-4 px-4 py-4" noValidate>
          {done ? (
            <div
              role="status"
              className="rounded-md border border-ok bg-ok-subtle px-3 py-2 text-xs text-ok"
            >
              Password changed. Your other sessions have been signed out.
            </div>
          ) : null}

          <FormError error={changePassword.error} />

          <FormRow
            label={forced ? "Password your administrator gave you" : "Current password"}
            htmlFor="current-password"
          >
            <TextInput
              id="current-password"
              type="password"
              value={currentPassword}
              onChange={setCurrentPassword}
              autoComplete="current-password"
              autoFocus
              required
            />
          </FormRow>

          <FormRow
            label="New password"
            htmlFor="new-password"
            error={
              tooShort
                ? `Must be at least ${MIN_LENGTH} characters`
                : sameAsCurrent
                  ? "Must be different from your current password"
                  : undefined
            }
          >
            <TextInput
              id="new-password"
              type="password"
              value={newPassword}
              onChange={setNewPassword}
              autoComplete="new-password"
              required
            />
          </FormRow>

          <FormRow
            label="Confirm new password"
            htmlFor="confirm-password"
            error={mismatch ? "The two passwords do not match" : undefined}
          >
            <TextInput
              id="confirm-password"
              type="password"
              value={confirmPassword}
              onChange={setConfirmPassword}
              autoComplete="new-password"
              required
            />
          </FormRow>

          <div className="flex items-center gap-2 pt-1">
            <Button type="submit" variant="primary" disabled={!canSubmit}>
              {changePassword.isPending ? "Changing…" : "Change password"}
            </Button>
            {forced ? (
              /*
                The way out of a screen that otherwise has none.

                On the forced path every other route is refused, so without this a person who
                mistypes the password their administrator sent them — or who is signed in as
                the wrong account — has no action available but to clear their cookies. It is
                worded as a way back to the sign-in page rather than as an escape, because
                that is what it is for.
              */
              <Button
                onClick={() => {
                  void logout().then(() => navigate("/login", { replace: true }));
                }}
              >
                Sign out instead
              </Button>
            ) : (
              <Button onClick={() => navigate(-1)}>Cancel</Button>
            )}
          </div>
        </form>
      </Card>
    </div>
  );
}
