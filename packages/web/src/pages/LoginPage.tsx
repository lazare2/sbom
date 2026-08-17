import { useState } from "react";
import { Navigate, useSearchParams } from "react-router";
import { useAuth } from "../auth/AuthProvider.tsx";
import { ApiError } from "../lib/api.ts";
import { Button, LoadingBlock, TextInput } from "../components/ui.tsx";

export function LoginPage() {
  const { user, isLoading, login, loginError, isLoggingIn } = useAuth();
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  // Only same-origin paths are honoured, so `?from=https://evil.example` cannot
  // turn the login page into an open redirect.
  const from = searchParams.get("from");
  const redirectTo = from && from.startsWith("/") && !from.startsWith("//") ? from : "/";

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingBlock label="Checking your session" />
      </div>
    );
  }
  if (user) return <Navigate to={redirectTo} replace />;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    try {
      await login(email, password);
    } catch {
      // Rendered from `loginError`; swallowed here so the rejection is not
      // reported as an unhandled promise.
    }
  }

  /**
   * The server deliberately returns the same generic message for a wrong password
   * and an unknown account, so this surfaces whatever it says rather than trying
   * to interpret it. The one case worth special-casing is a deactivated account
   * (403), where the user needs to know that retrying will not help.
   */
  const errorMessage =
    loginError instanceof ApiError
      ? loginError.message
      : loginError
        ? "Could not sign in. Please try again."
        : null;

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2.5">
          <span aria-hidden="true" className="grid size-8 place-items-center rounded-md bg-accent text-base text-white">
            S
          </span>
          <div>
            <h1 className="text-base font-semibold text-text-base">SBOM Platform</h1>
            <p className="text-xs text-text-muted">Internal dependency inventory</p>
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-lg border border-border-base bg-bg-raised p-5"
          noValidate
        >
          <h2 className="mb-4 text-sm font-semibold text-text-base">Sign in</h2>

          {errorMessage ? (
            <div
              role="alert"
              className="mb-4 rounded-md border border-danger bg-danger-subtle px-3 py-2 text-xs text-danger"
            >
              {errorMessage}
            </div>
          ) : null}

          <div className="space-y-3">
            <div>
              <label htmlFor="email" className="mb-1 block text-xs font-medium text-text-muted">
                Email
              </label>
              {/*
                `type="text"`, not `type="email"`. These identifiers are
                usernames written in email form and the platform never sends
                mail to them, so the browser's RFC validation would block a
                perfectly valid account like `admin@localhost`.
              */}
              <TextInput
                id="email"
                type="text"
                value={email}
                onChange={setEmail}
                autoComplete="username"
                required
                autoFocus
                placeholder="you@example.com"
              />
            </div>

            <div>
              <label htmlFor="password" className="mb-1 block text-xs font-medium text-text-muted">
                Password
              </label>
              <TextInput
                id="password"
                type="password"
                value={password}
                onChange={setPassword}
                autoComplete="current-password"
                required
              />
            </div>
          </div>

          <div className="mt-5">
            <Button type="submit" variant="primary" disabled={isLoggingIn || !email || !password}>
              {isLoggingIn ? "Signing in…" : "Sign in"}
            </Button>
          </div>

        </form>

        <p className="mt-4 text-center text-xs text-text-faint">
          Accounts are created by an administrator, and so are password resets — there is no
          self-service signup or recovery. If you are locked out, ask an administrator to issue you a
          new password.
        </p>
      </div>
    </div>
  );
}
