import { useState } from "react";
import { Navigate, useSearchParams } from "react-router";
import { useAuth } from "../auth/AuthProvider.tsx";
import { ApiError } from "../lib/api.ts";
import { Button, LoadingBlock, TextInput } from "../components/ui.tsx";
import { useOidcEnabled } from "../lib/queries.ts";

/**
 * What each refusal means, in words the person reading them can act on.
 *
 * Keyed on the short codes the callback redirects with. Anything unrecognised renders nothing
 * rather than the raw code: the query string is attacker-controllable, and echoing it would
 * put chosen text on the sign-in page.
 */
const SSO_FAILURES: Record<string, string> = {
  disabled: "Single sign-on is not switched on for this deployment.",
  provider_unreachable:
    "This server could not reach your organisation's sign-in service. An administrator can see why on the Authentication page.",
  provider_refused: "Your organisation's sign-in service refused the request.",
  expired: "That sign-in attempt timed out. Try again.",
  bad_state: "That sign-in could not be matched to this browser. Try again.",
  no_code: "Your organisation's sign-in service did not complete the sign-in.",
  exchange_failed:
    "Your organisation's sign-in service would not complete the exchange. An administrator can see why on the Authentication page.",
  token_rejected: "The response from your organisation's sign-in service could not be trusted.",
  no_account:
    "You were signed in successfully, but this platform has no account for you. Ask an administrator to create one.",
  inactive: "This account has been deactivated. Contact an administrator.",
  identity_conflict:
    "An account exists for your address but is already linked to a different identity. Contact an administrator.",
};

export function LoginPage() {
  const { user, isLoading, login, loginError, isLoggingIn } = useAuth();
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const sso = useOidcEnabled();

  /*
    A refusal from the sign-on round trip, which can only come back as a code in the URL --
    the browser left this site, authenticated elsewhere, and returned. Every code is mapped to
    a sentence here rather than being shown raw, and the detail behind it stays in the server's
    error log: a person who cannot sign in needs to know who to ask, not what the provider
    said about the redirect URI.
  */
  const ssoFailure = SSO_FAILURES[searchParams.get("sso") ?? ""] ?? null;

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

          {ssoFailure ? (
            <div
              role="alert"
              className="mb-4 rounded-md border border-danger bg-danger-subtle px-3 py-2 text-xs text-danger"
            >
              {ssoFailure}
            </div>
          ) : null}

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

        {/*
          A link, not a fetch. The provider has to be reached by navigating the browser to it,
          and an XHR here would be blocked by the provider and look like the button doing
          nothing.
        */}
        {sso.data?.enabled ? (
          <div className="mt-4 border-t border-border-base pt-4">
            <a
              href="/api/v1/auth/oidc/start"
              className="flex w-full items-center justify-center rounded-md border border-border-base px-3 py-1.5 text-sm font-medium text-text-base transition-colors hover:bg-neutral-subtle"
            >
              Sign in with your organisation account
            </a>
          </div>
        ) : null}

        <p className="mt-4 text-center text-xs text-text-faint">
          Accounts are created by an administrator, and so are password resets — there is no
          self-service signup or recovery. If you are locked out, ask an administrator to issue you a
          new password.
        </p>
      </div>
    </div>
  );
}
