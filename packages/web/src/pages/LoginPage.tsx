import { useRef, useState } from "react";
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
  /*
    Two wordings for one refusal, and the difference is a promise.

    `no_account_requested` is sent when the attempt reached the administrators' queue, so it can
    say somebody already knows. `no_account` is sent when it did not, and must not -- being told
    to wait for a notification nobody received is worse than being told to go and ask.
  */
  no_account:
    "You were signed in successfully, but this platform has no account for you. Ask an administrator to create one.",
  no_account_requested:
    "You signed in successfully, but your account on this platform has not been created yet. Administrators have been notified of your request. Wait for them, or let them know you need an account.",
  inactive: "This account has been deactivated. Contact an administrator.",
  identity_conflict:
    "An account exists for your address but is already linked to a different identity. Contact an administrator.",
};

/** Which of the two ways in is on screen. */
type Method = "directory" | "local";

const METHOD_STORAGE_KEY = "sbom.signin.method";

/**
 * The method this browser used last.
 *
 * Remembered because the two tabs have durably different populations: nearly everyone uses the
 * directory, and the handful of people holding local accounts -- administrators, and the
 * break-glass account that exists for when the directory is the thing that is broken -- would
 * otherwise click past the same tab every single time.
 *
 * Wrapped because storage throws outright in a private window rather than returning nothing,
 * and a sign-in page that cannot render is a worse failure than one that forgets a preference.
 */
function rememberedMethod(): Method {
  try {
    return window.localStorage.getItem(METHOD_STORAGE_KEY) === "local" ? "local" : "directory";
  } catch {
    return "directory";
  }
}

function remember(method: Method): void {
  try {
    window.localStorage.setItem(METHOD_STORAGE_KEY, method);
  } catch {
    // Nothing to do and nothing worth saying. The page works without it.
  }
}

export function LoginPage() {
  const { user, isLoading, login, loginError, isLoggingIn } = useAuth();
  const [searchParams] = useSearchParams();
  const sso = useOidcEnabled();

  /*
    A refusal from the sign-on round trip, which can only come back as a code in the URL --
    the browser left this site, authenticated elsewhere, and returned. Every code is mapped to
    a sentence here rather than being shown raw, and the detail behind it stays in the server's
    error log: a person who cannot sign in needs to know who to ask, not what the provider
    said about the redirect URI.
  */
  const ssoFailureCode = searchParams.get("sso");
  const ssoFailure = SSO_FAILURES[ssoFailureCode ?? ""] ?? null;

  const [chosen, setChosen] = useState<Method | null>(null);

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

  /*
    Tabs exist only where there is a second way in.

    With no connection configured, an "organisation account" tab would lead to a button that
    bounces straight back with `?sso=disabled`, so a deployment without a directory gets the
    plain password form it has always had and no tabs at all.
  */
  const hasDirectory = sso.data?.enabled === true;

  /*
    An `sso=` parameter overrides both the remembered tab and anything picked since.

    The browser is on this page *because* a directory sign-in was refused, and the sentence
    explaining why lives in that tab. Opening on the remembered tab would hide the explanation
    behind a tab the person has no reason to click, leaving a sign-in that failed for no
    visible reason.

    Keyed on whether the code is one we recognise, not on its mere presence. The query string
    is attacker-controllable, and a code with no sentence attached would otherwise move the
    tab while explaining nothing -- a chosen change to the page with no content to justify it.
  */
  const method: Method = !hasDirectory
    ? "local"
    : ssoFailure !== null
      ? "directory"
      : (chosen ?? rememberedMethod());

  function pick(next: Method): void {
    setChosen(next);
    remember(next);
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2.5">
          <span
            aria-hidden="true"
            className="grid size-8 place-items-center rounded-md bg-accent text-base text-white"
          >
            S
          </span>
          <div>
            <h1 className="text-base font-semibold text-text-base">SBOM Platform</h1>
            <p className="text-xs text-text-muted">Internal dependency inventory</p>
          </div>
        </div>

        <div className="rounded-lg border border-border-base bg-bg-raised p-5">
          <h2 className="mb-4 text-sm font-semibold text-text-base">Sign in</h2>

          {/*
            Held until the connection state is known, rather than rendering one tab and
            swapping it when the answer arrives. The swap would move focus and discard
            whatever somebody had already typed into the field that was there a moment ago.
          */}
          {sso.isLoading ? (
            <LoadingBlock label="Checking sign-in options" />
          ) : (
            <>
              {hasDirectory ? <MethodTabs method={method} onPick={pick} /> : null}

              {method === "directory" ? (
                <DirectoryPanel failure={ssoFailure} />
              ) : (
                <LocalPanel
                  login={login}
                  loginError={loginError}
                  isLoggingIn={isLoggingIn}
                  /* Shown here too: a failure on the local form is reported by the server,
                     but a *directory* failure arrives in the URL and is only explained on
                     the other tab. Without this, somebody who had defaulted to the local tab
                     after a refused SSO attempt would see no explanation anywhere -- which is
                     why an `sso=` code also forces that tab above. This is the belt to that
                     brace, for the case where they switch tabs afterwards. */
                  ssoFailure={ssoFailure}
                  /* Focused on arrival, not after a deliberate tab switch. Focusing it on a
                     switch would fight the arrow-key navigation above -- the keypress that
                     selected the tab would immediately hand focus to a text field, leaving no
                     way to arrow back. */
                  autoFocusEmail={chosen === null}
                />
              )}
            </>
          )}
        </div>

        <p className="mt-4 text-center text-xs text-text-faint">
          Accounts are created by an administrator, and so are password resets — there is no
          self-service signup or recovery. If you are locked out, ask an administrator to issue you
          a new password.
        </p>
      </div>
    </div>
  );
}

/**
 * The two ways in.
 *
 * A real tablist rather than two styled buttons, because arrow-key navigation between tabs is
 * what a screen reader announces as available the moment `role="tab"` appears — and offering it
 * without implementing it is worse than not claiming it at all.
 */
function MethodTabs({ method, onPick }: { method: Method; onPick: (m: Method) => void }) {
  const tabs: { id: Method; label: string }[] = [
    { id: "directory", label: "Organisation account" },
    { id: "local", label: "Local account" },
  ];
  const refs = useRef<Record<Method, HTMLButtonElement | null>>({ directory: null, local: null });

  function onKeyDown(event: React.KeyboardEvent): void {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const next: Method = method === "directory" ? "local" : "directory";
    onPick(next);
    refs.current[next]?.focus();
  }

  return (
    <div
      role="tablist"
      aria-label="Sign-in method"
      aria-orientation="horizontal"
      onKeyDown={onKeyDown}
      className="mb-4 flex gap-1 rounded-md bg-bg-subtle p-1"
    >
      {tabs.map((tab) => (
        <button
          key={tab.id}
          ref={(el) => {
            refs.current[tab.id] = el;
          }}
          type="button"
          role="tab"
          id={`signin-tab-${tab.id}`}
          aria-selected={method === tab.id}
          aria-controls={`signin-panel-${tab.id}`}
          /* Only the selected tab is in the tab order, which is what makes the arrow keys
             above the way between them rather than a second, redundant path. */
          tabIndex={method === tab.id ? 0 : -1}
          onClick={() => onPick(tab.id)}
          className={`flex-1 rounded px-2.5 py-1.5 text-xs font-medium transition-colors ${
            method === tab.id
              ? "bg-bg-raised text-text-base shadow-sm"
              : "text-text-muted hover:text-text-base"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

function DirectoryPanel({ failure }: { failure: string | null }) {
  return (
    <div role="tabpanel" id="signin-panel-directory" aria-labelledby="signin-tab-directory">
      {failure ? (
        <div
          role="alert"
          className="mb-4 rounded-md border border-danger bg-danger-subtle px-3 py-2 text-xs text-danger"
        >
          {failure}
        </div>
      ) : null}

      {/*
        A link, not a fetch. The provider has to be reached by navigating the browser to it,
        and an XHR here would be blocked by the provider and look like the button doing
        nothing.
      */}
      <a
        href="/api/v1/auth/oidc/start"
        className="flex w-full items-center justify-center rounded-md bg-accent px-3 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
      >
        Sign in with your organisation account
      </a>

      <p className="mt-3 text-xs text-text-muted">
        Uses the account you already sign in to at work. You may not be asked for a password if
        you are signed in there already.
      </p>
    </div>
  );
}

function LocalPanel({
  login,
  loginError,
  isLoggingIn,
  ssoFailure,
  autoFocusEmail,
}: {
  login: (email: string, password: string) => Promise<unknown>;
  loginError: unknown;
  isLoggingIn: boolean;
  ssoFailure: string | null;
  autoFocusEmail: boolean;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

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
    <div role="tabpanel" id="signin-panel-local" aria-labelledby="signin-tab-local">
      <form onSubmit={handleSubmit} noValidate>
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
              autoFocus={autoFocusEmail}
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
    </div>
  );
}
