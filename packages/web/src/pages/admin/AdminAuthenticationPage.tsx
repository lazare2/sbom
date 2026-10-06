import { useEffect, useState } from "react";
import { OIDC_CALLBACK_PATH, type OidcDiagnosis } from "@sbom/shared";
import { useOidcSettings } from "../../lib/queries.ts";
import { useSetOidcConnection, useTestOidcConnection } from "../../lib/mutations.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
  ErrorBanner,
  FormError,
  FormRow,
  LoadingBlock,
  Mono,
  PageHeader,
  TextInput,
} from "../../components/ui.tsx";

/**
 * How people sign in.
 *
 * The switch lives here rather than on Configuration because the only information that makes
 * flipping it meaningful is on this page: whether the provider answers, and whether it accepts
 * the credentials. A switch on one screen and the evidence for it on another is how a
 * deployment ends up with single sign-on enabled and nobody able to use it.
 *
 * Local password accounts are unaffected by everything here and keep working alongside it.
 */

export function AdminAuthenticationPage() {
  return (
    <div className="space-y-4">
      <PageHeader
        title="Authentication"
        subtitle="Let people sign in with their organisation account, alongside local passwords."
      />
      <SingleSignOnCard />
    </div>
  );
}

// ---- single sign-on ----

function SingleSignOnCard() {
  const settings = useOidcSettings();
  const save = useSetOidcConnection();
  const test = useTestOidcConnection();

  const stored = settings.data?.connection ?? null;

  const [issuerUrl, setIssuerUrl] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [groupName, setGroupName] = useState("");
  const [expiresOn, setExpiresOn] = useState("");
  const [enabled, setEnabled] = useState(false);

  /*
    Seeded when the connection arrives and re-seeded if it changes underneath, never on every
    render -- an in-flight refetch would otherwise overwrite what somebody is typing. The
    secret is deliberately not seeded: there is nothing to seed it with, because no endpoint
    returns it.
  */
  useEffect(() => {
    if (!stored) return;
    setIssuerUrl(stored.issuerUrl);
    setClientId(stored.clientId);
    setGroupName(stored.securityGroupName ?? "");
    setExpiresOn(stored.secretExpiresOn ?? "");
    setEnabled(stored.enabled);
  }, [stored]);

  const secretAvailable = clientSecret.trim() !== "" || (stored?.clientSecretConfigured ?? false);
  const complete = issuerUrl.trim() !== "" && clientId.trim() !== "" && secretAvailable;

  const changed =
    stored === null
      ? issuerUrl.trim() !== "" || clientId.trim() !== "" || clientSecret.trim() !== ""
      : issuerUrl !== stored.issuerUrl ||
        clientId !== stored.clientId ||
        clientSecret.trim() !== "" ||
        groupName !== (stored.securityGroupName ?? "") ||
        expiresOn !== (stored.secretExpiresOn ?? "") ||
        enabled !== stored.enabled;

  const body = {
    issuerUrl: issuerUrl.trim(),
    clientId: clientId.trim(),
    ...(clientSecret.trim() === "" ? {} : { clientSecret: clientSecret.trim() }),
    enabled,
    ...(groupName.trim() === "" ? {} : { securityGroupName: groupName.trim() }),
    ...(expiresOn.trim() === "" ? {} : { secretExpiresOn: expiresOn.trim() }),
  };

  async function onSave() {
    await save.mutateAsync(body);
    // Cleared only once the write succeeded. Wiping it on submit would lose the credential
    // if the save were rejected, and the provider shows it once.
    setClientSecret("");
  }

  /*
    The URI the provider redirects back to, as this browser sees it.

    Shown before any test has run, because it is the string somebody has to give their
    directory team and they should not have to run a test to learn it. The server builds the
    real one from PUBLIC_URL, so a mismatch between the two is itself a finding -- see below.
  */
  const browserRedirectUri = `${window.location.origin}${OIDC_CALLBACK_PATH}`;
  const verdict = test.data ?? settings.data?.lastTest ?? null;

  return (
    <Card>
      <CardHeader
        title="Single sign-on (OpenID Connect)"
        subtitle="Works with any OpenID Connect provider — Microsoft Entra ID, Keycloak, Okta — because every endpoint is read from the issuer's own discovery document."
      />

      {settings.isLoading ? (
        <LoadingBlock />
      ) : settings.error ? (
        <ErrorBanner error={settings.error} onRetry={() => void settings.refetch()} />
      ) : (
        <div className="space-y-4 p-4 pt-0">
          <FormRow
            label="Redirect URI to register with the provider"
            hint="Providers compare this exactly. A mismatch is rejected in the browser, where this platform never sees it."
          >
            <Mono>{browserRedirectUri}</Mono>
          </FormRow>

          <FormRow
            label="Issuer URL"
            htmlFor="oidc-issuer"
            hint="For Entra ID: https://login.microsoftonline.com/<tenant-id>/v2.0 — no trailing slash."
          >
            <TextInput
              id="oidc-issuer"
              value={issuerUrl}
              onChange={setIssuerUrl}
              placeholder="https://login.microsoftonline.com/<tenant-id>/v2.0"
            />
          </FormRow>

          <FormRow label="Application (client) ID" htmlFor="oidc-client-id">
            <TextInput id="oidc-client-id" value={clientId} onChange={setClientId} />
          </FormRow>

          <FormRow
            label="Client secret"
            htmlFor="oidc-secret"
            hint={
              stored?.clientSecretConfigured
                ? "A secret is stored. Leave this blank to keep it; it is never shown again."
                : "The secret value shown once at creation — not the secret ID beside it."
            }
          >
            <TextInput
              id="oidc-secret"
              type="password"
              value={clientSecret}
              onChange={setClientSecret}
              autoComplete="new-password"
              placeholder={stored?.clientSecretConfigured ? "•••••••• (stored)" : ""}
            />
          </FormRow>

          <div className="grid gap-4 sm:grid-cols-2">
            <FormRow
              label="Secret expires on (optional)"
              htmlFor="oidc-expiry"
              hint="Recorded, not enforced. Sign-in stops the day it lapses, with no warning."
            >
              <TextInput
                id="oidc-expiry"
                value={expiresOn}
                onChange={setExpiresOn}
                placeholder="2027-10-06"
              />
            </FormRow>

            <FormRow
              label="Directory group (optional)"
              htmlFor="oidc-group"
              hint="Recorded so it is answerable later who is meant to have access. Membership is enforced by the provider, not here."
            >
              <TextInput id="oidc-group" value={groupName} onChange={setGroupName} />
            </FormRow>
          </div>

          <div className="border-t border-border-base pt-3">
            <Checkbox
              checked={enabled}
              onChange={setEnabled}
              disabled={!complete}
              label="Offer the organisation sign-in button"
            />
            {!complete ? (
              <p className="mt-1 text-xs text-text-faint">
                {/*
                  Names what is missing rather than saying "not configured", and is disabled
                  rather than letting the server reject it -- a switch that can be flipped and
                  then fails teaches nothing about why.
                */}
                Needs an issuer URL, a client ID and a client secret first.
              </p>
            ) : null}
          </div>

          <FormError error={save.error} />

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              disabled={!complete || !changed || save.isPending}
              onClick={() => void onSave()}
            >
              {save.isPending ? "Saving…" : "Save connection"}
            </Button>
            <Button
              disabled={!complete || test.isPending}
              onClick={() => void test.mutateAsync(changed ? body : undefined)}
            >
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
            {changed && complete ? (
              <span className="text-xs text-text-faint">Testing uses the values above, unsaved.</span>
            ) : null}
          </div>

          {verdict ? <Verdict verdict={verdict} browserRedirectUri={browserRedirectUri} /> : null}
        </div>
      )}
    </Card>
  );
}

// ---- the result of a connection test ----

/**
 * Renders a diagnosis, and compares the two redirect URIs.
 *
 * The server builds the URI it sends from `PUBLIC_URL`; this page knows the origin the browser
 * is actually on. When those disagree the provider will be handed a URI nobody registered, and
 * the resulting failure appears on the provider's own error page — so the disagreement is worth
 * more than either value shown alone.
 */
function Verdict({
  verdict,
  browserRedirectUri,
}: {
  verdict: OidcDiagnosis;
  browserRedirectUri: string;
}) {
  const mismatch = verdict.redirectUri !== browserRedirectUri;

  return (
    <div className="space-y-2 rounded-md border border-border-base p-3">
      <div className="flex items-center gap-2">
        <Badge tone={!verdict.ok ? "danger" : verdict.credentialsAccepted === true ? "ok" : "warn"}>
          {!verdict.ok
            ? "Failed"
            : verdict.credentialsAccepted === true
              ? "Working"
              : "Reachable"}
        </Badge>
        <span className="text-xs text-text-muted">{verdict.code}</span>
      </div>

      <p className="text-sm text-text-base">{verdict.summary}</p>
      {verdict.hint ? <p className="text-xs text-text-muted">{verdict.hint}</p> : null}
      {verdict.detail ? (
        <p className="text-xs text-text-faint">
          <Mono>{verdict.detail}</Mono>
        </p>
      ) : null}

      {mismatch ? (
        <p className="text-xs text-danger">
          This server will send <Mono>{verdict.redirectUri}</Mono>, which is not the address this
          browser is on. That comes from PUBLIC_URL in the deployment’s environment, and the
          provider will reject a URI nobody registered.
        </p>
      ) : null}

      {verdict.issuer ? (
        <dl className="grid gap-x-4 gap-y-1 pt-1 text-xs sm:grid-cols-[auto_1fr]">
          <dt className="text-text-faint">Issuer</dt>
          <dd className="text-text-muted">
            <Mono>{verdict.issuer}</Mono>
          </dd>
          <dt className="text-text-faint">Signing keys</dt>
          <dd className="text-text-muted">{verdict.jwksKeyCount ?? "—"}</dd>
          <dt className="text-text-faint">Credentials</dt>
          <dd className="text-text-muted">
            {verdict.credentialsAccepted === true
              ? "accepted"
              : verdict.credentialsAccepted === false
                ? "rejected"
                : "not verifiable without a sign-in"}
          </dd>
        </dl>
      ) : null}

      <p className="text-[11px] text-text-faint">
        Checked {new Date(verdict.checkedAt).toLocaleString()}
      </p>
    </div>
  );
}
