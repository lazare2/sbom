import { useState } from "react";
import { API_TOKEN_SECRET_PREFIX, type ApiTokenSummary } from "@sbom/shared";
import { useApiAccess, useApiTokens } from "../lib/queries.ts";
import { useCreateApiToken, useRevokeApiToken } from "../lib/mutations.ts";
import { formatDate, formatRelative } from "../lib/format.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  ErrorBanner,
  FormError,
  FormRow,
  LoadingBlock,
  Mono,
  PageHeader,
  SecretReveal,
  Select,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../components/ui.tsx";

/**
 * The API, for people who would rather not use the web app.
 *
 * There is no second API: every screen in this platform is drawn by calling the endpoints
 * documented here, so a token opens the surface the UI already uses rather than a new one. That
 * is worth saying on the page, because the first question a developer asks is "what can I get
 * at", and the honest answer is "whatever you can see".
 *
 * Reachable by every signed-in account, not just administrators. Self-service is the point —
 * a queue behind an administrator is how four engineers end up sharing one credential.
 */
export function ApiAccessPage() {
  const access = useApiAccess();
  const tokens = useApiTokens();

  return (
    <div className="space-y-4">
      <PageHeader
        title="API access"
        subtitle="Query the platform from a script with a personal token. The same endpoints this web app uses."
      />

      {access.isLoading ? (
        <LoadingBlock label="Loading API details" />
      ) : access.error ? (
        <ErrorBanner error={access.error} onRetry={() => void access.refetch()} />
      ) : access.data ? (
        <>
          <EndpointCard
            baseUrl={access.data.baseUrl}
            specPath={access.data.specPath}
            docsPath={access.data.docsPath}
          />
          <TokenCard tokens={tokens} maxDays={access.data.maxExpiryDays} />
        </>
      ) : null}
    </div>
  );
}

/** Where the API is, and a request that works as written. */
function EndpointCard({
  baseUrl,
  specPath,
  docsPath,
}: {
  baseUrl: string;
  specPath: string;
  docsPath: string;
}) {
  return (
    <Card>
      <CardHeader
        title="Where the API is"
        subtitle="Every response is JSON. Authentication is a bearer token on each request — there is no sign-in step and no cookie."
      />
      <div className="space-y-4 p-4 pt-0">
        <FormRow
          label="Base URL"
          hint="Taken from this deployment's configured public address, not from your browser — so it is the address a script on another machine should use."
        >
          <Mono>{baseUrl}</Mono>
        </FormRow>

        <FormRow label="A request that works" hint="Replace the token with one from below.">
          <pre className="overflow-x-auto rounded-md border border-border-base bg-bg-subtle p-3 text-[11px] leading-relaxed text-text-base">
{`curl -s -H "Authorization: Bearer ${API_TOKEN_SECRET_PREFIX}…" \\
  "${baseUrl}/applications?pageSize=5"`}
          </pre>
        </FormRow>

        <div className="flex flex-wrap gap-2 border-t border-border-base pt-3">
          {/*
            Plain links rather than router navigation: both are served by the API, not by this
            single-page app, so routing to them would leave the SPA trying to render a path it
            has no route for.
          */}
          <a
            href={docsPath}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center rounded-md border border-border-base px-3 py-1.5 text-sm font-medium text-text-base transition-colors hover:bg-neutral-subtle"
          >
            Browse the endpoints ↗
          </a>
          <a
            href={specPath}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center rounded-md border border-border-base px-3 py-1.5 text-sm text-text-muted transition-colors hover:bg-neutral-subtle"
          >
            OpenAPI document ↗
          </a>
        </div>

        <p className="text-xs text-text-faint">
          A token acts as you. It reaches exactly the environments, groups and applications your
          account reaches — resolved on every request, so a change to your access applies to your
          tokens immediately.
        </p>
      </div>
    </Card>
  );
}

function TokenCard({
  tokens,
  maxDays,
}: {
  tokens: ReturnType<typeof useApiTokens>;
  maxDays: number;
}) {
  const create = useCreateApiToken();
  const revoke = useRevokeApiToken();

  const [name, setName] = useState("");
  const [scope, setScope] = useState<"read" | "write">("read");
  const [expiry, setExpiry] = useState("90");
  /** Shown once, immediately after minting. Never cached. */
  const [issued, setIssued] = useState<{ name: string; secret: string } | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setActionError(null);
    try {
      const result = await create.mutateAsync({
        name: name.trim(),
        scope,
        expiresInDays: expiry === "never" ? null : Number(expiry),
      });
      setIssued({ name: result.token.name, secret: result.secret });
      setName("");
      setScope("read");
      setExpiry("90");
    } catch {
      // Rendered from the mutation's error state.
    }
  }

  const rows = tokens.data?.tokens ?? [];

  return (
    <Card>
      <CardHeader
        title="Your tokens"
        subtitle="Shown once at creation and stored only as a hash — a lost token cannot be recovered, only replaced."
      />

      <div className="space-y-4 p-4 pt-0">
        {issued ? (
          <div className="space-y-2 rounded-md border border-ok bg-ok-subtle p-3">
            <SecretReveal
              label={`Token “${issued.name}”`}
              value={issued.secret}
              note="Copy it now. It is stored only as a hash and will never be shown again."
            />
            <Button size="sm" onClick={() => setIssued(null)}>
              Done
            </Button>
          </div>
        ) : null}

        <form onSubmit={submit} className="grid items-end gap-3 sm:grid-cols-[1fr_auto_auto_auto]">
          <FormRow label="What it is for" htmlFor="token-name">
            <TextInput
              id="token-name"
              value={name}
              onChange={setName}
              placeholder="reporting script"
            />
          </FormRow>

          <FormRow label="Access" htmlFor="token-scope">
            <Select
              id="token-scope"
              value={scope}
              onChange={(v) => setScope(v as "read" | "write")}
              options={[
                { value: "read", label: "Read only" },
                { value: "write", label: "Read and write" },
              ]}
            />
          </FormRow>

          <FormRow label="Expires" htmlFor="token-expiry">
            <Select
              id="token-expiry"
              value={expiry}
              onChange={setExpiry}
              options={[
                { value: "30", label: "30 days" },
                { value: "90", label: "90 days" },
                { value: "365", label: `${maxDays} days` },
                { value: "never", label: "Never" },
              ]}
            />
          </FormRow>

          <Button type="submit" variant="primary" disabled={!name.trim() || create.isPending}>
            {create.isPending ? "Creating…" : "Create token"}
          </Button>
        </form>

        {/*
          Said at the point the choice is made, not in documentation nobody opens. A write
          token can do anything its owner can, which for an administrator is everything —
          and the common reason to want a token needs no write access at all.
        */}
        {scope === "write" ? (
          <p className="text-xs text-warn">
            A read-and-write token can change anything your account can change. If this is for
            pulling data out, read-only is enough.
          </p>
        ) : null}
        {expiry === "never" ? (
          <p className="text-xs text-warn">
            A token that never expires outlives the script it was made for. Prefer a date unless
            nothing can rotate it.
          </p>
        ) : null}

        <FormError error={create.error} />
        <FormError error={actionError} />

        {tokens.isLoading ? (
          <LoadingBlock label="Loading tokens" />
        ) : tokens.error ? (
          <ErrorBanner error={tokens.error} onRetry={() => void tokens.refetch()} />
        ) : rows.length === 0 ? (
          <p className="text-xs text-text-faint">
            You have no tokens yet. Create one above to call the API from a script.
          </p>
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <Tr>
                  <Th>Name</Th>
                  <Th>Access</Th>
                  <Th>Token</Th>
                  <Th>Last used</Th>
                  <Th>Expires</Th>
                  <Th />
                </Tr>
              </thead>
              <tbody>
                {rows.map((token) => (
                  <TokenRow
                    key={token.id}
                    token={token}
                    busy={revoke.isPending}
                    onRevoke={() => {
                      setActionError(null);
                      revoke.mutate(token.id, { onError: (err) => setActionError(err) });
                    }}
                  />
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </div>
    </Card>
  );
}

const INACTIVE_REASON: Record<string, string> = {
  revoked: "Revoked",
  expired: "Expired",
  account_inactive: "Account disabled",
};

function TokenRow({
  token,
  busy,
  onRevoke,
}: {
  token: ApiTokenSummary;
  busy: boolean;
  onRevoke: () => void;
}) {
  return (
    <Tr>
      <Td>
        <span className="font-medium text-text-base">{token.name}</span>
        {!token.active ? (
          <>
            {" "}
            <Badge tone="neutral">{INACTIVE_REASON[token.inactiveReason ?? ""] ?? "Inactive"}</Badge>
          </>
        ) : null}
      </Td>
      <Td>
        <Badge tone={token.scope === "write" ? "warn" : "neutral"}>
          {token.scope === "write" ? "read + write" : "read only"}
        </Badge>
      </Td>
      {/* The last four characters are all that is kept of the plaintext, and they exist purely
          so two tokens can be told apart in this list. */}
      <Td>
        <Mono>…{token.tokenSuffix}</Mono>
      </Td>
      <Td title={token.lastUsedAt ?? ""}>
        {/*
          "Never" is the useful answer here, not a dash: it is what makes an abandoned token
          safe to revoke, which is the question that otherwise stops anybody tidying up.
        */}
        {token.lastUsedAt === null ? (
          <span className="text-text-faint">Never used</span>
        ) : (
          formatRelative(token.lastUsedAt)
        )}
      </Td>
      <Td title={token.expiresAt ?? ""}>
        {token.expiresAt === null ? (
          <span className="text-warn">Never</span>
        ) : (
          formatDate(token.expiresAt)
        )}
      </Td>
      <Td align="right">
        {token.revokedAt === null ? (
          <Button size="sm" variant="ghost" disabled={busy} onClick={onRevoke}>
            Revoke
          </Button>
        ) : null}
      </Td>
    </Tr>
  );
}
