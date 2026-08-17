import { useState } from "react";
import type { IngestTokenSummary } from "@sbom/shared";
import { formatDate, formatRelative } from "../../lib/format.ts";
import { useCreateIngestToken, useRevokeIngestToken } from "../../lib/mutations.ts";
import { useIngestTokens } from "../../lib/queries.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorBanner,
  FormError,
  FormRow,
  LoadingBlock,
  Modal,
  SecretReveal,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";

/**
 * CI credentials for the ingest endpoint.
 *
 * These attest "a trusted CI system is calling", not which application is being
 * reported — the application comes entirely from the `app_name` form field.
 * Separate named tokens exist so Jenkins and GitLab can be rotated and revoked
 * independently rather than sharing one secret nobody dares change.
 */
export function AdminTokensPage() {
  const tokens = useIngestTokens();
  const revoke = useRevokeIngestToken();
  const [createOpen, setCreateOpen] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);

  async function handleRevoke(token: IngestTokenSummary) {
    if (!token.id) return;
    setActionError(null);
    try {
      await revoke.mutateAsync(token.id);
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <Card>
        <CardHeader
          title="CI ingest tokens"
          subtitle="Presented as an Authorization: Bearer header on POST /api/v1/scans. Store in the Jenkins credentials store or a GitLab group-level CI/CD variable."
          actions={
            <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
              New token
            </Button>
          }
        />

        {actionError ? (
          <div className="px-4 pt-3">
            <FormError error={actionError} />
          </div>
        ) : null}

        {tokens.isLoading ? (
          <LoadingBlock label="Loading tokens" />
        ) : tokens.error ? (
          <div className="p-4">
            <ErrorBanner error={tokens.error} onRetry={() => void tokens.refetch()} />
          </div>
        ) : !tokens.data || tokens.data.length === 0 ? (
          <EmptyState
            title="No ingest tokens"
            hint="Without one, no pipeline can submit an SBOM. Create a token, or set INGEST_TOKENS in the environment."
          />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Token</Th>
                  <Th>Source</Th>
                  <Th>Status</Th>
                  <Th>Last used</Th>
                  <Th>Created</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {tokens.data.map((token) => (
                  <Tr key={token.id ?? `env-${token.name}`}>
                    <Td className="font-medium text-text-base">{token.name}</Td>
                    <Td>
                      <code className="font-mono text-xs text-text-muted">…{token.tokenSuffix}</code>
                    </Td>
                    <Td>
                      {token.source === "env" ? (
                        <Badge
                          tone="info"
                          title="Configured through the INGEST_TOKENS environment variable. Change it where the deployment is configured, not here."
                        >
                          environment
                        </Badge>
                      ) : (
                        <Badge tone="neutral">database</Badge>
                      )}
                    </Td>
                    <Td>
                      {token.isActive ? <Badge tone="ok">Active</Badge> : <Badge tone="danger">Revoked</Badge>}
                    </Td>
                    <Td title={token.lastUsedAt ?? ""}>
                      {token.source === "env" ? (
                        <span className="text-text-faint" title="Usage is only tracked for database tokens">
                          not tracked
                        </span>
                      ) : (
                        formatRelative(token.lastUsedAt)
                      )}
                    </Td>
                    <Td>{token.createdAt ? formatDate(token.createdAt) : "—"}</Td>
                    <Td align="right">
                      {token.source === "db" && token.isActive ? (
                        <Button size="sm" variant="ghost" onClick={() => void handleRevoke(token)} disabled={revoke.isPending}>
                          Revoke
                        </Button>
                      ) : null}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>

      <CreateTokenModal open={createOpen} onClose={() => setCreateOpen(false)} />
    </>
  );
}

function CreateTokenModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const createToken = useCreateIngestToken();
  const [name, setName] = useState("");
  const [issued, setIssued] = useState<{ name: string; token: string } | null>(null);

  function close() {
    setName("");
    setIssued(null);
    createToken.reset();
    onClose();
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      const result = await createToken.mutateAsync(name);
      setIssued({ name: result.token.name, token: result.plaintext });
    } catch {
      // Rendered from the mutation error state.
    }
  }

  return (
    <Modal
      open={open}
      onClose={close}
      title={issued ? "Token created" : "New ingest token"}
      footer={
        issued ? (
          <Button variant="primary" onClick={close}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={close} disabled={createToken.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              type="submit"
              form="token-form"
              disabled={!name.trim() || createToken.isPending}
            >
              {createToken.isPending ? "Creating…" : "Create token"}
            </Button>
          </>
        )
      }
    >
      {issued ? (
        <div className="space-y-3">
          <SecretReveal
            label={`Token for ${issued.name}`}
            value={issued.token}
            note="Shown once — only its hash is stored. Copy it into your CI credential store now."
          />
          <div>
            <p className="mb-1 text-xs font-medium text-text-muted">Example pipeline step</p>
            <pre className="overflow-x-auto rounded-md border border-border-base bg-bg-subtle p-3 font-mono text-[11px] leading-relaxed text-text-muted">
{`syft "$IMAGE" -o cyclonedx-json > sbom.json

curl -f -X POST "$SBOM_URL/api/v1/scans" \\
  -H "Authorization: Bearer $SBOM_TOKEN" \\
  -F "sbom=@sbom.json" \\
  -F "app_name=$CI_PROJECT_NAME" \\
  -F "commit_sha=$CI_COMMIT_SHA" \\
  -F "build_number=$CI_PIPELINE_IID" \\
  -F "branch=$CI_COMMIT_REF_NAME" \\
  -F "image_ref=$IMAGE"`}
            </pre>
            <p className="mt-1 text-xs text-text-faint">
              <code className="font-mono">curl -f</code> makes the step fail on any non-2xx, which is the
              behaviour the API's status codes are designed around.
            </p>
          </div>
        </div>
      ) : (
        <form id="token-form" onSubmit={submit} className="space-y-3" noValidate>
          <FormError error={createToken.error} />
          <FormRow
            label="Name"
            htmlFor="token-name"
            hint="Identifies the CI system. Recorded on every scan it submits, so keep it recognisable — e.g. jenkins-prod."
          >
            <TextInput id="token-name" value={name} onChange={setName} placeholder="jenkins" autoFocus required />
          </FormRow>
        </form>
      )}
    </Modal>
  );
}
