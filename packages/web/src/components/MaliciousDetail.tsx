import { useEffect, useState } from "react";
import { Link } from "react-router";
import {
  MALICIOUS_ACK_LABELS,
  maliciousAckStates,
  type MaliciousAckState,
  type MaliciousApplicationImpact,
  type MaliciousFinding,
} from "@sbom/shared";
import { useMaliciousFinding } from "../lib/queries.ts";
import {
  useAcknowledgeMalicious,
  useRemoveMaliciousAcknowledgement,
} from "../lib/mutations.ts";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import { ComponentLocationCell } from "./ComponentLocationCell.tsx";
import {
  Badge,
  Button,
  EmptyState,
  ErrorBanner,
  Field,
  FormError,
  FormRow,
  LoadingBlock,
  Modal,
  Mono,
  Select,
  StatusBadge,
  Table,
  TableWrap,
  Td,
  Th,
  Tr,
} from "./ui.tsx";

/**
 * One malicious package in full.
 *
 * The layout is ordered by what the reader has to do, not by what the database holds. The
 * remediation notice comes first because the instinct on seeing this is to delete the package
 * and move on, and that leaves the actual damage -- credentials read at install time -- in
 * place. Then the affected applications, split by whether they still ship it, because those
 * two groups need different work. Upstream's description of the payload comes last but is
 * always present: it is what turns "rotate everything" into "rotate the npm token".
 */
export function MaliciousDetailModal({
  id,
  enabled,
  isAdmin,
  onClose,
}: {
  id: string | null;
  enabled: boolean;
  isAdmin: boolean;
  onClose: () => void;
}) {
  const { data: finding, isLoading, error, refetch } = useMaliciousFinding(id ?? undefined, enabled);
  const removeAck = useRemoveMaliciousAcknowledgement();

  const current = finding?.impacts.filter((i) => i.inCurrentBuild) ?? [];
  const historical = finding?.impacts.filter((i) => !i.inCurrentBuild) ?? [];

  return (
    <Modal
      open={id !== null}
      onClose={onClose}
      wide
      title={finding ? finding.packageName : "Malicious package"}
      footer={<Button onClick={onClose}>Close</Button>}
    >
      {isLoading ? (
        <LoadingBlock label="Loading finding" />
      ) : error ? (
        <ErrorBanner error={error} onRetry={() => void refetch()} />
      ) : !finding ? null : (
        <div className="space-y-4 text-sm">
          {/* The part that is easy to skip and expensive to skip. */}
          <div className="rounded-md border border-danger bg-danger-subtle px-3 py-2 text-xs text-danger">
            <p className="font-semibold">Removing the package is not sufficient on its own.</p>
            <p className="mt-1">
              Package managers run install scripts, so this executed on every machine that
              installed it — developer laptops and CI runners alike — before it was reported.
              Treat every credential those machines could read as compromised and rotate it: CI
              tokens, registry credentials, cloud keys.
            </p>
          </div>

          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Field label="Report">
              <Mono>{finding.id}</Mono>
            </Field>
            <Field label="Ecosystem">{finding.ecosystem}</Field>
            <Field label="In current builds">
              {finding.currentApplications > 0 ? (
                <Badge tone="danger">{formatNumber(finding.currentApplications)}</Badge>
              ) : (
                <span className="text-text-muted">None</span>
              )}
            </Field>
            <Field label="Ever shipped by">{formatNumber(finding.affectedApplications)}</Field>
            <Field label="Versions seen here">
              {finding.observedVersions.length > 0 ? finding.observedVersions.join(", ") : "—"}
            </Field>
            <Field label="Report covers">
              {/*
                What upstream says is affected, which is NOT the same as what was found here.
                Showing both is what lets a reader confirm the match rather than take it on
                trust -- the whole reason provenance travels with these findings.
              */}
              {finding.matchMode === "all_versions"
                ? "Every version"
                : finding.affectedVersions.length > 0
                  ? finding.affectedVersions.join(", ")
                  : "A version range"}
            </Field>
            <Field label="Reported">
              {finding.publishedAt ? formatDateTime(finding.publishedAt) : "—"}
            </Field>
            <Field label="Sources">
              {finding.sources.length > 0 ? finding.sources.join(", ") : "—"}
            </Field>
          </dl>

          {finding.withdrawnAt ? (
            <div className="rounded-md border border-border-strong bg-bg-subtle px-3 py-2 text-xs text-text-muted">
              This report was <strong className="text-text-base">withdrawn upstream</strong> on{" "}
              {formatDateTime(finding.withdrawnAt)}. It no longer produces findings, and is shown
              here only because a decision was recorded against it.
            </div>
          ) : null}

          <ImpactTable
            title="Still in the current build"
            hint="Remove the package and rebuild, then rotate this pipeline's credentials."
            rows={current}
            tone="danger"
          />
          <ImpactTable
            title="Shipped previously, already gone"
            hint="No longer present, but it ran on the machines that built these. Their credentials still need rotating."
            rows={historical}
            tone="warn"
          />

          {finding.details ? (
            <div>
              <h3 className="mb-1 text-xs font-semibold tracking-wide text-text-muted uppercase">
                What upstream reported
              </h3>
              {/*
                Pre-wrapped rather than rendered as markup. This text comes from a third-party
                feed, and the one thing it must not be able to do is inject anything into this
                page.
              */}
              <pre className="max-h-64 overflow-auto rounded-md border border-border-base bg-bg-subtle p-3 text-xs whitespace-pre-wrap text-text-muted">
                {finding.details}
              </pre>
            </div>
          ) : null}

          {finding.referenceUrl ? (
            <p className="text-xs">
              <a
                href={finding.referenceUrl}
                target="_blank"
                rel="noreferrer"
                className="text-accent hover:underline"
              >
                Upstream advisory
              </a>
            </p>
          ) : null}

          {finding.acknowledgements.length > 0 ? (
            <div>
              <h3 className="mb-1 text-xs font-semibold tracking-wide text-text-muted uppercase">
                Recorded decisions
              </h3>
              <ul className="space-y-2">
                {finding.acknowledgements.map((ack) => (
                  <li
                    key={ack.id}
                    className="rounded-md border border-border-base bg-bg-subtle px-3 py-2 text-xs"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone={ack.state === "remediated" ? "ok" : "warn"}>
                        {MALICIOUS_ACK_LABELS[ack.state]}
                      </Badge>
                      <span className="text-text-muted">
                        {ack.applicationName ?? "Every application"}
                      </span>
                      <span className="text-text-faint">
                        {ack.acknowledgedByEmail ?? "unknown"} · {formatRelative(ack.createdAt)}
                      </span>
                      {isAdmin ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={removeAck.isPending}
                          onClick={() => removeAck.mutate(ack.id)}
                        >
                          Remove
                        </Button>
                      ) : null}
                    </div>
                    <p className="mt-1 text-text-base">{ack.note}</p>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}
    </Modal>
  );
}

function ImpactTable({
  title,
  hint,
  rows,
  tone,
}: {
  title: string;
  hint: string;
  rows: MaliciousApplicationImpact[];
  tone: "danger" | "warn";
}) {
  if (rows.length === 0) return null;
  return (
    <div>
      <h3 className="text-xs font-semibold tracking-wide text-text-muted uppercase">
        <Badge tone={tone}>{rows.length}</Badge> {title}
      </h3>
      <p className="mt-1 mb-2 text-xs text-text-faint">{hint}</p>
      <TableWrap>
        <Table>
          <thead>
            <tr>
              <Th>Application</Th>
              <Th width="300px">Where it is</Th>
              <Th width="120px">Versions</Th>
              <Th align="right" width="80px">
                Builds
              </Th>
              <Th width="130px">First seen</Th>
              <Th width="130px">Last seen</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((impact) => (
              <Tr key={impact.applicationId}>
                <Td>
                  <Link
                    to={`/applications/${impact.applicationId}`}
                    className="text-accent hover:underline"
                  >
                    {impact.applicationName}
                  </Link>
                  <StatusBadge status={impact.applicationStatus as "active"} />
                  {impact.acknowledgement ? (
                    <Badge tone="neutral">{MALICIOUS_ACK_LABELS[impact.acknowledgement.state]}</Badge>
                  ) : null}
                </Td>
                <Td>
                  {/*
                    The question this whole column answers is "is this in our code or in the
                    image underneath it", which decides who has to fix it. The origin badge is
                    the short answer and the paths under it are the evidence — shown together
                    so a misclassification is visible rather than authoritative.
                  */}
                  <ComponentLocationCell location={impact.location} />
                </Td>
                <Td className="text-text-muted">{impact.versions.join(", ") || "—"}</Td>
                <Td align="right" className="nums text-text-muted">
                  {formatNumber(impact.builds)}
                </Td>
                <Td className="text-text-muted" title={formatDateTime(impact.firstSeenAt)}>
                  {formatRelative(impact.firstSeenAt)}
                </Td>
                <Td className="text-text-muted" title={formatDateTime(impact.lastSeenAt)}>
                  <Link to={`/scans/${impact.lastScanId}`} className="text-accent hover:underline">
                    {formatRelative(impact.lastSeenAt)}
                  </Link>
                </Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      </TableWrap>
    </div>
  );
}

/**
 * Record a decision about a finding.
 *
 * The note is required by the form as well as by the server, because the field is the whole
 * point of the feature. An acknowledgement without a reason cannot be told apart from someone
 * clearing a red banner to make it stop, and it is read months later by somebody deciding
 * whether an incident was actually closed.
 */
export function AcknowledgeModal({
  finding,
  onClose,
}: {
  finding: MaliciousFinding | null;
  onClose: () => void;
}) {
  const acknowledge = useAcknowledgeMalicious();
  const [state, setState] = useState<MaliciousAckState>("investigating");
  const [note, setNote] = useState("");

  useEffect(() => {
    if (finding) {
      // Seeded from the existing decision so "Update" edits rather than starts over.
      setState(finding.acknowledgement?.state ?? "investigating");
      setNote(finding.acknowledgement?.note ?? "");
      acknowledge.reset();
    }
    // `acknowledge` is a stable mutation object; including it would re-run on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finding]);

  const canSave = note.trim().length > 0 && !acknowledge.isPending;

  return (
    <Modal
      open={finding !== null}
      onClose={onClose}
      title="Record a decision"
      footer={
        <>
          <Button onClick={onClose} disabled={acknowledge.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            disabled={!canSave}
            onClick={() => {
              if (!finding) return;
              acknowledge.mutate(
                { maliciousPackageId: finding.id, state, note: note.trim() },
                { onSuccess: onClose },
              );
            }}
          >
            {acknowledge.isPending ? "Saving…" : "Save"}
          </Button>
        </>
      }
    >
      {finding ? (
        <div className="space-y-3 text-sm text-text-muted">
          <FormError error={acknowledge.error} />
          <p>
            <strong className="text-text-base">{finding.packageName}</strong> —{" "}
            <span className="text-xs"><Mono>{finding.id}</Mono></span>
          </p>
          <p className="text-xs">
            This does not hide the finding. It stays on the list with the label and note below,
            so anyone looking later can tell a handled finding from an ignored one.
          </p>

          <FormRow label="Decision" htmlFor="ack-state">
            <Select
              id="ack-state"
              value={state}
              onChange={(next) => setState(next)}
              options={maliciousAckStates.map((s) => ({ value: s, label: MALICIOUS_ACK_LABELS[s] }))}
            />
          </FormRow>

          <FormRow label="Note (required)" htmlFor="ack-note">
            <textarea
              id="ack-note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              rows={4}
              placeholder="What was done — e.g. removed in build 418, npm and AWS tokens rotated 14:20."
              className="w-full rounded-md border border-border-strong bg-bg-raised px-2 py-1.5 text-sm text-text-base focus:border-accent"
            />
          </FormRow>

          {state === "remediated" ? (
            <p className="rounded-md border border-border-base bg-bg-subtle px-3 py-2 text-xs">
              Marking this remediated asserts both halves: the package is gone, and the
              credentials the installing machines could read have been rotated.
            </p>
          ) : null}
        </div>
      ) : (
        <EmptyState title="Nothing selected" hint="" />
      )}
    </Modal>
  );
}
