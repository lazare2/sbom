import { useRef, useState } from "react";
import { Link } from "react-router";
import {
  VULN_DB_INTERVAL_MAX_HOURS,
  VULN_DB_INTERVAL_MIN_HOURS,
  type VulnDbUpdateAttempt,
  type VulnScanStatus,
} from "@sbom/shared";
import {
  useImportVulnDb,
  useRunVulnSweep,
  useUpdateVulnDb,
  useUpdateVulnSettings,
  useDeleteSuppression,
} from "../../lib/mutations.ts";
import { useVulnAdminStatus, useVulnHistory, useVulnSuppressions } from "../../lib/queries.ts";
import { formatDateTime, formatNumber, formatRelative } from "../../lib/format.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
  EmptyState,
  ErrorBanner,
  Field,
  FormError,
  FormRow,
  LoadingBlock,
  Mono,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";
import { SeverityBadge, SEVERITY_ORDER } from "../../components/Severity.tsx";
import { useClientSort } from "../../lib/useSort.ts";

/**
 * Admin control panel for vulnerability scanning.
 *
 * Answers four questions, in the order an administrator asks them: is scanning on, does
 * the scanner work, how old is the data, and what happened the last time it tried to
 * update. Each is reported separately because they fail independently — a working binary
 * with no database and a current database with no binary need different fixes, and one
 * "healthy" light would hide which.
 *
 * There is deliberately no field for the grype binary path. That would let an admin
 * session choose which executable the server runs, which is a remote-code-execution
 * primitive; it stays in the environment where changing it needs deployment access. What
 * the panel shows instead is where the binary was looked for and what was found there.
 */
export function AdminVulnerabilitiesPage() {
  const { data: status, isLoading, error, refetch } = useVulnAdminStatus();

  if (isLoading) return <LoadingBlock label="Loading scanner status" />;
  if (error) return <ErrorBanner error={error} onRetry={() => void refetch()} />;
  if (!status) return null;

  return (
    <div className="space-y-4">
      <EnableCard status={status} />
      <ScannerCard status={status} />
      <DatabaseCard status={status} />
      <CoverageCard status={status} />
      <HistoryCard />
      <SuppressionsCard />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Enable / interval
// ---------------------------------------------------------------------------

function EnableCard({ status }: { status: VulnScanStatus }) {
  const update = useUpdateVulnSettings();
  const [interval, setInterval] = useState(String(status.updates.intervalHours));

  const intervalChanged = Number(interval) !== status.updates.intervalHours;
  const intervalValid =
    Number.isFinite(Number(interval)) &&
    Number(interval) >= VULN_DB_INTERVAL_MIN_HOURS &&
    Number(interval) <= VULN_DB_INTERVAL_MAX_HOURS;

  return (
    <Card>
      <CardHeader
        title="Vulnerability scanning"
        subtitle="When off, this platform is a dependency inventory and nothing is matched against a vulnerability database."
      />
      <div className="space-y-4 p-4">
        <Checkbox
          checked={status.enabled}
          onChange={(enabled) => update.mutate({ enabled })}
          label={status.enabled ? "Enabled — packages are matched against the database" : "Enable Grype scan"}
        />

        {status.enabled ? (
          <p className="text-xs text-text-muted">
            Newly ingested SBOMs are matched within seconds of arriving. Ingestion never waits for
            it — a build's <Mono>curl -f</Mono> returns as soon as the SBOM is stored.
          </p>
        ) : (
          <p className="text-xs text-text-muted">
            Switching this on matches everything already in the estate, which takes a couple of
            minutes for a few tens of thousands of packages. Without that backfill the feature would
            appear to do nothing until the next build arrived.
          </p>
        )}

        <div className="flex flex-wrap items-end gap-3 border-t border-border-base pt-4">
          <div className="w-40">
            <FormRow
              label="Check for updates every"
              htmlFor="vuln-interval"
              hint={`Hours. ${VULN_DB_INTERVAL_MIN_HOURS}–${VULN_DB_INTERVAL_MAX_HOURS} allowed.`}
            >
              <TextInput id="vuln-interval" value={interval} onChange={setInterval} />
            </FormRow>
          </div>
          <Button
            variant="primary"
            size="sm"
            disabled={!intervalChanged || !intervalValid || update.isPending}
            onClick={() => update.mutate({ intervalHours: Number(interval) })}
          >
            {update.isPending ? "Saving…" : "Save interval"}
          </Button>
          {status.updates.nextCheckAt ? (
            <p className="text-xs text-text-faint">
              Next check {formatRelative(status.updates.nextCheckAt)}
            </p>
          ) : (
            <p className="text-xs text-text-faint">
              {/* Honest about the schedule not running, rather than showing a time that will not happen. */}
              No scheduled checks while scanning is disabled.
            </p>
          )}
        </div>

        {/*
          Anchore rebuilds roughly daily, so a 3-hour check is a cheap listing request that
          usually finds nothing — worth saying, because "every 3 hours" otherwise sounds
          like eight 141 MB downloads a day.
        */}
        <p className="text-xs text-text-faint">
          A check fetches a small listing file first and only downloads when the published database
          is newer. Anchore rebuilds it about once a day, so most checks transfer nothing.
        </p>

        <FormError error={update.error} />
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

function ScannerCard({ status }: { status: VulnScanStatus }) {
  const { scanner } = status;
  return (
    <Card>
      <CardHeader
        title="Scanner"
        subtitle="The Grype binary. Ships inside the container image; on a native install it is found on PATH or in var/bin."
        actions={
          scanner.available ? (
            <Badge tone="ok">Available</Badge>
          ) : (
            <Badge tone="danger">Not found</Badge>
          )
        }
      />
      <dl className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
        <Field label="Version">{scanner.version ?? "—"}</Field>
        <Field label="Resolved by">{scanner.resolvedBy ?? "—"}</Field>
        <div className="col-span-2">
          <Field label="Path">
            <Mono title={scanner.path ?? undefined}>{scanner.path ?? "—"}</Mono>
          </Field>
        </div>
      </dl>

      {!scanner.available && scanner.attempts.length > 0 ? (
        <div className="border-t border-border-base px-4 py-3">
          {/*
            Every rule that was tried and why it failed. This is the difference between a
            setup someone completes in two minutes and one they give up on — "not found"
            alone tells nobody where to put the binary.
          */}
          <p className="mb-2 text-xs font-medium text-text-muted">Where it was looked for</p>
          <ul className="space-y-1">
            {scanner.attempts.map((attempt) => (
              <li key={attempt.strategy} className="text-xs text-text-muted">
                <span className="font-medium text-text-base">{attempt.strategy}</span>{" "}
                <Mono>{attempt.location}</Mono> — {attempt.reason}
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-text-muted">
            On a native install run <Mono>npm run grype:install</Mono>, or set{" "}
            <Mono>GRYPE_PATH</Mono> to an existing binary. The path is an environment setting
            rather than a field here, because it decides which executable the server runs.
          </p>
        </div>
      ) : null}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

/** Grype refuses to consider a database current past five days; surfaced as a warning. */
const STALE_AFTER_HOURS = 120;

function DatabaseCard({ status }: { status: VulnScanStatus }) {
  const { database, updates } = status;
  const runUpdate = useUpdateVulnDb();
  const runImport = useImportVulnDb();
  const fileInput = useRef<HTMLInputElement>(null);

  const stale = database.ageHours !== null && database.ageHours > STALE_AFTER_HOURS;
  const result = runUpdate.data ?? runImport.data;
  const busy = runUpdate.isPending || runImport.isPending || updates.inProgress;

  return (
    <Card>
      <CardHeader
        title="Vulnerability database"
        subtitle="Downloaded from Anchore at runtime, not shipped in the image — it is about 1.9 GB expanded and is rebuilt daily, so a bundled copy would arrive stale."
        actions={
          database.present ? (
            stale ? (
              <Badge tone="warn">{Math.round(database.ageHours! / 24)} days old</Badge>
            ) : (
              <Badge tone="ok">Current</Badge>
            )
          ) : (
            <Badge tone="warn">Not installed</Badge>
          )
        }
      />

      <dl className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
        {/* The figure the user asked for by name: when was it last updated. */}
        <Field label="Last updated">
          {database.builtAt ? (
            <span title={formatDateTime(database.builtAt)}>{formatRelative(database.builtAt)}</span>
          ) : (
            <span className="text-text-faint">never</span>
          )}
        </Field>
        <Field label="Built">{database.builtAt ? formatDateTime(database.builtAt) : "—"}</Field>
        <Field label="Schema">{database.schemaVersion ?? "—"}</Field>
        <Field label="Age">
          {database.ageHours === null
            ? "—"
            : database.ageHours < 48
              ? `${Math.round(database.ageHours)} hours`
              : `${Math.round(database.ageHours / 24)} days`}
        </Field>
        <div className="col-span-2 sm:col-span-4">
          <Field label="Update source">
            <Mono>{updates.listingUrl}</Mono>
          </Field>
        </div>
        {database.error ? (
          <div className="col-span-2 sm:col-span-4">
            <Field label="Reported problem">
              <span className="text-warn">{database.error}</span>
            </Field>
          </div>
        ) : null}
      </dl>

      <div className="flex flex-wrap items-center gap-2 border-t border-border-base px-4 py-3">
        <Button
          variant="primary"
          size="sm"
          disabled={busy}
          onClick={() => runUpdate.mutate()}
          // A disabled button with no explanation is the most annoying state in any admin
          // panel. If another attempt holds the claim, say since when.
          title={
            updates.inProgress && updates.last
              ? `An update has been running since ${formatDateTime(updates.last.startedAt)}.`
              : undefined
          }
        >
          {runUpdate.isPending ? "Checking…" : updates.inProgress ? "Update running…" : "Update now"}
        </Button>
        <Button size="sm" disabled={busy} onClick={() => fileInput.current?.click()}>
          {runImport.isPending ? "Importing…" : "Import from file…"}
        </Button>
        <input
          ref={fileInput}
          type="file"
          accept=".tar.zst,.zst,.tar,application/octet-stream"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) runImport.mutate(file);
            e.target.value = "";
          }}
        />
        <p className="text-xs text-text-faint">
          Import is for machines with no internet access — download the archive elsewhere and upload
          it here.
        </p>
      </div>

      {result ? <UpdateOutcome result={result} /> : null}
      <div className="px-4 pb-3">
        <FormError error={runUpdate.error ?? runImport.error} />
      </div>
    </Card>
  );
}

/**
 * The result of an update attempt.
 *
 * `unreachable` is rendered as information, not as an error, and that is the whole point:
 * a server with no route to the internet is in a normal state that needs a different
 * response from a genuine failure. The message carries the exact URL that could not be
 * reached, so nobody has to guess what to allow through a firewall.
 */
function UpdateOutcome({ result }: { result: { outcome: string; message: string } }) {
  const tone =
    result.outcome === "updated" || result.outcome === "imported"
      ? "border-ok bg-ok-subtle text-ok"
      : result.outcome === "already-current"
        ? "border-border-base bg-bg-subtle text-text-muted"
        : result.outcome === "unreachable"
          ? "border-warn bg-warn-subtle text-warn"
          : "border-danger bg-danger-subtle text-danger";

  const heading =
    result.outcome === "updated"
      ? "Database updated — every package will be rematched"
      : result.outcome === "imported"
        ? "Database imported — every package will be rematched"
        : result.outcome === "already-current"
          ? "Already up to date"
          : result.outcome === "unreachable"
            ? "No internet connection"
            : result.outcome === "busy"
              ? "An update is already running"
              : "Update failed";

  return (
    <div className={`mx-4 mb-3 rounded-md border px-3 py-2.5 text-xs ${tone}`} role="status">
      <p className="font-semibold">{heading}</p>
      <p className="mt-1 break-words">{result.message}</p>
      {result.outcome === "unreachable" ? (
        <p className="mt-1.5">
          Nothing else is affected: ingestion, search and the dashboards continue as normal, and the
          previously installed database is untouched. Use <strong>Import from file</strong> to update
          without network access.
        </p>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

function CoverageCard({ status }: { status: VulnScanStatus }) {
  const sweep = useRunVulnSweep();
  const { coverage } = status;
  const total = coverage.scanned + coverage.pending;
  const pct = total === 0 ? 0 : Math.round((coverage.scanned / total) * 100);

  return (
    <Card>
      <CardHeader
        title="Match coverage"
        subtitle="Packages matched against the installed database. Anything pending is work the background sweep has still to do — a new database makes every package pending again."
        actions={
          coverage.sweeping ? <Badge tone="info">Sweeping…</Badge> : <Badge tone="neutral">Idle</Badge>
        }
      />
      <div className="space-y-3 p-4">
        <div className="flex items-center gap-3">
          <span className="inline-flex h-2 flex-1 overflow-hidden rounded-full bg-neutral-subtle">
            <span className="bg-accent" style={{ width: `${pct}%` }} />
          </span>
          <span className="nums w-32 text-right text-xs text-text-muted">
            {formatNumber(coverage.scanned)} / {formatNumber(total)} ({pct}%)
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-4 text-xs text-text-muted">
          <span>{formatNumber(coverage.pending)} pending</span>
          {coverage.lastSweepFinishedAt ? (
            <span title={formatDateTime(coverage.lastSweepFinishedAt)}>
              Last sweep finished {formatRelative(coverage.lastSweepFinishedAt)}
            </span>
          ) : null}
          <Button size="sm" disabled={sweep.isPending || coverage.sweeping} onClick={() => sweep.mutate()}>
            {sweep.isPending ? "Sweeping…" : "Sweep now"}
          </Button>
        </div>
        {sweep.data ? (
          <p className="text-xs text-text-muted">
            {sweep.data.message} ({formatNumber(sweep.data.componentsScanned)} matched,{" "}
            {formatNumber(sweep.data.remaining)} remaining)
          </p>
        ) : null}
        <FormError error={sweep.error} />
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

/** Client-side: the endpoint returns the last 20 attempts in one response. */
const HISTORY_COLUMNS = {
  startedAt: "date",
  trigger: "text",
  outcome: "text",
  actor: "text",
} as const;

function HistoryCard() {
  const { data: attempts, isLoading } = useVulnHistory(20);

  const sort = useClientSort(
    attempts,
    HISTORY_COLUMNS,
    { sortBy: "startedAt" },
    (attempt, field) => {
      switch (field) {
        case "trigger":
          return attempt.trigger;
        case "outcome":
          return attempt.outcome;
        // Null for the scheduler, which is the system rather than a person.
        case "actor":
          return attempt.actorEmail;
        case "startedAt":
        default:
          return attempt.startedAt;
      }
    },
    (attempt) => attempt.id,
  );

  return (
    <Card>
      <CardHeader
        title="Update history"
        subtitle="Every attempt, including the ones that found no route to the internet — that is how an old database becomes explainable rather than mysterious."
      />
      {isLoading ? (
        <LoadingBlock label="Loading history" />
      ) : !attempts || attempts.length === 0 ? (
        <EmptyState title="No update has been attempted yet" />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("startedAt")} sorted={sort.stateOf("startedAt")} width="170px">
                  Started
                </Th>
                <Th onSort={() => sort.toggle("trigger")} sorted={sort.stateOf("trigger")} width="110px">
                  Trigger
                </Th>
                <Th onSort={() => sort.toggle("outcome")} sorted={sort.stateOf("outcome")} width="130px">
                  Outcome
                </Th>
                {/* Free-text detail, often a multi-line grype error. Not orderable usefully. */}
                <Th>Detail</Th>
                <Th onSort={() => sort.toggle("actor")} sorted={sort.stateOf("actor")} width="150px">
                  Actor
                </Th>
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((attempt) => (
                <Tr key={attempt.id}>
                  <Td title={formatDateTime(attempt.startedAt)}>{formatDateTime(attempt.startedAt)}</Td>
                  <Td className="text-text-muted">{attempt.trigger}</Td>
                  <Td>
                    <OutcomeBadge attempt={attempt} />
                  </Td>
                  <Td className="max-w-[520px] truncate text-text-muted" title={attempt.message ?? undefined}>
                    {attempt.message ?? "—"}
                  </Td>
                  <Td className="text-text-muted">{attempt.actorEmail ?? "scheduled"}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </Card>
  );
}

function OutcomeBadge({ attempt }: { attempt: VulnDbUpdateAttempt }) {
  if (attempt.finishedAt === null) return <Badge tone="info">running</Badge>;
  switch (attempt.outcome) {
    case "updated":
    case "imported":
      return <Badge tone="ok">{attempt.outcome}</Badge>;
    case "already-current":
      return <Badge tone="neutral">up to date</Badge>;
    case "unreachable":
      // Warn, not danger: being air-gapped is a state, not a fault.
      return <Badge tone="warn">no connection</Badge>;
    default:
      return <Badge tone="danger">failed</Badge>;
  }
}

// ---------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------

/** Client-side: accepted risks are a short, deliberately curated list. */
const SUPPRESSION_COLUMNS = {
  vulnerability: "text",
  severity: "number",
  scope: "text",
  acceptedBy: "text",
  expiresAt: "date",
} as const;

function SuppressionsCard() {
  const { data: suppressions, isLoading } = useVulnSuppressions();
  const remove = useDeleteSuppression();

  const sort = useClientSort(
    suppressions,
    SUPPRESSION_COLUMNS,
    { sortBy: "severity" },
    (row, field) => {
      switch (field) {
        // Ranked, not alphabetical: `critical` must not sort below `low`.
        case "severity":
          return row.severity ? SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(row.severity) : 0;
        case "scope":
          /*
            Sorted so the broadest suppressions surface first in the natural direction.
            Estate-wide is the biggest decision on this screen and the one most worth
            reviewing, so it should not be scattered among per-application rows.
          */
          return `${row.applicationName ?? ""} ${row.componentName ?? ""}`.trim();
        case "acceptedBy":
          return row.createdByEmail;
        case "expiresAt":
          return row.expiresAt;
        case "vulnerability":
        default:
          return row.vulnerabilityId;
      }
    },
    (row) => row.id,
  );

  return (
    <Card>
      <CardHeader
        title="Accepted risks"
        subtitle="Findings an administrator has assessed and excluded from every count. Excluded, never deleted — so the decision stays auditable."
      />
      {isLoading ? (
        <LoadingBlock label="Loading accepted risks" />
      ) : !suppressions || suppressions.length === 0 ? (
        <EmptyState
          title="Nothing has been accepted"
          hint="Accept a risk from a findings list when a vulnerability does not apply in context. Every count on the dashboards then excludes it."
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th onSort={() => sort.toggle("vulnerability")} sorted={sort.stateOf("vulnerability")} width="190px">
                  Advisory
                </Th>
                <Th onSort={() => sort.toggle("severity")} sorted={sort.stateOf("severity")} width="90px">
                  Severity
                </Th>
                <Th onSort={() => sort.toggle("scope")} sorted={sort.stateOf("scope")} width="200px">
                  Scope
                </Th>
                {/* Free text written by whoever accepted the risk. */}
                <Th>Reason</Th>
                <Th onSort={() => sort.toggle("acceptedBy")} sorted={sort.stateOf("acceptedBy")} width="150px">
                  Accepted by
                </Th>
                <Th onSort={() => sort.toggle("expiresAt")} sorted={sort.stateOf("expiresAt")} width="120px">
                  Expires
                </Th>
                <Th width="80px" />
              </tr>
            </thead>
            <tbody>
              {sort.rows.map((s) => (
                <Tr key={s.id}>
                  <Td>
                    <Link to={`/vulnerabilities/${encodeURIComponent(s.vulnerabilityId)}`} className="text-accent hover:underline">
                      <Mono>{s.vulnerabilityId}</Mono>
                    </Link>
                  </Td>
                  <Td>{s.severity ? <SeverityBadge severity={s.severity} /> : "—"}</Td>
                  <Td className="text-xs text-text-muted">
                    {/* Spelled out: an estate-wide suppression is a much bigger decision than a
                        per-package one, and the table has to make the difference obvious. */}
                    {s.componentName
                      ? `${s.componentName}${s.componentVersion ? ` ${s.componentVersion}` : ""}`
                      : s.applicationName
                        ? s.applicationName
                        : "Everywhere"}
                  </Td>
                  <Td className="max-w-[380px] truncate" title={s.reason}>
                    {s.reason}
                  </Td>
                  <Td className="text-text-muted">{s.createdByEmail ?? "—"}</Td>
                  <Td className="text-text-muted">
                    {s.expiresAt ? (
                      s.expired ? (
                        <Badge tone="warn" title="Past its review date, so it no longer applies.">
                          expired
                        </Badge>
                      ) : (
                        formatDateTime(s.expiresAt)
                      )
                    ) : (
                      "never"
                    )}
                  </Td>
                  <Td>
                    <Button size="sm" variant="ghost" onClick={() => remove.mutate(s.id)}>
                      Remove
                    </Button>
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
