import { Link } from "react-router";
import type { ReportRunSummary } from "@sbom/shared";
import { useReportRuns, useReportSettings } from "../../lib/queries.ts";
import { useGenerateReport, useSendReport, useUpdateReportSettings } from "../../lib/mutations.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Mono,
  Table,
  TableWrap,
  Td,
  Th,
  Tr,
} from "../../components/ui.tsx";
import { formatDateTime } from "../../lib/format.ts";

/**
 * The monthly management report: produce one now, configure who receives it, and see what
 * was sent.
 *
 * The history table is the part that matters most and is easiest to leave out. A report that
 * goes to management every month is a record of what management was told, and an
 * administrator asked "what did they get in July, and did it actually arrive" needs to be
 * able to answer without reading a mail server log.
 */
export function AdminReportsPage() {
  return (
    <div className="space-y-4">
      <GenerateCard />
      <ScheduleCard />
      <HistoryCard />
    </div>
  );
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

function GenerateCard() {
  const generate = useGenerateReport();
  const settings = useReportSettings();

  return (
    <Card>
      <CardHeader
        title="Generate a report"
        subtitle="Produces a report covering the month so far and compares it with the last monthly report."
      />
      <div className="space-y-3 p-4">
        <p className="text-xs text-text-muted">
          {/*
            The distinction between the two kinds is the one thing a reader has to understand
            before pressing this, because it is invisible afterwards.
          */}
          This produces a report to look at. It is not emailed, and it does not become the
          comparison point for next month — the scheduled monthly report keeps that role, so
          pressing this cannot shorten the period the next report covers.
        </p>
        <div className="flex items-center gap-3">
          <Button
            variant="primary"
            size="sm"
            disabled={generate.isPending}
            onClick={() => generate.mutate("adhoc")}
          >
            {generate.isPending ? "Generating…" : "Generate now"}
          </Button>
          {generate.data ? (
            <a
              href={`/api/v1/admin/reports/${generate.data.run.id}.pdf`}
              className="text-sm text-accent hover:underline"
            >
              Download {generate.data.run.periodLabel} report
            </a>
          ) : null}
        </div>
        {generate.error ? <ErrorBanner error={generate.error} /> : null}
        {settings.data && !settings.data.enabled ? (
          <p className="text-xs text-text-faint">
            Scheduled monthly delivery is currently off. Reports generated here are still
            stored and can be downloaded below.
          </p>
        ) : null}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// scheduled delivery
// ---------------------------------------------------------------------------

/**
 * The master switch, kept here rather than with the relay settings it depends on.
 *
 * This is the one report control an administrator flips while looking at something: the
 * history below is the evidence that delivery is actually working, and a switch separated
 * from its evidence is a switch nobody trusts.
 *
 * It cannot be turned on until a relay, a sender and at least one recipient exist, because
 * the server rejects a half-configured object and a checkbox that fails with a validation
 * error is worse than one that explains why it is unavailable.
 */
function ScheduleCard() {
  const query = useReportSettings();
  const update = useUpdateReportSettings();
  const settings = query.data;

  if (query.isLoading) {
    return (
      <Card>
        <LoadingBlock />
      </Card>
    );
  }
  if (query.error) {
    return (
      <Card>
        <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />
      </Card>
    );
  }
  if (!settings) return null;

  const configured =
    settings.smtpHost.length > 0 &&
    settings.smtpFrom.length > 0 &&
    settings.recipients.length > 0;

  return (
    <Card>
      <CardHeader
        title="Scheduled delivery"
        subtitle="Whether the report is emailed automatically each month."
      />
      <div className="space-y-3 p-4">
        <Checkbox
          checked={settings.enabled}
          onChange={(enabled) => update.mutate({ ...settings, enabled })}
          label={
            settings.enabled
              ? "On — sent on the first working day of each month"
              : "Send the report automatically each month"
          }
          disabled={!configured || update.isPending}
        />

        {configured ? (
          <p className="text-xs text-text-muted">
            Sent to {settings.recipients.length}{" "}
            {settings.recipients.length === 1 ? "recipient" : "recipients"} at{" "}
            {String(settings.sendHour).padStart(2, "0")}:00 {settings.timeZone}, through{" "}
            <Mono>{settings.smtpHost}</Mono>. Weekends are skipped, and the same month cannot
            be sent twice.{" "}
            <Link to="/admin/configuration" className="text-accent hover:underline">
              Change delivery settings
            </Link>
          </p>
        ) : (
          /*
            Names the missing piece rather than saying "not configured". An administrator
            who has set the relay but no recipients should not have to guess which half is
            outstanding.
          */
          <p className="text-xs text-text-muted">
            Scheduled sending needs a mail server, a sender address and at least one
            recipient. Missing:{" "}
            {[
              settings.smtpHost.length === 0 ? "mail server" : null,
              settings.smtpFrom.length === 0 ? "sender address" : null,
              settings.recipients.length === 0 ? "recipients" : null,
            ]
              .filter(Boolean)
              .join(", ")}
            .{" "}
            <Link to="/admin/configuration" className="text-accent hover:underline">
              Configure delivery
            </Link>
          </p>
        )}

        {update.error ? <ErrorBanner error={update.error} /> : null}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

function HistoryCard() {
  const query = useReportRuns();
  const send = useSendReport();
  const items = query.data?.items ?? [];

  return (
    <Card>
      <CardHeader
        title="Report history"
        subtitle="Every report produced, and whether it reached its recipients."
      />
      {query.isLoading ? (
        <LoadingBlock />
      ) : query.error ? (
        <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState
          title="No reports yet"
          hint="Generate one above, or wait for the first working day of next month."
        />
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Period</Th>
                <Th>Kind</Th>
                <Th>Generated</Th>
                <Th align="right">Applications</Th>
                <Th align="right">Findings</Th>
                <Th>Delivery</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {items.map((run) => (
                <Tr key={run.id}>
                  <Td>{run.periodLabel}</Td>
                  <Td>
                    <Badge tone={run.kind === "monthly" ? "accent" : "neutral"}>
                      {run.kind === "monthly" ? "Monthly" : "On demand"}
                    </Badge>
                  </Td>
                  <Td>
                    <span title={run.generatedBy ?? "Scheduled"}>
                      {formatDateTime(run.generatedAt)}
                    </span>
                  </Td>
                  <Td align="right" className="nums">
                    {run.totals.applications}
                  </Td>
                  <Td align="right" className="nums">
                    {run.totals.findings}
                  </Td>
                  <Td>
                    <DeliveryCell run={run} />
                  </Td>
                  <Td align="right">
                    <div className="flex justify-end gap-2">
                      <a
                        href={`/api/v1/admin/reports/${run.id}.pdf`}
                        className="text-sm text-accent hover:underline"
                      >
                        PDF
                      </a>
                      {run.sentAt ? null : (
                        <Button
                          size="sm"
                          disabled={send.isPending}
                          onClick={() => send.mutate(run.id)}
                        >
                          Send
                        </Button>
                      )}
                    </div>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}
      {send.error ? (
        <div className="p-4">
          <ErrorBanner error={send.error} />
        </div>
      ) : null}
    </Card>
  );
}

function DeliveryCell({ run }: { run: ReportRunSummary }) {
  if (run.sentAt) {
    const count = run.recipients?.length ?? 0;
    return (
      <span className="text-xs text-ok" title={run.recipients?.join(", ")}>
        Sent to {count} {count === 1 ? "recipient" : "recipients"}
      </span>
    );
  }
  if (run.deliveryError) {
    // The relay's own message, not a paraphrase. It is the only thing that says whether the
    // host is wrong, the port is closed or one address was refused.
    return (
      <span className="text-xs text-danger" title={run.deliveryError}>
        Failed: {run.deliveryError}
      </span>
    );
  }
  return <span className="text-xs text-text-faint">Not sent</span>;
}
