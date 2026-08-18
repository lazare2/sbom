import { useEffect, useState } from "react";
import {
  REPORT_RECIPIENT_LIMIT,
  REPORT_TEMPLATE_PLACEHOLDERS,
  smtpEncryptions,
  type ReportRunSummary,
  type ReportSettings,
  type SmtpEncryption,
} from "@sbom/shared";
import { useReportRuns, useReportSettings } from "../../lib/queries.ts";
import {
  useGenerateReport,
  useSendReport,
  useTestReportEmail,
  useUpdateReportSettings,
} from "../../lib/mutations.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
  EmptyState,
  ErrorBanner,
  FormRow,
  LoadingBlock,
  Select,
  Table,
  TableWrap,
  Td,
  Textarea,
  TextInput,
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
      <DeliveryCard />
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
// delivery settings
// ---------------------------------------------------------------------------

const ENCRYPTION_LABELS: Record<SmtpEncryption, string> = {
  none: "None (plain SMTP)",
  starttls: "STARTTLS",
  tls: "TLS (implicit)",
};

/** Recipients are edited as one address per line, which is how people paste a list. */
function parseRecipients(text: string): string[] {
  return text
    .split(/[\n,;]+/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function DeliveryCard() {
  const query = useReportSettings();
  const update = useUpdateReportSettings();
  const test = useTestReportEmail();

  const [form, setForm] = useState<ReportSettings | null>(null);
  const [recipientText, setRecipientText] = useState("");
  const [testAddress, setTestAddress] = useState("");

  // Seeded once the server value arrives, and re-seeded if it changes underneath. Not on
  // every render, or typing would be overwritten by an in-flight query.
  useEffect(() => {
    if (query.data) {
      setForm(query.data);
      setRecipientText(query.data.recipients.join("\n"));
    }
  }, [query.data]);

  if (query.isLoading) return <Card><LoadingBlock /></Card>;
  if (query.error) {
    return (
      <Card>
        <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />
      </Card>
    );
  }
  if (!form) return null;

  const recipients = parseRecipients(recipientText);
  const set = <K extends keyof ReportSettings>(key: K, value: ReportSettings[K]) =>
    setForm({ ...form, [key]: value });

  const tooMany = recipients.length > REPORT_RECIPIENT_LIMIT;
  const canSave = !update.isPending && !tooMany;

  return (
    <Card>
      <CardHeader
        title="Delivery"
        subtitle="Where the monthly report is sent from, and to whom."
      />
      <div className="space-y-4 p-4">
        <Checkbox
          checked={form.enabled}
          onChange={(checked) => set("enabled", checked)}
          label="Send the report automatically each month"
        />
        <p className="text-xs text-text-muted">
          Sent on the first working day of the month, at the hour below, covering the month
          that has just finished. Weekends are skipped. If the service is down at that hour it
          sends when it comes back, and it cannot send the same month twice.
        </p>

        <div className="grid gap-3 sm:grid-cols-2">
          <FormRow
            label="Mail server"
            htmlFor="smtp-host"
            hint="Hostname or IP address only — no scheme, port or credentials."
          >
            <TextInput
              id="smtp-host"
              value={form.smtpHost}
              onChange={(value) => set("smtpHost", value)}
              placeholder="smtp.example.org"
            />
          </FormRow>
          <FormRow label="Port" htmlFor="smtp-port">
            <TextInput
              id="smtp-port"
              value={String(form.smtpPort)}
              onChange={(value) => set("smtpPort", Number(value) || 0)}
              placeholder="25"
            />
          </FormRow>
          <FormRow
            label="Encryption"
            htmlFor="smtp-encryption"
            hint="Most internal relays accept plain SMTP from inside the network."
          >
            <Select<SmtpEncryption>
              id="smtp-encryption"
              value={form.smtpEncryption}
              onChange={(value) => set("smtpEncryption", value)}
              options={smtpEncryptions.map((value) => ({
                value,
                label: ENCRYPTION_LABELS[value],
              }))}
            />
          </FormRow>
          <FormRow label="From address" htmlFor="smtp-from">
            <TextInput
              id="smtp-from"
              value={form.smtpFrom}
              onChange={(value) => set("smtpFrom", value)}
              placeholder="sbom-platform@example.org"
            />
          </FormRow>
          <FormRow
            label="Time zone"
            htmlFor="report-tz"
            hint="Decides both the reporting month and the hour it is sent."
          >
            <TextInput
              id="report-tz"
              value={form.timeZone}
              onChange={(value) => set("timeZone", value)}
              placeholder="Asia/Tbilisi"
            />
          </FormRow>
          <FormRow label="Send at (hour, 24h)" htmlFor="report-hour">
            <TextInput
              id="report-hour"
              value={String(form.sendHour)}
              onChange={(value) => set("sendHour", Number(value) || 0)}
              placeholder="9"
            />
          </FormRow>
        </div>

        <FormRow
          label="Recipients"
          htmlFor="report-recipients"
          hint={`One address per line. ${recipients.length} of ${REPORT_RECIPIENT_LIMIT} used.`}
          error={tooMany ? `At most ${REPORT_RECIPIENT_LIMIT} recipients.` : undefined}
        >
          <Textarea
            id="report-recipients"
            rows={4}
            value={recipientText}
            onChange={setRecipientText}
            placeholder={"management@example.org\nsecurity@example.org"}
          />
        </FormRow>

        {/*
          No password field, and the absence is stated rather than left as a gap someone
          later "fixes". A secret held in this table would be readable by every administrator
          and written to the audit log the moment it changed.
        */}
        <p className="text-xs text-text-faint">
          There is no username or password: the report is sent through a relay that accepts
          mail from this server without authenticating it. If your relay requires credentials,
          they belong in the deployment environment rather than on this page.
        </p>

        <div className="border-t border-border-base pt-4">
          <TemplateFields form={form} set={set} />
        </div>

        <div className="flex flex-wrap items-center gap-3 border-t border-border-base pt-4">
          <Button
            variant="primary"
            size="sm"
            disabled={!canSave}
            onClick={() => update.mutate({ ...form, recipients })}
          >
            {update.isPending ? "Saving…" : "Save"}
          </Button>

          <span className="text-xs text-text-faint">Send a test message to:</span>
          <div className="w-64">
            <TextInput
              value={testAddress}
              onChange={setTestAddress}
              ariaLabel="Test recipient"
              placeholder="you@example.org"
            />
          </div>
          <Button
            size="sm"
            disabled={test.isPending || testAddress.trim() === ""}
            onClick={() => test.mutate(testAddress.trim())}
          >
            {test.isPending ? "Sending…" : "Send test"}
          </Button>
          {test.isSuccess ? <span className="text-xs text-ok">Test message sent.</span> : null}
        </div>

        {/*
          A failing test is the whole point of the button, so its error is shown in full
          rather than as "something went wrong": the relay's own message is what tells an
          administrator whether the host is wrong, the port is closed or the sender refused.
        */}
        {test.error ? <ErrorBanner error={test.error} /> : null}
        {update.error ? <ErrorBanner error={update.error} /> : null}
      </div>
    </Card>
  );
}

function TemplateFields({
  form,
  set,
}: {
  form: ReportSettings;
  set: <K extends keyof ReportSettings>(key: K, value: ReportSettings[K]) => void;
}) {
  return (
    <div className="space-y-3">
      <FormRow label="Email subject" htmlFor="report-subject">
        <TextInput
          id="report-subject"
          value={form.subjectTemplate}
          onChange={(value) => set("subjectTemplate", value)}
        />
      </FormRow>
      <FormRow
        label="Email body"
        htmlFor="report-body"
        hint="Plain text. The report itself is attached as a PDF."
      >
        <Textarea
          id="report-body"
          rows={10}
          value={form.bodyTemplate}
          onChange={(value) => set("bodyTemplate", value)}
        />
      </FormRow>
      <div className="text-xs text-text-faint">
        Available placeholders:{" "}
        {REPORT_TEMPLATE_PLACEHOLDERS.map((placeholder, index) => (
          <span key={placeholder}>
            {index > 0 ? ", " : ""}
            <code className="rounded bg-bg-subtle px-1 py-0.5 text-[11px]">{placeholder}</code>
          </span>
        ))}
        . Anything else is left exactly as typed, so a misspelled placeholder shows up in the
        email rather than disappearing.
      </div>
    </div>
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
