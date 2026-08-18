import { useEffect, useState } from "react";
import { Link } from "react-router";
import {
  REPORT_RECIPIENT_LIMIT,
  REPORT_TEMPLATE_PLACEHOLDERS,
  STALE_THRESHOLD_MAX_DAYS,
  STALE_THRESHOLD_MIN_DAYS,
  VULN_DB_INTERVAL_MAX_HOURS,
  VULN_DB_INTERVAL_MIN_HOURS,
  smtpEncryptions,
  type ReportSettings,
  type SmtpEncryption,
} from "@sbom/shared";
import {
  usePlatformSettings,
  useReportSettings,
  useVulnAdminStatus,
} from "../../lib/queries.ts";
import {
  useTestReportEmail,
  useUpdatePlatformSettings,
  useUpdateReportSettings,
  useUpdateVulnSettings,
} from "../../lib/mutations.ts";
import {
  Button,
  Card,
  CardHeader,
  ErrorBanner,
  FormRow,
  LoadingBlock,
  Select,
  Textarea,
  TextInput,
} from "../../components/ui.tsx";

/**
 * Every value an administrator sets once and forgets, in one place.
 *
 * The line this page draws is between *configuration* and *operation*, not between
 * settings and everything else. A tuning knob — how many days is stale, how often to check
 * for a database, which relay to mail through — is set during setup and rarely touched
 * again, and gathering those makes "what is this deployment configured to do" answerable on
 * one screen.
 *
 * Master on/off switches deliberately stay where the evidence for flipping them is.
 * Enabling vulnerability scanning is a decision made while looking at whether the scanner
 * binary exists and whether a database is installed; moving that switch here would separate
 * it from the only information that makes it meaningful. Each of those tabs links here for
 * the knobs, and this page links back for the switches.
 *
 * Every section saves independently. One button spanning three endpoints would produce
 * partial failures — the relay saved, the threshold rejected — with no way to report which.
 */
export function AdminConfigurationPage() {
  return (
    <div className="space-y-4">
      <StaleThresholdCard />
      <VulnIntervalCard />
      <ReportDeliveryCard />
    </div>
  );
}

// ---------------------------------------------------------------------------
// estate
// ---------------------------------------------------------------------------

function StaleThresholdCard() {
  const query = usePlatformSettings();
  const update = useUpdatePlatformSettings();
  const current = query.data?.settings.staleThresholdDays;

  const [days, setDays] = useState("");
  // Seeded from the server once it arrives, and re-seeded if it changes underneath -- but
  // not on every render, or typing would be overwritten by the in-flight query.
  useEffect(() => {
    if (current !== undefined) setDays(String(current));
  }, [current]);

  const parsed = Number(days);
  const valid =
    days.trim() !== "" &&
    Number.isInteger(parsed) &&
    parsed >= STALE_THRESHOLD_MIN_DAYS &&
    parsed <= STALE_THRESHOLD_MAX_DAYS;
  const changed = current !== undefined && parsed !== current;

  return (
    <Card>
      <CardHeader
        title="Stale applications"
        subtitle="How long an application can go without a scan before it is reported as stale."
      />
      {query.isLoading ? (
        <LoadingBlock />
      ) : query.error ? (
        <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />
      ) : (
        <div className="space-y-4 p-4">
          <div className="max-w-xs">
            <FormRow label="Days without a scan">
              <TextInput value={days} onChange={setDays} ariaLabel="Days without a scan" />
            </FormRow>
          </div>
          <p className="text-xs text-text-muted">
            {/*
              Named consequences rather than a bare range. The number decides what the
              overview, the applications list and the analytics report each call stale, and
              a reader deserves to know that before changing it.
            */}
            Between {STALE_THRESHOLD_MIN_DAYS} and {formatDays(STALE_THRESHOLD_MAX_DAYS)}. This
            is the right number for how often your teams actually build: weekly releases and
            quarterly releases disagree about it by an order of magnitude. Changing it takes
            effect immediately across the overview, the applications list and the analytics
            report — no scan has to run, and none of the underlying data changes.
          </p>
          {!valid && days.trim() !== "" ? (
            <p className="text-xs text-danger">
              Enter a whole number between {STALE_THRESHOLD_MIN_DAYS} and{" "}
              {STALE_THRESHOLD_MAX_DAYS}.
            </p>
          ) : null}
          <div className="flex items-center gap-3">
            <Button
              variant="primary"
              size="sm"
              disabled={!valid || !changed || update.isPending}
              onClick={() => update.mutate({ staleThresholdDays: parsed })}
            >
              {update.isPending ? "Saving…" : "Save threshold"}
            </Button>
            {current !== undefined ? (
              <span className="text-xs text-text-faint">Currently {formatDays(current)}.</span>
            ) : null}
          </div>
          {update.error ? <ErrorBanner error={update.error} /> : null}
        </div>
      )}
    </Card>
  );
}

/** "30 days", but "1 day" rather than "1 days". */
function formatDays(n: number): string {
  return `${n} ${n === 1 ? "day" : "days"}`;
}

// ---------------------------------------------------------------------------
// vulnerability database
// ---------------------------------------------------------------------------

function VulnIntervalCard() {
  const query = useVulnAdminStatus();
  const update = useUpdateVulnSettings();
  const status = query.data;
  const current = status?.updates.intervalHours;

  const [hours, setHours] = useState("");
  useEffect(() => {
    if (current !== undefined) setHours(String(current));
  }, [current]);

  const parsed = Number(hours);
  const valid =
    Number.isFinite(parsed) &&
    parsed >= VULN_DB_INTERVAL_MIN_HOURS &&
    parsed <= VULN_DB_INTERVAL_MAX_HOURS;
  const changed = current !== undefined && parsed !== current;

  return (
    <Card>
      <CardHeader
        title="Vulnerability database updates"
        subtitle="How often to check Anchore for a newer database."
      />
      {query.isLoading ? (
        <LoadingBlock />
      ) : query.error ? (
        <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />
      ) : (
        <div className="space-y-4 p-4">
          <div className="max-w-xs">
            <FormRow
              label="Check for updates every"
              htmlFor="vuln-interval"
              hint={`Hours. ${VULN_DB_INTERVAL_MIN_HOURS}–${VULN_DB_INTERVAL_MAX_HOURS} allowed.`}
            >
              <TextInput id="vuln-interval" value={hours} onChange={setHours} />
            </FormRow>
          </div>
          {/*
            Anchore rebuilds roughly daily, so a 3-hour check is a cheap listing request that
            usually finds nothing — worth saying, because "every 3 hours" otherwise sounds
            like eight 141 MB downloads a day.
          */}
          <p className="text-xs text-text-muted">
            A check fetches a small listing file first and only downloads when the published
            database is newer. Anchore rebuilds it about once a day, so most checks transfer
            nothing.
          </p>
          {!valid && hours.trim() !== "" ? (
            <p className="text-xs text-danger">
              Enter a number between {VULN_DB_INTERVAL_MIN_HOURS} and{" "}
              {VULN_DB_INTERVAL_MAX_HOURS}.
            </p>
          ) : null}
          <div className="flex flex-wrap items-center gap-3">
            <Button
              variant="primary"
              size="sm"
              disabled={!valid || !changed || update.isPending}
              onClick={() => update.mutate({ intervalHours: parsed })}
            >
              {update.isPending ? "Saving…" : "Save interval"}
            </Button>
            {/*
              The switch itself lives with the scanner status that justifies flipping it, so
              this states the current position rather than silently ignoring it: an interval
              that will never fire is worth knowing about while editing it.
            */}
            {status && !status.enabled ? (
              <span className="text-xs text-text-faint">
                Scanning is off, so no checks are scheduled.{" "}
                <Link to="/admin/vulnerabilities" className="text-accent hover:underline">
                  Vulnerability scanning
                </Link>
              </span>
            ) : null}
          </div>
          {update.error ? <ErrorBanner error={update.error} /> : null}
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// monthly report delivery
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

function ReportDeliveryCard() {
  const query = useReportSettings();
  const update = useUpdateReportSettings();
  const test = useTestReportEmail();

  const [form, setForm] = useState<ReportSettings | null>(null);
  const [recipientText, setRecipientText] = useState("");
  const [testAddress, setTestAddress] = useState("");

  useEffect(() => {
    if (query.data) {
      setForm(query.data);
      setRecipientText(query.data.recipients.join("\n"));
    }
  }, [query.data]);

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
  if (!form) return null;

  const recipients = parseRecipients(recipientText);
  const set = <K extends keyof ReportSettings>(key: K, value: ReportSettings[K]) =>
    setForm({ ...form, [key]: value });

  const tooMany = recipients.length > REPORT_RECIPIENT_LIMIT;

  return (
    <Card>
      <CardHeader
        title="Monthly report delivery"
        subtitle="Where the monthly report is sent from, to whom, and what the email says."
      />
      <div className="space-y-4 p-4">
        {/*
          `enabled` is not edited here -- it stays on the report tab beside the history that
          shows whether delivery is working. It rides along in the saved object untouched,
          which is why the form is seeded from the server rather than field by field.
        */}
        <p className="text-xs text-text-muted">
          The report is sent on the first working day of each month, at the hour below,
          covering the month that has just finished. Weekends are skipped. Turn scheduled
          sending on or off under{" "}
          <Link to="/admin/reports" className="text-accent hover:underline">
            Monthly report
          </Link>
          .
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

        <div className="space-y-3 border-t border-border-base pt-4">
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
            . Anything else is left exactly as typed, so a misspelled placeholder shows up in
            the email rather than disappearing.
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 border-t border-border-base pt-4">
          <Button
            variant="primary"
            size="sm"
            disabled={update.isPending || tooMany}
            onClick={() => update.mutate({ ...form, recipients })}
          >
            {update.isPending ? "Saving…" : "Save delivery settings"}
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
