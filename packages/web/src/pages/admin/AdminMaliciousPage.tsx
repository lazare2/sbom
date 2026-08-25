import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { MaliciousFeedAttempt, MaliciousSettings, MaliciousStatus } from "@sbom/shared";
import { api } from "../../lib/api.ts";
import { useUpdateMaliciousFeed, useUpdateMaliciousSettings } from "../../lib/mutations.ts";
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
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";

/**
 * Administering malicious-package detection.
 *
 * Separate from the vulnerability-scanning tab even though the two look similar, because they
 * are independently switchable and an operator has real reasons to run one without the other.
 * This one needs no scanner binary and no multi-gigabyte database — it is a 40 MB download and
 * a name lookup — so an estate that cannot host Grype can still have this.
 */

interface SettingsResponse {
  settings: MaliciousSettings;
  status: MaliciousStatus;
}

/**
 * Share of the installed feed confirmed by more than one reporter.
 *
 * A percentage rather than a count, because the count on its own says nothing without the
 * denominator, and the denominator is 236,000. One decimal place: the figure moves slowly and
 * rounding to whole percents would hide a feed addition doing exactly what it was added for.
 */
function sharePercent(b: { corroborated: number; singleSource: number; unattributed: number }): string {
  const total = b.corroborated + b.singleSource + b.unattributed;
  if (total === 0) return "—";
  return `${((b.corroborated / total) * 100).toFixed(1)}%`;
}

export function AdminMaliciousPage() {
  const settingsQuery = useQuery({
    queryKey: ["admin", "malicious", "settings"],
    queryFn: () => api.get<SettingsResponse>("/admin/malicious/settings"),
    refetchInterval: (query) =>
      // Polled only while something is actually moving, so an idle admin page is not a
      // permanent source of requests.
      query.state.data?.status.refreshing || query.state.data?.status.sweeping ? 3000 : false,
  });
  const historyQuery = useQuery({
    queryKey: ["admin", "malicious", "history"],
    queryFn: () => api.get<{ attempts: MaliciousFeedAttempt[] }>("/admin/malicious/history?limit=10"),
    select: (data) => data.attempts,
  });

  const update = useUpdateMaliciousSettings();
  const refresh = useUpdateMaliciousFeed();

  const [intervalHours, setIntervalHours] = useState("6");
  const [feedUrl, setFeedUrl] = useState("");
  const [recipients, setRecipients] = useState("");

  const settings = settingsQuery.data?.settings;
  const status = settingsQuery.data?.status;

  useEffect(() => {
    if (!settings) return;
    setIntervalHours(String(settings.intervalHours));
    setFeedUrl(settings.feedUrl);
    setRecipients(settings.alertRecipients.join(", "));
  }, [settings]);

  if (settingsQuery.isLoading) return <LoadingBlock label="Loading settings" />;
  if (settingsQuery.error) {
    return <ErrorBanner error={settingsQuery.error} onRetry={() => void settingsQuery.refetch()} />;
  }
  if (!settings || !status) return null;

  const parsedRecipients = recipients
    .split(/[,\n]/)
    .map((r) => r.trim())
    .filter((r) => r !== "");

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="Malicious package detection"
          subtitle="Matches the estate against the OpenSSF malicious-packages feed — typosquats, dependency-confusion stubs, and legitimate packages whose maintainer accounts were compromised. Apache-2.0, no account or key required."
          actions={
            <Button
              variant={settings.enabled ? "secondary" : "primary"}
              disabled={update.isPending}
              onClick={() => update.mutate({ enabled: !settings.enabled })}
            >
              {update.isPending ? "Saving…" : settings.enabled ? "Disable" : "Enable"}
            </Button>
          }
        />
        <div className="p-4">
          <FormError error={update.error} />
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Field label="Status">
              {settings.enabled ? <Badge tone="ok">Enabled</Badge> : <Badge tone="neutral">Disabled</Badge>}
            </Field>
            <Field label="Reports installed">
              {/*
                Null, not zero, before the first download. "0 reports" reads as a feed that
                found nothing rather than one that has never been fetched.
              */}
              {status.reportCount === null ? (
                <span className="text-text-muted">No feed yet</span>
              ) : (
                formatNumber(status.reportCount)
              )}
            </Field>
            <Field label="Feed built">
              {status.feedBuiltAt ? (
                <span title={formatDateTime(status.feedBuiltAt)}>
                  {formatRelative(status.feedBuiltAt)}
                </span>
              ) : (
                <span className="text-text-muted">Never</span>
              )}
            </Field>
            <Field label="Corroborated">
              {/*
                The baseline the whole "add more feeds" question turns on. Shown as a share
                rather than a bare count because the number that matters is the proportion --
                if a second feed is worth its complexity, this percentage rises.
              */}
              {status.corroboration === null ? (
                <span className="text-text-muted">No feed yet</span>
              ) : (
                <span
                  title={
                    `${formatNumber(status.corroboration.corroborated)} confirmed by 2+ reporters, ` +
                    `${formatNumber(status.corroboration.singleSource)} by one, ` +
                    `${formatNumber(status.corroboration.unattributed)} with no attribution recorded, ` +
                    `across ${formatNumber(status.corroboration.reporters)} reporters.`
                  }
                >
                  {sharePercent(status.corroboration)}
                  {/*
                    The denominator is spelled out because "6.4% of 8 reporters" -- the first
                    wording here -- reads as a share of the reporters rather than of the
                    reports, which is a different and much more flattering number. The
                    reporter count moved into the tooltip, where it cannot be misparsed as
                    the thing being divided.
                  */}
                  <span className="text-text-muted">
                    {" "}
                    of {formatNumber(
                      status.corroboration.corroborated +
                        status.corroboration.singleSource +
                        status.corroboration.unattributed,
                    )}{" "}
                    reports
                  </span>
                </span>
              )}
            </Field>
            <Field label="Packages checked">
              {status.coverage === null ? (
                <span className="text-text-muted">Not assessed</span>
              ) : (
                <>
                  {formatNumber(status.coverage.matched)}
                  {status.coverage.pending > 0 ? (
                    <span className="text-warn"> · {formatNumber(status.coverage.pending)} pending</span>
                  ) : null}
                </>
              )}
            </Field>
          </dl>

          {status.refreshing || status.sweeping ? (
            <p className="mt-3 text-xs text-accent">
              {status.refreshing ? "Downloading the feed…" : "Matching packages…"}
            </p>
          ) : null}
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Feed"
          actions={
            <Button
              disabled={refresh.isPending || !settings.enabled}
              onClick={() => refresh.mutate()}
            >
              {refresh.isPending ? "Refreshing…" : "Refresh now"}
            </Button>
          }
          subtitle="The feed is a single archive of roughly 236,000 reports. Refreshing takes under a minute and replaces the installed snapshot."
        />
        <div className="space-y-3 p-4">
          <FormError error={refresh.error} />
          {refresh.data ? (
            <p className="text-xs text-text-muted">
              Last refresh: <strong className="text-text-base">{refresh.data.outcome}</strong>
              {refresh.data.message ? ` — ${refresh.data.message}` : ""}
            </p>
          ) : null}

          <FormRow label="Refresh every (hours)" htmlFor="mal-interval">
            <TextInput id="mal-interval" value={intervalHours} onChange={setIntervalHours} />
          </FormRow>

          <FormRow label="Feed URL" htmlFor="mal-url">
            <TextInput id="mal-url" value={feedUrl} onChange={setFeedUrl} />
          </FormRow>
          <p className="text-xs text-text-faint">
            Override to point at an internal mirror. An air-gapped deployment records every
            failed attempt below with the URL it could not reach, rather than silently
            reporting nothing found.
          </p>

          <div>
            <Button
              variant="primary"
              disabled={update.isPending}
              onClick={() =>
                update.mutate({
                  intervalHours: Number(intervalHours),
                  feedUrl: feedUrl.trim(),
                })
              }
            >
              Save
            </Button>
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Email alerts"
          subtitle="Sent once per package per application, as soon as a finding appears. Uses the SMTP relay configured on the Monthly report tab."
        />
        <div className="space-y-3 p-4">
          <Checkbox
            checked={settings.alertsEnabled}
            onChange={(alertsEnabled) => update.mutate({ alertsEnabled })}
            label="Email when a malicious package is found"
          />

          <FormRow label="Recipients" htmlFor="mal-recipients">
            <TextInput
              id="mal-recipients"
              value={recipients}
              onChange={setRecipients}
              placeholder="security@example.com, oncall@example.com"
            />
          </FormRow>
          <p className="text-xs text-text-faint">
            Kept separate from the monthly report&rsquo;s distribution list on purpose: the
            people who want a management summary once a month are rarely the people who should
            be woken up for this.
          </p>

          <div>
            <Button
              variant="primary"
              disabled={update.isPending}
              onClick={() => update.mutate({ alertRecipients: parsedRecipients })}
            >
              Save recipients
            </Button>
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Refresh history"
          subtitle="Every attempt, successful or not — so a stale feed can be explained rather than guessed at."
        />
        {historyQuery.isLoading ? (
          <LoadingBlock label="Loading history" />
        ) : !historyQuery.data || historyQuery.data.length === 0 ? (
          <EmptyState title="No refreshes yet" hint="Enable detection to fetch the feed." />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th width="170px">Started</Th>
                  <Th width="100px">Trigger</Th>
                  <Th width="110px">Outcome</Th>
                  <Th align="right" width="100px">
                    Reports
                  </Th>
                  <Th align="right" width="100px">
                    Changed
                  </Th>
                  <Th>Detail</Th>
                </tr>
              </thead>
              <tbody>
                {historyQuery.data.map((attempt) => (
                  <Tr key={attempt.id}>
                    <Td title={formatDateTime(attempt.startedAt)}>
                      {formatRelative(attempt.startedAt)}
                    </Td>
                    <Td className="text-text-muted">{attempt.trigger}</Td>
                    <Td>
                      <Badge
                        tone={
                          attempt.outcome === "updated"
                            ? "ok"
                            : attempt.outcome === "unchanged"
                              ? "neutral"
                              : attempt.outcome === "unreachable"
                                ? "warn"
                                : "danger"
                        }
                      >
                        {attempt.outcome ?? "running"}
                      </Badge>
                    </Td>
                    <Td align="right" className="nums text-text-muted">
                      {attempt.reportsTotal === null ? "—" : formatNumber(attempt.reportsTotal)}
                    </Td>
                    <Td align="right" className="nums text-text-muted">
                      {attempt.reportsChanged === null ? "—" : formatNumber(attempt.reportsChanged)}
                    </Td>
                    <Td className="text-xs text-text-faint">
                      {attempt.message ?? attempt.sourceUrl ?? "—"}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>
    </div>
  );
}
