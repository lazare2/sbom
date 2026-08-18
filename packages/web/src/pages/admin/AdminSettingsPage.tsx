import { useEffect, useState } from "react";
import {
  STALE_THRESHOLD_MAX_DAYS,
  STALE_THRESHOLD_MIN_DAYS,
} from "@sbom/shared";
import { usePlatformSettings } from "../../lib/queries.ts";
import { useUpdatePlatformSettings } from "../../lib/mutations.ts";
import {
  Button,
  Card,
  CardHeader,
  ErrorBanner,
  FormRow,
  LoadingBlock,
  TextInput,
} from "../../components/ui.tsx";

/**
 * Settings that belong to whoever runs the estate, rather than to whoever deployed it.
 *
 * The distinction is the same one `config.ts` and the settings table already draw: the
 * environment holds what deployment owns, and this page holds the handful of values an
 * administrator changes while the service runs. Nothing here can influence what code the
 * server executes, which is why it is safe to expose at all.
 */
export function AdminSettingsPage() {
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
    <div className="space-y-4">
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
                {update.isPending ? "Saving…" : "Save"}
              </Button>
              {current !== undefined ? (
                <span className="text-xs text-text-faint">
                  Currently {formatDays(current)}.
                </span>
              ) : null}
            </div>
            {update.error ? <ErrorBanner error={update.error} /> : null}
          </div>
        )}
      </Card>
    </div>
  );
}

/** "30 days", but "1 day" rather than "1 days". */
function formatDays(n: number): string {
  return `${n} ${n === 1 ? "day" : "days"}`;
}
