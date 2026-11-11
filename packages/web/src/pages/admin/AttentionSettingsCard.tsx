import { useEffect, useState } from "react";
import { attentionSettingsSchema, DEFAULT_ATTENTION_SETTINGS, type AttentionSettings } from "@sbom/shared";
import { useAttentionSettings } from "../../lib/queries.ts";
import { useUpdateAttentionSettings } from "../../lib/mutations.ts";
import { Button, Card, CardHeader, Checkbox, ErrorBanner, FormRow, LoadingBlock, TextInput } from "../../components/ui.tsx";

/** The form holds strings so a half-typed number is not coerced while the admin is typing. */
type Draft = Record<Exclude<keyof AttentionSettings, "buildOverdueMode" | "useMultiplier">, string> &
  Pick<AttentionSettings, "buildOverdueMode" | "useMultiplier">;

function toDraft(s: AttentionSettings): Draft {
  return {
    buildOverdueMode: s.buildOverdueMode,
    useMultiplier: s.useMultiplier,
    fixedDays: String(s.fixedDays),
    multiplier: String(s.multiplier),
    minimumDays: String(s.minimumDays),
    cadenceWindowDays: String(s.cadenceWindowDays),
    minimumBuilds: String(s.minimumBuilds),
    criticalFixDays: String(s.criticalFixDays),
  };
}

/**
 * When Analytics flags a project as needing attention.
 *
 * Build overdue has two modes, chosen here: one fixed limit for every project, or each project
 * judged against its own usual pace. Every number is explained where it is entered, because
 * these decide which teams the analytics page and the monthly report name.
 */
export function AttentionSettingsCard() {
  const query = useAttentionSettings();
  const update = useUpdateAttentionSettings();
  const current = query.data?.settings;
  const [draft, setDraft] = useState<Draft>(toDraft(DEFAULT_ATTENTION_SETTINGS));

  useEffect(() => {
    if (current) setDraft(toDraft(current));
  }, [current]);

  const parsed = attentionSettingsSchema.safeParse(draft);
  const issues = parsed.success
    ? {}
    : Object.fromEntries(parsed.error.issues.map((i) => [String(i.path[0]), i.message]));
  const changed = current !== undefined && parsed.success && JSON.stringify(parsed.data) !== JSON.stringify(current);
  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));
  const average = draft.buildOverdueMode === "average";

  return (
    <Card>
      <CardHeader
        title="Needs attention"
        subtitle="When Analytics and the monthly report flag a project. Every flag states the reason it was raised, using these numbers."
      />
      {query.isLoading ? (
        <LoadingBlock />
      ) : query.error ? (
        <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />
      ) : (
        <div className="space-y-5 p-4">
          <section className="space-y-3">
            <h3 className="text-xs font-semibold text-text-base">Build overdue</h3>
            <div role="radiogroup" aria-label="Build overdue mode" className="space-y-2">
              {(
                [
                  [
                    "average",
                    "Each project's average days between builds",
                    "A project is judged against its own pace: a service built every two days is overdue long before a monthly job is.",
                  ],
                  ["fixed", "A fixed number of days", "Every project is flagged the same number of days after its last build."],
                ] as const
              ).map(([value, label, hint]) => (
                <label key={value} className="flex cursor-pointer items-start gap-2 text-sm">
                  <input
                    type="radio"
                    name="build-overdue-mode"
                    className="mt-1"
                    checked={draft.buildOverdueMode === value}
                    onChange={() => set({ buildOverdueMode: value })}
                  />
                  <span>
                    <span className="font-medium text-text-base">{label}</span>
                    <span className="block text-xs text-text-muted">{hint}</span>
                  </span>
                </label>
              ))}
            </div>

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <FormRow
                label="Fixed limit (days)"
                hint={average ? "Also used for projects with too little history for an average." : undefined}
                error={issues.fixedDays}
              >
                <TextInput value={draft.fixedDays} onChange={(v) => set({ fixedDays: v })} ariaLabel="Fixed limit in days" />
              </FormRow>
              {average ? (
                <>
                  <FormRow label="Average over the last (days)" error={issues.cadenceWindowDays}>
                    <TextInput
                      value={draft.cadenceWindowDays}
                      onChange={(v) => set({ cadenceWindowDays: v })}
                      ariaLabel="Average over the last days"
                    />
                  </FormRow>
                  <FormRow label="Builds needed for an average" error={issues.minimumBuilds}>
                    <TextInput
                      value={draft.minimumBuilds}
                      onChange={(v) => set({ minimumBuilds: v })}
                      ariaLabel="Builds needed for an average"
                    />
                  </FormRow>
                  <FormRow label="Never sooner than (days)" error={issues.minimumDays}>
                    <TextInput value={draft.minimumDays} onChange={(v) => set({ minimumDays: v })} ariaLabel="Never sooner than days" />
                  </FormRow>
                </>
              ) : null}
            </div>

            {average ? (
              <div className="flex flex-wrap items-end gap-4">
                <Checkbox
                  checked={draft.useMultiplier}
                  onChange={(useMultiplier) => set({ useMultiplier })}
                  label="Allow slack beyond the average"
                />
                {/* Shown only while slack is on: a multiplier that is ignored reads as one that applies. */}
                {draft.useMultiplier ? (
                  <div className="w-40">
                    <FormRow label="Multiplier" error={issues.multiplier}>
                      <TextInput value={draft.multiplier} onChange={(v) => set({ multiplier: v })} ariaLabel="Multiplier" />
                    </FormRow>
                  </div>
                ) : null}
              </div>
            ) : null}

            <p className="text-xs text-text-muted">
              {average ? (
                <>
                  A project is flagged once it has gone{" "}
                  {draft.useMultiplier ? `${draft.multiplier || "?"} times` : "longer than"} its average gap between builds
                  over the last {draft.cadenceWindowDays || "?"} days, and never sooner than {draft.minimumDays || "?"} days.
                  With fewer than {draft.minimumBuilds || "?"} builds in that time it has no usable average, and the fixed{" "}
                  {draft.fixedDays || "?"}-day limit applies - the flag says so. Identical rebuilds count as builds here.
                </>
              ) : (
                <>Every project is flagged after {draft.fixedDays || "?"} days without a build.</>
              )}
            </p>
          </section>

          <section className="space-y-2">
            <h3 className="text-xs font-semibold text-text-base">Critical fix overdue</h3>
            <div className="max-w-xs">
              <FormRow label="Open longer than (days)" error={issues.criticalFixDays}>
                <TextInput
                  value={draft.criticalFixDays}
                  onChange={(v) => set({ criticalFixDays: v })}
                  ariaLabel="Critical fix open longer than days"
                />
              </FormRow>
            </div>
            <p className="text-xs text-text-muted">
              A critical finding with a fixed version available, still open in the current build after this long. Known-exploited
              advisories are flagged at any age, and builds that introduce more than they fix are flagged in any window.
            </p>
          </section>

          <div className="flex items-center gap-3">
            <Button
              variant="primary"
              size="sm"
              disabled={!parsed.success || !changed || update.isPending}
              onClick={() => parsed.success && update.mutate(parsed.data)}
            >
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setDraft(toDraft(DEFAULT_ATTENTION_SETTINGS))}>
              Restore defaults
            </Button>
          </div>
          {update.error ? <ErrorBanner error={update.error} /> : null}
        </div>
      )}
    </Card>
  );
}
