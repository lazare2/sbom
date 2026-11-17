import { useEffect, useState } from "react";
import { DEFAULT_TARGET_DATES, type TargetDates } from "@sbom/shared";
import { Button, Card, CardHeader, ErrorBanner, FormError, FormRow, LoadingBlock, TextInput } from "../../components/ui.tsx";
import { useUpdateTargetDates } from "../../lib/mutations.ts";
import { useTargetDates } from "../../lib/queries.ts";

const FIELDS: Array<{ key: keyof TargetDates; label: string; hint: string }> = [
  { key: "usedInAttacksDays", label: "Used in real attacks, fix available", hint: `Starts at ${DEFAULT_TARGET_DATES.usedInAttacksDays} days.` },
  {
    key: "criticalDays",
    label: "Critical, fix available",
    hint: "The same value as \"critical finding with a fix\" under Needs attention: changing one changes both.",
  },
  { key: "highDays", label: "High, fix available", hint: `Starts at ${DEFAULT_TARGET_DATES.highDays} days.` },
];

/**
 * Target dates: how many days a team has to fix a vulnerability, by rule. Everything else has
 * no target. Applies at once to every project's action plan and status.
 */
export function TargetDatesCard() {
  const current = useTargetDates();
  const save = useUpdateTargetDates();
  const [form, setForm] = useState<Record<keyof TargetDates, string> | null>(null);

  useEffect(() => {
    if (current.data && form === null) {
      const t = current.data.targets;
      setForm({ usedInAttacksDays: String(t.usedInAttacksDays), criticalDays: String(t.criticalDays), highDays: String(t.highDays) });
    }
  }, [current.data, form]);

  if (current.isLoading || form === null) return <LoadingBlock />;
  if (current.error) return <ErrorBanner error={current.error} onRetry={() => void current.refetch()} />;

  const valid = FIELDS.every((f) => /^\d+$/.test(form[f.key]) && Number(form[f.key]) >= 1 && Number(form[f.key]) <= 3650);
  const changed = current.data ? FIELDS.some((f) => Number(form[f.key]) !== current.data!.targets[f.key]) : false;

  return (
    <Card>
      <CardHeader
        title="Target dates"
        subtitle="Days a team has to fix a vulnerability, counted from when it was first seen in the project. Actions past their date are marked Late. Vulnerabilities without a fix, and lower severities, have no target."
      />
      <div className="grid gap-4 p-4 sm:grid-cols-3">
        {FIELDS.map((f) => (
          <FormRow key={f.key} label={`${f.label} (days)`} htmlFor={`target-${f.key}`}>
            <TextInput
              id={`target-${f.key}`}
              value={form[f.key]}
              onChange={(v) => setForm({ ...form, [f.key]: v.trim() })}
              ariaLabel={f.label}
            />
            <p className="mt-1 text-[11px] text-text-muted">{f.hint}</p>
          </FormRow>
        ))}
      </div>
      <div className="flex items-center justify-between gap-2 border-t border-border-base px-4 py-3">
        <FormError error={save.error} />
        <Button
          variant="primary"
          disabled={!valid || !changed || save.isPending}
          onClick={() =>
            save.mutate({
              usedInAttacksDays: Number(form.usedInAttacksDays),
              criticalDays: Number(form.criticalDays),
              highDays: Number(form.highDays),
            })
          }
        >
          {save.isPending ? "Saving…" : "Save target dates"}
        </Button>
      </div>
    </Card>
  );
}
