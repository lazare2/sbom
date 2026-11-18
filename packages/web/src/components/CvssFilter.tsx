import { useState } from "react";
import {
  CVSS_FILTER_METRICS,
  CVSS_VERSION_LABELS,
  cvssVersionFilterValues,
  parseCvssFilter,
  readCvssMetrics,
  type AttackVectorFilter,
  type CvssFilterMetric,
  type CvssVersionFilter,
} from "@sbom/shared";
import { TogglePills } from "./FilterBar.tsx";
import type { FilterChip } from "./FilterBar.tsx";

/**
 * Filtering on every CVSS base metric, by the names in FIRST's CVSS 3.1 and 4.0 specifications.
 *
 * Attack vector is the page's existing "Attack from" filter, so its row edits that filter rather
 * than adding a second one. Every other metric is a `cvss` part such as "AC:L": values of one
 * metric are alternatives, different metrics must all hold.
 */

const AV_BY_LETTER: Record<string, AttackVectorFilter> = { N: "network", A: "adjacent", L: "local", P: "physical" };
const LETTER_BY_AV = Object.fromEntries(Object.entries(AV_BY_LETTER).map(([l, av]) => [av, l])) as Record<string, string>;

export interface CvssFilterValue {
  attackVector: AttackVectorFilter[];
  cvss: string[];
  cvssVersion: CvssVersionFilter[];
}

export function CvssFilterSection({ value, onChange }: { value: CvssFilterValue; onChange: (patch: Partial<CvssFilterValue>) => void }) {
  const [pasted, setPasted] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  const lettersOf = (metric: CvssFilterMetric) =>
    metric.key === "AV"
      ? value.attackVector.map((av) => LETTER_BY_AV[av]).filter((l): l is string => Boolean(l))
      : value.cvss.filter((p) => p.startsWith(`${metric.key}:`)).map((p) => p.slice(metric.key.length + 1));

  const setLetters = (metric: CvssFilterMetric, letters: string[]) => {
    if (metric.key === "AV") {
      // "Unknown" lives only in the Attack from filter; keep it when the letters change here.
      const keep = value.attackVector.filter((av) => av === "unknown");
      onChange({ attackVector: [...keep, ...letters.map((l) => AV_BY_LETTER[l]!)] });
    } else {
      onChange({ cvss: [...value.cvss.filter((p) => !p.startsWith(`${metric.key}:`)), ...letters.map((l) => `${metric.key}:${l}`)] });
    }
  };

  const applyPasted = () => {
    const { parts, ignored } = parseCvssFilter(pasted);
    if (parts.length === 0) {
      setMessage("No CVSS base metric found. Paste something like AV:N/AC:L/PR:N.");
      return;
    }
    // The pasted metrics replace what was chosen for those metrics; the others stay.
    const keys = new Set(parts.map((p) => p.split(":")[0]));
    const av = parts.filter((p) => p.startsWith("AV:")).map((p) => AV_BY_LETTER[p.slice(3)]!);
    onChange({
      ...(av.length > 0 ? { attackVector: av } : {}),
      cvss: [...value.cvss.filter((p) => !keys.has(p.split(":")[0])), ...parts.filter((p) => !p.startsWith("AV:"))],
    });
    setPasted("");
    setMessage(ignored.length > 0 ? `Applied. Not base metrics, so left out: ${ignored.join(", ")}.` : "Applied.");
  };

  return (
    <div className="space-y-3 sm:col-span-2">
      <div className="flex gap-2">
        <input
          value={pasted}
          onChange={(e) => setPasted(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              applyPasted();
            }
          }}
          placeholder="Paste a vector or part of one: AV:N/PR:N/UI:N"
          aria-label="Paste a CVSS vector"
          className="h-[30px] min-w-0 flex-1 rounded-md border border-border-strong bg-bg-raised px-2 font-mono text-xs"
        />
        <button type="button" onClick={applyPasted} className="rounded-md border border-border-strong px-2.5 text-xs hover:bg-bg-subtle">
          Apply
        </button>
      </div>
      {message ? <p className="text-xs text-text-muted">{message}</p> : null}
      <dl className="grid grid-cols-[minmax(150px,auto)_1fr] items-center gap-x-3 gap-y-2">
        {CVSS_FILTER_METRICS.map((metric) => (
          <div key={metric.key} className="contents">
            <dt className="text-xs text-text-muted">
              {metric.label} <span className="font-mono text-text-faint">{metric.key}</span>
              {metric.only ? <span className="text-text-faint"> · {metric.only} only</span> : null}
            </dt>
            <dd>
              <TogglePills
                label={metric.label}
                options={metric.values.map((v) => ({ value: v.letter, label: v.label, title: `${metric.key}:${v.letter}` }))}
                selected={lettersOf(metric)}
                onChange={(letters) => setLetters(metric, letters)}
              />
            </dd>
          </div>
        ))}
        <dt className="text-xs text-text-muted">CVSS version</dt>
        <dd>
          <TogglePills
            label="CVSS version"
            options={cvssVersionFilterValues.map((v) => ({ value: v, label: CVSS_VERSION_LABELS[v] }))}
            selected={value.cvssVersion}
            onChange={(v) => onChange({ cvssVersion: v as CvssVersionFilter[] })}
          />
        </dd>
      </dl>
    </div>
  );
}

/** The chips for the CVSS filter: one per metric, naming its chosen values. */
export function cvssChips(value: CvssFilterValue, onChange: (patch: Partial<CvssFilterValue>) => void): FilterChip[] {
  const chips: FilterChip[] = [];
  for (const metric of CVSS_FILTER_METRICS) {
    if (metric.key === "AV") continue; // shown by the Attack from chip
    const letters = value.cvss.filter((p) => p.startsWith(`${metric.key}:`)).map((p) => p.slice(metric.key.length + 1));
    if (letters.length === 0) continue;
    chips.push({
      id: `cvss-${metric.key}`,
      label: metric.label,
      value: letters.map((l) => metric.values.find((v) => v.letter === l)?.label ?? l).join(", "),
      onRemove: () => onChange({ cvss: value.cvss.filter((p) => !p.startsWith(`${metric.key}:`)) }),
    });
  }
  if (value.cvssVersion.length > 0) {
    chips.push({
      id: "cvss-version",
      label: "CVSS version",
      value: value.cvssVersion.map((v) => CVSS_VERSION_LABELS[v]).join(", "),
      onRemove: () => onChange({ cvssVersion: [] }),
    });
  }
  return chips;
}

/**
 * An advisory's vector as short tags under its attack-vector badge: AC:L PR:N UI:N ... Each
 * names its metric on hover, and - where the page passes `onPick` - adds itself as a filter.
 */
export function CvssTags({ vector, onPick }: { vector: string | null; onPick?: (part: string) => void }) {
  const metrics = readCvssMetrics(vector);
  const shown = CVSS_FILTER_METRICS.filter((m) => m.key !== "AV" && metrics[m.key]);
  if (shown.length === 0) return null;
  return (
    <div className="mt-1 flex flex-wrap gap-x-1 font-mono text-[10px] leading-4 text-text-faint">
      {shown.map((m) => {
        const letter = metrics[m.key]!;
        const words = `${m.label}: ${m.values.find((v) => v.letter === letter)?.label ?? letter}`;
        return onPick ? (
          <button
            key={m.key}
            type="button"
            onClick={() => onPick(`${m.key}:${letter}`)}
            title={`${words}. Click to show only advisories with this.`}
            className="hover:text-accent hover:underline"
          >
            {m.key}:{letter}
          </button>
        ) : (
          <span key={m.key} title={words}>
            {m.key}:{letter}
          </span>
        );
      })}
    </div>
  );
}
