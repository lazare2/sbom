import {
  dashboardSeverityBuckets,
  SEVERITY_BUCKET_LABELS,
  VULN_SCOPE_LABELS,
  vulnScopes,
  type DashboardSeverityBucket,
  type VulnScope,
} from "@sbom/shared";
import { readEnum } from "../lib/useUrlState.ts";

/**
 * The dashboard vulnerability filter: which half of the split, and which severities.
 *
 * Shared by the overview and the analytics page so a filter means the same thing on both
 * and a link carries between them. Deliberately not a dropdown: the whole point of this
 * control is that a reader can see what has been narrowed without opening anything, since
 * a figure read under a filter nobody noticed is worse than no figure at all.
 *
 * It sits inside the vulnerability section rather than in the page toolbar, because that
 * is the extent of what it changes. Severity has no meaning for package counts, coverage
 * or churn, and a control in the page header would imply a reach it does not have.
 */

/** The parsed filter the control and the panels work with. */
export interface VulnFilterUrlState {
  scope: VulnScope;
  severity: DashboardSeverityBucket[];
}

/**
 * The URL-facing form: exactly what appears in the address bar.
 *
 * Severity is one comma-separated parameter rather than a repeated key, so a filtered
 * dashboard link stays short enough to paste into a ticket. Kept as a string at this layer
 * because `useUrlState` writes values through `String()` — an array there would produce
 * repeated keys and quietly break the round trip.
 */
/*
 * A type alias rather than an interface, deliberately. `useUrlState` is generic over
 * `Record<string, unknown>`, and TypeScript grants an implicit index signature to object
 * type aliases but not to interfaces — an interface here fails to satisfy the constraint
 * for a reason that has nothing to do with this filter.
 */
export type VulnFilterParams = {
  scope: VulnScope;
  severity: string;
};

export const VULN_FILTER_URL_DEFAULTS: VulnFilterParams = { scope: "all", severity: "" };
export const VULN_FILTER_DEFAULTS: VulnFilterUrlState = { scope: "all", severity: [] };

export function readVulnFilterParams(params: URLSearchParams): VulnFilterParams {
  return {
    scope: readEnum(params, "scope", vulnScopes, "all"),
    severity: params.get("severity") ?? "",
  };
}

/**
 * Parses the URL form into buckets.
 *
 * Unrecognised names are dropped rather than treated as an error: a stale bookmark naming
 * a bucket that no longer exists should widen to everything, not fail.
 */
export function toVulnFilter(raw: VulnFilterParams): VulnFilterUrlState {
  const seen = new Set(
    raw.severity
      .split(",")
      .map((part) => part.trim().toLowerCase())
      .filter((part): part is DashboardSeverityBucket =>
        (dashboardSeverityBuckets as readonly string[]).includes(part),
      ),
  );
  return {
    scope: raw.scope,
    // Canonical order regardless of how the URL listed them, so two links selecting the
    // same buckets produce the same query key and hit the same cache entry.
    severity: dashboardSeverityBuckets.filter((bucket) => seen.has(bucket)),
  };
}

export function fromVulnFilter(filter: VulnFilterUrlState): VulnFilterParams {
  return { scope: filter.scope, severity: filter.severity.join(",") };
}

/** Query parameters for the API and the PDF link. Omits anything inert. */
export function vulnFilterQuery(filter: VulnFilterUrlState): Record<string, string> {
  const params: Record<string, string> = {};
  if (filter.scope !== "all") params.scope = filter.scope;
  if (filter.severity.length > 0) params.severity = filter.severity.join(",");
  return params;
}

/** True when the filter narrows anything — drives the "clear" affordance. */
export function isVulnFilterActive(filter: VulnFilterUrlState): boolean {
  return filter.scope !== "all" || filter.severity.length > 0;
}

const BUCKET_TONE: Record<DashboardSeverityBucket, string> = {
  critical: "border-danger text-danger",
  high: "border-warn text-warn",
  medium: "border-info text-info",
  low: "border-accent text-accent",
  other: "border-border-strong text-text-muted",
};

function Chip({
  label,
  pressed,
  onClick,
  tone,
  title,
}: {
  label: string;
  pressed: boolean;
  onClick: () => void;
  tone?: string;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={pressed}
      title={title}
      className={`rounded-full border px-2.5 py-1 text-xs font-medium transition-colors ${
        pressed
          ? `bg-bg-subtle ${tone ?? "border-accent text-accent"}`
          : "border-border-base text-text-faint hover:border-border-strong hover:text-text-muted"
      }`}
    >
      {label}
    </button>
  );
}

export function VulnFilterControl({
  filter,
  onChange,
}: {
  filter: VulnFilterUrlState;
  onChange: (next: VulnFilterUrlState) => void;
}) {
  /*
   * Selecting every bucket and selecting none describe the same set, so the second click
   * that would complete the set clears it instead. Otherwise the page would show a filter
   * chip row that looks active while narrowing nothing, and "Clear" would appear to do
   * nothing at all.
   */
  function toggleSeverity(bucket: DashboardSeverityBucket) {
    const next = filter.severity.includes(bucket)
      ? filter.severity.filter((entry) => entry !== bucket)
      : dashboardSeverityBuckets.filter((entry) => entry === bucket || filter.severity.includes(entry));
    onChange({
      ...filter,
      severity: next.length === dashboardSeverityBuckets.length ? [] : next,
    });
  }

  const active = isVulnFilterActive(filter);

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Package scope">
        <span className="text-[11px] font-medium tracking-wide text-text-faint uppercase">Scope</span>
        {vulnScopes.map((scope) => (
          <Chip
            key={scope}
            label={scope === "all" ? "Both" : scope === "app" ? "App deps" : "Base image"}
            title={VULN_SCOPE_LABELS[scope]}
            pressed={filter.scope === scope}
            onClick={() => onChange({ ...filter, scope })}
          />
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Severity">
        <span className="text-[11px] font-medium tracking-wide text-text-faint uppercase">Severity</span>
        {dashboardSeverityBuckets.map((bucket) => (
          <Chip
            key={bucket}
            label={SEVERITY_BUCKET_LABELS[bucket]}
            title={
              bucket === "other"
                ? "Negligible, plus advisories no upstream feed has rated."
                : undefined
            }
            // With nothing selected every severity is included, so every chip reads as on.
            // Showing them all off would suggest the page was displaying nothing.
            pressed={filter.severity.length === 0 || filter.severity.includes(bucket)}
            tone={BUCKET_TONE[bucket]}
            onClick={() => toggleSeverity(bucket)}
          />
        ))}
      </div>

      {active ? (
        <button
          type="button"
          onClick={() => onChange({ ...VULN_FILTER_DEFAULTS })}
          className="text-xs text-accent hover:underline"
        >
          Clear filter
        </button>
      ) : null}
    </div>
  );
}

/**
 * States the active filter in words, above the figures it produced.
 *
 * Chips show what is selected; this says what that means for the numbers. Both are needed:
 * someone scrolling to a total will not stop to decode a chip row, and a total read as
 * estate-wide when it covers four critical findings is the failure this whole section is
 * built to avoid.
 */
export function VulnFilterBanner({ label }: { label: string | null }) {
  if (label === null) return null;
  return (
    <div className="mb-3 rounded-lg border border-warn bg-warn-subtle px-3 py-2">
      <p className="text-xs font-medium text-warn">Filtered: {label}</p>
      <p className="mt-0.5 text-[11px] text-text-muted">
        Every vulnerability figure below counts only matching findings. Inventory, coverage and
        platform figures are unfiltered and describe the whole estate.
      </p>
    </div>
  );
}
