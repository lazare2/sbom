import type { ReactNode } from "react";
import type { SeverityCounts, VulnSeverity } from "@sbom/shared";
import { Badge } from "./ui.tsx";

/**
 * Severity presentation, in one place.
 *
 * Colour is doing real work here, unlike most badges in this app: a reader scans a
 * hundred-row findings table by colour and only then reads the words. So the mapping has
 * to be consistent everywhere, which means it lives here rather than being chosen per
 * page.
 *
 * `unknown` is grey rather than being hidden or promoted to low. Plenty of advisories
 * carry no severity rating, and both alternatives misrepresent that — hiding loses a real
 * finding, and colouring it as low invents an assessment nobody made.
 */

const SEVERITY_TONE: Record<VulnSeverity, "danger" | "warn" | "info" | "neutral"> = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "info",
  negligible: "neutral",
  unknown: "neutral",
};

const SEVERITY_LABEL: Record<VulnSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  negligible: "Negligible",
  unknown: "Unknown",
};

/** Highest first — the order every list and legend here is read in. */
export const SEVERITY_ORDER: VulnSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "negligible",
  "unknown",
];

export function SeverityBadge({ severity }: { severity: VulnSeverity }) {
  return (
    <Badge
      tone={SEVERITY_TONE[severity]}
      title={
        severity === "unknown"
          ? "The advisory carries no severity rating. Not an absence of risk — an absence of assessment."
          : undefined
      }
    >
      {SEVERITY_LABEL[severity]}
    </Badge>
  );
}

/**
 * A severity distribution as a single stacked bar.
 *
 * Compact enough to sit in a table row, which matters because the alternative — six
 * numbers per row — is unreadable at a glance across twenty applications. Zero-width
 * segments are omitted rather than rendered as slivers.
 */
export function SeverityBar({
  counts,
  total,
  className = "",
}: {
  counts: SeverityCounts;
  /** Scale reference, so several bars can be compared against each other. */
  total?: number;
  className?: string;
}) {
  const sum = SEVERITY_ORDER.reduce((acc, key) => acc + counts[key], 0);
  const scale = total && total > 0 ? total : sum;
  if (sum === 0 || scale === 0) {
    return <span className={`text-xs text-text-faint ${className}`}>none</span>;
  }

  const fill: Record<VulnSeverity, string> = {
    critical: "bg-danger",
    high: "bg-warn",
    medium: "bg-info",
    low: "bg-accent",
    negligible: "bg-neutral-subtle",
    unknown: "bg-neutral-subtle",
  };

  return (
    <span
      className={`inline-flex h-2 w-full overflow-hidden rounded-full bg-neutral-subtle ${className}`}
      role="img"
      aria-label={SEVERITY_ORDER.filter((k) => counts[k] > 0)
        .map((k) => `${counts[k]} ${SEVERITY_LABEL[k].toLowerCase()}`)
        .join(", ")}
      title={SEVERITY_ORDER.filter((k) => counts[k] > 0)
        .map((k) => `${SEVERITY_LABEL[k]}: ${counts[k]}`)
        .join(" · ")}
    >
      {SEVERITY_ORDER.map((key) =>
        counts[key] > 0 ? (
          <span key={key} className={fill[key]} style={{ width: `${(counts[key] / scale) * 100}%` }} />
        ) : null,
      )}
    </span>
  );
}

/** Inline "C 3 · H 11 · M 20" summary, for places a bar has no room. */
/**
 * Just the critical and high counts, for places too narrow for a full breakdown.
 *
 * Lives here rather than at the call site so the tones stay governed by `SEVERITY_TONE` —
 * both are `danger`, which is deliberate: a reader scanning a column by colour should see one
 * signal for "act on this", and the letter distinguishes which. Splitting them into two
 * colours here would quietly contradict every other severity display in the app.
 *
 * A zero is omitted rather than shown as "0 critical". The row already carries the total, so
 * an empty space means "none of these" without spending width to say it.
 */
export function CriticalHighBadges({ critical, high }: { critical: number; high: number }) {
  if (critical === 0 && high === 0) return null;
  return (
    <span className="inline-flex gap-1">
      {critical > 0 ? (
        <Badge tone={SEVERITY_TONE.critical} title={`${critical} critical`}>
          {critical}C
        </Badge>
      ) : null}
      {high > 0 ? (
        <Badge tone={SEVERITY_TONE.high} title={`${high} high`}>
          {high}H
        </Badge>
      ) : null}
    </span>
  );
}

export function SeverityCountsInline({ counts }: { counts: SeverityCounts }) {
  const present = SEVERITY_ORDER.filter((k) => counts[k] > 0);
  if (present.length === 0) return <span className="text-text-faint">none</span>;
  return (
    <span className="nums whitespace-nowrap text-xs text-text-muted">
      {present.map((key, i) => (
        <span key={key}>
          {i > 0 ? " · " : ""}
          <span className={key === "critical" || key === "high" ? "font-medium text-text-base" : ""}>
            {SEVERITY_LABEL[key][0]} {counts[key]}
          </span>
        </span>
      ))}
    </span>
  );
}

/**
 * The state to render when scanning is switched off.
 *
 * Exists so no page has to decide for itself how to represent "not assessed", and so no
 * page can accidentally represent it as zero. That distinction is the single most
 * important thing about this feature's UI: an empty findings list means the packages were
 * checked and are clean, and this means nothing was checked at all.
 */
export function ScanningDisabledNotice({
  what,
  isAdmin,
  children,
}: {
  /** What is unavailable, e.g. "Vulnerability findings". */
  what: string;
  isAdmin?: boolean;
  children?: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border-base bg-bg-subtle px-4 py-6 text-center">
      <p className="text-sm font-medium text-text-base">{what} are not available</p>
      <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
        Vulnerability scanning is switched off, so no package here has been matched against a
        vulnerability database.{" "}
        <strong className="font-semibold">This is not a clean result — nothing has been checked.</strong>
      </p>
      {isAdmin ? (
        <p className="mt-3 text-xs text-text-muted">
          Enable it under{" "}
          <a href="/admin/vulnerabilities" className="text-accent hover:underline">
            Admin → Vulnerability scanning
          </a>
          .
        </p>
      ) : (
        <p className="mt-3 text-xs text-text-faint">An administrator can enable it.</p>
      )}
      {children}
    </div>
  );
}
