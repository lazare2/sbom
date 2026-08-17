/** Presentation helpers. Kept pure and dependency-free so they are trivially testable. */

const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
});

const dateFormat = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
});

export function formatDateTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : dateTimeFormat.format(d);
}

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : dateFormat.format(d);
}

/**
 * Coarse relative time ("3 days ago").
 *
 * Intentionally coarse: for scan history, "2 hours ago" and "3 hours ago" carry
 * the same meaning to a reader, and the exact timestamp is one hover away.
 */
export function formatRelative(iso: string | null): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";

  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 60) return "just now";

  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.round(hours / 24);
  if (days < 31) return `${days}d ago`;

  const months = Math.round(days / 30.44);
  if (months < 12) return `${months}mo ago`;

  return `${Math.round(days / 365.25)}y ago`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value.toLocaleString();
}

/** Short commit SHA, the form people actually recognise. */
export function shortSha(sha: string | null): string {
  if (!sha) return "—";
  return sha.length > 10 ? sha.slice(0, 10) : sha;
}

/**
 * Trims a long image reference to its meaningful tail.
 *
 * A registry path can be 90 characters of hostname and project prefix; the
 * image name and tag at the end are what identifies the build.
 */
export function shortImageRef(ref: string | null, maxLength = 46): string {
  if (!ref) return "—";
  if (ref.length <= maxLength) return ref;
  return `…${ref.slice(-(maxLength - 1))}`;
}

/**
 * Turns an attribute key into a readable label: `cost_centre` -> `Cost centre`.
 *
 * Used only as a fallback while the attribute definitions are still loading.
 * Without it the filter labels briefly render as raw lower_snake_case keys, which
 * reads like a bug even though it resolves in a few hundred milliseconds.
 */
export function humanizeKey(key: string): string {
  const words = key.replace(/_/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export const STATUS_LABELS: Record<string, string> = {
  active: "Active",
  inactive: "Inactive",
  pending_confirmation: "Unconfirmed",
};
