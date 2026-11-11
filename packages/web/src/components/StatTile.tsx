import { Link } from "react-router";
import { formatNumber } from "../lib/format.ts";

/**
 * One headline figure, optionally a link to the list behind it.
 *
 * A figure you cannot drill into is trivia - "9 stale applications" only becomes work once you
 * can see which nine - so a tile takes `to` wherever such a list exists.
 */
export function StatTile({
  label,
  value,
  hint,
  to,
  tone,
}: {
  label: string;
  value: number | string;
  hint?: string;
  to?: string;
  tone?: "warn" | "ok" | "danger";
}) {
  const toneClass =
    tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : tone === "ok" ? "text-ok" : "text-text-base";

  const body = (
    <>
      <p className="text-[11px] font-medium uppercase tracking-wide text-text-faint">{label}</p>
      <p className={`nums mt-1 text-2xl font-semibold ${toneClass}`}>
        {typeof value === "number" ? formatNumber(value) : value}
      </p>
      {hint ? <p className="mt-0.5 text-xs text-text-muted">{hint}</p> : null}
    </>
  );

  if (!to) return <div className="rounded-lg border border-border-base bg-bg-raised px-4 py-3">{body}</div>;
  return (
    <Link
      to={to}
      className="block rounded-lg border border-border-base bg-bg-raised px-4 py-3 transition-colors hover:border-border-strong hover:bg-bg-subtle"
    >
      {body}
    </Link>
  );
}

/** A proportion bar beside its percentage, relative to the largest value in the table. */
export function ShareBar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.max(1, Math.round((value / max) * 100)) : 0;
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-neutral-subtle">
        <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
      <span className="nums w-9 text-right text-xs text-text-muted">{pct}%</span>
    </div>
  );
}
