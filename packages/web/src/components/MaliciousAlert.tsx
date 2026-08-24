import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useDashboardMalicious } from "../lib/queries.ts";
import { formatNumber, formatRelative } from "../lib/format.ts";

/**
 * The dashboard's malicious-package alert.
 *
 * Renders nothing at all in four of its five states, and that restraint is what makes the
 * fifth one mean something. A banner that is permanently present — saying "0 malicious
 * packages" on a healthy estate — is a banner people stop reading, and the day it changes to
 * a number nobody notices.
 *
 * So:
 *   detection off, or no feed installed  -> nothing. The page cannot claim anything either
 *                                           way, and a reassuring green panel would be a
 *                                           claim.
 *   feed installed, nothing found        -> nothing. Covered by the page's own empty state,
 *                                           which can qualify it properly.
 *   everything acknowledged              -> nothing. Somebody has looked at each finding and
 *                                           written down what they decided; the findings page
 *                                           still lists them, marked.
 *   dismissed, and nothing has changed   -> nothing. See below.
 *   anything outstanding                 -> this.
 *
 * The historical case gets its own wording rather than a smaller number in the same sentence.
 * "Nothing in your current builds, but four applications shipped this" is the state most
 * likely to be misread as safe, and it is the one where the remaining work — rotating the
 * credentials those builds exposed — has not been done.
 */

/**
 * Where a dismissal is remembered.
 *
 * localStorage rather than component state, or the banner would return on every navigation
 * and the button would be decorative. What is stored is the *signature* of the outstanding
 * finding set, never a bare "dismissed" flag — see the guard in the component.
 */
const DISMISSED_KEY = "sbom.malicious-alert.dismissed";

function readDismissed(): string | null {
  try {
    return window.localStorage.getItem(DISMISSED_KEY);
  } catch {
    // Private-browsing modes and locked-down enterprise policies both throw here. Failing to
    // read a dismissal means the alert shows, which is the safe direction to fail in.
    return null;
  }
}

export function MaliciousAlert() {
  const { data: summary, isSuccess } = useDashboardMalicious();
  const [dismissed, setDismissed] = useState<string | null>(readDismissed);

  const signature = summary?.signature ?? null;

  useEffect(() => {
    /*
     * Clear the stored dismissal once the set it referred to is gone, so localStorage does not
     * accumulate signatures for findings that no longer exist.
     *
     * Gated on `isSuccess`, and that guard is load-bearing rather than defensive. `summary` is
     * `undefined` while the query is in flight, which makes `signature` null for the first
     * render of every page load — indistinguishable here from "nothing is outstanding".
     * Without the guard this effect fired before the data arrived and deleted the dismissal on
     * every refresh, so the alert came back each time and the close button appeared to do
     * nothing beyond the current render.
     */
    if (!isSuccess) return;
    if (signature === null && dismissed !== null) {
      try {
        window.localStorage.removeItem(DISMISSED_KEY);
      } catch {
        /* nothing to do; the value is inert either way */
      }
      setDismissed(null);
    }
  }, [isSuccess, signature, dismissed]);

  // `undefined` while loading, `null` when detection is off or no feed is installed. Neither
  // is a finding, and neither may render as reassurance.
  if (!summary) return null;
  // Zero here means "nothing outstanding" — either nothing was found, or every finding has
  // been acknowledged. Both are states the findings page describes properly and neither
  // warrants interrupting.
  if (summary.everPackages === 0) return null;

  /*
   * Dismissal is matched against the signature, never against a boolean.
   *
   * A plain "dismissed" flag would be a permanent mute on the one notice in this platform
   * that must not have one: dismiss it today, and the malicious package that lands next week
   * arrives silently. Comparing signatures means the button says "I have seen these", and any
   * change to the outstanding set brings the alert straight back.
   */
  if (signature !== null && dismissed === signature) return null;

  const inCurrent = summary.currentPackages > 0;

  const dismiss = () => {
    if (signature === null) return;
    try {
      window.localStorage.setItem(DISMISSED_KEY, signature);
    } catch {
      /* the in-memory state below still hides it for this page view */
    }
    setDismissed(signature);
  };

  return (
    <div
      role="alert"
      className={`mb-4 rounded-lg border px-4 py-3 ${
        inCurrent ? "border-danger bg-danger-subtle" : "border-warn bg-warn-subtle"
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className={`text-sm font-semibold ${inCurrent ? "text-danger" : "text-warn"}`}>
            {inCurrent
              ? `${formatNumber(summary.currentPackages)} malicious ${
                  summary.currentPackages === 1 ? "package is" : "packages are"
                } in current builds`
              : `${formatNumber(summary.everPackages)} malicious ${
                  summary.everPackages === 1 ? "package was" : "packages were"
                } shipped previously`}
          </h2>

          <p className="mt-1 text-xs text-text-muted">
            {inCurrent ? (
              <>
                Affecting {formatNumber(summary.currentApplications)}{" "}
                {summary.currentApplications === 1 ? "application" : "applications"} now, and{" "}
                {formatNumber(summary.everApplications)} across all retained builds. Remove the
                packages, then rotate the credentials their build machines could read.
              </>
            ) : (
              <>
                Already gone from every current build, but{" "}
                {formatNumber(summary.everApplications)}{" "}
                {summary.everApplications === 1 ? "application" : "applications"} shipped them.
                The payload ran at install time, so those pipelines&rsquo; credentials still
                need rotating.
              </>
            )}
          </p>

          <p className="mt-1 text-[11px] text-text-faint">
            Feed built {formatRelative(summary.feedBuiltAt)}
            {summary.pendingComponents > 0
              ? ` · ${formatNumber(summary.pendingComponents)} packages still to check`
              : ""}
            {/*
              Stated because these counts now exclude acknowledged findings. Without this the
              numbers would appear to drop on their own and a reader could not tell a handled
              estate from one that was never examined.
            */}
            {summary.acknowledgedPackages > 0
              ? ` · ${formatNumber(summary.acknowledgedPackages)} acknowledged, not counted above`
              : ""}
          </p>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <Link
            to={inCurrent ? "/malicious?presence=current" : "/malicious"}
            className={`rounded-md px-3 py-1.5 text-sm font-medium text-white ${
              inCurrent ? "bg-danger" : "bg-warn"
            } hover:opacity-90`}
          >
            Review
          </Link>
          <button
            type="button"
            onClick={dismiss}
            aria-label="Dismiss until a new malicious package is found"
            title="Dismiss. The alert returns if another malicious package is found."
            className={`rounded-md px-2 py-1 text-lg leading-none ${
              inCurrent ? "text-danger" : "text-warn"
            } hover:bg-black/5 dark:hover:bg-white/10`}
          >
            &times;
          </button>
        </div>
      </div>
    </div>
  );
}
