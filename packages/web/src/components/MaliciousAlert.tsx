import { Link } from "react-router";
import { useDashboardMalicious } from "../lib/queries.ts";
import { formatNumber, formatRelative } from "../lib/format.ts";

/**
 * The dashboard's malicious-package alert.
 *
 * Renders nothing at all in three of its four states, and that restraint is what makes the
 * fourth one mean something. A banner that is permanently present — saying "0 malicious
 * packages" on a healthy estate — is a banner people stop reading, and the day it changes to
 * a number nobody notices.
 *
 * So:
 *   detection off, or no feed installed  -> nothing. The page cannot claim anything either
 *                                           way, and a reassuring green panel would be a
 *                                           claim.
 *   feed installed, nothing found        -> nothing. Covered by the page's own empty state,
 *                                           which can qualify it properly.
 *   anything found                       -> this.
 *
 * The historical case gets its own wording rather than a smaller number in the same sentence.
 * "Nothing in your current builds, but four applications shipped this" is the state most
 * likely to be misread as safe, and it is the one where the remaining work — rotating the
 * credentials those builds exposed — has not been done.
 */
export function MaliciousAlert() {
  const { data: summary } = useDashboardMalicious();

  // `undefined` while loading, `null` when detection is off or no feed is installed. Neither
  // is a finding, and neither may render as reassurance.
  if (!summary) return null;
  if (summary.everPackages === 0) return null;

  const inCurrent = summary.currentPackages > 0;

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
            {summary.acknowledgedPackages > 0
              ? ` · ${formatNumber(summary.acknowledgedPackages)} acknowledged`
              : ""}
          </p>
        </div>

        <Link
          to={inCurrent ? "/malicious?presence=current" : "/malicious"}
          className={`shrink-0 rounded-md px-3 py-1.5 text-sm font-medium text-white ${
            inCurrent ? "bg-danger" : "bg-warn"
          } hover:opacity-90`}
        >
          Review
        </Link>
      </div>
    </div>
  );
}
