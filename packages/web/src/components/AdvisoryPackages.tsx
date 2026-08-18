import { ADVISORY_PACKAGE_LIST_CAP, type AdvisorySummary } from "@sbom/shared";
import { Link } from "react-router";
import { formatNumber } from "../lib/format.ts";
import { Td } from "./ui.tsx";

/**
 * The affected-package count for one advisory, expandable to the packages behind it.
 *
 * The count alone was the honest answer for as long as the list was not available: one CVE
 * affects many packages, so a per-advisory row has no single package to name. Now that the
 * list travels with the row there is something to open, and opening it is the whole point —
 * "8 packages" and "eight versions of openssl" are very different findings, and only the
 * second one tells you it is a single upgrade.
 *
 * The list comes from the same aggregate and the same WHERE clause as the number beside it,
 * which is why this takes both from one row rather than fetching on expand. The app and
 * base-image split is a shared SQL predicate rather than a column, so a list fetched
 * separately could not be narrowed to match the count, and a scoped count of 3 above an
 * unscoped list of 8 is a contradiction a reader cannot resolve.
 */
export function AdvisoryPackagesCell({ advisory }: { advisory: AdvisorySummary }) {
  const listed = advisory.affectedPackageList.length;
  /*
    Derived rather than carried as a flag, so it cannot disagree with the list it describes.
    Also covers the case where two components share a name and version across ecosystems:
    they collapse into one entry but count as two, which reads here as truncation. That
    over-reports "more not shown" in a rare case and never under-reports it, which is the
    safe direction -- a partial list that looks complete is the failure worth avoiding.
  */
  const hidden = advisory.affectedPackages - listed;

  if (listed === 0) {
    return (
      <Td align="right" className="nums text-text-muted">
        {formatNumber(advisory.affectedPackages)}
      </Td>
    );
  }

  return (
    <Td align="right" className="text-text-muted">
      <details>
        <summary
          className="nums cursor-pointer list-none hover:text-accent"
          title="Show the affected packages"
        >
          {formatNumber(advisory.affectedPackages)}
        </summary>
        <div className="mt-1 flex flex-wrap justify-end gap-1">
          {advisory.affectedPackageList.map((entry) => {
            /*
              Entries are "name version". Split on the first space: package names do not
              contain spaces in any ecosystem here, and versions can, so the first space is
              the only reliable boundary.
            */
            const cut = entry.indexOf(" ");
            const name = cut === -1 ? entry : entry.slice(0, cut);
            return (
              <Link
                key={entry}
                to={`/search?name=${encodeURIComponent(name)}&match=exact&scope=all`}
                title={`Find ${name} across the estate`}
                className="rounded border border-border-base px-1.5 py-0.5 font-mono text-[11px] whitespace-nowrap text-text-muted hover:border-accent hover:text-accent"
              >
                {entry}
              </Link>
            );
          })}
        </div>
        {hidden > 0 ? (
          <p
            className="mt-1 text-[11px] text-warn"
            title={`Only the first ${ADVISORY_PACKAGE_LIST_CAP} are carried on the row. Open the advisory for the full list.`}
          >
            {formatNumber(hidden)} more not shown
          </p>
        ) : null}
      </details>
    </Td>
  );
}
