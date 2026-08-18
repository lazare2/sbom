import { EXPANDABLE_LIST_CAP, type AdvisorySummary } from "@sbom/shared";
import { Link } from "react-router";
import { formatNumber } from "../lib/format.ts";
import { Td } from "./ui.tsx";

/**
 * Counts on an advisory row that open to show what they counted.
 *
 * A count alone was the honest answer for as long as the detail was not on the row: one
 * advisory reaches many packages and many applications, so there is no single value to put
 * in the cell. Now that the lists travel with the row there is something to open, and
 * opening it is the point — "8 packages" and "eight versions of openssl" are very different
 * findings, and only the second says it is one upgrade.
 *
 * Every list here is produced by the same aggregate, under the same WHERE clause and the
 * same FILTER, as the number beside it. That is a correctness constraint rather than an
 * optimisation: the app/base-image split is a shared SQL predicate rather than a column, so
 * a list fetched separately could not be narrowed to the same scope, and a scoped count of 3
 * above an unscoped list of 8 is a contradiction the reader cannot resolve.
 */
export function ExpandableCountCell({
  count,
  items,
  hrefFor,
  linkTitle,
  overflowTitle,
  className,
  summaryTitle,
}: {
  count: number;
  items: string[];
  hrefFor: (item: string) => string;
  linkTitle: (item: string) => string;
  overflowTitle: string;
  className: string;
  summaryTitle: string;
}) {
  /*
    Derived rather than carried as a flag, so it cannot disagree with the list it describes.
    Over-reports in one rare case — two entries identical after formatting collapse into one
    but count as two — and never under-reports, which is the safe direction: a partial list
    that looks complete is the failure worth avoiding.
  */
  const hidden = count - items.length;

  // Nothing to open. A disclosure control that reveals an empty box is worse than a number.
  if (items.length === 0) {
    return (
      <Td align="right" className={`nums ${className}`}>
        {formatNumber(count)}
      </Td>
    );
  }

  return (
    <Td align="right" className={className}>
      <details>
        <summary className="nums cursor-pointer list-none hover:text-accent" title={summaryTitle}>
          {formatNumber(count)}
        </summary>
        <div className="mt-1 flex flex-wrap justify-end gap-1">
          {items.map((item) => (
            <Link
              key={item}
              to={hrefFor(item)}
              title={linkTitle(item)}
              className="rounded border border-border-base px-1.5 py-0.5 font-mono text-[11px] whitespace-nowrap text-text-muted hover:border-accent hover:text-accent"
            >
              {item}
            </Link>
          ))}
        </div>
        {hidden > 0 ? (
          <p className="mt-1 text-[11px] text-warn" title={overflowTitle}>
            {formatNumber(hidden)} more not shown
          </p>
        ) : null}
      </details>
    </Td>
  );
}

/** Affected package count, expanding to the exact name-and-version pairs behind it. */
export function AdvisoryPackagesCell({ advisory }: { advisory: AdvisorySummary }) {
  return (
    <ExpandableCountCell
      count={advisory.affectedPackages}
      items={advisory.affectedPackageList}
      /*
        Entries are "name version". Split on the first space: package names contain no spaces
        in any ecosystem here, and versions can, so the first space is the only reliable
        boundary.
      */
      hrefFor={(entry) => {
        const cut = entry.indexOf(" ");
        const name = cut === -1 ? entry : entry.slice(0, cut);
        return `/search?name=${encodeURIComponent(name)}&match=exact&scope=all`;
      }}
      linkTitle={(entry) => `Find ${entry.split(" ")[0]} across the estate`}
      overflowTitle={`Only the first ${EXPANDABLE_LIST_CAP} are carried on the row. Open the advisory for the full list.`}
      className="text-text-muted"
      summaryTitle="Show the affected packages"
    />
  );
}

/**
 * Application count, expanding to which applications.
 *
 * `historical` changes only the wording, never the reading. The two counts are *not*
 * complements: an application shipping one affected version in an older build and a
 * different affected version in its current one appears under both, so the historical list
 * says "has history with this advisory" rather than "is clean now". Labelling it as resolved
 * would turn a still-vulnerable application into a fixed one.
 */
export function AdvisoryApplicationsCell({
  advisory,
  historical = false,
}: {
  advisory: AdvisorySummary;
  historical?: boolean;
}) {
  return (
    <ExpandableCountCell
      count={historical ? advisory.historicalApplications : advisory.currentApplications}
      items={historical ? advisory.historicalApplicationList : advisory.currentApplicationList}
      hrefFor={(name) => `/applications?search=${encodeURIComponent(name)}`}
      linkTitle={(name) => `Open ${name}`}
      overflowTitle={`Only the first ${EXPANDABLE_LIST_CAP} are carried on the row. Open the advisory for the full list.`}
      className={historical ? "text-text-faint" : "font-medium text-text-base"}
      summaryTitle={
        historical
          ? "Show the applications that shipped an affected package in an earlier build"
          : "Show the applications whose current build is affected"
      }
    />
  );
}

/**
 * An application count on any row, expanding to which applications.
 *
 * Every table that counts applications uses this one cell, so "click the number to see who"
 * is learned once rather than per table. The names must come from the same aggregate as the
 * count -- see ExpandableCountCell -- which is why each caller passes both together rather
 * than fetching the list on expand.
 */
export function ApplicationsCell({
  count,
  names,
  className = "text-text-muted",
  what,
}: {
  count: number;
  names: string[];
  className?: string;
  /** What the applications have in common, for the tooltip: "ship this package". */
  what: string;
}) {
  return (
    <ExpandableCountCell
      count={count}
      items={names}
      hrefFor={(name) => `/applications?search=${encodeURIComponent(name)}`}
      linkTitle={(name) => `Open ${name}`}
      overflowTitle={`Only the first ${EXPANDABLE_LIST_CAP} are carried on the row.`}
      className={className}
      summaryTitle={`Show the applications that ${what}`}
    />
  );
}
