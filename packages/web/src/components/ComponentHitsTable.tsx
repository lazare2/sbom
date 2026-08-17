import { Link } from "react-router";
import type { ComponentSearchHit, componentSearchSort } from "@sbom/shared";
import { formatDateTime, formatRelative } from "../lib/format.ts";
import type { SortControl } from "../lib/useSort.ts";
import { Badge, EcosystemBadge, StatusBadge, Table, TableWrap, Td, Th, Tr } from "./ui.tsx";

type HitSortField = (typeof componentSearchSort)["fields"][number];

/**
 * The package × application result table.
 *
 * Shared by the single search and the bulk list search. Both produce the same
 * `ComponentSearchHit`, and rendering them through one component is what stops the
 * two views drifting apart in how they describe a hit — "current" meaning one
 * thing on one screen and something subtly different on the other is the kind of
 * inconsistency that makes people stop trusting a search.
 *
 * `sort` is optional so a caller that renders an unpaginated excerpt can omit it and get
 * plain headers. Where it is passed, both callers page server-side and the sort goes with
 * the query — sorting a page in the browser would reorder the rows on screen while leaving
 * the rest of the result set untouched.
 */
export function ComponentHitsTable({
  hits,
  sort,
}: {
  hits: readonly ComponentSearchHit[];
  sort?: SortControl<HitSortField>;
}) {
  /** Undefined when unsorted, so `<Th>` falls back to a plain header. */
  const on = (field: HitSortField) => (sort ? () => sort.toggle(field) : undefined);
  const at = (field: HitSortField) => (sort ? sort.stateOf(field) : undefined);

  return (
    <TableWrap>
      <Table>
        <thead>
          <tr>
            <Th onSort={on("applicationName")} sorted={at("applicationName")}>
              Application
            </Th>
            <Th onSort={on("applicationStatus")} sorted={at("applicationStatus")} width="120px">
              Status
            </Th>
            <Th onSort={on("componentName")} sorted={at("componentName")}>
              Package
            </Th>
            <Th onSort={on("componentVersion")} sorted={at("componentVersion")} width="170px">
              Version
            </Th>
            <Th onSort={on("ecosystem")} sorted={at("ecosystem")} width="110px">
              Ecosystem
            </Th>
            <Th onSort={on("usage")} sorted={at("usage")} width="130px">
              Usage
            </Th>
            <Th onSort={on("lastSeenAt")} sorted={at("lastSeenAt")} width="200px">
              Last seen in
            </Th>
          </tr>
        </thead>
        <tbody>
          {hits.map((hit) => (
            <Tr key={`${hit.applicationId}:${hit.componentId}`}>
              <Td>
                <Link
                  to={`/applications/${hit.applicationId}`}
                  className="font-medium text-accent hover:underline"
                >
                  {hit.applicationName}
                </Link>
              </Td>
              <Td>
                <StatusBadge status={hit.applicationStatus} />
              </Td>
              <Td className="font-medium">{hit.componentName}</Td>
              <Td className="nums font-mono text-xs text-text-muted">
                {hit.componentVersion ?? <span className="text-text-faint">unknown</span>}
              </Td>
              <Td>
                <EcosystemBadge ecosystem={hit.ecosystem} />
              </Td>
              <Td>
                {hit.usage === "current" ? (
                  <Badge tone="ok" title="Present in this application's latest scan.">
                    current
                  </Badge>
                ) : (
                  <Badge
                    tone="warn"
                    title="Present in an earlier build but absent from the latest scan — removed or upgraded away."
                  >
                    removed
                  </Badge>
                )}
              </Td>
              <Td>
                {/*
                  The concrete answer to "when did this app last ship this
                  package": build number plus date, linked to that exact scan.
                */}
                <Link
                  to={`/scans/${hit.lastSeenScanId}`}
                  className="text-accent hover:underline"
                  title={formatDateTime(hit.lastSeenAt)}
                >
                  {hit.lastSeenBuildNumber ? `build ${hit.lastSeenBuildNumber}` : "scan"}
                </Link>
                <span className="ml-1.5 text-xs text-text-faint">{formatRelative(hit.lastSeenAt)}</span>
              </Td>
            </Tr>
          ))}
        </tbody>
      </Table>
    </TableWrap>
  );
}
