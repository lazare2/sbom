import { Link } from "react-router";
import type { ComponentSearchHit } from "@sbom/shared";
import { formatDateTime, formatRelative } from "../lib/format.ts";
import { Badge, EcosystemBadge, StatusBadge, Table, TableWrap, Td, Th, Tr } from "./ui.tsx";

/**
 * The package × application result table.
 *
 * Shared by the single search and the bulk list search. Both produce the same
 * `ComponentSearchHit`, and rendering them through one component is what stops the
 * two views drifting apart in how they describe a hit — "current" meaning one
 * thing on one screen and something subtly different on the other is the kind of
 * inconsistency that makes people stop trusting a search.
 */
export function ComponentHitsTable({ hits }: { hits: readonly ComponentSearchHit[] }) {
  return (
    <TableWrap>
      <Table>
        <thead>
          <tr>
            <Th>Application</Th>
            <Th width="120px">Status</Th>
            <Th>Package</Th>
            <Th width="170px">Version</Th>
            <Th width="110px">Ecosystem</Th>
            <Th width="130px">Usage</Th>
            <Th width="200px">Last seen in</Th>
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
