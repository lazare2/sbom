import { Link } from "react-router";
import type { ScanDiff } from "@sbom/shared";
import { formatDateTime, formatNumber, formatRelative, shortSha } from "../lib/format.ts";
import { useClientSort } from "../lib/useSort.ts";
import {
  Badge,
  Card,
  CardHeader,
  EcosystemBadge,
  EmptyState,
  Mono,
  Table,
  TableWrap,
  Td,
  Th,
  Tr,
} from "./ui.tsx";

/**
 * Build-to-build dependency changes.
 *
 * Ordered removed → changed → added deliberately. A package disappearing is the
 * finding people come here for ("we dropped it, when?"); a version bump is
 * routine; a new dependency is worth knowing but rarely urgent. Sorting by what
 * matters beats sorting alphabetically across one merged list.
 */
/*
  Client-side on all three tables. A diff is returned whole (capped per side, and the
  response says when it was), so there is no page for a server sort to reorder.
*/
const DIFF_COLUMNS = { package: "text", version: "text", ecosystem: "text" } as const;
const CHANGED_COLUMNS = { package: "text", from: "text", to: "text", ecosystem: "text" } as const;

export function DiffView({ diff }: { diff: ScanDiff }) {
  const removedSort = useClientSort(
    diff.removed,
    DIFF_COLUMNS,
    { sortBy: "package" },
    (c, f) => (f === "version" ? c.version : f === "ecosystem" ? c.ecosystem : c.name),
    (c) => `${c.name}:${c.version ?? ""}`,
  );
  const changedSort = useClientSort(
    diff.changed,
    CHANGED_COLUMNS,
    { sortBy: "package" },
    (c, f) => (f === "from" ? c.fromVersion : f === "to" ? c.toVersion : f === "ecosystem" ? c.ecosystem : c.name),
    (c) => c.name,
  );
  const addedSort = useClientSort(
    diff.added,
    DIFF_COLUMNS,
    { sortBy: "package" },
    (c, f) => (f === "version" ? c.version : f === "ecosystem" ? c.ecosystem : c.name),
    (c) => `${c.name}:${c.version ?? ""}`,
  );

  const nothingChanged =
    diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0;

  return (
    <>
      <Card className="mb-4">
        <CardHeader
          title="Comparing builds"
          subtitle={
            <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <ScanChip label="From" scan={diff.fromScan} />
              <span aria-hidden="true">→</span>
              <ScanChip label="To" scan={diff.toScan} />
            </span>
          }
          actions={
            <span className="flex flex-wrap items-center gap-2 text-xs">
              <Badge tone="danger">{formatNumber(diff.removed.length)} removed</Badge>
              <Badge tone="warn">{formatNumber(diff.changed.length)} changed</Badge>
              <Badge tone="ok">{formatNumber(diff.added.length)} added</Badge>
              <Badge tone="neutral">{formatNumber(diff.unchangedCount)} unchanged</Badge>
            </span>
          }
        />

        {diff.truncated ? (
          <div className="border-t border-border-base px-4 py-2.5 text-xs text-warn">
            This comparison hit its size limit, so the lists below are partial. That normally means the
            base image changed and swapped out most of the OS packages at once.
          </div>
        ) : null}

        {nothingChanged ? (
          <EmptyState
            title="No dependency changes"
            hint="These two builds shipped exactly the same set of packages at the same versions."
          />
        ) : null}
      </Card>

      {diff.removed.length > 0 ? (
        <Card className="mb-4">
          <CardHeader
            title={`Removed (${formatNumber(diff.removed.length)})`}
            subtitle="Present in the earlier build, gone from the later one — and not replaced by another version."
          />
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th onSort={() => removedSort.toggle("package")} sorted={removedSort.stateOf("package")}>
                    Package
                  </Th>
                  <Th onSort={() => removedSort.toggle("version")} sorted={removedSort.stateOf("version")} width="180px">
                    Version
                  </Th>
                  <Th
                    onSort={() => removedSort.toggle("ecosystem")}
                    sorted={removedSort.stateOf("ecosystem")}
                    width="120px"
                  >
                    Ecosystem
                  </Th>
                  {/* Every row in this table was last seen in the `from` scan by definition. */}
                  <Th>Last seen in</Th>
                </tr>
              </thead>
              <tbody>
                {removedSort.rows.map((c) => (
                  <Tr key={c.id}>
                    <Td>
                      <PackageLink name={c.name} />
                    </Td>
                    <Td className="nums font-mono text-xs text-danger">{c.version ?? "unknown"}</Td>
                    <Td>
                      <EcosystemBadge ecosystem={c.ecosystem} />
                    </Td>
                    <Td>
                      <LastSeen
                        scanId={c.lastSeenScanId}
                        buildNumber={c.lastSeenBuildNumber}
                        at={c.lastSeenAt}
                      />
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        </Card>
      ) : null}

      {diff.changed.length > 0 ? (
        <Card className="mb-4">
          <CardHeader
            title={`Version changes (${formatNumber(diff.changed.length)})`}
            subtitle="Same package, different version. Usually the bulk of a routine build."
          />
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th onSort={() => changedSort.toggle("package")} sorted={changedSort.stateOf("package")}>
                    Package
                  </Th>
                  <Th onSort={() => changedSort.toggle("from")} sorted={changedSort.stateOf("from")} width="180px">
                    From
                  </Th>
                  <Th onSort={() => changedSort.toggle("to")} sorted={changedSort.stateOf("to")} width="180px">
                    To
                  </Th>
                  <Th
                    onSort={() => changedSort.toggle("ecosystem")}
                    sorted={changedSort.stateOf("ecosystem")}
                    width="120px"
                  >
                    Ecosystem
                  </Th>
                </tr>
              </thead>
              <tbody>
                {changedSort.rows.map((c) => (
                  <Tr key={`${c.ecosystem}-${c.name}`}>
                    <Td>
                      <PackageLink name={c.name} />
                    </Td>
                    <Td className="nums font-mono text-xs text-text-muted">{c.fromVersion ?? "unknown"}</Td>
                    <Td className="nums font-mono text-xs text-text-base">{c.toVersion ?? "unknown"}</Td>
                    <Td>
                      <EcosystemBadge ecosystem={c.ecosystem} />
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        </Card>
      ) : null}

      {diff.added.length > 0 ? (
        <Card>
          <CardHeader
            title={`Added (${formatNumber(diff.added.length)})`}
            subtitle="New in the later build, with no earlier version of the same package."
          />
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th onSort={() => addedSort.toggle("package")} sorted={addedSort.stateOf("package")}>
                    Package
                  </Th>
                  <Th onSort={() => addedSort.toggle("version")} sorted={addedSort.stateOf("version")} width="180px">
                    Version
                  </Th>
                  <Th
                    onSort={() => addedSort.toggle("ecosystem")}
                    sorted={addedSort.stateOf("ecosystem")}
                    width="120px"
                  >
                    Ecosystem
                  </Th>
                  <Th>Package URL</Th>
                </tr>
              </thead>
              <tbody>
                {addedSort.rows.map((c) => (
                  <Tr key={c.id}>
                    <Td>
                      <PackageLink name={c.name} />
                    </Td>
                    <Td className="nums font-mono text-xs text-ok">{c.version ?? "unknown"}</Td>
                    <Td>
                      <EcosystemBadge ecosystem={c.ecosystem} />
                    </Td>
                    <Td className="max-w-[520px] truncate" title={c.purl ?? undefined}>
                      {c.purl ? <Mono>{c.purl}</Mono> : <span className="text-text-faint">—</span>}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        </Card>
      ) : null}
    </>
  );
}

function ScanChip({ label, scan }: { label: string; scan: ScanDiff["fromScan"] }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="text-[11px] uppercase tracking-wide text-text-faint">{label}</span>
      <Link to={`/scans/${scan.id}`} className="text-accent hover:underline">
        {scan.buildNumber ? `build ${scan.buildNumber}` : formatDateTime(scan.createdAt)}
      </Link>
      {scan.commitSha ? <Mono title={scan.commitSha}>{shortSha(scan.commitSha)}</Mono> : null}
      <span className="text-text-faint" title={formatDateTime(scan.createdAt)}>
        {formatRelative(scan.createdAt)}
      </span>
    </span>
  );
}

/** Cross-link into global search: "which other applications ship this?" */
export function PackageLink({ name }: { name: string }) {
  return (
    <Link
      to={`/search?name=${encodeURIComponent(name)}&match=exact&scope=all`}
      className="font-medium text-accent hover:underline"
      title={`Find every application using ${name}`}
    >
      {name}
    </Link>
  );
}

/**
 * "last seen in build #N, on date D" — the exact phrasing the requirement asks
 * for, rendered as a link to that build's full component list.
 */
export function LastSeen({
  scanId,
  buildNumber,
  at,
}: {
  scanId: string;
  buildNumber: string | null;
  at: string;
}) {
  if (!scanId) return <span className="text-text-faint">—</span>;
  return (
    <span className="flex flex-wrap items-center gap-1.5 text-xs">
      <Link to={`/scans/${scanId}`} className="text-accent hover:underline">
        {buildNumber ? `build ${buildNumber}` : "that build"}
      </Link>
      <span className="text-text-muted" title={formatDateTime(at)}>
        {formatRelative(at)}
      </span>
    </span>
  );
}
