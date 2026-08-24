import { classifyComponentOrigin, type ComponentLocation } from "@sbom/shared";

/**
 * Turning `scan_component`'s location columns into the client contract.
 *
 * One function rather than a copy in each of the three services that select these columns.
 * They are read by the scan component list, by vulnerability findings and by malicious-package
 * impacts, and the shaping carries two decisions that must not be allowed to drift apart:
 *
 *  - **`origin` is derived here, not stored.** The prefix list behind `classifyComponentOrigin`
 *    is a heuristic, and keeping it out of the schema means correcting it is a release rather
 *    than a migration plus a re-sweep of the largest table in the database.
 *  - **Absent is null, never zero or empty.** `pathCount: 0` reads as "we looked everywhere and
 *    it is nowhere", which is the opposite of what an unrecorded path means. Three different
 *    reasons produce a null here — an OS package whose paths locate only the package manager's
 *    database, an SBOM from a tool that emits no locations, and a scan ingested before the
 *    columns existed — and `origin` is what tells the first of those apart from the other two.
 */

/** The location columns as selected from `scan_component`, joined to `component`. */
export interface LocationRow {
  ecosystem: string;
  kind?: string | null;
  paths: string[] | null;
  path_count: number | string | null;
  layer_id: string | null;
}

export function toComponentLocation(row: LocationRow): ComponentLocation {
  // Postgres returns an empty array rather than NULL if one is ever written; both mean the
  // same thing to a reader, so they collapse to null here and stay one case downstream.
  const paths = row.paths && row.paths.length > 0 ? row.paths : null;

  return {
    paths,
    pathCount: paths ? Number(row.path_count ?? paths.length) : null,
    layerId: row.layer_id,
    origin: classifyComponentOrigin({
      ecosystem: row.ecosystem,
      paths,
      kind: row.kind ?? null,
    }),
  };
}
