import {
  COMPONENT_ORIGIN_HINTS,
  COMPONENT_ORIGIN_LABELS,
  type ComponentLocation,
  type ComponentOrigin,
} from "@sbom/shared";
import { Badge } from "./ui.tsx";
import type { BadgeTone } from "./ui.tsx";

/**
 * Where a package was found, rendered.
 *
 * ## The label never appears without the path
 *
 * `origin` is a heuristic — a prefix list, checked against real images but still a guess about
 * somebody else's filesystem layout. That is only acceptable because this component always
 * shows the evidence underneath it. A reader who sees "Image" above
 * `/usr/src/app/node_modules/evil` knows instantly that the label is wrong and the path is
 * right, and acts on the path. A badge on its own would have to be trusted, and it has not
 * earned that.
 *
 * ## Absent is not empty
 *
 * Three different things produce no path, and they are three different sentences:
 *
 *   os_package  the package manager tracks it, so no single path exists. Not a gap.
 *   unknown     this SBOM recorded no location. A gap, and the reader is told it is one.
 *   not extracted   the scan predates the platform recording locations, and a backfill would
 *                   fill it in. Distinguishable only because `scan.locations_extracted_at`
 *                   exists; without that column this case would be indistinguishable from the
 *                   one above and both would render as a shrug.
 *
 * None of them renders as blank, because a blank cell in a table of paths reads as "this
 * package is nowhere", which is a claim about the artifact rather than about the record.
 */

const ORIGIN_TONES: Record<ComponentOrigin, BadgeTone> = {
  // Neither of the two real origins is a problem in itself — a package being in the base image
  // is not worse than being in the app, only differently owned — so neither gets a warning
  // tone. `unknown` does, because it is the one that means the platform cannot answer.
  application: "info",
  image: "neutral",
  os_package: "neutral",
  unknown: "warn",
};

export function OriginBadge({ origin }: { origin: ComponentOrigin }) {
  return (
    <Badge tone={ORIGIN_TONES[origin]} title={COMPONENT_ORIGIN_HINTS[origin]}>
      {COMPONENT_ORIGIN_LABELS[origin]}
    </Badge>
  );
}

/**
 * The full cell: origin, then every stored path, then the truncation notice.
 *
 * `compact` drops the badge for contexts that already state the origin in a column of their
 * own, so the same paths are not annotated twice on one row.
 */
export function ComponentLocationCell({
  location,
  extracted = true,
  compact = false,
}: {
  location: ComponentLocation;
  /**
   * False when this scan has never had a location pass. Changes the wording from "no location
   * recorded" to "not extracted yet", which is the difference between a dead end and a button
   * an administrator can press.
   */
  extracted?: boolean;
  compact?: boolean;
}) {
  const { paths, pathCount, origin } = location;

  return (
    <div className="space-y-1">
      {compact ? null : <OriginBadge origin={origin} />}

      {paths && paths.length > 0 ? (
        <>
          <ul className="space-y-0.5">
            {paths.map((path) => (
              <li key={path} className="font-mono text-[11px] leading-snug break-all text-text-muted">
                {path}
              </li>
            ))}
          </ul>
          {pathCount !== null && pathCount > paths.length ? (
            <p className="text-[11px] text-text-faint">
              {/* Showing "3 of 47" rather than three unlabelled lines. A truncated list that
                  does not admit it is truncated is read as complete. */}
              Showing {paths.length} of {pathCount} locations
            </p>
          ) : null}
        </>
      ) : (
        <p className="text-[11px] text-text-faint">{absentReason(origin, extracted)}</p>
      )}
    </div>
  );
}

function absentReason(origin: ComponentOrigin, extracted: boolean): string {
  if (origin === "os_package") {
    return "Tracked by the distribution's package manager, not at a single path.";
  }
  if (!extracted) {
    return "Not extracted yet — this build predates location recording.";
  }
  return "This SBOM recorded no location for the package.";
}
