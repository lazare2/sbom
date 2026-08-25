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
 *
 * ## Dependants sit here too
 *
 * "Where is it" and "what pulled it in" are different questions, but they are read together
 * and by the same person: the first says where to look, the second says what to change. They
 * come from the same row and are rendered in the same cell so a reader never has to correlate
 * two columns to act on one finding. See DependantsLine for why that half stays silent when
 * nothing was recorded, which is the opposite of the rule the paths above follow.
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
  dependantsExtracted = true,
  compact = false,
}: {
  location: ComponentLocation;
  /**
   * False when this scan has never had a location pass. Changes the wording from "no location
   * recorded" to "not extracted yet", which is the difference between a dead end and a button
   * an administrator can press.
   */
  extracted?: boolean;
  /**
   * The same for dependants, and a separate flag rather than a reuse of the one above.
   *
   * They diverge on exactly the rows where it matters: a scan processed by the earlier,
   * locations-only backfill has its paths but has never had its dependency graph read. One
   * shared flag would either claim those dependants were checked when they were not, or
   * re-report their locations as missing when they are right there.
   */
  dependantsExtracted?: boolean;
  compact?: boolean;
}) {
  const { paths, pathCount, origin, pulledInBy, pulledInByCount } = location;

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

      <DependantsLine
        pulledInBy={pulledInBy}
        pulledInByCount={pulledInByCount}
        extracted={dependantsExtracted}
      />
    </div>
  );
}

/**
 * "Pulled in by fastify, avvio" — the actionable half of a finding.
 *
 * A finding against a package nobody installed is unactionable on its own: nothing names
 * @fastify/error in any manifest, so a developer reading that row has nothing to change.
 * Naming the packages that depend on it names the one to upgrade.
 *
 * ## Silence when there is nothing recorded, and why that is not the usual sin
 *
 * Everywhere else in this platform an absence is spelled out, because an unrendered absence
 * reads as a negative. Here it is rendered as nothing at all, and the reason is that no claim
 * is being suppressed: the column is null only when the SBOM carried no edge, never when it
 * carried an empty one. The parser stores null and never an empty array, so "nothing depends
 * on this" is a state that cannot reach here.
 *
 * The alternative was tried on paper and rejected. Syft reads dependency edges from a
 * lockfile, so a container-image scan has none for its application packages at all —
 * measured at 0 of 193 npm packages in node:20-alpine. A sentence explaining the absence
 * would therefore appear on every row of such a build, which is not information, it is a
 * wall of identical grey text that teaches people to skip the cell.
 *
 * The one absence worth a sentence is the actionable one: a build that has never had its
 * dependency graph read, which an administrator can fix by pressing a button.
 */
function DependantsLine({
  pulledInBy,
  pulledInByCount,
  extracted,
}: {
  pulledInBy: string[] | null;
  pulledInByCount: number | null;
  extracted: boolean;
}) {
  if (!pulledInBy || pulledInBy.length === 0) {
    if (extracted) return null;
    return (
      <p className="text-[11px] text-text-faint">
        Dependencies not extracted yet for this build.
      </p>
    );
  }

  return (
    <p className="text-[11px] leading-snug text-text-muted">
      <span className="text-text-faint">Pulled in by </span>
      {pulledInBy.join(", ")}
      {/* Same rule as the path list: a capped list has to say it is capped, or five names
          read as the complete set and removing all five looks sufficient when it is not. */}
      {pulledInByCount !== null && pulledInByCount > pulledInBy.length ? (
        <span className="text-text-faint"> and {pulledInByCount - pulledInBy.length} more</span>
      ) : null}
    </p>
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
