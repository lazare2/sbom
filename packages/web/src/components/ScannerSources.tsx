import type { FindingSourceDetail, FixState, VulnScanner } from "@sbom/shared";
import { VULN_SCANNER_LABELS } from "@sbom/shared";
import { Mono } from "./ui.tsx";

/**
 * Which scanners reported a finding, and what each said about fixing it.
 *
 * Findings are merged across scanners (see the API's `mergeFindings`), so a fix shown here
 * may come from one scanner while another reports none. Both facts are kept: the cell shows
 * the merged answer and the hover text says who said what.
 */

/** The scanners behind a finding, as quiet inline text rather than badges - it is provenance. */
export function FoundBy({ scanners }: { scanners: readonly VulnScanner[] }) {
  if (scanners.length === 0) return null;
  return (
    <span className="text-[10px] text-text-faint" title="The scanners that reported this. Their findings are merged.">
      found by {scanners.map((s) => VULN_SCANNER_LABELS[s]).join(" · ")}
    </span>
  );
}

/** The leading number of a version, for telling a patch from a move to another release line. */
function major(version: string): string | null {
  return /^\D*?(\d+)/.exec(version)?.[1] ?? null;
}

function describeSource(s: FindingSourceDetail): string {
  const fix =
    s.fixVersions.length > 0
      ? `fixed in ${s.fixVersions.join(", ")}`
      : s.fixState === "wont-fix"
        ? "won't be fixed"
        : s.fixState === "not-fixed"
          ? "no fix"
          : "fix unknown";
  const range = s.affectedRange ? ` (affects ${s.affectedRange})` : "";
  const id = ` as ${s.advisoryId}`;
  return `${VULN_SCANNER_LABELS[s.scanner]}: ${fix}${range}${id}`;
}

/**
 * The fix column.
 *
 * Three different "no version" answers, kept apart because they call for different actions:
 * a scanner that says *not fixed* has checked and found nothing; one whose data has no fix
 * information at all (*unknown*) has not said either way - worth a look elsewhere; and *won't
 * fix* is a vendor decision. They used to render identically as "no fix yet".
 *
 * A fix on a different major version is labelled as such: for spring-webflux 6.2.0 the only
 * open-source fix is 7.0.9, which is a real answer and also a migration, not a patch.
 */
export function FixCell({
  fixState,
  fixVersions,
  installed,
  sources,
}: {
  fixState: FixState;
  fixVersions: readonly string[];
  installed: string | null;
  sources: readonly FindingSourceDetail[];
}) {
  const detail = sources.length > 0 ? sources.map(describeSource).join("\n") : undefined;

  if (fixVersions.length > 0) {
    const first = fixVersions[0]!;
    const laterLine = installed !== null && major(first) !== null && major(installed) !== null && major(first) !== major(installed);
    return (
      <span className="flex flex-col gap-0.5" title={detail ?? fixVersions.join(", ")}>
        <Mono>{first}</Mono>
        {laterLine ? <span className="text-[10px] text-warn">newer release line</span> : null}
        {fixVersions.length > 1 ? (
          <span className="text-[10px] text-text-faint">or {fixVersions.slice(1, 3).join(", ")}</span>
        ) : null}
      </span>
    );
  }
  if (fixState === "wont-fix") {
    return (
      <span className="text-xs text-warn" title={detail ?? "Upstream will not fix this."}>
        won't fix
      </span>
    );
  }
  if (fixState === "not-fixed") {
    return (
      <span className="text-xs text-text-faint" title={detail ?? "The scanners checked and know of no fixed version."}>
        no fix yet
      </span>
    );
  }
  return (
    <span
      className="text-xs text-text-faint"
      title={detail ?? "The data this was matched against carries no fix information either way. Check the advisory's references."}
    >
      fix unknown
    </span>
  );
}
