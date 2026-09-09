import type { VulnSeverity } from "@sbom/shared";
import type { ParsedFinding } from "./grype-output.js";
import type { XrayVulnerability } from "./xray-client.js";

/**
 * Turning an Xray graph-scan result into this platform's findings.
 *
 * The counterpart of `grype-output.ts`, and deliberately the same shape out: everything
 * downstream — the sweep, the per-scan summaries, every dashboard figure — is written against
 * `ParsedFinding` and must not learn which provider produced it.
 *
 * ## Recovering which component a finding belongs to
 *
 * Grype carries the component id in the document's `bom-ref` and hands it back as
 * `artifact.id`. Xray has no such channel: a graph node is only its coordinate string, so the
 * caller supplies the coordinate-to-component-id map it built when submitting, and findings
 * are matched back through that.
 *
 * The map is one-to-many on purpose. Two components with different identity hashes can
 * produce the same Xray coordinate — the same package recorded once with a distro qualifier
 * and once without — and a finding has to reach both of them or one silently reads as clean.
 */

/**
 * Xray's severity ladder onto this platform's.
 *
 * `Unknown` stays unknown rather than becoming `low`: a missing rating is a real answer from
 * the feeds and promoting it would overstate what is known. `Information` maps to
 * `negligible`, which is a rating rather than an absence — the two are not the same and this
 * platform has a bucket for each.
 */
const SEVERITIES: Record<string, VulnSeverity> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  information: "negligible",
  informational: "negligible",
  negligible: "negligible",
  unknown: "unknown",
  none: "unknown",
};

function toSeverity(raw: string | undefined): VulnSeverity {
  return SEVERITIES[(raw ?? "").trim().toLowerCase()] ?? "unknown";
}

function toNumber(value: number | string | undefined): number | null {
  if (value === undefined || value === null || value === "") return null;
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * The advisory's primary identity, and the aliases that point at it.
 *
 * A CVE is preferred when there is one, because it is what a reader recognises and what they
 * search for. Xray's own `XRAY-nnnnn` id becomes an alias rather than the key — it is
 * meaningful only inside JFrog, and keying on it would make the same advisory unrecognisable
 * against anything else the platform stores.
 *
 * With several CVEs on one issue the lowest-sorting one is chosen so the choice is stable
 * across runs; the rest stay as aliases. An issue with no CVE at all keeps the Xray id, which
 * is better than inventing one.
 */
function identify(vuln: XrayVulnerability): { id: string; aliases: string[] } | null {
  const cves = (vuln.cves ?? [])
    .map((entry) => entry.cve?.trim())
    .filter((cve): cve is string => !!cve && cve !== "")
    .sort();

  const issueId = vuln.issue_id?.trim();

  if (cves.length > 0) {
    const [primary, ...rest] = cves;
    return { id: primary!, aliases: issueId ? [...rest, issueId] : rest };
  }
  if (issueId) return { id: issueId, aliases: [] };

  /*
    No identity at all. Dropped rather than synthesised: a finding keyed on a generated id
    would be a new advisory on every scan, and the "introduced since last month" figure in
    the management report would grow forever.
  */
  return null;
}

/** The strongest CVSS the issue carries, preferring v3 as the feeds do. */
function scoreOf(vuln: XrayVulnerability): { score: number | null; vector: string | null } {
  let score: number | null = null;
  let vector: string | null = null;
  for (const entry of vuln.cves ?? []) {
    const v3 = toNumber(entry.cvss_v3_score);
    if (v3 !== null && (score === null || v3 > score)) {
      score = v3;
      vector = entry.cvss_v3_vector?.trim() || null;
    }
  }
  if (score === null) {
    for (const entry of vuln.cves ?? []) {
      const v2 = toNumber(entry.cvss_v2_score);
      if (v2 !== null && (score === null || v2 > score)) score = v2;
    }
  }
  return { score, vector };
}

export interface XrayMapping {
  /** Xray coordinate -> the component ids that produced it. */
  byCoordinate: Map<string, number[]>;
}

/**
 * Maps a completed scan onto findings.
 *
 * Returns the findings plus the count of component references Xray reported that were never
 * submitted. That number should always be zero; it is counted rather than ignored because a
 * non-zero value means the coordinate written on the way out is not the one that came back,
 * and every finding for those packages is being dropped on the floor.
 */
export function toFindings(
  vulnerabilities: readonly XrayVulnerability[],
  mapping: XrayMapping,
): { findings: ParsedFinding[]; unmatchedReferences: number; unidentified: number } {
  const findings: ParsedFinding[] = [];
  let unmatchedReferences = 0;
  let unidentified = 0;

  for (const vuln of vulnerabilities) {
    const identity = identify(vuln);
    if (!identity) {
      unidentified += 1;
      continue;
    }
    const { score, vector } = scoreOf(vuln);
    const severity = toSeverity(vuln.severity);

    for (const [coordinate, detail] of Object.entries(vuln.components ?? {})) {
      const componentIds = mapping.byCoordinate.get(coordinate);
      if (!componentIds || componentIds.length === 0) {
        unmatchedReferences += 1;
        continue;
      }

      const fixVersions = (detail.fixed_versions ?? [])
        .map((v) => (typeof v === "string" ? v.trim() : ""))
        .filter((v) => v !== "");

      for (const componentId of componentIds) {
        findings.push({
          componentId,
          vulnerabilityId: identity.id,
          severity,
          aliases: identity.aliases,
          cvssBaseScore: score,
          cvssVector: vector,
          /*
            Xray publishes neither EPSS nor the CISA known-exploited catalogue. Null and
            false here are not claims about the advisory -- they are the absence of an
            answer, and the provider's declared capabilities are what stop the platform
            rendering them as one.
          */
          epssScore: null,
          epssPercentile: null,
          knownExploited: false,
          description: vuln.summary?.trim() || null,
          dataSource: "jfrog-xray",
          namespace: detail.package_type?.trim() || null,
          urls: (vuln.references ?? []).filter((u) => typeof u === "string" && u.trim() !== ""),
          /*
            Xray states the versions that fix an issue but not a fix *state* -- there is no
            "wont-fix" or "unknown" in this response. A populated list means fixed; an empty
            one means Xray knows of no fix, which is `unknown` rather than `not-fixed`,
            because the two differ by whether anybody looked.
          */
          fixState: fixVersions.length > 0 ? "fixed" : "unknown",
          fixVersions,
          matchType: "xray-graph",
        });
      }
    }
  }

  return { findings, unmatchedReferences, unidentified };
}
