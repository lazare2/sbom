import type { FindingSourceDetail, FixState, VulnScanner, VulnSeverity } from "@sbom/shared";
import { vulnScanners } from "@sbom/shared";
import type { ParsedFinding } from "./grype-output.js";
import { compareVersions } from "./versions.js";

/**
 * Merging what several scanners reported about the same packages.
 *
 * ## When two findings are the same finding
 *
 * When they are against the same component and share a name: the advisory id one scanner
 * uses, or any alias either lists. Grype's GHSA-9qf2-26p9-2q2q with alias CVE-2026-47892,
 * Trivy's CVE-2026-47892 with vendor id GHSA-9qf2-26p9-2q2q and OSV's GHSA-9qf2-26p9-2q2q are
 * one finding.
 *
 * Two guards keep that from over-reaching:
 *
 *   - A CVE links findings only when it is the one CVE a finding is about. An advisory that
 *     covers several (a distro bulletin, the odd multi-CVE GHSA) would otherwise chain
 *     unrelated findings into one and undercount.
 *   - Two findings from the same scanner are never merged. A scanner that reports two ids
 *     against one package means two advisories, whatever their aliases say.
 *
 * ## Which id the merged finding keeps
 *
 * The one the platform already knows, when any of its names is already a stored advisory -
 * so accepted risks, history and links keep pointing at it. Then Grype's, the scanner this
 * platform has always reported under. Then a GHSA, then a CVE.
 *
 * ## What the merged finding says
 *
 * The highest severity any scanner gave. Every fix version any scanner named, lowest first,
 * and "fixed" when any of them names one. The longest description and every alias, CWE and
 * reference. Per-scanner detail is kept in `sources`, so a disagreement stays visible.
 */

const SEVERITY_RANK: Record<VulnSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  negligible: 1,
  unknown: 0,
};

const ORDER: readonly VulnScanner[] = vulnScanners;

const CVE = /^CVE-\d{4}-\d+$/i;

/** Every name a finding goes by, in its original case. Compare them upper-cased. */
function names(f: ParsedFinding): string[] {
  return [f.vulnerabilityId, ...f.aliases];
}

/** The names that may link this finding to another one; see the module comment. */
function linkKeys(f: ParsedFinding): string[] {
  const all = names(f);
  const cves = all.filter((n) => CVE.test(n));
  return all.filter((n) => !CVE.test(n) || cves.length === 1);
}

function mergeFixState(states: FixState[]): FixState {
  if (states.includes("fixed")) return "fixed";
  if (states.includes("wont-fix")) return "wont-fix";
  if (states.includes("not-fixed")) return "not-fixed";
  return "unknown";
}

/**
 * Choose the merged id.
 *
 * `known` maps any upper-cased name to the id of a stored advisory that carries it, as the id
 * or as an alias.
 */
function canonicalId(group: ParsedFinding[], known: ReadonlyMap<string, string>): string {
  const bySource = [...group].sort((a, b) => ORDER.indexOf(a.source) - ORDER.indexOf(b.source));
  for (const f of bySource) {
    const stored = known.get(f.vulnerabilityId.toUpperCase());
    if (stored) return stored;
  }
  // Through aliases only by the names that may link: a bulletin naming two CVEs must not
  // take the id of the first one, or it lands on that CVE's own finding.
  for (const f of bySource) {
    for (const n of linkKeys(f)) {
      const stored = known.get(n.toUpperCase());
      if (stored) return stored;
    }
  }
  const grype = bySource.find((f) => f.source === "grype");
  if (grype) return grype.vulnerabilityId;
  const all = [...new Set(group.flatMap((f) => [f.vulnerabilityId, ...linkKeys(f)]))].sort();
  return (
    all.find((n) => /^GHSA-/i.test(n)) ??
    all.find((n) => CVE.test(n)) ??
    bySource[0]!.vulnerabilityId
  );
}

function mergeGroup(group: ParsedFinding[], known: ReadonlyMap<string, string>): ParsedFinding {
  const bySource = [...group].sort((a, b) => ORDER.indexOf(a.source) - ORDER.indexOf(b.source));
  const id = canonicalId(group, known);
  const top = Math.max(...group.map((f) => SEVERITY_RANK[f.severity]));
  const severest = bySource.filter((f) => SEVERITY_RANK[f.severity] === top);
  // The score shown beside a severity should be one that produced it.
  const scored = severest.find((f) => f.cvssBaseScore !== null) ?? bySource.find((f) => f.cvssBaseScore !== null);
  const epss = bySource.filter((f) => f.epssScore !== null).sort((a, b) => b.epssScore! - a.epssScore!)[0];
  const describedBest = [...bySource].sort((a, b) => (b.description?.length ?? 0) - (a.description?.length ?? 0))[0]!;
  const titled = bySource.find((f) => f.summary !== null);
  const fixVersions = [...new Set(group.flatMap((f) => f.fixVersions))].sort(compareVersions).slice(0, 16);

  const description = describedBest.description;
  const summaryCandidate = titled?.summary ?? null;

  return {
    componentId: group[0]!.componentId,
    vulnerabilityId: id,
    severity: severest[0]!.severity,
    aliases: [...new Set(group.flatMap((f) => [f.vulnerabilityId, ...f.aliases]))].filter((n) => n !== id).sort(),
    cvssBaseScore: scored?.cvssBaseScore ?? null,
    cvssVector: scored?.cvssVector ?? null,
    epssScore: epss?.epssScore ?? null,
    epssPercentile: epss?.epssPercentile ?? null,
    knownExploited: group.some((f) => f.knownExploited),
    description,
    summary: summaryCandidate && summaryCandidate !== description ? summaryCandidate : null,
    cwes: [...new Set(group.flatMap((f) => f.cwes))],
    dataSource: bySource.find((f) => f.dataSource !== null)?.dataSource ?? null,
    namespace: bySource.find((f) => f.namespace !== null)?.namespace ?? null,
    urls: [...new Set(bySource.flatMap((f) => f.urls))].slice(0, 32),
    fixState: fixVersions.length > 0 ? "fixed" : mergeFixState(group.map((f) => f.fixState)),
    fixVersions,
    matchType: bySource.find((f) => f.matchType !== null)?.matchType ?? null,
    source: bySource[0]!.source,
    affectedRange: bySource.find((f) => f.affectedRange !== null)?.affectedRange ?? null,
    foundBy: [...new Set(bySource.map((f) => f.source))],
    sources: bySource.map(
      (f): FindingSourceDetail => ({
        scanner: f.source,
        advisoryId: f.vulnerabilityId,
        severity: f.severity,
        fixState: f.fixState,
        fixVersions: f.fixVersions,
        affectedRange: f.affectedRange,
      }),
    ),
  };
}

/**
 * Merge the findings of several scanners into one finding per (component, flaw).
 *
 * `known` maps upper-cased advisory names to stored advisory ids - see `canonicalId`. Pass an
 * empty map to merge without reference to what is stored.
 */
export function mergeFindings(findings: readonly ParsedFinding[], known: ReadonlyMap<string, string> = new Map()): ParsedFinding[] {
  const byComponent = new Map<number, ParsedFinding[]>();
  for (const f of findings) byComponent.set(f.componentId, [...(byComponent.get(f.componentId) ?? []), f]);

  const out: ParsedFinding[] = [];
  for (const list of byComponent.values()) {
    // Union-find over this component's findings. Each set records which scanners it holds,
    // so a union that would put two findings from one scanner together can be refused.
    const parent = list.map((_, i) => i);
    const sources = list.map((f) => new Set<VulnScanner>([f.source]));
    const find = (i: number): number => {
      while (parent[i] !== i) {
        parent[i] = parent[parent[i]!]!;
        i = parent[i]!;
      }
      return i;
    };
    const union = (a: number, b: number) => {
      const ra = find(a);
      const rb = find(b);
      if (ra === rb) return;
      for (const s of sources[rb]!) if (sources[ra]!.has(s)) return;
      parent[rb] = ra;
      for (const s of sources[rb]!) sources[ra]!.add(s);
    };

    const owner = new Map<string, number>();
    // Grype first, so its findings anchor the groups the others join.
    const order = list.map((_, i) => i).sort((a, b) => ORDER.indexOf(list[a]!.source) - ORDER.indexOf(list[b]!.source));
    for (const i of order) {
      for (const key of linkKeys(list[i]!).map((n) => n.toUpperCase())) {
        const j = owner.get(key);
        if (j === undefined) owner.set(key, i);
        else union(j, i);
      }
    }

    const groups = new Map<number, ParsedFinding[]>();
    for (let i = 0; i < list.length; i++) groups.set(find(i), [...(groups.get(find(i)) ?? []), list[i]!]);

    // One scanner can report one flaw twice under two match rules; that collapses here too.
    const merged = new Map<string, ParsedFinding>();
    for (const group of groups.values()) {
      const m = mergeGroup(group, known);
      const prior = merged.get(m.vulnerabilityId);
      merged.set(m.vulnerabilityId, prior ? mergeGroup([...priorMembers(prior), ...group], known) : m);
    }
    out.push(...merged.values());
  }
  return out;
}

/**
 * The findings a merged one was built from, rebuilt from its per-source detail. Needed only
 * when two separately merged groups land on the same id - rare, but merging them again must
 * not drop what the first one knew.
 */
function priorMembers(prior: ParsedFinding): ParsedFinding[] {
  return (prior.sources ?? []).map((s) => ({
    ...prior,
    vulnerabilityId: s.advisoryId,
    severity: s.severity,
    fixState: s.fixState,
    fixVersions: s.fixVersions,
    affectedRange: s.affectedRange,
    source: s.scanner,
    foundBy: undefined,
    sources: undefined,
  }));
}
