import type { FixState, VulnSeverity } from "@sbom/shared";

/**
 * Parsing of Grype's JSON report into normalised findings.
 *
 * Deliberately pure and free of any I/O, because this is where the correctness risk
 * in the whole feature lives: every figure on every dashboard is downstream of these
 * few functions, and a silently mis-parsed severity or a finding attributed to the
 * wrong package produces numbers that look entirely plausible and are wrong.
 * Isolating it here means it can be tested against real recorded output rather than
 * only observed through a database.
 *
 * Written as hand-rolled field reads rather than a Zod schema over `matches[]`, for
 * the same reason the CycloneDX parser is: one sweep can carry tens of thousands of
 * matches, and per-object schema validation there costs real CPU for no benefit when
 * every field consumed is individually checked anyway.
 *
 * The shapes below were confirmed against Grype 0.115.0 output, not assumed.
 */

/** One advisory affecting one package, mapped back to the component we submitted. */
export interface ParsedFinding {
  /** The `component.id` this finding belongs to, recovered exactly — see `readArtifactId`. */
  componentId: number;
  vulnerabilityId: string;
  severity: VulnSeverity;
  /** CVE ids and other names for the same advisory. */
  aliases: string[];
  cvssBaseScore: number | null;
  cvssVector: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  knownExploited: boolean;
  description: string | null;
  dataSource: string | null;
  namespace: string | null;
  urls: string[];
  fixState: FixState;
  fixVersions: string[];
  matchType: string | null;
}

export interface ParsedReport {
  findings: ParsedFinding[];
  grypeVersion: string | null;
  /** `built` timestamp of the database that produced this report. */
  dbBuiltAt: Date | null;
  dbSchemaVersion: string | null;
  /**
   * Findings whose `artifact.id` was not a component id we submitted.
   *
   * Should always be zero. Counted rather than ignored because a non-zero value
   * means findings are being dropped, and a silent drop here would understate every
   * count on every dashboard — the one failure mode that looks like good news.
   */
  unmappedFindings: number;
}

/**
 * Grype's severity strings, lowercased onto our enum.
 *
 * Anything unrecognised becomes `unknown` rather than being dropped or promoted:
 * a finding with a severity we cannot interpret is still a finding, and guessing
 * `low` would be a fabrication while dropping it would hide a real match.
 */
export function toSeverity(raw: unknown): VulnSeverity {
  if (typeof raw !== "string") return "unknown";
  switch (raw.trim().toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "negligible":
      return "negligible";
    default:
      return "unknown";
  }
}

/**
 * Grype's `fix.state`, normalised.
 *
 * `wont-fix` is kept distinct from `not-fixed` because they call for different
 * responses: one means "wait for or chase a release", the other means "no release is
 * coming, so mitigate or accept". Collapsing them would erase the difference between
 * a finding that will age out and one that never will.
 */
export function toFixState(raw: unknown): FixState {
  if (typeof raw !== "string") return "unknown";
  switch (raw.trim().toLowerCase()) {
    case "fixed":
      return "fixed";
    case "not-fixed":
    case "not_fixed":
      return "not-fixed";
    case "wont-fix":
    case "wont_fix":
    case "will-not-fix":
      return "wont-fix";
    default:
      return "unknown";
  }
}

function asString(value: unknown, max = 4096): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed === "") return null;
  return trimmed.length > max ? trimmed.slice(0, max) : trimmed;
}

function asStringArray(value: unknown, max = 64): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const entry of value) {
    const s = asString(entry, 2048);
    if (s && !out.includes(s)) out.push(s);
    if (out.length >= max) break;
  }
  return out;
}

function asFiniteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * Highest-versioned CVSS score on the advisory.
 *
 * Grype can report several — a v2 alongside a v3.1, `Primary` alongside
 * `Secondary`. Taking the highest *version* rather than the highest *score* is
 * deliberate: the newest metric is the most current assessment, whereas picking the
 * largest number would systematically inflate scores by always preferring whichever
 * scale happened to rate it worst.
 */
export function pickCvss(raw: unknown): { baseScore: number | null; vector: string | null } {
  if (!Array.isArray(raw) || raw.length === 0) return { baseScore: null, vector: null };

  let best: { version: number; baseScore: number | null; vector: string | null } | null = null;
  for (const entry of raw) {
    if (typeof entry !== "object" || entry === null) continue;
    const e = entry as { version?: unknown; vector?: unknown; metrics?: unknown };
    const versionText = asString(e.version, 16) ?? "0";
    // "3.1" -> 3.1, "2.0" -> 2. A non-numeric version sorts lowest rather than
    // throwing off the comparison.
    const version = Number.parseFloat(versionText);
    const metrics = typeof e.metrics === "object" && e.metrics !== null ? (e.metrics as { baseScore?: unknown }) : {};
    const candidate = {
      version: Number.isFinite(version) ? version : 0,
      baseScore: asFiniteNumber(metrics.baseScore),
      vector: asString(e.vector, 256),
    };
    if (!best || candidate.version > best.version) best = candidate;
  }

  return best ? { baseScore: best.baseScore, vector: best.vector } : { baseScore: null, vector: null };
}

/**
 * EPSS probability and percentile, if present.
 *
 * An array in Grype's output, one entry per CVE the advisory covers. The highest
 * probability is the right pick here — unlike CVSS, these are all the same metric on
 * the same scale, so "the worst of the CVEs this advisory covers" is a coherent
 * answer rather than a scale mix-up.
 */
export function pickEpss(raw: unknown): { score: number | null; percentile: number | null } {
  if (!Array.isArray(raw) || raw.length === 0) return { score: null, percentile: null };

  let best: { score: number; percentile: number | null } | null = null;
  for (const entry of raw) {
    if (typeof entry !== "object" || entry === null) continue;
    const e = entry as { epss?: unknown; percentile?: unknown };
    const score = asFiniteNumber(e.epss);
    if (score === null) continue;
    if (!best || score > best.score) best = { score, percentile: asFiniteNumber(e.percentile) };
  }

  return best ? { score: best.score, percentile: best.percentile } : { score: null, percentile: null };
}

/**
 * CVE ids for the same advisory, gathered from `relatedVulnerabilities`.
 *
 * This is what makes a CVE search work at all. Grype's primary id for a language
 * package is usually a GHSA — Log4Shell is `GHSA-jfh8-c2jp-5v3q`, with
 * `CVE-2021-44228` only appearing as a related entry. Someone searching for the CVE
 * number they read in the news has to reach the same row, and storing the aliases is
 * the only way that happens.
 */
export function collectAliases(match: unknown): string[] {
  if (typeof match !== "object" || match === null) return [];
  const m = match as { relatedVulnerabilities?: unknown; vulnerability?: unknown };
  const primaryId =
    typeof m.vulnerability === "object" && m.vulnerability !== null
      ? asString((m.vulnerability as { id?: unknown }).id, 128)
      : null;

  const out: string[] = [];
  if (Array.isArray(m.relatedVulnerabilities)) {
    for (const related of m.relatedVulnerabilities) {
      if (typeof related !== "object" || related === null) continue;
      const id = asString((related as { id?: unknown }).id, 128);
      // Never list the advisory as its own alias: it would make dedupe-by-alias
      // match a row against itself.
      if (id && id !== primaryId && !out.includes(id)) out.push(id);
    }
  }
  return out;
}

/**
 * Recovers the component id from `artifact.id`.
 *
 * Verified against Grype 0.115.0: the `bom-ref` set on each component of the
 * synthetic SBOM is echoed back verbatim as `artifact.id`. That gives an exact
 * one-to-one mapping and removes the whole class of mis-attribution bugs that
 * matching on purl or name+version invites — two components can share a name and
 * version while differing by ecosystem, and a package with no purl has no other
 * stable key at all.
 *
 * When no `bom-ref` is supplied Grype substitutes a generated hash, which fails this
 * check and is counted as unmapped rather than guessed at.
 */
function readArtifactId(artifact: unknown): number | null {
  if (typeof artifact !== "object" || artifact === null) return null;
  const raw = (artifact as { id?: unknown }).id;
  if (typeof raw !== "string") return null;
  // Bare digits only. A grype-generated hash like `92547e41269f40eb` must not parse.
  if (!/^\d+$/.test(raw)) return null;
  const id = Number.parseInt(raw, 10);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

/** Reads the database provenance Grype reports alongside the matches. */
function readDescriptor(doc: {
  descriptor?: unknown;
}): { grypeVersion: string | null; dbBuiltAt: Date | null; dbSchemaVersion: string | null } {
  const empty = { grypeVersion: null, dbBuiltAt: null, dbSchemaVersion: null };
  if (typeof doc.descriptor !== "object" || doc.descriptor === null) return empty;

  const d = doc.descriptor as { version?: unknown; db?: unknown };
  const grypeVersion = asString(d.version, 64);

  let dbBuiltAt: Date | null = null;
  let dbSchemaVersion: string | null = null;
  if (typeof d.db === "object" && d.db !== null) {
    const status = (d.db as { status?: unknown }).status;
    if (typeof status === "object" && status !== null) {
      const s = status as { built?: unknown; schemaVersion?: unknown };
      const built = asString(s.built, 64);
      if (built) {
        const parsed = new Date(built);
        if (!Number.isNaN(parsed.getTime())) dbBuiltAt = parsed;
      }
      dbSchemaVersion = asString(s.schemaVersion, 32);
    }
  }

  return { grypeVersion, dbBuiltAt, dbSchemaVersion };
}

/**
 * Parse one Grype JSON report.
 *
 * Never throws on a malformed individual match — the surrounding sweep processes
 * thousands and one odd entry must not discard the batch. A payload that is not a
 * Grype report at all does throw, because continuing would silently record an empty
 * result as "no vulnerabilities found".
 */
export function parseGrypeReport(raw: string): ParsedReport {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `grype did not return valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new Error("grype report must be a JSON object");
  }

  const root = doc as { matches?: unknown; descriptor?: unknown };
  if (!Array.isArray(root.matches)) {
    throw new Error("grype report has no `matches` array");
  }

  const descriptor = readDescriptor(root);
  const findings: ParsedFinding[] = [];
  /**
   * One row per (component, advisory).
   *
   * Grype can report the same pairing more than once when several match rules fire —
   * a direct purl match and a CPE match, say. Those are one finding, and letting
   * both through would double-count it in every severity total.
   */
  const seen = new Set<string>();
  let unmappedFindings = 0;

  for (const match of root.matches) {
    if (typeof match !== "object" || match === null) continue;
    const m = match as { vulnerability?: unknown; artifact?: unknown; matchDetails?: unknown };

    const componentId = readArtifactId(m.artifact);
    if (componentId === null) {
      unmappedFindings++;
      continue;
    }

    if (typeof m.vulnerability !== "object" || m.vulnerability === null) continue;
    const v = m.vulnerability as {
      id?: unknown;
      severity?: unknown;
      cvss?: unknown;
      epss?: unknown;
      knownExploited?: unknown;
      description?: unknown;
      dataSource?: unknown;
      namespace?: unknown;
      urls?: unknown;
      fix?: unknown;
    };

    const vulnerabilityId = asString(v.id, 128);
    if (!vulnerabilityId) continue;

    const key = `${componentId} ${vulnerabilityId}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const cvss = pickCvss(v.cvss);
    const epss = pickEpss(v.epss);

    const fix = typeof v.fix === "object" && v.fix !== null ? (v.fix as { state?: unknown; versions?: unknown }) : {};

    let matchType: string | null = null;
    if (Array.isArray(m.matchDetails) && m.matchDetails.length > 0) {
      const first = m.matchDetails[0];
      if (typeof first === "object" && first !== null) {
        matchType = asString((first as { type?: unknown }).type, 64);
      }
    }

    findings.push({
      componentId,
      vulnerabilityId,
      severity: toSeverity(v.severity),
      aliases: collectAliases(match),
      cvssBaseScore: cvss.baseScore,
      cvssVector: cvss.vector,
      epssScore: epss.score,
      epssPercentile: epss.percentile,
      // Presence of any entry means CISA has recorded active exploitation.
      knownExploited: Array.isArray(v.knownExploited) && v.knownExploited.length > 0,
      description: asString(v.description, 4000),
      dataSource: asString(v.dataSource, 512),
      namespace: asString(v.namespace, 128),
      urls: asStringArray(v.urls, 16),
      fixState: toFixState(fix.state),
      fixVersions: asStringArray(fix.versions, 16),
      matchType,
    });
  }

  return {
    findings,
    grypeVersion: descriptor.grypeVersion,
    dbBuiltAt: descriptor.dbBuiltAt,
    dbSchemaVersion: descriptor.dbSchemaVersion,
    unmappedFindings,
  };
}

// ---------------------------------------------------------------------------
// Synthetic SBOM construction
// ---------------------------------------------------------------------------

export interface ScannablePackage {
  componentId: number;
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string;
}

/**
 * Builds the CycloneDX document handed to Grype for a batch of components.
 *
 * This is the other half of the component-keyed design. Rather than re-scanning each
 * application's SBOM, the platform's globally deduplicated component set is fed
 * through in batches — so a package shared by forty applications is matched once, and
 * re-evaluating the whole estate after a database update is one pass over distinct
 * packages instead of one Grype run per application.
 *
 * Two details make it work:
 *   - `bom-ref` carries the component id, which comes back as `artifact.id`.
 *   - The purl is passed through verbatim, including its qualifiers. Verified: a deb
 *     package matches identically with or without a declared `operating-system`
 *     component, because `?distro=debian-11` already carries the distro context. That
 *     is what makes a merged, cross-distro batch sound.
 */
export function buildScanDocument(packages: readonly ScannablePackage[]): string {
  return JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      // No `component` subject: this document describes no single image, and
      // inventing one would put a meaningless name in Grype's output.
      tools: { components: [{ type: "application", name: "sbom-platform" }] },
    },
    components: packages.map((pkg) => ({
      "bom-ref": String(pkg.componentId),
      type: "library",
      name: pkg.name,
      ...(pkg.version === null ? {} : { version: pkg.version }),
      ...(pkg.purl === null ? {} : { purl: pkg.purl }),
    })),
  });
}
