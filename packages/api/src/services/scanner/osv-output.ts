import type { FixState, VulnSeverity } from "@sbom/shared";
import type { ParsedFinding, ScannablePackage } from "./grype-output.js";
import { isKernelHeaders, sourcePackage } from "./trivy-output.js";
import { compareVersions, upgradeFixes } from "./versions.js";

/**
 * Building osv-scanner's input and reading its output.
 *
 * Confirmed against osv-scanner 2.7.0 in offline mode:
 *
 *   - Each package in the output carries the full OSV records that matched it - summary,
 *     details, CVSS vectors, CWE ids, and the affected ranges with their fixed versions - so
 *     nothing has to be looked up afterwards.
 *   - The output does not echo `bom-ref`. It does echo the purl exactly as submitted, so the
 *     purl is the key back to component ids. Two components that submit the same purl (two
 *     Debian binaries of one source package) both receive its findings, which is right: the
 *     advisory is against the source they share.
 *   - Debian is matched by source package: `libssl3` matched nothing, `openssl` matched
 *     fifty-four. The source comes from Syft's `upstream` purl qualifier.
 *   - `groups` collects the records that describe one flaw (a PYSEC and a GHSA for the same
 *     CVE). One finding is produced per group.
 */

/** Purl types OSV cannot match against any database; sending them only costs time. */
const UNMATCHABLE = new Set(["generic", "binary", "unknown", "github", "docker", "oci"]);

export interface OsvDocument {
  json: string;
  /** The exact purl submitted -> the components it stands for. */
  byPurl: Map<string, number[]>;
}

function purlType(purl: string): string {
  return purl.slice(4).split("/")[0]?.toLowerCase() ?? "";
}

function qualifier(purl: string, key: string): string | undefined {
  const q = purl.indexOf("?");
  if (q < 0) return undefined;
  for (const pair of (purl.slice(q + 1).split("#")[0] ?? "").split("&")) {
    const eq = pair.indexOf("=");
    if (eq > 0 && pair.slice(0, eq).toLowerCase() === key) {
      try {
        return decodeURIComponent(pair.slice(eq + 1));
      } catch {
        return pair.slice(eq + 1);
      }
    }
  }
  return undefined;
}

/**
 * The purl to submit for a package. Debian packages are rewritten to their source package,
 * keeping the `distro` and `arch` qualifiers OSV needs to pick the release.
 */
export function osvPurl(pkg: ScannablePackage): string | null {
  const purl = pkg.purl;
  if (!purl || !purl.startsWith("pkg:")) return null;
  const type = purlType(purl);
  if (UNMATCHABLE.has(type)) return null;
  if (type !== "deb") return purl;

  const src = sourcePackage(type, qualifier(purl, "upstream"), pkg.version);
  if (!src || !src.version) return purl;
  const namespace = purl.slice(4).split("/")[1] ?? "debian";
  const qualifiers = ["arch", "distro"]
    .map((k) => [k, qualifier(purl, k)] as const)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}=${encodeURIComponent(v!)}`)
    .join("&");
  return `pkg:deb/${namespace}/${encodeURIComponent(src.name)}@${encodeURIComponent(src.version)}${qualifiers ? `?${qualifiers}` : ""}`;
}

/** The distribution an OS package purl names: its namespace, `pkg:deb/ubuntu/...` -> `ubuntu`. */
function distroOf(purl: string): string | null {
  const [type, namespace] = purl.slice(4).split("/");
  return type && ["deb", "apk", "rpm"].includes(type.toLowerCase()) && namespace ? namespace.toLowerCase() : null;
}

/** `skipDistros`: distributions left out - see OSV_SKIP_DISTROS. */
export function buildOsvDocument(packages: readonly ScannablePackage[], skipDistros: readonly string[] = []): OsvDocument {
  const byPurl = new Map<string, number[]>();
  for (const pkg of packages) {
    if (isKernelHeaders(pkg)) continue;
    const purl = osvPurl(pkg);
    if (!purl) continue;
    const distro = distroOf(purl);
    if (distro !== null && skipDistros.includes(distro)) continue;
    byPurl.set(purl, [...(byPurl.get(purl) ?? []), pkg.componentId]);
  }
  const components = [...byPurl.keys()].map((purl, i) => {
    const at = purl.lastIndexOf("@");
    const head = purl.slice(4, at > 0 ? at : undefined).split("?")[0] ?? "";
    const name = decodeURIComponent(head.split("/").pop() ?? "");
    const version = at > 0 ? decodeURIComponent(purl.slice(at + 1).split("?")[0] ?? "") : undefined;
    return { "bom-ref": `p${i}`, type: "library", name, ...(version ? { version } : {}), purl };
  });
  return {
    byPurl,
    json: JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      version: 1,
      metadata: { tools: { components: [{ type: "application", name: "sbom-platform" }] } },
      components,
    }),
  };
}

// --- reading the output -------------------------------------------------------

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvRecord {
  id?: unknown;
  aliases?: unknown;
  upstream?: unknown;
  summary?: unknown;
  details?: unknown;
  severity?: unknown;
  database_specific?: { severity?: unknown; cwe_ids?: unknown; source?: unknown } | null;
  references?: unknown;
  affected?: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: Array<{ type?: string; events?: OsvEvent[] }>;
    database_specific?: { source?: unknown } | null;
  }>;
}

function str(value: unknown, max = 4096): string | null {
  if (typeof value !== "string") return null;
  const t = value.trim();
  return t === "" ? null : t.slice(0, max);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.map((v) => str(v, 256)).filter((v): v is string => v !== null) : [];
}

/** Advisory kinds that bundle several CVEs into one notice. */
const BUNDLE = /^(DSA|DLA|DTSA|USN|RHSA|RHBA|RHEA|ALSA|ALBA|RLSA|ELSA|SUSE-SU|openSUSE-SU)-/i;

/**
 * Which record of a group to report under: the GHSA when there is one, then the CVE, then an
 * ecosystem's own id, with distro bundles last. A GHSA first keeps OSV's findings under the
 * same id Grype uses for language packages.
 */
function rank(id: string): number {
  if (/^GHSA-/i.test(id)) return 0;
  if (/^CVE-/i.test(id)) return 1;
  if (BUNDLE.test(id)) return 4;
  if (/-CVE-\d/i.test(id)) return 3; // ALPINE-CVE-…, DEBIAN-CVE-…, UBUNTU-CVE-…
  return 2; // PYSEC, GO, RUSTSEC, …
}

/** `moderate` is GitHub's word for medium. */
function textSeverity(raw: unknown): VulnSeverity | null {
  const s = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (s === "critical" || s === "high" || s === "medium" || s === "low") return s;
  if (s === "moderate") return "medium";
  if (s === "negligible" || s === "unimportant") return "negligible";
  return null;
}

/** CVSS base score bands, as NVD draws them. */
export function scoreSeverity(score: number | null): VulnSeverity {
  if (score === null || !Number.isFinite(score)) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "negligible";
}

function cvssVector(records: OsvRecord[]): string | null {
  for (const type of ["CVSS_V4", "CVSS_V3", "CVSS_V2"]) {
    for (const r of records) {
      if (!Array.isArray(r.severity)) continue;
      for (const s of r.severity as Array<{ type?: string; score?: string }>) {
        if (s.type === type && typeof s.score === "string" && s.score.startsWith("CVSS")) return s.score;
      }
    }
  }
  return null;
}

/**
 * Fix versions and the matched range, from the affected entries for this exact package.
 *
 * Fix versions are every `fixed` event newer than the installed version, which deliberately
 * includes fixes on later release lines: for spring-webflux 6.2.0 the 6.2 line has no
 * open-source fix but 7.0.9 does, and saying "fixed in 7.0.9" is the useful answer.
 */
export function osvFix(
  records: OsvRecord[],
  pkg: { ecosystem: string; name: string },
  installed: string | null,
): { fixState: FixState; fixVersions: string[]; affectedRange: string | null } {
  const fixed: string[] = [];
  let affectedRange: string | null = null;
  let sawRange = false;
  const sameName = (a: string, b: string) => a.toLowerCase().replace(/[-_.]+/g, "-") === b.toLowerCase().replace(/[-_.]+/g, "-");

  for (const record of records) {
    for (const affected of record.affected ?? []) {
      if (affected.package?.ecosystem !== pkg.ecosystem || !sameName(affected.package?.name ?? "", pkg.name)) continue;
      for (const range of affected.ranges ?? []) {
        if (range.type === "GIT") continue;
        sawRange = true;
        let introduced: string | null = null;
        for (const event of range.events ?? []) {
          if (event.introduced !== undefined) introduced = event.introduced;
          if (event.fixed !== undefined) fixed.push(event.fixed);
          const upper = event.fixed ?? event.last_affected;
          if (upper === undefined || affectedRange !== null || !installed) continue;
          const from = introduced && introduced !== "0" ? introduced : null;
          const inside =
            (from === null || compareVersions(installed, from) >= 0) &&
            (event.fixed !== undefined
              ? compareVersions(installed, event.fixed) < 0
              : compareVersions(installed, event.last_affected!) <= 0);
          if (inside) {
            const lower = from ? `>=${from}` : null;
            const top = event.fixed !== undefined ? `<${event.fixed}` : `<=${event.last_affected}`;
            affectedRange = [lower, top].filter(Boolean).join(",");
          }
        }
      }
    }
  }

  const fixVersions = upgradeFixes(fixed, installed).slice(0, 16);
  return {
    fixState: fixVersions.length > 0 ? "fixed" : sawRange ? "not-fixed" : "unknown",
    fixVersions,
    affectedRange,
  };
}

/** Parse one osv-scanner JSON report into findings against the submitted components. */
export function parseOsvReport(raw: string, byPurl: ReadonlyMap<string, number[]>): { findings: ParsedFinding[]; unmappedFindings: number } {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    throw new Error(`osv-scanner did not return valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (typeof doc !== "object" || doc === null) throw new Error("osv-scanner report must be a JSON object");
  const results = (doc as { results?: unknown }).results;

  const findings: ParsedFinding[] = [];
  let unmappedFindings = 0;

  for (const result of Array.isArray(results) ? results : []) {
    for (const entry of ((result as { packages?: unknown }).packages as unknown[]) ?? []) {
      const p = entry as {
        package?: { name?: string; version?: string; ecosystem?: string; purl?: string };
        vulnerabilities?: OsvRecord[];
        groups?: Array<{ ids?: string[]; aliases?: string[]; max_severity?: string }>;
      };
      const records = new Map<string, OsvRecord>();
      for (const r of p.vulnerabilities ?? []) {
        const id = str(r.id, 128);
        if (id) records.set(id, r);
      }
      if (records.size === 0) continue;

      const componentIds = p.package?.purl ? byPurl.get(p.package.purl) : undefined;
      if (!componentIds || componentIds.length === 0) {
        unmappedFindings += records.size;
        continue;
      }

      /*
        Grouped here rather than taken from osv-scanner's `groups`. Those join records through
        any shared alias, and a Debian bulletin (DSA-6015-1) aliases every CVE it fixes - so
        DEBIAN-CVE-2025-9230 and DEBIAN-CVE-2025-9232 arrived as one group, two flaws counted
        as one and matching neither of Grype's per-CVE findings. Records are linked through a
        CVE only when it is the one CVE they are about, and bulletins link nothing.
      */
      const scoreOf = new Map<string, number>();
      for (const g of p.groups ?? []) {
        const n = g.max_severity ? Number.parseFloat(g.max_severity) : NaN;
        if (Number.isFinite(n)) for (const id of g.ids ?? []) scoreOf.set(id, n);
      }
      const cvesOf = (id: string): string[] => {
        const r = records.get(id);
        const own = /^(?:[A-Z]+-)?(CVE-\d{4}-\d+)$/i.exec(id)?.[1];
        return [
          ...new Set([own, ...strings(r?.aliases), ...strings(r?.upstream)].filter((x): x is string => !!x && /^CVE-\d{4}-\d+$/i.test(x))),
        ];
      };
      const linkKeys = (id: string): string[] => {
        const r = records.get(id);
        const ghsa = [id, ...strings(r?.aliases)].filter((x) => /^GHSA-/i.test(x));
        const cves = cvesOf(id);
        return [id, ...ghsa, ...(cves.length === 1 ? cves : [])];
      };

      const plain = [...records.keys()].filter((id) => !BUNDLE.test(id));
      const parent = new Map(plain.map((id) => [id, id]));
      const find = (id: string): string => {
        let root = id;
        while (parent.get(root) !== root) root = parent.get(root)!;
        parent.set(id, root);
        return root;
      };
      const owner = new Map<string, string>();
      for (const id of plain) {
        for (const key of linkKeys(id)) {
          const seen = owner.get(key);
          if (seen === undefined) owner.set(key, id);
          else parent.set(find(id), find(seen));
        }
      }
      const groups = new Map<string, string[]>();
      for (const id of plain) groups.set(find(id), [...(groups.get(find(id)) ?? []), id]);

      // A bulletin is kept only when it covers a CVE no plain record does.
      const coveredCves = new Set(plain.flatMap(cvesOf));
      for (const id of [...records.keys()].filter((x) => BUNDLE.test(x))) {
        const cves = cvesOf(id);
        if (cves.length > 0 && cves.every((c) => coveredCves.has(c))) continue;
        groups.set(id, [id]);
      }

      for (const ids of groups.values()) {
        const members = ids.map((id) => records.get(id)!);
        const primaryId = [...ids].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))[0]!;
        const primary = records.get(primaryId)!;
        const aliases = [
          ...new Set([...ids, ...ids.flatMap(cvesOf), ...members.flatMap((r) => strings(r.aliases).filter((a) => !BUNDLE.test(a)))]),
        ].filter((a) => a !== primaryId);

        const scores = ids.map((id) => scoreOf.get(id)).filter((n): n is number => n !== undefined && n > 0);
        const score = scores.length > 0 ? Math.max(...scores) : null;
        const severity =
          members.map((r) => textSeverity(r.database_specific?.severity)).find((s) => s !== null) ?? scoreSeverity(score);

        const describing = [primary, ...members.filter((r) => r !== primary)];
        const summary = describing.map((r) => str(r.summary, 1024)).find((s) => s !== null) ?? null;
        const details = describing.map((r) => str(r.details, 16_000)).sort((a, b) => (b?.length ?? 0) - (a?.length ?? 0))[0] ?? null;
        const cwes = [
          ...new Set(members.flatMap((r) => strings(r.database_specific?.cwe_ids).map((c) => c.toUpperCase()))),
        ].filter((c) => /^CWE-\d+$/.test(c));
        const urls = [
          ...new Set(
            members.flatMap((r) =>
              Array.isArray(r.references) ? (r.references as Array<{ url?: string }>).map((ref) => str(ref.url, 2048)) : [],
            ),
          ),
        ].filter((u): u is string => u !== null).slice(0, 24);

        const fix = osvFix(members, { ecosystem: p.package?.ecosystem ?? "", name: p.package?.name ?? "" }, p.package?.version ?? null);

        for (const componentId of componentIds) {
          findings.push({
            componentId,
            vulnerabilityId: primaryId,
            severity,
            aliases,
            cvssBaseScore: score,
            cvssVector: cvssVector(describing),
            epssScore: null,
            epssPercentile: null,
            knownExploited: false,
            description: details && summary && details !== summary ? details : (details ?? summary),
            summary: details && summary && details !== summary ? summary : null,
            cwes,
            dataSource: `https://osv.dev/vulnerability/${primaryId}`,
            namespace: p.package?.ecosystem ?? null,
            urls,
            fixState: fix.fixState,
            fixVersions: fix.fixVersions,
            matchType: null,
            source: "osv",
            affectedRange: fix.affectedRange,
          });
        }
      }
    }
  }

  return { findings, unmappedFindings };
}
