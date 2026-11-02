import type { FixState, VulnSeverity } from "@sbom/shared";
import { toSeverity, type ParsedFinding, type ScannablePackage } from "./grype-output.js";
import { upgradeFixes } from "./versions.js";

/**
 * Building Trivy's input and reading its output.
 *
 * Pure, like the Grype parser, and for the same reason: every figure downstream depends on a
 * finding landing on the right component, so the mapping is tested against recorded output
 * rather than only observed through a database.
 *
 * Confirmed against Trivy 0.76.1 rather than assumed:
 *
 *   - `PkgIdentifier.BOMRef` echoes the `bom-ref` we set, so findings map back to component
 *     ids exactly, as Grype's do.
 *   - One SBOM may carry only one OS package type. Mixing apk and deb fails the whole scan
 *     ("multiple types of OS packages in SBOM are not supported"), so a batch is split into
 *     one document per distribution plus one for language packages.
 *   - OS packages are matched only under an `operating-system` component naming the
 *     distribution; without one Trivy reports nothing for them, silently.
 *   - Debian advisories are keyed by *source* package. A `libssl3` with no source name
 *     matched nothing; with `aquasecurity:trivy:SrcName=openssl` it matched fifty. Syft
 *     records the source in the purl's `upstream` qualifier, which is where it is read from.
 */

/**
 * Kernel header packages, which are left out of Trivy and OSV the way Grype leaves them out.
 *
 * Their source package is the kernel, so every kernel CVE matches them - but a container runs
 * on its host's kernel, and headers used to build against it are not that kernel. Grype
 * ignores these matches by default; Trivy does not, and on this estate that difference was
 * 1,601 of Trivy's 1,734 findings that Grype did not have: noise that would have buried the
 * 133 genuine ones.
 */
export function isKernelHeaders(pkg: Pick<ScannablePackage, "name">): boolean {
  return /^(linux-libc-dev|linux-headers(-.*)?|linux-api-headers|linux-kernel-headers|kernel-headers)$/i.test(pkg.name);
}

/** Purl types Trivy treats as operating-system packages. */
const OS_TYPES = new Set(["apk", "deb", "rpm"]);

/** Distribution names in purl `distro` qualifiers, as Trivy's OS families call them. */
const OS_FAMILY: Record<string, string> = {
  rhel: "redhat",
  "red hat": "redhat",
  ol: "oracle",
  amzn: "amazon",
  sles: "suse linux enterprise server",
  opensuse: "opensuse.leap",
  "opensuse-leap": "opensuse.leap",
  rocky: "rocky",
  almalinux: "alma",
  alma: "alma",
  wolfi: "wolfi",
  chainguard: "chainguard",
};

interface ParsedPurl {
  type: string;
  qualifiers: Record<string, string>;
}

function parsePurl(purl: string | null): ParsedPurl | null {
  if (!purl || !purl.startsWith("pkg:")) return null;
  const withoutScheme = purl.slice(4);
  const type = withoutScheme.split("/")[0]?.toLowerCase() ?? "";
  const qualifiers: Record<string, string> = {};
  const q = withoutScheme.indexOf("?");
  if (q >= 0) {
    const raw = withoutScheme.slice(q + 1).split("#")[0] ?? "";
    for (const pair of raw.split("&")) {
      const eq = pair.indexOf("=");
      if (eq <= 0) continue;
      try {
        qualifiers[pair.slice(0, eq).toLowerCase()] = decodeURIComponent(pair.slice(eq + 1));
      } catch {
        qualifiers[pair.slice(0, eq).toLowerCase()] = pair.slice(eq + 1);
      }
    }
  }
  return { type, qualifiers };
}

/**
 * `debian-12.11` -> `{ family: "debian", version: "12.11" }`.
 *
 * The version is everything after the last hyphen followed by a digit, so a family with a
 * hyphen in its name (`opensuse-leap-15.5`) keeps it.
 */
export function parseDistro(distro: string | undefined): { family: string; version: string } | null {
  if (!distro) return null;
  const m = /^(.*?)-(\d[^-]*)$/.exec(distro.trim());
  if (!m) return null;
  const family = m[1]!.toLowerCase();
  return { family: OS_FAMILY[family] ?? family, version: m[2]! };
}

/**
 * The source package behind an OS package, from Syft's `upstream` qualifier.
 *
 * Syft writes it as `openssl`, or `libgav1@0.18.0-1` when the source version differs, and
 * for RPMs as the source RPM file name (`openssl-3.0.7-24.el9.src.rpm`).
 */
export function sourcePackage(type: string, upstream: string | undefined, version: string | null): { name: string; version: string | null } | null {
  if (!upstream) return null;
  if (type === "rpm") {
    const m = /^(.+)-([^-]+)-([^-]+)\.src\.rpm$/.exec(upstream);
    if (m) return { name: m[1]!, version: `${m[2]}-${m[3]}` };
    return { name: upstream.replace(/\.src\.rpm$/, ""), version };
  }
  const at = upstream.lastIndexOf("@");
  if (at > 0) return { name: upstream.slice(0, at), version: upstream.slice(at + 1) };
  return { name: upstream, version };
}

export interface TrivyDocument {
  /** Short label for logs: `language`, or the distribution. */
  label: string;
  json: string;
  componentIds: number[];
}

/**
 * Split a batch into documents Trivy will accept: one for language packages, one per
 * distribution release. OS packages whose purl names no distribution cannot be matched by
 * Trivy at all and are left out rather than sent to fail.
 */
export function buildTrivyDocuments(packages: readonly ScannablePackage[]): TrivyDocument[] {
  const language: ScannablePackage[] = [];
  const byDistro = new Map<string, { family: string; version: string; packages: ScannablePackage[] }>();

  for (const pkg of packages) {
    const purl = parsePurl(pkg.purl);
    if (!purl) continue; // Trivy matches by purl; nothing to go on without one.
    if (isKernelHeaders(pkg)) continue;
    if (OS_TYPES.has(purl.type)) {
      const distro = parseDistro(purl.qualifiers.distro);
      if (!distro) continue;
      const key = `${purl.type}|${distro.family}|${distro.version}`;
      const group = byDistro.get(key) ?? { ...distro, packages: [] };
      group.packages.push(pkg);
      byDistro.set(key, group);
    } else {
      language.push(pkg);
    }
  }

  const component = (pkg: ScannablePackage) => {
    const purl = parsePurl(pkg.purl)!;
    const props: Array<{ name: string; value: string }> = [];
    if (OS_TYPES.has(purl.type)) {
      const src = sourcePackage(purl.type, purl.qualifiers.upstream, pkg.version);
      props.push({ name: "aquasecurity:trivy:SrcName", value: src?.name ?? pkg.name });
      const srcVersion = src?.version ?? pkg.version;
      if (srcVersion) props.push({ name: "aquasecurity:trivy:SrcVersion", value: srcVersion });
    }
    return {
      "bom-ref": String(pkg.componentId),
      type: "library",
      name: pkg.name,
      ...(pkg.version === null ? {} : { version: pkg.version }),
      purl: pkg.purl,
      ...(props.length > 0 ? { properties: props } : {}),
    };
  };

  const documents: TrivyDocument[] = [];
  const doc = (label: string, pkgs: ScannablePackage[], os: { family: string; version: string } | null) => {
    const components: unknown[] = pkgs.map(component);
    const dependencies: unknown[] = [];
    if (os) {
      components.unshift({ "bom-ref": "os", type: "operating-system", name: os.family, version: os.version });
      dependencies.push({ ref: "os", dependsOn: pkgs.map((p) => String(p.componentId)) });
    }
    documents.push({
      label,
      componentIds: pkgs.map((p) => p.componentId),
      json: JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        version: 1,
        metadata: { tools: { components: [{ type: "application", name: "sbom-platform" }] } },
        components,
        ...(dependencies.length > 0 ? { dependencies } : {}),
      }),
    });
  };

  if (language.length > 0) doc("language", language, null);
  for (const group of byDistro.values()) doc(`${group.family} ${group.version}`, group.packages, group);
  return documents;
}

/** Trivy's `Status`, onto the fix states the platform uses. */
export function trivyFixState(status: unknown, fixVersions: readonly string[]): FixState {
  switch (typeof status === "string" ? status.toLowerCase() : "") {
    case "fixed":
      // Fixed somewhere, but every named fix is older than what is installed: nothing to
      // upgrade to on this line.
      return fixVersions.length > 0 ? "fixed" : "not-fixed";
    case "will_not_fix":
    case "end_of_life":
      return "wont-fix";
    case "affected":
    case "fix_deferred":
    case "under_investigation":
      return "not-fixed";
    default:
      return fixVersions.length > 0 ? "fixed" : "unknown";
  }
}

interface TrivyVulnerability {
  VulnerabilityID?: unknown;
  VendorIDs?: unknown;
  PkgIdentifier?: { BOMRef?: unknown };
  InstalledVersion?: unknown;
  FixedVersion?: unknown;
  Status?: unknown;
  SeveritySource?: unknown;
  DataSource?: { ID?: unknown; Name?: unknown; URL?: unknown };
  Title?: unknown;
  Description?: unknown;
  Severity?: unknown;
  CweIDs?: unknown;
  CVSS?: unknown;
  References?: unknown;
}

function str(value: unknown, max = 4096): string | null {
  if (typeof value !== "string") return null;
  const t = value.trim();
  return t === "" ? null : t.slice(0, max);
}

function strings(value: unknown, max = 32): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((v) => str(v, 2048)).filter((v): v is string => v !== null))].slice(0, max);
}

/** The CVSS entry from the source Trivy took its severity from, else NVD's, else any. */
function trivyCvss(cvss: unknown, preferred: string | null): { score: number | null; vector: string | null } {
  if (typeof cvss !== "object" || cvss === null) return { score: null, vector: null };
  const entries = cvss as Record<string, { V3Score?: unknown; V3Vector?: unknown; V40Score?: unknown; V40Vector?: unknown; V2Score?: unknown; V2Vector?: unknown }>;
  const order = [preferred, "nvd", ...Object.keys(entries)].filter((k): k is string => !!k && k in entries);
  for (const key of order) {
    const e = entries[key]!;
    const pick = (score: unknown, vector: unknown) =>
      typeof score === "number" && Number.isFinite(score) ? { score, vector: str(vector, 256) } : null;
    const found = pick(e.V40Score, e.V40Vector) ?? pick(e.V3Score, e.V3Vector) ?? pick(e.V2Score, e.V2Vector);
    if (found) return found;
  }
  return { score: null, vector: null };
}

/**
 * Parse one Trivy JSON report into findings.
 *
 * `submitted` is the set of component ids in the document: a BOMRef outside it is counted as
 * unmapped rather than attributed to whatever id it happens to parse as.
 */
export function parseTrivyReport(
  raw: string,
  submitted: ReadonlySet<number>,
): { findings: ParsedFinding[]; unmappedFindings: number; trivyVersion: string | null } {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    throw new Error(`trivy did not return valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (typeof doc !== "object" || doc === null) throw new Error("trivy report must be a JSON object");
  const root = doc as { Results?: unknown; Trivy?: { Version?: unknown } };

  const findings: ParsedFinding[] = [];
  const seen = new Set<string>();
  let unmappedFindings = 0;

  for (const result of Array.isArray(root.Results) ? root.Results : []) {
    const vulns = (result as { Vulnerabilities?: unknown }).Vulnerabilities;
    if (!Array.isArray(vulns)) continue;
    for (const entry of vulns) {
      if (typeof entry !== "object" || entry === null) continue;
      const v = entry as TrivyVulnerability;
      const id = str(v.VulnerabilityID, 128);
      if (!id) continue;

      const ref = str(v.PkgIdentifier?.BOMRef, 32);
      const componentId = ref && /^\d+$/.test(ref) ? Number.parseInt(ref, 10) : NaN;
      if (!Number.isSafeInteger(componentId) || !submitted.has(componentId)) {
        unmappedFindings++;
        continue;
      }
      const key = `${componentId}\u0000${id}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const installed = str(v.InstalledVersion, 256);
      const fixVersions = upgradeFixes(
        (str(v.FixedVersion, 2048) ?? "").split(",").map((s) => s.trim()),
        installed,
      ).slice(0, 16);
      const cvss = trivyCvss(v.CVSS, str(v.SeveritySource, 64));
      const title = str(v.Title, 1024);
      const description = str(v.Description, 16_000);

      findings.push({
        componentId,
        vulnerabilityId: id,
        severity: toSeverity(v.Severity) as VulnSeverity,
        aliases: strings(v.VendorIDs).filter((alias) => alias !== id),
        cvssBaseScore: cvss.score,
        cvssVector: cvss.vector,
        epssScore: null,
        epssPercentile: null,
        knownExploited: false,
        description,
        summary: title && title !== description ? title : null,
        cwes: strings(v.CweIDs).map((c) => c.toUpperCase()).filter((c) => /^CWE-\d+$/.test(c)),
        dataSource: str(v.DataSource?.URL, 512) ?? str(v.DataSource?.Name, 512),
        namespace: str(v.DataSource?.ID, 128),
        urls: strings(v.References, 24),
        fixState: trivyFixState(v.Status, fixVersions),
        fixVersions,
        matchType: null,
        source: "trivy",
        affectedRange: null,
      });
    }
  }

  return { findings, unmappedFindings, trivyVersion: str(root.Trivy?.Version, 64) };
}
