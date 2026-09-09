import type { ScannablePackage } from "./grype-output.js";

/**
 * Translating this platform's packages into the component identifiers Xray understands.
 *
 * Grype is handed a CycloneDX document and matches purls directly. Xray's graph scan takes a
 * flat list of its own coordinate strings — `npm://lodash:4.17.15`, `gav://group:artifact:v`
 * — so every package has to be rewritten, and a package that cannot be rewritten cannot be
 * assessed at all.
 *
 * ## The rule that matters: unmapped is not clean
 *
 * A package this module returns `null` for is never submitted, and must never be recorded as
 * having been assessed. That distinction is the whole reason this file is separate and
 * tested: silently dropping a package produces a scan that reports no findings for it, which
 * is indistinguishable from a package that was checked and found safe.
 *
 * On a typical container image the packages at risk of being dropped are the operating-system
 * ones, and they are roughly two thirds of the component list — the exact figure from the
 * Xray-generated SBOM this was designed against was 413 deb packages out of 613 components.
 *
 * ## The schemes are a best-known mapping, not a guarantee
 *
 * JFrog documents the coordinate forms, but which ones a *particular* Xray deployment
 * actually holds data for depends on its version, its licence tier and which feeds it
 * synchronises. Rather than assume, the scanner probes each ecosystem with a known-vulnerable
 * canary (see `XRAY_CANARIES`) and reports the ones that come back empty as uncovered. So a
 * mistake in this table degrades to "not assessed" rather than to a false all-clear.
 */

/**
 * Canonical ecosystem (purl type, as this platform stores it) -> Xray scheme.
 *
 * Only ecosystems with a known coordinate form appear. Everything else is deliberately
 * absent rather than guessed, because a wrong scheme and an unsupported one look identical
 * from here — both return nothing — and only one of them is worth fixing in this table.
 */
const SCHEMES: Record<string, string> = {
  /*
    Confirmed against JFrog's published component-identifier examples: gav, npm, pip, nuget,
    go, composer, deb and rpm. The three below them are inferred from the same pattern and
    have never been seen to work -- they are safe to include only because every ecosystem
    here is probed with a canary before its results are trusted. An inferred scheme that is
    wrong reports as uncovered; it cannot report as clean.
  */
  npm: "npm",
  maven: "gav",
  /*
    `pip`, not `pypi`. This was written the other way round from memory and corrected against
    JFrog's published examples, which give `pip://raven:5.13.0` -- matching the form the
    manual investigation used before this feature existed.
  */
  pypi: "pip",
  golang: "go",
  nuget: "nuget",
  composer: "composer",
  // Inferred, not documented. Proven or disproven by the canary probe, never assumed.
  gem: "gem",
  cargo: "cargo",
  // Operating-system packages. Whether a given Xray covers these is what the probe settles.
  deb: "deb",
  rpm: "rpm",
  // Also inferred. Alpine images therefore get OS coverage only if the probe confirms it.
  apk: "alpine",
};

interface ParsedPurl {
  type: string;
  namespace: string | null;
  name: string;
  version: string | null;
  /**
   * Qualifiers, lowercased by key.
   *
   * Kept only because Xray identifies operating-system packages by architecture --
   * `deb://<arch>:<name>:<version>`. Everything else here ignores them.
   */
  qualifiers: Record<string, string>;
}

/**
 * Enough of the purl spec to build a coordinate, and no more.
 *
 * Subpaths are discarded; qualifiers are kept but only `arch` is ever read. Xray's deb and
 * rpm identifiers carry the architecture as a segment of their own, which is the one piece
 * of purl metadata that changes what gets submitted rather than merely describing it.
 */
export function parsePurl(purl: string): ParsedPurl | null {
  if (!purl.startsWith("pkg:")) return null;

  // Order matters: the subpath separator may legally appear after qualifiers.
  const withoutSubpath = purl.split("#")[0]!;
  const [beforeQualifiers, rawQualifiers] = withoutSubpath.split("?");
  const body = beforeQualifiers!.slice("pkg:".length);

  const qualifiers: Record<string, string> = {};
  for (const pair of (rawQualifiers ?? "").split("&")) {
    if (pair === "") continue;
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    qualifiers[decodeURIComponent(pair.slice(0, eq)).toLowerCase()] = decodeURIComponent(
      pair.slice(eq + 1),
    );
  }

  const at = body.lastIndexOf("@");
  // A bare `@` at position 0 would be a scoped npm name with no type, which is not a purl.
  const version = at > 0 ? decodeURIComponent(body.slice(at + 1)) : null;
  const path = at > 0 ? body.slice(0, at) : body;

  const segments = path.split("/").filter((s) => s !== "");
  if (segments.length < 2) return null;

  const type = decodeURIComponent(segments[0]!).toLowerCase();
  const name = decodeURIComponent(segments[segments.length - 1]!);
  const namespace =
    segments.length > 2
      ? segments.slice(1, -1).map(decodeURIComponent).join("/")
      : null;

  if (name === "") return null;
  return { type, namespace, name, version: version === "" ? null : version, qualifiers };
}

/**
 * The Xray component identifier for one package, or null when it cannot be expressed.
 *
 * Null has one meaning and it is load-bearing: this package will not be submitted, and the
 * caller must record it as unassessed rather than as assessed-and-clean.
 */
export function toXrayCoordinate(pkg: ScannablePackage): string | null {
  // A version is required. Xray matches a coordinate against version ranges, and one with no
  // version silently matches nothing rather than matching every version.
  if (!pkg.version || pkg.version.trim() === "") return null;

  const parsed = pkg.purl ? parsePurl(pkg.purl) : null;
  const ecosystem = (parsed?.type ?? pkg.ecosystem ?? "").toLowerCase();
  const scheme = SCHEMES[ecosystem];
  if (!scheme) return null;

  const version = pkg.version.trim();

  if (scheme === "gav") {
    /*
      Maven is the one coordinate that is not `name:version`: Xray wants group and artifact
      as separate segments. Without a purl there is no reliable way to split a stored name
      into the two, and guessing on the last dot turns `org.apache.commons.io` into a wrong
      group and a wrong artifact -- which matches nothing, silently.
    */
    if (!parsed?.namespace) return null;
    return `gav://${parsed.namespace}:${parsed.name}:${version}`;
  }

  if (scheme === "go") {
    // The full module path, which purl splits across namespace and name.
    const module = parsed?.namespace ? `${parsed.namespace}/${parsed.name}` : (parsed?.name ?? pkg.name);
    return `go://${module}:${version}`;
  }

  if (scheme === "deb" || scheme === "rpm") {
    /*
      `deb://[dist:]<arch>:<name>:<version>`, per JFrog's published examples
      (`deb://lucid:i386:acl:2.2.49-2`, `rpm://el6:i386:ImageMagick:6.7.2.7-4`). Two things
      about that shape are easy to get wrong, and both were wrong here first:

      The architecture is a segment, not a qualifier. It comes from the purl's `arch`, which
      is why this module keeps qualifiers at all. Without one the identifier cannot be built
      correctly, so the package is not submitted — an OS package assessed against the wrong
      architecture is worse than one honestly marked unassessed.

      The distribution is deliberately omitted even though Syft supplies something for it.
      JFrog's examples use release codenames (`lucid`, `el6`); Syft's `distro` qualifier is
      `debian-10`. Those are not the same vocabulary, and a wrong dist segment matches
      nothing while looking entirely reasonable. Dist is optional in the format, so leaving
      it out is the one choice that cannot be wrong.
    */
    const arch = parsed?.qualifiers.arch?.trim();
    if (!arch) return null;
    return `${scheme}://${arch}:${parsed?.name ?? pkg.name}:${version}`;
  }

  if (scheme === "npm") {
    // Scoped packages keep their `@scope/name` form; purl percent-encodes the `@`.
    const name = parsed?.namespace ? `${parsed.namespace}/${parsed.name}` : (parsed?.name ?? pkg.name);
    return `npm://${name}:${version}`;
  }

  const name = parsed?.name ?? pkg.name;
  return `${scheme}://${name}:${version}`;
}

/** The ecosystems this module can express at all. Anything else is never assessed by Xray. */
export function mappableEcosystems(): string[] {
  return Object.keys(SCHEMES).sort();
}

/**
 * Known-vulnerable packages, one per ecosystem, used to ask a specific Xray deployment what
 * it actually covers.
 *
 * This is the manual database-health check from the original investigation — Log4Shell and a
 * vulnerable lodash — generalised into something the platform performs for itself. Each entry
 * is a package with long-standing, widely published advisories, chosen so that "no findings"
 * is far more likely to mean "this ecosystem is not covered" than "this version is fine".
 *
 * It is a heuristic and is presented as one: the admin screen names the canary it used, so an
 * administrator who disagrees can see exactly what was asked.
 */
export const XRAY_CANARIES: ReadonlyArray<{
  ecosystem: string;
  coordinate: string;
  /** What it is, for the admin screen. */
  label: string;
}> = [
  { ecosystem: "maven", coordinate: "gav://org.apache.logging.log4j:log4j-core:2.14.1", label: "log4j-core 2.14.1 (Log4Shell)" },
  { ecosystem: "npm", coordinate: "npm://lodash:4.17.15", label: "lodash 4.17.15" },
  { ecosystem: "pypi", coordinate: "pip://django:2.2.0", label: "django 2.2.0" },
  { ecosystem: "golang", coordinate: "go://golang.org/x/text:v0.3.0", label: "golang.org/x/text v0.3.0" },
  { ecosystem: "nuget", coordinate: "nuget://Newtonsoft.Json:12.0.2", label: "Newtonsoft.Json 12.0.2" },
  { ecosystem: "gem", coordinate: "gem://rack:2.0.7", label: "rack 2.0.7" },
  { ecosystem: "composer", coordinate: "composer://guzzlehttp/guzzle:6.5.0", label: "guzzlehttp/guzzle 6.5.0" },
  { ecosystem: "cargo", coordinate: "cargo://time:0.1.44", label: "time 0.1.44" },
  /*
    The operating-system canaries, and the reason this probe exists at all. OpenSSL on an
    end-of-life Debian release carries dozens of published advisories; an Xray that returns
    nothing for it is not telling us the package is safe.
  */
  { ecosystem: "deb", coordinate: "deb://amd64:openssl:1.1.1n-0+deb10u3", label: "openssl 1.1.1n (amd64)" },
  { ecosystem: "rpm", coordinate: "rpm://x86_64:openssl:1.1.1k-4.el8", label: "openssl 1.1.1k (x86_64)" },
  { ecosystem: "apk", coordinate: "alpine://openssl:1.1.1k-r0", label: "openssl 1.1.1k on Alpine" },
];
