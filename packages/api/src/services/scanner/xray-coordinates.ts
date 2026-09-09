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
  npm: "npm",
  maven: "gav",
  /*
    JFrog's documentation uses `pypi://`. The manual testing that preceded this feature used
    `pip://` and did not verify a Python result either way -- only Maven and npm canaries were
    confirmed. `pypi` is the documented form, so it is the one used; if the probe reports pypi
    as uncovered on a deployment where Python packages exist, this line is the thing to change.
  */
  pypi: "pypi",
  golang: "go",
  nuget: "nuget",
  gem: "gem",
  composer: "composer",
  cargo: "cargo",
  // Operating-system packages. Whether a given Xray covers these is what the probe settles.
  deb: "deb",
  rpm: "rpm",
  apk: "alpine",
};

interface ParsedPurl {
  type: string;
  namespace: string | null;
  name: string;
  version: string | null;
}

/**
 * Enough of the purl spec to build a coordinate, and no more.
 *
 * Not a general parser: qualifiers and subpaths are discarded on purpose. Xray coordinates
 * carry no equivalent, and passing `?distro=debian-12` through would produce an identifier
 * that matches nothing while looking plausible in a log.
 */
export function parsePurl(purl: string): ParsedPurl | null {
  if (!purl.startsWith("pkg:")) return null;

  // Order matters: the subpath separator may legally appear after qualifiers.
  const withoutSubpath = purl.split("#")[0]!;
  const withoutQualifiers = withoutSubpath.split("?")[0]!;
  const body = withoutQualifiers.slice("pkg:".length);

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
  return { type, namespace, name, version: version === "" ? null : version };
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

  if (scheme === "deb") {
    /*
      Debian and Ubuntu packages are identified per distribution, because the same package
      name and version carry different fix states on different releases. The namespace of a
      Syft-produced purl is the distribution (`debian`, `ubuntu`); with none, the plain form
      is the best available and the probe will report whether it lands.
    */
    const name = parsed?.name ?? pkg.name;
    return parsed?.namespace ? `deb://${parsed.namespace}:${name}:${version}` : `deb://${name}:${version}`;
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
  { ecosystem: "pypi", coordinate: "pypi://django:2.2.0", label: "django 2.2.0" },
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
  { ecosystem: "deb", coordinate: "deb://debian:openssl:1.1.1n-0+deb10u3", label: "openssl 1.1.1n on Debian" },
  { ecosystem: "rpm", coordinate: "rpm://openssl:1.1.1k-4.el8", label: "openssl 1.1.1k on RHEL 8" },
  { ecosystem: "apk", coordinate: "alpine://openssl:1.1.1k-r0", label: "openssl 1.1.1k on Alpine" },
];
