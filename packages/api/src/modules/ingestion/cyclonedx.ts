import {
  COMPONENT_LOCATION_PATH_CAP,
  ecosystemHasMeaningfulPaths,
  normalizeLocationPath,
} from "@sbom/shared";
import { sha256Hex } from "../../lib/crypto.js";
import { UnprocessableError } from "../../lib/errors.js";
import {
  detectPlatform,
  isKnownRuntime,
  type PlatformCandidate,
  type ScanPlatformData,
} from "./platform.js";
import { normalizePurl, purlType } from "./purl.js";

/**
 * CycloneDX JSON parser, targeting Syft's `-o cyclonedx-json` output.
 *
 * Design constraints that shaped this:
 *
 *  1. NEVER DROP A SCAN. CI calls this with `curl -f`. A malformed *component*
 *     must not fail the whole upload — it is recorded as skipped and the rest is
 *     ingested. Only a document that isn't a CycloneDX SBOM at all is rejected.
 *
 *  2. Hand-rolled iteration, not a Zod schema over `components[]`. A single
 *     container SBOM can carry 50k+ components; per-object schema validation
 *     there costs seconds of CPU per upload for no benefit, since every field we
 *     read is individually checked anyway.
 *
 *  3. Dedupe within the document. `scan_component` is keyed on
 *     (scan_id, component_id), so the same package appearing twice in one SBOM
 *     would abort the insert. Syft does emit duplicates — the same library found
 *     in two image layers, or via two catalogers.
 */

export interface ParsedComponent {
  /** Dedupe key across the whole platform. */
  identityHash: string;
  name: string;
  version: string | null;
  ecosystem: string;
  /** Normalised purl (qualifiers sorted), or null when the SBOM had none. */
  purl: string | null;
  cpe: string | null;
  /**
   * `library` for an ordinary dependency, `os` for the base distribution,
   * `runtime` for an interpreter or app server. Keeps the base image out of
   * aggregates about dependencies without dropping it from the inventory.
   */
  kind: "library" | "os" | "runtime";
  /**
   * Where the package was found, capped at `COMPONENT_LOCATION_PATH_CAP` and sorted.
   *
   * Null for OS-package ecosystems, whose recorded paths locate the package manager's
   * database rather than the package — see `ecosystemHasMeaningfulPaths`. Also null when the
   * SBOM carried no location properties at all, which a non-Syft tool may well not emit.
   */
  paths: string[] | null;
  /** True total before capping, so a truncated list can say "3 of 81". */
  pathCount: number | null;
  /** Image layer digest of the first recorded location. Null outside image scans. */
  layerId: string | null;
}

export type SkipReason = "missing_name" | "not_an_object" | "excluded_type";

export interface SkippedComponent {
  index: number;
  reason: SkipReason;
  name?: string;
}

export interface ParsedSbom {
  specVersion: string | null;
  serialNumber: string | null;
  toolName: string | null;
  toolVersion: string | null;
  /** The image or artifact the SBOM describes, from `metadata.component`. */
  subjectName: string | null;
  subjectVersion: string | null;
  components: ParsedComponent[];
  skipped: SkippedComponent[];
  /** Components that were valid but collapsed into an earlier identical entry. */
  duplicatesCollapsed: number;
  /**
   * OS distribution and language runtimes observed in the image. Every field can
   * be null: a scratch or distroless image genuinely has neither.
   */
  platform: ScanPlatformData;
}

/**
 * CycloneDX component types we do not store.
 *
 * `file` entries appear only when file cataloguing is enabled and would add
 * thousands of rows per scan that are not dependencies in any useful sense.
 * Everything else (library, application, operating-system, framework,
 * container, ...) is kept: the OS entry in particular is how you answer "which
 * base image is this app on".
 */
const EXCLUDED_COMPONENT_TYPES = new Set(["file"]);

/**
 * Syft's `syft:package:type` property values -> canonical purl-style ecosystem.
 *
 * Only consulted when the component has no purl to derive the type from, which
 * is rare but does happen for packages Syft cannot construct a purl for.
 */
const SYFT_TYPE_TO_ECOSYSTEM: Record<string, string> = {
  "alpm": "alpm",
  "apk": "apk",
  "binary": "generic",
  "cocoapods": "cocoapods",
  "conan": "conan",
  "dart-pub": "pub",
  "deb": "deb",
  "dotnet": "nuget",
  "elixir-hex": "hex",
  "erlang-otp": "hex",
  "gem": "gem",
  "github-action": "generic",
  "go-module": "golang",
  "graalvm-native-image": "generic",
  "haskell": "hackage",
  "java-archive": "maven",
  "jenkins-plugin": "maven",
  "linux-kernel": "generic",
  "linux-kernel-module": "generic",
  "lua-rocks": "luarocks",
  "msrc-kb": "generic",
  "nix": "nix",
  "npm": "npm",
  "nuget": "nuget",
  "php-composer": "composer",
  "php-pecl": "generic",
  "portage": "portage",
  "python": "pypi",
  "rpm": "rpm",
  "rust-crate": "cargo",
  "swift": "swift",
  "swiplpack": "generic",
  "wordpress-plugin": "generic",
};

interface RawComponent {
  name?: unknown;
  version?: unknown;
  type?: unknown;
  purl?: unknown;
  cpe?: unknown;
  properties?: unknown;
}

function asNonEmptyString(value: unknown, maxLength = 2048): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed === "") return null;
  return trimmed.length > maxLength ? trimmed.slice(0, maxLength) : trimmed;
}

/** Reads a `syft:package:type`-style entry out of a component's properties array. */
function readProperty(properties: unknown, key: string): string | null {
  if (!Array.isArray(properties)) return null;
  for (const prop of properties) {
    if (typeof prop !== "object" || prop === null) continue;
    const p = prop as { name?: unknown; value?: unknown };
    if (p.name === key) return asNonEmptyString(p.value, 256);
  }
  return null;
}

/**
 * Reads every `syft:location:N:path` / `syft:location:N:layerID` pair out of a component.
 *
 * Indices are not assumed contiguous or ordered — the properties array is walked once and
 * grouped by the index in the key, because nothing in the CycloneDX spec promises the encoder
 * emits them in order and a missed location is a package the reader cannot find.
 *
 * Returns raw values; capping, sorting and the OS-ecosystem exclusion are the caller's job,
 * because they have to happen *after* duplicate components have been merged together.
 */
function readLocations(properties: unknown): { paths: string[]; layerId: string | null } {
  if (!Array.isArray(properties)) return { paths: [], layerId: null };

  const paths: string[] = [];
  let layerId: string | null = null;

  for (const prop of properties) {
    if (typeof prop !== "object" || prop === null) continue;
    const p = prop as { name?: unknown; value?: unknown };
    if (typeof p.name !== "string") continue;

    const pathMatch = /^syft:location:(\d+):path$/.exec(p.name);
    if (pathMatch) {
      const value = asNonEmptyString(p.value, 1024);
      if (value !== null) {
        const normalized = normalizeLocationPath(value);
        if (normalized !== null) paths.push(normalized);
      }
      continue;
    }

    // The first layer digest is enough: it is kept as corroborating evidence for the origin
    // label, not as a per-location index, and a package spread over several layers is far
    // rarer than one spread over several paths in the same layer.
    if (layerId === null && /^syft:location:\d+:layerID$/.test(p.name)) {
      layerId = asNonEmptyString(p.value, 256);
    }
  }

  return { paths, layerId };
}

/**
 * Determines the ecosystem, preferring the purl because it is the
 * spec-standard, tool-independent source. Syft properties are a fallback, and
 * `unknown` is stored rather than dropping the component — an unrecognised
 * ecosystem is still a dependency someone may need to search for.
 */
function resolveEcosystem(purl: string | null, properties: unknown): string {
  if (purl) {
    const fromPurl = purlType(purl);
    if (fromPurl) return fromPurl;
  }
  const syftType = readProperty(properties, "syft:package:type");
  if (syftType) {
    return SYFT_TYPE_TO_ECOSYSTEM[syftType.toLowerCase()] ?? syftType.toLowerCase();
  }
  return "unknown";
}

/**
 * Unambiguous encoding of a field list, as `len:value|len:value`.
 *
 * A plain delimiter is not safe here. Joined by a space, ecosystem `npm` /
 * name `a b` / version `1` and ecosystem `npm` / name `a` / version `b 1`
 * produce the same string, which would collapse two unrelated packages into one
 * component row. Length prefixes are unambiguous for any input, and these
 * strings come from third-party SBOMs, so they are not values we control.
 */
function lengthPrefixed(parts: readonly string[]): string {
  return parts.map((p) => String(p.length) + ":" + p).join("|");
}

/**
 * Stable identity for a package across the whole platform.
 *
 * Prefers the normalised purl: for OS packages, two entries can share name and
 * version yet differ by architecture or epoch, and those are genuinely different
 * artifacts. Falls back to the ecosystem/name/version triple when there is no
 * purl.
 *
 * The `purl:` / `nvt:` scheme prefix keeps the two derivations from colliding
 * with each other.
 */
export function computeIdentityHash(input: {
  purl: string | null;
  ecosystem: string;
  name: string;
  version: string | null;
}): string {
  if (input.purl) return sha256Hex("purl:" + lengthPrefixed([input.purl]));
  return sha256Hex("nvt:" + lengthPrefixed([input.ecosystem, input.name, input.version ?? ""]));
}

/**
 * Classifies a component as the base OS, a language runtime, or an ordinary
 * library.
 *
 * Uses the same signals as platform detection and the same closed runtime list,
 * so a component labelled `runtime` here is exactly one that appears in the
 * scan's platform summary. Deriving them separately would let the two disagree —
 * a package could be excluded from the dependency aggregates while never
 * appearing as a runtime either, which is the one outcome that loses data.
 */
function classifyComponent(
  cdxType: string | null,
  name: string,
  syftType: string | null,
  purl: string | null,
): "library" | "os" | "runtime" {
  if (cdxType === "operating-system") return "os";
  const isBinary = syftType === "binary" || (purl?.startsWith("pkg:generic/") ?? false);
  if (isBinary && isKnownRuntime(name)) return "runtime";
  return "library";
}

/** Handles both the CycloneDX 1.4 (`tools: []`) and 1.5+ (`tools.components: []`) shapes. */
function readTool(metadata: unknown): { name: string | null; version: string | null } {
  if (typeof metadata !== "object" || metadata === null) return { name: null, version: null };
  const tools = (metadata as { tools?: unknown }).tools;

  // 1.4 and earlier: a bare array of tool objects.
  if (Array.isArray(tools)) {
    const first = tools[0];
    if (typeof first === "object" && first !== null) {
      const t = first as { name?: unknown; version?: unknown };
      return { name: asNonEmptyString(t.name, 128), version: asNonEmptyString(t.version, 128) };
    }
    return { name: null, version: null };
  }

  // 1.5+: tools is an object with `components` (and/or `services`).
  if (typeof tools === "object" && tools !== null) {
    const components = (tools as { components?: unknown }).components;
    if (Array.isArray(components)) {
      const first = components[0];
      if (typeof first === "object" && first !== null) {
        const t = first as { name?: unknown; version?: unknown };
        return { name: asNonEmptyString(t.name, 128), version: asNonEmptyString(t.version, 128) };
      }
    }
  }

  return { name: null, version: null };
}

function readSubject(metadata: unknown): { name: string | null; version: string | null } {
  if (typeof metadata !== "object" || metadata === null) return { name: null, version: null };
  const component = (metadata as { component?: unknown }).component;
  if (typeof component !== "object" || component === null) return { name: null, version: null };
  const c = component as { name?: unknown; version?: unknown };
  return { name: asNonEmptyString(c.name, 1024), version: asNonEmptyString(c.version, 512) };
}

/** Reads the first CPE, tolerating both the `cpe` string and a `cpes` array. */
function readCpe(raw: RawComponent): string | null {
  const direct = asNonEmptyString(raw.cpe, 512);
  if (direct) return direct;
  const cpes = (raw as { cpes?: unknown }).cpes;
  if (Array.isArray(cpes)) {
    for (const entry of cpes) {
      const value = asNonEmptyString(entry, 512);
      if (value) return value;
    }
  }
  return null;
}

/**
 * Decodes the uploaded bytes to a JSON string, honouring a byte order mark.
 *
 * `JSON.parse` throws on a leading BOM, but RFC 8259 §8.1 explicitly permits a
 * parser to ignore one. Syft does not emit a BOM, but anything that
 * post-processes an SBOM on Windows easily can — PowerShell's `Set-Content
 * -Encoding utf8` adds one — and rejecting a scan over an invisible three-byte
 * prefix contradicts the whole point of never dropping a build's data.
 *
 * UTF-16 is handled too: a UTF-16 encoded SBOM would otherwise produce a
 * baffling "Unexpected token" error naming a character the author cannot see.
 */
function decodeSbomText(raw: Buffer | string): string {
  if (typeof raw === "string") {
    // A string may still carry U+FEFF if it was decoded elsewhere.
    return raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  }

  // UTF-8 BOM: EF BB BF
  if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
    return raw.subarray(3).toString("utf8");
  }
  // UTF-16 LE BOM: FF FE
  if (raw.length >= 2 && raw[0] === 0xff && raw[1] === 0xfe) {
    return raw.subarray(2).toString("utf16le");
  }
  // UTF-16 BE BOM: FE FF. Node has no utf16be decoder, so swap to LE first.
  if (raw.length >= 2 && raw[0] === 0xfe && raw[1] === 0xff) {
    const swapped = Buffer.from(raw.subarray(2));
    swapped.swap16();
    return swapped.toString("utf16le");
  }

  return raw.toString("utf8");
}

/**
 * Parse a CycloneDX JSON document.
 *
 * @throws {UnprocessableError} only when the payload is not a CycloneDX SBOM —
 *   invalid JSON, or a JSON document without the CycloneDX markers. This is the
 *   one case where CI should see a 4xx, because retrying will not help.
 */
export function parseCycloneDx(raw: Buffer | string): ParsedSbom {
  let doc: unknown;
  try {
    doc = JSON.parse(decodeSbomText(raw));
  } catch (err) {
    throw new UnprocessableError(
      "SBOM is not valid JSON. Check that the CI step uploads the file produced by `syft -o cyclonedx-json`.",
      { parseError: err instanceof Error ? err.message : String(err) },
    );
  }

  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new UnprocessableError("SBOM must be a JSON object.");
  }

  const root = doc as {
    bomFormat?: unknown;
    specVersion?: unknown;
    serialNumber?: unknown;
    metadata?: unknown;
    components?: unknown;
  };

  const bomFormat = asNonEmptyString(root.bomFormat, 64);
  const specVersion = asNonEmptyString(root.specVersion, 32);

  // Accept a document that identifies as CycloneDX by either marker. Some
  // toolchains post-process SBOMs and drop `bomFormat` while keeping
  // `specVersion`; rejecting those would lose real data for a cosmetic reason.
  if (bomFormat === null && specVersion === null) {
    throw new UnprocessableError(
      "SBOM does not look like CycloneDX: both `bomFormat` and `specVersion` are missing. " +
        "Only CycloneDX JSON is supported — generate it with `syft <image> -o cyclonedx-json`.",
    );
  }
  if (bomFormat !== null && bomFormat.toLowerCase() !== "cyclonedx") {
    throw new UnprocessableError(
      `Unsupported SBOM format "${bomFormat}". Only CycloneDX JSON is supported in this phase.`,
    );
  }

  const tool = readTool(root.metadata);
  const subject = readSubject(root.metadata);

  const components: ParsedComponent[] = [];
  const skipped: SkippedComponent[] = [];
  /**
   * Identity hash -> index into `components`.
   *
   * An index rather than a bare presence set, because a duplicate entry has to be *merged*
   * into the one already kept rather than discarded. Syft emits the same package twice when it
   * finds it in two image layers or via two catalogers, and those duplicates are precisely the
   * entries carrying a location the first one did not have. Dropping them outright — which is
   * what this did before locations were recorded — would silently throw away most of the
   * multi-location data on exactly the packages installed in more than one place.
   */
  const indexByHash = new Map<string, number>();
  /** Locations accumulated per kept component, parallel to `components`. */
  const locationsByIndex: Array<{ paths: string[]; layerId: string | null }> = [];
  let duplicatesCollapsed = 0;
  // Collected during the same walk and reduced once at the end, rather than a
  // second pass over the document.
  const platformCandidates: PlatformCandidate[] = [];

  // An SBOM with no components is legitimate — a scratch or distroless image may
  // genuinely contain no catalogued packages. It is stored as an empty scan, not
  // rejected, so the history still records that the build was scanned.
  const rawComponents = Array.isArray(root.components) ? root.components : [];

  for (let i = 0; i < rawComponents.length; i++) {
    const entry = rawComponents[i];

    if (typeof entry !== "object" || entry === null) {
      skipped.push({ index: i, reason: "not_an_object" });
      continue;
    }

    const rawComponent = entry as RawComponent;

    const cdxType = asNonEmptyString(rawComponent.type, 64)?.toLowerCase();
    if (cdxType && EXCLUDED_COMPONENT_TYPES.has(cdxType)) {
      skipped.push({ index: i, reason: "excluded_type" });
      continue;
    }

    const name = asNonEmptyString(rawComponent.name, 512);
    if (!name) {
      skipped.push({ index: i, reason: "missing_name" });
      continue;
    }

    const rawPurl = asNonEmptyString(rawComponent.purl, 2048);
    const purl = rawPurl ? normalizePurl(rawPurl) : null;
    const ecosystem = resolveEcosystem(purl, rawComponent.properties);
    // Version is genuinely optional in CycloneDX; a package with no resolvable
    // version is still worth recording.
    const version = asNonEmptyString(rawComponent.version, 512);
    const cpe = readCpe(rawComponent);

    const syftType = readProperty(rawComponent.properties, "syft:package:type");

    platformCandidates.push({
      name,
      version,
      cdxType: cdxType ?? null,
      purl,
      syftType,
      distroId: readProperty(rawComponent.properties, "syft:distro:id"),
      distroVersionId: readProperty(rawComponent.properties, "syft:distro:versionID"),
      distroPrettyName: readProperty(rawComponent.properties, "syft:distro:prettyName"),
    });

    const kind = classifyComponent(cdxType ?? null, name, syftType, purl);

    const identityHash = computeIdentityHash({ purl, ecosystem, name, version });

    const locations = readLocations(rawComponent.properties);

    const existingIndex = indexByHash.get(identityHash);
    if (existingIndex !== undefined) {
      duplicatesCollapsed++;
      const acc = locationsByIndex[existingIndex]!;
      acc.paths.push(...locations.paths);
      acc.layerId ??= locations.layerId;
      continue;
    }

    indexByHash.set(identityHash, components.length);
    locationsByIndex.push({ paths: locations.paths, layerId: locations.layerId });
    components.push({
      identityHash,
      name,
      version,
      ecosystem,
      purl,
      cpe,
      kind,
      // Filled in below, once every duplicate has contributed its locations.
      paths: null,
      pathCount: null,
      layerId: null,
    });
  }

  /**
   * Reduce the accumulated locations to what is stored.
   *
   * Deferred to here rather than done inline because capping before the merge would keep an
   * arbitrary three of the first entry's paths and discard a later duplicate's, which is the
   * subtle version of the bug the merge exists to prevent.
   *
   * OS-package ecosystems are dropped entirely: their recorded paths are the package
   * manager's database (`/var/lib/dpkg/status`, `/lib/apk/db/installed`) and locate nothing.
   * `null` rather than `[]` so the reader can tell "no path applies here" from "we looked and
   * found none".
   */
  for (let i = 0; i < components.length; i++) {
    const parsed = components[i]!;
    const acc = locationsByIndex[i]!;

    if (!ecosystemHasMeaningfulPaths(parsed.ecosystem)) continue;
    if (acc.paths.length === 0) continue;

    // Sorted so the stored subset is deterministic: the same SBOM ingested twice must produce
    // the same three paths, or a re-ingest looks like the package moved.
    const unique = [...new Set(acc.paths)].sort();
    parsed.paths = unique.slice(0, COMPONENT_LOCATION_PATH_CAP);
    parsed.pathCount = unique.length;
    parsed.layerId = acc.layerId;
  }

  return {
    specVersion,
    serialNumber: asNonEmptyString(root.serialNumber, 128),
    toolName: tool.name,
    toolVersion: tool.version,
    subjectName: subject.name,
    subjectVersion: subject.version,
    components,
    skipped,
    duplicatesCollapsed,
    platform: detectPlatform(platformCandidates),
  };
}
