/**
 * Extracts "what is this image built on" from a Syft CycloneDX document: the OS
 * distribution and the language runtimes present.
 *
 * This information is already in every SBOM the platform receives and was
 * previously discarded. It is the difference between "this app has 400 packages"
 * and "this app runs Node 22.11 on Alpine 3.20" — the second is what someone
 * planning a base-image upgrade actually needs.
 *
 * What this deliberately does NOT claim to know is the base image *name*. An
 * SBOM describes a flattened filesystem, not layer ancestry, so nothing here can
 * tell you the Dockerfile said `FROM node:22-alpine`. Two images built from
 * different bases with identical contents produce identical SBOMs. What is
 * reported is observed contents, which is a different and honest claim.
 */

export interface DetectedRuntime {
  /** Canonical runtime name, e.g. `node`, `python`, `java`. */
  name: string;
  version: string | null;
}

export interface ScanPlatformData {
  /** Distro id as Syft reports it: `alpine`, `debian`, `ubuntu`, `rhel`. */
  osName: string | null;
  osVersion: string | null;
  /** Distro's own pretty name, e.g. `Alpine Linux v3.20`. */
  osPretty: string | null;
  runtimes: DetectedRuntime[];
}

/**
 * Binary names Syft's classifier reports that represent a language runtime or an
 * application server, mapped to a canonical name.
 *
 * A closed list, not "anything Syft found as a binary". A container image
 * contains dozens of binaries — `busybox`, `openssl`, `bash`, `coreutils` — and
 * listing them all as "the runtime" would bury the one fact this feature exists
 * to surface. Names here are the ones that answer "what does this application
 * execute on".
 *
 * Aliases collapse onto one canonical name so that `python3` and `python`, or
 * the several JDK spellings, do not fragment the dashboard's counts.
 */
const RUNTIME_ALIASES: Record<string, string> = {
  node: "node",
  nodejs: "node",
  bun: "bun",
  deno: "deno",

  python: "python",
  python3: "python",
  cpython: "python",
  pypy: "pypy",

  java: "java",
  jdk: "java",
  jre: "java",
  openjdk: "java",
  "java-runtime": "java",
  graalvm: "java",

  ruby: "ruby",
  php: "php",
  perl: "perl",

  go: "go",
  golang: "go",
  rust: "rust",
  rustc: "rust",

  dotnet: "dotnet",
  "asp.net-core": "dotnet",
  mono: "dotnet",

  erlang: "erlang",
  elixir: "elixir",
  haskell: "haskell",
  ghc: "haskell",
  lua: "lua",
  swift: "swift",
  dart: "dart",

  // Application servers. Not language runtimes strictly, but for a web image
  // "nginx 1.27 on Alpine 3.20" is exactly the useful summary.
  nginx: "nginx",
  httpd: "apache-httpd",
  apache2: "apache-httpd",
  tomcat: "tomcat",
  caddy: "caddy",
  haproxy: "haproxy",
};

/**
 * True when a binary name is one of the runtimes this platform reports.
 *
 * Exported so the parser's component classification and platform detection share
 * one list. Two copies would drift, and then a component could be excluded from
 * the dependency aggregates as a "runtime" while never appearing as one.
 */
export function isKnownRuntime(name: string): boolean {
  return RUNTIME_ALIASES[name.toLowerCase()] !== undefined;
}

/** Human-facing display names, for the UI's benefit. */
export const RUNTIME_LABELS: Record<string, string> = {
  node: "Node.js",
  bun: "Bun",
  deno: "Deno",
  python: "Python",
  pypy: "PyPy",
  java: "Java",
  ruby: "Ruby",
  php: "PHP",
  perl: "Perl",
  go: "Go",
  rust: "Rust",
  dotnet: ".NET",
  erlang: "Erlang",
  elixir: "Elixir",
  haskell: "Haskell",
  lua: "Lua",
  swift: "Swift",
  dart: "Dart",
  nginx: "nginx",
  "apache-httpd": "Apache httpd",
  tomcat: "Tomcat",
  caddy: "Caddy",
  haproxy: "HAProxy",
};

const OS_LABELS: Record<string, string> = {
  alpine: "Alpine",
  debian: "Debian",
  ubuntu: "Ubuntu",
  rhel: "RHEL",
  centos: "CentOS",
  fedora: "Fedora",
  rocky: "Rocky Linux",
  almalinux: "AlmaLinux",
  amzn: "Amazon Linux",
  sles: "SLES",
  opensuse: "openSUSE",
  "opensuse-leap": "openSUSE Leap",
  arch: "Arch Linux",
  wolfi: "Wolfi",
  chainguard: "Chainguard",
  photon: "Photon OS",
  busybox: "BusyBox",
  windows: "Windows",
};

/**
 * The shape this reads from each component. Structurally identical to the
 * parser's own RawComponent, kept separate so platform detection can be tested
 * and reasoned about without importing the parser.
 */
export interface PlatformCandidate {
  name: string | null;
  version: string | null;
  /** Lowercased CycloneDX `type`. */
  cdxType: string | null;
  purl: string | null;
  /** Value of the `syft:package:type` property, if present. */
  syftType: string | null;
  /** Value of the `syft:distro:*` properties, when this is the OS component. */
  distroId?: string | null;
  distroVersionId?: string | null;
  distroPrettyName?: string | null;
}

/** Trims a distro version to the meaningful part: `3.20.3_alpha20240329` -> `3.20.3`. */
function cleanVersion(version: string | null): string | null {
  if (!version) return null;
  const trimmed = version.trim();
  return trimmed === "" ? null : trimmed.slice(0, 64);
}

/**
 * Reduce a document's components to the platform summary.
 *
 * Runs over the same array the dependency parser walks, so it costs one extra
 * pass over already-parsed objects rather than a second decode of the document.
 */
export function detectPlatform(candidates: readonly PlatformCandidate[]): ScanPlatformData {
  let osName: string | null = null;
  let osVersion: string | null = null;
  let osPretty: string | null = null;

  // Keyed by canonical name so `python3` and `python` collapse into one entry.
  const runtimes = new Map<string, DetectedRuntime>();

  for (const c of candidates) {
    if (!c.name) continue;

    // --- the OS component -------------------------------------------------
    if (c.cdxType === "operating-system") {
      // `syft:distro:*` properties are preferred over the component's own name
      // and version: Syft populates them straight from /etc/os-release, which is
      // the authoritative source, while the component fields are a rendering of
      // it. Falls back to the component itself for SBOMs from other tools.
      osName = (c.distroId ?? c.name).toLowerCase();
      osVersion = cleanVersion(c.distroVersionId ?? c.version);
      osPretty = c.distroPrettyName ?? null;
      continue;
    }

    // --- language runtimes and app servers --------------------------------
    // Only binary-cataloged components are considered. A `node` entry from the
    // npm cataloger is a package named "node" in someone's dependency tree, not
    // the interpreter the image runs — treating those as the runtime would
    // report a Java service as running Node.
    const isBinary = c.syftType === "binary" || (c.purl?.startsWith("pkg:generic/") ?? false);
    if (!isBinary) continue;

    const canonical = RUNTIME_ALIASES[c.name.toLowerCase()];
    if (!canonical) continue;

    const version = cleanVersion(c.version);
    const existing = runtimes.get(canonical);

    // Keep the highest version when an image genuinely carries two (a JDK and a
    // JRE, say). Reporting the lower one would understate what is installed.
    if (!existing || compareVersions(version, existing.version) > 0) {
      runtimes.set(canonical, { name: canonical, version });
    }
  }

  return {
    osName,
    osVersion,
    osPretty,
    // Stable order so a stored jsonb array does not churn between scans of an
    // unchanged image.
    runtimes: [...runtimes.values()].sort((a, b) => a.name.localeCompare(b.name)),
  };
}

/**
 * Compares dotted version strings numerically where possible.
 *
 * Not a semver implementation, and does not need to be: the only decision it
 * drives is which of two copies of the same runtime to report. A plain string
 * compare would rank `9.0` above `10.0`, which is the one wrong answer that
 * would actually mislead someone.
 */
export function compareVersions(a: string | null, b: string | null): number {
  if (a === b) return 0;
  if (a === null) return -1;
  if (b === null) return 1;

  const partsA = a.split(/[.\-+_~]/);
  const partsB = b.split(/[.\-+_~]/);

  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const rawA = partsA[i] ?? "";
    const rawB = partsB[i] ?? "";
    const numA = Number.parseInt(rawA, 10);
    const numB = Number.parseInt(rawB, 10);

    if (Number.isNaN(numA) || Number.isNaN(numB)) {
      const cmp = rawA.localeCompare(rawB);
      if (cmp !== 0) return cmp;
      continue;
    }
    if (numA !== numB) return numA - numB;
  }
  return 0;
}

/** `alpine` -> `Alpine`. Falls back to the raw id so unknown distros still read sensibly. */
export function osLabel(osName: string | null): string | null {
  if (!osName) return null;
  return OS_LABELS[osName.toLowerCase()] ?? osName;
}

export function runtimeLabel(name: string): string {
  return RUNTIME_LABELS[name] ?? name;
}

/**
 * One-line summary: `Alpine 3.20.3 · Node.js 22.11.0`.
 *
 * Returns null rather than a placeholder when nothing was detected, so callers
 * decide how to render "unknown" — a distroless or scratch image legitimately
 * has no OS packages and no runtime binary, and that is information, not a gap.
 */
export function platformSummary(platform: ScanPlatformData): string | null {
  const parts: string[] = [];

  const os = osLabel(platform.osName);
  if (os) parts.push(platform.osVersion ? `${os} ${platform.osVersion}` : os);

  for (const runtime of platform.runtimes) {
    const label = runtimeLabel(runtime.name);
    parts.push(runtime.version ? `${label} ${runtime.version}` : label);
  }

  return parts.length > 0 ? parts.join(" · ") : null;
}
