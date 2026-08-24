import type { MaliciousMatchMode } from "@sbom/shared";
import type { MaliciousVersionRange } from "../../db/schema.js";

/**
 * Deciding whether a package in the estate is the package a report names.
 *
 * Pure functions, kept away from the database and the feed parser because every one of them
 * is a place where the answer can be silently wrong in one of two expensive directions:
 *
 *   a false NEGATIVE hides real malware, and nobody ever finds out;
 *   a false POSITIVE starts an incident -- credentials rotated, a service torn down --
 *   over a package that was fine.
 *
 * The asymmetry is not clean enough to optimise for one side. What follows instead is exact
 * matching wherever the feed is exact (99.3% of reports), and an explicit, reviewable rule
 * for the remainder.
 */

/**
 * OSV ecosystem names to the purl types this platform stores on components.
 *
 * Two vocabularies for the same set, and neither is going to change to suit the other: OSV
 * says `PyPI` and `crates.io`, purl says `pypi` and `cargo`, and Syft gives us purl. Mapped
 * once here rather than at every comparison, so a missing entry is one obvious gap in one
 * table instead of an intermittent failure to match.
 */
const ECOSYSTEM_TO_PURL_TYPE: Record<string, string> = {
  npm: "npm",
  pypi: "pypi",
  rubygems: "gem",
  nuget: "nuget",
  "crates.io": "cargo",
  go: "golang",
  maven: "maven",
  packagist: "composer",
  hex: "hex",
  pub: "pub",
  hackage: "hackage",
  cran: "cran",
  swifturl: "swift",
};

/**
 * Reduce an OSV ecosystem to the purl type, or null when the platform cannot see it anyway.
 *
 * OSV qualifies some ecosystems after a colon -- `Debian:12`, `VSCode:https://open-vsx.org` --
 * and the qualifier names a distribution or a registry rather than a different ecosystem, so
 * it is dropped.
 *
 * Null for anything unmapped, and the caller drops the report. Storing a row that no purl can
 * ever equal would inflate the feed's own count of what it is protecting, which is a number
 * an administrator reads as coverage.
 */
export function normalizeEcosystem(osvEcosystem: string): string | null {
  const base = osvEcosystem.split(":")[0]?.trim().toLowerCase() ?? "";
  return ECOSYSTEM_TO_PURL_TYPE[base] ?? null;
}

/**
 * Reduce a package name to the form its ecosystem considers canonical.
 *
 * Applied to both sides of every comparison. The rules are the registries' own:
 *
 *  - PyPI (PEP 503) folds case and treats any run of `-`, `_` and `.` as a single `-`, so
 *    `Zope.Interface`, `zope_interface` and `zope-interface` are one project. A report filed
 *    under one spelling has to match an SBOM using another.
 *  - npm, RubyGems, NuGet, Packagist and Hex are case-insensitive in practice. npm has
 *    rejected uppercase in new names for years, but old packages predate that rule.
 *  - Maven and Go are case-SENSITIVE, and folding them would merge genuinely different
 *    artifacts. `github.com/Sirupsen/logrus` and `github.com/sirupsen/logrus` were famously
 *    two different modules at the same time.
 */
export function normalizePackageName(purlType: string, name: string): string {
  const trimmed = name.trim();
  switch (purlType) {
    case "pypi":
      return trimmed.toLowerCase().replace(/[-_.]+/g, "-");
    case "npm":
    case "gem":
    case "nuget":
    case "composer":
    case "hex":
    case "cargo":
    case "pub":
      return trimmed.toLowerCase();
    case "maven":
    case "golang":
    default:
      return trimmed;
  }
}

/**
 * Order two version strings, or return null when they cannot be ordered confidently.
 *
 * A deliberately general comparator rather than a strict semver one. It is asked about npm,
 * PyPI, RubyGems and NuGet versions, which agree on dot-separated numeric components and
 * disagree about everything after them, and a strict parser would reject perfectly ordinary
 * versions like `1.0.0.4` or `2.1-beta`.
 *
 * Null rather than a guess is the important part. It is the signal the caller uses to fall
 * back to reporting the match instead of quietly dismissing it -- see `versionInRange`.
 */
export function compareVersions(a: string, b: string): number | null {
  const parse = (v: string): { release: string[]; pre: string | null } | null => {
    const trimmed = v.trim().replace(/^[vV]/, "");
    if (trimmed === "") return null;
    // Everything from the first `-` or `+` is prerelease/build metadata.
    const marker = trimmed.search(/[-+]/);
    const release = marker === -1 ? trimmed : trimmed.slice(0, marker);
    const pre = marker === -1 ? null : trimmed.slice(marker + 1);
    const parts = release.split(".");
    // Every release component must be numeric, or ordering is a guess: `1.0.0` against
    // `1.0.RELEASE` has no defensible answer and pretending otherwise is how a range match
    // silently covers the wrong versions.
    if (!parts.every((p) => /^\d+$/.test(p))) return null;
    return { release: parts, pre };
  };

  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return null;

  const len = Math.max(pa.release.length, pb.release.length);
  for (let i = 0; i < len; i += 1) {
    const na = Number(pa.release[i] ?? "0");
    const nb = Number(pb.release[i] ?? "0");
    if (na !== nb) return na < nb ? -1 : 1;
  }

  // Equal releases: a prerelease sorts BELOW the release it leads to, per semver. `1.0.0-rc1`
  // is not `1.0.0`, and treating them as equal would make a range that starts at `1.0.0`
  // swallow the release candidates before it.
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === null) return 1;
  if (pb.pre === null) return -1;
  return pa.pre < pb.pre ? -1 : pa.pre > pb.pre ? 1 : 0;
}

/**
 * Whether a version falls inside any of a report's ranges.
 *
 * **Uncertainty resolves to `true`.** When the versions cannot be ordered, this reports the
 * match rather than dropping it, and the finding is labelled `version_range` so the screen
 * can tell the reader to check it against the report before acting.
 *
 * That direction is chosen, not accidental. A dropped match is invisible: nobody ever learns
 * that the platform quietly decided `1.0.RELEASE` was outside a range. A reported one is
 * visible, attributed, and dismissable in a click. Ranges are 0.7% of the feed, so the noise
 * this admits is bounded in a way the silence would not be.
 */
export function versionInRange(version: string, ranges: MaliciousVersionRange[]): boolean {
  if (ranges.length === 0) return false;

  return ranges.some((range) => {
    const { introduced, fixed, lastAffected } = range;

    // `introduced: "0"` is OSV's way of saying "from the beginning", and needs no comparison.
    if (introduced !== null && introduced !== "0") {
      const cmp = compareVersions(version, introduced);
      if (cmp === null) return true;
      if (cmp < 0) return false;
    }

    if (fixed !== null) {
      const cmp = compareVersions(version, fixed);
      if (cmp === null) return true;
      // `fixed` is exclusive: the fixed version itself is not affected.
      if (cmp >= 0) return false;
    }

    if (lastAffected !== null) {
      const cmp = compareVersions(version, lastAffected);
      if (cmp === null) return true;
      // `last_affected` is inclusive, unlike `fixed`. Conflating the two shifts every
      // bounded range by exactly one release.
      if (cmp > 0) return false;
    }

    return true;
  });
}

/** A report reduced to what matching needs. */
export interface MatchableReport {
  id: string;
  matchMode: MaliciousMatchMode;
  affectedVersions: string[];
  versionRanges: MaliciousVersionRange[] | null;
}

/**
 * Whether one component version is covered by one report.
 *
 * A component with no version is matched only by `all_versions` reports. CycloneDX permits a
 * component without a resolvable version, and for a package that is malicious in its entirety
 * the name alone is the finding -- but claiming an unknown version falls in a specific range
 * would be inventing the fact the match depends on.
 */
export function reportCoversVersion(report: MatchableReport, version: string | null): boolean {
  switch (report.matchMode) {
    case "all_versions":
      return true;
    case "exact_versions":
      if (version === null) return false;
      return report.affectedVersions.includes(version);
    case "version_range":
      if (version === null) return false;
      return versionInRange(version, report.versionRanges ?? []);
  }
}
