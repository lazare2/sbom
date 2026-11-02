/**
 * A version comparison good enough to order fix versions, across ecosystems.
 *
 * Used for two things only: dropping fix versions that are older than the installed one, and
 * listing the rest lowest-first. Trivy and OSV both report every fixed version an advisory
 * names - `2.9.10.1, 2.8.11.5, 2.6.7.3` for a jackson-databind at 2.9.10 - and offering
 * 2.6.7.3 as an upgrade from 2.9.10 would be wrong. Matching itself is never decided here;
 * the scanners own that, with their ecosystem-specific rules.
 *
 * The rules are the common ground of semver, Maven, PEP 440, Debian and Alpine: an optional
 * `epoch:` prefix, then runs of digits compared as numbers and runs of letters compared as
 * text, with a release outranking its own pre-release (`1.0` > `1.0-rc1`) and Debian's `~`
 * sorting before anything. Where two versions cannot be ordered meaningfully this still
 * returns an answer, and the callers treat an uncertain answer as "keep it".
 */

type Token = { kind: "num"; value: bigint } | { kind: "str"; value: string } | { kind: "tilde" };

/** Marks pre-releases, which sort before the release they precede. */
const PRE_RELEASE = /^(alpha|beta|rc|cr|pre|preview|dev|snapshot|milestone|m|a|b|c)$/i;

function tokenize(version: string): { epoch: bigint; tokens: Token[] } {
  let rest = version.trim().replace(/^v(?=\d)/i, "");
  let epoch = 0n;
  const epochMatch = /^(\d+):(.*)$/.exec(rest);
  if (epochMatch) {
    epoch = BigInt(epochMatch[1]!);
    rest = epochMatch[2]!;
  }
  const tokens: Token[] = [];
  const re = /(\d+)|([A-Za-z]+)|(~)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rest)) !== null) {
    if (m[1] !== undefined) tokens.push({ kind: "num", value: BigInt(m[1]) });
    else if (m[2] !== undefined) tokens.push({ kind: "str", value: m[2].toLowerCase() });
    else tokens.push({ kind: "tilde" });
  }
  return { epoch, tokens };
}

/** The weight of what follows the end of a version, against the token in the other one. */
function tailWeight(token: Token): number {
  if (token.kind === "tilde") return 1; // 1.0~rc1 < 1.0
  if (token.kind === "str" && PRE_RELEASE.test(token.value)) return 1; // 1.0-rc1 < 1.0
  return -1; // 1.0 < 1.0.1, 1.0 < 1.0-r1
}

/** Negative when `a` is older than `b`, positive when newer, zero when equivalent. */
export function compareVersions(a: string, b: string): number {
  const x = tokenize(a);
  const y = tokenize(b);
  if (x.epoch !== y.epoch) return x.epoch < y.epoch ? -1 : 1;

  const n = Math.max(x.tokens.length, y.tokens.length);
  for (let i = 0; i < n; i++) {
    const p = x.tokens[i];
    const q = y.tokens[i];
    if (p === undefined) return q === undefined ? 0 : tailWeight(q);
    if (q === undefined) return -tailWeight(p);
    if (p.kind === q.kind) {
      if (p.kind === "num" && q.kind === "num") {
        if (p.value !== q.value) return p.value < q.value ? -1 : 1;
      } else if (p.kind === "str" && q.kind === "str") {
        if (p.value !== q.value) {
          const pp = PRE_RELEASE.test(p.value);
          const qp = PRE_RELEASE.test(q.value);
          if (pp !== qp) return pp ? -1 : 1;
          return p.value < q.value ? -1 : 1;
        }
      }
      continue;
    }
    // Mixed kinds at the same position: tilde lowest, then letters, then numbers.
    const rank = (t: Token) => (t.kind === "tilde" ? 0 : t.kind === "str" ? 1 : 2);
    return rank(p) < rank(q) ? -1 : 1;
  }
  return 0;
}

/**
 * The fix versions worth offering for an installed version: newer than it, deduplicated,
 * lowest first. With no installed version to compare against, all of them, in order.
 */
export function upgradeFixes(fixVersions: readonly string[], installed: string | null): string[] {
  const unique = [...new Set(fixVersions.map((v) => v.trim()).filter((v) => v !== ""))];
  const newer = installed ? unique.filter((v) => compareVersions(v, installed) > 0) : unique;
  return newer.sort(compareVersions);
}
