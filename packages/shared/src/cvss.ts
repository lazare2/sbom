import { z } from "zod";

/**
 * Where an attacker has to be, read from an advisory's CVSS vector.
 *
 * The CVSS score says how bad; the vector says how it was counted. Its `AV` part (attack vector)
 * is the same in CVSS v2, v3 and v4:
 *
 *   AV:N  network   - can be attacked remotely, over the network
 *   AV:A  adjacent  - only from the same local network
 *   AV:L  local     - needs access to the machine
 *   AV:P  physical  - needs physical access (v3 and v4 only)
 *
 * Two more parts tell how much the attacker needs besides:
 *
 *   PR (v3, v4)  privileges required: N none, L low, H high.   v2's Au (authentication):
 *                N none, S single, M multiple - read as the same question.
 *   UI (v3, v4)  user interaction: N none; v3 R required; v4 P passive, A active.
 *                v2 has no such part, so it stays unknown.
 *
 * The platform reports what the advisory says and invents nothing: no vector, or a vector
 * without the part, is "unknown" - never guessed.
 */

export const attackVectors = ["network", "adjacent", "local", "physical"] as const;
export type AttackVector = (typeof attackVectors)[number];

/** The filter accepts the four vectors plus `unknown` for advisories that carry none. */
export const attackVectorFilterValues = [...attackVectors, "unknown"] as const;
export type AttackVectorFilter = (typeof attackVectorFilterValues)[number];
export const attackVectorFilterSchema = z.enum(attackVectorFilterValues);

export interface CvssExploitability {
  attackVector: AttackVector | null;
  /** No sign-in needed (PR:N, or v2 Au:N); false when some is; null when the vector does not say. */
  noPrivileges: boolean | null;
  /** No user action needed (UI:N); false when some is; null when the vector does not say. */
  noUserInteraction: boolean | null;
}

const AV: Record<string, AttackVector> = { N: "network", A: "adjacent", L: "local", P: "physical" };

/** One metric's value, e.g. `metric(vector, "AV")` → "N". Accepts "AV:N/..." and "(AV:N/...)". */
function metric(vector: string, name: string): string | null {
  const match = new RegExp(`(?:^|[/(])${name}:([A-Z])`).exec(vector);
  return match?.[1] ?? null;
}

export function readCvssVector(vector: string | null | undefined): CvssExploitability {
  if (!vector) return { attackVector: null, noPrivileges: null, noUserInteraction: null };
  const v = vector.trim().toUpperCase();

  const av = metric(v, "AV");
  const pr = metric(v, "PR") ?? metric(v, "AU");
  const ui = metric(v, "UI");
  return {
    attackVector: av ? (AV[av] ?? null) : null,
    noPrivileges: pr === null ? null : pr === "N",
    noUserInteraction: ui === null ? null : ui === "N",
  };
}

/** Remote, and needing neither a sign-in nor anybody's action: the easiest kind to attack. */
export function isOpenRemoteAttack(e: CvssExploitability): boolean {
  return e.attackVector === "network" && e.noPrivileges === true && e.noUserInteraction === true;
}

/** Short label for tables and filters. */
export const ATTACK_VECTOR_LABELS: Record<AttackVectorFilter, string> = {
  network: "Remote",
  adjacent: "Same network",
  local: "Local",
  physical: "Physical",
  unknown: "Unknown",
};

/** One plain sentence, for the vulnerability page. */
export function describeExploitability(e: CvssExploitability): string {
  const where = {
    network: "Can be attacked remotely, over the network",
    adjacent: "Can be attacked only from the same local network",
    local: "Can be attacked only by someone with access to the machine",
    physical: "Can be attacked only with physical access to the machine",
  } as const;
  if (!e.attackVector) return "The advisory does not say where an attacker has to be.";

  const needs: string[] = [];
  const free: string[] = [];
  if (e.noPrivileges === true) free.push("signing in");
  if (e.noPrivileges === false) needs.push("a signed-in account");
  if (e.noUserInteraction === true) free.push("anybody's action");
  if (e.noUserInteraction === false) needs.push("someone to take an action, such as opening a link");

  let sentence = where[e.attackVector];
  if (free.length > 0) sentence += `, without ${free.join(" or ")}`;
  if (needs.length > 0) sentence += `${free.length > 0 ? "; it needs" : ", and needs"} ${needs.join(" and ")}`;
  return `${sentence}.`;
}

// ---------------------------------------------------------------------------------------------
// Every base metric, for the full CVSS filter
// ---------------------------------------------------------------------------------------------

/**
 * The CVSS base metrics a list can be filtered on, named as in FIRST's CVSS 3.1 and 4.0
 * specifications. `names` are the abbreviations a vector uses for the metric: CVSS 4.0 calls the
 * impacts on the vulnerable system VC, VI and VA where 3.x says C, I and A, so one filter covers
 * both. Values a version does not have simply never match a vector of that version.
 *
 * CVSS 4.0's supplemental metrics reuse some letters (S Safety, AU Automatable); every pattern
 * is anchored on both sides and the values are checked, so they are never mistaken for these.
 */
export interface CvssFilterMetric {
  key: "AV" | "AC" | "AT" | "PR" | "UI" | "S" | "C" | "I" | "A";
  label: string;
  names: readonly string[];
  values: ReadonlyArray<{ letter: string; label: string }>;
  /** Which CVSS versions have it, when not all of 3.x and 4.0. */
  only?: string;
}

export const CVSS_FILTER_METRICS: readonly CvssFilterMetric[] = [
  { key: "AV", label: "Attack vector", names: ["AV"], values: [
    { letter: "N", label: "Network" }, { letter: "A", label: "Adjacent" }, { letter: "L", label: "Local" }, { letter: "P", label: "Physical" },
  ] },
  { key: "AC", label: "Attack complexity", names: ["AC"], values: [{ letter: "L", label: "Low" }, { letter: "H", label: "High" }] },
  { key: "AT", label: "Attack requirements", names: ["AT"], only: "4.0", values: [{ letter: "N", label: "None" }, { letter: "P", label: "Present" }] },
  { key: "PR", label: "Privileges required", names: ["PR"], values: [
    { letter: "N", label: "None" }, { letter: "L", label: "Low" }, { letter: "H", label: "High" },
  ] },
  { key: "UI", label: "User interaction", names: ["UI"], values: [
    { letter: "N", label: "None" }, { letter: "R", label: "Required (3.x)" }, { letter: "P", label: "Passive (4.0)" }, { letter: "A", label: "Active (4.0)" },
  ] },
  { key: "S", label: "Scope", names: ["S"], only: "3.x", values: [{ letter: "U", label: "Unchanged" }, { letter: "C", label: "Changed" }] },
  { key: "C", label: "Confidentiality impact", names: ["C", "VC"], values: [{ letter: "H", label: "High" }, { letter: "L", label: "Low" }, { letter: "N", label: "None" }] },
  { key: "I", label: "Integrity impact", names: ["I", "VI"], values: [{ letter: "H", label: "High" }, { letter: "L", label: "Low" }, { letter: "N", label: "None" }] },
  { key: "A", label: "Availability impact", names: ["A", "VA"], values: [{ letter: "H", label: "High" }, { letter: "L", label: "Low" }, { letter: "N", label: "None" }] },
];

const METRIC_BY_NAME = new Map<string, CvssFilterMetric>(
  CVSS_FILTER_METRICS.flatMap((m) => m.names.map((n) => [n, m] as const)),
);

/**
 * Reads filter text - "AC:L", a pasted vector such as "CVSS:3.1/AV:N/AC:L/PR:N", or several
 * parts - into canonical "KEY:LETTER" parts (VC:H becomes C:H). Parts it does not know, such as
 * CVSS 4.0's supplemental metrics, come back in `ignored` so a screen can say so.
 */
export function parseCvssFilter(input: string | readonly string[]): { parts: string[]; ignored: string[] } {
  const raw = (typeof input === "string" ? [input] : input)
    .flatMap((s) => s.replace(/[()\s]/g, "").split("/"))
    .filter((s) => s !== "" && !/^CVSS:/i.test(s));
  const parts = new Set<string>();
  const ignored: string[] = [];
  for (const piece of raw) {
    const [name, value] = piece.toUpperCase().split(":");
    const metric = name ? METRIC_BY_NAME.get(name) : undefined;
    if (metric && value && metric.values.some((v) => v.letter === value)) parts.add(`${metric.key}:${value}`);
    else ignored.push(piece);
  }
  return { parts: [...parts], ignored };
}

/** The filter parts grouped by metric: values of one metric are ORed, metrics are ANDed. */
export function groupCvssFilter(parts: readonly string[]): Map<CvssFilterMetric, string[]> {
  const out = new Map<CvssFilterMetric, string[]>();
  for (const part of parseCvssFilter(parts).parts) {
    const [key, letter] = part.split(":") as [string, string];
    const metric = METRIC_BY_NAME.get(key)!;
    out.set(metric, [...(out.get(metric) ?? []), letter]);
  }
  return out;
}

/**
 * One metric's test as a regular expression over the upper-cased vector. The same text runs in
 * Postgres (`~`) and in JavaScript; only letters from the metric's own list ever reach it.
 */
export function cvssMetricPattern(metric: CvssFilterMetric, letters: readonly string[]): string {
  const ok = letters.filter((l) => metric.values.some((v) => v.letter === l));
  return `(?:^|[/(])(?:${metric.names.join("|")}):(?:${ok.join("|")})(?:$|[/)])`;
}

/** Whether a vector passes the filter parts, in JavaScript - the rule the SQL applies. */
export function matchesCvssFilter(vector: string | null | undefined, parts: readonly string[]): boolean {
  const groups = groupCvssFilter(parts);
  if (groups.size === 0) return true;
  if (!vector) return false;
  const v = vector.trim().toUpperCase();
  return [...groups].every(([metric, letters]) => new RegExp(cvssMetricPattern(metric, letters)).test(v));
}

export const cvssVersionFilterValues = ["4", "3", "2", "none"] as const;
export type CvssVersionFilter = (typeof cvssVersionFilterValues)[number];
export const CVSS_VERSION_LABELS: Record<CvssVersionFilter, string> = { "4": "CVSS 4.0", "3": "CVSS 3.x", "2": "CVSS 2.0", none: "No vector" };

/** The vector's CVSS version, as the filter counts it. */
export function cvssVersionOf(vector: string | null | undefined): CvssVersionFilter {
  const v = (vector ?? "").trim().toUpperCase();
  if (!/(?:^|[/(])AV:/.test(v)) return "none";
  if (v.startsWith("CVSS:4")) return "4";
  if (v.startsWith("CVSS:3")) return "3";
  return "2";
}

/** Each filterable metric's letter in a vector, by key: what a row shows as tags. */
export function readCvssMetrics(vector: string | null | undefined): Partial<Record<CvssFilterMetric["key"], string>> {
  const out: Partial<Record<CvssFilterMetric["key"], string>> = {};
  if (!vector) return out;
  for (const piece of vector.trim().toUpperCase().replace(/[()]/g, "").split("/")) {
    const [name, value] = piece.split(":");
    const metric = name ? METRIC_BY_NAME.get(name) : undefined;
    if (metric && value && metric.values.some((v) => v.letter === value)) out[metric.key] = value;
  }
  return out;
}

/**
 * The `cvss` query parameter: repeated ("cvss=AC:L&cvss=PR:N") or one pasted vector
 * ("cvss=AV:N/PR:N/UI:N"). Unknown parts are refused rather than quietly dropped, so a typo
 * never widens a filter.
 */
export const cvssFilterParamSchema = z
  .union([z.string().max(300), z.array(z.string().max(300)).max(50)])
  .optional()
  .transform((value, ctx) => {
    if (value === undefined) return [] as string[];
    const { parts, ignored } = parseCvssFilter(value);
    if (ignored.length > 0) {
      ctx.addIssue({ code: "custom", message: `Not a CVSS base metric value this filter knows: ${ignored.join(", ")}` });
      return z.NEVER;
    }
    return parts;
  });

export const cvssVersionFilterSchema = z.enum(cvssVersionFilterValues);
