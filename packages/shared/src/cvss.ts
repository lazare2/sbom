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
