import {
  ATTACK_VECTOR_LABELS,
  attackVectorFilterValues,
  describeExploitability,
  isOpenRemoteAttack,
  type AttackVectorFilter,
  type CvssExploitability,
} from "@sbom/shared";
import { Badge } from "./ui.tsx";

/**
 * Where an attacker has to be, as a small badge. The full sentence is on hover.
 *
 * Red for remote with no sign-in and no action needed - the easiest kind to attack - amber for
 * other remote ones, grey for the rest. From the advisory's CVSS vector, never guessed.
 */
export function AttackVectorBadge({ exploitability }: { exploitability: CvssExploitability }) {
  const title = describeExploitability(exploitability);
  if (!exploitability.attackVector) {
    return (
      <span className="text-xs text-text-faint" title={title}>
        unknown
      </span>
    );
  }
  const open = isOpenRemoteAttack(exploitability);
  const tone = open ? "danger" : exploitability.attackVector === "network" ? "warn" : "neutral";
  return (
    <Badge tone={tone} title={title}>
      {ATTACK_VECTOR_LABELS[exploitability.attackVector]}
      {open ? ", no sign-in" : ""}
    </Badge>
  );
}

/** The Excel cell for the same thing: the label plus the conditions, in words. */
export function exportAttackVector(e: CvssExploitability): string {
  if (!e.attackVector) return "Unknown";
  const parts = [ATTACK_VECTOR_LABELS[e.attackVector]];
  if (e.noPrivileges === true) parts.push("no sign-in needed");
  if (e.noPrivileges === false) parts.push("sign-in needed");
  if (e.noUserInteraction === true) parts.push("no user action needed");
  if (e.noUserInteraction === false) parts.push("user action needed");
  return parts.join(", ");
}

export const ATTACK_VECTOR_OPTIONS: readonly AttackVectorFilter[] = attackVectorFilterValues;
export const attackVectorOptionLabel = (v: string) => ATTACK_VECTOR_LABELS[v as AttackVectorFilter] ?? v;
