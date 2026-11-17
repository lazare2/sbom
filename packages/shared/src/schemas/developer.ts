import { z } from "zod";
import type { SeverityCounts, VulnSeverity } from "./vulnerability.js";

/**
 * The developer view: "My projects" with a status in words, and a project's action plan.
 *
 * ## The rules, in one place
 *
 * Each vulnerability gets an urgency; a project's status is its most urgent one. Accepted risks
 * never count. Step 5 makes the values editable (target dates); until then they live here.
 *
 *   now    a fix is available, and it is used in real attacks (CISA KEV), or it is critical and
 *          can be attacked remotely (CVSS AV:N)
 *   soon   a fix is available, and it is critical or high
 *   later  a fix is available, lower severity
 *   none   no fix yet: nothing to do but wait
 *
 * Project status:
 *   Fix now          some vulnerability is `now`
 *   Fix soon         otherwise, some is `soon`
 *   No recent build  otherwise, the last build is older than the "stale" limit, or there is none
 *   Nothing to do    otherwise
 */

export const urgencies = ["now", "soon", "later", "none"] as const;
export type Urgency = (typeof urgencies)[number];

export const projectStatuses = ["fix-now", "fix-soon", "no-recent-build", "nothing-to-do"] as const;
export type ProjectStatus = (typeof projectStatuses)[number];

export const PROJECT_STATUS_LABELS: Record<ProjectStatus, string> = {
  "fix-now": "Fix now",
  "fix-soon": "Fix soon",
  "no-recent-build": "No recent build",
  "nothing-to-do": "Nothing to do",
};

/** Sorts "most urgent first". */
export const PROJECT_STATUS_RANK: Record<ProjectStatus, number> = {
  "fix-now": 0,
  "fix-soon": 1,
  "no-recent-build": 2,
  "nothing-to-do": 3,
};

export interface UrgencyInput {
  fixable: boolean;
  usedInAttacks: boolean;
  severity: VulnSeverity;
  remote: boolean;
}

export function findingUrgency(f: UrgencyInput): Urgency {
  if (!f.fixable) return "none";
  if (f.usedInAttacks || (f.severity === "critical" && f.remote)) return "now";
  if (f.severity === "critical" || f.severity === "high") return "soon";
  return "later";
}

/** What a project's status is computed from. The same numbers on the list and the project page. */
export interface ProjectUrgencyCounts {
  /** Vulnerabilities in the current build, accepted risks left out. */
  total: number;
  now: number;
  /** Of `now`: used in real attacks. The rest are critical and remote. */
  nowUsedInAttacks: number;
  soon: number;
  later: number;
  /** No fix yet. */
  none: number;
  /** Of `none`: critical or high. Said in the reason, because waiting on them is a risk too. */
  noneSerious: number;
  /** Past their target date (see `targetDays`). */
  late: number;
  /** First seen after the person's previous visit to the project. 0 when there was none. */
  newSinceVisit: number;
}

export interface ProjectStatusInput {
  counts: ProjectUrgencyCounts;
  hasBuild: boolean;
  /** The last build is older than the stale limit. */
  stale: boolean;
  /** Days since the last build, for the reason. Null without a build. */
  daysSinceBuild: number | null;
  /** Vulnerability scanning is switched off: the status cannot speak about vulnerabilities. */
  scanningOff: boolean;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** The status and the reason, always together. */
export function projectStatus(input: ProjectStatusInput): { status: ProjectStatus; reason: string } {
  const { counts: c } = input;
  const built = input.daysSinceBuild === null ? "" : `last build ${plural(input.daysSinceBuild, "day")} ago`;

  if (!input.hasBuild) return { status: "no-recent-build", reason: "No build has been received yet." };
  if (input.scanningOff) {
    return input.stale
      ? { status: "no-recent-build", reason: `No recent build: ${built}. Vulnerability scanning is switched off.` }
      : { status: "nothing-to-do", reason: "Vulnerability scanning is switched off, so nothing is checked." };
  }

  const staleNote =
    (c.late > 0 ? ` ${c.late} ${c.late === 1 ? "is" : "are"} past the target date.` : "") +
    (input.stale ? ` No recent build: ${built}.` : "");
  if (c.now > 0) {
    const parts: string[] = [];
    if (c.nowUsedInAttacks > 0) parts.push(`${plural(c.nowUsedInAttacks, "vulnerability", "vulnerabilities")} used in real attacks`);
    const remote = c.now - c.nowUsedInAttacks;
    if (remote > 0) parts.push(`${remote} critical that can be attacked remotely`);
    return { status: "fix-now", reason: `${parts.join(" and ")}, with a fix available.${staleNote}` };
  }
  if (c.soon > 0) {
    return {
      status: "fix-soon",
      reason: `${plural(c.soon, "critical or high vulnerability", "critical or high vulnerabilities")} with a fix available.${staleNote}`,
    };
  }
  const notes: string[] = [];
  if (c.later > 0) notes.push(`${plural(c.later, "lower-severity fix", "lower-severity fixes")} available`);
  if (c.noneSerious > 0) notes.push(`${c.noneSerious} critical or high without a fix yet`);
  const tail = notes.length > 0 ? ` (${notes.join("; ")})` : "";
  if (input.stale) return { status: "no-recent-build", reason: `No recent build: ${built}${tail}.` };
  return {
    status: "nothing-to-do",
    reason: c.total === 0 ? "No known vulnerabilities." : `No critical or high vulnerability with a fix${tail}.`,
  };
}

// --- Target dates ------------------------------------------------------------------------

/**
 * How many days a team has to fix a vulnerability, by rule. Only vulnerabilities with a fix
 * have one; the rest have none - nobody can be late fixing what cannot be fixed.
 *
 *   usedInAttacksDays  used in real attacks (CISA KEV), fix available      starts at 7
 *   criticalDays       critical, fix available                              starts at the
 *                      existing "critical fix" value in Needs attention (30) - the same setting
 *   highDays           high, fix available                                  starts at 60
 *
 * The clock starts when the vulnerability was first seen in that project: the later of when it
 * was first found in the package version and the project's first build containing that version.
 * Where two rules apply, the shorter one wins.
 */
export const targetDatesSchema = z.object({
  usedInAttacksDays: z.coerce.number().int().min(1).max(3650),
  criticalDays: z.coerce.number().int().min(1).max(3650),
  highDays: z.coerce.number().int().min(1).max(3650),
});
export type TargetDates = z.infer<typeof targetDatesSchema>;

export const DEFAULT_TARGET_DATES: TargetDates = { usedInAttacksDays: 7, criticalDays: 30, highDays: 60 };

export interface TargetRule {
  days: number;
  /** The rule in words, shown beside every date. */
  rule: string;
}

export function targetFor(
  f: { fixable: boolean; usedInAttacks: boolean; severity: VulnSeverity },
  t: TargetDates,
): TargetRule | null {
  if (!f.fixable) return null;
  const rules: TargetRule[] = [];
  if (f.usedInAttacks) rules.push({ days: t.usedInAttacksDays, rule: `used in real attacks, fix available: ${t.usedInAttacksDays} days` });
  if (f.severity === "critical") rules.push({ days: t.criticalDays, rule: `critical, fix available: ${t.criticalDays} days` });
  if (f.severity === "high") rules.push({ days: t.highDays, rule: `high, fix available: ${t.highDays} days` });
  return rules.sort((a, b) => a.days - b.days)[0] ?? null;
}

// --- My projects -------------------------------------------------------------------------

export interface MyProject {
  applicationId: string;
  name: string;
  status: ProjectStatus;
  reason: string;
  lastBuildAt: string | null;
  counts: ProjectUrgencyCounts;
  /** How the person reaches it: their squads, or a grant to them. */
  via: string[];
}

export interface MyProjectsResponse {
  projects: MyProject[];
  /** False when the person is on no squad and has no grant: the page says how to get some. */
  hasMembership: boolean;
}

// --- Action plan -------------------------------------------------------------------------

/** One thing to do, not one vulnerability: "upgrade lodash" clears every lodash advisory. */
export interface ActionPlanItem {
  /** Stable within the module, so a later build can be matched to the same action. */
  key: string;
  kind: "upgrade" | "base-image" | "no-fix";
  /** What to do, in plain words. */
  title: string;
  /** Why, in plain words. */
  reason: string;
  urgency: Urgency;
  /** Lower comes first. */
  priority: number;
  /** Vulnerabilities this action clears. */
  clears: number;
  counts: SeverityCounts;
  usedInAttacks: number;
  remote: number;
  /** How big the change is: `patch` and `minor` are usually safe, `major` may need code changes. */
  size?: "patch" | "minor" | "major" | "rebuild" | "unknown";
  /** Where to change it: the manifest, the Dockerfile's FROM line. */
  where?: string;
  /** A line the developer can copy. */
  copyLine?: string;
  packageName?: string;
  fromVersion?: string;
  toVersion?: string;
  /** The advisories behind it, for the link to the full list. */
  vulnerabilityIds: string[];
  /** The earliest target date among its vulnerabilities, and the rule that set it. */
  dueAt?: string;
  dueRule?: string;
  /** Past `dueAt`. */
  late?: boolean;
  /** Some of its vulnerabilities appeared after the person's previous visit. */
  isNew?: boolean;
}

/** An action plan item, tagged with the module that contributed it. */
export interface ModuleActionPlanItem extends ActionPlanItem {
  moduleId: string;
}

export interface ActionPlanResponse {
  applicationId: string;
  name: string;
  /** The person's previous visit, which "new" is measured from. Null on a first visit. */
  previousVisitAt: string | null;
  /** True for administrators and for team leads of a squad this project belongs to. */
  canAcceptRisk: boolean;
  targets: TargetDates;
  status: ProjectStatus;
  reason: string;
  counts: ProjectUrgencyCounts;
  lastBuildAt: string | null;
  items: ModuleActionPlanItem[];
}

