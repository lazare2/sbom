import type {
  AttentionFlag,
  AttentionProject,
  AttentionSettings,
  BuildDeltaCounts,
  BuildDeltaPair,
  BuildDeltaSection,
  BuildDeltaSide,
  ProgressRollup,
  ProjectBuildDeltas,
  ProjectBuilds,
  ProjectProgress,
} from "@sbom/shared";

/**
 * The progress, attention and build-to-build rules, as pure functions.
 *
 * The queries fetch facts - builds, per-pair finding movements, ages - and everything that
 * turns them into a judgement lives here, where it can be tested without a database. These are
 * the figures that name a team as needing attention, so every rule is stated where it is
 * applied, and every flag carries the sentence that explains it.
 */

const DAY_MS = 86_400_000;
const round1 = (n: number) => Math.round(n * 10) / 10;

export interface BuildFact {
  applicationId: string;
  scanId: string;
  createdAt: Date;
  sha: string;
  buildNumber: string | null;
  /** The build has a frozen summary, i.e. every package in it has been matched. */
  assessed: boolean;
  /** Critical + high findings in this build by today's database (both halves); null if unassessed. */
  criticalHigh: number | null;
}

export interface BuildPair {
  applicationId: string;
  from: BuildFact;
  to: BuildFact;
  /** The later build arrived inside the reporting window. */
  inWindow: boolean;
  /** The later build is the project's latest distinct build. */
  isLast: boolean;
  /** Both builds have been matched, so their findings can be compared. */
  comparable: boolean;
}

const byTime = (a: BuildFact, b: BuildFact) =>
  a.createdAt.getTime() - b.createdAt.getTime() || (a.scanId < b.scanId ? -1 : a.scanId > b.scanId ? 1 : 0);

/**
 * Consecutive build pairs for one project, identical rebuilds skipped.
 *
 * A build whose SBOM is byte-identical to the build before it changed nothing - comparing it
 * would only add a zero row and pull every average towards zero - so it is dropped, and the next
 * build is compared with the last one that differed. Counted, so the page can say how many.
 */
export function buildPairs(builds: readonly BuildFact[], periodStart: Date): {
  pairs: BuildPair[];
  identicalSkippedInWindow: number;
} {
  const sorted = [...builds].sort(byTime);
  const distinct: BuildFact[] = [];
  let identicalSkippedInWindow = 0;
  for (let i = 0; i < sorted.length; i++) {
    const build = sorted[i]!;
    const previous = sorted[i - 1];
    if (previous && previous.sha === build.sha) {
      if (build.createdAt >= periodStart) identicalSkippedInWindow += 1;
      continue;
    }
    distinct.push(build);
  }

  const pairs: BuildPair[] = [];
  for (let i = 1; i < distinct.length; i++) {
    const from = distinct[i - 1]!;
    const to = distinct[i]!;
    pairs.push({
      applicationId: to.applicationId,
      from,
      to,
      inWindow: to.createdAt >= periodStart,
      isLast: i === distinct.length - 1,
      comparable: from.assessed && to.assessed,
    });
  }
  return { pairs, identicalSkippedInWindow };
}

/**
 * How often a project builds: the mean gap between its builds inside the cadence window.
 *
 * Every build counts here, identical rebuilds included - a pipeline that ran is evidence the
 * project is alive, which is the question this answers. (The build-to-build table skips them for
 * the opposite reason: they cannot have changed anything.)
 */
export function buildCadence(
  builds: readonly BuildFact[],
  now: Date,
  periodStart: Date,
  cadenceWindowDays: number,
): ProjectBuilds {
  const sorted = [...builds].sort(byTime);
  const cadenceStart = new Date(now.getTime() - cadenceWindowDays * DAY_MS);
  const recent = sorted.filter((b) => b.createdAt >= cadenceStart);
  const last = sorted[sorted.length - 1] ?? null;
  const average =
    recent.length >= 2
      ? (recent[recent.length - 1]!.createdAt.getTime() - recent[0]!.createdAt.getTime()) / DAY_MS / (recent.length - 1)
      : null;
  return {
    inWindow: sorted.filter((b) => b.createdAt >= periodStart).length,
    lastBuildAt: last ? last.createdAt.toISOString() : null,
    daysSinceLastBuild: last ? Math.floor((now.getTime() - last.createdAt.getTime()) / DAY_MS) : null,
    cadenceBuilds: recent.length,
    averageDaysBetweenBuilds: average === null ? null : round1(average),
  };
}

function plural(n: number, word: string, many = `${word}s`): string {
  return `${n} ${n === 1 ? word : many}`;
}

function days(n: number): string {
  return plural(round1(n), "day");
}

/**
 * Whether a project is overdue for a build, and the sentence that says why.
 *
 * Average mode judges a project against its own rhythm, with an optional multiplier for slack
 * and a floor so a project that builds several times a day is not flagged after a quiet
 * afternoon. A project with too little recent history to have a rhythm falls back to the fixed
 * limit, and the reason says so rather than presenting a fixed limit as its own average.
 */
export function buildOverdueFlag(builds: ProjectBuilds, settings: AttentionSettings): AttentionFlag | null {
  if (builds.lastBuildAt === null || builds.daysSinceLastBuild === null) {
    return { kind: "build_overdue", reason: "No build has been received for this project yet." };
  }
  const since = builds.daysSinceLastBuild;

  if (settings.buildOverdueMode === "fixed") {
    return since > settings.fixedDays
      ? { kind: "build_overdue", reason: `No build in ${days(since)}; the limit is ${days(settings.fixedDays)}.` }
      : null;
  }

  const average = builds.averageDaysBetweenBuilds;
  if (builds.cadenceBuilds < settings.minimumBuilds || average === null) {
    return since > settings.fixedDays
      ? {
          kind: "build_overdue",
          reason:
            `Not enough recent history to judge its usual pace (${plural(builds.cadenceBuilds, "build")} in the last ` +
            `${days(settings.cadenceWindowDays)}; ${settings.minimumBuilds} needed), so the fixed limit of ${days(settings.fixedDays)} ` +
            `applies. Last build ${days(since)} ago.`,
        }
      : null;
  }

  const scaled = settings.useMultiplier ? average * settings.multiplier : average;
  const limit = Math.max(settings.minimumDays, scaled);
  if (since <= limit) return null;

  const how =
    settings.useMultiplier && scaled >= settings.minimumDays
      ? `flagged after ${settings.multiplier}x that, ${days(limit)}`
      : scaled < settings.minimumDays
        ? `flagged after the ${days(settings.minimumDays)} minimum`
        : `flagged after ${days(limit)}`;
  return {
    kind: "build_overdue",
    reason:
      `Usually built every ${days(average)} (${plural(builds.cadenceBuilds, "build")} in the last ` +
      `${days(settings.cadenceWindowDays)}); ${how}. Last build ${days(since)} ago.`,
  };
}

export interface CurrentRiskFacts {
  /** Known-exploited advisories open in the current build. */
  knownExploited: { count: number; ids: string[] } | null;
  /** Critical findings with a fix available, with how long each has been open, in days. */
  criticalFixable: Array<{ vulnerabilityId: string; packageName: string; openDays: number }>;
}

/** Every flag that applies to one project, most urgent first. */
export function attentionFlags(
  project: ProjectProgress,
  risk: CurrentRiskFacts | undefined,
  settings: AttentionSettings,
): AttentionFlag[] {
  const flags: AttentionFlag[] = [];

  if (risk?.knownExploited && risk.knownExploited.count > 0) {
    const { count, ids } = risk.knownExploited;
    const named = ids.slice(0, 3).join(", ");
    flags.push({
      kind: "known_exploited",
      reason:
        `${plural(count, "known-exploited advisory", "known-exploited advisories")} open in the current build ` +
        `(${named}${count > 3 ? ", …" : ""}). These are on CISA's list of vulnerabilities being exploited in the wild.`,
    });
  }

  const overdue = (risk?.criticalFixable ?? []).filter((f) => f.openDays > settings.criticalFixDays);
  if (overdue.length > 0) {
    const oldest = overdue.reduce((a, b) => (b.openDays > a.openDays ? b : a));
    flags.push({
      kind: "critical_fix_overdue",
      reason:
        `${plural(overdue.length, "critical finding")} with a fix available open longer than ${days(settings.criticalFixDays)}; ` +
        `the oldest is ${oldest.vulnerabilityId} in ${oldest.packageName}, open ${days(oldest.openDays)}.`,
    });
  }

  const overdueBuild = buildOverdueFlag(project.builds, settings);
  if (overdueBuild) flags.push(overdueBuild);

  const v = project.vulnerabilities;
  if (v && v.comparedBuilds > 0 && v.net > 0) {
    flags.push({
      kind: "vulnerabilities_rising",
      reason:
        `Builds in this window introduced ${plural(v.introduced, "finding")} and fixed ${v.fixed} ` +
        `(net +${v.net}${v.introducedCriticalHigh > 0 ? `, ${v.introducedCriticalHigh} of them critical or high` : ""}).`,
    });
  }
  return flags;
}

export function attentionProjects(
  projects: readonly ProjectProgress[],
  risk: ReadonlyMap<string, CurrentRiskFacts>,
  settings: AttentionSettings,
): AttentionProject[] {
  const order: Record<AttentionFlag["kind"], number> = {
    known_exploited: 0,
    critical_fix_overdue: 1,
    vulnerabilities_rising: 2,
    build_overdue: 3,
  };
  return projects
    .map((p) => ({
      applicationId: p.applicationId,
      name: p.name,
      squads: p.squads,
      tribes: p.tribes,
      flags: attentionFlags(p, risk.get(p.applicationId), settings),
    }))
    .filter((p) => p.flags.length > 0)
    .sort(
      (a, b) =>
        Math.min(...a.flags.map((f) => order[f.kind])) - Math.min(...b.flags.map((f) => order[f.kind])) ||
        b.flags.length - a.flags.length ||
        a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
    );
}

// ---------------------------------------------------------------------------
// build-to-build
// ---------------------------------------------------------------------------

const zeroCounts = (): BuildDeltaCounts => ({ total: 0, critical: 0, high: 0 });
const zeroSide = (): BuildDeltaSide => ({ fixed: zeroCounts(), introduced: zeroCounts(), unchanged: zeroCounts() });
export const zeroPair = (): BuildDeltaPair => ({ app: zeroSide(), os: zeroSide() });

function mapPair(pairs: readonly BuildDeltaPair[], fn: (values: number[]) => number): BuildDeltaPair {
  const out = zeroPair();
  for (const half of ["app", "os"] as const) {
    for (const movement of ["fixed", "introduced", "unchanged"] as const) {
      for (const level of ["total", "critical", "high"] as const) {
        out[half][movement][level] = fn(pairs.map((p) => p[half][movement][level]));
      }
    }
  }
  return out;
}

const mean = (values: number[]) => (values.length === 0 ? 0 : round1(values.reduce((a, b) => a + b, 0) / values.length));

/** Averages per build pair for one project, plus its latest pair. */
export function projectBuildDeltas(
  applicationId: string,
  name: string,
  pairs: readonly BuildPair[],
  deltas: ReadonlyMap<string, BuildDeltaPair>,
): ProjectBuildDeltas {
  const inWindow = pairs.filter((p) => p.inWindow && p.comparable);
  const windowDeltas = inWindow.map((p) => deltas.get(p.to.scanId) ?? zeroPair());
  const last = pairs.find((p) => p.isLast && p.comparable);
  return {
    applicationId,
    name,
    comparedBuilds: inWindow.length,
    average: windowDeltas.length > 0 ? mapPair(windowDeltas, mean) : null,
    last: last
      ? {
          ...(deltas.get(last.to.scanId) ?? zeroPair()),
          scanId: last.to.scanId,
          buildNumber: last.to.buildNumber,
          at: last.to.createdAt.toISOString(),
        }
      : null,
  };
}

export function buildDeltaSection(projects: ProjectBuildDeltas[], identicalRebuildsSkipped: number): BuildDeltaSection {
  const averaged = projects.flatMap((p) => (p.average ? [p.average] : []));
  return {
    projects,
    estateAverage: averaged.length > 0 ? mapPair(averaged, mean) : null,
    comparedBuilds: projects.reduce((n, p) => n + p.comparedBuilds, 0),
    identicalRebuildsSkipped,
  };
}

// ---------------------------------------------------------------------------
// progress
// ---------------------------------------------------------------------------

/** Sums a project's in-window pairs into its fixed / introduced figures. */
export function windowMovement(
  pairs: readonly BuildPair[],
  deltas: ReadonlyMap<string, BuildDeltaPair>,
): { compared: number; fixed: number; introduced: number; fixedCH: number; introducedCH: number } {
  let fixed = 0;
  let introduced = 0;
  let fixedCH = 0;
  let introducedCH = 0;
  let compared = 0;
  for (const pair of pairs) {
    if (!pair.inWindow || !pair.comparable) continue;
    compared += 1;
    const d = deltas.get(pair.to.scanId) ?? zeroPair();
    for (const half of [d.app, d.os]) {
      fixed += half.fixed.total;
      introduced += half.introduced.total;
      fixedCH += half.fixed.critical + half.fixed.high;
      introducedCH += half.introduced.critical + half.introduced.high;
    }
  }
  return { compared, fixed, introduced, fixedCH, introducedCH };
}

/** The last assessed build strictly before the window: the "at the start" reference. */
export function baselineBuild(builds: readonly BuildFact[], periodStart: Date): BuildFact | null {
  const before = [...builds].filter((b) => b.createdAt < periodStart).sort(byTime);
  return before[before.length - 1] ?? null;
}

/** Rolls projects up to squads or tribes. Projects on none form one unnamed row. */
export function rollup(
  projects: readonly ProjectProgress[],
  key: "squads" | "tribes",
  flagged: ReadonlySet<string>,
): ProgressRollup[] {
  const groups = new Map<string | null, ProjectProgress[]>();
  const canonical = new Map<string, string>();
  for (const p of projects) {
    const names = p[key].length > 0 ? p[key] : [null];
    for (const raw of names) {
      // Case-insensitive, like every squad and tribe filter; spelled as first seen.
      const lower = raw === null ? null : raw.toLowerCase();
      if (lower !== null && !canonical.has(lower)) canonical.set(lower, raw!);
      const k = lower === null ? null : canonical.get(lower)!;
      const list = groups.get(k) ?? [];
      list.push(p);
      groups.set(k, list);
    }
  }

  const rows: ProgressRollup[] = [];
  for (const [name, members] of groups) {
    const cadences = members.flatMap((m) =>
      m.builds.averageDaysBetweenBuilds === null ? [] : [m.builds.averageDaysBetweenBuilds],
    );
    const withVulns = members.flatMap((m) => (m.vulnerabilities ? [m.vulnerabilities] : []));
    const timed = withVulns.filter((v) => v.meanDaysToFix !== null && v.fixesTimed > 0);
    const timedFixes = timed.reduce((n, v) => n + v.fixesTimed, 0);
    const changes = withVulns.flatMap((v) => (v.criticalHighChange === null ? [] : [v.criticalHighChange]));
    rows.push({
      name,
      applications: members.length,
      buildsInWindow: members.reduce((n, m) => n + m.builds.inWindow, 0),
      averageDaysBetweenBuilds: cadences.length > 0 ? mean(cadences) : null,
      flaggedApplications: members.filter((m) => flagged.has(m.applicationId)).length,
      vulnerabilities:
        members.length > 0 && members.every((m) => m.vulnerabilities === null)
          ? null
          : {
              comparedBuilds: withVulns.reduce((n, v) => n + v.comparedBuilds, 0),
              fixed: withVulns.reduce((n, v) => n + v.fixed, 0),
              introduced: withVulns.reduce((n, v) => n + v.introduced, 0),
              net: withVulns.reduce((n, v) => n + v.net, 0),
              openCritical: withVulns.reduce((n, v) => n + (v.openCritical ?? 0), 0),
              openHigh: withVulns.reduce((n, v) => n + (v.openHigh ?? 0), 0),
              criticalHighChange: changes.length > 0 ? changes.reduce((a, b) => a + b, 0) : null,
              // Weighted by fixes, so a squad's figure is the mean over its fixes, not over projects.
              meanDaysToFix:
                timedFixes > 0
                  ? round1(timed.reduce((n, v) => n + v.meanDaysToFix! * v.fixesTimed, 0) / timedFixes)
                  : null,
            },
    });
  }
  return rows.sort(
    (a, b) =>
      (a.name === null ? 1 : 0) - (b.name === null ? 1 : 0) ||
      (a.name ?? "").localeCompare(b.name ?? "", undefined, { sensitivity: "base" }),
  );
}
