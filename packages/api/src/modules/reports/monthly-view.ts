import {
  SEVERITY_ORDER,
  type ReportDelta,
  type ReportRunSummary,
  type ReportSnapshot,
  type SnapshotComponent,
  type VulnSeverity,
} from "@sbom/shared";

/**
 * Everything the monthly report states, derived from one snapshot and one delta.
 *
 * Pure, and separated from the renderer on purpose. A PDF can only be tested by parsing it
 * back out of a binary, which is enough to prove a heading appears and nowhere near enough
 * to prove a number is right. Deriving the figures here means the arithmetic that management
 * will act on is testable directly, and the renderer's job shrinks to placing text.
 *
 * Everything comes from the stored snapshot rather than from a fresh query, so a report
 * regenerated a year later prints exactly what it printed the day it was produced.
 */

/** Severity ladder, worst first, as every list in the report is read. */
const SEVERITY_DISPLAY: VulnSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "negligible",
  "unknown",
];

function rankOf(severity: string): number {
  return SEVERITY_ORDER[severity as VulnSeverity] ?? 0;
}

export interface SeverityMovement {
  severity: string;
  now: number;
  /** Null when there is no baseline. Zero would read as "all of these are new". */
  before: number | null;
  change: number | null;
}

export interface CauseBreakdown {
  label: string;
  count: number;
  /** What this cause means, in a sentence management can act on. */
  meaning: string;
}

export interface ApplicationRisk {
  id: string;
  name: string;
  /** Findings in the application's own dependencies. */
  appFindings: number;
  /** Findings inherited from the base image. */
  baseFindings: number;
  critical: number;
  high: number;
  /** Change in total findings since the baseline. Null when the app is new this period. */
  change: number | null;
}

export interface PackageExposure {
  name: string;
  version: string | null;
  ecosystem: string;
  scope: "app" | "os";
  /** How many applications carry this exact package with at least one finding. */
  applications: number;
  findings: number;
  worstSeverity: string;
}

export interface MonthlyReportView {
  run: ReportRunSummary;
  /** Null for the first report, which has nothing to compare against. */
  delta: ReportDelta | null;
  /**
   * Whether this report has a baseline to compare against.
   *
   * Read by the renderer to drop every comparison column rather than print zeroes. A first
   * report showing "Critical 82, last report 0, change +82" states that 82 critical findings
   * appeared this month, which is false and is the most alarming thing the document could
   * say. An absent baseline has to look absent.
   */
  comparable: boolean;

  headline: {
    applications: number;
    /** Findings in applications' own dependencies -- the ones a team can act on directly. */
    appFindings: number;
    /** Findings inherited from base images, fixed by rebuilding rather than by a team. */
    baseFindings: number;
    totalFindings: number;
    criticalAndHigh: number;
    resolved: number;
    introduced: number;
    reintroduced: number;
  };

  /**
   * The report's central caveat, present only when it applies.
   *
   * A changed vulnerability database means part of the movement below is the world changing
   * its mind rather than work anyone did, and the reader has to be told before they read a
   * single number.
   */
  databaseCaveat: string | null;

  /** One-paragraph summary in plain English, written so it can be read aloud in a meeting. */
  summary: string;

  resolvedByCause: CauseBreakdown[];
  introducedByCause: CauseBreakdown[];
  severityMovement: SeverityMovement[];

  applicationsAdded: Array<{ id: string; name: string }>;
  applicationsRemoved: Array<{ id: string; name: string }>;
  dependencyMovement: {
    added: number;
    removed: number;
    total: number;
    /** Null without a baseline, for the same reason as `SeverityMovement.before`. */
    previousTotal: number | null;
  };

  riskiestApplications: ApplicationRisk[];
  /** Packages ordered by how many applications they put at risk at once. */
  widestPackages: PackageExposure[];
  /** New findings this period, worst first, for the teams who have to act on them. */
  newFindings: Array<{
    applicationName: string;
    package: string;
    vulnerabilityId: string;
    severity: string;
    cause: string;
  }>;
}

const RESOLVED_CAUSE_LABELS: Record<string, { label: string; meaning: string }> = {
  "upgraded-or-removed": {
    label: "Fixed by upgrade or removal",
    meaning: "The vulnerable package has left the build. This is work the teams did.",
  },
  "advisory-withdrawn-or-rescored": {
    label: "Advisory withdrawn or re-scored",
    meaning: "The package is unchanged; the advisory changed. Nobody fixed anything.",
  },
  "application-removed": {
    label: "Application no longer tracked",
    meaning: "The findings left with the application; they were not resolved.",
  },
};

const INTRODUCED_CAUSE_LABELS: Record<string, { label: string; meaning: string }> = {
  "new-dependency": {
    label: "New or changed dependency",
    meaning: "A package entered a build carrying a known vulnerability.",
  },
  "newly-published-advisory": {
    label: "Newly published advisory",
    meaning: "The package was already in use; the advisory is new.",
  },
  "application-added": {
    label: "Newly tracked application",
    meaning: "Existing risk becoming visible for the first time, not new risk.",
  },
};

function countByCause(
  items: Array<{ cause: string }>,
  labels: Record<string, { label: string; meaning: string }>,
): CauseBreakdown[] {
  const counts = new Map<string, number>();
  for (const item of items) counts.set(item.cause, (counts.get(item.cause) ?? 0) + 1);

  /*
    Every cause is listed, including the ones at zero. A cause that vanishes from the table
    reads as though it cannot happen, and "advisory withdrawn: 0" is a meaningful statement:
    it tells the reader the fixes below are real.
  */
  return Object.entries(labels).map(([cause, meta]) => ({
    label: meta.label,
    meaning: meta.meaning,
    count: counts.get(cause) ?? 0,
  }));
}

/** Splits a finding key back into its parts. Mirrors `findingKey` in the differ. */
function parts(key: string): { applicationId: string; componentId: number; vulnerabilityId: string } | null {
  const first = key.indexOf("|");
  const second = key.indexOf("|", first + 1);
  if (first < 0 || second < 0) return null;
  return {
    applicationId: key.slice(0, first),
    componentId: Number(key.slice(first + 1, second)),
    vulnerabilityId: key.slice(second + 1),
  };
}

function packageLabel(component: SnapshotComponent | null): string {
  if (!component) return "unknown package";
  return component.version ? `${component.name} ${component.version}` : component.name;
}

/** How many findings each application had in the baseline, for the movement column. */
function findingsPerApplication(snapshot: ReportSnapshot): Map<string, number> {
  const counts = new Map<string, number>();
  for (const key of snapshot.findings) {
    const p = parts(key);
    if (!p) continue;
    counts.set(p.applicationId, (counts.get(p.applicationId) ?? 0) + 1);
  }
  return counts;
}

export function buildMonthlyView(input: {
  run: ReportRunSummary;
  snapshot: ReportSnapshot;
  delta: ReportDelta | null;
  baseline?: ReportSnapshot | undefined;
}): MonthlyReportView {
  const { run, snapshot, delta } = input;

  const components = new Map<number, SnapshotComponent>();
  for (const component of snapshot.components) components.set(component.id, component);

  const applications = new Map(snapshot.applications.map((a) => [a.id, a]));

  // --- per-application and per-package aggregation, in one pass over the findings ---
  const perApp = new Map<string, ApplicationRisk>();
  const perPackage = new Map<string, PackageExposure & { appIds: Set<string> }>();
  let appFindings = 0;
  let baseFindings = 0;
  let criticalAndHigh = 0;

  for (const key of snapshot.findings) {
    const p = parts(key);
    if (!p) continue;
    const component = components.get(p.componentId) ?? null;
    const severity = snapshot.severities[p.vulnerabilityId] ?? "unknown";
    const isBase = component?.scope === "os";

    if (isBase) baseFindings += 1;
    else appFindings += 1;
    if (severity === "critical" || severity === "high") criticalAndHigh += 1;

    const app = perApp.get(p.applicationId) ?? {
      id: p.applicationId,
      name: applications.get(p.applicationId)?.name ?? p.applicationId,
      appFindings: 0,
      baseFindings: 0,
      critical: 0,
      high: 0,
      change: null,
    };
    if (isBase) app.baseFindings += 1;
    else app.appFindings += 1;
    if (severity === "critical") app.critical += 1;
    if (severity === "high") app.high += 1;
    perApp.set(p.applicationId, app);

    if (component) {
      // Keyed by exact name and version: openssl 3.0.11 and openssl 3.0.14 are different
      // exposures, and merging them would overstate how many applications one upgrade fixes.
      const pkgKey = `${component.ecosystem}|${component.name}|${component.version ?? ""}`;
      const pkg = perPackage.get(pkgKey) ?? {
        name: component.name,
        version: component.version,
        ecosystem: component.ecosystem,
        scope: component.scope,
        applications: 0,
        findings: 0,
        worstSeverity: "unknown",
        appIds: new Set<string>(),
      };
      pkg.findings += 1;
      pkg.appIds.add(p.applicationId);
      if (rankOf(severity) > rankOf(pkg.worstSeverity)) pkg.worstSeverity = severity;
      perPackage.set(pkgKey, pkg);
    }
  }

  const baselineCounts = input.baseline ? findingsPerApplication(input.baseline) : null;
  if (baselineCounts) {
    for (const app of perApp.values()) {
      const before = baselineCounts.get(app.id);
      // Null rather than the full count for an application that did not exist last month:
      // "+312" in a movement column reads as a regression rather than as new visibility.
      app.change = before === undefined ? null : app.appFindings + app.baseFindings - before;
    }
  }

  const riskiestApplications = [...perApp.values()].sort(
    (a, b) =>
      b.critical - a.critical ||
      b.high - a.high ||
      b.appFindings + b.baseFindings - (a.appFindings + a.baseFindings) ||
      a.name.localeCompare(b.name),
  );

  const widestPackages = [...perPackage.values()]
    .map(({ appIds, ...pkg }) => ({ ...pkg, applications: appIds.size }))
    .sort(
      (a, b) =>
        b.applications - a.applications ||
        rankOf(b.worstSeverity) - rankOf(a.worstSeverity) ||
        b.findings - a.findings ||
        a.name.localeCompare(b.name),
    );

  const severityMovement: SeverityMovement[] = SEVERITY_DISPLAY.map((severity) => {
    const movement = delta?.findings.bySeverity[severity];
    const now = movement?.now ?? snapshot.totals.bySeverity[severity] ?? 0;
    const before = delta ? (movement?.before ?? 0) : null;
    return { severity, now, before, change: before === null ? null : now - before };
  }).filter((row) => row.now > 0 || (row.before ?? 0) > 0);

  const resolved = delta?.findings.resolved ?? [];
  const introduced = delta?.findings.introduced ?? [];

  const newFindings = [...introduced]
    .sort(
      (a, b) =>
        rankOf(b.severity) - rankOf(a.severity) ||
        a.applicationName.localeCompare(b.applicationName),
    )
    .map((f) => ({
      applicationName: f.applicationName,
      package: packageLabel(f.component),
      vulnerabilityId: f.vulnerabilityId,
      severity: f.severity,
      cause: INTRODUCED_CAUSE_LABELS[f.cause]?.label ?? f.cause,
    }));

  const genuineFixes = resolved.filter((f) => f.cause === "upgraded-or-removed").length;

  return {
    run,
    delta,
    comparable: delta !== null,
    headline: {
      applications: snapshot.totals.applications,
      appFindings,
      baseFindings,
      totalFindings: snapshot.totals.findings,
      criticalAndHigh,
      resolved: resolved.length,
      introduced: introduced.length,
      reintroduced: delta?.findings.reintroduced.length ?? 0,
    },
    databaseCaveat: delta?.databaseChanged
      ? "The vulnerability database was updated during this period. Some of the movement below reflects advisories being published, withdrawn or re-scored rather than changes to the estate, and each figure is attributed accordingly."
      : null,
    summary: summarise({
      delta,
      genuineFixes,
      appFindings,
      baseFindings,
      periodLabel: run.periodLabel,
    }),
    resolvedByCause: countByCause(resolved, RESOLVED_CAUSE_LABELS),
    introducedByCause: countByCause(introduced, INTRODUCED_CAUSE_LABELS),
    severityMovement,
    applicationsAdded: delta?.applications.added ?? [],
    applicationsRemoved: delta?.applications.removed ?? [],
    dependencyMovement: {
      added: delta?.dependencies.added ?? 0,
      removed: delta?.dependencies.removed ?? 0,
      total: delta?.dependencies.total ?? countPairs(snapshot),
      previousTotal: delta?.dependencies.previousTotal ?? null,
    },
    riskiestApplications,
    widestPackages,
    newFindings,
  };
}

function countPairs(snapshot: ReportSnapshot): number {
  let total = 0;
  for (const list of Object.values(snapshot.dependencies)) total += list.length;
  return total;
}

/**
 * The paragraph a manager reads if they read nothing else.
 *
 * Written to be defensible rather than flattering. When most of a fall came from the
 * vulnerability database rather than from upgrades, this says so in the same sentence as the
 * headline figure, because a caveat further down the page does not travel with the number
 * when it is quoted in a meeting.
 */
function summarise(input: {
  delta: ReportDelta | null;
  genuineFixes: number;
  appFindings: number;
  baseFindings: number;
  periodLabel: string;
}): string {
  const { delta, genuineFixes, appFindings, baseFindings } = input;
  const total = appFindings + baseFindings;

  if (!delta) {
    return `This is the first report in the series, so there is nothing to compare it against. The estate currently carries ${total.toLocaleString("en-US")} open findings, of which ${appFindings.toLocaleString("en-US")} are in applications' own dependencies and ${baseFindings.toLocaleString("en-US")} come from base images. Next month's report will show movement against these figures.`;
  }

  const resolved = delta.findings.resolved.length;
  const introduced = delta.findings.introduced.length;
  const net = delta.findings.total - delta.findings.previousTotal;
  const direction = net === 0 ? "unchanged" : net < 0 ? "down" : "up";

  const sentences: string[] = [];
  sentences.push(
    `Open findings are ${direction}${net === 0 ? "" : ` by ${Math.abs(net).toLocaleString("en-US")}`} since the last report, at ${delta.findings.total.toLocaleString("en-US")}. ${resolved.toLocaleString("en-US")} findings were resolved and ${introduced.toLocaleString("en-US")} appeared.`,
  );

  if (resolved > 0) {
    const share = Math.round((genuineFixes / resolved) * 100);
    sentences.push(
      genuineFixes === resolved
        ? `All of the resolved findings were fixed by upgrading or removing the affected package.`
        : genuineFixes === 0
          ? `None of them were fixed by upgrading or removing a package; the reasons are attributed below.`
          : `${genuineFixes.toLocaleString("en-US")} of those (${share}%) were fixed by upgrading or removing the affected package; the rest are attributed below.`,
    );
  }

  if (delta.findings.reintroduced.length > 0) {
    sentences.push(
      `${delta.findings.reintroduced.length.toLocaleString("en-US")} had been resolved in an earlier period and have returned.`,
    );
  }

  sentences.push(
    `${baseFindings.toLocaleString("en-US")} of the ${total.toLocaleString("en-US")} open findings come from base images rather than from application dependencies, and are addressed by rebuilding on a newer image rather than by individual teams.`,
  );

  return sentences.join(" ");
}
