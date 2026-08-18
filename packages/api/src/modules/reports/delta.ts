import type {
  FindingMovement,
  IntroducedCause,
  IntroducedFinding,
  ReportDelta,
  ReportSnapshot,
  ResolvedCause,
  ResolvedFinding,
} from "@sbom/shared";

/**
 * Diffing two snapshots into a report a manager can act on.
 *
 * Pure functions over two snapshots, with no database access, because this is where the
 * report can most easily lie and pure code is the only kind that can be exhaustively tested.
 * Every number the report prints comes from here.
 */

/** The identity that makes a finding the same finding next month. */
export function findingKey(
  applicationId: string,
  componentId: number,
  vulnerabilityId: string,
): string {
  return applicationId + "|" + componentId + "|" + vulnerabilityId;
}

/** Splits a flat finding key back into its parts. */
function parseKey(
  key: string,
): { applicationId: string; componentId: number; vulnerabilityId: string } | null {
  const first = key.indexOf("|");
  const second = key.indexOf("|", first + 1);
  if (first < 0 || second < 0) return null;
  const componentId = Number(key.slice(first + 1, second));
  if (!Number.isFinite(componentId)) return null;
  return {
    applicationId: key.slice(0, first),
    componentId,
    vulnerabilityId: key.slice(second + 1),
  };
}

function indexBy<T, K extends string | number>(items: T[], key: (item: T) => K): Map<K, T> {
  const map = new Map<K, T>();
  for (const item of items) map.set(key(item), item);
  return map;
}

/** Every (application, component) pair in a snapshot, as a flat set. */
function dependencyPairs(snapshot: ReportSnapshot): Set<string> {
  const pairs = new Set<string>();
  for (const [applicationId, componentIds] of Object.entries(snapshot.dependencies)) {
    for (const componentId of componentIds) pairs.add(applicationId + "|" + componentId);
  }
  return pairs;
}

/**
 * Compares two snapshots, attributing every movement to a cause.
 *
 * `previous` is the report before the baseline, used only to recognise a reintroduction:
 * something absent last month but present both now and the month before is a regression
 * rather than a new problem, and the two deserve different attention. Omitted for the first
 * two reports, where no such history exists and claiming otherwise would be invention.
 */
export function computeDelta(
  baseline: ReportSnapshot,
  current: ReportSnapshot,
  previous?: ReportSnapshot | undefined,
): ReportDelta {
  const baselineApps = indexBy(baseline.applications, (a) => a.id);
  const currentApps = indexBy(current.applications, (a) => a.id);
  const currentComponents = indexBy(current.components, (c) => c.id);
  const baselineComponents = indexBy(baseline.components, (c) => c.id);

  const baselineFindings = new Set(baseline.findings);
  const currentFindings = new Set(current.findings);
  const previousFindings = previous ? new Set(previous.findings) : null;

  const baselinePairs = dependencyPairs(baseline);
  const currentPairs = dependencyPairs(current);

  const resolved: ResolvedFinding[] = [];
  for (const key of baselineFindings) {
    if (currentFindings.has(key)) continue;
    const parts = parseKey(key);
    if (!parts) continue;

    /*
      Order matters here. An application that left the estate takes its findings with it,
      and reporting those as "upgraded" would credit a team for a deletion. Only once the
      application is known to still exist does the presence of the package decide between a
      real fix and the advisory changing underneath it.
    */
    const cause: ResolvedCause = !currentApps.has(parts.applicationId)
      ? "application-removed"
      : currentPairs.has(parts.applicationId + "|" + parts.componentId)
        ? "advisory-withdrawn-or-rescored"
        : "upgraded-or-removed";

    resolved.push({
      applicationId: parts.applicationId,
      applicationName: baselineApps.get(parts.applicationId)?.name ?? parts.applicationId,
      component: baselineComponents.get(parts.componentId) ?? null,
      vulnerabilityId: parts.vulnerabilityId,
      severity: baseline.severities[parts.vulnerabilityId] ?? "unknown",
      cause,
    });
  }

  const introduced: IntroducedFinding[] = [];
  const reintroduced: FindingMovement[] = [];
  for (const key of currentFindings) {
    if (baselineFindings.has(key)) continue;
    const parts = parseKey(key);
    if (!parts) continue;

    const movement: FindingMovement = {
      applicationId: parts.applicationId,
      applicationName: currentApps.get(parts.applicationId)?.name ?? parts.applicationId,
      component: currentComponents.get(parts.componentId) ?? null,
      vulnerabilityId: parts.vulnerabilityId,
      severity: current.severities[parts.vulnerabilityId] ?? "unknown",
    };

    const cause: IntroducedCause = !baselineApps.has(parts.applicationId)
      ? "application-added"
      : baselinePairs.has(parts.applicationId + "|" + parts.componentId)
        ? "newly-published-advisory"
        : "new-dependency";

    introduced.push({ ...movement, cause });

    /*
      Counted in addition to being introduced, not instead of it. The introduced total has
      to stay the sum of its causes or the report stops adding up; a regression is a
      property of a finding rather than a fourth category alongside them.
    */
    if (previousFindings?.has(key)) reintroduced.push(movement);
  }

  const bySeverity: Record<string, { now: number; before: number }> = {};
  for (const [severity, count] of Object.entries(current.totals.bySeverity)) {
    bySeverity[severity] = { now: count, before: baseline.totals.bySeverity[severity] ?? 0 };
  }
  for (const [severity, count] of Object.entries(baseline.totals.bySeverity)) {
    // A severity that vanished entirely still has to appear, showing its fall to zero.
    // Dropping it would quietly remove the best news in the report.
    if (!bySeverity[severity]) bySeverity[severity] = { now: 0, before: count };
  }

  const added = current.applications.filter((a) => !baselineApps.has(a.id));
  const removed = baseline.applications.filter((a) => !currentApps.has(a.id));

  let pairsAdded = 0;
  for (const pair of currentPairs) if (!baselinePairs.has(pair)) pairsAdded += 1;
  let pairsRemoved = 0;
  for (const pair of baselinePairs) if (!currentPairs.has(pair)) pairsRemoved += 1;

  return {
    /*
      Compared as instants rather than by identity: re-downloading the same build is not a
      change, and reporting it as one would attach a caveat to a report that needs none.
    */
    databaseChanged: baseline.vulnDbBuiltAt !== current.vulnDbBuiltAt,
    baselineDbBuiltAt: baseline.vulnDbBuiltAt,
    currentDbBuiltAt: current.vulnDbBuiltAt,
    applications: {
      added: added.map((a) => ({ id: a.id, name: a.name })),
      removed: removed.map((a) => ({ id: a.id, name: a.name })),
      total: current.totals.applications,
      previousTotal: baseline.totals.applications,
    },
    dependencies: {
      added: pairsAdded,
      removed: pairsRemoved,
      total: currentPairs.size,
      previousTotal: baselinePairs.size,
    },
    findings: {
      resolved,
      introduced,
      reintroduced,
      total: current.totals.findings,
      previousTotal: baseline.totals.findings,
      bySeverity,
    },
  };
}
