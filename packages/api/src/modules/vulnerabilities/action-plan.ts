import {
  EMPTY_SEVERITY_COUNTS,
  findingUrgency,
  type ActionPlanItem,
  type ProjectUrgencyCounts,
  type SeverityCounts,
  type Urgency,
  type VulnSeverity,
} from "@sbom/shared";
import { attackVectorLetter } from "./attack-vector.js";
import { compareVersions, normalizeVersion, planPackages, type FindingInput } from "./fix-advisor.js";

/**
 * A project's action plan, from the vulnerabilities in its current build.
 *
 * One line per thing to do, not per vulnerability:
 *
 *   - each application package with a fix: "upgrade lodash from 4.17.15 to 4.17.21", clearing
 *     every advisory against it at once (the version is the fix advisor's minimum);
 *   - the whole base image: one "rebuild on an up-to-date base image", because a base image is
 *     fixed by rebuilding, not by upgrading its packages one by one;
 *   - what has no fix yet: one closing line, since there is nothing to do but wait.
 *
 * Every vulnerability lands in exactly one line, so the lines add up to the project's
 * vulnerability list (accepted risks left out) - which the tests and the live check hold to.
 * Pure: the service feeds it rows, so it can be tested without a database.
 */

export interface PlanFinding {
  componentId: number;
  name: string;
  version: string | null;
  ecosystem: string;
  purl: string | null;
  origin: "app" | "os";
  vulnerabilityId: string;
  severity: VulnSeverity;
  knownExploited: boolean;
  fixState: string;
  fixVersions: string[];
  cvssVector: string | null;
  /** Where the package sits: manifest or file paths, from the SBOM. */
  paths: string[];
  /** The direct dependency that brought it in, when it is transitive. */
  pulledInBy: string[];
}

export interface PlanContext {
  /** The base image's distribution, e.g. "Debian GNU/Linux 12 (bookworm)". */
  osPretty: string | null;
  imageRef: string | null;
}

const URGENCY_RANK: Record<Urgency, number> = { now: 0, soon: 1, later: 2, none: 3 };
const SEVERITY_ORDER: VulnSeverity[] = ["critical", "high", "medium", "low", "negligible", "unknown"];

export function isRemote(f: { cvssVector: string | null }): boolean {
  return attackVectorLetter(f.cvssVector) === "N";
}

export function urgencyOf(f: PlanFinding): Urgency {
  return findingUrgency({
    fixable: f.fixState === "fixed",
    usedInAttacks: f.knownExploited,
    severity: f.severity,
    remote: isRemote(f),
  });
}

/** The counts a project's status is computed from. */
export function urgencyCounts(findings: readonly PlanFinding[]): ProjectUrgencyCounts {
  const c: ProjectUrgencyCounts = { total: 0, now: 0, nowUsedInAttacks: 0, soon: 0, later: 0, none: 0, noneSerious: 0 };
  for (const f of findings) {
    c.total += 1;
    const u = urgencyOf(f);
    c[u] += 1;
    if (u === "now" && f.knownExploited) c.nowUsedInAttacks += 1;
    if (u === "none" && (f.severity === "critical" || f.severity === "high")) c.noneSerious += 1;
  }
  return c;
}

function countsOf(findings: readonly PlanFinding[]): SeverityCounts {
  const counts = { ...EMPTY_SEVERITY_COUNTS };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

function mostUrgent(findings: readonly PlanFinding[]): Urgency {
  return findings.map(urgencyOf).sort((a, b) => URGENCY_RANK[a] - URGENCY_RANK[b])[0] ?? "none";
}

/** "1 used in real attacks, 2 critical, 3 high" - what an action clears, worst first. */
export function describeFindings(findings: readonly PlanFinding[]): string {
  const parts: string[] = [];
  const attacks = findings.filter((f) => f.knownExploited).length;
  if (attacks > 0) parts.push(`${attacks} used in real attacks`);
  const counts = countsOf(findings);
  for (const s of SEVERITY_ORDER) {
    if (counts[s] === 0) continue;
    const remote = findings.filter((f) => f.severity === s && isRemote(f)).length;
    const label = s === "unknown" ? "of unknown severity" : s;
    parts.push(`${counts[s]} ${label}${(s === "critical" || s === "high") && remote > 0 ? ` (${remote} remote)` : ""}`);
  }
  return parts.join(", ");
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** How big a version change is, from the first two numbers. */
export function changeSize(from: string | null, to: string | null): "patch" | "minor" | "major" | "unknown" {
  const nums = (v: string | null) => (normalizeVersion(v ?? "") ?? "").match(/\d+/g)?.map(Number) ?? [];
  const a = nums(from);
  const b = nums(to);
  if (a.length === 0 || b.length === 0) return "unknown";
  if (a[0] !== b[0]) return "major";
  if ((a[1] ?? 0) !== (b[1] ?? 0)) return "minor";
  return "patch";
}

/**
 * The line to copy for an upgrade, in the package manager's own words. Null where there is no
 * single obvious command (the developer then has the version and the place to change it).
 */
export function upgradeLine(ecosystem: string, name: string, version: string, purl: string | null): string | null {
  const eco = ecosystem.toLowerCase();
  switch (eco) {
    case "npm":
      return `npm install ${name}@${version}`;
    case "pypi":
    case "python":
      return `${name}>=${version}`;
    case "maven": {
      // purl: pkg:maven/group/artifact@version
      const m = /^pkg:maven\/([^/]+)\/([^@?#]+)/.exec(purl ?? "");
      const group = m?.[1] ?? name.split(":")[0] ?? name;
      const artifact = m?.[2] ?? name.split(":").pop() ?? name;
      return `<dependency><groupId>${group}</groupId><artifactId>${artifact}</artifactId><version>${version}</version></dependency>`;
    }
    case "golang":
    case "go":
    case "go-module":
      return `go get ${name}@${version.startsWith("v") ? version : `v${version}`}`;
    case "nuget":
      return `dotnet add package ${name} --version ${version}`;
    case "gem":
    case "rubygems":
      return `gem "${name}", ">= ${version}"`;
    case "cargo":
    case "rust-crate":
      return `cargo update -p ${name} --precise ${version}`;
    case "composer":
    case "php-composer":
      return `composer require ${name}:^${version}`;
    default:
      return null;
  }
}

/** Builds the plan. Items come back unsorted by module; the frame sorts by priority. */
export function buildActionPlan(findings: readonly PlanFinding[], context: PlanContext): ActionPlanItem[] {
  const items: ActionPlanItem[] = [];
  const fixable = (f: PlanFinding) => f.fixState === "fixed";
  const noFix: PlanFinding[] = findings.filter((f) => !fixable(f));

  // --- application packages: one upgrade each ---------------------------------------
  const appFixable = findings.filter((f) => f.origin === "app" && fixable(f));
  const byPackage = new Map<string, PlanFinding[]>();
  for (const f of appFixable) {
    const key = `${f.ecosystem.toLowerCase()}:${f.name.toLowerCase()}`;
    const list = byPackage.get(key);
    if (list) list.push(f);
    else byPackage.set(key, [f]);
  }
  for (const [key, rows] of byPackage) {
    const plan = planPackages(rows.map(toFindingInput))[0];
    const first = rows[0]!;
    const from = plan?.installedVersions[plan.installedVersions.length - 1] ?? first.version;
    const to = plan?.minimumVersion ?? null;
    const urgency = mostUrgent(rows);
    const size = changeSize(from, to);
    const pulledInBy = [...new Set(rows.flatMap((r) => r.pulledInBy))];
    const paths = [...new Set(rows.flatMap((r) => r.paths))];
    const where =
      pulledInBy.length > 0
        ? `Brought in by ${pulledInBy.slice(0, 3).join(", ")}: upgrade that, or pin ${first.name} to ${to ?? "a fixed version"} in your dependency file.`
        : paths.length > 0
          ? `In ${paths.slice(0, 2).join(", ")}${paths.length > 2 ? ` and ${paths.length - 2} more` : ""}.`
          : undefined;
    const copyLine = to ? upgradeLine(first.ecosystem, first.name, to, first.purl) : null;

    items.push({
      key: `upgrade:${key}`,
      kind: "upgrade",
      title: to ? `Upgrade ${first.name} from ${from ?? "?"} to ${to}` : `Upgrade ${first.name} to a fixed version`,
      reason: `Clears ${plural(rows.length, "vulnerability", "vulnerabilities")}: ${describeFindings(rows)}.${
        size === "major" ? " A major version: check the release notes for breaking changes." : ""
      }`,
      urgency,
      priority: URGENCY_RANK[urgency] * 100_000 - rows.length,
      clears: rows.length,
      counts: countsOf(rows),
      usedInAttacks: rows.filter((r) => r.knownExploited).length,
      remote: rows.filter(isRemote).length,
      size,
      ...(where ? { where } : {}),
      ...(copyLine ? { copyLine } : {}),
      packageName: first.name,
      ...(from ? { fromVersion: from } : {}),
      ...(to ? { toVersion: to } : {}),
      vulnerabilityIds: [...new Set(rows.map((r) => r.vulnerabilityId))],
    });
  }

  // --- the base image: one rebuild ----------------------------------------------------
  const osFixable = findings.filter((f) => f.origin === "os" && fixable(f));
  if (osFixable.length > 0) {
    const urgency = mostUrgent(osFixable);
    const packages = new Set(osFixable.map((f) => `${f.ecosystem}:${f.name}`)).size;
    const base = context.osPretty ?? "base image";
    items.push({
      key: "base-image",
      kind: "base-image",
      title: `Rebuild on an up-to-date ${base}`,
      reason: `Clears ${plural(osFixable.length, "vulnerability", "vulnerabilities")} in ${plural(packages, "operating-system package")}: ${describeFindings(osFixable)}. The fixes are in newer packages of the same distribution; rebuilding without the cache picks them up.`,
      urgency,
      priority: URGENCY_RANK[urgency] * 100_000 - osFixable.length,
      clears: osFixable.length,
      counts: countsOf(osFixable),
      usedInAttacks: osFixable.filter((r) => r.knownExploited).length,
      remote: osFixable.filter(isRemote).length,
      size: "rebuild",
      where: `Your Dockerfile's FROM line${context.imageRef ? ` (image ${context.imageRef})` : ""}: keep the tag, or move to the newest patch release of ${base}.`,
      copyLine: "docker build --pull --no-cache .",
      vulnerabilityIds: [...new Set(osFixable.map((r) => r.vulnerabilityId))],
    });
  }

  // --- no fix yet: one closing line ---------------------------------------------------
  if (noFix.length > 0) {
    const packages = [...new Set(noFix.map((f) => f.name))];
    items.push({
      key: "no-fix",
      kind: "no-fix",
      title: `No fix yet for ${plural(noFix.length, "vulnerability", "vulnerabilities")}`,
      reason: `In ${packages.slice(0, 4).join(", ")}${packages.length > 4 ? ` and ${packages.length - 4} more` : ""}: ${describeFindings(noFix)}. Nothing to do until a fix is published; they will move up here when one is.`,
      urgency: "none",
      priority: 1_000_000,
      clears: 0,
      counts: countsOf(noFix),
      usedInAttacks: noFix.filter((r) => r.knownExploited).length,
      remote: noFix.filter(isRemote).length,
      vulnerabilityIds: [...new Set(noFix.map((r) => r.vulnerabilityId))],
    });
  }

  return items;
}

function toFindingInput(f: PlanFinding): FindingInput {
  return {
    componentId: f.componentId,
    name: f.name,
    version: f.version,
    ecosystem: f.ecosystem,
    purl: f.purl,
    origin: f.origin,
    vulnerabilityId: f.vulnerabilityId,
    severity: f.severity,
    knownExploited: f.knownExploited,
    fixState: f.fixState,
    fixVersions: f.fixVersions,
  };
}

export { compareVersions };
