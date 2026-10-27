import { sql } from "drizzle-orm";
import {
  EMPTY_SEVERITY_COUNTS,
  type CandidateAdvisory,
  type CandidateCheck,
  type FixRecommendation,
  type FixRecommendationAdvisory,
  type FixRecommendationQuery,
  type FixRecommendationReport,
  type FixRecommendationStatus,
  type FixState,
  type VulnSeverity,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { NotFoundError } from "../../lib/errors.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { applicationReadableBy, type ReadAccess } from "../environments/environment.service.js";
import type { ScannablePackage, VulnerabilityScanner } from "../../services/scanner/index.js";
import { NOT_SUPPRESSED, SCOPE_GROUP_EXPR, scopePredicate } from "./scope.js";

/**
 * Fix recommendations: one upgrade target per vulnerable package, checked before it is offered.
 *
 * Two halves. The pure half below turns the findings already stored for a build into a minimum
 * version per package. The service half asks the scanner about that version as though it were a
 * package in an SBOM, and walks forward while the answer is still "affected, fixed in a later
 * version". The contract and its limits are described in `schemas/fix-recommendation`.
 */

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/**
 * One fix-version string, cleaned of the notation providers wrap it in.
 *
 * Grype reports bare versions. Xray reports `[2.15.0]`-style ranges, and occasionally a
 * leading operator. Neither the brackets nor the operator are part of the version, and a
 * comparator handed `[2.15.0]` would order it by the bracket.
 */
export function normalizeVersion(raw: string): string | null {
  let v = raw.trim();
  v = v.replace(/^[[(]+/, "").replace(/[\])]+$/, "");
  if (v.includes(",")) v = v.split(",").map((part) => part.trim()).find((part) => part !== "") ?? "";
  v = v.replace(/^[<>=^\s]+/, "").trim();
  if (/^v\d/i.test(v)) v = v.slice(1);
  return v === "" ? null : v;
}

type Token = { kind: "num"; value: number } | { kind: "str"; value: string } | { kind: "tilde" };

/** Words that mark a version as earlier than the release they qualify, in order. */
const PRE_RELEASE_RANK: Record<string, number> = {
  snapshot: 0,
  dev: 0,
  alpha: 1,
  a: 1,
  beta: 2,
  b: 2,
  milestone: 3,
  m: 3,
  rc: 4,
  cr: 4,
  pre: 4,
  preview: 4,
  ea: 4,
};

/** Words that mean "the release itself": `1.0.Final` is `1.0`. */
const RELEASE_WORDS = new Set(["final", "ga", "release", "r"]);

function tokenize(version: string): { epoch: number; tokens: Token[] } {
  let rest = version;
  let epoch = 0;
  // Debian and RPM epochs: `1:2.3-4` sorts after any `2.x` with no epoch.
  const epochMatch = /^(\d+):(.+)$/.exec(rest);
  if (epochMatch) {
    epoch = Number(epochMatch[1]);
    rest = epochMatch[2]!;
  }
  const tokens: Token[] = [];
  for (const match of rest.matchAll(/(\d+)|([a-z]+)|(~)/gi)) {
    if (match[1] !== undefined) tokens.push({ kind: "num", value: Number(match[1]) });
    else if (match[2] !== undefined) tokens.push({ kind: "str", value: match[2].toLowerCase() });
    else tokens.push({ kind: "tilde" });
  }
  return { epoch, tokens };
}

/** How a token compares against the end of a shorter version: negative means it sorts before. */
function againstEnd(token: Token): number {
  if (token.kind === "tilde") return -1; // Debian: `1.0~rc1` < `1.0`
  if (token.kind === "num") return 1; // `1.0.1` > `1.0`
  if (token.value in PRE_RELEASE_RANK) return -1; // `1.0-rc1` < `1.0`
  if (RELEASE_WORDS.has(token.value)) return 0; // `1.0.Final` = `1.0`
  return 1; // `1.0-sp1`, `1.0-1ubuntu1`: a revision after the release
}

/**
 * Orders two version strings, ecosystem-blind.
 *
 * A heuristic, and stated as one: Maven, npm, PyPI, Debian and RPM each define their own
 * ordering, and none of them is implemented exactly. What is implemented is the part they agree
 * on - numeric runs compare as numbers, `~` and the common pre-release words sort before the
 * release they qualify, an epoch outranks everything - which orders the fix versions scanners
 * actually report correctly in the overwhelming majority of cases. The recommendation is then
 * checked against the scanner, which is what catches the cases this gets wrong.
 */
export function compareVersions(left: string, right: string): number {
  const a = tokenize(left);
  const b = tokenize(right);
  if (a.epoch !== b.epoch) return a.epoch < b.epoch ? -1 : 1;

  const length = Math.max(a.tokens.length, b.tokens.length);
  for (let i = 0; i < length; i++) {
    const x = a.tokens[i];
    const y = b.tokens[i];
    if (x === undefined && y === undefined) return 0;
    if (x === undefined) {
      const order = againstEnd(y!);
      if (order !== 0) return -order;
      continue;
    }
    if (y === undefined) {
      const order = againstEnd(x);
      if (order !== 0) return order;
      continue;
    }

    if (x.kind === "tilde" || y.kind === "tilde") {
      if (x.kind === y.kind) continue;
      return x.kind === "tilde" ? -1 : 1;
    }
    if (x.kind === "num" && y.kind === "num") {
      if (x.value !== y.value) return x.value < y.value ? -1 : 1;
      continue;
    }
    // A number outranks a word in the same position: `1.0.1` > `1.0.rc1`.
    if (x.kind === "num") return 1;
    if (y.kind === "num") return -1;

    const rank = (word: string) =>
      word in PRE_RELEASE_RANK ? PRE_RELEASE_RANK[word]! : RELEASE_WORDS.has(word) ? 5 : 6;
    const rx = rank(x.value);
    const ry = rank(y.value);
    if (rx !== ry) return rx < ry ? -1 : 1;
    if (rx === 6 && x.value !== y.value) return x.value < y.value ? -1 : 1;
  }
  return 0;
}

function maxVersion(versions: readonly string[]): string | null {
  let best: string | null = null;
  for (const v of versions) if (best === null || compareVersions(v, best) > 0) best = v;
  return best;
}

/**
 * The fix that applies to an installed version: the lowest one above it.
 *
 * An advisory can list several fixed versions, one per release line (`2.12.2`, `2.15.0`), and
 * the one that matters is the nearest upgrade, not the newest release. Versions at or below the
 * installed one are ignored - they belong to an older line - and if nothing is above it, there
 * is no fix to recommend from this advisory.
 */
export function chooseFix(fixVersions: readonly string[], installed: string | null): string | null {
  const candidates = fixVersions
    .map(normalizeVersion)
    .filter((v): v is string => v !== null)
    .filter((v) => installed === null || compareVersions(v, installed) > 0);
  let best: string | null = null;
  for (const v of candidates) if (best === null || compareVersions(v, best) < 0) best = v;
  return best;
}

/**
 * The package URL with another version in it.
 *
 * Qualifiers survive, and they are the reason this is done on the purl rather than on name and
 * version: `?distro=debian-12` is what tells the scanner which advisories apply to a deb, and a
 * candidate checked without it would be compared against the wrong distribution.
 *
 * The version is the part after the *last* `@` in the path, so a scoped npm name spelled with a
 * literal `@` (`pkg:npm/@babel/core@7.0.0`) keeps its scope.
 */
export function withVersion(purl: string, version: string): string | null {
  if (!purl.startsWith("pkg:")) return null;
  const cut = purl.search(/[?#]/);
  let base = cut < 0 ? purl : purl.slice(0, cut);
  const tail = cut < 0 ? "" : purl.slice(cut);
  const at = base.lastIndexOf("@");
  if (at > base.lastIndexOf("/")) base = base.slice(0, at);
  return `${base}@${encodeURIComponent(version)}${tail}`;
}

// ---------------------------------------------------------------------------
// From findings to a minimum version
// ---------------------------------------------------------------------------

/** One stored finding, as the report query returns it. */
export interface FindingInput {
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
}

/** A package with its minimum, before any checking. */
export interface PackagePlan {
  key: string;
  name: string;
  ecosystem: string;
  origin: "app" | "os";
  installedVersions: string[];
  /** The purl to substitute candidate versions into, from the newest installed version. */
  purl: string | null;
  advisories: FixRecommendationAdvisory[];
  minimumVersion: string | null;
  resolvedByMinimum: number;
}

const SEVERITY_RANK: Record<VulnSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  negligible: 1,
  unknown: 0,
};

/**
 * Groups findings by package and works out the least upgrade that clears them.
 *
 * Grouped by ecosystem and name, not by component, because "the same package" is what the
 * upgrade is about: a build carrying log4j 2.14 in one jar and 2.16 in another is fixed by
 * moving both to one version, and two rows recommending different ones would be two answers to
 * one question.
 *
 * The minimum is the highest of the per-advisory fixes, and never below a version already
 * shipped - recommending 2.15 to a build that also ships 2.16 would be advising a downgrade.
 */
export function planPackages(findings: readonly FindingInput[]): PackagePlan[] {
  const groups = new Map<string, FindingInput[]>();
  for (const finding of findings) {
    const key = `${finding.ecosystem.toLowerCase()}:${finding.name.toLowerCase()}`;
    const list = groups.get(key);
    if (list) list.push(finding);
    else groups.set(key, [finding]);
  }

  const plans: PackagePlan[] = [];
  for (const [key, rows] of groups) {
    const first = rows[0]!;
    const installed = [...new Set(rows.map((r) => r.version).filter((v): v is string => v !== null))]
      .sort(compareVersions);
    const newestInstalled = installed[installed.length - 1] ?? null;

    // One advisory can be reported against two installed versions; it is one advisory to fix.
    const seen = new Set<string>();
    const advisories: FixRecommendationAdvisory[] = [];
    for (const row of rows) {
      const id = `${row.vulnerabilityId}@${row.version ?? ""}`;
      if (seen.has(id)) continue;
      seen.add(id);
      advisories.push({
        vulnerabilityId: row.vulnerabilityId,
        severity: row.severity,
        knownExploited: row.knownExploited,
        installedVersion: row.version,
        fixVersions: row.fixVersions,
        fixedIn: chooseFix(row.fixVersions, row.version),
        fixState: row.fixState,
      });
    }
    advisories.sort(
      (x, y) =>
        SEVERITY_RANK[y.severity] - SEVERITY_RANK[x.severity] ||
        x.vulnerabilityId.localeCompare(y.vulnerabilityId),
    );

    const fixes = advisories.map((a) => a.fixedIn).filter((v): v is string => v !== null);
    let minimum = maxVersion(fixes);
    if (minimum !== null && newestInstalled !== null && compareVersions(minimum, newestInstalled) < 0) {
      minimum = newestInstalled;
    }

    const purlSource =
      [...rows]
        .filter((r) => r.purl !== null)
        .sort((x, y) => compareVersions(x.version ?? "", y.version ?? ""))
        .pop() ?? null;

    plans.push({
      key,
      name: first.name,
      ecosystem: first.ecosystem,
      origin: first.origin,
      installedVersions: installed,
      purl: purlSource?.purl ?? null,
      advisories,
      minimumVersion: minimum,
      resolvedByMinimum: advisories.filter((a) => a.fixedIn !== null).length,
    });
  }
  return plans;
}

/** What the scanner said about one candidate version. */
export interface CandidateFinding {
  vulnerabilityId: string;
  severity: VulnSeverity;
  fixState: FixState;
  fixVersions: string[];
}

/**
 * Walks one package forward from its minimum while the scanner keeps saying "fixed later".
 *
 * Pure over a lookup, so the walk can be tested without a scanner: `lookup` answers for a
 * version, or returns undefined when it could not be asked. Ends at the first version with
 * nothing against it (`clean`), at one whose remaining advisories have no later fix
 * (`residual`), or when it runs out of answers or rounds (`unverified`).
 */
export function walkCandidate(
  start: string,
  lookup: (version: string) => CandidateFinding[] | undefined,
  maxRounds: number,
): { status: FixRecommendationStatus; recommendedVersion: string; checks: CandidateCheck[] } {
  const checks: CandidateCheck[] = [];
  let target = start;
  for (let round = 0; round < maxRounds; round++) {
    const found = lookup(target);
    if (found === undefined) {
      // Never asked about this version. The last one that was asked is still the best answer,
      // but it was not shown clean, so the result is unverified rather than residual.
      return { status: "unverified", recommendedVersion: target, checks };
    }
    const advisories: CandidateAdvisory[] = found.map((f) => ({
      vulnerabilityId: f.vulnerabilityId,
      severity: f.severity,
      fixedIn: chooseFix(f.fixVersions, target),
    }));
    checks.push({ version: target, advisories });
    if (advisories.length === 0) return { status: "clean", recommendedVersion: target, checks };

    const next = maxVersion(advisories.map((a) => a.fixedIn).filter((v): v is string => v !== null));
    if (next === null || compareVersions(next, target) <= 0) {
      return { status: "residual", recommendedVersion: target, checks };
    }
    target = next;
  }
  return { status: "unverified", recommendedVersion: target, checks };
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

/** How many versions one package is walked through before the answer is called unverified. */
const MAX_ROUNDS = 5;

/**
 * Packages verified per request.
 *
 * A base image can carry hundreds of vulnerable packages, and the first open of an unverified
 * build pays one scanner run per round for all of them. Past this the rest are reported as
 * unverified rather than making the request wait; the cache means the next open goes further.
 */
const MAX_VERIFIED_PACKAGES = 400;

interface ReportFindingRow {
  component_id: number | string;
  name: string;
  version: string | null;
  ecosystem: string;
  purl: string | null;
  origin: string;
  vulnerability_id: string;
  severity: VulnSeverity;
  known_exploited: boolean;
  fix_state: string;
  fix_versions: string[] | null;
}

export class FixAdvisorService {
  /** Scanner runs in flight. The database update reads this and waits rather than swap the file. */
  private checking = 0;
  /** Serialises scanner runs from this service: two tabs opening at once share one queue. */
  private queue: Promise<unknown> = Promise.resolve();
  /**
   * The database watermark, remembered briefly.
   *
   * Grype answers it by running a subprocess -- several seconds on a large database -- and the
   * tab asks on every open, so without this a fully cached answer still cost a scanner start.
   * Dropped the moment a replacement is seen in progress, and short-lived either way, so a new
   * database is picked up within minutes; a check keyed to the old watermark meanwhile is only
   * re-asked later, never trusted wrongly.
   */
  private watermarkCache: { value: Date | null; until: number } | null = null;

  constructor(
    private readonly deps: {
      db: Database;
      scanner: VulnerabilityScanner;
      /** Which provider is active, so a cached answer from the other one is not reused. */
      provider: () => Promise<string>;
      /** True while the database is being replaced; checking then waits for the next request. */
      dbReplacing: () => boolean;
      logger: { warn(obj: unknown, msg?: string): void };
    },
  ) {}

  /** Whether a scanner run is in flight, for the database update's exclusion check. */
  get isChecking(): boolean {
    return this.checking > 0;
  }

  async report(
    applicationId: string,
    query: FixRecommendationQuery,
    access: ReadAccess,
  ): Promise<FixRecommendationReport> {
    const apps = await this.deps.db.execute<Row<{ latest_scan_id: string | null }>>(sql`
      SELECT latest_scan_id FROM application a
       WHERE a.id = ${applicationId}::uuid AND ${applicationReadableBy("a", access)}
    `);
    const app = rowsOf(apps)[0];
    if (!app) throw new NotFoundError("Application");

    const empty: FixRecommendationReport = {
      applicationId,
      scanId: app.latest_scan_id,
      scope: query.scope,
      verification: { status: "skipped", message: null, databaseBuiltAt: null },
      summary: { packages: 0, findings: 0, resolvable: 0, withoutFix: 0 },
      recommendations: [],
    };
    if (!app.latest_scan_id) return empty;

    // Accepted risks are left out, exactly as they are from every count.
    const rows = await this.deps.db.execute<Row<ReportFindingRow>>(sql`
      SELECT c.id AS component_id, c.name, c.version, c.ecosystem, c.purl,
             ${SCOPE_GROUP_EXPR} AS origin,
             v.id AS vulnerability_id, v.severity, v.known_exploited,
             cv.fix_state, cv.fix_versions
        FROM scan_component sc
        JOIN component c ON c.id = sc.component_id
        JOIN component_vulnerability cv ON cv.component_id = c.id
        JOIN vulnerability v ON v.id = cv.vulnerability_id
        JOIN application a ON a.id = sc.application_id
       WHERE sc.scan_id = ${app.latest_scan_id}::uuid
         AND ${scopePredicate(query.scope)}
         AND ${NOT_SUPPRESSED}
    `);

    const plans = planPackages(
      rowsOf(rows).map((r) => ({
        componentId: Number(r.component_id),
        name: r.name,
        version: r.version,
        ecosystem: r.ecosystem,
        purl: r.purl,
        origin: r.origin === "os" ? "os" : "app",
        vulnerabilityId: r.vulnerability_id,
        severity: r.severity,
        knownExploited: r.known_exploited === true,
        fixState: r.fix_state,
        fixVersions: r.fix_versions ?? [],
      })),
    );

    let verification: FixRecommendationReport["verification"] = {
      status: "skipped",
      message: null,
      databaseBuiltAt: null,
    };
    let walks = new Map<string, ReturnType<typeof walkCandidate>>();
    if (query.verify) {
      const verified = await this.verify(applicationId, plans);
      verification = verified.verification;
      walks = verified.walks;
    }

    const recommendations = plans.map((plan): FixRecommendation => {
      const counts = { ...EMPTY_SEVERITY_COUNTS };
      for (const advisory of plan.advisories) counts[advisory.severity] += 1;
      const highestSeverity = plan.advisories[0]?.severity ?? "unknown";
      const walk = walks.get(plan.key);

      return {
        key: plan.key,
        name: plan.name,
        ecosystem: plan.ecosystem,
        origin: plan.origin,
        installedVersions: plan.installedVersions,
        findings: plan.advisories.length,
        counts,
        highestSeverity,
        knownExploited: plan.advisories.filter((a) => a.knownExploited).length,
        advisories: plan.advisories,
        minimumVersion: plan.minimumVersion,
        resolvedByMinimum: plan.resolvedByMinimum,
        recommendedVersion: walk?.recommendedVersion ?? plan.minimumVersion,
        status: plan.minimumVersion === null ? "no_fix" : (walk?.status ?? "unverified"),
        checks: walk?.checks ?? [],
      };
    });

    // Something to do first, then worst first, then the upgrades that clear the most, so the
    // top of the list is the afternoon's work. On a base image most rows have no fix at all,
    // and sorting them in by severity would bury the handful that can be acted on.
    recommendations.sort(
      (x, y) =>
        Number(x.minimumVersion === null) - Number(y.minimumVersion === null) ||
        SEVERITY_RANK[y.highestSeverity] - SEVERITY_RANK[x.highestSeverity] ||
        y.resolvedByMinimum - x.resolvedByMinimum ||
        x.name.localeCompare(y.name),
    );

    const findings = recommendations.reduce((sum, r) => sum + r.findings, 0);
    const resolvable = recommendations.reduce((sum, r) => sum + r.resolvedByMinimum, 0);
    return {
      ...empty,
      verification,
      summary: {
        packages: recommendations.length,
        findings,
        resolvable,
        withoutFix: findings - resolvable,
      },
      recommendations,
    };
  }

  /**
   * Walks every package with a minimum forward through the scanner, in rounds.
   *
   * One scanner run per round for all packages that still need an answer, rather than one per
   * package: a scanner run is dominated by loading its database, so fifty candidates cost about
   * what one does.
   */
  private async verify(
    applicationId: string,
    plans: readonly PackagePlan[],
  ): Promise<{
    verification: FixRecommendationReport["verification"];
    walks: Map<string, ReturnType<typeof walkCandidate>>;
  }> {
    const walks = new Map<string, ReturnType<typeof walkCandidate>>();
    const watermark = await this.currentWatermark();
    if (watermark === null) {
      return {
        verification: {
          status: "unavailable",
          message:
            "The scanner has no usable vulnerability database right now, so the recommended versions could not be checked. They clear what is reported today, but may themselves be affected.",
          databaseBuiltAt: null,
        },
        walks,
      };
    }

    const candidates = plans.filter((p) => p.minimumVersion !== null && p.purl !== null);
    const checked = candidates.slice(0, MAX_VERIFIED_PACKAGES);
    const suppressed = await this.suppressedAdvisories(applicationId);
    const answers = new Map<string, CandidateFinding[]>();
    let failure: string | null = null;

    // Each round asks about every version the walks will need next.
    const targets = new Map<string, string>(checked.map((p) => [p.key, p.minimumVersion!]));
    for (let round = 0; round < MAX_ROUNDS && targets.size > 0 && failure === null; round++) {
      const wanted = [...targets].map(([key, version]) => {
        const plan = checked.find((p) => p.key === key)!;
        return { plan, version, purl: withVersion(plan.purl!, version) };
      });
      const result = await this.lookup(
        wanted.filter((w) => w.purl !== null).map((w) => ({ ...w, purl: w.purl! })),
        watermark,
      );
      if (result.failure) failure = result.failure;
      const known = answers.size;
      for (const [purl, found] of result.answers) answers.set(purl, found);
      // A round that learned nothing would ask the same unanswerable questions again -- a
      // package the scanner declines to assess -- so the walk stops where it stands.
      const learned = answers.size > known;

      targets.clear();
      for (const { plan } of wanted) {
        const walk = walkCandidate(
          plan.minimumVersion!,
          (version) => {
            const purl = withVersion(plan.purl!, version);
            const found = purl === null ? undefined : answers.get(purl);
            return found?.filter((f) => !suppressed.has(f.vulnerabilityId));
          },
          MAX_ROUNDS,
        );
        walks.set(plan.key, walk);
        // Unverified because the next version has not been asked yet: ask in the next round.
        if (learned && walk.status === "unverified" && walk.checks.length < MAX_ROUNDS) {
          targets.set(plan.key, walk.recommendedVersion);
        }
      }
    }

    const partial = candidates.length > checked.length;
    return {
      verification: {
        status: failure !== null ? "unavailable" : partial ? "partial" : "verified",
        message:
          failure ??
          (partial
            ? `Only the first ${MAX_VERIFIED_PACKAGES} packages were checked on this request; open the tab again to check more.`
            : null),
        databaseBuiltAt: watermark.toISOString(),
      },
      walks,
    };
  }

  /**
   * Answers for a set of candidate purls: from the cache where it is current, from the scanner
   * otherwise. Never throws - a scanner failure becomes a message, and the recommendations it
   * could not check are reported as unverified.
   */
  private async lookup(
    wanted: ReadonlyArray<{ plan: PackagePlan; version: string; purl: string }>,
    watermark: Date,
  ): Promise<{ answers: Map<string, CandidateFinding[]>; failure: string | null }> {
    const answers = new Map<string, CandidateFinding[]>();
    if (wanted.length === 0) return { answers, failure: null };
    const provider = await this.deps.provider();
    const purls = [...new Set(wanted.map((w) => w.purl))];

    const cached = await this.deps.db.execute<Row<{ purl: string; findings: CandidateFinding[] }>>(sql`
      SELECT purl, findings FROM fix_candidate_check
       WHERE purl = ANY(${sql.param(purls)}::text[])
         AND provider = ${provider}
         AND watermark = ${watermark.toISOString()}::timestamptz
    `);
    for (const row of rowsOf(cached)) answers.set(row.purl, row.findings ?? []);

    const missing = wanted.filter((w, i) => !answers.has(w.purl) && wanted.findIndex((o) => o.purl === w.purl) === i);
    if (missing.length === 0) return { answers, failure: null };

    if (this.deps.dbReplacing()) {
      return {
        answers,
        failure:
          "The vulnerability database is being replaced, so some recommended versions could not be checked. Reopen this tab in a minute.",
      };
    }

    // bom-ref ids are local to this batch; they only have to map an answer back to its purl.
    const packages: ScannablePackage[] = missing.map((w, index) => ({
      componentId: index + 1,
      name: w.plan.name,
      version: w.version,
      purl: w.purl,
      ecosystem: w.plan.ecosystem,
    }));

    try {
      const result = await this.exclusive(() => this.deps.scanner.match(packages));
      const byId = new Map<number, CandidateFinding[]>();
      for (const finding of result.findings) {
        const list = byId.get(finding.componentId) ?? [];
        list.push({
          vulnerabilityId: finding.vulnerabilityId,
          severity: finding.severity,
          fixState: finding.fixState,
          fixVersions: finding.fixVersions,
        });
        byId.set(finding.componentId, list);
      }

      /*
        Only what the scanner actually assessed is recorded. A package it skipped -- Xray with no
        coordinate for that ecosystem -- is left unanswered rather than cached as clean, which
        would turn "could not ask" into "asked and found nothing".
      */
      const assessed = new Set(result.submittedComponentIds);
      for (const pkg of packages) {
        if (!assessed.has(pkg.componentId)) continue;
        const found = byId.get(pkg.componentId) ?? [];
        answers.set(pkg.purl!, found);
        await this.deps.db.execute(sql`
          INSERT INTO fix_candidate_check (purl, provider, watermark, findings, checked_at)
          VALUES (${pkg.purl}, ${provider}, ${watermark.toISOString()}::timestamptz,
                  ${JSON.stringify(found)}::jsonb, now())
          ON CONFLICT (purl) DO UPDATE
             SET provider = EXCLUDED.provider,
                 watermark = EXCLUDED.watermark,
                 findings = EXCLUDED.findings,
                 checked_at = EXCLUDED.checked_at
        `);
      }
      return { answers, failure: null };
    } catch (error) {
      this.deps.logger.warn({ err: error, packages: packages.length }, "could not check candidate fix versions");
      return {
        answers,
        failure:
          "The scanner could not check the recommended versions just now, so they are shown unverified. The error log has the detail.",
      };
    }
  }

  private async currentWatermark(): Promise<Date | null> {
    if (this.deps.dbReplacing()) this.watermarkCache = null;
    if (this.watermarkCache && this.watermarkCache.until > Date.now()) return this.watermarkCache.value;
    const value = await this.deps.scanner.watermark().catch(() => null);
    // A missing database is not remembered: it is the state an administrator is about to fix.
    this.watermarkCache = value === null ? null : { value, until: Date.now() + 5 * 60 * 1000 };
    return value;
  }

  /** Advisories accepted for this application regardless of package version. */
  private async suppressedAdvisories(applicationId: string): Promise<Set<string>> {
    const rows = await this.deps.db.execute<Row<{ vulnerability_id: string }>>(sql`
      SELECT DISTINCT vulnerability_id FROM vulnerability_suppression
       WHERE component_id IS NULL
         AND (application_id IS NULL OR application_id = ${applicationId}::uuid)
         AND (expires_at IS NULL OR expires_at > now())
    `);
    return new Set(rowsOf(rows).map((r) => r.vulnerability_id));
  }

  private exclusive<T>(work: () => Promise<T>): Promise<T> {
    const run = this.queue.then(async () => {
      this.checking += 1;
      try {
        return await work();
      } finally {
        this.checking -= 1;
      }
    });
    // The queue carries on whether this run succeeded or not.
    this.queue = run.catch(() => undefined);
    return run;
  }
}
