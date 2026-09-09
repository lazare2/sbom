import type { FastifyBaseLogger } from "fastify";
import type { XrayCoverage } from "@sbom/shared";
import { toFindings, type XrayMapping } from "./xray-findings.js";
import { toXrayCoordinate, XRAY_CANARIES } from "./xray-coordinates.js";
import { XrayClient, XrayError, type XrayCredentials } from "./xray-client.js";
import type {
  DbUpdateResult,
  MatchResult,
  ReachabilityResult,
  ScannablePackage,
  ScannerAvailability,
  ScannerDbStatus,
  VulnerabilityScanner,
} from "./types.js";

/**
 * The `VulnerabilityScanner` port, backed by an organisation's own JFrog Xray.
 *
 * Everything upstream — the sweep, the frozen per-scan summaries, every dashboard figure —
 * is written against this port and cannot tell which implementation answered. That is the
 * point: adding a second vulnerability database should not require a second code path
 * through the platform.
 *
 * ## Where the port fits Grype better than Xray, and what is done about it
 *
 * Half of this interface describes a *local database*: its build date, its schema, how to
 * update it, how to import it from an archive on an air-gapped host. Xray has none of those.
 * The database lives on somebody else's server, is synchronised by them, and exposes no
 * build timestamp this platform can read.
 *
 * Those methods therefore answer honestly rather than pretending. `updateDb` does not
 * silently succeed — reporting "already current" would be a claim about a database this
 * platform has no visibility into, and an administrator watching the update log would take
 * it as confirmation that something happened.
 */
export class XrayScanner implements VulnerabilityScanner {
  readonly name = "jfrog-xray";
  private readonly client: XrayClient;

  constructor(
    private readonly credentials: XrayCredentials,
    /*
      The client is injectable for the same reason the scanner itself is a port: the
      behaviour worth testing here is which packages get submitted and which get marked as
      assessed, and neither needs a socket to establish.
    */
    private readonly deps: {
      logger: FastifyBaseLogger;
      client?: XrayClient;
      /**
       * The data set this scanner is matching against, as a timestamp.
       *
       * Xray publishes no database build date, so one is kept on this side: it is advanced
       * when the connection changes and once per configured interval, and never otherwise.
       * Using the current time instead would make every component look stale on every tick
       * and re-scan the entire estate against a shared corporate server continuously.
       */
      assessmentEpoch: Date;
    },
  ) {
    this.client = deps.client ?? new XrayClient(credentials);
  }

  /**
   * Whether the configured Xray answers, and as what.
   *
   * `path` carries the base URL and `resolvedBy` says the settings supplied it, so the admin
   * screen's existing "where did this scanner come from" line stays meaningful without
   * needing to know which provider it is describing.
   */
  async availability(): Promise<ScannerAvailability> {
    try {
      const version = await this.client.version();
      return {
        available: true,
        version,
        path: this.credentials.baseUrl,
        resolvedBy: "settings",
        // Grype's binary and database schemas have to agree. Nothing here does.
        supportedDbSchema: null,
        attempts: [],
      };
    } catch (error) {
      const detail = error instanceof XrayError ? error.message : String(error);
      return {
        available: false,
        version: null,
        path: this.credentials.baseUrl,
        resolvedBy: "settings",
        supportedDbSchema: null,
        attempts: [{ strategy: "settings", location: this.credentials.baseUrl, reason: detail }],
      };
    }
  }

  /**
   * The remote database, as far as it can be described from here.
   *
   * `builtAt` is null and stays null: Xray publishes no build timestamp for its feed, and
   * inventing one — the time of the last successful call, say — would put a date on the
   * admin screen that looks like a database age and is not one. The platform shows "not
   * reported" instead, which is true.
   *
   * That null has a second consequence worth naming. Grype re-scans the estate when a newer
   * database build appears; with no build timestamp there is nothing to compare, so under
   * Xray the re-scan is driven by the configured interval alone.
   */
  async dbStatus(): Promise<ScannerDbStatus> {
    const reachable = await this.checkReachable();
    return {
      present: reachable.reachable,
      builtAt: null,
      schemaVersion: null,
      valid: reachable.reachable,
      error: reachable.reachable ? null : reachable.message,
      path: this.credentials.baseUrl,
    };
  }

  /**
   * The epoch, not a database date.
   *
   * Deliberately not derived from anything that moves on its own. A component assessed at
   * the current epoch is up to date until somebody changes the connection or the interval
   * rolls over — which is the same contract Grype's build timestamp provides, expressed by
   * the only side that can know it.
   */
  async watermark(): Promise<Date | null> {
    return this.deps.assessmentEpoch;
  }

  async listingUrl(): Promise<string> {
    return `${this.credentials.baseUrl.replace(/\/+$/, "")}/xray/api/v1/system/version`;
  }

  async checkReachable(): Promise<ReachabilityResult> {
    const url = await this.listingUrl();
    try {
      const version = await this.client.version();
      return { reachable: true, url, message: `Xray ${version}` };
    } catch (error) {
      return {
        reachable: false,
        url,
        message: error instanceof XrayError ? error.message : String(error),
      };
    }
  }

  /**
   * Refused, deliberately, and the message says who does the updating.
   *
   * Reporting `already-current` would be the comfortable answer and the wrong one: it is a
   * statement about a database this platform cannot see, and it would appear in the update
   * history as though a check had been performed.
   */
  async updateDb(): Promise<DbUpdateResult> {
    return {
      outcome: "failed",
      message:
        "JFrog Xray maintains its own vulnerability database. There is nothing for this platform to download — its synchronisation is managed on the Xray server.",
      builtBefore: null,
      builtAfter: null,
      schemaVersion: null,
      sourceUrl: this.credentials.baseUrl,
    };
  }

  async importDb(): Promise<DbUpdateResult> {
    return {
      outcome: "failed",
      message:
        "A database archive cannot be imported into JFrog Xray from here. Import it on the Xray server, or switch the provider back to Grype to use a local database.",
      builtBefore: null,
      builtAfter: null,
      schemaVersion: null,
      sourceUrl: null,
    };
  }

  /**
   * Matches one batch of packages against Xray.
   *
   * ## Packages that cannot be expressed are not silently dropped
   *
   * `submittedComponentIds` is what the sweep marks as scanned, and it deliberately contains
   * only the components that were actually sent. A package with no coordinate — an ecosystem
   * Xray has no identifier for, an OS package with no architecture — is left out of that
   * list, so the sweep does not stamp it as assessed and every figure derived from it reads
   * as not assessed rather than as clean.
   *
   * That is the single most important line in this file. Including them would turn "we could
   * not ask" into "we asked and found nothing".
   */
  async match(packages: readonly ScannablePackage[]): Promise<MatchResult> {
    const byCoordinate = new Map<string, number[]>();
    const submittedComponentIds: number[] = [];

    for (const pkg of packages) {
      const coordinate = toXrayCoordinate(pkg);
      if (!coordinate) continue;
      const existing = byCoordinate.get(coordinate);
      if (existing) existing.push(pkg.componentId);
      else byCoordinate.set(coordinate, [pkg.componentId]);
      submittedComponentIds.push(pkg.componentId);
    }

    const skipped = packages.length - submittedComponentIds.length;
    if (skipped > 0) {
      this.deps.logger.debug(
        { batch: packages.length, skipped },
        "packages in this batch have no Xray coordinate and were left unassessed",
      );
    }

    if (byCoordinate.size === 0) {
      return {
        findings: [],
        grypeVersion: null,
        dbBuiltAt: null,
        unmappedFindings: 0,
        submittedComponentIds: [],
      };
    }

    const result = await this.client.scanGraph([...byCoordinate.keys()]);
    const mapping: XrayMapping = { byCoordinate };
    const { findings, unmatchedReferences, unidentified } = toFindings(
      result.vulnerabilities,
      mapping,
    );

    if (unidentified > 0) {
      this.deps.logger.warn(
        { unidentified },
        "Xray reported issues with neither a CVE nor an issue id; they cannot be stored",
      );
    }

    return {
      findings,
      // Named for Grype but meaning "the tool that produced this", which is what it is used for.
      grypeVersion: null,
      dbBuiltAt: null,
      unmappedFindings: unmatchedReferences,
      submittedComponentIds,
    };
  }

  /**
   * Asks this Xray which package ecosystems it actually has data for.
   *
   * One known-vulnerable canary per ecosystem, submitted as a single graph scan. An ecosystem
   * whose canary comes back with no findings is reported as uncovered, and everything in it
   * is then rendered as not assessed rather than as clean.
   *
   * This is the manual database-health check from the original investigation — Log4Shell and
   * a vulnerable lodash, to prove the server was synchronised rather than silently empty —
   * turned into something the platform performs for itself and repeats whenever the
   * connection is tested.
   *
   * It is a heuristic and is presented as one. A canary that has genuinely been assessed as
   * safe would read as an uncovered ecosystem; the admin screen names the package it asked
   * about so that judgement stays with a person.
   */
  async probeCoverage(): Promise<XrayCoverage> {
    const result = await this.client.scanGraph(XRAY_CANARIES.map((c) => c.coordinate));

    const withFindings = new Set<string>();
    for (const vulnerability of result.vulnerabilities) {
      for (const coordinate of Object.keys(vulnerability.components ?? {})) {
        withFindings.add(coordinate);
      }
    }

    const covered: string[] = [];
    const uncovered: string[] = [];
    for (const canary of XRAY_CANARIES) {
      (withFindings.has(canary.coordinate) ? covered : uncovered).push(canary.ecosystem);
    }

    return { covered, uncovered, checkedAt: new Date().toISOString() };
  }
}
