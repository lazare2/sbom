import type {
  DbUpdateResult,
  MatchResult,
  ReachabilityResult,
  ScannerAvailability,
  ScannerDbStatus,
  VulnerabilityScanner,
} from "./types.js";

/**
 * A stand-in for a provider that was chosen but cannot be reached.
 *
 * Every method answers the way an unusable scanner should: unavailable, no database, no
 * watermark. The sweep's own guards then stop it, so nothing is assessed and nothing is
 * stamped - which is what keeps "the connection is broken" from rendering as "the estate is
 * clean".
 */
export class UnavailableScanner implements VulnerabilityScanner {
  readonly name = "unavailable";

  constructor(
    private readonly reason: string,
    private readonly where: string,
  ) {}

  async availability(): Promise<ScannerAvailability> {
    return {
      available: false,
      version: null,
      path: this.where,
      resolvedBy: "settings",
      supportedDbSchema: null,
      attempts: [{ strategy: "settings", location: this.where, reason: this.reason }],
    };
  }

  async dbStatus(): Promise<ScannerDbStatus> {
    return {
      present: false,
      builtAt: null,
      schemaVersion: null,
      valid: false,
      error: this.reason,
      path: this.where,
    };
  }

  /** Null, so the sweep refuses to run rather than assessing against nothing. */
  async watermark(): Promise<Date | null> {
    return null;
  }

  async listingUrl(): Promise<string> {
    return this.where;
  }

  async checkReachable(): Promise<ReachabilityResult> {
    return { reachable: false, url: this.where, message: this.reason };
  }

  async updateDb(): Promise<DbUpdateResult> {
    return {
      outcome: "failed",
      message: this.reason,
      builtBefore: null,
      builtAfter: null,
      schemaVersion: null,
      sourceUrl: null,
    };
  }

  async importDb(): Promise<DbUpdateResult> {
    return this.updateDb();
  }

  /**
   * Submits nothing and reports nothing assessed.
   *
   * Never reached in practice - the sweep stops at `availability` - but a `match` that threw
   * would turn a configuration problem into a crashed background job, and one that returned
   * component ids would mark them assessed by a scanner that does not exist.
   */
  async match(): Promise<MatchResult> {
    return {
      findings: [],
      grypeVersion: null,
      dbBuiltAt: null,
      unmappedFindings: 0,
      submittedComponentIds: [],
    };
  }
}

/**
 * Builds the resolver the delegating scanner calls.
 *
 * Grype is constructed once and reused: it shells out to a binary and holds no per-call
 * state. The Xray scanner is rebuilt each time because its credentials and its assessment
 * epoch both live in settings an administrator can change, and a cached instance would keep
 * using the connection that was configured when the process started.
 */
