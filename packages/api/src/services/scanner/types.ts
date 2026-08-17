import type { VulnDbUpdateOutcome } from "@sbom/shared";
import type { ParsedFinding, ScannablePackage } from "./grype-output.js";

export type { ParsedFinding, ScannablePackage };

/** Where the binary is and whether it can be run. */
export interface ScannerAvailability {
  available: boolean;
  version: string | null;
  path: string | null;
  resolvedBy: string | null;
  /** The database schema this binary supports, which must match the installed DB. */
  supportedDbSchema: number | null;
  attempts: Array<{ strategy: string; location: string; reason: string }>;
}

/**
 * The installed vulnerability database, as Grype reports it.
 *
 * `builtAt` comes straight from Grype rather than being tracked separately, so the
 * "last updated" figure shown to an administrator cannot drift out of sync with the
 * database actually in use.
 */
export interface ScannerDbStatus {
  present: boolean;
  builtAt: Date | null;
  schemaVersion: string | null;
  valid: boolean;
  /** Grype's own reason when the database is unusable, e.g. "database does not exist". */
  error: string | null;
  path: string | null;
}

export interface MatchResult {
  findings: ParsedFinding[];
  grypeVersion: string | null;
  dbBuiltAt: Date | null;
  /** Non-zero means findings were dropped — see `ParsedReport.unmappedFindings`. */
  unmappedFindings: number;
  /** Component ids submitted in this batch, so the caller can mark them all scanned. */
  submittedComponentIds: number[];
}

export interface DbUpdateResult {
  outcome: VulnDbUpdateOutcome;
  /**
   * Human-readable detail. On `unreachable` this carries the exact URL that could not
   * be reached, which is the whole point: an air-gapped deployment must be able to
   * show an administrator *what* it failed to contact rather than a generic error.
   */
  message: string;
  builtBefore: Date | null;
  builtAfter: Date | null;
  schemaVersion: string | null;
  sourceUrl: string | null;
}

export interface ReachabilityResult {
  reachable: boolean;
  /** The listing URL that was probed, always populated so it can be reported. */
  url: string;
  message: string | null;
}

/**
 * The port the rest of the platform talks to.
 *
 * An interface rather than a concrete class for the same reason `BlobStore` and
 * `AuthProvider` are: it keeps the ingest and sweep paths independent of Grype
 * specifically, lets tests substitute a fake with no subprocess or database, and
 * leaves room for a different matcher without touching anything upstream.
 *
 * Every method is expected to resolve rather than throw for operational problems —
 * a missing binary, an unreachable listing, an invalid database. Those are states to
 * report, not exceptions to propagate, because none of them may be allowed to break
 * ingestion or any other part of the platform.
 */
export interface VulnerabilityScanner {
  readonly name: string;
  availability(): Promise<ScannerAvailability>;
  dbStatus(): Promise<ScannerDbStatus>;
  /**
   * The exact URL consulted for updates, derived from the binary's supported schema.
   *
   * Exposed so the admin panel can show it even when nothing has failed yet — an
   * operator pointing at an internal mirror needs to confirm the platform agrees with
   * them before they wait for a scheduled check to prove it.
   */
  listingUrl(): Promise<string>;
  /** Probes the listing URL only. Cheap, and the basis of the "no internet" message. */
  checkReachable(): Promise<ReachabilityResult>;
  updateDb(): Promise<DbUpdateResult>;
  /** Installs a database from a local archive — the air-gapped path. */
  importDb(archivePath: string): Promise<DbUpdateResult>;
  /** Matches one batch of packages. Throws only if the batch itself cannot be processed. */
  match(packages: readonly ScannablePackage[]): Promise<MatchResult>;
}
