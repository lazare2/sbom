import type { Config } from "../../config.js";
import { GrypeScanner } from "./grype.js";
import type { VulnerabilityScanner } from "./types.js";

export type {
  DbUpdateResult,
  MatchResult,
  ParsedFinding,
  ReachabilityResult,
  ScannablePackage,
  ScannerAvailability,
  ScannerDbStatus,
  VulnerabilityScanner,
} from "./types.js";
export { GrypeScanner } from "./grype.js";
export { parseGrypeReport, buildScanDocument, toSeverity, toFixState, pickCvss, pickEpss, collectAliases } from "./grype-output.js";
export { resolveGrypeBinary } from "./grype-binary.js";

/**
 * Builds the scanner.
 *
 * One implementation today, chosen the same way `createBlobStore` picks fs or s3.
 * The factory exists so the rest of the platform depends on the port rather than on
 * Grype, which is what lets the wiring tests substitute a fake with no subprocess.
 */
export function createScanner(config: Config): VulnerabilityScanner {
  return new GrypeScanner(config);
}
