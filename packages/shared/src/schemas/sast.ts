import { z } from "zod";
import { applicationNameSchema } from "./application.js";

/**
 * Static-analysis findings from `sast-scan` (see `sast-scan/README.md`).
 *
 * A deliberately separate ladder and a deliberately separate table set
 * (`sast_run` / `sast_finding`) from `VulnSeverity` and `component_vulnerability`.
 * A SAST finding is a file/line in this application's own source, not a
 * package/version match against a CVE database — see "Static analysis (SAST)"
 * in the top-level README for why the two are not merged.
 */
export const sastSeverities = ["low", "medium", "high", "critical"] as const;
export const sastSeveritySchema = z.enum(sastSeverities);
export type SastSeverity = z.infer<typeof sastSeveritySchema>;

/**
 * Which of sast-scan's three detection methods produced a finding.
 *
 * Stored rather than inferred from the rule id's prefix: a custom rules file
 * may use any id it likes, and the UI's category filter must keep working for
 * rules this platform has never seen.
 */
export const sastCategories = ["secrets", "ast", "taint"] as const;
export const sastCategorySchema = z.enum(sastCategories);
export type SastCategory = z.infer<typeof sastCategorySchema>;

/** Display order and sort weight — highest first, same convention as SEVERITY_ORDER. */
export const SAST_SEVERITY_ORDER: Record<SastSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * One finding exactly as `python3 -m sast ... --format json` emits it, modulo
 * case: the CLI's `Severity` enum prints upper-case (`"HIGH"`); lower-cased on
 * the way in so it agrees with `sastSeverities` and with how `VulnSeverity`
 * elsewhere in this package is cased.
 */
export const sastFindingInputSchema = z.object({
  rule_id: z.string().trim().min(1).max(200),
  severity: z
    .string()
    .trim()
    .toLowerCase()
    .pipe(sastSeveritySchema),
  cwe: z.number().int().nonnegative(),
  message: z.string().trim().min(1).max(2000),
  file: z.string().trim().min(1).max(1024),
  line: z.number().int().positive(),
  col: z.number().int().positive(),
  /*
   * Both optional: a pipeline pinned to an older sast-scan predates them, and
   * refusing that upload would turn a scanner upgrade into a coordinated
   * deploy. Absent category defaults to `ast` (what the bundled rules mostly
   * are); absent remediation renders as "no guidance for this rule".
   */
  category: sastCategorySchema.default("ast"),
  remediation: z.string().trim().max(2000).default(""),
});
export type SastFindingInput = z.infer<typeof sastFindingInputSchema>;

/**
 * Body of `POST /api/v1/sast` — JSON, not multipart: there is no file, only the
 * array `sast-scan --format json` already produced. Field names below
 * deliberately match `ingestScanFieldsSchema`'s so a CI author who has already
 * wired up the SBOM upload recognises the shape immediately.
 */
export const ingestSastRequestSchema = z.object({
  app_name: applicationNameSchema,
  /** Same rule as the SBOM ingest endpoint's `environment` field — see ingest.ts. */
  environment: z.string().trim().min(1).max(60).optional(),
  commit_sha: z.string().trim().max(255).optional(),
  branch: z.string().trim().max(255).optional(),
  /**
   * Capped well above any real run: sast-scan's own fixtures top out in the
   * dozens. A number in the thousands is far more likely a misconfigured
   * `SAST_TARGET` (e.g. scanning `node_modules`) than a legitimate result.
   */
  findings: z.array(sastFindingInputSchema).max(5000),
});
export type IngestSastRequest = z.infer<typeof ingestSastRequestSchema>;

export type SastSeverityCounts = Record<SastSeverity, number>;

export function emptySastSeverityCounts(): SastSeverityCounts {
  return { low: 0, medium: 0, high: 0, critical: 0 };
}

export interface IngestSastResponse {
  runId: string;
  applicationId: string;
  applicationName: string;
  findingCount: number;
  severityCounts: SastSeverityCounts;
}

export interface SastFinding {
  id: string;
  ruleId: string;
  severity: SastSeverity;
  cwe: number;
  message: string;
  file: string;
  line: number;
  col: number;
  category: SastCategory;
  /** Empty when the rule that produced this finding shipped no guidance. */
  remediation: string;
}

/**
 * The latest SAST run for one application, with its findings inline.
 *
 * Unpaginated on purpose, like `VulnStatus`'s finding list: a run's finding
 * count is capped at 5000 by `ingestSastRequestSchema`, and in practice a real
 * one is a few dozen — small enough that a second request for "page 2" would
 * cost more than sending the rest up front.
 */
/**
 * One row of an application's SAST run history.
 *
 * Header fields only -- deliberately without `findings`, so the history list
 * stays one small query. The findings come from asking for that run
 * specifically.
 */
export interface SastRunListEntry {
  runId: string;
  commitSha: string | null;
  branch: string | null;
  createdAt: string;
  findingCount: number;
  severityCounts: SastSeverityCounts;
  /** True for the run the application's Static analysis tab shows by default. */
  isLatest: boolean;
}

export interface SastRunSummary {
  runId: string;
  applicationId: string;
  commitSha: string | null;
  branch: string | null;
  createdAt: string;
  findingCount: number;
  severityCounts: SastSeverityCounts;
  findings: SastFinding[];
}
