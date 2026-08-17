import { z } from "zod";
import { applicationNameSchema } from "./application.js";

/**
 * Metadata fields accepted alongside the `sbom` file part on
 * `POST /api/v1/scans`. Sent as `multipart/form-data`, so every value arrives
 * as a string and empty strings must be treated as absent — CI templates
 * routinely interpolate unset variables into empty form fields.
 */
const optionalFormString = (max: number) =>
  z
    .string()
    .trim()
    .max(max)
    .transform((v) => (v === "" ? undefined : v))
    .optional();

export const ingestScanFieldsSchema = z.object({
  app_name: applicationNameSchema,
  commit_sha: optionalFormString(255),
  build_number: optionalFormString(255),
  pipeline_id: optionalFormString(255),
  image_ref: optionalFormString(1024),
  branch: optionalFormString(255),
});
export type IngestScanFields = z.infer<typeof ingestScanFieldsSchema>;

/**
 * Metadata accepted alongside the `sbom` file part on
 * `POST /api/v1/applications/:id/scans` — a signed-in user uploading an SBOM by
 * hand from an application's scan history.
 *
 * Deliberately the same field names as the CI form, minus `app_name` (the
 * application comes from the URL) and `pipeline_id` (a manual upload has no
 * pipeline). Matching names mean someone who has read the CI template can fill
 * this in without a second reference, and the stored row is indistinguishable in
 * shape from a pipeline's.
 */
export const manualUploadFieldsSchema = z.object({
  commit_sha: optionalFormString(255),
  build_number: optionalFormString(255),
  image_ref: optionalFormString(1024),
  branch: optionalFormString(255),
  /** Why this was uploaded by hand. Free text, surfaced on the scan detail page. */
  note: optionalFormString(500),
  /**
   * Set to `true` to store an SBOM this application has already received.
   *
   * Without it, a byte-identical re-upload is refused with a 409 rather than
   * silently creating a second identical build — a double-click on the upload
   * button is far more likely than a genuine need for the duplicate.
   */
  allow_duplicate: z
    .enum(["true", "false"])
    .default("false")
    .transform((v) => v === "true"),
});
export type ManualUploadFields = z.infer<typeof manualUploadFieldsSchema>;

export interface IngestScanResponse {
  scanId: string;
  applicationId: string;
  applicationName: string;
  applicationStatus: "active" | "inactive" | "pending_confirmation";
  /** True when this scan caused the application to be auto-created as pending. */
  applicationCreated: boolean;
  /** Set when an alias from a merge-always redirected this scan to another app. */
  redirectedFrom: string | null;
  componentCount: number;
  /** Components in the SBOM that were skipped, with a reason, so CI logs are actionable. */
  skippedComponents: number;
}

export interface ManualUploadResponse extends IngestScanResponse {
  /** Always `manual` here. Present so the client renders provenance from the response, not an assumption. */
  source: "manual";
  /**
   * True when this scan is now the application's current build.
   *
   * Effectively always true — a manual upload is stamped `now()`, and the latest
   * pointer only moves forward — but reported rather than assumed, because the
   * pointer is advanced by SQL that a concurrent CI push also competes in.
   */
  becameLatest: boolean;
  /**
   * The earlier scan this upload duplicates, when it was stored anyway via
   * `allow_duplicate`. Null on a first upload.
   */
  duplicateOfScanId: string | null;
}

/**
 * `error.details` on the 409 a duplicate upload receives.
 *
 * Names the existing scan so the UI can link to it instead of asking the user to
 * go hunting for the build they may have already uploaded.
 */
export interface DuplicateSbomDetails {
  existingScanId: string;
  existingScanCreatedAt: string;
  existingBuildNumber: string | null;
  /** True when the matching scan is the application's current build. */
  existingIsLatest: boolean;
}
