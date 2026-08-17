import { z } from "zod";
import type { ScanSource } from "../enums.js";
import { paginationQuerySchema, uuidSchema } from "./common.js";

export const listScansQuerySchema = paginationQuerySchema.extend({
  branch: z.string().trim().max(255).optional(),
  sortDir: z.enum(["asc", "desc"]).default("desc"),
});
export type ListScansQuery = z.infer<typeof listScansQuerySchema>;

/** A language runtime or application server observed in the image. */
export interface DetectedRuntime {
  /** Canonical name: `node`, `python`, `java`, `nginx`, ... */
  name: string;
  version: string | null;
}

/**
 * What the scanned image is built on, derived from the SBOM's own contents.
 *
 * Every field is nullable, and that is meaningful rather than missing: a scratch
 * or distroless image has no OS release file and no runtime binary.
 *
 * This describes observed *contents*, not image ancestry. An SBOM sees a
 * flattened filesystem, so nothing here can report that the Dockerfile said
 * `FROM node:22-alpine` — only that Node 22 and Alpine files are present.
 */
export interface ScanPlatform {
  osName: string | null;
  osVersion: string | null;
  osPretty: string | null;
  runtimes: DetectedRuntime[];
  /** Pre-rendered one-liner, e.g. `Alpine 3.20.3 · Node.js 22.11.0`. Null when nothing was detected. */
  summary: string | null;
}

export interface ScanSummary {
  id: string;
  applicationId: string;
  createdAt: string;
  commitSha: string | null;
  buildNumber: string | null;
  pipelineId: string | null;
  imageRef: string | null;
  branch: string | null;
  componentCount: number;
  /** CycloneDX `metadata.tools` — which Syft version produced this SBOM. */
  toolName: string | null;
  toolVersion: string | null;
  sbomSizeBytes: number;
  /** True when this scan is its application's current state. */
  isLatest: boolean;
  platform: ScanPlatform;
  /**
   * How the SBOM arrived: a CI pipeline, or a person uploading it by hand.
   *
   * Carried on the summary rather than only the detail view so the history table
   * can label it. A hand-uploaded build that looks identical to a pipeline's in
   * the list would quietly misrepresent where the data came from.
   */
  source: ScanSource;
  /** Set for `manual` scans. Survives deletion of the uploader's account. */
  uploadedByEmail: string | null;
}

export const listScanComponentsQuerySchema = paginationQuerySchema.extend({
  search: z.string().trim().max(255).optional(),
  ecosystem: z.string().trim().max(64).optional(),
  sortBy: z.enum(["name", "version", "ecosystem"]).default("name"),
  sortDir: z.enum(["asc", "desc"]).default("asc"),
});
export type ListScanComponentsQuery = z.infer<typeof listScanComponentsQuerySchema>;

export interface ComponentRef {
  id: string;
  name: string;
  version: string | null;
  ecosystem: string;
  purl: string | null;
}

// --- diff -------------------------------------------------------------------

/**
 * Compare two scans of the same application. When `fromScanId` is omitted the
 * API picks the immediately-previous scan; when `toScanId` is omitted it uses
 * the application's latest scan.
 */
export const scanDiffQuerySchema = z.object({
  fromScanId: uuidSchema.optional(),
  toScanId: uuidSchema.optional(),
});
export type ScanDiffQuery = z.infer<typeof scanDiffQuerySchema>;

export interface RemovedComponent extends ComponentRef {
  /** The most recent scan of this application that still contained the component. */
  lastSeenScanId: string;
  lastSeenAt: string;
  lastSeenBuildNumber: string | null;
}

export interface ScanDiff {
  applicationId: string;
  fromScan: Pick<ScanSummary, "id" | "createdAt" | "commitSha" | "buildNumber">;
  toScan: Pick<ScanSummary, "id" | "createdAt" | "commitSha" | "buildNumber">;
  added: ComponentRef[];
  removed: RemovedComponent[];
  /** Same package name + ecosystem, different version. */
  changed: Array<{
    name: string;
    ecosystem: string;
    fromVersion: string | null;
    toVersion: string | null;
    fromComponentId: string;
    toComponentId: string;
  }>;
  unchangedCount: number;
  /** True when either side was capped; the counts are then lower bounds. */
  truncated: boolean;
}

/**
 * Everything this application has *ever* shipped that its current build does
 * not contain.
 *
 * Distinct from the scan-to-scan diff: this looks across the whole retained
 * history, so a package dropped twenty builds ago still appears with the build
 * it was last seen in. This is the "package X was used before but is not in the
 * current build" view, and it is the reason scan history is kept indefinitely.
 */
export const listRemovedComponentsQuerySchema = paginationQuerySchema.extend({
  search: z.string().trim().max(255).optional(),
  ecosystem: z.string().trim().max(64).optional(),
  /**
   * When true, a package counts as removed only if no version of it remains.
   * When false (the default), an upgraded package reports its old version as
   * removed — which is usually what someone auditing a specific vulnerable
   * version wants to see.
   */
  ignoreVersion: z
    .enum(["true", "false"])
    .transform((v) => v === "true")
    .default("false"),
  sortBy: z.enum(["lastSeenAt", "name"]).default("lastSeenAt"),
  sortDir: z.enum(["asc", "desc"]).default("desc"),
});
export type ListRemovedComponentsQuery = z.infer<typeof listRemovedComponentsQuerySchema>;
