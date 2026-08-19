import { z } from "zod";
import type { ScanSource } from "../enums.js";
import { paginationQuerySchema, uuidSchema } from "./common.js";
import { defineSortTable } from "./sort.js";

/**
 * Sortable columns of an application's scan history.
 *
 * Defaults to newest first — a build list is read from the top, and "what shipped most
 * recently" is the question the page exists to answer.
 */
export const scanHistorySort = defineSortTable(
  {
    scannedAt: "date",
    buildNumber: "text",
    commitSha: "text",
    branch: "text",
    componentCount: "number",
    imageRef: "text",
    source: "text",
  } as const,
  "scannedAt",
);

export const listScansQuerySchema = paginationQuerySchema
  .extend({
    branch: z.string().trim().max(255).optional(),
  })
  .merge(scanHistorySort.querySchema);
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

/** Sortable columns of a component list — a scan's inventory, or an application's. */
export const componentListSort = defineSortTable(
  { name: "text", version: "text", ecosystem: "text", purl: "text" } as const,
  "name",
);

export const listScanComponentsQuerySchema = paginationQuerySchema
  .extend({
    search: z.string().trim().max(255).optional(),
    ecosystem: z.string().trim().max(64).optional(),
  })
  .merge(componentListSort.querySchema);
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
/** Sortable columns of the removed-components table. Defaults to most recently dropped. */
export const removedComponentSort = defineSortTable(
  { name: "text", version: "text", ecosystem: "text", lastSeenAt: "date", purl: "text" } as const,
  "lastSeenAt",
);

export const listRemovedComponentsQuerySchema = paginationQuerySchema
  .extend({
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
  })
  .merge(removedComponentSort.querySchema);
export type ListRemovedComponentsQuery = z.infer<typeof listRemovedComponentsQuerySchema>;

// --- deletion ---------------------------------------------------------------

/**
 * The outcome of removing one scan from an application's history.
 *
 * Every field exists because the caller cannot infer it. A deletion here is not a
 * row disappearing from a table: removing the current build promotes the one
 * before it, which changes the application's component list, its findings, and
 * its contribution to every dashboard figure. The UI has to be able to say which
 * of those happened, and the audit trail has to record it.
 */
export interface DeleteScanResponse {
  applicationId: string;
  /** True when the deleted scan had been the application's current state. */
  wasLatest: boolean;
  /**
   * The build promoted back to current, or null when the application now has no
   * scans at all and has returned to "never scanned".
   *
   * Only meaningful when `wasLatest`; otherwise it is the unchanged current build.
   */
  currentScanId: string | null;
  /** Scans left in this application's history. */
  remainingScanCount: number;
  /**
   * Whether the raw CycloneDX document was removed along with the scan.
   *
   * False when another scan still holds a byte-identical SBOM — blobs are
   * content-addressed and therefore shared, so a rebuild of unchanged code has
   * the same key. Reported rather than assumed, because "the original upload is
   * gone" is a different claim from "the scan record is gone".
   */
  rawSbomDeleted: boolean;
}
