import { z } from "zod";
import { paginationQuerySchema } from "./common.js";
import { defineSortTable } from "./sort.js";

// --- audit trail ------------------------------------------------------------

/**
 * Sortable columns of the audit trail. Newest first by default — an audit log is read
 * from the top, and "what just happened" is the question it is usually opened for.
 *
 * `metadata` is deliberately not sortable: it is a jsonb blob whose shape differs per
 * action, so there is no ordering of it that would mean anything to a reader.
 */
export const auditSort = defineSortTable(
  { createdAt: "date", actorEmail: "text", action: "text", targetType: "text" } as const,
  "createdAt",
);

export const listAuditLogQuerySchema = paginationQuerySchema
  .extend({
    targetType: z.enum(["application", "user", "attribute_definition", "ingest_token", "scan"]).optional(),
    targetId: z.string().trim().max(64).optional(),
    action: z.string().trim().max(64).optional(),
  })
  .merge(auditSort.querySchema);
export type ListAuditLogQuery = z.infer<typeof listAuditLogQuerySchema>;

export interface AuditLogEntry {
  id: string;
  actorUserId: string | null;
  /** Denormalised, so the trail stays readable after the actor's account is deleted. */
  actorEmail: string | null;
  action: string;
  targetType: string;
  targetId: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
}

// --- CI ingest tokens -------------------------------------------------------

export const createIngestTokenRequestSchema = z.object({
  /** Identifies the CI system, e.g. `jenkins` or `gitlab-prod`. Recorded on every scan it submits. */
  name: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9][a-z0-9._-]*$/i, "letters, digits, dot, dash and underscore only"),
});
export type CreateIngestTokenRequest = z.infer<typeof createIngestTokenRequestSchema>;

export interface IngestTokenSummary {
  /** Null for tokens configured via the INGEST_TOKENS environment variable. */
  id: string | null;
  name: string;
  /** Last 4 characters of the plaintext, so two tokens can be told apart. */
  tokenSuffix: string;
  isActive: boolean;
  /**
   * `env` tokens come from configuration and cannot be revoked through the UI —
   * they exist as a break-glass path for when every database token is revoked.
   */
  source: "db" | "env";
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string | null;
}

/** The plaintext is returned exactly once, at creation. Only its hash is stored. */
export interface CreateIngestTokenResponse {
  token: IngestTokenSummary;
  plaintext: string;
}

// --- dashboard --------------------------------------------------------------

/**
 * Whole-estate counters for the landing page.
 *
 * Every figure here is a plain aggregate over data the platform already stores.
 * Nothing is precomputed or cached: at ~1000 applications the queries run in
 * milliseconds off existing indexes, and a materialised view would be one more
 * thing that can silently go stale.
 */
export interface DashboardStats {
  applications: {
    total: number;
    active: number;
    inactive: number;
    pendingConfirmation: number;
    /** Active apps whose latest scan is older than STALE_APP_THRESHOLD_DAYS. */
    stale: number;
    /** Registered but never scanned. */
    neverScanned: number;
  };
  scans: {
    total: number;
    last24h: number;
    last7d: number;
    latestAt: string | null;
  };
  components: {
    /** Distinct packages known across the whole estate. */
    distinct: number;
    /** Distinct packages present in some application's current state. */
    inCurrentUse: number;
  };
  staleThresholdDays: number;
}

export interface EcosystemBreakdownEntry {
  ecosystem: string;
  /** Distinct packages of this ecosystem in current use. */
  components: number;
  /** Applications currently shipping at least one package of this ecosystem. */
  applications: number;
  /**
   * The applications behind that count, capped at EXPANDABLE_LIST_CAP.
   *
   * Produced by the same aggregate and the same WHERE clause as the count, so the two
   * cannot disagree on screen. See EXPANDABLE_LIST_CAP for why that is a constraint rather
   * than a convenience.
   */
  applicationList: string[];
}

/** Packages present in the most applications right now — the blast-radius list. */
export interface TopComponentEntry {
  componentId: string;
  name: string;
  version: string | null;
  ecosystem: string;
  applications: number;
  /**
   * The applications behind that count, capped at EXPANDABLE_LIST_CAP.
   *
   * Produced by the same aggregate and the same WHERE clause as the count, so the two
   * cannot disagree on screen. See EXPANDABLE_LIST_CAP for why that is a constraint rather
   * than a convenience.
   */
  applicationList: string[];
}

/**
 * How many applications currently run each OS and each runtime.
 *
 * The upgrade-planning view: "nine applications on Node 22, three still on Node
 * 18" is the number that decides whether an upgrade is a ticket or a programme.
 * Counted over each application's current build only — a runtime that was
 * dropped six months ago is not something anyone needs to plan around.
 */
export interface PlatformBreakdown {
  operatingSystems: Array<{
    /** Distro id as reported, e.g. `alpine`. Null groups applications where none was detected. */
    name: string | null;
    version: string | null;
    applications: number;
    /** The applications behind that count, capped at EXPANDABLE_LIST_CAP. */
    applicationList: string[];
  }>;
  runtimes: Array<{
    name: string;
    version: string | null;
    applications: number;
    /** The applications behind that count, capped at EXPANDABLE_LIST_CAP. */
    applicationList: string[];
  }>;
  /** Applications whose current build revealed no OS and no runtime at all. */
  unknown: number;
}

export const topComponentsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(50).default(10),
  /** Group by package name instead of name+version, to see total reach across versions. */
  groupByName: z
    .enum(["true", "false"])
    .transform((v) => v === "true")
    .default("false"),
});
export type TopComponentsQuery = z.infer<typeof topComponentsQuerySchema>;
