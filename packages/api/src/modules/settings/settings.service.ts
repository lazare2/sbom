import { sql, type SQL } from "drizzle-orm";
import {
  STALE_THRESHOLD_MAX_DAYS,
  STALE_THRESHOLD_MIN_DAYS,
  VULN_DB_INTERVAL_DEFAULT_HOURS,
  type PlatformSettings,
} from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { setting } from "../../db/schema.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { Actor } from "../admin/audit.service.js";

/**
 * Admin-editable runtime settings.
 *
 * Distinct from `config.ts`, which reads the environment once at boot and belongs to
 * whoever deploys the service. This is for the few values an administrator changes
 * from the UI while it runs.
 *
 * Deliberately narrow: two keys, both typed, neither of which can influence what code
 * the server executes. Executable paths and credentials stay in the environment,
 * where changing them needs deployment access rather than an admin session.
 */

export const SETTING_KEYS = {
  /** Master switch for vulnerability scanning. Off on a fresh install. */
  vulnEnabled: "vuln.enabled",
  /** Hours between scheduled database update checks. */
  vulnIntervalHours: "vuln.interval_hours",
  /** Days without a scan before an application counts as stale. */
  staleThresholdDays: "app.stale_threshold_days",
} as const;

export interface VulnSettings {
  enabled: boolean;
  intervalHours: number;
}

/**
 * Off by default, and that default lives here rather than in a migration.
 *
 * A migration-inserted row would make "never configured" and "explicitly disabled"
 * indistinguishable, and would silently re-enable the feature for anyone who deleted
 * the row expecting it to reset.
 */
export const DEFAULT_VULN_SETTINGS: VulnSettings = {
  enabled: false,
  intervalHours: VULN_DB_INTERVAL_DEFAULT_HOURS,
};

export class SettingsService {
  /**
   * Short-lived cache.
   *
   * The enabled flag is consulted on nearly every request that could render
   * vulnerability data, so reading it from Postgres each time would add a query to
   * most page loads. A few seconds of staleness is the right trade: it keeps the read
   * path cheap while still letting a second replica notice a toggle without any
   * cross-process invalidation machinery.
   */
  private cache: { value: VulnSettings; expiresAt: number } | null = null;
  private static readonly CACHE_TTL_MS = 5_000;

  /**
   * Cached separately from the vulnerability settings.
   *
   * The stale threshold is read by the applications list, the overview and the analytics
   * report -- three of the busiest queries -- so it gets the same short TTL for the same
   * reason. Separate entry rather than one combined object so a vulnerability toggle does
   * not invalidate it, and vice versa.
   */
  private platformCache: { value: PlatformSettings; expiresAt: number } | null = null;

  constructor(private readonly deps: { db: Database; config: Config }) {}

  /**
   * The stale threshold, falling back to the deployment's environment value.
   *
   * The fallback is the environment rather than a literal so that clearing the override
   * returns to whatever the deployment chose, and an operator who never opens the settings
   * page sees no change in behaviour from this feature existing.
   */
  async getPlatformSettings(): Promise<PlatformSettings> {
    if (this.platformCache && this.platformCache.expiresAt > Date.now()) {
      return this.platformCache.value;
    }

    const value: PlatformSettings = {
      staleThresholdDays: this.deps.config.STALE_APP_THRESHOLD_DAYS,
    };

    const rows = await this.deps.db.execute<Row<{ key: string; value: unknown }>>(sql`
      SELECT key, value FROM setting WHERE key = ${SETTING_KEYS.staleThresholdDays}
    `);
    for (const row of rowsOf(rows)) {
      // Re-validated on read, not only on write. A row can predate a narrowing of the
      // bounds, or be edited straight in the database, and an out-of-range interval reaches
      // SQL as an interval literal.
      if (
        typeof row.value === "number" &&
        Number.isInteger(row.value) &&
        row.value >= STALE_THRESHOLD_MIN_DAYS &&
        row.value <= STALE_THRESHOLD_MAX_DAYS
      ) {
        value.staleThresholdDays = row.value;
      }
    }

    this.platformCache = { value, expiresAt: Date.now() + SettingsService.CACHE_TTL_MS };
    return value;
  }

  /**
   * Days as a SQL interval, for the queries that compare a scan date against it.
   *
   * Built here rather than at each call site so the three places that ask "is this stale"
   * cannot disagree. Interpolated as a literal after `Math.trunc`, which is safe because the
   * value is an integer validated on both write and read -- but the truncation is what makes
   * that guarantee local rather than an assumption about callers.
   */
  async staleInterval(): Promise<SQL> {
    const { staleThresholdDays } = await this.getPlatformSettings();
    return sql.raw(`interval '${Math.trunc(staleThresholdDays)} days'`);
  }

  async updatePlatformSettings(
    patch: { staleThresholdDays?: number | undefined },
    actor: Actor | null,
  ): Promise<{ before: PlatformSettings; after: PlatformSettings }> {
    const before = await this.getPlatformSettings();

    if (patch.staleThresholdDays !== undefined) {
      await this.deps.db
        .insert(setting)
        .values({
          key: SETTING_KEYS.staleThresholdDays,
          value: patch.staleThresholdDays,
          updatedByUserId: actor?.id ?? null,
          updatedByEmail: actor?.email ?? null,
        })
        .onConflictDoUpdate({
          target: setting.key,
          set: {
            value: patch.staleThresholdDays,
            updatedAt: new Date(),
            updatedByUserId: actor?.id ?? null,
            updatedByEmail: actor?.email ?? null,
          },
        });
    }

    this.platformCache = null;
    return { before, after: await this.getPlatformSettings() };
  }

  async getVulnSettings(): Promise<VulnSettings> {
    if (this.cache && this.cache.expiresAt > Date.now()) return this.cache.value;

    const rows = await this.deps.db.execute<Row<{ key: string; value: unknown }>>(sql`
      SELECT key, value FROM setting
      WHERE key IN (${SETTING_KEYS.vulnEnabled}, ${SETTING_KEYS.vulnIntervalHours})
    `);

    const value = { ...DEFAULT_VULN_SETTINGS };
    for (const row of rowsOf(rows)) {
      if (row.key === SETTING_KEYS.vulnEnabled && typeof row.value === "boolean") {
        value.enabled = row.value;
      }
      if (
        row.key === SETTING_KEYS.vulnIntervalHours &&
        typeof row.value === "number" &&
        Number.isFinite(row.value) &&
        row.value > 0
      ) {
        value.intervalHours = row.value;
      }
    }

    this.cache = { value, expiresAt: Date.now() + SettingsService.CACHE_TTL_MS };
    return value;
  }

  /**
   * Convenience read used on the hot path.
   *
   * Fails closed: if the settings table cannot be read, scanning is reported as
   * disabled rather than assumed on. A database problem must not cause the platform
   * to start rendering half-populated vulnerability figures.
   */
  async vulnScanningEnabled(): Promise<boolean> {
    try {
      return (await this.getVulnSettings()).enabled;
    } catch {
      return false;
    }
  }

  /**
   * Writes one or both vulnerability settings.
   *
   * Returns both the previous and the new value: the caller needs the transition to
   * decide what to do next — switching scanning on is what triggers the initial
   * sweep, and it is also what the audit entry has to record.
   */
  async updateVulnSettings(
    patch: { enabled?: boolean | undefined; intervalHours?: number | undefined },
    actor: Actor | null,
  ): Promise<{ before: VulnSettings; after: VulnSettings }> {
    const before = await this.getVulnSettings();

    const entries: Array<{ key: string; value: unknown }> = [];
    if (patch.enabled !== undefined) {
      entries.push({ key: SETTING_KEYS.vulnEnabled, value: patch.enabled });
    }
    if (patch.intervalHours !== undefined) {
      entries.push({ key: SETTING_KEYS.vulnIntervalHours, value: patch.intervalHours });
    }

    for (const entry of entries) {
      await this.deps.db
        .insert(setting)
        .values({
          key: entry.key,
          value: entry.value,
          updatedByUserId: actor?.id ?? null,
          updatedByEmail: actor?.email ?? null,
        })
        .onConflictDoUpdate({
          target: setting.key,
          set: {
            value: entry.value,
            updatedAt: new Date(),
            updatedByUserId: actor?.id ?? null,
            updatedByEmail: actor?.email ?? null,
          },
        });
    }

    // Dropped rather than patched: the next read repopulates from the table, so a
    // failed write can never leave the cache asserting something that was not stored.
    this.cache = null;
    const after = await this.getVulnSettings();
    return { before, after };
  }

  /** Test and toggle helper: forces the next read to hit the database. */
  invalidate(): void {
    this.cache = null;
  }
}
