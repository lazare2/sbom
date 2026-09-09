import { sql, type SQL } from "drizzle-orm";
import {
  DEFAULT_REPORT_BODY,
  DEFAULT_REPORT_SUBJECT,
  REPORT_DEFAULT_TIMEZONE,
  STALE_THRESHOLD_MAX_DAYS,
  STALE_THRESHOLD_MIN_DAYS,
  VULN_DB_INTERVAL_DEFAULT_HOURS,
  reportSettingsFieldsSchema,
  updateReportSettingsSchema,
  updateMaliciousSettingsSchema,
  MALICIOUS_DEFAULT_FEED_URL,
  type MaliciousSettings,
  type VulnProvider,
  type XrayConnectionInput,
  type XrayCoverage,
  type XraySettings,
  type PlatformSettings,
  type ReportSettings,
} from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { setting } from "../../db/schema.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { Actor } from "../admin/audit.service.js";
import { BadRequestError } from "../../lib/errors.js";
import { openSecret, sealSecret } from "../../lib/secret-box.js";
import type { XrayCredentials } from "../../services/scanner/xray-client.js";

/**
 * Admin-editable runtime settings.
 *
 * Distinct from `config.ts`, which reads the environment once at boot and belongs to
 * whoever deploys the service. This is for the few values an administrator changes
 * from the UI while it runs.
 *
 * Deliberately narrow: every key here is typed, and none of them can influence what code
 * the server executes. Executable paths and credentials stay in the environment, where
 * changing them needs deployment access rather than an admin session.
 *
 * The report's mail settings are the one thing here that reaches the network, and they are
 * held to the same rule. The host is validated as a bare hostname so it cannot smuggle a
 * scheme or a credential pair, and there is no password field at all: a secret stored here
 * would be readable by every administrator and written to the audit log when it changed.
 */

export const SETTING_KEYS = {
  /** Master switch for vulnerability scanning. Off on a fresh install. */
  vulnEnabled: "vuln.enabled",
  /** Hours between scheduled database update checks. */
  vulnIntervalHours: "vuln.interval_hours",
  /** Days without a scan before an application counts as stale. */
  staleThresholdDays: "app.stale_threshold_days",
  /** Monthly report delivery, stored as one JSON object. */
  reportDelivery: "report.delivery",
  /**
   * Malicious-package detection, stored as one JSON object.
   *
   * Its own key rather than fields on the vulnerability settings, because the two features
   * are independently switchable on purpose: an estate may want the malicious feed -- small,
   * fast, no scanner binary -- while leaving Grype off entirely, and one combined object
   * would make disabling either of them rewrite the other's configuration.
   */
  maliciousDetection: "malicious.detection",
  /**
   * Which vulnerability database is the authority, and how to reach it.
   *
   * One key rather than two, because the provider choice and the Xray connection are one
   * decision: switching to Xray with no connection configured is not a state anybody means
   * to be in, and separate keys would let a half-applied write produce exactly that.
   */
  vulnProvider: "vuln.provider",
} as const;

/**
 * Where the monthly report starts before anyone configures it.
 *
 * Disabled, with no host and no recipients, so a fresh install cannot mail anything to
 * anyone. Everything else is a working default an administrator only has to change if they
 * disagree with it.
 */
export const DEFAULT_REPORT_SETTINGS: ReportSettings = {
  enabled: false,
  smtpHost: "",
  smtpPort: 25,
  smtpEncryption: "none",
  smtpFrom: "",
  recipients: [],
  timeZone: REPORT_DEFAULT_TIMEZONE,
  sendHour: 9,
  subjectTemplate: DEFAULT_REPORT_SUBJECT,
  bodyTemplate: DEFAULT_REPORT_BODY,
};

/**
 * Where malicious-package detection starts on a fresh install.
 *
 * Off, like vulnerability scanning, and for a stronger reason: enabling it downloads a
 * 40 MB archive from the public internet, which is not something a platform should do on
 * first boot without somebody asking for it. Alerts are off separately, so switching
 * detection on cannot start mailing people before recipients have been chosen.
 */
export const DEFAULT_MALICIOUS_SETTINGS: MaliciousSettings = {
  enabled: false,
  intervalHours: 6,
  feedUrl: MALICIOUS_DEFAULT_FEED_URL,
  alertsEnabled: false,
  alertRecipients: [],
};

/** The stored shape. `tokenEnvelope` is ciphertext and never leaves this service as-is. */
interface StoredXray {
  baseUrl: string;
  username: string;
  tokenEnvelope: string | null;
  allowSelfSignedCertificate: boolean;
}

interface StoredProviderSettings {
  provider: VulnProvider;
  xray: StoredXray;
  coverage: XrayCoverage | null;
  /** ISO timestamp standing in for a database build date, which Xray does not publish. */
  assessmentEpoch: string;
}

/**
 * Grype, and no connection.
 *
 * The default has to be the local database: a deployment that has never opened this screen,
 * or whose stored value cannot be read, must keep scanning rather than silently stop.
 */
const DEFAULT_PROVIDER_SETTINGS: StoredProviderSettings = {
  provider: "grype",
  xray: { baseUrl: "", username: "", tokenEnvelope: null, allowSelfSignedCertificate: false },
  coverage: null,
  assessmentEpoch: new Date(0).toISOString(),
};

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

  /**
   * Report settings, cached like the others.
   *
   * Read by the scheduler on every tick rather than by a request path, so the TTL matters
   * less here -- but a shared cache would mean a change to the send hour waited on a
   * vulnerability toggle to take effect, which is the kind of coupling that produces a bug
   * report once a month.
   */
  private reportCache: { value: ReportSettings; expiresAt: number } | null = null;

  /**
   * Malicious-detection settings, cached like the rest.
   *
   * Read by the findings endpoints on every request that could render a finding, so it gets
   * the same short TTL as the vulnerability flag for the same reason.
   */
  private maliciousCache: { value: MaliciousSettings; expiresAt: number } | null = null;

  /**
   * Provider settings, cached like the rest.
   *
   * Read on every sweep tick and by the scanner resolver, so an uncached read would put a
   * query in front of every match. Its own entry rather than a shared one so that changing
   * the relay or a vulnerability toggle does not invalidate the credentials.
   */
  private providerCache: { value: StoredProviderSettings; expiresAt: number } | null = null;

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

  /**
   * Monthly report delivery settings.
   *
   * Re-validated on read against the same schema that guards the write. A row can predate a
   * change to the rules or be edited straight in the database, and this value decides where
   * the platform opens a network connection and who receives an email -- neither of which
   * should be reachable by writing a bad row.
   *
   * An invalid field falls back to its default rather than failing the read, because the
   * consequence of a bad host is a report that does not send, while the consequence of
   * throwing here is an admin page that cannot be opened to fix it.
   */
  async getReportSettings(): Promise<ReportSettings> {
    if (this.reportCache && this.reportCache.expiresAt > Date.now()) return this.reportCache.value;

    const rows = await this.deps.db.execute<Row<{ value: unknown }>>(sql`
      SELECT value FROM setting WHERE key = ${SETTING_KEYS.reportDelivery}
    `);

    const stored = rowsOf(rows)[0]?.value;
    let value = { ...DEFAULT_REPORT_SETTINGS };

    if (stored && typeof stored === "object") {
      const parsed = updateReportSettingsSchema.safeParse({
        ...DEFAULT_REPORT_SETTINGS,
        ...(stored as Record<string, unknown>),
      });
      if (parsed.success) {
        value = parsed.data;
      } else {
        /*
          Merged field by field rather than discarded wholesale. A single invalid field --
          a host that no longer passes a tightened rule, say -- should not throw away the
          recipient list an administrator spent time entering.
        */
        for (const [key, fieldSchema] of Object.entries(reportSettingsFieldsSchema.shape)) {
          const candidate = (stored as Record<string, unknown>)[key];
          if (candidate === undefined) continue;
          const field = fieldSchema.safeParse(candidate);
          if (field.success) (value as Record<string, unknown>)[key] = field.data;
        }
      }
    }

    this.reportCache = { value, expiresAt: Date.now() + SettingsService.CACHE_TTL_MS };
    return value;
  }

  /**
   * Whether the platform has everything it needs to actually send.
   *
   * Separate from `enabled` because they answer different questions: `enabled` is the
   * administrator's intent, this is whether that intent can be carried out. The scheduler
   * needs both, and the admin page needs to be able to explain which one is missing.
   */
  async reportDeliveryConfigured(): Promise<boolean> {
    const settings = await this.getReportSettings();
    return (
      settings.enabled &&
      settings.smtpHost.length > 0 &&
      settings.smtpFrom.length > 0 &&
      settings.recipients.length > 0
    );
  }

  async updateReportSettings(
    next: ReportSettings,
    actor: Actor | null,
  ): Promise<{ before: ReportSettings; after: ReportSettings }> {
    const before = await this.getReportSettings();

    await this.deps.db
      .insert(setting)
      .values({
        key: SETTING_KEYS.reportDelivery,
        value: next,
        updatedByUserId: actor?.id ?? null,
        updatedByEmail: actor?.email ?? null,
      })
      .onConflictDoUpdate({
        target: setting.key,
        set: {
          value: next,
          updatedAt: new Date(),
          updatedByUserId: actor?.id ?? null,
          updatedByEmail: actor?.email ?? null,
        },
      });

    this.reportCache = null;
    return { before, after: await this.getReportSettings() };
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

  // -- vulnerability provider -------------------------------------------------

  /**
   * Which vulnerability database is the authority, and how to reach it.
   *
   * Stored as one object under a single key, like the report's delivery settings, because
   * the provider choice and the Xray connection are one decision: switching to Xray with no
   * connection configured is not a state anybody means to be in, and two keys would let a
   * half-applied write produce exactly that.
   *
   * The token is held encrypted and is never part of what this method returns. Callers that
   * need to *use* it go through `xrayCredentials`, which is the only path that decrypts.
   */
  private async getProviderSettings(): Promise<StoredProviderSettings> {
    if (this.providerCache && this.providerCache.expiresAt > Date.now()) {
      return this.providerCache.value;
    }

    const rows = await this.deps.db.execute<Row<{ value: unknown }>>(sql`
      SELECT value FROM setting WHERE key = ${SETTING_KEYS.vulnProvider}
    `);

    const stored = rowsOf(rows)[0]?.value;
    const value: StoredProviderSettings = { ...DEFAULT_PROVIDER_SETTINGS };
    if (stored && typeof stored === "object") {
      const raw = stored as Record<string, unknown>;
      if (raw.provider === "grype" || raw.provider === "xray") value.provider = raw.provider;
      if (raw.xray && typeof raw.xray === "object") {
        value.xray = { ...value.xray, ...(raw.xray as Record<string, unknown>) } as StoredXray;
      }
      if (raw.coverage && typeof raw.coverage === "object") {
        value.coverage = raw.coverage as XrayCoverage;
      }
      if (typeof raw.assessmentEpoch === "string") value.assessmentEpoch = raw.assessmentEpoch;
    }

    this.providerCache = { value, expiresAt: Date.now() + SettingsService.CACHE_TTL_MS };
    return value;
  }

  /**
   * The active provider, defaulting to Grype.
   *
   * Read on every sweep and by the scanner resolver, so it is cached like the rest. The
   * fallback matters: a deployment that has never touched this setting, or one whose stored
   * value is unreadable, must keep matching against the local database rather than silently
   * stop scanning.
   */
  async vulnProvider(): Promise<VulnProvider> {
    try {
      return (await this.getProviderSettings()).provider;
    } catch {
      return "grype";
    }
  }

  /** What the admin screen reads back. Never the token — only whether one is stored. */
  async xraySettings(): Promise<XraySettings> {
    const stored = await this.getProviderSettings();
    const configured = stored.xray.baseUrl !== "" && stored.xray.username !== "";
    return {
      connection: configured
        ? {
            baseUrl: stored.xray.baseUrl,
            username: stored.xray.username,
            tokenConfigured: stored.xray.tokenEnvelope !== null,
            allowSelfSignedCertificate: stored.xray.allowSelfSignedCertificate,
          }
        : null,
      coverage: stored.coverage,
    };
  }

  /**
   * The data set the Xray scanner is matching against.
   *
   * Xray publishes no database build date, so one is kept here. It moves when the connection
   * changes — new credentials may reach a different server with different data — and
   * otherwise only when `advanceAssessmentEpoch` is called on the configured interval.
   * Deriving it from the current time instead would make every component look stale on every
   * tick and re-scan the whole estate against a shared corporate server continuously.
   */
  async xrayAssessmentEpoch(): Promise<Date> {
    const stored = await this.getProviderSettings();
    const parsed = new Date(stored.assessmentEpoch);
    return Number.isNaN(parsed.getTime()) ? new Date(0) : parsed;
  }

  /**
   * The credentials, decrypted, or null when they cannot be used.
   *
   * The only path in the platform that decrypts a stored secret. Null rather than throwing
   * for a missing or unreadable token: an unusable credential is an operational state the
   * scanner reports as unavailable, not an exception that should escape into a sweep running
   * on a timer with nothing to catch it.
   */
  async xrayCredentials(): Promise<XrayCredentials | null> {
    const stored = await this.getProviderSettings();
    if (stored.xray.baseUrl === "" || stored.xray.tokenEnvelope === null) return null;

    const key = this.deps.config.SECRETS_KEY;
    if (!key) return null;

    try {
      return {
        baseUrl: stored.xray.baseUrl,
        username: stored.xray.username,
        token: openSecret(stored.xray.tokenEnvelope, key),
        allowSelfSigned: stored.xray.allowSelfSignedCertificate,
      };
    } catch {
      // A rotated SECRETS_KEY, or a value edited by hand. Reported by the scanner as an
      // unavailable connection, which is what an administrator can act on.
      return null;
    }
  }

  async setVulnProvider(provider: VulnProvider): Promise<void> {
    const current = await this.getProviderSettings();
    await this.writeProviderSettings({ ...current, provider });
  }

  /**
   * Saves the connection, encrypting the token.
   *
   * An omitted token leaves the stored one alone, which is what lets an administrator
   * correct a typo in the URL without pasting the credential again. Saving *any* change
   * advances the assessment epoch: different credentials may reach a different Xray with
   * different data, so every existing finding is now of unknown provenance and the estate
   * is re-assessed rather than trusted.
   */
  async setXrayConnection(input: XrayConnectionInput): Promise<void> {
    const current = await this.getProviderSettings();

    let envelope = current.xray.tokenEnvelope;
    if (input.token !== undefined && input.token !== "") {
      const key = this.deps.config.SECRETS_KEY;
      if (!key) {
        throw new BadRequestError(
          "SECRETS_KEY is not set on this deployment, so an API token cannot be stored. Add it to the environment and restart, then save again.",
        );
      }
      envelope = sealSecret(input.token, key);
    }

    await this.writeProviderSettings({
      ...current,
      xray: {
        baseUrl: input.baseUrl,
        username: input.username,
        tokenEnvelope: envelope,
        allowSelfSignedCertificate: input.allowSelfSignedCertificate,
      },
      // The connection changed, so what was measured about the old one no longer applies.
      coverage: null,
      assessmentEpoch: new Date().toISOString(),
    });
  }

  /** Records what the probe found, so the platform knows which results it may trust. */
  async setXrayCoverage(coverage: XrayCoverage): Promise<void> {
    const current = await this.getProviderSettings();
    await this.writeProviderSettings({ ...current, coverage });
  }

  /**
   * Moves the epoch forward, re-queueing the estate for re-assessment.
   *
   * Xray's equivalent of a newly published Grype database. Called by the worker once the
   * configured interval has elapsed, which is the only thing that makes a component
   * assessed against Xray go stale.
   */
  async advanceAssessmentEpoch(): Promise<void> {
    const current = await this.getProviderSettings();
    await this.writeProviderSettings({ ...current, assessmentEpoch: new Date().toISOString() });
  }

  private async writeProviderSettings(next: StoredProviderSettings): Promise<void> {
    await this.deps.db
      .insert(setting)
      .values({ key: SETTING_KEYS.vulnProvider, value: next })
      .onConflictDoUpdate({
        target: setting.key,
        set: { value: next, updatedAt: new Date() },
      });
    this.providerCache = null;
  }

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

  /**
   * Malicious-package detection settings.
   *
   * Re-validated on read against the write schema, exactly as the report settings are and for
   * the same reason: `feedUrl` decides where the server opens an outbound connection and
   * `alertRecipients` decides who receives mail, so neither may be settable by writing a bad
   * row straight into the table.
   *
   * A field that fails validation falls back to its default instead of throwing, because an
   * admin page that cannot open is a worse failure than a setting that reverted.
   */
  async getMaliciousSettings(): Promise<MaliciousSettings> {
    if (this.maliciousCache && this.maliciousCache.expiresAt > Date.now()) {
      return this.maliciousCache.value;
    }

    const rows = await this.deps.db.execute<Row<{ value: unknown }>>(sql`
      SELECT value FROM setting WHERE key = ${SETTING_KEYS.maliciousDetection}
    `);

    const stored = rowsOf(rows)[0]?.value;
    // Deliberately not annotated as MaliciousSettings: the field-by-field merge below
    // indexes it by string, which the declared interface has no signature for.
    const value = { ...DEFAULT_MALICIOUS_SETTINGS };

    if (stored && typeof stored === "object") {
      for (const [key, fieldSchema] of Object.entries(updateMaliciousSettingsSchema.innerType().shape)) {
        const candidate = (stored as Record<string, unknown>)[key];
        if (candidate === undefined) continue;
        const field = fieldSchema.safeParse(candidate);
        if (field.success) (value as Record<string, unknown>)[key] = field.data;
      }
    }

    this.maliciousCache = { value, expiresAt: Date.now() + SettingsService.CACHE_TTL_MS };
    return value;
  }

  async updateMaliciousSettings(
    patch: Partial<MaliciousSettings>,
    actor: Actor | null,
  ): Promise<{ before: MaliciousSettings; after: MaliciousSettings }> {
    const before = await this.getMaliciousSettings();
    // Merged rather than replaced, so a PATCH that changes the interval cannot silently
    // clear a recipient list somebody else configured.
    const merged: MaliciousSettings = { ...before, ...patch };

    await this.deps.db
      .insert(setting)
      .values({
        key: SETTING_KEYS.maliciousDetection,
        value: merged,
        updatedByUserId: actor?.id ?? null,
        updatedByEmail: actor?.email ?? null,
      })
      .onConflictDoUpdate({
        target: setting.key,
        set: {
          value: merged,
          updatedAt: new Date(),
          updatedByUserId: actor?.id ?? null,
          updatedByEmail: actor?.email ?? null,
        },
      });

    this.maliciousCache = null;
    return { before, after: await this.getMaliciousSettings() };
  }

}
