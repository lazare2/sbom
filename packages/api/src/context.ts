import type { FastifyBaseLogger } from "fastify";
import { getConfig, type Config } from "./config.js";
import { getDb, type Database } from "./db/client.js";
import { AuthService } from "./modules/auth/auth.service.js";
import { AuthProviderRegistry } from "./modules/auth/provider.js";
import { LocalPasswordProvider } from "./modules/auth/providers/local.js";
import { SessionService } from "./modules/auth/session.service.js";
import { AdminApplicationsService } from "./modules/admin/applications.admin.service.js";
import { AdminUsersService } from "./modules/admin/users.service.js";
import { AttributeDefinitionsService } from "./modules/admin/attribute-definitions.service.js";
import { AuditService } from "./modules/admin/audit.service.js";
import { AnalyticsService } from "./modules/analytics/analytics.service.js";
import { ApplicationsService } from "./modules/applications/applications.service.js";
import { BulkSearchService } from "./modules/components/bulk-search.service.js";
import { ComponentsService } from "./modules/components/components.service.js";
import { DashboardService } from "./modules/dashboard/dashboard.service.js";
import { DiffService } from "./modules/diff/diff.service.js";
import { GroupsAdminService } from "./modules/groups/groups.admin.service.js";
import { ScansAdminService } from "./modules/scans/scans.admin.service.js";
import { ExportService } from "./modules/exports/export.service.js";
import { MaliciousService } from "./modules/malicious/malicious.service.js";
import { MaliciousAdminService } from "./modules/malicious/malicious.admin.service.js";
import { MaliciousFeedService } from "./modules/malicious/malicious-feed.service.js";
import { MaliciousMatchService } from "./modules/malicious/malicious-match.service.js";
import { MaliciousAlertService } from "./modules/malicious/malicious-alert.service.js";
import { MaliciousWorker } from "./modules/malicious/malicious-worker.js";
import { GroupsService } from "./modules/groups/groups.service.js";
import { EnvironmentService } from "./modules/environments/environment.service.js";
import { IngestTokenService } from "./modules/ingestion/ingest-token.service.js";
import { IngestionService } from "./modules/ingestion/ingestion.service.js";
import { SbomBackfillService } from "./modules/ingestion/sbom-backfill.service.js";
import { Mailer } from "./modules/reports/mailer.js";
import { ReportScheduler } from "./modules/reports/report-scheduler.js";
import { ReportService } from "./modules/reports/report.service.js";
import { SnapshotService } from "./modules/reports/snapshot.service.js";
import { ScansService } from "./modules/scans/scans.service.js";
import { SastService } from "./modules/sast/sast.service.js";
import { SettingsService } from "./modules/settings/settings.service.js";
import { SweepService } from "./modules/vulnerabilities/sweep.service.js";
import { VulnDbService } from "./modules/vulnerabilities/vuln-db.service.js";
import { VulnWorker } from "./modules/vulnerabilities/vuln-worker.js";
import { VulnerabilityService } from "./modules/vulnerabilities/vulnerability.service.js";
import { VulnReportService } from "./modules/vulnerabilities/vuln-report.service.js";
import { createBlobStore, type BlobStore } from "./services/blob-store/index.js";
import { createScanner, type VulnerabilityScanner } from "./services/scanner/index.js";

/**
 * Wiring for the whole application.
 *
 * Constructor injection with one explicit factory, rather than a DI framework:
 * the graph is small, and this way "what does the ingest path depend on" is
 * answerable by reading one file. It also makes tests able to swap the blob
 * store for a fake without touching module state.
 */
export interface AppContext {
  config: Config;
  db: Database;
  logger: FastifyBaseLogger;
  blobStore: BlobStore;
  providers: AuthProviderRegistry;
  sessions: SessionService;
  auth: AuthService;
  ingestTokens: IngestTokenService;
  ingestion: IngestionService;
  /** Recovers component locations from SBOMs ingested before the platform recorded them. */
  sbomBackfill: SbomBackfillService;
  applications: ApplicationsService;
  /** Reads over named sets of applications. Counts distinct advisories, not summed findings. */
  groups: GroupsService;
  /*
   * Constructed before anything that reads the estate: every one of those services
   * takes an EnvironmentScope, and a scope can only be produced here.
   */
  environments: EnvironmentService;
  scans: ScansService;
  /** SAST runs/findings from sast-scan — see "Static analysis (SAST)" in the schema. */
  sast: SastService;
  components: ComponentsService;
  bulkSearch: BulkSearchService;
  diff: DiffService;
  dashboard: DashboardService;
  analytics: AnalyticsService;
  /*
   * Vulnerability scanning.
   *
   * Present in the graph whether or not scanning is enabled. The feature flag is a
   * runtime setting rather than a wiring decision, so these are always constructed and
   * simply report "disabled" — which is what lets the admin panel explain the state
   * instead of the routes disappearing.
   */
  settings: SettingsService;
  /*
   * The management report.
   *
   * Two objects rather than one because they answer to different pressures: the snapshot is
   * a query over the live estate, while the report is a record with a baseline and a
   * duplicate guard. Keeping the capture separable is also what lets the delta be tested
   * against hand-written estates that no database has to contain.
   */
  snapshots: SnapshotService;
  reports: ReportService;
  mailer: Mailer;
  reportScheduler: ReportScheduler;
  scanner: VulnerabilityScanner;
  vulnerabilities: VulnerabilityService;
  vulnDb: VulnDbService;
  sweep: SweepService;
  vulnWorker: VulnWorker;
  /*
   * Malicious-package detection.
   *
   * A parallel pipeline to the vulnerability one rather than a mode of it: its own feed, its
   * own watermark on `component`, its own schedule and its own switch. The two answer
   * different questions and are independently switchable on purpose -- this one needs no
   * scanner binary and no gigabytes of database, so an estate can reasonably run it alone.
   */
  maliciousFeed: MaliciousFeedService;
  maliciousMatch: MaliciousMatchService;
  maliciousAlerts: MaliciousAlertService;
  malicious: MaliciousService;
  exports: ExportService;
  maliciousWorker: MaliciousWorker;
  // Write side. Every one of these is reachable only through `requireAdmin`.
  audit: AuditService;
  adminUsers: AdminUsersService;
  adminApplications: AdminApplicationsService;
  adminGroups: GroupsAdminService;
  adminScans: ScansAdminService;
  adminMalicious: MaliciousAdminService;
  attributeDefinitions: AttributeDefinitionsService;
}

export interface BuildContextOverrides {
  config?: Config;
  db?: Database;
  blobStore?: BlobStore;
  /** Substituted by the wiring tests so they never spawn a subprocess. */
  scanner?: VulnerabilityScanner;
}

export function buildContext(logger: FastifyBaseLogger, overrides: BuildContextOverrides = {}): AppContext {
  const config = overrides.config ?? getConfig();
  // Config is threaded through rather than let `getDb()` reach for process.env,
  // so an injected config always decides which database is used.
  const db = overrides.db ?? getDb(config);
  const blobStore = overrides.blobStore ?? createBlobStore(config);

  // Registered in the order given by AUTH_PROVIDERS. Only `local` exists in this
  // phase; an LdapProvider would be constructed and registered here, and nothing
  // downstream would change.
  const providers = new AuthProviderRegistry();
  for (const name of config.AUTH_PROVIDERS) {
    switch (name) {
      case "local":
        providers.register(new LocalPasswordProvider(db));
        break;
      default:
        // Unreachable: config validation rejects unknown provider names.
        throw new Error(`unsupported auth provider "${name}"`);
    }
  }

  const sessions = new SessionService(db, config.SESSION_TTL_HOURS);

  const auth = new AuthService({ db, config, providers, sessions, logger });

  const ingestTokens = new IngestTokenService({ db, config });
  const ingestion = new IngestionService({ db, blobStore, logger });
  const sbomBackfill = new SbomBackfillService({ db, blobs: blobStore, logger });

  // Read side. Stateless query services over the same pool.
  //
  // Settings first: the applications list, the overview and the analytics report all
  // resolve the stale threshold through it, and resolving it independently would let them
  // disagree about which applications are stale.
  const settings = new SettingsService({ db, config });
  const applications = new ApplicationsService({ db, config, settings });
  const environments = new EnvironmentService({ db });
  const groups = new GroupsService({ db, settings });
  const scans = new ScansService({ db, blobStore });
  const sast = new SastService({ db });
  const components = new ComponentsService({ db });
  const bulkSearch = new BulkSearchService({ db });
  const diff = new DiffService({ db });
  const dashboard = new DashboardService({ db, config, settings });
  // Composed onto the dashboard rather than duplicating its aggregates: the
  // report's ecosystem, platform and top-package sections must be the same
  // numbers the overview page shows, and sharing the query is the only way to
  // guarantee that as either one changes.
  // The estate's vulnerability aggregates, which the report composes in alongside the
  // inventory sections it owns itself.
  const vulnReport = new VulnReportService({ db });
  const analytics = new AnalyticsService({ db, config, dashboard, settings, vulnReport });

  const snapshots = new SnapshotService({ db });
  const mailer = new Mailer({ logger });
  const reports = new ReportService({ db, blobStore, snapshots, settings, mailer, logger });
  const reportScheduler = new ReportScheduler({ settings, reports, environments, logger });

  // Vulnerability scanning. The scanner is a port so the wiring tests can supply a
  // fake and never spawn grype.
  const scanner = overrides.scanner ?? createScanner(config);
  const vulnerabilities = new VulnerabilityService({ db });
  /*
    These two guard each other: a database may not be replaced while a sweep holds it
    open, and a sweep may not start while it is being replaced. The references are
    mutual, so they are passed as thunks rather than as the objects — each body runs long
    after both constructors have returned, which is what keeps the cycle harmless.
  */
  const vulnDb = new VulnDbService({
    db,
    config,
    scanner,
    settings,
    // Annotated: without an explicit return type TypeScript tries to infer it through
    // the mutual reference and gives up with TS7022.
    scanBusy: (): boolean => sweep.isRunning,
  });
  const sweep = new SweepService({
    db,
    config,
    scanner,
    settings,
    logger,
    dbReplacing: (): boolean => vulnDb.replacingDatabase,
  });
  const vulnWorker = new VulnWorker({ settings, vulnDb, sweep, logger });

  /*
   * Constructed after `settings` and `mailer`, which both feed it, and after `sweep` only for
   * readability -- there is no dependency between the two pipelines.
   *
   * The worker takes the alert service rather than the mailer directly, so the decision about
   * whether an alert is due lives in one place instead of being re-derived by every trigger.
   */
  const maliciousFeed = new MaliciousFeedService({ db, settings, logger });
  const maliciousMatch = new MaliciousMatchService({ db, logger });
  const maliciousAlerts = new MaliciousAlertService({
    db,
    settings,
    mailer,
    logger,
    publicUrl: config.PUBLIC_URL,
  });
  const malicious = new MaliciousService({
    db,
    settings,
    feed: maliciousFeed,
    match: maliciousMatch,
  });
  /*
    Constructed after `settings` because it resolves both feature toggles to decide whether an
    enriched export may claim the estate was assessed. It reads nothing else, so it does not
    need to wait on the vulnerability or malicious services themselves.
  */
  const exports = new ExportService({ db, settings });

  const maliciousWorker = new MaliciousWorker({
    settings,
    feed: maliciousFeed,
    match: maliciousMatch,
    alerts: maliciousAlerts,
    logger,
  });

  // Write side.
  const audit = new AuditService({ db });
  const adminUsers = new AdminUsersService({ db, sessions, audit, environments });
  const adminApplications = new AdminApplicationsService({ db, audit, applications });
  const adminGroups = new GroupsAdminService({ db, audit, groups });
  const adminMalicious = new MaliciousAdminService({
    db,
    audit,
    settings,
    feed: maliciousFeed,
    worker: maliciousWorker,
  });
  const adminScans = new ScansAdminService({ db, blobStore, audit });
  const attributeDefinitions = new AttributeDefinitionsService({ db, audit });

  return {
    config,
    db,
    logger,
    blobStore,
    providers,
    sessions,
    auth,
    ingestTokens,
    ingestion,
    sbomBackfill,
    applications,
    groups,
    environments,
    scans,
    sast,
    components,
    bulkSearch,
    diff,
    dashboard,
    analytics,
    settings,
    snapshots,
    reports,
    mailer,
    reportScheduler,
    scanner,
    vulnerabilities,
    vulnDb,
    sweep,
    vulnWorker,
    maliciousFeed,
    maliciousMatch,
    maliciousAlerts,
    malicious,
    maliciousWorker,
    exports,
    audit,
    adminUsers,
    adminApplications,
    adminGroups,
    adminScans,
    adminMalicious,
    attributeDefinitions,
  };
}
