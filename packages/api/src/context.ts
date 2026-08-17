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
import { IngestTokenService } from "./modules/ingestion/ingest-token.service.js";
import { IngestionService } from "./modules/ingestion/ingestion.service.js";
import { ScansService } from "./modules/scans/scans.service.js";
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
  applications: ApplicationsService;
  scans: ScansService;
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
  scanner: VulnerabilityScanner;
  vulnerabilities: VulnerabilityService;
  vulnDb: VulnDbService;
  sweep: SweepService;
  vulnWorker: VulnWorker;
  // Write side. Every one of these is reachable only through `requireAdmin`.
  audit: AuditService;
  adminUsers: AdminUsersService;
  adminApplications: AdminApplicationsService;
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

  // Read side. Stateless query services over the same pool.
  const applications = new ApplicationsService({ db, config });
  const scans = new ScansService({ db, blobStore });
  const components = new ComponentsService({ db });
  const bulkSearch = new BulkSearchService({ db });
  const diff = new DiffService({ db });
  const dashboard = new DashboardService({ db, config });
  // Constructed before analytics: the report asks the flag whether to include
  // vulnerability sections at all.
  const settings = new SettingsService({ db });
  // Composed onto the dashboard rather than duplicating its aggregates: the
  // report's ecosystem, platform and top-package sections must be the same
  // numbers the overview page shows, and sharing the query is the only way to
  // guarantee that as either one changes.
  // The estate's vulnerability aggregates, which the report composes in alongside the
  // inventory sections it owns itself.
  const vulnReport = new VulnReportService({ db });
  const analytics = new AnalyticsService({ db, config, dashboard, settings, vulnReport });

  // Vulnerability scanning. The scanner is a port so the wiring tests can supply a
  // fake and never spawn grype.
  const scanner = overrides.scanner ?? createScanner(config);
  const vulnerabilities = new VulnerabilityService({ db });
  const vulnDb = new VulnDbService({ db, config, scanner, settings });
  const sweep = new SweepService({ db, config, scanner, settings, logger });
  const vulnWorker = new VulnWorker({ settings, vulnDb, sweep, logger });

  // Write side.
  const audit = new AuditService({ db });
  const adminUsers = new AdminUsersService({ db, sessions, audit });
  const adminApplications = new AdminApplicationsService({ db, audit, applications });
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
    applications,
    scans,
    components,
    bulkSearch,
    diff,
    dashboard,
    analytics,
    settings,
    scanner,
    vulnerabilities,
    vulnDb,
    sweep,
    vulnWorker,
    audit,
    adminUsers,
    adminApplications,
    attributeDefinitions,
  };
}
