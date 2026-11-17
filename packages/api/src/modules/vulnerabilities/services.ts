import { sql } from "drizzle-orm";
import type { FastifyBaseLogger } from "fastify";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { CompositeScanner, type ScannerMember } from "../../services/scanner/composite.js";
import { GrypeScanner } from "../../services/scanner/grype.js";
import type { VulnerabilityScanner } from "../../services/scanner/index.js";
import { OsvScanner, OSV_DB_SOURCE } from "../../services/scanner/osv.js";
import { UnavailableScanner } from "../../services/scanner/provider-scanner.js";
import { TrivyScanner } from "../../services/scanner/trivy.js";
import { XrayScanner } from "../../services/scanner/xray.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import { FixAdvisorService } from "./fix-advisor.js";
import { SweepService } from "./sweep.service.js";
import { VulnDbService } from "./vuln-db.service.js";
import { VulnWorker } from "./vuln-worker.js";
import { VulnerabilityService } from "./vulnerability.service.js";

/**
 * The vulnerability module's services, built here rather than in context.ts so the module's
 * wiring lives with the module. context.ts calls this once and keeps the results on the context
 * under the same names as before.
 */
export function buildVulnerabilityServices(deps: {
  db: Database;
  config: Config;
  settings: SettingsService;
  logger: FastifyBaseLogger;
  /** Substituted by the wiring tests so they never spawn a subprocess. */
  scanner?: VulnerabilityScanner;
}) {
  const { db, config, settings, logger } = deps;
  const overrides = { scanner: deps.scanner };

  // Vulnerability scanning. The scanner is a port so the wiring tests can supply a
  // fake and never spawn grype.
  /*
    Resolved per call rather than constructed once. The provider is a runtime setting now, so
    a scanner chosen at boot would keep talking to the database it was born with until
    somebody restarted the process -- and nothing on the admin panel would say so.

    Constructed after `settings`, which it reads on every resolve.
  */
  const grypeScanner = new GrypeScanner(config);
  const caCert = () => grypeScanner.caCertificate();
  const trivyScanner = new TrivyScanner(config, { caCert });
  const osvScanner = new OsvScanner(config, {
    caCert,
    /*
      One package per purl type and distribution: osv-scanner downloads a database for every
      ecosystem a scan touches, so this is the smallest scan that fetches all of them.
    */
    representativePackages: async () => {
      const rows = await db.execute<
        Row<{ id: number | string; name: string; version: string | null; purl: string; ecosystem: string }>
      >(sql`
        SELECT DISTINCT ON (split_part(substr(c.purl, 5), '/', 1), coalesce(substring(c.purl from 'distro=([^&#]+)'), ''))
               c.id, c.name, c.version, c.purl, c.ecosystem
        FROM component c
        WHERE c.purl LIKE 'pkg:%'
        ORDER BY split_part(substr(c.purl, 5), '/', 1), coalesce(substring(c.purl from 'distro=([^&#]+)'), ''), c.id
      `);
      return rowsOf(rows).map((r) => ({
        componentId: Number(r.id),
        name: r.name,
        version: r.version,
        purl: r.purl,
        ecosystem: r.ecosystem,
      }));
    },
  });
  const scanner: VulnerabilityScanner =
    overrides.scanner ??
    new CompositeScanner({
      logger,
      settings: () => settings.vulnScanners(),
      watermarkStore: {
        read: () => settings.readVulnWatermark(),
        write: (value) => settings.writeVulnWatermark(value),
      },
      members: async () => {
        const enabled = await settings.vulnScanners();
        const members: ScannerMember[] = [];
        if (enabled.grype) members.push({ name: "grype", scanner: grypeScanner });
        if (enabled.trivy) members.push({ name: "trivy", scanner: trivyScanner });
        if (enabled.osv) members.push({ name: "osv", scanner: osvScanner });
        if (enabled.xray) {
          const credentials = await settings.xrayCredentials();
          members.push({
            name: "xray",
            scanner: credentials
              ? new XrayScanner(credentials, { logger, assessmentEpoch: await settings.xrayAssessmentEpoch() })
              : new UnavailableScanner(
                  config.SECRETS_KEY
                    ? "JFrog Xray is switched on but no connection is configured, or the stored API token could not be decrypted. Re-enter it in Administration."
                    : "JFrog Xray is switched on but SECRETS_KEY is not set on this deployment, so the stored API token cannot be read.",
                  "settings",
                ),
          });
        }
        return members;
      },
      knownAdvisories: async (names) => {
        const known = new Map<string, string>();
        if (names.length === 0) return known;
        const rows = await db.execute<Row<{ id: string; aliases: string[] | null }>>(sql`
          SELECT id, aliases FROM vulnerability
          WHERE id = ANY(${sql.param(names)}::text[]) OR aliases && ${sql.param(names)}::text[]
        `);
        const wanted = new Set(names.map((n) => n.toUpperCase()));
        // Ids first, so a name that is itself a stored advisory maps to that advisory rather
        // than to another one that happens to list it as an alias.
        for (const row of rowsOf(rows)) known.set(row.id.toUpperCase(), row.id);
        for (const row of rowsOf(rows)) {
          for (const alias of row.aliases ?? []) {
            const key = alias.toUpperCase();
            if (wanted.has(key) && !known.has(key)) known.set(key, row.id);
          }
        }
        return known;
      },
      updateSources: {
        grype: async () => config.GRYPE_DB_UPDATE_URL,
        trivy: async () => config.TRIVY_DB_REPOSITORY,
        osv: async () => OSV_DB_SOURCE,
        xray: async () => (await settings.xraySettings()).connection?.baseUrl ?? null,
      },
    });
  const vulnerabilities = new VulnerabilityService({ db });
  /*
    These two guard each other: a database may not be replaced while a sweep holds it
    open, and a sweep may not start while it is being replaced. The references are
    mutual, so they are passed as thunks rather than as the objects - each body runs long
    after both constructors have returned, which is what keeps the cycle harmless.
  */
  const vulnDb = new VulnDbService({
    db,
    config,
    scanner,
    settings,
    // Annotated: without an explicit return type TypeScript tries to infer it through
    // the mutual reference and gives up with TS7022.
    //
    // A fix-recommendation check holds the database open exactly as a sweep does, so it
    // blocks a replacement for the same reason.
    scanBusy: (): boolean => sweep.isRunning || fixAdvisor.isChecking,
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
  const fixAdvisor = new FixAdvisorService({
    db,
    scanner,
    // The cached answers are only good for the scanner set that gave them.
    provider: async () => {
      const s = await settings.vulnScanners();
      return (["grype", "trivy", "osv", "xray"] as const).filter((n) => s[n]).join("+");
    },
    dbReplacing: (): boolean => vulnDb.replacingDatabase,
    logger,
  });


  return { scanner, vulnerabilities, vulnDb, sweep, fixAdvisor, vulnWorker };
}
