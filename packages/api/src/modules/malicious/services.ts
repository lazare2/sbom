import type { FastifyBaseLogger } from "fastify";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import type { AuditService } from "../admin/audit.service.js";
import type { Mailer } from "../reports/mailer.js";
import type { SettingsService } from "../settings/settings.service.js";
import { MaliciousAlertService } from "./malicious-alert.service.js";
import { MaliciousAdminService } from "./malicious.admin.service.js";
import { MaliciousFeedService } from "./malicious-feed.service.js";
import { MaliciousMatchService } from "./malicious-match.service.js";
import { MaliciousService } from "./malicious.service.js";
import { MaliciousWorker } from "./malicious-worker.js";

/**
 * The malicious-packages module's services, built here rather than in context.ts so the
 * module's wiring lives with the module. Same names on the context as before.
 */
export function buildMaliciousServices(deps: {
  db: Database;
  config: Config;
  settings: SettingsService;
  logger: FastifyBaseLogger;
  mailer: Mailer;
  audit: AuditService;
}) {
  const { db, config, settings, logger, mailer, audit } = deps;

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

  const maliciousWorker = new MaliciousWorker({
    settings,
    feed: maliciousFeed,
    match: maliciousMatch,
    alerts: maliciousAlerts,
    logger,
  });

  const adminMalicious = new MaliciousAdminService({
    db,
    audit,
    settings,
    feed: maliciousFeed,
    worker: maliciousWorker,
  });

  return { maliciousFeed, maliciousMatch, maliciousAlerts, malicious, maliciousWorker, adminMalicious };
}
