import { sql } from "drizzle-orm";
import type {
  AcknowledgeMaliciousRequest,
  MaliciousAckSummary,
  MaliciousSettings,
  UpdateMaliciousSettings,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { NotFoundError } from "../../lib/errors.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import type { Actor, AuditService } from "../admin/audit.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import type { MaliciousFeedService } from "./malicious-feed.service.js";
import type { MaliciousWorker } from "./malicious-worker.js";

/**
 * Admin writes for malicious-package detection.
 *
 * Split from the read service on the same line every module here draws: reads are open to any
 * authenticated user, writes are admin-only and audited.
 */
export class MaliciousAdminService {
  constructor(
    private readonly deps: {
      db: Database;
      audit: AuditService;
      settings: SettingsService;
      feed: MaliciousFeedService;
      worker: MaliciousWorker;
    },
  ) {}

  /**
   * Record a decision about a finding.
   *
   * Upserts rather than accumulating: one decision per report per application, replaced when
   * somebody revises it. The alternative -- a history of every state a finding has passed
   * through -- reads well in the abstract and in practice produces a page where the current
   * decision is hidden among four superseded ones. The audit log already holds the history,
   * with who changed what and when, and it is the right place for it.
   */
  async acknowledge(
    input: AcknowledgeMaliciousRequest,
    actor: Actor,
  ): Promise<MaliciousAckSummary> {
    const exists = await this.deps.db.execute<Row<{ id: string }>>(sql`
      SELECT id FROM malicious_package WHERE id = ${input.maliciousPackageId}
    `);
    if (rowsOf(exists).length === 0) throw new NotFoundError("Malicious package report");

    if (input.applicationId) {
      const app = await this.deps.db.execute<Row<{ id: string }>>(sql`
        SELECT id FROM application WHERE id = ${input.applicationId}::uuid
      `);
      if (rowsOf(app).length === 0) throw new NotFoundError("Application");
    }

    return this.deps.db.transaction(async (tx) => {
      /*
       * Two conflict targets, because the uniqueness is enforced by two partial indexes --
       * one for per-application rows and one for the estate-wide row. `ON CONFLICT` needs to
       * name the matching index predicate, so the two cases cannot share a statement.
       */
      const upsert = input.applicationId
        ? sql`
            INSERT INTO malicious_acknowledgement
              (malicious_package_id, application_id, state, note, acknowledged_by_user_id, acknowledged_by_email)
            VALUES (${input.maliciousPackageId}, ${input.applicationId}::uuid, ${input.state},
                    ${input.note}, ${actor.id}::uuid, ${actor.email})
            ON CONFLICT (malicious_package_id, application_id) WHERE application_id IS NOT NULL
            DO UPDATE SET state = excluded.state, note = excluded.note,
                          acknowledged_by_user_id = excluded.acknowledged_by_user_id,
                          acknowledged_by_email = excluded.acknowledged_by_email,
                          updated_at = now()
            RETURNING id, malicious_package_id, application_id, state, note,
                      acknowledged_by_email, created_at
          `
        : sql`
            INSERT INTO malicious_acknowledgement
              (malicious_package_id, application_id, state, note, acknowledged_by_user_id, acknowledged_by_email)
            VALUES (${input.maliciousPackageId}, NULL, ${input.state},
                    ${input.note}, ${actor.id}::uuid, ${actor.email})
            ON CONFLICT (malicious_package_id) WHERE application_id IS NULL
            DO UPDATE SET state = excluded.state, note = excluded.note,
                          acknowledged_by_user_id = excluded.acknowledged_by_user_id,
                          acknowledged_by_email = excluded.acknowledged_by_email,
                          updated_at = now()
            RETURNING id, malicious_package_id, application_id, state, note,
                      acknowledged_by_email, created_at
          `;

      const rows = await tx.execute<Row<Record<string, unknown>>>(upsert);
      const row = rowsOf(rows)[0]!;

      await this.deps.audit.record(
        {
          actor,
          action: "malicious.acknowledge",
          targetType: "malicious_package",
          targetId: input.maliciousPackageId,
          metadata: {
            state: input.state,
            applicationId: input.applicationId ?? null,
            // The note is the actor's own record of the decision, written to be kept.
            note: input.note,
          },
        },
        tx,
      );

      let applicationName: string | null = null;
      if (input.applicationId) {
        const named = await tx.execute<Row<{ name: string }>>(sql`
          SELECT name FROM application WHERE id = ${input.applicationId}::uuid
        `);
        applicationName = rowsOf(named)[0]?.name ?? null;
      }

      return {
        id: String(row.id),
        state: input.state,
        note: input.note,
        applicationId: (row.application_id as string | null) ?? null,
        applicationName,
        acknowledgedByEmail: (row.acknowledged_by_email as string | null) ?? null,
        createdAt: toIso(row.created_at as string)!,
      };
    });
  }

  /** Withdraw a decision, putting the finding back in its unacknowledged state. */
  async removeAcknowledgement(id: string, actor: Actor): Promise<void> {
    await this.deps.db.transaction(async (tx) => {
      const rows = await tx.execute<Row<{ malicious_package_id: string; state: string }>>(sql`
        DELETE FROM malicious_acknowledgement WHERE id = ${id}::uuid
        RETURNING malicious_package_id, state
      `);
      const row = rowsOf(rows)[0];
      if (!row) throw new NotFoundError("Acknowledgement");

      await this.deps.audit.record(
        {
          actor,
          action: "malicious.acknowledge_remove",
          targetType: "malicious_package",
          targetId: row.malicious_package_id,
          metadata: { previousState: row.state },
        },
        tx,
      );
    });
  }

  async getSettings(): Promise<MaliciousSettings> {
    return this.deps.settings.getMaliciousSettings();
  }

  /**
   * Change the feature's settings.
   *
   * Switching detection on kicks the worker immediately rather than waiting for the next
   * heartbeat: the moment somebody enables this is the moment they want to know, and a
   * six-hour wait for the first answer would read as the feature not working.
   */
  async updateSettings(
    patch: UpdateMaliciousSettings,
    actor: Actor,
  ): Promise<MaliciousSettings> {
    const { before, after } = await this.deps.settings.updateMaliciousSettings(patch, actor);

    await this.deps.audit.record({
      actor,
      action: "malicious.settings_update",
      targetType: "setting",
      targetId: "malicious.detection",
      metadata: {
        enabled: { from: before.enabled, to: after.enabled },
        intervalHours: { from: before.intervalHours, to: after.intervalHours },
        feedUrl: { from: before.feedUrl, to: after.feedUrl },
        alertsEnabled: { from: before.alertsEnabled, to: after.alertsEnabled },
        // Counts, never addresses. The trail must show the distribution list changed without
        // becoming a second, unpruned copy of people's email addresses.
        alertRecipientCount: {
          from: before.alertRecipients.length,
          to: after.alertRecipients.length,
        },
      },
    });

    if (!before.enabled && after.enabled) this.deps.worker.requestRefresh("enable");

    return after;
  }

  /** Refresh the feed now, then re-match. Returns once the feed is in; matching continues. */
  async updateFeed(actor: Actor): Promise<{ outcome: string; message: string | null }> {
    const result = await this.deps.feed.update("manual", actor);

    await this.deps.audit.record({
      actor,
      action: "malicious.feed_update",
      targetType: "setting",
      targetId: "malicious.detection",
      metadata: {
        outcome: result.outcome,
        reportsTotal: result.reportsTotal,
        reportsChanged: result.reportsChanged,
        message: result.message,
      },
    });

    if (result.outcome === "updated" || result.outcome === "unchanged") {
      this.deps.worker.requestSweep();
    }

    return { outcome: result.outcome, message: result.message };
  }
}
