import { sql, type SQL } from "drizzle-orm";
import type { AuditLogEntry, ListAuditLogQuery, Paginated } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { auditLog } from "../../db/schema.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";

/** The actor behind a write. Denormalised into the row so the trail survives account deletion. */
export interface Actor {
  id: string;
  email: string;
}

/**
 * Append-only record of admin write actions.
 *
 * The motivating case is pending-app resolution: a merge moves scan history
 * between applications and then deletes the source app. Without this, "why does
 * payments-api suddenly have 40 more scans, and where did payments_api go" is
 * unanswerable.
 */
export class AuditService {
  constructor(private readonly deps: { db: Database }) {}

  /**
   * Record one action.
   *
   * Takes an optional transaction handle so a write and its audit row commit or
   * roll back together. Passing the transaction is the default at every call
   * site: an audit row describing a merge that was rolled back is worse than no
   * row at all, because it reads as authoritative.
   */
  async record(
    entry: {
      actor: Actor | null;
      action: string;
      targetType: string;
      targetId?: string | null;
      metadata?: Record<string, unknown>;
    },
    tx?: Database,
  ): Promise<void> {
    const db = tx ?? this.deps.db;
    await db.insert(auditLog).values({
      actorUserId: entry.actor?.id ?? null,
      actorEmail: entry.actor?.email ?? null,
      action: entry.action,
      targetType: entry.targetType,
      targetId: entry.targetId ?? null,
      metadata: entry.metadata ?? {},
    });
  }

  async list(query: ListAuditLogQuery): Promise<Paginated<AuditLogEntry>> {
    const conditions: SQL[] = [sql`TRUE`];
    if (query.targetType) conditions.push(sql`al.target_type = ${query.targetType}`);
    if (query.targetId) conditions.push(sql`al.target_id = ${query.targetId}`);
    if (query.action) conditions.push(sql`al.action = ${query.action}`);

    const rows = await this.deps.db.execute<Row<AuditRow>>(sql`
      SELECT
        al.id, al.actor_user_id, al.actor_email, al.action,
        al.target_type, al.target_id, al.metadata, al.created_at,
        count(*) OVER () AS total
      FROM audit_log al
      WHERE ${sql.join(conditions, sql` AND `)}
      ORDER BY al.created_at DESC, al.id DESC
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    const items = rowsOf(rows).map(
      (r): AuditLogEntry => ({
        id: r.id,
        actorUserId: r.actor_user_id,
        actorEmail: r.actor_email,
        action: r.action,
        targetType: r.target_type,
        targetId: r.target_id,
        metadata: r.metadata ?? {},
        createdAt: toIso(r.created_at)!,
      }),
    );

    return paginate(items, totalFromRows(rowsOf(rows)), query);
  }
}

interface AuditRow {
  id: string;
  actor_user_id: string | null;
  actor_email: string | null;
  action: string;
  target_type: string;
  target_id: string | null;
  metadata: Record<string, unknown> | null;
  created_at: Date | string;
  total?: number | string;
}
