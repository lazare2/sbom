import { sql } from "drizzle-orm";
import type {
  AccessRequest,
  AccessRequestReason,
  AccessRequestStatus,
  ListAccessRequestsQuery,
} from "@sbom/shared";
import { accessRequestReasons, accessRequestStatuses } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { rowsOf, type Row } from "../../lib/rows.js";
import { toIso } from "../applications/applications.service.js";
import type { Actor } from "../admin/audit.service.js";
import type { VerifiedIdentity } from "../../services/auth/id-token.js";

/**
 * The queue of people the directory vouched for and this platform refused.
 *
 * Accounts here are created by an administrator before anyone can sign in, which is deliberate
 * and stays that way. What was missing is the other half: a colleague who authenticates
 * correctly and is turned away leaves no trace, so whether an administrator ever hears about it
 * depends on whether that person bothers to say so. This records it instead, the same way an
 * SBOM arriving under an unknown name becomes an application awaiting confirmation rather than
 * a rejected upload.
 *
 * ## Everything written here was signed by the provider
 *
 * `record` takes a `VerifiedIdentity` and nothing else -- the output of a token whose signature,
 * issuer, audience and nonce have all already been checked against the provider's own keys.
 * There is deliberately no overload taking an address: a string from the sign-in form would make
 * this table writable by anyone who can reach the login page, and no amount of deduplication
 * fixes that, because the string would be theirs to vary. Somebody who needs a *local* account
 * therefore still has to ask out of band, which is a real gap and a smaller one than the
 * alternative.
 *
 * ## No audit rows from here
 *
 * `record` is reached by an anonymous visitor and the audit trail is a record of *admin* writes;
 * a row per refused sign-in would drown the trail in events no administrator caused. The two
 * admin actions -- resolving and dismissing -- are audited by their routes, as the other writes
 * on that screen are.
 */
export class AccessRequestService {
  constructor(
    private readonly deps: {
      db: Database;
      /**
       * Where a failure to record goes.
       *
       * Load-bearing, not decoration. The two write paths below swallow their exceptions so a
       * clean refusal is never turned into a 500 -- which means a broken statement would
       * otherwise disable this entire feature in perfect silence, and the only symptom would be
       * a queue that stays empty while people are locked out. That is indistinguishable, from
       * the outside, from nobody having tried. A log line is the difference.
       */
      logger: { warn(obj: unknown, msg?: string): void };
    },
  ) {}

  /**
   * Record that a verified identity was refused, or fold it into the request already open.
   *
   * Returns whether a request is now on the queue. The caller needs that answer rather than
   * void, because the sign-in page says "administrators have been notified" and that sentence
   * must not appear when the write failed. A false here is what keeps the screen honest.
   *
   * Never throws. This runs on a path whose job is to refuse a sign-in, and a failure to file
   * the paperwork must not turn a clean refusal into a 500 -- the person would be left staring
   * at a server error instead of an explanation.
   */
  async record(
    identity: VerifiedIdentity,
    opts: { provider: string; reason: AccessRequestReason },
  ): Promise<boolean> {
    try {
      /*
        Upserted onto the partial unique index from migration 0020, which covers
        (provider, subject) only where the row is still pending.

        The inference clause has to repeat that predicate or Postgres cannot tell which index
        is meant and rejects the statement outright. Matching on the subject rather than the
        address is also what makes a repeat attempt fold correctly for somebody whose address
        the directory changed between tries: one person, asking once.
      */
      const rows = await this.deps.db.execute<Row<{ id: string }>>(sql`
        INSERT INTO access_request (provider, subject, email, display_name, reason)
        VALUES (
          ${opts.provider},
          ${identity.subject},
          ${identity.email},
          ${identity.name},
          ${opts.reason}
        )
        ON CONFLICT (provider, subject) WHERE status = 'pending'
        DO UPDATE SET
          attempts = access_request.attempts + 1,
          last_seen_at = now(),
          -- The directory is authoritative, so a fresh value wins; a token that carried none
          -- must not blank what an earlier attempt told us.
          email = COALESCE(EXCLUDED.email, access_request.email),
          display_name = COALESCE(EXCLUDED.display_name, access_request.display_name)
        RETURNING id
      `);
      return rowsOf(rows).length > 0;
    } catch (error) {
      this.deps.logger.warn(
        { err: error, provider: opts.provider, reason: opts.reason },
        "could not record an access request; the refused sign-in will not appear on the queue",
      );
      return false;
    }
  }

  /**
   * Close any request open for an identity that has just signed in successfully.
   *
   * The queue drains itself. An administrator who creates the account from this screen
   * resolves the row directly, but one who creates it from the Users page, or by hand, or who
   * simply reactivates a disabled account, does not -- and a queue that only empties when
   * somebody remembers the right button is a queue that grows stale entries nobody trusts.
   *
   * `resolved_by_user_id` is left null on purpose: no administrator was present, and naming one
   * would put a decision in the record that nobody made. `created_user_id` is filled only if it
   * is still empty, so an explicit resolution is never overwritten by a later sign-in.
   */
  async resolveOnSignIn(opts: {
    provider: string;
    subject: string;
    userId: string;
  }): Promise<void> {
    try {
      await this.deps.db.execute(sql`
        UPDATE access_request
           SET status = 'resolved',
               resolved_at = now(),
               created_user_id = COALESCE(created_user_id, ${opts.userId}::uuid)
         WHERE provider = ${opts.provider}
           AND subject = ${opts.subject}
           AND status = 'pending'
      `);
    } catch (error) {
      // Swallowed for the same reason as `record`: this hangs off a sign-in that has already
      // succeeded, and failing to tidy the queue must not cost somebody their session. Logged
      // for the same reason too -- the visible symptom is a stale row, which reads as a bug in
      // the queue rather than in the statement that was meant to clear it.
      this.deps.logger.warn(
        { err: error, provider: opts.provider },
        "could not clear the access request for a successful sign-in",
      );
    }
  }

  async list(query: ListAccessRequestsQuery): Promise<AccessRequest[]> {
    const status = query.status ?? "pending";

    const rows = await this.deps.db.execute<Row<AccessRequestQueryRow>>(sql`
      SELECT ar.id,
             ar.provider,
             ar.email,
             ar.display_name,
             ar.reason,
             ar.status,
             ar.attempts,
             ar.first_seen_at,
             ar.last_seen_at,
             ar.resolved_at,
             resolver.email AS resolved_by_email
        FROM access_request ar
        LEFT JOIN "user" resolver ON resolver.id = ar.resolved_by_user_id
       WHERE ar.status = ${status}
       -- Longest-waiting first. A queue sorted newest-first buries the person who has been
       -- waiting since Tuesday under everyone who tried this morning.
       ORDER BY ar.first_seen_at ASC
       LIMIT 200
    `);

    return rowsOf(rows).map(toAccessRequest);
  }

  /** What the badge on the admin nav counts. */
  async pendingCount(): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ n: number }>>(
      sql`SELECT count(*)::int AS n FROM access_request WHERE status = 'pending'`,
    );
    return Number(rowsOf(rows)[0]?.n ?? 0);
  }

  /**
   * Mark a request dealt with.
   *
   * Returns false when nothing was pending under that id, which the route turns into a 404
   * rather than a silent success: two administrators working the same queue is the ordinary
   * case, and "I pressed it and nothing happened" has to be distinguishable from "somebody
   * else got there first".
   */
  async settle(opts: {
    id: string;
    status: Extract<AccessRequestStatus, "resolved" | "dismissed">;
    actor: Actor;
    createdUserId?: string;
  }): Promise<boolean> {
    const rows = await this.deps.db.execute<Row<{ id: string }>>(sql`
      UPDATE access_request
         SET status = ${opts.status},
             resolved_at = now(),
             resolved_by_user_id = ${opts.actor.id}::uuid,
             created_user_id = COALESCE(${opts.createdUserId ?? null}::uuid, created_user_id)
       WHERE id = ${opts.id}::uuid
         AND status = 'pending'
      RETURNING id
    `);
    return rowsOf(rows).length > 0;
  }
}

export interface AccessRequestQueryRow {
  id: string;
  provider: string;
  email: string | null;
  display_name: string | null;
  reason: string;
  status: string;
  attempts: number;
  first_seen_at: Date | string;
  last_seen_at: Date | string;
  resolved_at: Date | string | null;
  resolved_by_email: string | null;
}

/**
 * Narrows the two free-text columns back to their unions.
 *
 * `reason` and `status` are `text` in the database rather than enums, so that adding a value
 * is a code change and not a migration — but that means a row written by a future version, or
 * by hand, can hold something this build has never heard of. Falling back keeps the screen
 * rendering instead of throwing on one bad row, which matters because this is the screen an
 * administrator opens to find out who is locked out.
 */
export function toAccessRequest(row: AccessRequestQueryRow): AccessRequest {
  const reason = (accessRequestReasons as readonly string[]).includes(row.reason)
    ? (row.reason as AccessRequestReason)
    : "no_account";
  const status = (accessRequestStatuses as readonly string[]).includes(row.status)
    ? (row.status as AccessRequestStatus)
    : "pending";

  return {
    id: row.id,
    provider: row.provider,
    email: row.email,
    displayName: row.display_name,
    reason,
    status,
    attempts: Number(row.attempts),
    firstSeenAt: toIso(row.first_seen_at) ?? new Date(0).toISOString(),
    lastSeenAt: toIso(row.last_seen_at) ?? new Date(0).toISOString(),
    resolvedAt: toIso(row.resolved_at),
    resolvedByEmail: row.resolved_by_email,
  };
}
