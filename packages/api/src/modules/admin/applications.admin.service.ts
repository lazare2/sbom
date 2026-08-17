import { asc, eq, sql } from "drizzle-orm";
import type {
  ApplicationDetail,
  Attributes,
  ConfirmApplicationRequest,
  CreateApplicationRequest,
  MergeApplicationRequest,
  MergeApplicationResponse,
  UpdateApplicationRequest,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { application, applicationAlias, attributeDefinition } from "../../db/schema.js";
import {
  BadRequestError,
  ConflictError,
  isPgError,
  NotFoundError,
  PG_UNIQUE_VIOLATION,
} from "../../lib/errors.js";
import type { ApplicationsService } from "../applications/applications.service.js";
import { mergeAttributes, validateAttributes } from "./attributes.js";
import type { Actor, AuditService } from "./audit.service.js";

/**
 * Admin write operations on applications.
 *
 * Kept separate from `ApplicationsService` (which is read-only and used by every
 * authenticated user) so the boundary between "anyone can read this" and "only
 * an admin can do this" is a file boundary, not a per-method annotation someone
 * can forget.
 */
export class AdminApplicationsService {
  constructor(
    private readonly deps: {
      db: Database;
      audit: AuditService;
      applications: ApplicationsService;
    },
  ) {}

  /**
   * Pre-register an application before its first scan arrives.
   *
   * Worth doing for applications that matter: the app exists with its squad and
   * owner filled in from day one, and the first CI upload lands on an `active`
   * record instead of creating a `pending_confirmation` one somebody has to
   * triage.
   */
  async create(input: CreateApplicationRequest, actor: Actor): Promise<ApplicationDetail> {
    const attributes = await this.validate(input.attributes);

    let created;
    try {
      [created] = await this.deps.db
        .insert(application)
        .values({ name: input.name, status: input.status, attributes })
        .returning();
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(
          `An application named "${input.name}" already exists. Names are matched case-insensitively.`,
        );
      }
      throw err;
    }
    if (!created) throw new Error("insert returned no row");

    await this.deps.audit.record({
      actor,
      action: "application.create",
      targetType: "application",
      targetId: created.id,
      metadata: { name: created.name, status: created.status, attributes },
    });

    return this.deps.applications.getById(created.id);
  }

  async update(id: string, input: UpdateApplicationRequest, actor: Actor): Promise<ApplicationDetail> {
    const existing = await this.requireApplication(id);

    const patch: Partial<typeof application.$inferInsert> = { updatedAt: new Date() };

    if (input.attributes !== undefined) {
      const validated = await this.validate(input.attributes);
      patch.attributes = mergeAttributes(existing.attributes ?? {}, validated);
    }
    if (input.name !== undefined) patch.name = input.name;
    if (input.status !== undefined) {
      if (existing.status === "pending_confirmation") {
        // Confirming has its own endpoint because it means something different:
        // it is an assertion that this auto-created record is a real
        // application, and it is recorded as such on the audit trail.
        throw new BadRequestError(
          "This application is awaiting confirmation. Use confirm, merge, or delete to resolve it.",
        );
      }
      patch.status = input.status;
    }

    try {
      await this.deps.db.update(application).set(patch).where(eq(application.id, id));
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`An application named "${input.name}" already exists.`);
      }
      throw err;
    }

    await this.deps.audit.record({
      actor,
      action: "application.update",
      targetType: "application",
      targetId: id,
      metadata: {
        name: patch.name ?? existing.name,
        before: { name: existing.name, status: existing.status, attributes: existing.attributes },
        after: {
          name: patch.name ?? existing.name,
          status: patch.status ?? existing.status,
          attributes: patch.attributes ?? existing.attributes,
        },
        // A rename frees the old name. The next CI build posting under it will
        // auto-create a fresh pending application rather than landing here,
        // unless an alias is added — surfaced in the UI as a warning.
        renamed: input.name !== undefined && input.name !== existing.name,
      },
    });

    return this.deps.applications.getById(id);
  }

  /**
   * Delete an application and its entire scan history.
   *
   * The only operation in the system that destroys retained SBOM data, so it is
   * deliberately blunt: no soft delete, no undo. `inactive` exists precisely so
   * that "we don't build this any more" does not require deleting the history
   * that answers "did we ever ship log4j".
   *
   * Cascades to `scan` and `scan_component`. Deliberately does NOT touch
   * `component`: those rows are shared across the whole estate, and the FK from
   * `scan_component` is ON DELETE RESTRICT so an accidental cascade there would
   * fail loudly rather than delete another application's package identities.
   */
  async remove(id: string, actor: Actor): Promise<{ scansDeleted: number }> {
    const existing = await this.requireApplication(id);

    await this.deps.audit.record({
      actor,
      action: "application.delete",
      targetType: "application",
      targetId: id,
      metadata: {
        name: existing.name,
        status: existing.status,
        scanCount: existing.scanCount,
        attributes: existing.attributes,
      },
    });

    await this.deps.db.delete(application).where(eq(application.id, id));
    return { scansDeleted: existing.scanCount };
  }

  // -------------------------------------------------------------------------
  // Pending-confirmation resolution
  // -------------------------------------------------------------------------

  /** Confirm: this auto-created record is a real application. Fills attributes and activates. */
  async confirm(id: string, input: ConfirmApplicationRequest, actor: Actor): Promise<ApplicationDetail> {
    const existing = await this.requirePending(id);
    const validated = await this.validate(input.attributes);

    const patch: Partial<typeof application.$inferInsert> = {
      status: "active",
      attributes: mergeAttributes(existing.attributes ?? {}, validated),
      updatedAt: new Date(),
    };
    if (input.name !== undefined) patch.name = input.name;

    try {
      await this.deps.db.update(application).set(patch).where(eq(application.id, id));
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`An application named "${input.name}" already exists.`);
      }
      throw err;
    }

    await this.deps.audit.record({
      actor,
      action: "application.confirm",
      targetType: "application",
      targetId: id,
      metadata: { name: patch.name ?? existing.name, previousName: existing.name },
    });

    return this.deps.applications.getById(id);
  }

  /**
   * Merge a pending application into an existing one.
   *
   * `always: false` moves the scans and deletes the pending record. A future
   * build under the same unmatched name creates a new pending application.
   *
   * `always: true` additionally records an alias, so ingest redirects that
   * `app_name` automatically from then on. That is the difference between
   * fixing this occurrence and fixing the cause — a CI job whose name will keep
   * arriving every single build wants the alias.
   *
   * The whole thing runs in one transaction. A half-applied merge would leave
   * scans pointing at a deleted application, or an application whose
   * `latest_scan_id` is someone else's scan.
   */
  async merge(id: string, input: MergeApplicationRequest, actor: Actor): Promise<MergeApplicationResponse> {
    const source = await this.requirePending(id);

    if (source.id === input.targetApplicationId) {
      throw new BadRequestError("An application cannot be merged into itself.");
    }

    const [target] = await this.deps.db
      .select()
      .from(application)
      .where(eq(application.id, input.targetApplicationId))
      .limit(1);
    if (!target) throw new NotFoundError("Target application");

    if (target.status === "pending_confirmation") {
      throw new BadRequestError(
        `"${target.name}" is itself awaiting confirmation. Confirm it first, then merge into it.`,
      );
    }

    const result = await this.deps.db.transaction(async (tx) => {
      // Move the history. `scan_component.application_id` is denormalised from
      // `scan` for the global-search index, so it has to move in step or
      // cross-application package search would keep attributing these packages
      // to an application that no longer exists.
      const moved = await tx.execute(sql`
        UPDATE scan SET application_id = ${target.id}::uuid
        WHERE application_id = ${source.id}::uuid
      `);
      await tx.execute(sql`
        UPDATE scan_component SET application_id = ${target.id}::uuid
        WHERE application_id = ${source.id}::uuid
      `);

      // Full recompute rather than an increment: the merged scans may interleave
      // with the target's own history, so the newest scan overall — and
      // therefore the current state — can come from either side.
      await tx.execute(sql`
        UPDATE application a SET
          scan_count = (SELECT count(*) FROM scan s WHERE s.application_id = a.id),
          last_scan_at = (SELECT max(s.created_at) FROM scan s WHERE s.application_id = a.id),
          latest_scan_id = (
            SELECT s.id FROM scan s WHERE s.application_id = a.id
            ORDER BY s.created_at DESC, s.id DESC LIMIT 1
          ),
          updated_at = now()
        WHERE a.id = ${target.id}::uuid
      `);

      let aliasCreated: string | null = null;
      if (input.always) {
        try {
          await tx
            .insert(applicationAlias)
            .values({
              aliasName: source.name,
              applicationId: target.id,
              createdByUserId: actor.id,
            });
          aliasCreated = source.name;
        } catch (err) {
          if (isPgError(err, PG_UNIQUE_VIOLATION)) {
            throw new ConflictError(
              `An alias for "${source.name}" already exists and points somewhere else. ` +
                "Remove it first, or merge without creating a permanent alias.",
            );
          }
          throw err;
        }
      }

      // Safe only because the scans were reassigned above: `scan.application_id`
      // is ON DELETE CASCADE, so deleting first would destroy the history this
      // operation exists to preserve.
      await tx.delete(application).where(eq(application.id, source.id));

      await this.deps.audit.record(
        {
          actor,
          action: input.always ? "application.merge_always" : "application.merge_once",
          targetType: "application",
          targetId: target.id,
          metadata: {
            sourceApplicationId: source.id,
            sourceName: source.name,
            targetName: target.name,
            scansMoved: moved.rowCount ?? 0,
            aliasCreated,
          },
        },
        tx,
      );

      return { scansMoved: moved.rowCount ?? 0, aliasCreated };
    });

    return {
      targetApplicationId: target.id,
      scansMoved: result.scansMoved,
      aliasCreated: result.aliasCreated,
    };
  }

  // -------------------------------------------------------------------------
  // Aliases
  // -------------------------------------------------------------------------

  async addAlias(applicationId: string, aliasName: string, actor: Actor): Promise<void> {
    await this.requireApplication(applicationId);

    // An alias that shadows a real application name is unreachable: ingest
    // matches names before aliases, so the scan would never get here. Rejecting
    // is better than storing a rule that silently never fires.
    const [clash] = await this.deps.db
      .select({ id: application.id, name: application.name })
      .from(application)
      .where(sql`lower(${application.name}) = lower(${aliasName})`)
      .limit(1);
    if (clash) {
      throw new ConflictError(
        `"${clash.name}" is already an application name. Ingest matches names before aliases, so this alias would never be used.`,
      );
    }

    try {
      await this.deps.db.insert(applicationAlias).values({
        aliasName,
        applicationId,
        createdByUserId: actor.id,
      });
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`An alias named "${aliasName}" already exists.`);
      }
      throw err;
    }

    await this.deps.audit.record({
      actor,
      action: "application.alias_add",
      targetType: "application",
      targetId: applicationId,
      metadata: { aliasName },
    });
  }

  async removeAlias(applicationId: string, aliasName: string, actor: Actor): Promise<void> {
    const deleted = await this.deps.db
      .delete(applicationAlias)
      .where(
        sql`${applicationAlias.applicationId} = ${applicationId}::uuid AND lower(${applicationAlias.aliasName}) = lower(${aliasName})`,
      )
      .returning({ id: applicationAlias.id });

    if (deleted.length === 0) throw new NotFoundError("Alias");

    await this.deps.audit.record({
      actor,
      action: "application.alias_remove",
      targetType: "application",
      targetId: applicationId,
      metadata: { aliasName },
    });
  }

  // -------------------------------------------------------------------------

  private async validate(attributes: Attributes) {
    const definitions = await this.deps.db
      .select()
      .from(attributeDefinition)
      .where(eq(attributeDefinition.isActive, true))
      .orderBy(asc(attributeDefinition.sortOrder));
    return validateAttributes(definitions, attributes);
  }

  private async requireApplication(id: string) {
    const [row] = await this.deps.db.select().from(application).where(eq(application.id, id)).limit(1);
    if (!row) throw new NotFoundError("Application");
    return row;
  }

  private async requirePending(id: string) {
    const row = await this.requireApplication(id);
    if (row.status !== "pending_confirmation") {
      throw new BadRequestError(
        `"${row.name}" is not awaiting confirmation (status: ${row.status}).`,
      );
    }
    return row;
  }
}
