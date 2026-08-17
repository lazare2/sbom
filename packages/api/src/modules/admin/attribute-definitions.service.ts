import { asc, eq, sql } from "drizzle-orm";
import type { AttributeDefinition, AttributeDefinitionInput, UpdateAttributeDefinitionInput } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { application, attributeDefinition, type AttributeDefinitionRow } from "../../db/schema.js";
import {
  BadRequestError,
  ConflictError,
  isPgError,
  NotFoundError,
  PG_UNIQUE_VIOLATION,
} from "../../lib/errors.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { Actor, AuditService } from "./audit.service.js";

/**
 * CRUD for the attribute definitions that drive the per-application metadata.
 *
 * These exist as rows, not columns, so that adding "tier" or "cost_centre" is
 * something an admin does at 3pm on a Tuesday rather than a migration and a
 * deploy. The values themselves live in `application.attributes` (jsonb).
 */
export class AttributeDefinitionsService {
  constructor(private readonly deps: { db: Database; audit: AuditService }) {}

  async list(includeInactive = true): Promise<AttributeDefinition[]> {
    const rows = await this.deps.db
      .select()
      .from(attributeDefinition)
      .orderBy(asc(attributeDefinition.sortOrder), asc(attributeDefinition.key));

    return rows.filter((r) => includeInactive || r.isActive).map(toDefinition);
  }

  async create(input: AttributeDefinitionInput, actor: Actor): Promise<AttributeDefinition> {
    assertSelectHasOptions(input);

    let created;
    try {
      [created] = await this.deps.db
        .insert(attributeDefinition)
        .values({
          key: input.key,
          label: input.label,
          type: input.type,
          options: input.type === "select" ? input.options : null,
          sortOrder: input.sortOrder,
          isActive: input.isActive,
        })
        .returning();
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`An attribute with the key "${input.key}" already exists.`);
      }
      throw err;
    }
    if (!created) throw new Error("insert returned no row");

    await this.deps.audit.record({
      actor,
      action: "attribute_definition.create",
      targetType: "attribute_definition",
      targetId: created.id,
      metadata: { key: created.key, label: created.label, type: created.type },
    });

    return toDefinition(created);
  }

  /**
   * Update everything except the key.
   *
   * The key is immutable on purpose: it is the property name inside every
   * application's jsonb document, so renaming it here without rewriting all of
   * them would orphan every stored value at once. If a key is genuinely wrong,
   * the honest path is create-new, re-tag, delete-old — visible in the audit
   * trail instead of silently losing data.
   */
  async update(
    id: string,
    input: UpdateAttributeDefinitionInput,
    actor: Actor,
  ): Promise<AttributeDefinition> {
    const existing = await this.require(id);

    const nextType = input.type ?? existing.type;
    const nextOptions = input.options !== undefined ? input.options : existing.options;
    if (nextType === "select" && (!nextOptions || nextOptions.length === 0)) {
      throw new BadRequestError('A "select" attribute needs at least one option.');
    }

    const patch: Partial<typeof attributeDefinition.$inferInsert> = {};
    if (input.label !== undefined) patch.label = input.label;
    if (input.type !== undefined) patch.type = input.type;
    if (input.sortOrder !== undefined) patch.sortOrder = input.sortOrder;
    if (input.isActive !== undefined) patch.isActive = input.isActive;
    // Options only mean anything for a select; clearing them when the type
    // changes away keeps the row self-consistent.
    patch.options = nextType === "select" ? (nextOptions ?? null) : null;

    const [updated] = await this.deps.db
      .update(attributeDefinition)
      .set(patch)
      .where(eq(attributeDefinition.id, id))
      .returning();
    if (!updated) throw new NotFoundError("Attribute definition");

    await this.deps.audit.record({
      actor,
      action: "attribute_definition.update",
      targetType: "attribute_definition",
      targetId: id,
      metadata: {
        key: updated.key,
        before: { label: existing.label, type: existing.type, options: existing.options, isActive: existing.isActive },
        after: { label: updated.label, type: updated.type, options: updated.options, isActive: updated.isActive },
      },
    });

    return toDefinition(updated);
  }

  /** How many applications currently carry a value for this key. */
  async usageCount(key: string): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ count: number | string }>>(sql`
      SELECT count(*)::int AS count FROM application a WHERE a.attributes ? ${key}
    `);
    return Number(rowsOf(rows)[0]?.count ?? 0);
  }

  /**
   * Delete a definition.
   *
   * Refuses while any application still carries the key, unless `purge` is set —
   * in which case the values are stripped from every application in the same
   * transaction. Deleting the definition alone would leave the values in the
   * jsonb documents where nothing renders or filters them: invisible data that
   * reappears the day someone recreates the key with a different meaning.
   *
   * Deactivating (`isActive: false`) is the non-destructive alternative and is
   * what the UI suggests first: the key stops being offered on the edit form
   * while existing values stay searchable.
   */
  async remove(id: string, opts: { purge: boolean }, actor: Actor): Promise<{ valuesPurged: number }> {
    const existing = await this.require(id);
    const inUse = await this.usageCount(existing.key);

    if (inUse > 0 && !opts.purge) {
      throw new ConflictError(
        `"${existing.label}" is set on ${inUse} application${inUse === 1 ? "" : "s"}. ` +
          "Deactivate it to hide it while keeping the values, or delete with purge to remove them.",
        { key: existing.key, applicationsAffected: inUse },
      );
    }

    await this.deps.db.transaction(async (tx) => {
      if (inUse > 0) {
        // `- text` removes the key from a jsonb object. Restricted to rows that
        // actually have it so this does not rewrite every application row.
        await tx.execute(sql`
          UPDATE ${application}
          SET attributes = attributes - ${existing.key}, updated_at = now()
          WHERE attributes ? ${existing.key}
        `);
      }
      await tx.delete(attributeDefinition).where(eq(attributeDefinition.id, id));

      await this.deps.audit.record(
        {
          actor,
          action: "attribute_definition.delete",
          targetType: "attribute_definition",
          targetId: id,
          metadata: { key: existing.key, label: existing.label, valuesPurged: inUse },
        },
        tx,
      );
    });

    return { valuesPurged: inUse };
  }

  private async require(id: string): Promise<AttributeDefinitionRow> {
    const [row] = await this.deps.db
      .select()
      .from(attributeDefinition)
      .where(eq(attributeDefinition.id, id))
      .limit(1);
    if (!row) throw new NotFoundError("Attribute definition");
    return row;
  }
}

function assertSelectHasOptions(input: { type: string; options?: string[] | null }): void {
  if (input.type === "select" && (!input.options || input.options.length === 0)) {
    throw new BadRequestError('A "select" attribute needs at least one option.');
  }
}

function toDefinition(row: AttributeDefinitionRow): AttributeDefinition {
  return {
    id: row.id,
    key: row.key,
    label: row.label,
    type: row.type,
    options: row.options ?? null,
    sortOrder: row.sortOrder,
    isActive: row.isActive,
    createdAt: row.createdAt.toISOString(),
  };
}
