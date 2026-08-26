import { sql } from "drizzle-orm";
import type {
  Environment,
  EnvironmentAccess,
  CreateEnvironmentRequest,
  UpdateEnvironmentRequest,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import type { UserRow } from "../../db/schema.js";
import { BadRequestError, ConflictError, ForbiddenError, NotFoundError } from "../../lib/errors.js";
import { rowsOf, type Row } from "../applications/applications.service.js";

/**
 * One estate, resolved and checked.
 *
 * Services take this rather than a bare id string on purpose. A `string` parameter is easy
 * to satisfy with the wrong string — a request's raw query value, an application's id, an
 * empty default — and every one of those silently reads somebody else's estate. A nominal
 * type means the only way to obtain one is to go through `resolve` or `requireDefault`,
 * both of which check access first.
 */
export interface EnvironmentScope {
  readonly id: string;
  readonly name: string;
  /** Present so the type is not structurally identical to any other {id, name} pair. */
  readonly __environmentScope: true;
}

function scopeOf(id: string, name: string): EnvironmentScope {
  return { id, name, __environmentScope: true };
}

interface EnvironmentRow {
  id: string;
  name: string;
  description: string | null;
  application_count: number | string;
  scan_count: number | string;
  created_at: Date | string;
  updated_at: Date | string;
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toEnvironment(row: EnvironmentRow): Environment {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    applicationCount: Number(row.application_count),
    scanCount: Number(row.scan_count),
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
  };
}

export class EnvironmentService {
  constructor(private readonly deps: { db: Database }) {}

  /**
   * What this user may read.
   *
   * Administrators are `all: true` rather than an enumerated list, so an environment created
   * after their account was set up is reachable without anybody re-granting it.
   */
  async accessFor(user: UserRow): Promise<EnvironmentAccess> {
    if (user.role === "admin") return { all: true, environmentIds: [] };

    const result = await this.deps.db.execute<Row<{ environment_id: string }>>(sql`
      SELECT environment_id FROM user_environment WHERE user_id = ${user.id}::uuid
    `);
    return { all: false, environmentIds: rowsOf(result).map((r) => r.environment_id) };
  }

  /** True when this access grants the environment. The single place that decision is made. */
  private permits(access: EnvironmentAccess, environmentId: string): boolean {
    return access.all || access.environmentIds.includes(environmentId);
  }

  async list(access: EnvironmentAccess): Promise<Environment[]> {
    /*
      A non-admin with no grants gets an empty list rather than every environment. The
      `= ANY(...)` form with an empty array yields no rows, which is the correct answer --
      but it is worth stating, because "no filter" and "a filter that matches nothing" look
      alike in SQL and differ by the whole estate.
    */
    const visible = access.all
      ? sql`TRUE`
      : sql`e.id = ANY(${access.environmentIds}::uuid[])`;

    const result = await this.deps.db.execute<Row<EnvironmentRow>>(sql`
      SELECT
        e.id, e.name, e.description, e.created_at, e.updated_at,
        count(DISTINCT a.id) AS application_count,
        coalesce(sum(a.scan_count), 0) AS scan_count
      FROM environment e
      LEFT JOIN application a ON a.environment_id = e.id
      WHERE ${visible}
      GROUP BY e.id
      ORDER BY e.created_at ASC
    `);
    return rowsOf(result).map(toEnvironment);
  }

  async get(id: string, access: EnvironmentAccess): Promise<Environment> {
    const all = await this.list(access);
    const found = all.find((e) => e.id === id);
    if (!found) throw new NotFoundError("Environment");
    return found;
  }

  /**
   * Turns a request's `environment` value into a checked scope.
   *
   * Accepts an id or a name, because a pasted link reading `?environment=Production` is
   * worth more than one carrying a uuid, and CI configuration names the estate rather than
   * identifying it. Names are unique case-insensitively, so neither form is ambiguous.
   *
   * An environment that exists but is not granted returns **404, not 403**. A 403 confirms
   * the estate exists, which tells someone who should not know that there is a `production`
   * they cannot see.
   */
  async resolve(ref: string, access: EnvironmentAccess): Promise<EnvironmentScope> {
    const looksLikeUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      ref,
    );

    const result = await this.deps.db.execute<Row<{ id: string; name: string }>>(
      looksLikeUuid
        ? sql`SELECT id, name FROM environment WHERE id = ${ref}::uuid`
        : sql`SELECT id, name FROM environment WHERE lower(name) = lower(${ref})`,
    );
    const row = rowsOf(result)[0];
    if (!row) throw new NotFoundError("Environment");
    if (!this.permits(access, row.id)) throw new NotFoundError("Environment");
    return scopeOf(row.id, row.name);
  }

  /**
   * The estate a request means when it does not say.
   *
   * The oldest one the caller can reach. Deterministic rather than clever: on every
   * deployment that existed before environments, the oldest is the migrated `Production`,
   * so an API client written against the old API keeps reading the same estate it always
   * did. The UI never relies on this -- it puts the environment in the URL -- so the default
   * only ever serves callers that predate the concept.
   */
  async requireDefault(access: EnvironmentAccess): Promise<EnvironmentScope> {
    const all = await this.list(access);
    const first = all[0];
    if (!first) {
      throw new ForbiddenError("You do not have access to any environment.");
    }
    return scopeOf(first.id, first.name);
  }

  /** Every scope the caller may read, for the searches that deliberately span estates. */
  async scopesFor(access: EnvironmentAccess): Promise<EnvironmentScope[]> {
    const all = await this.list(access);
    return all.map((e) => scopeOf(e.id, e.name));
  }

  /**
   * Narrows a span-everything search to the subset the caller asked for.
   *
   * An empty or absent selection means every environment they can reach, which is what the
   * search page opens on. A selection naming something they cannot reach is refused rather
   * than quietly dropped -- silently returning fewer estates than were asked for produces an
   * answer that looks complete and is not.
   */
  async scopesForSelection(
    refs: string[] | undefined,
    access: EnvironmentAccess,
  ): Promise<EnvironmentScope[]> {
    if (!refs || refs.length === 0) return this.scopesFor(access);
    const resolved: EnvironmentScope[] = [];
    for (const ref of refs) {
      resolved.push(await this.resolve(ref, access));
    }
    // Deduplicate: the same estate named twice must not double its rows.
    const seen = new Set<string>();
    return resolved.filter((s) => (seen.has(s.id) ? false : (seen.add(s.id), true)));
  }

  // -- administration -------------------------------------------------------

  async create(input: CreateEnvironmentRequest): Promise<Environment> {
    const existing = await this.deps.db.execute<Row<{ id: string }>>(sql`
      SELECT id FROM environment WHERE lower(name) = lower(${input.name})
    `);
    if (rowsOf(existing).length > 0) {
      throw new ConflictError(`An environment named "${input.name}" already exists.`);
    }

    const result = await this.deps.db.execute<Row<{ id: string }>>(sql`
      INSERT INTO environment (name, description)
      VALUES (${input.name}, ${input.description ?? null})
      RETURNING id
    `);
    const id = rowsOf(result)[0]?.id;
    if (!id) throw new NotFoundError("Environment");
    return this.get(id, { all: true, environmentIds: [] });
  }

  async update(id: string, input: UpdateEnvironmentRequest): Promise<Environment> {
    const current = await this.get(id, { all: true, environmentIds: [] });

    if (input.name !== undefined && input.name.toLowerCase() !== current.name.toLowerCase()) {
      const clash = await this.deps.db.execute<Row<{ id: string }>>(sql`
        SELECT id FROM environment WHERE lower(name) = lower(${input.name}) AND id <> ${id}::uuid
      `);
      if (rowsOf(clash).length > 0) {
        throw new ConflictError(`An environment named "${input.name}" already exists.`);
      }
    }

    await this.deps.db.execute(sql`
      UPDATE environment
      SET name = ${input.name ?? current.name},
          description = ${
            input.description === undefined ? current.description : input.description || null
          },
          updated_at = now()
      WHERE id = ${id}::uuid
    `);
    return this.get(id, { all: true, environmentIds: [] });
  }

  /**
   * Destroys the environment and everything in it, by cascade: applications, builds, the
   * groups organising them, the suppressions applied to their findings, the reports about
   * them, and the ingest tokens bound to it.
   *
   * Raw SBOM blobs are removed by the same sweep that already handles a deleted application,
   * since scan rows are what reference them.
   *
   * Two guards, and neither is decoration. The typed name proves the caller knows which
   * estate they are on -- a dialog opened from the wrong row does not. Refusing the last
   * environment prevents a deployment with nowhere for an upload to land, which is not
   * recoverable through the UI because every screen needs an environment to render.
   */
  async remove(id: string, confirmName: string): Promise<{ name: string; applications: number }> {
    const target = await this.get(id, { all: true, environmentIds: [] });

    if (confirmName.trim().toLowerCase() !== target.name.toLowerCase()) {
      throw new BadRequestError(
        `Type the environment's name exactly ("${target.name}") to confirm deletion.`,
      );
    }

    const total = await this.deps.db.execute<Row<{ count: number | string }>>(
      sql`SELECT count(*) AS count FROM environment`,
    );
    if (Number(rowsOf(total)[0]?.count ?? 0) <= 1) {
      throw new ConflictError(
        "This is the only environment. Create another before deleting this one — the platform needs somewhere for an upload to land.",
      );
    }

    await this.deps.db.execute(sql`DELETE FROM environment WHERE id = ${id}::uuid`);
    return { name: target.name, applications: target.applicationCount };
  }

  // -- per-user access ------------------------------------------------------

  async environmentsForUser(userId: string): Promise<string[]> {
    const result = await this.deps.db.execute<Row<{ environment_id: string }>>(sql`
      SELECT environment_id FROM user_environment WHERE user_id = ${userId}::uuid
    `);
    return rowsOf(result).map((r) => r.environment_id);
  }

  /**
   * Replaces a user's grants with exactly this set.
   *
   * Rows are written for administrators too if an admin sets them, and simply not consulted
   * while the account is an admin -- so demoting somebody to a read-only role does not
   * silently hand them the whole deployment.
   */
  async setEnvironmentsForUser(userId: string, environmentIds: string[]): Promise<void> {
    await this.deps.db.transaction(async (tx) => {
      await tx.execute(sql`DELETE FROM user_environment WHERE user_id = ${userId}::uuid`);
      for (const environmentId of environmentIds) {
        await tx.execute(sql`
          INSERT INTO user_environment (user_id, environment_id)
          VALUES (${userId}::uuid, ${environmentId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
    });
  }

  /** Every environment id, for "grant all" when an account is created. */
  async allIds(): Promise<string[]> {
    const result = await this.deps.db.execute<Row<{ id: string }>>(
      sql`SELECT id FROM environment ORDER BY created_at ASC`,
    );
    return rowsOf(result).map((r) => r.id);
  }
}
