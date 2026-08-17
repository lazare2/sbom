import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema.js";
import { getConfig, type Config } from "../config.js";

export type Database = NodePgDatabase<typeof schema>;

/**
 * `pg` parses int8 (bigint) into a JS string by default to avoid precision
 * loss. Our only int8 columns are `component.id` and `scan.sbom_size_bytes`,
 * both far below 2^53, and Drizzle's `mode: "number"` expects numbers — so
 * parse them as numbers to keep the mapping honest.
 */
pg.types.setTypeParser(pg.types.builtins.INT8, (value) => Number(value));

let pool: pg.Pool | undefined;
let db: Database | undefined;

/**
 * Builds a pool from an explicit config.
 *
 * The config is a parameter rather than read from `getConfig()` inside, so a
 * caller that was handed a config (tests, and `buildContext`) cannot silently
 * end up connecting somewhere else because the module reached for
 * `process.env` on its own.
 */
export function createPool(config: Config): pg.Pool {
  return new pg.Pool({
    connectionString: config.DATABASE_URL,
    max: config.DATABASE_POOL_MAX,
    // A long-running ingest transaction is normal; an idle client holding a
    // connection for ten minutes is not.
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    application_name: "sbom-api",
  });
}

export function createDb(config: Config): Database {
  return drizzle(createPool(config), { schema, casing: "snake_case" });
}

/** Process-wide pool, created on first access. Used by the server and CLI scripts. */
export function getPool(config?: Config): pg.Pool {
  if (!pool) {
    pool = createPool(config ?? getConfig());
    pool.on("error", (err) => {
      // An idle client erroring out must not take the process down.
      console.error("[db] idle client error", err);
    });
  }
  return pool;
}

export function getDb(config?: Config): Database {
  db ??= drizzle(getPool(config), { schema, casing: "snake_case" });
  return db;
}

export async function closeDb(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = undefined;
    db = undefined;
  }
}

export { schema };
