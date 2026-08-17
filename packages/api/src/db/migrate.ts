import path from "node:path";
import { fileURLToPath } from "node:url";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { closeDb, getDb } from "./client.js";
import { getConfig } from "../config.js";

/**
 * Applies pending migrations from ./drizzle.
 *
 * Drizzle records applied migrations in `drizzle.__drizzle_migrations` and runs
 * each file in a transaction, so this is safe to run on every deploy and safe to
 * run twice. Schema changes are always generated as files (`npm run db:generate`)
 * and reviewed — never applied by pushing the schema directly.
 */
async function main(): Promise<void> {
  const config = getConfig();
  const db = getDb();

  const migrationsFolder = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../drizzle");

  console.log(`[migrate] applying migrations from ${migrationsFolder}`);
  console.log(`[migrate] target: ${config.DATABASE_URL.replace(/:[^:@/]*@/, ":****@")}`);

  await migrate(db, { migrationsFolder });

  console.log("[migrate] done");
}

main()
  .then(() => closeDb())
  .then(() => process.exit(0))
  .catch(async (err: unknown) => {
    console.error("[migrate] failed:", err);
    await closeDb().catch(() => undefined);
    process.exit(1);
  });
