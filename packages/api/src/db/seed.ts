import { sql } from "drizzle-orm";
import { getConfig } from "../config.js";
import { generatePassword } from "../lib/crypto.js";
import { hashPassword } from "../modules/auth/password.js";
import { closeDb, getDb } from "./client.js";
import { attributeDefinition, user } from "./schema.js";

/**
 * Idempotent seed: the three starting attribute definitions, and a bootstrap
 * admin if the instance has no users yet.
 *
 * Safe to run on every deploy. Kept out of the migrations so an admin who
 * renames or deactivates an attribute definition does not have it silently
 * reinstated by the next `db:migrate`.
 */

/**
 * The attributes the spec starts with. They live in `attribute_definition`
 * rather than as columns on `application`, so adding a fourth later is an admin
 * action instead of a migration.
 */
const DEFAULT_ATTRIBUTES = [
  { key: "squad", label: "Squad", type: "string" as const, options: null, sortOrder: 10 },
  { key: "owner", label: "Owner", type: "string" as const, options: null, sortOrder: 20 },
  {
    key: "severity",
    label: "Severity",
    type: "select" as const,
    options: ["critical", "high", "medium", "low"],
    sortOrder: 30,
  },
];

async function seedAttributeDefinitions(): Promise<void> {
  const db = getDb();
  const inserted = await db
    .insert(attributeDefinition)
    .values(DEFAULT_ATTRIBUTES)
    // Leaves an admin's edits to these rows untouched on re-run.
    .onConflictDoNothing({ target: attributeDefinition.key })
    .returning({ key: attributeDefinition.key });

  if (inserted.length > 0) {
    console.log(`[seed] created attribute definitions: ${inserted.map((r) => r.key).join(", ")}`);
  } else {
    console.log("[seed] attribute definitions already present");
  }
}

async function seedBootstrapAdmin(): Promise<void> {
  const config = getConfig();
  const db = getDb();

  const rows = await db.select({ count: sql<number>`count(*)::int` }).from(user);
  const count = rows[0]?.count ?? 0;

  if (count > 0) {
    console.log("[seed] users already exist; skipping bootstrap admin");
    return;
  }

  if (!config.BOOTSTRAP_ADMIN_EMAIL) {
    console.log(
      "[seed] no users and no BOOTSTRAP_ADMIN_EMAIL set — set it (and optionally " +
        "BOOTSTRAP_ADMIN_PASSWORD) and re-run `npm run db:seed` to create the first admin",
    );
    return;
  }

  const email = config.BOOTSTRAP_ADMIN_EMAIL.toLowerCase();

  /**
   * With no password configured, generate one and print it.
   *
   * An account with no password used to be a valid state, recoverable through
   * an emailed setup link. There is no such link any more — emails are
   * identifiers, not mailboxes — so a passwordless bootstrap admin would be an
   * instance nobody can ever log into. Printing a generated password to the
   * seed output is the only honest option: it goes to the operator's terminal,
   * which is where they already are.
   */
  const generated = config.BOOTSTRAP_ADMIN_PASSWORD ? null : generatePassword();
  const password = config.BOOTSTRAP_ADMIN_PASSWORD ?? generated!;

  await db.insert(user).values({
    email,
    passwordHash: await hashPassword(password),
    role: "admin",
    authProvider: "local",
    isActive: true,
    // A configured password came from the operator and is theirs already; a
    // generated one has just been printed to a terminal and quite possibly a
    // CI log, so it must not survive first use.
    mustChangePassword: generated !== null,
  });

  console.log(`[seed] created bootstrap admin: ${email}`);
  if (generated) {
    console.log(`[seed] generated password: ${generated}`);
    console.log("[seed] you will be required to change it at first sign-in");
  }
}

async function main(): Promise<void> {
  await seedAttributeDefinitions();
  await seedBootstrapAdmin();
  console.log("[seed] done");
}

main()
  .then(() => closeDb())
  .then(() => process.exit(0))
  .catch(async (err: unknown) => {
    console.error("[seed] failed:", err);
    await closeDb().catch(() => undefined);
    process.exit(1);
  });
