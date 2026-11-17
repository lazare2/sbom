import { sql, type SQL } from "drizzle-orm";
import type { AttackVectorFilter } from "@sbom/shared";

/**
 * The attack-vector filters, in SQL over `v.cvss_vector`.
 *
 * Read from the vector already stored on every advisory, so no column and no migration: the
 * same rules as `readCvssVector` in @sbom/shared (see there for the CVSS background), written
 * as Postgres regular expressions over the upper-cased vector. The patterns are exported so
 * attack-vector.test.ts can hold them to `readCvssVector` on the same vectors.
 *
 * `(?:^|[/(])` anchors each metric at the start of the vector or after a separator, so `AV:N`
 * is never found inside another metric's name.
 */
export const AV_PATTERN = "(?:^|[/(])AV:([NALP])";
export const PR_NONE_PATTERN = "(?:^|[/(])PR:N";
export const PR_ANY_PATTERN = "(?:^|[/(])PR:";
/** CVSS v2's authentication metric, read only when the vector has no PR. */
export const AU_NONE_PATTERN = "(?:^|[/(])AU:N";
export const UI_NONE_PATTERN = "(?:^|[/(])UI:N";

/** The vector's AV letter (N, A, L, P), or NULL when there is no vector or no AV part. */
const AV_LETTER = sql`substring(upper(v.cvss_vector) from ${sql.raw(`'${AV_PATTERN}'`)})`;

const LETTER: Record<Exclude<AttackVectorFilter, "unknown">, string> = {
  network: "N",
  adjacent: "A",
  local: "L",
  physical: "P",
};

/** Advisories whose attack vector is any of `wanted`. "unknown" matches no vector at all. */
export function attackVectorCondition(wanted: readonly AttackVectorFilter[]): SQL | null {
  if (wanted.length === 0) return null;
  const letters = wanted.filter((w) => w !== "unknown").map((w) => LETTER[w as keyof typeof LETTER]);
  const parts: SQL[] = [];
  if (letters.length > 0) parts.push(sql`${AV_LETTER} = ANY(${sql.param(letters)}::text[])`);
  if (wanted.includes("unknown")) parts.push(sql`${AV_LETTER} IS NULL`);
  return sql`(${sql.join(parts, sql` OR `)})`;
}

/**
 * Needs neither a sign-in nor anybody's action: PR:N (or v2's Au:N) and UI:N.
 *
 * CVSS v2 has no user-interaction part, so a v2 advisory never matches - the platform does not
 * claim "no action needed" when the advisory does not say so. v2's Au is read only when there is
 * no PR, because CVSS v4 has an unrelated supplemental metric also called AU (Automatable).
 */
export const NO_PREREQUISITES_CONDITION = sql.raw(`(
  (
    upper(v.cvss_vector) ~ '${PR_NONE_PATTERN}'
    OR (upper(v.cvss_vector) !~ '${PR_ANY_PATTERN}' AND upper(v.cvss_vector) ~ '${AU_NONE_PATTERN}')
  )
  AND upper(v.cvss_vector) ~ '${UI_NONE_PATTERN}'
)`);

/** The same test in JavaScript, for the tests that hold the SQL to `readCvssVector`. */
export function matchesNoPrerequisites(vector: string | null): boolean {
  if (!vector) return false;
  const v = vector.toUpperCase();
  const pr = new RegExp(PR_NONE_PATTERN).test(v) || (!new RegExp(PR_ANY_PATTERN).test(v) && new RegExp(AU_NONE_PATTERN).test(v));
  return pr && new RegExp(UI_NONE_PATTERN).test(v);
}

/** The AV letter the SQL would read, in JavaScript. */
export function attackVectorLetter(vector: string | null): string | null {
  if (!vector) return null;
  return new RegExp(AV_PATTERN).exec(vector.toUpperCase())?.[1] ?? null;
}
