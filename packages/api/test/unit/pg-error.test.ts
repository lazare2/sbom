import { describe, expect, it } from "vitest";
import { DrizzleQueryError } from "drizzle-orm";
import { isPgError, PG_FOREIGN_KEY_VIOLATION, PG_UNIQUE_VIOLATION } from "../../src/lib/errors.js";

/**
 * drizzle-orm 0.44 started wrapping driver errors in DrizzleQueryError. Every duplicate-name
 * check in the platform turned from 409 into 500 without a unit test failing, because they
 * mock the database. These pin the helper to the shape drizzle really throws.
 */
describe("isPgError", () => {
  const pgUnique = Object.assign(new Error("duplicate key value violates unique constraint"), { code: "23505" });

  it("matches a bare driver error", () => {
    expect(isPgError(pgUnique, PG_UNIQUE_VIOLATION)).toBe(true);
  });

  it("matches a driver error wrapped by drizzle", () => {
    const wrapped = new DrizzleQueryError("insert into \"user\" ...", [], pgUnique);
    expect(isPgError(wrapped, PG_UNIQUE_VIOLATION)).toBe(true);
  });

  it("does not match a different code", () => {
    const wrapped = new DrizzleQueryError("insert ...", [], pgUnique);
    expect(isPgError(wrapped, PG_FOREIGN_KEY_VIOLATION)).toBe(false);
  });

  it("is safe on values that are not errors", () => {
    expect(isPgError(null, PG_UNIQUE_VIOLATION)).toBe(false);
    expect(isPgError("23505", PG_UNIQUE_VIOLATION)).toBe(false);
    expect(isPgError({ cause: { cause: { cause: { cause: { cause: { cause: { code: "23505" } } } } } } }, PG_UNIQUE_VIOLATION)).toBe(false);
  });
});
