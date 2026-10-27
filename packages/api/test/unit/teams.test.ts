import { describe, expect, it } from "vitest";
import { createSquadSchema, createTribeSchema, updateSquadSchema } from "@sbom/shared";
import { assertRequiredPresent } from "../../src/modules/admin/attributes.js";
import { parseTeamNames, TeamAttributes } from "../../src/modules/squads/team-attributes.js";
import type { AttributeDefinitionRow } from "../../src/db/schema.js";
import type { Database } from "../../src/db/client.js";

function def(overrides: Partial<AttributeDefinitionRow> & { key: string }): AttributeDefinitionRow {
  return {
    id: `id-${overrides.key}`,
    key: overrides.key,
    label: overrides.label ?? overrides.key,
    type: overrides.type ?? "string",
    options: overrides.options ?? null,
    sortOrder: overrides.sortOrder ?? 0,
    isActive: overrides.isActive ?? true,
    isRequired: overrides.isRequired ?? false,
    linkedTo: overrides.linkedTo ?? null,
    createdAt: new Date(),
  };
}

describe("parseTeamNames", () => {
  it("splits on commas and trims", () => {
    expect(parseTeamNames("payments, storefront")).toEqual(["payments", "storefront"]);
  });

  it("drops blanks and case-insensitive repeats, keeping the first spelling", () => {
    expect(parseTeamNames(" Payments ,, payments , ,Data")).toEqual(["Payments", "Data"]);
  });

  it("reads null, undefined and an empty string as no teams", () => {
    expect(parseTeamNames(null)).toEqual([]);
    expect(parseTeamNames(undefined)).toEqual([]);
    expect(parseTeamNames("  ")).toEqual([]);
  });
});

describe("assertRequiredPresent", () => {
  const DEFS = [
    def({ key: "squad", label: "Squad", isRequired: true, linkedTo: "squad" }),
    def({ key: "owner", label: "Owner", isRequired: true }),
    def({ key: "notes", label: "Notes" }),
    def({ key: "tier", label: "Tier", isRequired: true, isActive: false }),
  ];

  it("passes when every active required attribute has a value", () => {
    expect(() => assertRequiredPresent(DEFS, { squad: "payments", owner: "aisha" })).not.toThrow();
  });

  it("names every empty required attribute at once", () => {
    try {
      assertRequiredPresent(DEFS, { owner: "  " });
      expect.unreachable();
    } catch (err) {
      expect((err as { details?: unknown }).details).toEqual({
        squad: ['"Squad" is required'],
        owner: ['"Owner" is required'],
      });
    }
  });

  it("ignores inactive definitions", () => {
    expect(() => assertRequiredPresent(DEFS, { squad: "x", owner: "y" })).not.toThrow();
  });

  it("checks only the keys an edit touched when told to", () => {
    // An application CI created with no owner can still have its squad changed.
    expect(() => assertRequiredPresent(DEFS, { squad: "payments" }, ["squad"])).not.toThrow();
    expect(() => assertRequiredPresent(DEFS, {}, ["squad"])).toThrow(/required/);
  });
});

describe("squad and tribe names", () => {
  it("refuse a comma, which would read back as two names", () => {
    expect(createSquadSchema.safeParse({ name: "payments, cards" }).success).toBe(false);
    expect(createTribeSchema.safeParse({ name: "Retail, Corporate" }).success).toBe(false);
  });

  it("accept tribes on a squad, deduplicated", () => {
    const id = "6f1c3f39-9a5f-4b0f-8d61-3d2b2a7c1e01";
    const parsed = createSquadSchema.parse({ name: "payments", tribeIds: [id, id] });
    expect(parsed.tribeIds).toEqual([id]);
  });

  it("count a tribe change as something to save", () => {
    expect(updateSquadSchema.safeParse({ tribeIds: [] }).success).toBe(true);
    expect(updateSquadSchema.safeParse({}).success).toBe(false);
  });
});

/**
 * The bound array of lowered names inside a drizzle query: the value of its one Param (the
 * object carrying an encoder), not the SQL text fragments, which are string arrays too.
 */
function findStringArray(value: unknown, seen = new Set<unknown>()): string[] | undefined {
  if (value === null || typeof value !== "object" || seen.has(value)) return undefined;
  seen.add(value);
  const record = value as Record<string, unknown>;
  if ("encoder" in record && Array.isArray(record.value)) return record.value as string[];
  for (const child of Object.values(value as Record<string, unknown>)) {
    const found = findStringArray(child, seen);
    if (found) return found;
  }
  return undefined;
}

describe("TeamAttributes.resolve", () => {
  /** Answers the name lookup from a fixed list of squads and tribes. */
  function fakeDb(known: { squad: Record<string, string>; tribe: Record<string, string> }): Database {
    return {
      execute: async (query: unknown) => {
        const text = JSON.stringify(query);
        const table = text.includes("FROM squad ") ? known.squad : known.tribe;
        const names = findStringArray(query);
        const rows = (names ?? [])
          .filter((n) => table[n] !== undefined)
          .map((n) => ({ id: table[n], lname: n }));
        return { rows };
      },
    } as unknown as Database;
  }

  const DEFS = [
    def({ key: "squad", label: "Squad", linkedTo: "squad" }),
    def({ key: "tribe", label: "Tribe", linkedTo: "tribe" }),
    def({ key: "owner", label: "Owner" }),
  ];

  it("turns names into ids and leaves other attributes alone", async () => {
    const teams = new TeamAttributes({
      db: fakeDb({ squad: { payments: "s1", storefront: "s2" }, tribe: { retail: "t1" } }),
    });
    const out = await teams.resolve(DEFS, {
      squad: "Payments, storefront",
      tribe: "retail",
      owner: "aisha",
    });
    expect(out.plain).toEqual({ owner: "aisha" });
    expect(out.assignments).toEqual({ squad: ["s1", "s2"], tribe: ["t1"] });
  });

  it("reads a cleared value as no assignments, and an absent key as no change", async () => {
    const teams = new TeamAttributes({ db: fakeDb({ squad: {}, tribe: {} }) });
    const out = await teams.resolve(DEFS, { squad: null });
    expect(out.assignments).toEqual({ squad: [] });
    expect(out.assignments.tribe).toBeUndefined();
  });

  it("refuses unknown names instead of creating them, naming each one", async () => {
    const teams = new TeamAttributes({ db: fakeDb({ squad: { payments: "s1" }, tribe: {} }) });
    await expect(teams.resolve(DEFS, { squad: "payments, Paymnets, cards" })).rejects.toMatchObject({
      details: {
        squad: [
          expect.stringContaining('No squad named "Paymnets"'),
          expect.stringContaining('No squad named "cards"'),
        ],
      },
    });
  });
});
