import { describe, expect, it } from "vitest";
import {
  advisorySort,
  applicationSort,
  auditSort,
  componentListSort,
  componentSearchSort,
  defineSortTable,
  findingSort,
  firstDirectionFor,
  removedComponentSort,
  scanHistorySort,
  sortRows,
  userSort,
  type SortTable,
} from "@sbom/shared";
import { escapeLikeTerm } from "../../src/modules/components/bulk-search.service.js";

/**
 * Table sorting: the shared declarations, and the client-side comparator.
 *
 * The server-side ORDER BY construction is not unit-testable without a database — it
 * produces SQL, and asserting on generated SQL strings tests the formatter rather than the
 * behaviour. What *is* covered here is the layer both ends validate against, plus the two
 * properties whose absence produces silent wrongness rather than an error:
 *
 *   - every declared field is reachable through the zod schema, so a column the UI makes
 *     clickable cannot be rejected by the API and fall back to the default order;
 *   - the comparator puts missing values last in both directions, ranks numerically, and
 *     is deterministic under ties.
 *
 * Stable pagination — the reason `orderBy` demands a unique tiebreaker — is asserted
 * end-to-end in scripts/smoke-test.ps1 against real data, where page boundaries exist.
 */

const ALL_TABLES: Array<[string, SortTable<string>]> = [
  ["application", applicationSort],
  ["componentList", componentListSort],
  ["removedComponent", removedComponentSort],
  ["scanHistory", scanHistorySort],
  ["componentSearch", componentSearchSort],
  ["user", userSort],
  ["audit", auditSort],
  ["finding", findingSort],
  ["advisory", advisorySort],
];

describe("sort table declarations", () => {
  for (const [name, table] of ALL_TABLES) {
    describe(name, () => {
      it("accepts every field it declares", () => {
        // The property that keeps the two ends in agreement: the UI renders a header for
        // each of `fields`, so a field the schema rejects would be a clickable control that
        // silently does nothing.
        for (const field of table.fields) {
          const parsed = table.querySchema.parse({ sortBy: field });
          expect(parsed.sortBy).toBe(field);
        }
      });

      it("rejects anything it does not declare", () => {
        // Second line of defence behind the ORDER BY whitelists: a column name reaching SQL
        // from the client is an injection, so this must never be permissive.
        expect(() => table.querySchema.parse({ sortBy: "id; DROP TABLE application" })).toThrow();
        expect(() => table.querySchema.parse({ sortBy: "no_such_column" })).toThrow();
      });

      it("applies its declared defaults when nothing is asked for", () => {
        const parsed = table.querySchema.parse({});
        expect(parsed.sortBy).toBe(table.defaultField);
        expect(parsed.sortDir).toBe(table.defaultDirection);
      });

      it("declares a kind for every field, and its default field is one of them", () => {
        expect(table.fields.length).toBeGreaterThan(0);
        expect(table.fields).toContain(table.defaultField);
        for (const field of table.fields) {
          expect(["text", "number", "date"]).toContain(table.kind[field]);
        }
      });

      it("narrows untrusted values with isField", () => {
        expect(table.isField(table.defaultField)).toBe(true);
        expect(table.isField("definitely-not-a-column")).toBe(false);
        expect(table.isField(undefined)).toBe(false);
        expect(table.isField(42)).toBe(false);
      });
    });
  }

  it("gives text columns an A→Z first click and numbers/dates a largest-first one", () => {
    expect(firstDirectionFor("text")).toBe("asc");
    expect(firstDirectionFor("number")).toBe("desc");
    expect(firstDirectionFor("date")).toBe("desc");
  });

  it("opens the applications list on names A→Z and the audit trail on newest first", () => {
    // Spot-checks that the type-aware rule reaches the two tables people open most.
    expect(applicationSort.defaultDirection).toBe("asc");
    expect(applicationSort.firstDirectionFor("lastScanAt")).toBe("desc");
    expect(applicationSort.firstDirectionFor("componentCount")).toBe("desc");
    expect(auditSort.defaultDirection).toBe("desc");
  });

  it("ranks severity numerically so criticals lead, despite the column being text", () => {
    // The column is text in Postgres; ranking it alphabetically would put `critical` below
    // `low` and make the severity sort look broken.
    expect(findingSort.kind.severity).toBe("number");
    expect(findingSort.firstDirectionFor("severity")).toBe("desc");
    expect(advisorySort.kind.severity).toBe("number");
  });

  it("refuses a default field that is not declared", () => {
    // Catches the likely edit — renaming a column and forgetting the default — at module
    // load rather than as an ORDER BY that silently falls through to its else branch.
    expect(() => defineSortTable({ name: "text" } as const, "nope" as never)).toThrow(/not one of/);
  });

  it("lets a table override the direction its default field would imply", () => {
    const table = defineSortTable({ createdAt: "date", name: "text" } as const, "createdAt", "asc");
    expect(table.defaultDirection).toBe("asc");
    // The per-column first click is unaffected: only the table default was overridden.
    expect(table.firstDirectionFor("createdAt")).toBe("desc");
  });

  it("shares one declaration between the single search and the list search", () => {
    // Both render ComponentHitsTable. Two declarations would let the same header sort
    // differently on the two screens.
    expect(componentSearchSort.fields).toContain("applicationName");
    expect(componentSearchSort.fields).toContain("lastSeenAt");
  });
});

describe("sortRows", () => {
  interface Row {
    name: string;
    count: number | null;
    seen: string | null;
  }
  const rows: Row[] = [
    { name: "beta", count: 2, seen: "2026-02-01T00:00:00Z" },
    { name: "alpha", count: 10, seen: null },
    { name: "gamma", count: null, seen: "2026-01-01T00:00:00Z" },
  ];

  it("sorts text case-insensitively", () => {
    const mixed = [{ name: "Zebra" }, { name: "apple" }, { name: "Banana" }];
    const asc = sortRows(mixed, (r) => r.name, "asc").map((r) => r.name);
    // Not ["Banana", "Zebra", "apple"], which is what a naive comparison gives — all
    // capitals ahead of all lowercase reads as a broken sort.
    expect(asc).toEqual(["apple", "Banana", "Zebra"]);
  });

  it("sorts numeric text by value, not lexically", () => {
    const versions = [{ v: "9" }, { v: "10" }, { v: "2" }];
    expect(sortRows(versions, (r) => r.v, "asc").map((r) => r.v)).toEqual(["2", "9", "10"]);
  });

  it("puts missing values last in BOTH directions", () => {
    /*
      The property worth a test of its own. Absent data is not an extreme value: a
      never-scanned application floated to the top of "newest first" would read as the most
      recently scanned one, which is the opposite of the truth.
    */
    const ascending = sortRows(rows, (r) => r.count, "asc").map((r) => r.name);
    const descending = sortRows(rows, (r) => r.count, "desc").map((r) => r.name);

    expect(ascending.at(-1)).toBe("gamma");
    expect(descending.at(-1)).toBe("gamma");
    expect(ascending.slice(0, 2)).toEqual(["beta", "alpha"]);
    expect(descending.slice(0, 2)).toEqual(["alpha", "beta"]);
  });

  it("treats an empty string as missing too", () => {
    // An unset text attribute arrives as "" rather than null, and sorting those to the top
    // of a name column would bury the rows that have data.
    const withBlank = [{ name: "b" }, { name: "" }, { name: "a" }];
    expect(sortRows(withBlank, (r) => r.name, "asc").map((r) => r.name)).toEqual(["a", "b", ""]);
    expect(sortRows(withBlank, (r) => r.name, "desc").map((r) => r.name)).toEqual(["b", "a", ""]);
  });

  it("breaks ties with the tiebreaker, in a fixed order regardless of input order", () => {
    const tied = [
      { id: "c", group: 1 },
      { id: "a", group: 1 },
      { id: "b", group: 1 },
    ];
    const forwards = sortRows(tied, (r) => r.group, "desc", (r) => r.id).map((r) => r.id);
    const backwards = sortRows([...tied].reverse(), (r) => r.group, "desc", (r) => r.id).map((r) => r.id);

    expect(forwards).toEqual(["a", "b", "c"]);
    // The same result from a different starting order is what makes the display stable as
    // the underlying data changes.
    expect(backwards).toEqual(forwards);
  });

  it("keeps the tiebreaker ascending even when the primary sort is descending", () => {
    // A tiebreaker that flipped with the primary direction would make tied rows appear to
    // reorder for no reason when the user reverses an unrelated column.
    const tied = [
      { id: "a", group: 5 },
      { id: "b", group: 5 },
    ];
    expect(sortRows(tied, (r) => r.group, "asc", (r) => r.id).map((r) => r.id)).toEqual(["a", "b"]);
    expect(sortRows(tied, (r) => r.group, "desc", (r) => r.id).map((r) => r.id)).toEqual(["a", "b"]);
  });

  it("sorts date strings chronologically", () => {
    const asc = sortRows(rows, (r) => r.seen, "asc").map((r) => r.name);
    expect(asc.slice(0, 2)).toEqual(["gamma", "beta"]);
    // alpha has no timestamp, so it lands last rather than reading as the oldest.
    expect(asc.at(-1)).toBe("alpha");
  });

  it("does not mutate the input", () => {
    // The rows come straight from react-query's cache; sorting in place would reorder the
    // cached array under every other consumer of the same query.
    const original = [...rows];
    sortRows(rows, (r) => r.name, "desc");
    expect(rows).toEqual(original);
  });

  it("handles an empty list", () => {
    expect(sortRows([], (r: { name: string }) => r.name, "asc")).toEqual([]);
  });
});

describe("escapeLikeTerm", () => {
  /**
   * The list search's substring mode builds `ILIKE '%' || term || '%'`, so LIKE
   * metacharacters in a pasted package name have to be neutralised. Unescaped, an entry of
   * `%` matches every package in the estate while looking like an ordinary line in the
   * input — a wrong answer that reports itself as a very successful search.
   */
  it("escapes the LIKE wildcards", () => {
    expect(escapeLikeTerm("foo_bar")).toBe("foo\\_bar");
    expect(escapeLikeTerm("50%")).toBe("50\\%");
    expect(escapeLikeTerm("%")).toBe("\\%");
  });

  it("escapes the escape character first, so the escaping cannot be escaped away", () => {
    // `\%` must become `\\\%` — a literal backslash then a literal percent. Doing the
    // wildcards first would produce `\\%`, which is a literal backslash followed by a live
    // wildcard.
    expect(escapeLikeTerm("\\%")).toBe("\\\\\\%");
    expect(escapeLikeTerm("a\\b")).toBe("a\\\\b");
  });

  it("leaves ordinary package names untouched", () => {
    // Every character real package names use — scopes, dots, dashes, slashes, plus signs —
    // has to survive verbatim, or exact-looking searches would quietly stop matching.
    for (const name of ["react", "@lit/reactive-element", "log4j-core", "libstdc++6", "django", "gopkg.in/yaml.v2"]) {
      expect(escapeLikeTerm(name)).toBe(name);
    }
  });
});
