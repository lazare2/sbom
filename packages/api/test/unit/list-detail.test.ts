import { describe, expect, it } from "vitest";
import { EXPANDABLE_LIST_CAP } from "@sbom/shared";
import { capOr, fullLists, listCap, runWithListDetail } from "../../src/lib/list-detail.js";

/** Exports get every name in a list; screens get the first EXPANDABLE_LIST_CAP. */
describe("list detail per request", () => {
  it("cuts lists for the screen by default", () => {
    expect(fullLists()).toBe(false);
    expect(listCap()).toBe(EXPANDABLE_LIST_CAP);
    expect(capOr(500)).toBe(500);
  });

  it("lifts every cap for a request that asks for full lists, and only for that request", async () => {
    const inside = await runWithListDetail(true, async () => {
      await new Promise((r) => setTimeout(r, 5)); // survives an await, as a handler does
      return { full: fullLists(), cap: listCap(), impact: capOr(500) };
    });
    expect(inside.full).toBe(true);
    expect(inside.cap).toBeGreaterThan(100_000);
    expect(inside.impact).toBeGreaterThan(100_000);
    expect(listCap()).toBe(EXPANDABLE_LIST_CAP);
  });

  it("keeps two requests apart", async () => {
    const [a, b] = await Promise.all([
      runWithListDetail(true, async () => {
        await new Promise((r) => setTimeout(r, 10));
        return listCap();
      }),
      runWithListDetail(false, async () => {
        await new Promise((r) => setTimeout(r, 5));
        return listCap();
      }),
    ]);
    expect(a).toBeGreaterThan(100_000);
    expect(b).toBe(EXPANDABLE_LIST_CAP);
  });
});
