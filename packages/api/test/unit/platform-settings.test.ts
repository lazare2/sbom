import { describe, expect, it } from "vitest";
import { SettingsService } from "../../src/modules/settings/settings.service.js";
import type { Config } from "../../src/config.js";
import type { Database } from "../../src/db/client.js";

/**
 * The stale threshold reaches SQL as an interval literal, so what comes back out of the
 * settings table matters more than what went in.
 *
 * A row can predate a change to the bounds, or be edited straight in the database, and the
 * write-side schema cannot help with either. These tests cover the read path specifically:
 * the environment default when nothing is stored, and the refusal to trust a stored value
 * that is out of range or the wrong type.
 */

function serviceWith(rows: Array<{ key: string; value: unknown }>, envDefault = 30): SettingsService {
  const db = { execute: async () => ({ rows }) } as unknown as Database;
  return new SettingsService({
    db,
    config: { STALE_APP_THRESHOLD_DAYS: envDefault } as unknown as Config,
  });
}

const KEY = "app.stale_threshold_days";

describe("platform settings", () => {
  it("falls back to the environment when nothing is stored", async () => {
    // Clearing the override must return to the deployment's value, not to a literal
    // hidden in the code, or the env var silently stops meaning anything.
    expect((await serviceWith([], 45).getPlatformSettings()).staleThresholdDays).toBe(45);
  });

  it("uses a stored override", async () => {
    const s = serviceWith([{ key: KEY, value: 7 }], 30);
    expect((await s.getPlatformSettings()).staleThresholdDays).toBe(7);
  });

  it.each([
    ["zero", 0],
    ["negative", -5],
    ["above the ceiling", 99999],
    ["fractional", 1.5],
    ["a string", "14"],
    ["null", null],
  ])("ignores %s and keeps the environment default", async (_label, stored) => {
    const s = serviceWith([{ key: KEY, value: stored }], 30);
    expect((await s.getPlatformSettings()).staleThresholdDays).toBe(30);
  });

  it("renders the interval as a literal that cannot carry anything but digits", async () => {
    const s = serviceWith([{ key: KEY, value: 14 }], 30);
    const interval = await s.staleInterval();
    // The value is interpolated rather than bound, so this asserts the shape reaching SQL.
    expect(JSON.stringify(interval)).toContain("interval '14 days'");
  });
});
