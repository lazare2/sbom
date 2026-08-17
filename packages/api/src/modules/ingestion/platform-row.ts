import type { ScanPlatform } from "@sbom/shared";
import { platformSummary, type DetectedRuntime } from "./platform.js";

/** The platform columns as they come back from a raw SQL select on `scan`. */
export interface PlatformRow {
  os_name?: string | null;
  os_version?: string | null;
  os_pretty?: string | null;
  runtimes?: unknown;
}

/**
 * Maps the four denormalised scan columns to the wire shape, computing the
 * display summary server-side.
 *
 * The summary is rendered here rather than in the browser so the OS and runtime
 * label tables live in exactly one place. Otherwise adding "Wolfi" or "Bun"
 * would mean editing two lists that drift apart, and the API and UI would
 * disagree about what an image runs.
 */
export function toScanPlatform(row: PlatformRow): ScanPlatform {
  const runtimes = normalizeRuntimes(row.runtimes);
  const data = {
    osName: row.os_name ?? null,
    osVersion: row.os_version ?? null,
    osPretty: row.os_pretty ?? null,
    runtimes,
  };
  return { ...data, summary: platformSummary(data) };
}

/**
 * Defensively normalises the jsonb column.
 *
 * jsonb is schemaless from Postgres's point of view, and these rows can predate
 * the current shape — a scan ingested before this feature existed has SQL NULL,
 * and a hand-edited row could hold anything. Validating here keeps a malformed
 * value from reaching the UI as a crash on `.map`.
 */
function normalizeRuntimes(value: unknown): DetectedRuntime[] {
  if (!Array.isArray(value)) return [];
  const out: DetectedRuntime[] = [];
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null) continue;
    const e = entry as { name?: unknown; version?: unknown };
    if (typeof e.name !== "string" || e.name === "") continue;
    out.push({ name: e.name, version: typeof e.version === "string" ? e.version : null });
  }
  return out;
}
