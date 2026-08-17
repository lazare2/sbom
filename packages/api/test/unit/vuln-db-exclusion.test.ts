import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config.js";
import { SweepService } from "../../src/modules/vulnerabilities/sweep.service.js";
import { VulnDbService } from "../../src/modules/vulnerabilities/vuln-db.service.js";
import type { Database } from "../../src/db/client.js";
import type { SettingsService } from "../../src/modules/settings/settings.service.js";
import type { VulnerabilityScanner } from "../../src/services/scanner/index.js";

/**
 * Mutual exclusion between replacing the vulnerability database and sweeping against it.
 *
 * This exists because of an observed failure, not a hypothetical one. A scheduled sweep
 * was matching packages when an administrator pressed "Update now"; grype downloaded the
 * new database, then failed to install it:
 *
 *   failed to purge existing database: unlinkat ...\6\vulnerability.db:
 *   The process cannot access the file because it is being used by another process.
 *
 * The damaging part is what that leaves behind. grype's purge had already deleted
 * import.json before it reached the file it could not unlink, so the installation was
 * left present-but-invalid — a working database broken by an update that never landed.
 *
 * Windows reports it; POSIX unlink-while-open hides it, but a sweep reading a file being
 * swapped underneath it is wrong on Linux too, so both directions are excluded on every
 * platform.
 */

const config = loadConfig({
  NODE_ENV: "test",
  LOG_LEVEL: "silent",
  DATABASE_URL: "postgres://sbom:sbom@127.0.0.1:5432/sbom_test",
  SESSION_SECRET: "t".repeat(48),
  PUBLIC_URL: "http://localhost:5173",
});

/**
 * A database handle that fails the test if it is touched.
 *
 * The point of both guards is to short-circuit *before* any work: the update must not
 * claim a history row, and the sweep must not count pending components. Reaching Postgres
 * at all would mean the guard is in the wrong place, so this turns that into a failure
 * rather than a silent connection attempt.
 */
const untouchableDb = new Proxy(
  {},
  {
    get(_target, prop) {
      throw new Error(`the guard should short-circuit before touching the database (accessed ${String(prop)})`);
    },
  },
) as unknown as Database;

/** Available, so the guard under test is the next check reached rather than the last. */
const availableScanner = {
  name: "fake",
  async availability() {
    return {
      available: true,
      version: "0.115.0",
      path: "/fake/grype",
      resolvedBy: "bundled" as const,
      supportedDbSchema: 6,
      attempts: [],
    };
  },
  async dbStatus() {
    return {
      present: true,
      builtAt: new Date("2026-08-17T06:19:33.000Z"),
      schemaVersion: "v6.1.9",
      valid: true,
      error: null,
      path: "/fake/6/vulnerability.db",
    };
  },
  async listingUrl() {
    return "https://example.invalid/databases/v6/latest.json";
  },
  async checkReachable() {
    return { reachable: true, url: "https://example.invalid/databases/v6/latest.json", message: null };
  },
  async updateDb() {
    throw new Error("updateDb must not be reached while a sweep is running");
  },
  async importDb() {
    throw new Error("importDb must not be reached while a sweep is running");
  },
  async match() {
    return { findings: [], grypeVersion: null, dbBuiltAt: null, unmappedFindings: 0, submittedComponentIds: [] };
  },
} as unknown as VulnerabilityScanner;

const enabledSettings = {
  async vulnScanningEnabled() {
    return true;
  },
  async getVulnSettings() {
    return { enabled: true, updateIntervalHours: 3 };
  },
} as unknown as SettingsService;

function vulnDbWith(scanBusy: () => boolean): VulnDbService {
  return new VulnDbService({
    db: untouchableDb,
    config,
    scanner: availableScanner,
    settings: enabledSettings,
    scanBusy,
  });
}

function sweepWith(dbReplacing: () => boolean): SweepService {
  return new SweepService({
    db: untouchableDb,
    config,
    scanner: availableScanner,
    settings: enabledSettings,
    logger: { info() {}, warn() {}, error() {}, debug() {} } as never,
    dbReplacing,
  });
}

describe("vulnerability database / sweep mutual exclusion", () => {
  describe("a sweep in progress blocks a replacement", () => {
    it("refuses an online update, reporting busy rather than failing", async () => {
      const result = await vulnDbWith(() => true).update("manual", null);

      expect(result.outcome).toBe("busy");
      expect(result.databaseChanged).toBe(false);
      expect(result.message).toMatch(/sweep is in progress/i);
    });

    it("refuses an archive import too — the same purge runs on that path", async () => {
      const result = await vulnDbWith(() => true).importArchive("/tmp/vulnerability-db.tar.zst", null);

      expect(result.outcome).toBe("busy");
      expect(result.databaseChanged).toBe(false);
      expect(result.message).toMatch(/sweep is in progress/i);
    });

    it("records nothing, so a transient collision leaves no failed row in the history", async () => {
      // `attempt: null` is the observable form of "not recorded". A history row here
      // would show the administrator a red failure for something that never ran, and
      // would leave the claim to expire on the one-hour cutoff.
      const update = await vulnDbWith(() => true).update("scheduled", null);
      const imported = await vulnDbWith(() => true).importArchive("/tmp/db.tar.zst", null);

      expect(update.attempt).toBeNull();
      expect(imported.attempt).toBeNull();
    });
  });

  describe("a replacement in progress blocks a sweep", () => {
    it("declines to start, and says why", async () => {
      const outcome = await sweepWith(() => true).sweep({ reason: "admin" });

      expect(outcome.status).toBe("already-running");
      expect(outcome.message).toMatch(/being replaced/i);
      expect(outcome.componentsScanned).toBe(0);
      expect(outcome.findingsStored).toBe(0);
    });
  });

  describe("with neither in progress", () => {
    it("gets past the guard — proving the tests above assert the guard and not some earlier check", async () => {
      /*
        Without this the suite would pass even if the guard were unreachable: every
        assertion above would still hold if, say, the scanner were reported unavailable.
        Here the guard lets the call through, so it reaches the untouchable database and
        throws — which is the evidence that the guard, and nothing before it, is what
        produced `busy` above.
      */
      await expect(vulnDbWith(() => false).update("manual", null)).rejects.toThrow(
        /should short-circuit before touching the database/,
      );
    });
  });
});
