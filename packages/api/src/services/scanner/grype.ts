import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Config } from "../../config.js";
import { buildScanDocument, parseGrypeReport } from "./grype-output.js";
import { resolveGrypeBinary, type BinaryResolution } from "./grype-binary.js";
import type {
  DbUpdateResult,
  MatchResult,
  ReachabilityResult,
  ScannablePackage,
  ScannerAvailability,
  ScannerDbStatus,
  VulnerabilityScanner,
} from "./types.js";

/**
 * Grype-backed implementation of the scanner port.
 *
 * Runs the binary as a subprocess. Two settings are forced on every invocation and
 * both are load-bearing:
 *
 *   GRYPE_DB_AUTO_UPDATE=false
 *     Measured on this codebase: the same match took 96 seconds with auto-update on
 *     and 1.8 seconds with it off, because Grype silently downloaded a 141 MB
 *     database first. On the ingest path that would turn a CI request into a
 *     multi-minute stall, and on an air-gapped host into a failure. The platform owns
 *     database updates explicitly — through the admin panel and the schedule — so
 *     that a download only ever happens when somebody asked for one.
 *
 *   GRYPE_DB_VALIDATE_AGE=false
 *     Grype otherwise refuses to match against a database older than five days. A
 *     stale database still produces genuinely useful findings, and an air-gapped
 *     deployment may have no way to get a fresher one. Refusing to scan at all would
 *     be strictly worse than scanning and reporting the age prominently, which is
 *     what the admin panel does.
 */
export class GrypeScanner implements VulnerabilityScanner {
  readonly name = "grype";

  /**
   * Binary resolution is cached after the first success.
   *
   * Resolution walks PATH and touches the filesystem, and the sweep asks for
   * availability on every batch. It is not cached on failure, so provisioning the
   * binary and restarting nothing still recovers.
   */
  private resolved: BinaryResolution | null = null;

  constructor(private readonly config: Config) {}

  // -------------------------------------------------------------------------
  // Environment
  // -------------------------------------------------------------------------

  private env(): NodeJS.ProcessEnv {
    return {
      ...process.env,
      GRYPE_DB_CACHE_DIR: path.resolve(this.config.GRYPE_DB_CACHE_DIR),
      GRYPE_DB_UPDATE_URL: this.config.GRYPE_DB_UPDATE_URL,
      GRYPE_DB_AUTO_UPDATE: "false",
      GRYPE_DB_VALIDATE_AGE: "false",
      ...(this.config.GRYPE_DB_CA_CERT ? { GRYPE_DB_CA_CERT: this.config.GRYPE_DB_CA_CERT } : {}),
      // Keeps stdout parseable: grype writes progress to stderr, but a TTY-detected
      // interactive mode would add control characters.
      NO_COLOR: "1",
    };
  }

  private async binary(): Promise<BinaryResolution> {
    if (this.resolved?.binary) return this.resolved;
    this.resolved = await resolveGrypeBinary(this.config.GRYPE_PATH);
    return this.resolved;
  }

  /**
   * Runs grype and captures its output.
   *
   * Resolves with the exit code rather than rejecting on a non-zero one: every
   * non-zero case here is an operational state to report (no route to the listing, no
   * database installed) rather than a programming error, and the caller needs stderr
   * to say something useful about it.
   */
  private async run(
    args: string[],
    options: { timeoutMs: number },
  ): Promise<{ code: number; stdout: string; stderr: string; error: Error | null }> {
    const resolution = await this.binary();
    if (!resolution.binary) {
      return {
        code: -1,
        stdout: "",
        stderr: "grype binary not found",
        error: new Error("grype binary not found"),
      };
    }

    return new Promise((resolve) => {
      const child = spawn(resolution.binary!.path, args, {
        env: this.env(),
        // Never a shell: arguments include filesystem paths, and a shell would make
        // any character in them meaningful.
        shell: false,
        windowsHide: true,
      });

      let stdout = "";
      let stderr = "";
      let settled = false;
      // Large reports arrive in many chunks; concatenating strings is cheaper here
      // than buffering and joining, and the ceiling is bounded by GRYPE_BATCH_SIZE.
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk: string) => {
        // Bounded: grype can emit a lot of progress output, and only the tail is
        // ever useful in an error message.
        stderr = (stderr + chunk).slice(-8192);
      });

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill("SIGKILL");
        resolve({
          code: -1,
          stdout,
          stderr,
          error: new Error(`grype timed out after ${options.timeoutMs}ms`),
        });
      }, options.timeoutMs);
      timer.unref();

      child.on("error", (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ code: -1, stdout, stderr, error: err });
      });

      child.on("close", (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ code: code ?? -1, stdout, stderr, error: null });
      });
    });
  }

  // -------------------------------------------------------------------------
  // Status
  // -------------------------------------------------------------------------

  async availability(): Promise<ScannerAvailability> {
    const resolution = await this.binary();
    if (!resolution.binary) {
      return {
        available: false,
        version: null,
        path: null,
        resolvedBy: null,
        supportedDbSchema: null,
        attempts: resolution.attempts,
      };
    }

    // Resolution proved a file exists; running it is what proves it works. A binary
    // for the wrong architecture, or one truncated by a failed download, resolves
    // fine and fails here — which is the honest place to discover it.
    const result = await this.run(["version", "-o", "json"], { timeoutMs: 30_000 });
    if (result.code !== 0) {
      // Drop the cache so a replaced binary is picked up without a restart.
      this.resolved = null;
      return {
        available: false,
        version: null,
        path: resolution.binary.path,
        resolvedBy: resolution.binary.resolvedBy,
        supportedDbSchema: null,
        attempts: [
          ...resolution.attempts,
          {
            strategy: resolution.binary.resolvedBy,
            location: resolution.binary.path,
            reason: result.error?.message ?? `exited ${result.code}: ${result.stderr.trim().slice(0, 300)}`,
          },
        ],
      };
    }

    let version: string | null = null;
    let supportedDbSchema: number | null = null;
    try {
      const parsed = JSON.parse(result.stdout) as { version?: unknown; supportedDbSchema?: unknown };
      if (typeof parsed.version === "string") version = parsed.version;
      if (typeof parsed.supportedDbSchema === "number") supportedDbSchema = parsed.supportedDbSchema;
    } catch {
      // Version output that will not parse does not make the scanner unusable.
    }

    return {
      available: true,
      version,
      path: resolution.binary.path,
      resolvedBy: resolution.binary.resolvedBy,
      supportedDbSchema,
      attempts: resolution.attempts,
    };
  }

  /**
   * Reads the installed database's state.
   *
   * Note the exit code is deliberately ignored. Verified against Grype 0.115.0: with
   * no database installed, `db status` prints `{"valid": false, "error": "database
   * does not exist"}` and exits **0**. Treating a zero exit as "database present"
   * would report an empty install as healthy.
   */
  async dbStatus(): Promise<ScannerDbStatus> {
    const absent: ScannerDbStatus = {
      present: false,
      builtAt: null,
      schemaVersion: null,
      valid: false,
      error: null,
      path: null,
    };

    const result = await this.run(["db", "status", "-o", "json"], { timeoutMs: 60_000 });
    if (!result.stdout.trim()) {
      return {
        ...absent,
        error: result.error?.message ?? result.stderr.trim().slice(0, 300) ?? "grype db status produced no output",
      };
    }

    try {
      const parsed = JSON.parse(result.stdout) as {
        schemaVersion?: unknown;
        built?: unknown;
        valid?: unknown;
        error?: unknown;
        path?: unknown;
      };

      const builtRaw = typeof parsed.built === "string" ? parsed.built : null;
      let builtAt: Date | null = null;
      if (builtRaw) {
        const date = new Date(builtRaw);
        // Grype reports the zero time (year 1) when nothing is installed.
        if (!Number.isNaN(date.getTime()) && date.getUTCFullYear() > 1970) builtAt = date;
      }

      const schemaVersion =
        typeof parsed.schemaVersion === "string" && parsed.schemaVersion.trim() !== ""
          ? parsed.schemaVersion
          : null;

      return {
        // A database is "present" when it has a build date and a schema, regardless of
        // whether grype considers it valid — an out-of-date database is installed and
        // usable, and the age is reported separately.
        present: builtAt !== null && schemaVersion !== null,
        builtAt,
        schemaVersion,
        valid: parsed.valid === true,
        error: typeof parsed.error === "string" && parsed.error.trim() !== "" ? parsed.error : null,
        path: typeof parsed.path === "string" ? parsed.path : null,
      };
    } catch {
      return { ...absent, error: "could not parse grype db status output" };
    }
  }

  // -------------------------------------------------------------------------
  // Database updates
  // -------------------------------------------------------------------------

  /** The exact listing URL grype consults, so a failure can name it. */
  async listingUrl(): Promise<string> {
    const base = this.config.GRYPE_DB_UPDATE_URL.replace(/\/+$/, "");
    const availability = await this.availability();
    // Falls back to 6 only if the binary could not be asked. Getting this from the
    // binary rather than hardcoding it means a grype upgrade that moves to schema 7
    // reports the right URL without a code change.
    const schema = availability.supportedDbSchema ?? 6;
    return `${base}/v${schema}/latest.json`;
  }

/**
   * The outbound proxy this process was given, if any.
   *
   * Node's fetch ignores these variables. Built-in support arrived in Node 24 behind
   * NODE_USE_ENV_PROXY and the runtime image is Node 22, so the probe below is blind to a
   * proxy that grype -- a Go binary, which honours them -- uses perfectly well. Left
   * unhandled that asymmetry reports "no internet connection" for a download that would
   * have succeeded, and no amount of correct proxy configuration fixes it.
   */
  private proxyFromEnv(): string | null {
    for (const key of ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]) {
      const value = process.env[key];
      if (value && value.trim() !== "") return value.trim();
    }
    return null;
  }

  /**
   * Probes the listing URL before attempting a download.
   *
   * Two implementations, because a preflight check is only worth anything if it predicts
   * what the real download will do:
   *
   *   no proxy   a plain fetch. Cheap, no process to spawn, and it can name the URL
   *              precisely -- the difference between an administrator knowing they are
   *              air-gapped and filing a bug.
   *   proxy set  grype's own `db check`, because fetch cannot see through the proxy and
   *              would report a failure the downloader would not hit. Same binary, same
   *              client, same proxy handling as the download it is predicting.
   *
   * `db check` exits 0 when the database is current and 100 when an update is available;
   * both mean the listing was reached, which is the only question being asked here. 1 is a
   * genuine failure and carries grype's own message, which names the URL and the cause.
   */
  async checkReachable(): Promise<ReachabilityResult> {
    const url = await this.listingUrl();

    const proxy = this.proxyFromEnv();
    if (proxy !== null) {
      const probe = await this.run(["db", "check"], {
        timeoutMs: this.config.GRYPE_REACHABILITY_TIMEOUT_MS,
      });
      if (probe.code === 0 || probe.code === 100) {
        return { reachable: true, url, message: null };
      }
      const detail = (probe.stderr.trim() || probe.error?.message || `exit ${probe.code}`).slice(0, 500);
      return {
        reachable: false,
        url,
        message: `No connection to ${url} via proxy ${proxy} (${detail})`,
      };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.GRYPE_REACHABILITY_TIMEOUT_MS);
    timer.unref();

    try {
      const response = await fetch(url, { signal: controller.signal, redirect: "follow" });
      if (!response.ok) {
        return {
          reachable: false,
          url,
          message: `${url} responded with HTTP ${response.status}`,
        };
      }
      // Body is drained so the connection is released rather than left dangling.
      await response.arrayBuffer();
      return { reachable: true, url, message: null };
    } catch (err) {
      const detail =
        err instanceof Error && err.name === "AbortError"
          ? `timed out after ${this.config.GRYPE_REACHABILITY_TIMEOUT_MS}ms`
          : err instanceof Error
            ? err.message
            : String(err);
      return { reachable: false, url, message: `No internet connection to ${url} (${detail})` };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Downloads and installs the current database.
   *
   * Checks reachability first so an offline deployment gets a precise, immediate
   * answer instead of a slow generic failure. On any failure the previously installed
   * database is left exactly as it was — a failed update never costs an administrator
   * the working database they already had.
   */
  async updateDb(): Promise<DbUpdateResult> {
    const before = await this.dbStatus();

    const reachability = await this.checkReachable();
    if (!reachability.reachable) {
      return {
        outcome: "unreachable",
        message: reachability.message ?? `No internet connection to ${reachability.url}`,
        builtBefore: before.builtAt,
        builtAfter: before.builtAt,
        schemaVersion: before.schemaVersion,
        sourceUrl: reachability.url,
      };
    }

    await mkdir(path.resolve(this.config.GRYPE_DB_CACHE_DIR), { recursive: true });

    const result = await this.run(["db", "update"], {
      timeoutMs: this.config.GRYPE_DB_UPDATE_TIMEOUT_MS,
    });
    const after = await this.dbStatus();

    if (result.code !== 0) {
      return {
        outcome: "failed",
        message: (result.error?.message ?? result.stderr.trim() ?? "grype db update failed").slice(0, 2000),
        builtBefore: before.builtAt,
        builtAfter: after.builtAt,
        schemaVersion: after.schemaVersion,
        sourceUrl: reachability.url,
      };
    }

    const changed =
      after.builtAt !== null && (before.builtAt === null || after.builtAt.getTime() !== before.builtAt.getTime());

    return {
      outcome: changed ? "updated" : "already-current",
      message: changed
        ? `Installed database built ${after.builtAt?.toISOString() ?? "unknown"}`
        : "The installed database is already the current one",
      builtBefore: before.builtAt,
      builtAfter: after.builtAt,
      schemaVersion: after.schemaVersion,
      sourceUrl: reachability.url,
    };
  }

  /**
   * Installs a database from a local archive.
   *
   * The air-gapped path: copy the `.tar.zst` across and import it, with no network
   * involved at any point.
   */
  async importDb(archivePath: string): Promise<DbUpdateResult> {
    const before = await this.dbStatus();
    await mkdir(path.resolve(this.config.GRYPE_DB_CACHE_DIR), { recursive: true });

    const result = await this.run(["db", "import", path.resolve(archivePath)], {
      timeoutMs: this.config.GRYPE_DB_UPDATE_TIMEOUT_MS,
    });
    const after = await this.dbStatus();

    if (result.code !== 0) {
      return {
        outcome: "failed",
        message: (result.error?.message ?? result.stderr.trim() ?? "grype db import failed").slice(0, 2000),
        builtBefore: before.builtAt,
        builtAfter: after.builtAt,
        schemaVersion: after.schemaVersion,
        sourceUrl: archivePath,
      };
    }

    return {
      outcome: "imported",
      message: `Imported database built ${after.builtAt?.toISOString() ?? "unknown"}`,
      builtBefore: before.builtAt,
      builtAfter: after.builtAt,
      schemaVersion: after.schemaVersion,
      sourceUrl: archivePath,
    };
  }

  // -------------------------------------------------------------------------
  // Matching
  // -------------------------------------------------------------------------

  /**
   * Matches one batch of packages against the installed database.
   *
   * The SBOM is written to a temp file rather than piped on stdin: grype's `sbom:`
   * scheme wants a path, and a file also means a failing batch can be reproduced by
   * hand from the logged path if it ever comes to that. The directory is removed in a
   * `finally`, so a thrown parse error does not leak a 5 MB document per batch.
   */
  async match(packages: readonly ScannablePackage[]): Promise<MatchResult> {
    const submittedComponentIds = packages.map((p) => p.componentId);
    if (packages.length === 0) {
      return {
        findings: [],
        grypeVersion: null,
        dbBuiltAt: null,
        unmappedFindings: 0,
        submittedComponentIds,
      };
    }

    const dir = await mkdtemp(path.join(tmpdir(), "sbom-grype-"));
    const documentPath = path.join(dir, "batch.cdx.json");

    try {
      await writeFile(documentPath, buildScanDocument(packages), "utf8");

      const result = await this.run(["sbom:" + documentPath, "-o", "json", "--quiet"], {
        timeoutMs: this.config.GRYPE_SCAN_TIMEOUT_MS,
      });

      if (result.error) throw result.error;
      if (result.code !== 0) {
        throw new Error(
          `grype exited ${result.code} while matching ${packages.length} packages: ${result.stderr.trim().slice(0, 500)}`,
        );
      }

      const report = parseGrypeReport(result.stdout);
      return {
        findings: report.findings,
        grypeVersion: report.grypeVersion,
        dbBuiltAt: report.dbBuiltAt,
        unmappedFindings: report.unmappedFindings,
        submittedComponentIds,
      };
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}
