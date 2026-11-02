import { copyFile, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Config } from "../../config.js";
import { resolveToolBinary, TRIVY_TOOL, type BinaryResolution } from "./grype-binary.js";
import type { ParsedFinding } from "./grype-output.js";
import { lastLine, runProcess } from "./process.js";
import { buildTrivyDocuments, parseTrivyReport } from "./trivy-output.js";
import type {
  DbUpdateResult,
  MatchResult,
  ReachabilityResult,
  ScannablePackage,
  ScannerAvailability,
  ScannerDbStatus,
  VulnerabilityScanner,
} from "./types.js";

async function exists(file: string): Promise<boolean> {
  try {
    await stat(file);
    return true;
  } catch {
    return false;
  }
}

/** Stderr fragments that mean "no route to the registry", as opposed to a broken download. */
const UNREACHABLE = /dial tcp|no such host|i\/o timeout|connection refused|tls: |x509: |proxyconnect|context deadline exceeded/i;

/**
 * Trivy, run as a local scanner beside Grype.
 *
 * Its database is an OCI artifact (`mirror.gcr.io/aquasec/trivy-db:2` by default) that it
 * downloads into its own cache; matching then runs fully offline (`--skip-db-update
 * --offline-scan`), so a sweep never touches the network - the same split Grype has between
 * "update the database" and "match against it".
 */
export class TrivyScanner implements VulnerabilityScanner {
  readonly name = "trivy";
  private resolved: BinaryResolution | null = null;

  constructor(
    private readonly config: Config,
    private readonly deps: { caCert: () => Promise<string | null> },
  ) {}

  private get cacheDir(): string {
    return path.resolve(this.config.TRIVY_CACHE_DIR);
  }

  private async binary(): Promise<BinaryResolution> {
    if (this.resolved?.binary) return this.resolved;
    this.resolved = await resolveToolBinary(TRIVY_TOOL, this.config.TRIVY_PATH);
    return this.resolved;
  }

  private async run(args: string[], timeoutMs: number) {
    const resolution = await this.binary();
    if (!resolution.binary) {
      return { code: -1, stdout: "", stderr: "trivy binary not found", error: new Error("trivy binary not found") };
    }
    const caCert = await this.deps.caCert().catch(() => null);
    return runProcess(resolution.binary.path, args, {
      label: "trivy",
      timeoutMs,
      env: {
        ...process.env,
        TRIVY_NO_PROGRESS: "true",
        TRIVY_DISABLE_VEX_NOTICE: "true",
        // Go reads a CA bundle from here; a TLS-inspecting proxy needs its CA trusted.
        ...(caCert ? { SSL_CERT_FILE: caCert } : {}),
        NO_COLOR: "1",
      },
    });
  }

  async availability(): Promise<ScannerAvailability> {
    const resolution = await this.binary();
    if (!resolution.binary) {
      return { available: false, version: null, path: null, resolvedBy: null, supportedDbSchema: null, attempts: resolution.attempts };
    }
    const result = await this.run(["version", "--format", "json"], 30_000);
    if (result.code !== 0) {
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
            reason: result.error?.message ?? `exited ${result.code}: ${lastLine(result.stderr)}`,
          },
        ],
      };
    }
    let version: string | null = null;
    try {
      const parsed = JSON.parse(result.stdout) as { Version?: unknown };
      if (typeof parsed.Version === "string") version = parsed.Version;
    } catch {
      // A version we cannot read does not make the binary unusable.
    }
    return {
      available: true,
      version,
      path: resolution.binary.path,
      resolvedBy: resolution.binary.resolvedBy,
      supportedDbSchema: 2,
      attempts: resolution.attempts,
    };
  }

  /** Read straight from the cache: `db/metadata.json` beside `db/trivy.db`. */
  async dbStatus(): Promise<ScannerDbStatus> {
    const dbPath = path.join(this.cacheDir, "db", "trivy.db");
    const absent: ScannerDbStatus = { present: false, builtAt: null, schemaVersion: null, valid: false, error: null, path: dbPath };
    try {
      await stat(dbPath);
    } catch {
      return { ...absent, error: "No Trivy database is installed yet." };
    }
    try {
      const meta = JSON.parse(await readFile(path.join(this.cacheDir, "db", "metadata.json"), "utf8")) as {
        Version?: unknown;
        UpdatedAt?: unknown;
      };
      const builtAt = typeof meta.UpdatedAt === "string" ? new Date(meta.UpdatedAt) : null;
      const valid = builtAt !== null && !Number.isNaN(builtAt.getTime());
      return {
        present: valid,
        builtAt: valid ? builtAt : null,
        schemaVersion: typeof meta.Version === "number" ? `v${meta.Version}` : null,
        valid,
        error: valid ? null : "The Trivy database metadata has no build time.",
        path: dbPath,
      };
    } catch {
      return { ...absent, error: "The Trivy database metadata could not be read." };
    }
  }

  async watermark(): Promise<Date | null> {
    return (await this.dbStatus()).builtAt;
  }

  async listingUrl(): Promise<string> {
    return this.config.TRIVY_DB_REPOSITORY;
  }

  /** Trivy is asked directly, through any proxy, by the update itself; see `updateDb`. */
  async checkReachable(): Promise<ReachabilityResult> {
    const host = this.config.TRIVY_DB_REPOSITORY.split("/")[0] ?? "";
    const url = `https://${host}/v2/`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.GRYPE_REACHABILITY_TIMEOUT_MS);
    timer.unref();
    try {
      // A registry answers /v2/ with 200 or 401; either proves there is a route.
      const response = await fetch(url, { signal: controller.signal });
      await response.arrayBuffer().catch(() => undefined);
      return { reachable: true, url, message: null };
    } catch (err) {
      return { reachable: false, url, message: `No connection to ${url} (${err instanceof Error ? err.message : String(err)})` };
    } finally {
      clearTimeout(timer);
    }
  }

  async updateDb(): Promise<DbUpdateResult> {
    const before = await this.dbStatus();
    await mkdir(this.cacheDir, { recursive: true });
    const result = await this.run(
      ["image", "--download-db-only", "--cache-dir", this.cacheDir, "--db-repository", this.config.TRIVY_DB_REPOSITORY, "--quiet"],
      this.config.GRYPE_DB_UPDATE_TIMEOUT_MS,
    );
    const after = await this.dbStatus();
    const sourceUrl = this.config.TRIVY_DB_REPOSITORY;

    if (result.code !== 0 || result.error) {
      const detail = (result.error?.message ?? lastLine(result.stderr)) || `exit ${result.code}`;
      return {
        outcome: UNREACHABLE.test(result.stderr) ? "unreachable" : "failed",
        message: `Trivy could not download its database from ${sourceUrl}: ${detail}`,
        builtBefore: before.builtAt,
        builtAfter: after.builtAt,
        schemaVersion: after.schemaVersion,
        sourceUrl,
      };
    }
    const changed = after.builtAt !== null && after.builtAt.getTime() !== before.builtAt?.getTime();
    return {
      outcome: changed ? "updated" : "already-current",
      message: changed
        ? `Installed Trivy database built ${after.builtAt!.toISOString()}`
        : "The installed Trivy database is already the current one",
      builtBefore: before.builtAt,
      builtAfter: after.builtAt,
      schemaVersion: after.schemaVersion,
      sourceUrl,
    };
  }

  /**
   * Install a database archive by hand: Trivy's `db.tar.gz`, the layer of the OCI artifact,
   * holding `trivy.db` and `metadata.json`. For a deployment that can reach no registry.
   */
  async importDb(archivePath: string): Promise<DbUpdateResult> {
    const before = await this.dbStatus();
    const fail = (message: string): DbUpdateResult => ({
      outcome: "failed",
      message,
      builtBefore: before.builtAt,
      builtAfter: before.builtAt,
      schemaVersion: before.schemaVersion,
      sourceUrl: archivePath,
    });
    /*
      Extracted by the system tar into a staging directory, not read through Node: the
      database inside is well over a gigabyte, and holding it in memory to write it back out
      would be the most expensive way to copy a file.
    */
    const staging = await mkdtemp(path.join(tmpdir(), "sbom-trivy-import-"));
    try {
      // Windows' own bsdtar by full path: a `tar` found first on PATH may be Git's GNU tar,
      // which reads the drive letter in a Windows path as a remote host.
      const tarBinary =
        process.platform === "win32" ? path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe") : "tar";
      const untar = await runProcess(tarBinary, ["-xzf", path.resolve(archivePath), "-C", staging], {
        env: process.env,
        timeoutMs: this.config.GRYPE_DB_UPDATE_TIMEOUT_MS,
        label: "tar",
      });
      if (untar.code !== 0 || untar.error) {
        return fail(`Not a Trivy database archive: ${(untar.error?.message ?? lastLine(untar.stderr)) || `tar exited ${untar.code}`}`);
      }
      const dbFile = path.join(staging, "trivy.db");
      const metaFile = path.join(staging, "metadata.json");
      if (!(await exists(dbFile)) || !(await exists(metaFile))) {
        return fail("The archive holds no trivy.db and metadata.json at its top level, so it is not a Trivy database.");
      }
      await mkdir(path.join(this.cacheDir, "db"), { recursive: true });
      await copyFile(dbFile, path.join(this.cacheDir, "db", "trivy.db"));
      await copyFile(metaFile, path.join(this.cacheDir, "db", "metadata.json"));
    } finally {
      await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    }
    const after = await this.dbStatus();
    return {
      outcome: "imported",
      message: `Imported Trivy database built ${after.builtAt?.toISOString() ?? "unknown"}`,
      builtBefore: before.builtAt,
      builtAfter: after.builtAt,
      schemaVersion: after.schemaVersion,
      sourceUrl: archivePath,
    };
  }

  async match(packages: readonly ScannablePackage[]): Promise<MatchResult> {
    const submittedComponentIds = packages.map((p) => p.componentId);
    const status = await this.dbStatus();
    const findings: ParsedFinding[] = [];
    let unmappedFindings = 0;
    let version: string | null = null;
    if (packages.length === 0) {
      return { findings, grypeVersion: null, dbBuiltAt: status.builtAt, unmappedFindings, submittedComponentIds };
    }

    const dir = await mkdtemp(path.join(tmpdir(), "sbom-trivy-"));
    try {
      const documents = buildTrivyDocuments(packages);
      for (const [i, document] of documents.entries()) {
        const file = path.join(dir, `batch-${i}.cdx.json`);
        await writeFile(file, document.json, "utf8");
        const result = await this.run(
          [
            "sbom",
            "--cache-dir",
            this.cacheDir,
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--scanners",
            "vuln",
            "--quiet",
            "--format",
            "json",
            file,
          ],
          this.config.GRYPE_SCAN_TIMEOUT_MS,
        );
        if (result.error) throw result.error;
        if (result.code !== 0) {
          throw new Error(`trivy exited ${result.code} while matching ${document.label} packages: ${lastLine(result.stderr)}`);
        }
        const report = parseTrivyReport(result.stdout, new Set(document.componentIds));
        findings.push(...report.findings);
        unmappedFindings += report.unmappedFindings;
        version ??= report.trivyVersion;
      }
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }

    return { findings, grypeVersion: version, dbBuiltAt: status.builtAt, unmappedFindings, submittedComponentIds };
  }
}
