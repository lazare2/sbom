import { mkdir, mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Config } from "../../config.js";
import { OSV_SCANNER_TOOL, resolveToolBinary, type BinaryResolution } from "./grype-binary.js";
import { buildOsvDocument, parseOsvReport } from "./osv-output.js";
import { lastLine, runProcess } from "./process.js";
import type {
  DbUpdateResult,
  MatchResult,
  ReachabilityResult,
  ScannablePackage,
  ScannerAvailability,
  ScannerDbStatus,
  VulnerabilityScanner,
} from "./types.js";

/** Where osv-scanner downloads its offline databases from. Not configurable in osv-scanner. */
export const OSV_DB_SOURCE = "https://osv-vulnerabilities.storage.googleapis.com";

const UNREACHABLE = /dial tcp|no such host|i\/o timeout|connection refused|tls: |x509: |proxyconnect|context deadline exceeded/i;

/**
 * osv-scanner in offline mode: OSV.dev's data, matched locally.
 *
 * OSV publishes one archive per ecosystem (`<ecosystem>/all.zip`). osv-scanner downloads the
 * ones a scan needs into `OSV_DB_DIR/osv-scalibr/<Ecosystem>/all.zip` and re-downloads one
 * only when the published copy has changed. So an update is a scan of one representative
 * package per ecosystem and distribution with downloading switched on, and every sweep after
 * that matches with downloading switched off - nothing the estate contains leaves the
 * network, only the names of the ecosystems in use.
 */
export class OsvScanner implements VulnerabilityScanner {
  readonly name = "osv";
  private resolved: BinaryResolution | null = null;

  constructor(
    private readonly config: Config,
    private readonly deps: {
      caCert: () => Promise<string | null>;
      /** One package per ecosystem and distribution in the estate: what an update downloads for. */
      representativePackages: () => Promise<ScannablePackage[]>;
    },
  ) {}

  private get dbDir(): string {
    return path.resolve(this.config.OSV_DB_DIR);
  }

  private async binary(): Promise<BinaryResolution> {
    if (this.resolved?.binary) return this.resolved;
    this.resolved = await resolveToolBinary(OSV_SCANNER_TOOL, this.config.OSV_SCANNER_PATH);
    return this.resolved;
  }

  private async run(args: string[], timeoutMs: number) {
    const resolution = await this.binary();
    if (!resolution.binary) {
      return { code: -1, stdout: "", stderr: "osv-scanner binary not found", error: new Error("osv-scanner binary not found") };
    }
    const caCert = await this.deps.caCert().catch(() => null);
    return runProcess(resolution.binary.path, args, {
      label: "osv-scanner",
      timeoutMs,
      env: {
        ...process.env,
        OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: this.dbDir,
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
    const result = await this.run(["--version"], 30_000);
    const version = /osv-scanner version:\s*(\S+)/i.exec(result.stdout)?.[1] ?? null;
    if (result.code !== 0 || version === null) {
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
    return {
      available: true,
      version,
      path: resolution.binary.path,
      resolvedBy: resolution.binary.resolvedBy,
      supportedDbSchema: null,
      attempts: resolution.attempts,
    };
  }

  /** The archives on disk, newest first. */
  private async archives(): Promise<Array<{ ecosystem: string; modifiedAt: Date }>> {
    const root = path.join(this.dbDir, "osv-scalibr");
    let names: string[];
    try {
      names = await readdir(root);
    } catch {
      return [];
    }
    const out: Array<{ ecosystem: string; modifiedAt: Date }> = [];
    for (const ecosystem of names) {
      try {
        const info = await stat(path.join(root, ecosystem, "all.zip"));
        out.push({ ecosystem, modifiedAt: info.mtime });
      } catch {
        // A directory without its archive is a download that never finished.
      }
    }
    return out.sort((a, b) => b.modifiedAt.getTime() - a.modifiedAt.getTime());
  }

  /**
   * Dated by the newest archive's modification time. osv-scanner rewrites an archive only
   * when the published one has changed, so this moves exactly when the data does.
   */
  async dbStatus(): Promise<ScannerDbStatus> {
    const archives = await this.archives();
    const newest = archives[0];
    return {
      present: newest !== undefined,
      builtAt: newest?.modifiedAt ?? null,
      schemaVersion: archives.length > 0 ? `${archives.length} ecosystems` : null,
      valid: newest !== undefined,
      error: newest ? null : "No OSV database has been downloaded yet.",
      path: path.join(this.dbDir, "osv-scalibr"),
    };
  }

  async watermark(): Promise<Date | null> {
    return (await this.dbStatus()).builtAt;
  }

  async listingUrl(): Promise<string> {
    return OSV_DB_SOURCE;
  }

  async checkReachable(): Promise<ReachabilityResult> {
    const url = `${OSV_DB_SOURCE}/ecosystems.txt`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.GRYPE_REACHABILITY_TIMEOUT_MS);
    timer.unref();
    try {
      const response = await fetch(url, { signal: controller.signal });
      await response.arrayBuffer().catch(() => undefined);
      return response.ok
        ? { reachable: true, url, message: null }
        : { reachable: false, url, message: `${url} responded with HTTP ${response.status}` };
    } catch (err) {
      return { reachable: false, url, message: `No connection to ${url} (${err instanceof Error ? err.message : String(err)})` };
    } finally {
      clearTimeout(timer);
    }
  }

  async updateDb(): Promise<DbUpdateResult> {
    const before = await this.dbStatus();
    const packages = await this.deps.representativePackages();
    // Skipped distributions are not downloaded either: that is most of what skipping saves.
    const document = buildOsvDocument(packages, this.config.OSV_SKIP_DISTROS);
    if (document.byPurl.size === 0) {
      return {
        outcome: "already-current",
        message: "No package in the estate is in an ecosystem OSV covers, so there is nothing to download yet.",
        builtBefore: before.builtAt,
        builtAfter: before.builtAt,
        schemaVersion: before.schemaVersion,
        sourceUrl: OSV_DB_SOURCE,
      };
    }

    await mkdir(this.dbDir, { recursive: true });
    const dir = await mkdtemp(path.join(tmpdir(), "sbom-osv-update-"));
    let result;
    try {
      // The name matters: osv-scanner recognises a CycloneDX file by its `.cdx.json` suffix.
      const file = path.join(dir, "ecosystems.cdx.json");
      await writeFile(file, document.json, "utf8");
      result = await this.run(
        ["scan", "source", "--offline-vulnerabilities", "--download-offline-databases", "--format", "json", "-L", file],
        this.config.GRYPE_DB_UPDATE_TIMEOUT_MS,
      );
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
    const after = await this.dbStatus();

    // Exit 1 means "vulnerabilities found", which an update scan routinely does; 128, that it
    // read no packages, which is not a download failure either.
    if (result.error || (result.code !== 0 && result.code !== 1 && result.code !== 128)) {
      const detail = (result.error?.message ?? lastLine(result.stderr)) || `exit ${result.code}`;
      return {
        outcome: UNREACHABLE.test(result.stderr) ? "unreachable" : "failed",
        message: `osv-scanner could not download its databases from ${OSV_DB_SOURCE}: ${detail}`,
        builtBefore: before.builtAt,
        builtAfter: after.builtAt,
        schemaVersion: after.schemaVersion,
        sourceUrl: OSV_DB_SOURCE,
      };
    }
    const changed = after.builtAt !== null && after.builtAt.getTime() !== before.builtAt?.getTime();
    return {
      outcome: changed ? "updated" : "already-current",
      message: changed
        ? `Downloaded OSV databases for ${after.schemaVersion ?? "the estate's ecosystems"}`
        : "The OSV databases are already current",
      builtBefore: before.builtAt,
      builtAfter: after.builtAt,
      schemaVersion: after.schemaVersion,
      sourceUrl: OSV_DB_SOURCE,
    };
  }

  async importDb(archivePath: string): Promise<DbUpdateResult> {
    const status = await this.dbStatus();
    return {
      outcome: "failed",
      message: `OSV databases are downloaded per ecosystem from ${OSV_DB_SOURCE} and cannot be imported from one archive.`,
      builtBefore: status.builtAt,
      builtAfter: status.builtAt,
      schemaVersion: status.schemaVersion,
      sourceUrl: archivePath,
    };
  }

  async match(packages: readonly ScannablePackage[]): Promise<MatchResult> {
    const submittedComponentIds = packages.map((p) => p.componentId);
    const status = await this.dbStatus();
    const document = buildOsvDocument(packages, this.config.OSV_SKIP_DISTROS);
    if (document.byPurl.size === 0) {
      return { findings: [], grypeVersion: null, dbBuiltAt: status.builtAt, unmappedFindings: 0, submittedComponentIds };
    }

    const dir = await mkdtemp(path.join(tmpdir(), "sbom-osv-"));
    try {
      const file = path.join(dir, "batch.cdx.json");
      await writeFile(file, document.json, "utf8");
      const result = await this.run(
        ["scan", "source", "--offline-vulnerabilities", "--format", "json", "-L", file],
        this.config.GRYPE_SCAN_TIMEOUT_MS,
      );
      if (result.error) throw result.error;
      // 0: nothing found, 1: vulnerabilities found, 128: no package it could read.
      if (result.code === 128) {
        return { findings: [], grypeVersion: null, dbBuiltAt: status.builtAt, unmappedFindings: 0, submittedComponentIds };
      }
      if (result.code !== 0 && result.code !== 1) {
        throw new Error(`osv-scanner exited ${result.code} while matching ${packages.length} packages: ${lastLine(result.stderr)}`);
      }
      const report = parseOsvReport(result.stdout, document.byPurl);
      return {
        findings: report.findings,
        grypeVersion: null,
        dbBuiltAt: status.builtAt,
        unmappedFindings: report.unmappedFindings,
        submittedComponentIds,
      };
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}
