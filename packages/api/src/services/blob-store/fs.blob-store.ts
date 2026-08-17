import { constants } from "node:fs";
import { access, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { gunzip, gzip } from "node:zlib";
import { promisify } from "node:util";
import { randomBytes } from "node:crypto";
import { InternalError, NotFoundError } from "../../lib/errors.js";
import type { BlobStore, PutResult } from "./blob-store.js";

const gzipAsync = promisify(gzip);
const gunzipAsync = promisify(gunzip);

/**
 * Filesystem driver — the default. Point `BLOB_STORE_FS_ROOT` at a volume or an
 * NFS mount and it is production-adequate for an internal tool.
 *
 * Payloads are gzipped before writing. CycloneDX JSON from Syft is extremely
 * repetitive, so compression typically cuts it by 80-90% and the CPU cost is
 * trivial next to the ingest transaction.
 */
export class FilesystemBlobStore implements BlobStore {
  readonly name = "fs";

  constructor(private readonly root: string) {}

  private resolve(key: string): string {
    // Keys are generated internally, but a path-traversal guard is cheap
    // insurance against a future caller passing something derived from input.
    const target = path.resolve(this.root, key);
    const rootResolved = path.resolve(this.root);
    if (target !== rootResolved && !target.startsWith(rootResolved + path.sep)) {
      throw new InternalError(`blob key escapes the store root: ${key}`);
    }
    return target;
  }

  async verify(): Promise<void> {
    await mkdir(this.root, { recursive: true });
    try {
      await access(this.root, constants.W_OK);
    } catch (err) {
      throw new InternalError(`blob store root is not writable: ${path.resolve(this.root)}`, err);
    }
  }

  async put(key: string, data: Buffer): Promise<PutResult> {
    const target = this.resolve(key);

    // Content-addressed, so an existing object with this key has identical
    // bytes. Skip the write rather than rewriting the same content.
    try {
      const existing = await stat(target);
      return { key, storedBytes: existing.size, deduplicated: true };
    } catch {
      // Not present; fall through and write it.
    }

    const compressed = await gzipAsync(data);
    await mkdir(path.dirname(target), { recursive: true });

    // Write to a unique temp name and rename into place. rename(2) is atomic
    // within a filesystem, so a crash mid-write can never leave a truncated
    // blob that later reads as valid-but-corrupt gzip.
    const tmp = `${target}.${randomBytes(6).toString("hex")}.tmp`;
    try {
      await writeFile(tmp, compressed, { flag: "wx" });
      await rename(tmp, target);
    } catch (err) {
      await rm(tmp, { force: true }).catch(() => undefined);
      throw new InternalError(`failed to write SBOM blob ${key}`, err);
    }

    return { key, storedBytes: compressed.length, deduplicated: false };
  }

  async get(key: string): Promise<Buffer> {
    try {
      const compressed = await readFile(this.resolve(key));
      return await gunzipAsync(compressed);
    } catch (err) {
      if (typeof err === "object" && err !== null && (err as { code?: string }).code === "ENOENT") {
        throw new NotFoundError("Raw SBOM");
      }
      throw new InternalError(`failed to read SBOM blob ${key}`, err);
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      await access(this.resolve(key), constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  async delete(key: string): Promise<void> {
    await rm(this.resolve(key), { force: true });
  }
}
