import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { sbomBlobKey } from "../../src/services/blob-store/blob-store.js";
import { FilesystemBlobStore } from "../../src/services/blob-store/fs.blob-store.js";
import { sha256Hex } from "../../src/lib/crypto.js";
import { AppError } from "../../src/lib/errors.js";

describe("sbomBlobKey", () => {
  it("shards by the first two byte-pairs of the hash", () => {
    const hash = "ab12cd34" + "e".repeat(56);
    expect(sbomBlobKey(hash)).toBe(`sbom/ab/12/${hash}.json.gz`);
  });

  it("is deterministic, which is what makes identical SBOMs dedupe", () => {
    const hash = sha256Hex("some sbom content");
    expect(sbomBlobKey(hash)).toBe(sbomBlobKey(hash));
  });
});

describe("FilesystemBlobStore", () => {
  let root: string;
  let store: FilesystemBlobStore;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), "sbom-blob-test-"));
    store = new FilesystemBlobStore(root);
    await store.verify();
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("round-trips a payload through gzip", async () => {
    const payload = Buffer.from(JSON.stringify({ bomFormat: "CycloneDX", components: [] }));
    const key = sbomBlobKey(sha256Hex(payload));

    const put = await store.put(key, payload);
    expect(put.deduplicated).toBe(false);
    expect(put.storedBytes).toBeGreaterThan(0);

    const read = await store.get(key);
    expect(read.toString()).toBe(payload.toString());
  });

  it("stores the object gzipped on disk, not as raw JSON", async () => {
    const payload = Buffer.from("x".repeat(4096));
    const key = sbomBlobKey(sha256Hex(payload));
    await store.put(key, payload);

    const onDisk = await readFile(path.join(root, key));
    // gzip magic bytes.
    expect(onDisk[0]).toBe(0x1f);
    expect(onDisk[1]).toBe(0x8b);
    expect(gunzipSync(onDisk).toString()).toBe(payload.toString());
    // Highly repetitive content, so compression should be dramatic.
    expect(onDisk.length).toBeLessThan(payload.length / 2);
  });

  it("skips the write when the content-addressed key already exists", async () => {
    const payload = Buffer.from("identical rebuild output");
    const key = sbomBlobKey(sha256Hex(payload));

    await store.put(key, payload);
    const second = await store.put(key, payload);

    // This is the property that keeps unchanged rebuilds from doubling storage.
    expect(second.deduplicated).toBe(true);
  });

  it("reports existence accurately", async () => {
    const payload = Buffer.from("present");
    const key = sbomBlobKey(sha256Hex(payload));

    expect(await store.exists(key)).toBe(false);
    await store.put(key, payload);
    expect(await store.exists(key)).toBe(true);
  });

  it("throws a 404-shaped error for a missing blob", async () => {
    try {
      await store.get(sbomBlobKey("0".repeat(64)));
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AppError);
      expect((err as AppError).statusCode).toBe(404);
    }
  });

  it("makes delete idempotent", async () => {
    const key = sbomBlobKey("1".repeat(64));
    await expect(store.delete(key)).resolves.toBeUndefined();
  });

  it("refuses a key that would escape the store root", async () => {
    await expect(store.put("../../escaped.json.gz", Buffer.from("x"))).rejects.toThrowError(
      /escapes the store root/,
    );
  });

  it("leaves no temp files behind after a successful write", async () => {
    const payload = Buffer.from("clean");
    const key = sbomBlobKey(sha256Hex(payload));
    await store.put(key, payload);

    const { readdir } = await import("node:fs/promises");
    const dir = path.join(root, path.dirname(key));
    const entries = await readdir(dir);
    expect(entries.filter((e) => e.endsWith(".tmp"))).toHaveLength(0);
    expect(entries).toHaveLength(1);
  });
});
