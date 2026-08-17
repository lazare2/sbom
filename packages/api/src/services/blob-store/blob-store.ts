export interface PutResult {
  key: string;
  /** Bytes actually written (i.e. after compression). */
  storedBytes: number;
  /** True when an object with this key already existed and the write was a no-op. */
  deduplicated: boolean;
}

/**
 * Storage for raw SBOM documents.
 *
 * The parsed relational data is the queryable copy; this holds the original
 * CycloneDX JSON for audit and for re-parsing when the parser improves. Keys are
 * opaque to callers — the layout is the driver's business.
 */
export interface BlobStore {
  readonly name: string;
  put(key: string, data: Buffer): Promise<PutResult>;
  get(key: string): Promise<Buffer>;
  exists(key: string): Promise<boolean>;
  delete(key: string): Promise<void>;
  /** Called at startup so a misconfigured bucket or unwritable path fails loudly. */
  verify(): Promise<void>;
}

/**
 * Content-addressed key for an SBOM, derived from the SHA-256 of the raw upload.
 *
 * Two consequences worth noting:
 *  - Identical SBOMs dedupe for free. A rebuild of unchanged code produces a
 *    byte-identical Syft output, and at thousands of builds a day that is a
 *    large fraction of the raw storage bill avoided.
 *  - Because a blob may therefore be shared by many scans, deleting a scan must
 *    never delete its blob unconditionally. Blob cleanup is a separate
 *    retention sweep keyed on "no scan references this hash".
 *
 * The two nested prefix directories keep any single filesystem directory from
 * holding millions of entries.
 */
export function sbomBlobKey(sha256: string): string {
  return `sbom/${sha256.slice(0, 2)}/${sha256.slice(2, 4)}/${sha256}.json.gz`;
}
