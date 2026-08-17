import type { Config } from "../../config.js";
import type { BlobStore } from "./blob-store.js";
import { FilesystemBlobStore } from "./fs.blob-store.js";
import { S3BlobStore } from "./s3.blob-store.js";

export type { BlobStore, PutResult } from "./blob-store.js";
export { sbomBlobKey } from "./blob-store.js";

/** Selects the blob-store driver from config. The only place a driver is named. */
export function createBlobStore(config: Config): BlobStore {
  switch (config.BLOB_STORE_DRIVER) {
    case "s3":
      return new S3BlobStore({
        bucket: config.BLOB_STORE_S3_BUCKET!,
        region: config.BLOB_STORE_S3_REGION,
        endpoint: config.BLOB_STORE_S3_ENDPOINT,
        accessKeyId: config.BLOB_STORE_S3_ACCESS_KEY_ID,
        secretAccessKey: config.BLOB_STORE_S3_SECRET_ACCESS_KEY,
        forcePathStyle: config.BLOB_STORE_S3_FORCE_PATH_STYLE,
      });
    case "fs":
      return new FilesystemBlobStore(config.BLOB_STORE_FS_ROOT);
  }
}
