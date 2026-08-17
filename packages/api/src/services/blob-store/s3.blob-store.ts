import { gunzip, gzip } from "node:zlib";
import { promisify } from "node:util";
import { InternalError, NotFoundError } from "../../lib/errors.js";
import type { BlobStore, PutResult } from "./blob-store.js";

const gzipAsync = promisify(gzip);
const gunzipAsync = promisify(gunzip);

export interface S3BlobStoreOptions {
  bucket: string;
  region?: string | undefined;
  endpoint?: string | undefined;
  accessKeyId?: string | undefined;
  secretAccessKey?: string | undefined;
  forcePathStyle?: boolean | undefined;
}

/**
 * S3-compatible driver (AWS S3, MinIO, Ceph RGW).
 *
 * `@aws-sdk/client-s3` is an *optional* dependency, imported lazily on first
 * use. Most internal deployments will run the filesystem driver, and there is no
 * reason to make every one of them install ~15 MB of AWS SDK to do it. If this
 * driver is selected without the package present, startup fails with an
 * actionable message rather than a module-not-found stack trace on the first
 * scan upload.
 */
export class S3BlobStore implements BlobStore {
  readonly name = "s3";

  // Typed as unknown-ish because the SDK types are not available unless the
  // optional dependency is installed.
  private client: {
    send(command: unknown): Promise<unknown>;
  } | null = null;
  private commands: {
    PutObjectCommand: new (input: unknown) => unknown;
    GetObjectCommand: new (input: unknown) => unknown;
    HeadObjectCommand: new (input: unknown) => unknown;
    DeleteObjectCommand: new (input: unknown) => unknown;
  } | null = null;

  constructor(private readonly options: S3BlobStoreOptions) {}

  private async ensureClient(): Promise<void> {
    if (this.client) return;

    let sdk: Record<string, unknown>;
    try {
      // Specifier held in a variable on purpose: it keeps TypeScript from
      // resolving the module at compile time, so the package stays genuinely
      // optional rather than a build-time requirement for every deployment.
      const specifier = "@aws-sdk/client-s3";
      sdk = (await import(specifier)) as unknown as Record<string, unknown>;
    } catch (err) {
      throw new InternalError(
        "BLOB_STORE_DRIVER=s3 requires the optional dependency @aws-sdk/client-s3. " +
          "Install it with `npm install @aws-sdk/client-s3 -w @sbom/api`, or set " +
          "BLOB_STORE_DRIVER=fs to use the filesystem driver.",
        err,
      );
    }

    const S3Client = sdk.S3Client as new (cfg: unknown) => { send(c: unknown): Promise<unknown> };
    this.client = new S3Client({
      ...(this.options.region ? { region: this.options.region } : {}),
      ...(this.options.endpoint ? { endpoint: this.options.endpoint } : {}),
      ...(this.options.forcePathStyle ? { forcePathStyle: true } : {}),
      // Omitted entirely when not configured, so the SDK falls back to the
      // standard credential chain (instance role, env, shared config).
      ...(this.options.accessKeyId && this.options.secretAccessKey
        ? {
            credentials: {
              accessKeyId: this.options.accessKeyId,
              secretAccessKey: this.options.secretAccessKey,
            },
          }
        : {}),
    });
    this.commands = {
      PutObjectCommand: sdk.PutObjectCommand as new (i: unknown) => unknown,
      GetObjectCommand: sdk.GetObjectCommand as new (i: unknown) => unknown,
      HeadObjectCommand: sdk.HeadObjectCommand as new (i: unknown) => unknown,
      DeleteObjectCommand: sdk.DeleteObjectCommand as new (i: unknown) => unknown,
    };
  }

  async verify(): Promise<void> {
    await this.ensureClient();
    try {
      // A HEAD on a key that will not exist still proves credentials, region,
      // and bucket reachability; a 404 is a successful round trip.
      await this.exists("sbom/.verify-probe");
    } catch (err) {
      throw new InternalError(`S3 blob store is not reachable (bucket: ${this.options.bucket})`, err);
    }
  }

  async put(key: string, data: Buffer): Promise<PutResult> {
    await this.ensureClient();
    const compressed = await gzipAsync(data);

    // Content-addressed keys mean an existing object is byte-identical.
    if (await this.exists(key)) {
      return { key, storedBytes: compressed.length, deduplicated: true };
    }

    await this.client!.send(
      new this.commands!.PutObjectCommand({
        Bucket: this.options.bucket,
        Key: key,
        Body: compressed,
        ContentType: "application/json",
        ContentEncoding: "gzip",
      }),
    );
    return { key, storedBytes: compressed.length, deduplicated: false };
  }

  async get(key: string): Promise<Buffer> {
    await this.ensureClient();
    try {
      const result = (await this.client!.send(
        new this.commands!.GetObjectCommand({ Bucket: this.options.bucket, Key: key }),
      )) as { Body?: { transformToByteArray(): Promise<Uint8Array> } };

      if (!result.Body) throw new NotFoundError("Raw SBOM");
      const bytes = await result.Body.transformToByteArray();
      return await gunzipAsync(Buffer.from(bytes));
    } catch (err) {
      if (isNotFound(err)) throw new NotFoundError("Raw SBOM");
      throw new InternalError(`failed to read SBOM blob ${key}`, err);
    }
  }

  async exists(key: string): Promise<boolean> {
    await this.ensureClient();
    try {
      await this.client!.send(
        new this.commands!.HeadObjectCommand({ Bucket: this.options.bucket, Key: key }),
      );
      return true;
    } catch (err) {
      if (isNotFound(err)) return false;
      throw err;
    }
  }

  async delete(key: string): Promise<void> {
    await this.ensureClient();
    await this.client!.send(
      new this.commands!.DeleteObjectCommand({ Bucket: this.options.bucket, Key: key }),
    );
  }
}

function isNotFound(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const e = err as { name?: string; $metadata?: { httpStatusCode?: number } };
  return e.name === "NotFound" || e.name === "NoSuchKey" || e.$metadata?.httpStatusCode === 404;
}
