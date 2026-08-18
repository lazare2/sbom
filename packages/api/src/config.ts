import { z } from "zod";

/**
 * All environment access happens here, validated once at boot. A missing or
 * malformed variable must fail startup loudly rather than surface as a runtime
 * error on the first password reset three weeks later.
 */

const booleanish = z
  .enum(["true", "false", "1", "0", ""])
  .transform((v) => v === "true" || v === "1")
  .optional();

/** `name:token,name2:token2` -> a map. Tokens with no name get a positional one. */
const ingestTokensSchema = z
  .string()
  .default("")
  .transform((raw) =>
    raw
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
      .map((entry, i) => {
        const sep = entry.indexOf(":");
        if (sep === -1) return { name: `env-${i + 1}`, token: entry };
        return { name: entry.slice(0, sep).trim() || `env-${i + 1}`, token: entry.slice(sep + 1).trim() };
      })
      .filter((t) => t.token.length > 0),
  );

const envSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
    API_PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    API_HOST: z.string().default("0.0.0.0"),
    PUBLIC_URL: z.string().url().default("http://localhost:5173"),

    DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
    DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(100).default(10),

    SESSION_SECRET: z.string().min(32, "SESSION_SECRET must be at least 32 characters"),
    SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(24 * 90).default(72),
    SESSION_COOKIE_NAME: z.string().min(1).default("sbom_session"),

    INGEST_TOKENS: ingestTokensSchema,
    INGEST_MAX_SBOM_BYTES: z.coerce
      .number()
      .int()
      .min(1024)
      .default(64 * 1024 * 1024),

    BLOB_STORE_DRIVER: z.enum(["fs", "s3"]).default("fs"),
    BLOB_STORE_FS_ROOT: z.string().default("./var/sboms"),
    BLOB_RETENTION_DAYS: z.coerce.number().int().min(0).default(0),
    BLOB_STORE_S3_ENDPOINT: z.string().url().optional(),
    BLOB_STORE_S3_REGION: z.string().optional(),
    BLOB_STORE_S3_BUCKET: z.string().optional(),
    BLOB_STORE_S3_ACCESS_KEY_ID: z.string().optional(),
    BLOB_STORE_S3_SECRET_ACCESS_KEY: z.string().optional(),
    BLOB_STORE_S3_FORCE_PATH_STYLE: booleanish,

    /*
     * There is no mail configuration.
     *
     * User "emails" are login identifiers, not mailboxes, so the platform never
     * sends anything: no invites, no password-reset links, no notifications.
     * Password recovery is an admin issuing a credential through the admin
     * panel. Anything that needs an SMTP server has been removed rather than
     * left configurable-but-broken.
     */

    AUTH_PROVIDERS: z
      .string()
      .default("local")
      .transform((v) =>
        v
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      ),

    /** Identifier, not an address — see `emailSchema` in @sbom/shared. */
    BOOTSTRAP_ADMIN_EMAIL: z
      .string()
      .trim()
      .toLowerCase()
      .min(3)
      .regex(/^\S+$/u, "must not contain spaces")
      .optional()
      .or(z.literal("").transform(() => undefined)),
    BOOTSTRAP_ADMIN_PASSWORD: z.string().optional(),

    STALE_APP_THRESHOLD_DAYS: z.coerce.number().int().min(1).default(30),

    /*
     * Vulnerability scanning (Grype).
     *
     * Whether scanning is *on* is not here — it is an admin-controlled row in the
     * `setting` table, because it is a runtime decision an administrator makes from
     * the UI. What lives here is everything the deployment operator owns: where the
     * binary is, where the database goes, and what it may talk to.
     *
     * The split matters. `GRYPE_PATH` decides which executable the server runs, so
     * it stays in the environment where changing it needs deployment access rather
     * than an admin session. A web form that sets an arbitrary executable path is a
     * remote-code-execution primitive, and this platform is meant to be published.
     */

    /**
     * Explicit path to the grype binary. Highest-priority resolution rule.
     *
     * Normally unset: the container image ships grype at a known location, and a
     * development machine usually has it on PATH. This exists for air-gapped or
     * distro-packaged installs where it is somewhere else entirely.
     */
    GRYPE_PATH: z.string().trim().optional().or(z.literal("").transform(() => undefined)),

    /**
     * Where the ~1.9 GB vulnerability database is stored.
     *
     * Must be a mounted volume in a container deployment, or every restart throws
     * away a 141 MB download.
     */
    GRYPE_DB_CACHE_DIR: z.string().default("./var/grype-db"),

    /**
     * Base URL for the database listing and archives.
     *
     * Points at Anchore by default; set it to an internal mirror to keep database
     * traffic inside the network. Grype appends `/v<schema>/latest.json` to find the
     * current build.
     */
    GRYPE_DB_UPDATE_URL: z.string().url().default("https://grype.anchore.io/databases"),

    /**
     * CA certificate for a mirror behind a TLS-inspecting proxy or a private CA.
     *
     * Usually unnecessary: leave it unset and drop the certificate into GRYPE_DB_CA_DIR
     * instead, which is discovered automatically. Set this only to name one exact file.
     */
    GRYPE_DB_CA_CERT: z.string().trim().optional().or(z.literal("").transform(() => undefined)),

    /**
     * Directory scanned for CA certificates when GRYPE_DB_CA_CERT is not set.
     *
     * Exists so installing a corporate CA is "drop the file in the folder" rather than
     * "drop the file in the folder AND name it in an env file AND get the in-container path
     * right". Every one of those steps was a place to get it wrong, and each failure looks
     * identical from the UI: a TLS error that says nothing about which step was missed.
     *
     * Several certificates are concatenated into one bundle rather than one being chosen,
     * because a corporate trust store commonly holds a handful with near-identical names and
     * picking between them is guesswork the machine can avoid. Go accepts a bundle and tries
     * all of them.
     */
    GRYPE_DB_CA_DIR: z.string().trim().default("/certs"),

    /**
     * Components per grype invocation.
     *
     * Measured: 50,000 components in one pass takes ~101s and emits ~90 MB of JSON.
     * Batching keeps peak memory bounded, gives the sweep frequent resume points,
     * and makes progress visible while a large estate catches up. 5,000 lands at
     * roughly 10s and 9 MB per batch.
     */
    GRYPE_BATCH_SIZE: z.coerce.number().int().min(100).max(50_000).default(5_000),

    /** Per-invocation match timeout. A batch that hangs must not stall the sweep forever. */
    GRYPE_SCAN_TIMEOUT_MS: z.coerce.number().int().min(10_000).default(10 * 60 * 1000),

    /** Database download timeout — 141 MB, which on a slow link genuinely takes a while. */
    GRYPE_DB_UPDATE_TIMEOUT_MS: z.coerce.number().int().min(10_000).default(30 * 60 * 1000),

    /** Reachability probe timeout. Short: this only answers "is there a route at all". */
    GRYPE_REACHABILITY_TIMEOUT_MS: z.coerce.number().int().min(500).default(8_000),

    /**
     * Upload ceiling for a hand-uploaded database archive.
     *
     * Deliberately separate from INGEST_MAX_SBOM_BYTES. These differ by more than an
     * order of magnitude — an SBOM is a JSON document, this is a compressed database
     * currently around 145 MB and growing with every year of published advisories — and
     * sharing one limit means the air-gapped install path breaks the moment someone
     * tightens the ingest limit, in the one deployment that has no other way to get a
     * database. 1 GiB leaves years of upstream growth.
     */
    GRYPE_DB_MAX_UPLOAD_BYTES: z.coerce
      .number()
      .int()
      .min(1024 * 1024)
      .default(1024 * 1024 * 1024),

    /** Comma-separated extra origins allowed to send credentialed requests. */
    CORS_ORIGINS: z
      .string()
      .default("")
      .transform((v) =>
        v
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      ),
  })
  .superRefine((env, ctx) => {
    if (env.BLOB_STORE_DRIVER === "s3" && !env.BLOB_STORE_S3_BUCKET) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["BLOB_STORE_S3_BUCKET"],
        message: "required when BLOB_STORE_DRIVER=s3",
      });
    }
    // A production deployment with the example secret is a real hazard: it would
    // let anyone who has read the repo forge a session cookie.
    if (env.NODE_ENV === "production" && env.SESSION_SECRET.startsWith("change-me")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["SESSION_SECRET"],
        message: "must not use the example value in production",
      });
    }
    const unsupported = env.AUTH_PROVIDERS.filter((p) => p !== "local");
    if (unsupported.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["AUTH_PROVIDERS"],
        message: `only "local" is implemented in this phase; got: ${unsupported.join(", ")}`,
      });
    }
  });

export type Config = z.infer<typeof envSchema> & {
  isProduction: boolean;
  isTest: boolean;
  /** Session cookies get the Secure flag whenever the public URL is https. */
  cookieSecure: boolean;
};

let cached: Config | undefined;

export function loadConfig(source: NodeJS.ProcessEnv = process.env): Config {
  const parsed = envSchema.safeParse(source);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`);
    throw new Error(`Invalid environment configuration:\n${lines.join("\n")}`);
  }
  const env = parsed.data;
  return {
    ...env,
    isProduction: env.NODE_ENV === "production",
    isTest: env.NODE_ENV === "test",
    cookieSecure: env.PUBLIC_URL.startsWith("https://"),
  };
}

/** Process-wide config, loaded on first access. */
export function getConfig(): Config {
  cached ??= loadConfig();
  return cached;
}

/** Test helper: drops the memoised config so a new env can be loaded. */
export function resetConfigCache(): void {
  cached = undefined;
}
