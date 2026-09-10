import { z } from "zod";

/**
 * Which vulnerability database the platform matches against.
 *
 * Two providers, exactly one active. They are not merged and never will be: Grype keys
 * advisories on its own primary id (frequently a GHSA, with CVEs as aliases) while Xray
 * returns JFrog issue ids alongside CVEs, and the same underlying flaw therefore arrives
 * under different identities. A dashboard fed from both would double-count some advisories,
 * miss the overlap between others, and report a total that describes neither database.
 *
 * ## What switching means
 *
 * Every component carries the provider that last assessed it. The sweep's work queue is
 * derived rather than stored — `vuln_scanned_at IS NULL OR vuln_provider <> <active>` — so
 * changing this setting re-queues the whole estate automatically, with nothing to migrate
 * and no findings to wipe. Until a component is re-assessed it reads as *not assessed*,
 * which is the honest state: the old finding was produced by a database that is no longer
 * the authority here.
 */
export const vulnProviders = ["grype", "xray"] as const;
export const vulnProviderSchema = z.enum(vulnProviders);
export type VulnProvider = z.infer<typeof vulnProviderSchema>;

export const VULN_PROVIDER_LABELS: Record<VulnProvider, string> = {
  grype: "Grype (local database)",
  xray: "JFrog Xray (your server)",
};

/**
 * A hostname the platform will make authenticated requests to, and nothing else.
 *
 * Narrow for the same reason the SMTP host is: this value is handed to an HTTP client with a
 * credential attached, so anything that could redirect where that credential goes has to be
 * rejected here rather than interpreted later.
 *
 * ## Why plaintext http is accepted
 *
 * This first refused `http` to anything but loopback, on the reasoning that a bearer token
 * should not cross a network in the clear. That reasoning is sound and the rule was still
 * wrong: Artifactory is very commonly published inside a corporate network on plain port 80,
 * which is exactly the deployment this provider was written for. The rule did not protect
 * that token, because there was no https listener to fall back to — it just made the feature
 * unusable and reported the refusal as "validation failed".
 *
 * So the scheme is accepted and the exposure is *stated*, on the screen where the URL is
 * entered, rather than being decided on the administrator's behalf by a validator that
 * cannot see their network. `xrayUrlIsPlaintext` is what the screen warns from.
 */
export const xrayBaseUrlSchema = z
  .string()
  .trim()
  .min(1)
  .max(500)
  .superRefine((value, ctx) => {
    const fail = (message: string) => ctx.addIssue({ code: z.ZodIssueCode.custom, message });

    let url: URL;
    try {
      url = new URL(value);
    } catch {
      fail('Must be a full URL including http:// or https://, like "https://artifactory.example.org".');
      return;
    }

    if (url.protocol !== "https:" && url.protocol !== "http:") {
      fail(`Must be an http or https URL — "${url.protocol}" is not supported.`);
      return;
    }
    if (url.username || url.password) {
      fail("Enter the URL on its own. Credentials go in the fields below.");
    }
  });

/**
 * Whether this URL sends the API token in the clear.
 *
 * Loopback is excluded because the traffic never reaches a network interface, so there is
 * nothing to intercept and a warning there would be noise that teaches people to ignore the
 * one that matters.
 */
export function xrayUrlIsPlaintext(value: string): boolean {
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "http:") return false;
    return !["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname);
  } catch {
    return false;
  }
}

/**
 * The connection, as an administrator enters it.
 *
 * The token is write-only across the whole API: it is accepted here, encrypted before
 * storage, and never returned by any endpoint. `undefined` on an update means "leave the
 * stored one alone", which is what lets an administrator correct a typo in the URL without
 * having to paste the token again — and is why it is optional rather than defaulted to "".
 */
export const xrayConnectionInputSchema = z.object({
  baseUrl: xrayBaseUrlSchema,
  username: z.string().trim().min(1, "required").max(200),
  token: z.string().trim().min(1).max(4000).optional(),
  /**
   * Skip TLS verification.
   *
   * Present because internal Artifactory instances routinely use a private certificate
   * authority, and the alternative to this checkbox is an administrator who cannot connect
   * at all. Off by default, and the admin screen says plainly what it gives up — a setting
   * that silently disabled verification would be worse than not offering it.
   */
  allowSelfSignedCertificate: z.boolean().default(false),
});
export type XrayConnectionInput = z.infer<typeof xrayConnectionInputSchema>;

/** What the admin screen reads back. Never the token. */
export interface XrayConnection {
  baseUrl: string;
  username: string;
  /** Whether a token is stored. The value itself is never returned. */
  tokenConfigured: boolean;
  allowSelfSignedCertificate: boolean;
}

/**
 * Which package ecosystems this Xray deployment actually assesses.
 *
 * Not a guess, and not a constant. Xray's graph scan is documented for application
 * dependencies, and whether a given deployment also returns findings for operating-system
 * packages depends on its version and configuration. That distinction decides whether a
 * base-image figure of zero is a clean bill of health or a question nobody asked — and on a
 * typical container image the OS packages are two thirds of the component list.
 *
 * So it is measured: the connection test submits one known-vulnerable canary per ecosystem
 * and records which came back. An ecosystem that returns nothing for a package known to be
 * vulnerable is not covered, and everything in it reads as not assessed rather than clean.
 */
export interface XrayCoverage {
  /** Ecosystems whose canary produced findings. */
  covered: string[];
  /** Ecosystems whose canary produced nothing, so results there cannot be trusted. */
  uncovered: string[];
  checkedAt: string;
}

export interface XraySettings {
  connection: XrayConnection | null;
  coverage: XrayCoverage | null;
}

export const updateXrayConnectionSchema = xrayConnectionInputSchema;

/**
 * The result of testing a connection, shaped like the SMTP diagnosis for the same reason:
 * the useful part is not the raw error but which of the handful of things went wrong.
 */
export interface XrayDiagnosis {
  ok: boolean;
  code: string;
  summary: string;
  hint: string | null;
  detail: string | null;
  /** Populated on success — Xray's reported version, proving it is Xray and reachable. */
  version: string | null;
  /** Populated when the probe ran, so an administrator sees coverage before switching. */
  coverage: XrayCoverage | null;
}

export const setVulnProviderSchema = z.object({ provider: vulnProviderSchema });
export type SetVulnProvider = z.infer<typeof setVulnProviderSchema>;

/**
 * Body for the connection test.
 *
 * `connection` is optional: absent means test what is saved. Supplying it lets an
 * administrator try a change before it replaces a working configuration -- without that, the
 * only way to test is to save first, and a failed test has already destroyed the values that
 * worked.
 */
export const testXrayConnectionSchema = z.object({
  connection: xrayConnectionInputSchema.optional(),
});
export type TestXrayConnection = z.infer<typeof testXrayConnectionSchema>;

/** What the admin screen reads back about the active database and its connection. */
export interface VulnProviderSettings {
  provider: VulnProvider;
  xray: XraySettings;
  /** False when SECRETS_KEY is unset, so the screen can say why a token cannot be saved. */
  secretsKeyConfigured: boolean;
}
