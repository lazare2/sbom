import type { FastifyBaseLogger } from "fastify";
import type { Config } from "../../config.js";
import { GrypeScanner } from "./grype.js";
import { XrayScanner } from "./xray.js";
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
 * The scanner the rest of the platform holds, which delegates to whichever provider is
 * currently selected.
 *
 * ## Why this exists rather than a factory call
 *
 * `createScanner(config)` ran once, at startup, and the result was injected into the sweep
 * and the database service. That is correct while the choice is made by an environment
 * variable. It stops being correct the moment an administrator can change the provider from
 * a screen: the process would keep talking to the database it was born with until somebody
 * restarted it, and nothing on the admin panel would say so.
 *
 * Resolving per call keeps every existing call site — fourteen of them — unchanged, and
 * means the switch takes effect on the next question anybody asks.
 *
 * ## What happens when Xray is selected but not usable
 *
 * A missing connection, an unreadable token, a rotated `SECRETS_KEY`. None of those are
 * exceptions to throw: the sweep runs on a timer with nothing to catch it, and an admin
 * page that 500s tells an administrator less than one that says the scanner is unavailable.
 * So the resolver falls back to a scanner that reports itself unavailable with the reason,
 * and the sweep declines to run rather than assessing anything.
 *
 * It deliberately does NOT fall back to Grype. Silently matching against a different
 * database than the one selected would produce findings attributed to the wrong provider,
 * and the estate would look assessed when the thing an administrator chose is not working.
 */
export class ProviderScanner implements VulnerabilityScanner {
  readonly name = "provider";

  constructor(
    private readonly deps: {
      config: Config;
      logger: FastifyBaseLogger;
      /** Reads the active provider and, when it is Xray, the connection to use. */
      resolve: () => Promise<VulnerabilityScanner>;
    },
  ) {}

  private active(): Promise<VulnerabilityScanner> {
    return this.deps.resolve();
  }

  async availability(): Promise<ScannerAvailability> {
    return (await this.active()).availability();
  }

  async dbStatus(): Promise<ScannerDbStatus> {
    return (await this.active()).dbStatus();
  }

  async watermark(): Promise<Date | null> {
    return (await this.active()).watermark();
  }

  async listingUrl(): Promise<string> {
    return (await this.active()).listingUrl();
  }

  async checkReachable(): Promise<ReachabilityResult> {
    return (await this.active()).checkReachable();
  }

  async updateDb(): Promise<DbUpdateResult> {
    return (await this.active()).updateDb();
  }

  async importDb(archivePath: string): Promise<DbUpdateResult> {
    return (await this.active()).importDb(archivePath);
  }

  async match(packages: readonly ScannablePackage[]): Promise<MatchResult> {
    return (await this.active()).match(packages);
  }
}

/**
 * A stand-in for a provider that was chosen but cannot be reached.
 *
 * Every method answers the way an unusable scanner should: unavailable, no database, no
 * watermark. The sweep's own guards then stop it, so nothing is assessed and nothing is
 * stamped — which is what keeps "the connection is broken" from rendering as "the estate is
 * clean".
 */
export class UnavailableScanner implements VulnerabilityScanner {
  readonly name = "unavailable";

  constructor(
    private readonly reason: string,
    private readonly where: string,
  ) {}

  async availability(): Promise<ScannerAvailability> {
    return {
      available: false,
      version: null,
      path: this.where,
      resolvedBy: "settings",
      supportedDbSchema: null,
      attempts: [{ strategy: "settings", location: this.where, reason: this.reason }],
    };
  }

  async dbStatus(): Promise<ScannerDbStatus> {
    return {
      present: false,
      builtAt: null,
      schemaVersion: null,
      valid: false,
      error: this.reason,
      path: this.where,
    };
  }

  /** Null, so the sweep refuses to run rather than assessing against nothing. */
  async watermark(): Promise<Date | null> {
    return null;
  }

  async listingUrl(): Promise<string> {
    return this.where;
  }

  async checkReachable(): Promise<ReachabilityResult> {
    return { reachable: false, url: this.where, message: this.reason };
  }

  async updateDb(): Promise<DbUpdateResult> {
    return {
      outcome: "failed",
      message: this.reason,
      builtBefore: null,
      builtAfter: null,
      schemaVersion: null,
      sourceUrl: null,
    };
  }

  async importDb(): Promise<DbUpdateResult> {
    return this.updateDb();
  }

  /**
   * Submits nothing and reports nothing assessed.
   *
   * Never reached in practice — the sweep stops at `availability` — but a `match` that threw
   * would turn a configuration problem into a crashed background job, and one that returned
   * component ids would mark them assessed by a scanner that does not exist.
   */
  async match(): Promise<MatchResult> {
    return {
      findings: [],
      grypeVersion: null,
      dbBuiltAt: null,
      unmappedFindings: 0,
      submittedComponentIds: [],
    };
  }
}

/**
 * Builds the resolver the delegating scanner calls.
 *
 * Grype is constructed once and reused: it shells out to a binary and holds no per-call
 * state. The Xray scanner is rebuilt each time because its credentials and its assessment
 * epoch both live in settings an administrator can change, and a cached instance would keep
 * using the connection that was configured when the process started.
 */
export function providerResolver(deps: {
  config: Config;
  logger: FastifyBaseLogger;
  settings: {
    vulnProvider(): Promise<"grype" | "xray">;
    xrayCredentials(): Promise<
      { baseUrl: string; username: string; token: string; allowSelfSigned: boolean } | null
    >;
    xrayAssessmentEpoch(): Promise<Date>;
  };
}): () => Promise<VulnerabilityScanner> {
  const grype = new GrypeScanner(deps.config);

  return async () => {
    const provider = await deps.settings.vulnProvider();
    if (provider === "grype") return grype;

    const credentials = await deps.settings.xrayCredentials();
    if (!credentials) {
      return new UnavailableScanner(
        deps.config.SECRETS_KEY
          ? "JFrog Xray is selected but no connection is configured, or the stored API token could not be decrypted. Re-enter it in Administration."
          : "JFrog Xray is selected but SECRETS_KEY is not set on this deployment, so the stored API token cannot be read.",
        "settings",
      );
    }

    return new XrayScanner(credentials, {
      logger: deps.logger,
      assessmentEpoch: await deps.settings.xrayAssessmentEpoch(),
    });
  };
}
