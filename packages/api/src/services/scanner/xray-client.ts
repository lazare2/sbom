import { Agent, request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { URL } from "node:url";

/**
 * The HTTP conversation with a JFrog Xray server.
 *
 * Separated from the scanner that uses it so the coordinate mapping, the polling loop and the
 * response translation can each be tested without a network — and so the operational quirks
 * below sit in one place instead of being rediscovered.
 *
 * ## Why the graph scan and not the component summary
 *
 * `POST /xray/api/v1/summary/component` is the obvious endpoint and the wrong one. It answers
 * from the platform's configured Watches and Policies: a component outside any active watch
 * comes back with its licences populated and its vulnerabilities **empty**. Not an error —
 * an empty list, which this platform would faithfully record as "assessed, clean".
 *
 * `POST /xray/api/v1/scan/graph?scan_type=dependency` is what the IDE plugins use. It audits
 * a raw dependency graph against the synchronised database with no policy in the way, which
 * is the question actually being asked here.
 *
 * ## Two things that break against corporate infrastructure
 *
 * Credentials are sent preemptively rather than waiting for a 401 challenge. Behind a proxy
 * the challenge is frequently answered by the proxy instead of the origin, and the request
 * fails in a way that looks like bad credentials.
 *
 * Internal Artifactory instances routinely present a certificate from a private authority.
 * That is a real deployment, not a misconfiguration, so `allowSelfSigned` exists — and it is
 * off by default, surfaced in the admin screen, and never assumed.
 */

export interface XrayCredentials {
  baseUrl: string;
  username: string;
  token: string;
  allowSelfSigned: boolean;
}

export class XrayError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly status: number | null = null,
    readonly detail: string | null = null,
  ) {
    super(message);
    this.name = "XrayError";
  }
}

/** One vulnerability as the graph scan reports it. */
export interface XrayVulnerability {
  issue_id?: string;
  summary?: string;
  severity?: string;
  cves?: Array<{
    cve?: string;
    cvss_v3_score?: number | string;
    cvss_v3_vector?: string;
    cvss_v2_score?: number | string;
  }>;
  /** Keyed by the coordinate that was submitted. */
  components?: Record<
    string,
    { fixed_versions?: string[]; impact_paths?: unknown[]; package_type?: string }
  >;
  references?: string[];
  edited?: string;
}

export interface XrayScanResult {
  status: string;
  vulnerabilities: XrayVulnerability[];
}

const REQUEST_TIMEOUT_MS = 30_000;

/**
 * How long to wait for one graph scan to finish.
 *
 * A dependency scan is asynchronous: the POST registers a job and the result is polled. Five
 * minutes is far longer than a batch of a few hundred coordinates should ever need, and the
 * ceiling exists so a wedged job cannot hold a sweep open indefinitely — the sweep runs on a
 * timer with nothing watching it.
 */
const SCAN_TIMEOUT_MS = 5 * 60_000;
const POLL_INTERVAL_MS = 2_000;

export class XrayClient {
  private readonly agent: Agent | undefined;

  constructor(private readonly credentials: XrayCredentials) {
    this.agent = credentials.allowSelfSigned
      ? new Agent({ rejectUnauthorized: false })
      : undefined;
  }

  private authHeader(): string {
    const raw = `${this.credentials.username}:${this.credentials.token}`;
    return `Basic ${Buffer.from(raw, "utf8").toString("base64")}`;
  }

  /**
   * One request, with the platform's own error vocabulary.
   *
   * Every network-level failure is turned into an `XrayError` carrying a code, because the
   * layer above reports which of a handful of things went wrong rather than a raw message —
   * the same treatment the SMTP client got, for the same reason: "connection refused" and
   * "wrong credentials" send an administrator to completely different places.
   */
  private async send<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = new URL(path, this.credentials.baseUrl.replace(/\/+$/, "") + "/");
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const isHttps = url.protocol === "https:";
    const send = isHttps ? httpsRequest : httpRequest;

    return new Promise<T>((resolve, reject) => {
      const req = send(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname + url.search,
          method,
          timeout: REQUEST_TIMEOUT_MS,
          headers: {
            Authorization: this.authHeader(),
            Accept: "application/json",
            ...(payload
              ? { "Content-Type": "application/json", "Content-Length": String(payload.length) }
              : {}),
          },
          ...(isHttps && this.agent ? { agent: this.agent } : {}),
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            const status = res.statusCode ?? 0;

            if (status === 401 || status === 403) {
              reject(
                new XrayError(
                  "Xray rejected the credentials.",
                  "unauthorized",
                  status,
                  text.slice(0, 400) || null,
                ),
              );
              return;
            }
            if (status === 404) {
              reject(
                new XrayError(
                  "Xray did not recognise that endpoint.",
                  "not_found",
                  status,
                  text.slice(0, 400) || null,
                ),
              );
              return;
            }
            if (status < 200 || status >= 300) {
              reject(
                new XrayError(
                  `Xray answered ${status}.`,
                  "http_error",
                  status,
                  text.slice(0, 400) || null,
                ),
              );
              return;
            }

            if (text.trim() === "") {
              resolve({} as T);
              return;
            }
            try {
              resolve(JSON.parse(text) as T);
            } catch {
              /*
                Almost always a proxy or SSO login page answering with 200 instead of the
                origin. Saying so is worth more than "unexpected token < in JSON".
              */
              reject(
                new XrayError(
                  "Xray returned something that is not JSON.",
                  "not_json",
                  status,
                  text.slice(0, 200),
                ),
              );
            }
          });
        },
      );

      req.on("timeout", () => {
        req.destroy();
        reject(new XrayError(`No answer within ${REQUEST_TIMEOUT_MS / 1000} seconds.`, "timeout"));
      });
      req.on("error", (error: NodeJS.ErrnoException) => {
        reject(new XrayError(error.message, error.code ?? "network_error", null, error.message));
      });

      if (payload) req.write(payload);
      req.end();
    });
  }

  /** Xray's own version, which doubles as proof that the thing answering really is Xray. */
  async version(): Promise<string> {
    const body = await this.send<{ xray_version?: string; version?: string }>(
      "GET",
      "xray/api/v1/system/version",
    );
    const version = body.xray_version ?? body.version;
    if (!version) {
      throw new XrayError(
        "The server answered but did not identify itself as Xray.",
        "not_xray",
        200,
        JSON.stringify(body).slice(0, 200),
      );
    }
    return version;
  }

  /**
   * Submits a set of coordinates and waits for the audit to finish.
   *
   * The root node is a synthetic reference rather than a real artifact: this is an ad-hoc
   * audit of a package list, not a scan of something stored in Artifactory, and giving it the
   * identity of a real artifact would file results against that artifact's history.
   */
  async scanGraph(coordinates: readonly string[], signal?: AbortSignal): Promise<XrayScanResult> {
    if (coordinates.length === 0) return { status: "completed", vulnerabilities: [] };

    const started = await this.send<{ scan_id?: string; info?: string }>(
      "POST",
      "xray/api/v1/scan/graph?scan_type=dependency",
      {
        component_id: "sbom-platform://batch",
        nodes: coordinates.map((component_id) => ({ component_id })),
      },
    );

    const scanId = started.scan_id;
    if (!scanId) {
      throw new XrayError(
        "Xray accepted the scan but returned no scan id.",
        "no_scan_id",
        200,
        started.info ?? null,
      );
    }

    const deadline = Date.now() + SCAN_TIMEOUT_MS;
    for (;;) {
      if (signal?.aborted) throw new XrayError("Scan cancelled.", "cancelled");

      const result = await this.send<XrayScanResult & { info?: string }>(
        "GET",
        `xray/api/v1/scan/graph/${encodeURIComponent(scanId)}?include_vulnerabilities=true`,
      );

      /*
        Xray reports `pending` and `scanning` while it works. Anything else that is not
        `completed` is a state this code does not know how to wait for, and treating an
        unknown state as "keep polling" is how a sweep hangs until the deadline for a job
        that already failed.
      */
      const status = (result.status ?? "").toLowerCase();
      if (status === "completed" || status === "done" || status === "") {
        return { status: "completed", vulnerabilities: result.vulnerabilities ?? [] };
      }
      if (status !== "pending" && status !== "scanning" && status !== "in_progress") {
        throw new XrayError(`Xray reported the scan as "${status}".`, "scan_failed", 200, result.info ?? null);
      }

      if (Date.now() > deadline) {
        throw new XrayError(
          `The scan did not finish within ${SCAN_TIMEOUT_MS / 60_000} minutes.`,
          "scan_timeout",
        );
      }
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
  }
}
