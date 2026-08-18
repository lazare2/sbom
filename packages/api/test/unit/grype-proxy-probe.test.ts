import { afterEach, describe, expect, it, vi } from "vitest";
import { GrypeScanner } from "../../src/services/scanner/grype.js";
import type { Config } from "../../src/config.js";

/**
 * The reachability probe has to predict what the download will do.
 *
 * It could not, and the failure was invisible in every test that mattered: Node's fetch
 * ignores HTTP_PROXY and HTTPS_PROXY (built-in support landed in Node 24 behind
 * NODE_USE_ENV_PROXY; the runtime image is Node 22), while grype is a Go binary that
 * honours them. On a proxied network the probe therefore failed, the update was refused
 * with "no internet connection", and the downloader that would have succeeded never ran.
 * Correct proxy configuration could not fix it, which is the part that cost real time.
 *
 * These tests pin the asymmetry shut from both sides. They assert on which client is used
 * rather than on any message, because the bug was never about wording.
 */

const PROXY_KEYS = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] as const;

function config(): Config {
  return {
    GRYPE_DB_UPDATE_URL: "https://grype.example.test/databases",
    GRYPE_REACHABILITY_TIMEOUT_MS: 1000,
    GRYPE_DB_CACHE_DIR: "/tmp/grype-db",
    GRYPE_PATH: "/nonexistent/grype",
  } as unknown as Config;
}

/** Runs `fn` with exactly the given proxy environment, restoring whatever was there. */
async function withProxyEnv(value: string | null, fn: () => Promise<void>): Promise<void> {
  const saved = new Map<string, string | undefined>();
  for (const k of PROXY_KEYS) {
    saved.set(k, process.env[k]);
    delete process.env[k];
  }
  if (value !== null) process.env.HTTPS_PROXY = value;
  try {
    await fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

afterEach(() => vi.restoreAllMocks());

describe("reachability probe and proxies", () => {
  it("uses a direct fetch when no proxy is configured", async () => {
    await withProxyEnv(null, async () => {
      const scanner = new GrypeScanner(config());
      const fetchSpy = vi
        .spyOn(globalThis, "fetch")
        .mockResolvedValue(new Response("{}", { status: 200 }));
      const runSpy = vi.spyOn(scanner as never, "run" as never);

      const result = await scanner.checkReachable();

      expect(fetchSpy).toHaveBeenCalledOnce();
      /*
        Not "run was never called": resolving the listing URL asks grype for its schema
        version, so it legitimately runs. The claim is narrower and is the one that
        matters -- the probe itself was the fetch, not `db check`.
      */
      const probeCalls = runSpy.mock.calls.filter(
        ([args]) => Array.isArray(args) && args[0] === "db" && args[1] === "check",
      );
      expect(probeCalls).toHaveLength(0);
      expect(result.reachable).toBe(true);
    });
  });

  it("probes through grype instead of fetch when a proxy is configured", async () => {
    await withProxyEnv("http://proxy.example.test:8080", async () => {
      const scanner = new GrypeScanner(config());
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      const runSpy = vi
        .spyOn(scanner as never, "run" as never)
        // 100 is grype's "an update is available", which means the listing was reached.
        .mockResolvedValue({ code: 100, stdout: "", stderr: "", error: null } as never);

      const result = await scanner.checkReachable();

      // The whole point: fetch cannot see through the proxy, so it must not decide this.
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(runSpy).toHaveBeenCalledWith(["db", "check"], expect.anything());
      expect(result.reachable).toBe(true);
    });
  });

  it("treats grype's already-current exit code as reachable", async () => {
    await withProxyEnv("http://proxy.example.test:8080", async () => {
      const scanner = new GrypeScanner(config());
      vi.spyOn(scanner as never, "run" as never).mockResolvedValue({
        code: 0,
        stdout: "",
        stderr: "",
        error: null,
      } as never);

      // 0 and 100 differ only in whether an update exists; both reached the listing, and
      // reading 100 as a failure would refuse updates on exactly the machines that need one.
      expect((await scanner.checkReachable()).reachable).toBe(true);
    });
  });

  it("reports unreachable with grype's own message when the proxy cannot connect", async () => {
    await withProxyEnv("http://proxy.example.test:8080", async () => {
      const scanner = new GrypeScanner(config());
      vi.spyOn(scanner as never, "run" as never).mockResolvedValue({
        code: 1,
        stdout: "",
        stderr: "unable to download listing: dial tcp: i/o timeout",
        error: null,
      } as never);

      const result = await scanner.checkReachable();

      expect(result.reachable).toBe(false);
      // Naming the proxy matters: the next question is always "which proxy did it try".
      expect(result.message).toContain("proxy.example.test:8080");
      expect(result.message).toContain("i/o timeout");
    });
  });
});
