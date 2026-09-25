import { describe, expect, it } from "vitest";
import { unavailableMessage } from "../../src/modules/vulnerabilities/sweep.service.js";
import type { ScannerAvailability } from "../../src/services/scanner/types.js";

/**
 * What the sweep says when it declines to run.
 *
 * This message is the entire diagnosis. The sweep does not throw and does not retry loudly;
 * it returns `unavailable` and the admin panel prints this string, so whatever it names is
 * where an administrator will go looking.
 *
 * The failure worth guarding against is a message that is merely *stale*: reporting a
 * missing grype binary on a deployment that has no binary and no filesystem to check sends
 * the reader somewhere there is nothing to find, while the real cause -- an unreachable
 * server -- goes unmentioned.
 */

const availability = (over: Partial<ScannerAvailability> = {}): ScannerAvailability => ({
  available: false,
  version: null,
  path: null,
  resolvedBy: null,
  supportedDbSchema: null,
  attempts: [],
  ...over,
});

describe("explaining why the sweep cannot run", () => {
  it("names Xray and its URL, not a binary, when Xray is the active provider", () => {
    const message = unavailableMessage(
      "xray",
      availability({ path: "http://repository.example.com" }),
    );

    expect(message).toContain("JFrog Xray");
    expect(message).toContain("http://repository.example.com");
    // The specific regression: a deployment with no grype binary at all was told to look
    // for one.
    expect(message).not.toContain("grype");
  });

  it("still names the binary under grype", () => {
    expect(unavailableMessage("grype", availability())).toContain("grype binary");
  });

  it("carries the reason the availability check recorded", () => {
    const message = unavailableMessage(
      "xray",
      availability({
        path: "http://repository.example.com",
        attempts: [
          {
            strategy: "settings",
            location: "http://repository.example.com",
            reason: "connect ETIMEDOUT 10.0.0.5:80",
          },
        ],
      }),
    );

    // Without this the administrator learns that something is unreachable but not whether
    // it was refused, timed out, or rejected the credential — three different next steps.
    expect(message).toContain("connect ETIMEDOUT 10.0.0.5:80");
  });

  it("reads as a complete sentence when no reason was recorded", () => {
    // An empty `attempts` is legitimate, and the message must not end up with a dangling
    // separator or a trailing space.
    const message = unavailableMessage("xray", availability({ path: "http://x.example" }));
    expect(message).toBe("JFrog Xray at http://x.example could not be reached.");
  });
});
