import { describe, expect, it } from "vitest";
import type { SmtpConnection } from "@sbom/shared";
import { diagnose } from "../../src/modules/reports/mailer.js";

/**
 * Turning a mail failure into something an administrator can act on.
 *
 * The failure this protects against is not a crash — it is a confident wrong answer. Every
 * way SMTP fails arrives as an `Error` with a short code, and the first two versions of this
 * mapping both read those codes at face value and were wrong:
 *
 *   - `ENOTFOUND` was matched against `error.code`, which nodemailer never sets to that. An
 *     unresolvable host fell through to "could not reach the server", so the one message that
 *     names the actual problem — a typo in the host — was the one nobody saw.
 *   - `ESOCKET` was mapped to "encryption mismatch". It is nodemailer's catch-all for socket
 *     trouble, so a closed port was reported as a TLS problem, sending the reader to change a
 *     dropdown that was already correct.
 *
 * The second is worse than no diagnosis at all, and neither showed up in a type check or in a
 * test that only asserted "an error is returned". So the shapes below are not invented: they
 * were captured from nodemailer against a real socket, and they are what the mapping has to
 * keep reading correctly.
 */

const CONNECTION: SmtpConnection = {
  smtpHost: "mail.corp.local",
  smtpPort: 25,
  smtpEncryption: "none",
  smtpFrom: "sbom@corp.local",
};

/** Exactly what nodemailer produced for each case, fields and all. */
const MEASURED = {
  unresolvableHost: {
    code: "EDNS",
    errno: -3008,
    syscall: "getaddrinfo",
    command: "CONN",
    message: "getaddrinfo ENOTFOUND mail.corp.local",
  },
  closedPort: {
    code: "ESOCKET",
    errno: -4078,
    syscall: "connect",
    command: "CONN",
    message: "connect ECONNREFUSED 127.0.0.1:2525",
  },
} as const;

describe("diagnosing an SMTP failure", () => {
  it("reads a DNS failure from the syscall, not from a code nodemailer never sets", () => {
    const result = diagnose(MEASURED.unresolvableHost, CONNECTION);

    expect(result.ok).toBe(false);
    expect(result.code).toBe("host_not_found");
    expect(result.summary).toContain("mail.corp.local");
    // The relay's own words survive: this is what gets pasted to whoever runs the server.
    expect(result.detail).toBe("getaddrinfo ENOTFOUND mail.corp.local");
  });

  it("reports a refused connection as a refused connection, not as an encryption problem", () => {
    const result = diagnose(MEASURED.closedPort, CONNECTION);

    // The regression that matters. `code` here is ESOCKET, and calling that an encryption
    // mismatch tells the reader to change a setting that is already right.
    expect(result.code).toBe("connection_refused");
    expect(result.hint).toMatch(/port/i);
  });

  it("does not claim an encryption mismatch unless the failure was in TLS", () => {
    for (const measured of Object.values(MEASURED)) {
      expect(diagnose(measured, CONNECTION).code).not.toBe("encryption_mismatch");
    }
  });

  it("recognises a genuine TLS failure", () => {
    const result = diagnose(
      { code: "ESOCKET", message: "140736: error:1408F10B:SSL routines:wrong version number" },
      { ...CONNECTION, smtpPort: 465, smtpEncryption: "tls" },
    );

    expect(result.code).toBe("encryption_mismatch");
    expect(result.hint).toMatch(/Plain|STARTTLS|TLS/);
  });

  it("says who has to change something when the relay demands authentication", () => {
    const result = diagnose({ code: "EAUTH", responseCode: 530, message: "530 5.7.0 Auth required" }, CONNECTION);

    expect(result.code).toBe("authentication_required");
    /*
      This platform deliberately holds no mail password, so "add your credentials" would be
      advice nobody can follow. The fix belongs to whoever runs the relay, and the hint has to
      say so or an administrator will hunt for a password field that does not exist.
    */
    expect(result.hint).toMatch(/relay has to be configured/i);
  });

  it("blames the sender address when the envelope is refused, and names it", () => {
    const result = diagnose({ code: "EENVELOPE", responseCode: 550, message: "550 sender rejected" }, CONNECTION);

    expect(result.code).toBe("address_refused");
    expect(result.hint).toContain("sbom@corp.local");
  });

  it("tailors the timeout hint to the encryption setting", () => {
    const plain = diagnose({ code: "ETIMEDOUT", message: "Greeting never received" }, CONNECTION);
    const tls = diagnose(
      { code: "ETIMEDOUT", message: "Greeting never received" },
      { ...CONNECTION, smtpEncryption: "tls" },
    );

    expect(plain.code).toBe("timed_out");
    expect(tls.code).toBe("timed_out");
    // A relay silently waiting for a plaintext command looks exactly like a firewall drop,
    // and the difference is the setting the reader can actually change.
    expect(tls.hint).toMatch(/Plain/);
    expect(plain.hint).not.toMatch(/Plain"/);
  });

  it("still answers when the error is nothing it recognises", () => {
    // A diagnosis that throws on an unexpected shape would reintroduce the 500 it exists to
    // prevent, which is the whole point of this file.
    const result = diagnose(new Error("something unprecedented"), CONNECTION);

    expect(result.ok).toBe(false);
    expect(result.code).toBe("failed");
    expect(result.detail).toBe("something unprecedented");
  });

  it("survives an error that is not an object at all", () => {
    expect(() => diagnose(null, CONNECTION)).not.toThrow();
    expect(diagnose(null, CONNECTION).ok).toBe(false);
  });
});
