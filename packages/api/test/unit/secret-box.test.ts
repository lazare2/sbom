import { describe, expect, it } from "vitest";
import { openSecret, sealSecret, SecretBoxError } from "../../src/lib/secret-box.js";

/**
 * The only secret this platform stores in a form it can read back.
 *
 * Everything else is hashed, because everything else only needs verifying. An Xray API token
 * has to be presented to Xray on every scan, so it has to be recoverable — and that makes
 * this the one place where getting the cryptography wrong loses a live credential rather than
 * merely breaking a login.
 *
 * The failure that matters is not "cannot decrypt". It is decrypting *successfully* into
 * something wrong: a tampered or truncated value that yields plausible bytes would be sent to
 * a remote host as a credential. So the assertions below are mostly about refusing, and the
 * authenticated cipher is what makes refusing possible.
 */

const KEY = "a-long-enough-encryption-key-for-tests-0123456789";
const OTHER_KEY = "a-different-encryption-key-that-is-also-long-9876";

describe("sealing a credential", () => {
  it("round-trips the exact value", () => {
    const token = "cmVmdGtuOjAxOjE3NjcyMjU2MDA6c29tZXRoaW5n";
    expect(openSecret(sealSecret(token, KEY), KEY)).toBe(token);
  });

  it("keeps the plaintext out of the stored value", () => {
    // The point of storing it encrypted. A substring check catches the mistake of
    // "encrypting" by encoding, which round-trips perfectly and protects nothing.
    const token = "super-secret-xray-token";
    expect(sealSecret(token, KEY)).not.toContain(token);
    expect(sealSecret(token, KEY)).not.toContain(Buffer.from(token).toString("base64"));
  });

  it("produces a different envelope every time, for the same input", () => {
    // A fresh nonce per encryption. Reusing one under GCM is the catastrophic failure mode,
    // and identical envelopes would be the visible symptom of it.
    const a = sealSecret("same", KEY);
    const b = sealSecret("same", KEY);
    expect(a).not.toBe(b);
    expect(openSecret(a, KEY)).toBe(openSecret(b, KEY));
  });

  it("refuses a value encrypted under a different key", () => {
    const sealed = sealSecret("token", KEY);
    // The rotated-key case, which is the realistic one: it must fail loudly rather than
    // hand back garbage that gets sent to Xray as a credential.
    expect(() => openSecret(sealed, OTHER_KEY)).toThrow(SecretBoxError);
  });

  it("refuses a ciphertext that has been altered", () => {
    const sealed = sealSecret("token", KEY);
    const parts = sealed.split(".");

    /*
      A bit is flipped in the decoded bytes, not in the base64url text.

      Editing the last character was the obvious way to do it and was flaky: base64url's
      final character carries unused bits when the length is not a multiple of four, so
      several different characters decode to identical bytes. Roughly one run in three left
      the ciphertext unchanged and the test failed for the right reason about the wrong
      thing.
    */
    const body = Buffer.from(parts[3]!, "base64url");
    body[0] ^= 0x01;
    parts[3] = body.toString("base64url");

    // Without authentication this would decrypt to corrupted bytes and be used as a
    // credential; the tag check refuses it first.
    expect(() => openSecret(parts.join("."), KEY)).toThrow(SecretBoxError);
  });

  it("refuses a value that is not an envelope at all", () => {
    // A plaintext token pasted straight into the column by hand, which is exactly what
    // somebody debugging would try.
    expect(() => openSecret("just-a-raw-token", KEY)).toThrow(SecretBoxError);
    expect(() => openSecret("v1.short", KEY)).toThrow(SecretBoxError);
    expect(() => openSecret("", KEY)).toThrow(SecretBoxError);
  });

  it("does not say why decryption failed", () => {
    // The distinction between a wrong key and a bad tag is only useful to somebody probing
    // the key. An administrator can act on "re-enter the token" and on nothing finer.
    try {
      openSecret(sealSecret("token", KEY), OTHER_KEY);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect((error as Error).message).toMatch(/re-enter the credential/i);
      expect((error as Error).message).not.toMatch(/tag|auth|cipher/i);
    }
  });

  it("handles a token with unicode and punctuation", () => {
    // Tokens are opaque strings from someone else's system. Assuming ASCII is how a
    // credential comes back subtly wrong months later.
    const token = "tökén:with/slashes+and=padding…";
    expect(openSecret(sealSecret(token, KEY), KEY)).toBe(token);
  });
});
