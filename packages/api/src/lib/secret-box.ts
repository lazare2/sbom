import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

/**
 * Encryption for the one kind of secret this platform has to be able to read back.
 *
 * Everything else here is one-way on purpose. Ingest tokens and session ids are stored as
 * SHA-256 hashes because they only ever need *verifying*; passwords go through argon2; the
 * SMTP relay has no password field at all, on the stated grounds that a secret in a settings
 * row is readable by every administrator and lands in the audit log the moment it changes.
 *
 * A JFrog Xray API token breaks that pattern for an unavoidable reason: the platform has to
 * present it to Xray on every scan, so it must be recoverable. The rule it was protecting is
 * still honoured by other means — the ciphertext is never returned by any endpoint, never
 * logged, and never written to an audit row; the admin screen shows whether a token is
 * configured, not what it is.
 *
 * ## Why the key is not in the database
 *
 * Storing the key beside the ciphertext protects against nothing. It lives in the
 * environment, which is where this codebase already keeps every other secret, so reading the
 * database — a backup, a replica, a support dump — is not enough to recover the token.
 *
 * ## Why AES-256-GCM
 *
 * Authenticated encryption, so a modified ciphertext fails to decrypt rather than yielding
 * plausible garbage that would then be sent to a remote host as a credential. The nonce is
 * random per encryption and stored alongside; GCM's failure mode without a unique nonce is
 * catastrophic, so it is never derived from anything reusable like a row id.
 */

const ALGORITHM = "aes-256-gcm";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

/** Prefix and version, so a stored value announces what produced it. */
const ENVELOPE_PREFIX = "v1";

/**
 * Derives the encryption key from the configured secret.
 *
 * HKDF rather than using the secret directly, with a fixed `info` label: the same
 * environment secret can then be reused for another purpose later without the two sharing a
 * key. Not a password KDF — the input is required to be high-entropy, so there is nothing to
 * slow an attacker down over.
 */
function keyFrom(secret: string): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, "sbom-secret-box", "xray-credentials", KEY_BYTES));
}

export class SecretBoxError extends Error {}

/**
 * Encrypts a secret for storage.
 *
 * Returns `v1.<nonce>.<tag>.<ciphertext>`, all base64url. One self-describing string rather
 * than three columns, so a settings object stays a settings object and no caller can store
 * the ciphertext while forgetting its nonce.
 */
export function sealSecret(plaintext: string, secret: string): string {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(ALGORITHM, keyFrom(secret), nonce);
  const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    ENVELOPE_PREFIX,
    nonce.toString("base64url"),
    tag.toString("base64url"),
    body.toString("base64url"),
  ].join(".");
}

/**
 * Recovers a stored secret.
 *
 * Throws rather than returning null on every failure, and the caller is expected to catch.
 * The three ways this fails — a rotated key, a truncated value, a tampered ciphertext — are
 * indistinguishable by design, and all of them mean the same thing operationally: the stored
 * credential cannot be used and has to be entered again.
 */
export function openSecret(envelope: string, secret: string): string {
  const parts = envelope.split(".");
  if (parts.length !== 4 || parts[0] !== ENVELOPE_PREFIX) {
    throw new SecretBoxError("Stored secret is not in the expected format.");
  }

  const [, nonceB64, tagB64, bodyB64] = parts;
  const nonce = Buffer.from(nonceB64!, "base64url");
  const tag = Buffer.from(tagB64!, "base64url");
  if (nonce.length !== NONCE_BYTES || tag.length !== TAG_BYTES) {
    throw new SecretBoxError("Stored secret is malformed.");
  }

  try {
    const decipher = createDecipheriv(ALGORITHM, keyFrom(secret), nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(Buffer.from(bodyB64!, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    /*
      Deliberately not re-thrown with the underlying reason. Node's message here distinguishes
      a bad tag from a bad key, and that difference is only useful to somebody probing the
      key — an administrator can act on "re-enter the token" and on nothing finer.
    */
    throw new SecretBoxError(
      "Stored secret could not be decrypted. If the encryption key changed, re-enter the credential.",
    );
  }
}
