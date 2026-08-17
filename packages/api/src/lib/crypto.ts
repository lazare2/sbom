import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Hashing and token generation for bearer-style secrets: session cookies and
 * CI ingest tokens.
 *
 * These are all high-entropy random values, not user-chosen passwords, so a
 * plain SHA-256 is the right tool — there is nothing to brute-force. User
 * passwords go through argon2 instead (see modules/auth/password.ts).
 */

/** 32 bytes of entropy, URL-safe so it can live in a link or a header. */
export function generateToken(byteLength = 32): string {
  return randomBytes(byteLength).toString("base64url");
}

/**
 * Alphabet for admin-issued temporary passwords.
 *
 * Crockford-style: no `0/O`, `1/I/L`, `U`, or mixed case. These get read aloud,
 * written on paper, and retyped by hand, so a character pair that looks
 * identical in a sans-serif font costs a support round-trip. Lowercase only for
 * the same reason — "was that a capital?" is not a question worth creating.
 *
 * Exactly 32 symbols, which matters: 256 is divisible by 32, so `byte % 32` is
 * uniform and needs no rejection sampling. A 30-symbol alphabet here would
 * quietly bias the first two characters.
 */
const PASSWORD_ALPHABET = "abcdefghjkmnpqrstvwxyz23456789#@";

/**
 * A temporary password an admin hands over out of band.
 *
 * 20 symbols over a 32-character alphabet is 100 bits of entropy — far beyond
 * what a login endpoint rate-limited to 10 attempts per minute could ever be
 * walked through. Grouped with dashes purely for legibility; the dashes are
 * part of the password and count toward the 12-character minimum.
 */
export function generatePassword(groups = 4, groupSize = 5): string {
  const bytes = randomBytes(groups * groupSize);
  const chars: string[] = [];
  for (const byte of bytes) {
    chars.push(PASSWORD_ALPHABET[byte % PASSWORD_ALPHABET.length]!);
  }
  const out: string[] = [];
  for (let i = 0; i < groups; i += 1) {
    out.push(chars.slice(i * groupSize, (i + 1) * groupSize).join(""));
  }
  return out.join("-");
}

export function sha256Hex(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Constant-time comparison of two hex digests.
 *
 * Used when a secret is compared against a value from config rather than looked
 * up by its hash in an indexed column — a direct `===` there would leak the
 * secret one byte at a time through response timing.
 */
const HEX_RE = /^[0-9a-f]+$/i;

export function safeCompareHex(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) return false;

  // `Buffer.from(s, "hex")` silently stops at the first invalid character, so
  // two malformed inputs both decode to an empty buffer and would compare
  // equal. Every current caller passes sha256Hex output, but validating here
  // means a future caller cannot turn that into an auth bypass.
  if (!HEX_RE.test(a) || !HEX_RE.test(b)) return false;

  const bufA = Buffer.from(a, "hex");
  const bufB = Buffer.from(b, "hex");
  if (bufA.length !== bufB.length || bufA.length === 0) return false;

  try {
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/** Last 4 characters of a token, for display in the admin UI. */
export function tokenSuffix(token: string): string {
  return token.slice(-4);
}
