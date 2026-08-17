import argon2 from "argon2";

/**
 * Password hashing for the local auth provider.
 *
 * argon2id with OWASP's recommended parameters. Set explicitly rather than
 * relying on library defaults so a dependency bump can't silently weaken them,
 * and so the cost is a reviewable number.
 */
const ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MiB
  timeCost: 3,
  parallelism: 4,
};

export async function hashPassword(plaintext: string): Promise<string> {
  return argon2.hash(plaintext, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, plaintext: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plaintext);
  } catch {
    // A malformed or truncated hash in the DB must read as "wrong password",
    // never as an unhandled 500 that distinguishes this account from others.
    return false;
  }
}

/**
 * A real argon2 hash of a fixed throwaway value, computed once at startup.
 *
 * Login verifies against this when the email doesn't exist or the account has no
 * password set, so the request costs the same as a genuine failed login.
 * Without it, response timing reveals which addresses have accounts.
 */
let dummyHashPromise: Promise<string> | undefined;

export function getDummyHash(): Promise<string> {
  dummyHashPromise ??= argon2.hash("not-a-real-password-timing-equalizer", ARGON2_OPTIONS);
  return dummyHashPromise;
}

/** Burns roughly one password-verification's worth of time. */
export async function burnPasswordTiming(plaintext: string): Promise<void> {
  const hash = await getDummyHash();
  await verifyPassword(hash, plaintext);
}

/**
 * True when a stored hash was produced with weaker parameters than the current
 * policy, so it should be transparently re-hashed on the user's next successful
 * login.
 */
export function needsRehash(hash: string): boolean {
  try {
    return argon2.needsRehash(hash, ARGON2_OPTIONS);
  } catch {
    return false;
  }
}
