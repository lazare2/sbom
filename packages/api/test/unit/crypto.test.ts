import { describe, expect, it } from "vitest";
import {
  generatePassword,
  generateToken,
  safeCompareHex,
  sha256Hex,
  tokenSuffix,
} from "../../src/lib/crypto.js";
import { IngestTokenService } from "../../src/modules/ingestion/ingest-token.service.js";

describe("generatePassword", () => {
  it("satisfies the 12-character minimum the password schema enforces", () => {
    // If these two ever disagree, every admin-generated password would be
    // rejected by the very endpoint that issued it.
    expect(generatePassword().length).toBeGreaterThanOrEqual(12);
  });

  it("omits characters that are ambiguous when read aloud or handwritten", () => {
    // These get transcribed by a human between two people. `0/O` and `1/l/I`
    // cost a support round-trip every time they appear.
    const joined = Array.from({ length: 200 }, () => generatePassword()).join("");
    expect(joined).not.toMatch(/[0O1lIiuU]/);
  });

  it("uses only the documented alphabet plus group separators", () => {
    for (let i = 0; i < 100; i++) {
      expect(generatePassword()).toMatch(/^[abcdefghjkmnpqrstvwxyz23456789#@-]+$/);
    }
  });

  it("groups for legibility without losing entropy to the separators", () => {
    // 4 groups of 5 plus 3 dashes.
    expect(generatePassword()).toMatch(/^[^-]{5}-[^-]{5}-[^-]{5}-[^-]{5}$/);
  });

  it("does not repeat", () => {
    const seen = new Set(Array.from({ length: 500 }, () => generatePassword()));
    expect(seen.size).toBe(500);
  });

  it("draws uniformly, with no character starved or favoured", () => {
    // The alphabet is exactly 32 symbols so `byte % 32` is unbiased. A 30-symbol
    // alphabet would quietly over-represent its first two characters, which this
    // catches: 20000 draws over 32 symbols averages 625 each.
    const counts = new Map<string, number>();
    for (let i = 0; i < 1000; i++) {
      for (const ch of generatePassword().replace(/-/g, "")) {
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
      }
    }
    expect(counts.size).toBe(32);
    for (const count of counts.values()) {
      expect(count).toBeGreaterThan(400);
      expect(count).toBeLessThan(900);
    }
  });
});

describe("generateToken", () => {
  it("produces URL-safe output, so it can go straight into a header or link", () => {
    for (let i = 0; i < 50; i++) {
      expect(generateToken()).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });

  it("does not repeat", () => {
    const tokens = new Set(Array.from({ length: 500 }, () => generateToken()));
    expect(tokens.size).toBe(500);
  });

  it("yields at least 32 bytes of entropy by default", () => {
    // base64url of 32 bytes is 43 characters.
    expect(generateToken().length).toBeGreaterThanOrEqual(43);
  });
});

describe("sha256Hex", () => {
  it("matches the known digest for an empty input", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("hashes a Buffer and its string form identically", () => {
    expect(sha256Hex(Buffer.from("abc"))).toBe(sha256Hex("abc"));
  });
});

describe("safeCompareHex", () => {
  it("accepts identical digests", () => {
    const h = sha256Hex("secret");
    expect(safeCompareHex(h, h)).toBe(true);
  });

  it("rejects different digests", () => {
    expect(safeCompareHex(sha256Hex("a"), sha256Hex("b"))).toBe(false);
  });

  it("rejects mismatched lengths without throwing", () => {
    expect(safeCompareHex("abcd", "abcdef")).toBe(false);
  });

  it("rejects non-hex input rather than decoding it to an empty buffer", () => {
    // Buffer.from(s, "hex") stops at the first invalid character, so without an
    // explicit format check two malformed inputs would compare equal.
    expect(safeCompareHex("zzzz", "zzzz")).toBe(false);
    expect(safeCompareHex("zzzz", sha256Hex("x").slice(0, 4))).toBe(false);
  });

  it("rejects empty input", () => {
    expect(safeCompareHex("", "")).toBe(false);
  });
});

describe("tokenSuffix", () => {
  it("returns the last four characters for display", () => {
    expect(tokenSuffix("abcdefghij")).toBe("ghij");
  });
});

describe("IngestTokenService.parseBearer", () => {
  it("extracts the token from a well-formed header", () => {
    expect(IngestTokenService.parseBearer("Bearer abc123")).toBe("abc123");
  });

  it("is case-insensitive on the scheme, as RFC 7235 requires", () => {
    expect(IngestTokenService.parseBearer("bearer abc123")).toBe("abc123");
    expect(IngestTokenService.parseBearer("BEARER abc123")).toBe("abc123");
  });

  it("tolerates surrounding and extra whitespace", () => {
    expect(IngestTokenService.parseBearer("  Bearer   abc123  ")).toBe("abc123");
  });

  it("returns null for a missing, empty, or non-bearer header", () => {
    expect(IngestTokenService.parseBearer(undefined)).toBeNull();
    expect(IngestTokenService.parseBearer("")).toBeNull();
    expect(IngestTokenService.parseBearer("Bearer")).toBeNull();
    expect(IngestTokenService.parseBearer("Bearer   ")).toBeNull();
    expect(IngestTokenService.parseBearer("Basic dXNlcjpwYXNz")).toBeNull();
  });
});
