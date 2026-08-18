import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GrypeScanner } from "../../src/services/scanner/grype.js";
import type { Config } from "../../src/config.js";

/**
 * Installing a corporate CA should be one action: put the file in the folder.
 *
 * It used to be three -- place the file, name it in an env file, and get the in-container
 * path right -- and all three fail with the same opaque TLS error, which says nothing about
 * which step was missed. These tests hold the discovery to that one action, including the
 * case that caused the trouble in practice: a trust store holding several certificates with
 * near-identical names, only one of which signed the proxy.
 */

const PEM_A = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
const PEM_B = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----";

let dirs: string[] = [];

async function scratch(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "ca-test-"));
  dirs.push(dir);
  return dir;
}

function config(over: Partial<Config>): Config {
  return {
    GRYPE_DB_UPDATE_URL: "https://grype.example.test/databases",
    GRYPE_REACHABILITY_TIMEOUT_MS: 1000,
    GRYPE_PATH: "/nonexistent/grype",
    ...over,
  } as unknown as Config;
}

/** The resolver is private: exercising it directly is the point of these tests. */
function resolve(scanner: GrypeScanner): Promise<string | null> {
  return (scanner as unknown as { resolveCaCert(): Promise<string | null> }).resolveCaCert();
}

afterEach(() => {
  dirs = [];
});

describe("CA certificate discovery", () => {
  it("finds a single dropped-in certificate without it being named anywhere", async () => {
    const caDir = await scratch();
    await writeFile(path.join(caDir, "proxy-ca.crt"), PEM_A, "utf8");

    const scanner = new GrypeScanner(
      config({ GRYPE_DB_CA_DIR: caDir, GRYPE_DB_CACHE_DIR: await scratch() }),
    );

    expect(await resolve(scanner)).toBe(path.join(caDir, "proxy-ca.crt"));
  });

  it("bundles several certificates rather than guessing which one signed the proxy", async () => {
    const caDir = await scratch();
    const cacheDir = await scratch();
    await writeFile(path.join(caDir, "org-root.crt"), PEM_A, "utf8");
    await writeFile(path.join(caDir, "org-issuing.pem"), PEM_B, "utf8");

    const scanner = new GrypeScanner(
      config({ GRYPE_DB_CA_DIR: caDir, GRYPE_DB_CACHE_DIR: cacheDir }),
    );
    const resolved = await resolve(scanner);

    // Written beside the database, never into the mount, which is read-only.
    expect(resolved).toBe(path.join(path.resolve(cacheDir), "ca-bundle.pem"));
    const bundle = await readFile(resolved!, "utf8");
    expect(bundle).toContain("AAAA");
    expect(bundle).toContain("BBBB");
  });

  it("ignores the README and .gitkeep that keep the mount source tracked", async () => {
    const caDir = await scratch();
    await mkdir(caDir, { recursive: true });
    await writeFile(path.join(caDir, "README.md"), "# not a certificate", "utf8");
    await writeFile(path.join(caDir, ".gitkeep"), "", "utf8");

    const scanner = new GrypeScanner(
      config({ GRYPE_DB_CA_DIR: caDir, GRYPE_DB_CACHE_DIR: await scratch() }),
    );

    // Those two files ship in the repository, so treating them as certificates would hand
    // grype a bad bundle on every deployment that never needed a CA at all.
    expect(await resolve(scanner)).toBeNull();
  });

  it("returns null when the directory does not exist, which is the normal case", async () => {
    const scanner = new GrypeScanner(
      config({
        GRYPE_DB_CA_DIR: path.join(tmpdir(), "definitely-not-here-ca-dir"),
        GRYPE_DB_CACHE_DIR: await scratch(),
      }),
    );

    expect(await resolve(scanner)).toBeNull();
  });

  it("lets an explicit GRYPE_DB_CA_CERT win over discovery", async () => {
    const caDir = await scratch();
    await writeFile(path.join(caDir, "ignored.crt"), PEM_A, "utf8");

    const scanner = new GrypeScanner(
      config({
        GRYPE_DB_CA_CERT: "/explicit/path.pem",
        GRYPE_DB_CA_DIR: caDir,
        GRYPE_DB_CACHE_DIR: await scratch(),
      }),
    );

    expect(await resolve(scanner)).toBe("/explicit/path.pem");
  });
});
