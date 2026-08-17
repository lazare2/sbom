#!/usr/bin/env node
/**
 * Fetches the pinned Grype build into `var/bin/`, for local development.
 *
 * Container deployments do not need this — the image already carries the binary. This
 * exists so a native setup is one command instead of a manual download, and so the
 * version a developer runs matches the version the image ships.
 *
 * Two properties make downloading and then executing a binary defensible:
 *
 *   1. The version and the expected SHA-256 are committed in this file. Nothing is
 *      trusted because it happened to be served — the archive is hashed and compared
 *      before anything is extracted, and a mismatch aborts.
 *   2. Only the archive for the current platform is fetched, from Anchore's GitHub
 *      release assets over HTTPS.
 *
 * If Grype is already on PATH (`brew install grype`, `scoop install grype`, a distro
 * package) this is unnecessary: binary resolution checks PATH too. Run it anyway if you
 * want the pinned version specifically.
 *
 * Upgrading: change GRYPE_VERSION and the four checksums below, taking them from
 * `grype_<version>_checksums.txt` in the release. Also update the FROM line in
 * packages/api/Dockerfile so the image and development agree.
 */

import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createWriteStream } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const GRYPE_VERSION = "0.115.0";

/**
 * SHA-256 of each release archive, from `grype_0.115.0_checksums.txt`.
 *
 * Windows on ARM is absent because Anchore publishes no such build; the resolver's PATH
 * rule still covers a hand-installed one there.
 */
const CHECKSUMS = {
  "linux_amd64.tar.gz": "3fad92940650e514c0aa2dad83526942a055e210cec09a8a59d9c024adc2b90e",
  "linux_arm64.tar.gz": "b8541b9ecc3e936e7db4ff14b71a9474b25f3898ccaad63ee0bfe3449fcd734d",
  "darwin_amd64.tar.gz": "f2c50aa2c00b633b24535dd44804f09d22b55a3f76d42b5290655af85e55aa64",
  "darwin_arm64.tar.gz": "a5faa957bca6f39e252a046b9431cd79745030c692dd400ab4c0c74266edc406",
  "windows_amd64.zip": "1a29532505bf582b8da80528ed997c786dfafd9ef5bfead3935665a70900ba71",
};

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN_DIR = path.join(REPO_ROOT, "var", "bin");

function assetName() {
  const platform =
    process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux";
  const arch = process.arch === "arm64" ? "arm64" : "amd64";
  const ext = platform === "windows" ? "zip" : "tar.gz";
  return { key: `${platform}_${arch}.${ext}`, platform, arch, ext };
}

async function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", shell: false, ...options });
    child.on("error", reject);
    child.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`${command} exited with ${code}`)),
    );
  });
}

async function main() {
  const { key, platform, arch, ext } = assetName();
  const expected = CHECKSUMS[key];

  if (!expected) {
    console.error(`No pinned Grype build for ${platform}/${arch}.`);
    console.error("Install grype yourself and put it on PATH, or set GRYPE_PATH.");
    process.exit(1);
  }

  const archive = `grype_${GRYPE_VERSION}_${key}`;
  const url = `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${archive}`;

  console.log(`Grype ${GRYPE_VERSION} for ${platform}/${arch}`);
  console.log(`  from ${url}`);

  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok) {
    console.error(`  download failed: HTTP ${response.status}`);
    console.error("  If this machine has no internet access, install grype by hand and");
    console.error("  set GRYPE_PATH to it — the platform never requires this script.");
    process.exit(1);
  }

  const bytes = Buffer.from(await response.arrayBuffer());
  const actual = createHash("sha256").update(bytes).digest("hex");

  if (actual !== expected) {
    /*
     * Refuses rather than warns. The whole point of the pin is that a binary which is
     * about to be executed has been verified; "downloaded something unexpected, running
     * it anyway" would make the checksum decorative.
     */
    console.error("  CHECKSUM MISMATCH — refusing to install.");
    console.error(`    expected ${expected}`);
    console.error(`    actual   ${actual}`);
    console.error("  If you have just changed GRYPE_VERSION, update CHECKSUMS in this script");
    console.error(`  from grype_${GRYPE_VERSION}_checksums.txt in the release.`);
    process.exit(1);
  }
  console.log(`  sha256 verified (${actual.slice(0, 16)}…)`);

  await mkdir(BIN_DIR, { recursive: true });
  const archivePath = path.join(BIN_DIR, archive);
  await writeFile(archivePath, bytes);

  try {
    if (ext === "zip") {
      // PowerShell's Expand-Archive rather than a zip dependency: it is present on every
      // supported Windows and this script must not add packages to install a binary.
      await run("powershell", [
        "-NoProfile",
        "-Command",
        `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${BIN_DIR}' -Force`,
      ]);
    } else {
      await run("tar", ["-xzf", archivePath, "-C", BIN_DIR, "grype"]);
    }
  } finally {
    await rm(archivePath, { force: true });
  }

  const binary = path.join(BIN_DIR, platform === "windows" ? "grype.exe" : "grype");
  if (platform !== "windows") await chmod(binary, 0o755);

  // Proves the extracted file actually runs, rather than only that it exists. A truncated
  // or wrong-architecture binary passes every check above and fails here.
  console.log("");
  await run(binary, ["version"]);

  console.log("");
  console.log(`Installed to ${path.relative(REPO_ROOT, binary)}`);
  console.log("The API finds it there automatically — no configuration needed.");
  console.log("Enable scanning under Admin -> Vulnerability scanning, then update the database.");
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
