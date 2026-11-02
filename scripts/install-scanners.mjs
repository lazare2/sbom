#!/usr/bin/env node
/**
 * Fetches the pinned Trivy and osv-scanner builds into var/bin, checksum-verified.
 *
 * The development counterpart of what the API image does at build time; Grype has its own
 * script (install-grype.mjs). Every download is compared against a SHA-256 published by the
 * project and copied here, so a tampered or truncated binary is refused rather than run.
 *
 * Upgrading: change the version and the checksums below, taking them from
 * trivy_<version>_checksums.txt and osv-scanner_SHA256SUMS on the release pages.
 */
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const TRIVY_VERSION = "0.76.1";
const TRIVY_CHECKSUMS = {
  "linux-amd64": ["Linux-64bit.tar.gz", "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"],
  "linux-arm64": ["Linux-ARM64.tar.gz", "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f"],
  "darwin-amd64": ["macOS-64bit.tar.gz", "7aa762eacd582052d053b62dcf972a1ab058abe39a57ccae234ed8894945b6b7"],
  "darwin-arm64": ["macOS-ARM64.tar.gz", "11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5"],
  "windows-amd64": ["windows-64bit.zip", "1051f49cb22d5284f43425f72aad9cda63ca12ceb92e7caa06903490c82dc9bf"],
};

const OSV_VERSION = "2.7.0";
const OSV_CHECKSUMS = {
  "linux-amd64": ["linux_amd64", "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"],
  "linux-arm64": ["linux_arm64", "4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7"],
  "darwin-amd64": ["darwin_amd64", "e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45"],
  "darwin-arm64": ["darwin_arm64", "d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b"],
  "windows-amd64": ["windows_amd64.exe", "9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438"],
  "windows-arm64": ["windows_arm64.exe", "3e630381c1f1fd3c9c4d447e6ff2ef6c737083371722773db8337eead0f97962"],
};

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN_DIR = path.join(REPO_ROOT, "var", "bin");
const EXE = process.platform === "win32" ? ".exe" : "";

function platformKey() {
  const os = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux";
  return `${os}-${process.arch === "arm64" ? "arm64" : "amd64"}`;
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", shell: false });
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`${command} exited with ${code}`))));
  });
}

async function download(url, expected) {
  console.log(`  ${url}`);
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok) throw new Error(`${url} answered HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== expected) throw new Error(`checksum mismatch for ${url}: expected ${expected}, got ${actual}`);
  return bytes;
}

async function installTrivy(key) {
  const pinned = TRIVY_CHECKSUMS[key];
  if (!pinned) return console.warn(`No pinned Trivy build for ${key}; install it yourself or set TRIVY_PATH.`);
  const [suffix, sum] = pinned;
  console.log(`Trivy ${TRIVY_VERSION}`);
  const bytes = await download(`https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${suffix}`, sum);
  const archive = path.join(BIN_DIR, `trivy-download.${suffix.endsWith(".zip") ? "zip" : "tar.gz"}`);
  await writeFile(archive, bytes);
  const staging = path.join(BIN_DIR, "trivy-extract");
  try {
    if (process.platform === "win32") {
      // As install-grype does: Expand-Archive is on every Windows machine, and the `tar` on a
      // Git Bash PATH is GNU tar, which reads "C:" in a path as a remote host.
      await run("powershell", [
        "-NoProfile",
        "-Command",
        `Expand-Archive -LiteralPath '${archive}' -DestinationPath '${staging}' -Force`,
      ]);
      await writeFile(path.join(BIN_DIR, "trivy.exe"), await readFile(path.join(staging, "trivy.exe")));
    } else {
      await run("tar", ["-xzf", archive, "-C", BIN_DIR, "trivy"]);
    }
  } finally {
    await rm(archive, { force: true });
    await rm(staging, { recursive: true, force: true });
  }
  if (!EXE) await chmod(path.join(BIN_DIR, "trivy"), 0o755);
}

async function installOsv(key) {
  const pinned = OSV_CHECKSUMS[key];
  if (!pinned) return console.warn(`No pinned osv-scanner build for ${key}; install it yourself or set OSV_SCANNER_PATH.`);
  const [suffix, sum] = pinned;
  console.log(`osv-scanner ${OSV_VERSION}`);
  const bytes = await download(`https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${suffix}`, sum);
  const target = path.join(BIN_DIR, `osv-scanner${EXE}`);
  await writeFile(target, bytes);
  if (!EXE) await chmod(target, 0o755);
}

async function main() {
  await mkdir(BIN_DIR, { recursive: true });
  const key = platformKey();
  await installTrivy(key);
  await installOsv(key);
  // Read back so a silently empty file is caught here rather than at the first sweep.
  for (const name of [`trivy${EXE}`, `osv-scanner${EXE}`]) {
    const size = (await readFile(path.join(BIN_DIR, name)).catch(() => Buffer.alloc(0))).length;
    console.log(`  ${name}: ${size > 0 ? `${(size / 1e6).toFixed(1)} MB` : "missing"}`);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
