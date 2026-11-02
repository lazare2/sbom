import { access, constants } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

/**
 * Finding the grype executable.
 *
 * Separate from the scanner itself because the two fail independently and an
 * administrator has to be told which one to fix: a deployment can have the binary
 * with no database installed, or a current database and a binary that was never
 * provisioned. Collapsing them into one "ready" flag hides the answer.
 *
 * Four rules, first match wins. They are ordered by how specific the intent is,
 * so an operator who has said exactly where the binary lives is never second-guessed:
 *
 *   1. `GRYPE_PATH`  - explicit. Air-gapped, distro-packaged, or anywhere unusual.
 *   2. bundled       - `var/bin/grype`, where the dev install script puts it, and
 *                      the path the container image uses.
 *   3. PATH          - a development machine, and whatever `brew`/`scoop`/`apt` did.
 *
 * Notably absent: any rule that reads a path out of the database. The path decides
 * which executable the server runs, so it stays in the environment where changing it
 * requires deployment access rather than an admin session. This project is meant to
 * be published, and an admin-editable executable path would ship a remote-code-
 * execution primitive to everyone who deployed it.
 */

export interface ResolutionAttempt {
  strategy: string;
  location: string;
  reason: string;
}

export interface ResolvedBinary {
  path: string;
  resolvedBy: string;
}

export interface BinaryResolution {
  binary: ResolvedBinary | null;
  /** Every rule tried and why it did not match. The admin panel renders this verbatim. */
  attempts: ResolutionAttempt[];
}

/** A scanner executable this platform knows how to find. */
export interface ToolSpec {
  /** Base name of the executable, without `.exe`. */
  name: string;
  /** The environment variable that names it explicitly. */
  envVar: string;
  /** How to get it into `var/bin` on a development machine. */
  installHint: string;
}

export const GRYPE_TOOL: ToolSpec = { name: "grype", envVar: "GRYPE_PATH", installHint: "npm run grype:install" };
export const TRIVY_TOOL: ToolSpec = { name: "trivy", envVar: "TRIVY_PATH", installHint: "npm run scanners:install" };
export const OSV_SCANNER_TOOL: ToolSpec = {
  name: "osv-scanner",
  envVar: "OSV_SCANNER_PATH",
  installHint: "npm run scanners:install",
};

function executableName(tool: ToolSpec): string {
  return process.platform === "win32" ? `${tool.name}.exe` : tool.name;
}

/** True when the path exists and is executable by this process. */
async function isExecutable(candidate: string): Promise<boolean> {
  try {
    // X_OK is not meaningful on Windows - every readable file reports executable -
    // so the existence check is what actually matters there, and the spawn attempt
    // is the real test on both platforms.
    await access(candidate, constants.F_OK | (process.platform === "win32" ? 0 : constants.X_OK));
    return true;
  } catch {
    return false;
  }
}

/**
 * Candidate locations for the bundled binary.
 *
 * `var/bin` is where `npm run grype:install` writes, relative to the repo root. The
 * container image places it on PATH instead, so this rule is really about the
 * development and offline-bundle cases.
 */
function bundledCandidates(executable: string): string[] {
  const cwd = process.cwd();
  return [
    // Running from packages/api (npm run dev) or from the repo root.
    path.resolve(cwd, "var", "bin", executable),
    path.resolve(cwd, "..", "..", "var", "bin", executable),
  ];
}

/** Directories on PATH, split for the current platform. */
function pathEntries(): string[] {
  const raw = process.env.PATH ?? process.env.Path ?? "";
  return raw
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

export async function resolveGrypeBinary(explicitPath?: string | undefined): Promise<BinaryResolution> {
  return resolveToolBinary(GRYPE_TOOL, explicitPath);
}

/** The same rules for any scanner executable: its env var, then `var/bin`, then PATH. */
export async function resolveToolBinary(tool: ToolSpec, explicitPath?: string | undefined): Promise<BinaryResolution> {
  const EXECUTABLE = executableName(tool);
  const attempts: ResolutionAttempt[] = [];

  // --- 1. explicit configuration ------------------------------------------
  if (explicitPath) {
    const resolved = path.resolve(explicitPath);
    if (await isExecutable(resolved)) {
      return { binary: { path: resolved, resolvedBy: "config" }, attempts };
    }
    attempts.push({
      strategy: "config",
      location: resolved,
      reason: `${tool.envVar} is set but no executable file is there`,
    });
  } else {
    attempts.push({ strategy: "config", location: tool.envVar, reason: "not set" });
  }

  // --- 2. bundled with the application ------------------------------------
  for (const candidate of bundledCandidates(EXECUTABLE)) {
    if (await isExecutable(candidate)) {
      return { binary: { path: candidate, resolvedBy: "bundled" }, attempts };
    }
  }
  attempts.push({
    strategy: "bundled",
    location: path.join("var", "bin", EXECUTABLE),
    reason: `not present - run \`${tool.installHint}\` to fetch the pinned build`,
  });

  // --- 3. PATH -------------------------------------------------------------
  for (const dir of pathEntries()) {
    const candidate = path.join(dir, EXECUTABLE);
    if (await isExecutable(candidate)) {
      return { binary: { path: candidate, resolvedBy: "path" }, attempts };
    }
  }
  attempts.push({
    strategy: "path",
    location: "PATH",
    reason: `no ${EXECUTABLE} found on PATH`,
  });

  return { binary: null, attempts };
}
