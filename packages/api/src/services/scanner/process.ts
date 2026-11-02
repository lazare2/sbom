import { spawn } from "node:child_process";

export interface ProcessResult {
  code: number;
  stdout: string;
  stderr: string;
  error: Error | null;
}

/**
 * Run a scanner executable and collect its output.
 *
 * The same contract GrypeScanner's runner keeps: never throws, kills the child on timeout,
 * keeps all of stdout (the JSON report) and only the tail of stderr (progress noise can run
 * to megabytes, and only the last lines say what went wrong).
 */
export function runProcess(
  binary: string,
  args: readonly string[],
  options: { env: NodeJS.ProcessEnv; timeoutMs: number; label: string },
): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const child = spawn(binary, args, { env: options.env, shell: false, windowsHide: true });
    let stdout = "";
    let stderr = "";
    let settled = false;
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr = (stderr + chunk).slice(-8192);
    });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      resolve({ code: -1, stdout, stderr, error: new Error(`${options.label} timed out after ${options.timeoutMs}ms`) });
    }, options.timeoutMs);
    timer.unref();

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr, error: err });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout, stderr, error: null });
    });
  });
}

/** The last meaningful line of a scanner's stderr, for an error message. */
export function lastLine(stderr: string): string {
  const lines = stderr
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "");
  return (lines.at(-1) ?? "").slice(0, 500);
}
