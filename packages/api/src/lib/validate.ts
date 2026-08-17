import type { z } from "zod";
import { ValidationError } from "./errors.js";

/**
 * Validates a request body/query against a Zod schema and returns the parsed
 * (and coerced) value.
 *
 * Zod is used rather than Fastify's JSON-schema validation because the same
 * schemas are shared with the frontend from `@sbom/shared`, so one definition
 * covers both sides of the wire.
 */
export function parseOrThrow<S extends z.ZodTypeAny>(schema: S, value: unknown, what = "Request"): z.infer<S> {
  const result = schema.safeParse(value);
  if (!result.success) {
    const details: Record<string, string[]> = {};
    for (const issue of result.error.issues) {
      const key = issue.path.length > 0 ? issue.path.join(".") : "_";
      (details[key] ??= []).push(issue.message);
    }
    throw new ValidationError(`${what} validation failed`, details);
  }
  return result.data;
}
