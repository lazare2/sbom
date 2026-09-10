import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import fp from "fastify-plugin";
import { ZodError } from "zod";
import type { ApiErrorBody } from "@sbom/shared";
import { AppError, isPgError, PG_UNIQUE_VIOLATION } from "../lib/errors.js";

/**
 * One place that turns any thrown value into an HTTP response.
 *
 * This is more than tidiness here: the CI/CD pipelines call the ingest endpoint
 * with `curl -f`, so the status code is the contract. A 2xx must mean the scan is
 * committed, and an unexpected exception must never leak through as anything but
 * a 5xx that fails the build.
 */
function toErrorBody(code: string, message: string, details?: unknown): ApiErrorBody {
  return { error: { code, message, ...(details === undefined ? {} : { details }) } };
}

/** Flattens a ZodError into `{ "field.path": ["message"] }`. */
function zodDetails(err: ZodError): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const issue of err.issues) {
    const key = issue.path.length > 0 ? issue.path.join(".") : "_";
    (out[key] ??= []).push(issue.message);
  }
  return out;
}

/**
 * Failures that are noise rather than diagnostics.
 *
 * An error log nobody can bear to read is the same as no error log. These three arrive
 * constantly on a healthy deployment and say nothing about it:
 *
 * - `unauthorized` is an expired session, which every idle browser tab produces.
 * - `route_not_found` is a favicon, a probe, or a stale bookmark.
 * - `vuln_scanning_disabled` is a designed refusal that the UI handles by rendering "not
 *   assessed" -- the feature working correctly, not a fault.
 *
 * Everything else that fails is recorded, 4xx included: a rejected request is precisely the
 * case an administrator cannot otherwise see.
 */
const NOT_WORTH_RECORDING = new Set(["unauthorized", "route_not_found", "vuln_scanning_disabled"]);

export const errorHandlerPlugin = fp(
  async (fastify: FastifyInstance) => {
    fastify.setNotFoundHandler((request, reply) => {
      reply
        .status(404)
        .send(toErrorBody("route_not_found", `Route ${request.method} ${request.url} not found`));
    });

    fastify.setErrorHandler((error: FastifyError, request: FastifyRequest, reply: FastifyReply) => {
      /*
        Every exit from this handler goes through here, so that what the administrator reads
        in the error log is character-for-character what the client was told. A second
        formatting of the same failure would drift, and the log would then describe a message
        nobody ever saw.

        The write is not awaited. This handler is the last thing between a failure and the
        client, and a logger that can make a request hang is worse than no logger -- so the
        response is sent regardless of whether the row lands. `record` swallows its own
        failures for the same reason.
      */
      const fail = (
        status: number,
        code: string,
        message: string,
        details?: unknown,
        /*
          Recorded instead of `details`, and never sent.

          The only user is the unexpected 500, where the two audiences genuinely differ: the
          client must not receive a stack trace or a SQL fragment, and an administrator signed
          in to this platform is precisely who should be able to read what broke. Without this
          the one class of failure that is actually the platform's fault would also be the
          only one the log cannot explain.
        */
        privateDetails?: unknown,
      ) => {
        if (!NOT_WORTH_RECORDING.has(code)) {
          const actor = request.currentUser;
          void fastify.ctx?.apiErrors?.record({
            method: request.method,
            path: request.url,
            statusCode: status,
            code,
            message,
            details: privateDetails ?? details,
            actor: actor ? { id: actor.id, email: actor.email } : null,
          });
        }
        return reply.status(status).send(toErrorBody(code, message, details));
      };

      // --- our own typed errors -------------------------------------------
      if (error instanceof AppError) {
        if (error.statusCode >= 500) {
          request.log.error({ err: error, code: error.code }, "request failed");
        } else {
          /*
            The rejected field, in the server's own log as well as the browser's.

            This used to log the code and the status and nothing else, so `docker compose logs
            api` could tell you that a request was rejected but never which value was wrong --
            leaving no way at all to diagnose a validation failure on a machine without
            developer tools. `details` is names and reasons, never submitted values.
          */
          request.log.info(
            { code: error.code, statusCode: error.statusCode, details: error.details },
            "request rejected",
          );
        }
        const message = error.expose ? error.message : "Internal server error";
        return fail(error.statusCode, error.code, message, error.details);
      }

      // --- request validation ---------------------------------------------
      if (error instanceof ZodError) {
        const details = zodDetails(error);
        request.log.info({ code: "validation_failed", details }, "request rejected");
        return fail(400, "validation_failed", "Request validation failed", details);
      }

      // --- multipart / body limits ----------------------------------------
      // @fastify/multipart signals an oversized upload with this code. Mapping it
      // explicitly keeps the CI-facing message actionable instead of a bare 413.
      if (error.code === "FST_REQ_FILE_TOO_LARGE") {
        return fail(
          413,
          "payload_too_large",
          // Worded for both audiences that hit this: a pipeline author reading
          // a CI log, and a person who just picked a file in the browser.
          "SBOM file exceeds the maximum upload size set by INGEST_MAX_SBOM_BYTES. Ask an administrator to raise it if this size is expected.",
        );
      }
      if (error.code === "FST_PARTS_LIMIT" || error.code === "FST_FILES_LIMIT") {
        return fail(400, "bad_request", "Too many parts in the multipart request.");
      }
      if (error.code === "FST_INVALID_MULTIPART_CONTENT_TYPE") {
        return fail(
          415,
          "unsupported_media_type",
          "This endpoint expects multipart/form-data. Use `curl -F sbom=@sbom.json -F app_name=...`.",
        );
      }

      // --- database -------------------------------------------------------
      if (isPgError(error, PG_UNIQUE_VIOLATION)) {
        request.log.warn({ err: error }, "unique constraint violation surfaced to the client");
        return fail(409, "conflict", "That value is already in use.");
      }

      // --- rate limiting / other Fastify errors ----------------------------
      const statusCode = error.statusCode ?? 500;
      if (statusCode < 500) {
        return fail(statusCode, error.code ?? "bad_request", error.message);
      }

      // --- anything else --------------------------------------------------
      // Log the full error, return nothing about it. An unexpected 500 body must
      // not carry a stack trace or a SQL fragment.
      request.log.error({ err: error }, "unhandled error");
      // The body stays empty of detail; the real cause goes to the error log only.
      return fail(500, "internal_error", "Internal server error", undefined, {
        _: [error.message || String(error)],
      });
    });
  },
  { name: "error-handler" },
);
