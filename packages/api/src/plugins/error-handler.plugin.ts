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

export const errorHandlerPlugin = fp(
  async (fastify: FastifyInstance) => {
    fastify.setNotFoundHandler((request, reply) => {
      reply
        .status(404)
        .send(toErrorBody("route_not_found", `Route ${request.method} ${request.url} not found`));
    });

    fastify.setErrorHandler((error: FastifyError, request: FastifyRequest, reply: FastifyReply) => {
      // --- our own typed errors -------------------------------------------
      if (error instanceof AppError) {
        if (error.statusCode >= 500) {
          request.log.error({ err: error, code: error.code }, "request failed");
        } else {
          request.log.info({ code: error.code, statusCode: error.statusCode }, "request rejected");
        }
        const message = error.expose ? error.message : "Internal server error";
        return reply.status(error.statusCode).send(toErrorBody(error.code, message, error.details));
      }

      // --- request validation ---------------------------------------------
      if (error instanceof ZodError) {
        return reply
          .status(400)
          .send(toErrorBody("validation_failed", "Request validation failed", zodDetails(error)));
      }

      // --- multipart / body limits ----------------------------------------
      // @fastify/multipart signals an oversized upload with this code. Mapping it
      // explicitly keeps the CI-facing message actionable instead of a bare 413.
      if (error.code === "FST_REQ_FILE_TOO_LARGE") {
        return reply
          .status(413)
          .send(
            toErrorBody(
              "payload_too_large",
              // Worded for both audiences that hit this: a pipeline author reading
              // a CI log, and a person who just picked a file in the browser.
              "SBOM file exceeds the maximum upload size set by INGEST_MAX_SBOM_BYTES. Ask an administrator to raise it if this size is expected.",
            ),
          );
      }
      if (error.code === "FST_PARTS_LIMIT" || error.code === "FST_FILES_LIMIT") {
        return reply
          .status(400)
          .send(toErrorBody("bad_request", "Too many parts in the multipart request."));
      }
      if (error.code === "FST_INVALID_MULTIPART_CONTENT_TYPE") {
        return reply
          .status(415)
          .send(
            toErrorBody(
              "unsupported_media_type",
              "This endpoint expects multipart/form-data. Use `curl -F sbom=@sbom.json -F app_name=...`.",
            ),
          );
      }

      // --- database -------------------------------------------------------
      if (isPgError(error, PG_UNIQUE_VIOLATION)) {
        request.log.warn({ err: error }, "unique constraint violation surfaced to the client");
        return reply
          .status(409)
          .send(toErrorBody("conflict", "That value is already in use."));
      }

      // --- rate limiting / other Fastify errors ----------------------------
      const statusCode = error.statusCode ?? 500;
      if (statusCode < 500) {
        return reply
          .status(statusCode)
          .send(toErrorBody(error.code ?? "bad_request", error.message));
      }

      // --- anything else --------------------------------------------------
      // Log the full error, return nothing about it. An unexpected 500 body must
      // not carry a stack trace or a SQL fragment.
      request.log.error({ err: error }, "unhandled error");
      return reply.status(500).send(toErrorBody("internal_error", "Internal server error"));
    });
  },
  { name: "error-handler" },
);
