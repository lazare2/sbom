/**
 * Typed application errors.
 *
 * Every error that reaches the client goes through one of these so the response
 * shape (`{ error: { code, message } }`) and the status code are decided in one
 * place. This matters more than usual here: CI/CD calls the ingest endpoint with
 * `curl -f`, so a 2xx must mean "the scan is durably stored" and nothing else.
 */
export class AppError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly details?: unknown;
  /** When false, the message is replaced with a generic one in production. */
  readonly expose: boolean;

  constructor(opts: {
    statusCode: number;
    code: string;
    message: string;
    details?: unknown;
    expose?: boolean;
    cause?: unknown;
  }) {
    super(opts.message, opts.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = new.target.name;
    this.statusCode = opts.statusCode;
    this.code = opts.code;
    this.details = opts.details;
    this.expose = opts.expose ?? opts.statusCode < 500;
  }
}

export class BadRequestError extends AppError {
  constructor(message: string, details?: unknown) {
    super({ statusCode: 400, code: "bad_request", message, details });
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: unknown) {
    super({ statusCode: 400, code: "validation_failed", message, details });
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = "Authentication required") {
    super({ statusCode: 401, code: "unauthorized", message });
  }
}

export class ForbiddenError extends AppError {
  constructor(message = "You do not have permission to perform this action") {
    super({ statusCode: 403, code: "forbidden", message });
  }
}

export class NotFoundError extends AppError {
  constructor(resource = "Resource") {
    super({ statusCode: 404, code: "not_found", message: `${resource} not found` });
  }
}

export class ConflictError extends AppError {
  constructor(message: string, details?: unknown) {
    super({ statusCode: 409, code: "conflict", message, details });
  }
}

export class PayloadTooLargeError extends AppError {
  constructor(message: string) {
    super({ statusCode: 413, code: "payload_too_large", message });
  }
}

export class UnprocessableError extends AppError {
  constructor(message: string, details?: unknown) {
    super({ statusCode: 422, code: "unprocessable_entity", message, details });
  }
}

export class TooManyRequestsError extends AppError {
  constructor(message = "Too many requests") {
    super({ statusCode: 429, code: "too_many_requests", message });
  }
}

export class InternalError extends AppError {
  constructor(message = "Internal server error", cause?: unknown) {
    super({ statusCode: 500, code: "internal_error", message, expose: false, cause });
  }
}

/** Postgres unique-violation SQLSTATE, used to turn a race into a clean 409. */
export const PG_UNIQUE_VIOLATION = "23505";
export const PG_FOREIGN_KEY_VIOLATION = "23503";

export function isPgError(err: unknown, code: string): boolean {
  return typeof err === "object" && err !== null && "code" in err && (err as { code?: unknown }).code === code;
}
