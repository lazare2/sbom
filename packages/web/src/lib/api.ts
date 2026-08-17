import type { ApiErrorBody } from "@sbom/shared";

/**
 * Typed fetch wrapper for the API.
 *
 * Requests go to a relative `/api/v1` path, never an absolute origin: the Vite
 * dev server proxies it and nginx serves it in production, so the app is
 * same-origin in both and the session cookie needs no CORS special-casing.
 */
const BASE = "/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;

  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    super(body?.error?.message ?? fallback);
    this.name = "ApiError";
    this.status = status;
    this.code = body?.error?.code ?? "unknown";
    this.details = body?.error?.details;
  }

  /** Field-level messages from a 400, keyed by field path. */
  get fieldErrors(): Record<string, string[]> {
    if (this.details && typeof this.details === "object" && !Array.isArray(this.details)) {
      return this.details as Record<string, string[]>;
    }
    return {};
  }
}

/** Raised on a 401 so the auth layer can distinguish "logged out" from a real failure. */
export class UnauthenticatedError extends ApiError {}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, signal } = options;

  const response = await fetch(`${BASE}${path}`, {
    method,
    // Sends and accepts the session cookie.
    credentials: "same-origin",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    ...(signal ? { signal } : {}),
  });

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
  }

  if (!response.ok) {
    const errorBody = (parsed as ApiErrorBody | null) ?? null;
    const message = `Request failed with status ${response.status}`;
    if (response.status === 401) throw new UnauthenticatedError(response.status, errorBody, message);
    throw new ApiError(response.status, errorBody, message);
  }

  return parsed as T;
}

/** Drops undefined/empty values so they don't appear as `?x=` in the URL. */
export function toQueryString(params: Record<string, unknown>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      // Repeated key, matching the API's array query convention.
      for (const entry of value) {
        if (entry !== undefined && entry !== null && entry !== "") search.append(key, String(entry));
      }
    } else {
      search.set(key, String(value));
    }
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

/**
 * POSTs `multipart/form-data`, for the manual SBOM upload.
 *
 * Deliberately does NOT set `Content-Type`: the browser has to write it itself so
 * it can append the generated boundary. Setting it by hand produces a body the
 * server cannot split, and the failure looks like a malformed SBOM rather than a
 * header mistake.
 *
 * Otherwise it reuses `request`'s error handling by going through the same status
 * and envelope logic, so an ApiError from an upload carries `code` and `details`
 * exactly like every other call — which the duplicate-SBOM 409 relies on.
 */
async function upload<T>(path: string, form: FormData): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    method: "POST",
    credentials: "same-origin",
    body: form,
  });

  const text = await response.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
  }

  if (!response.ok) {
    const errorBody = (parsed as ApiErrorBody | null) ?? null;
    const message = `Request failed with status ${response.status}`;
    if (response.status === 401) throw new UnauthenticatedError(response.status, errorBody, message);
    throw new ApiError(response.status, errorBody, message);
  }

  return parsed as T;
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, signal ? { signal } : {}),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: "POST", body }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: "PATCH", body }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  upload,
};
