import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router";

/**
 * Keeps filter and pagination state in the URL rather than component state.
 *
 * This is a deliberate choice, not incidental: a filtered dependency view is
 * exactly the kind of thing people paste into a ticket or a chat message. If the
 * state lived in React, the link would open on an unfiltered table and the
 * message would be meaningless. It also makes the back button behave.
 */
export interface UrlStateSpec<T> {
  /** Defaults are omitted from the URL, so a pristine view has a clean address. */
  defaults: T;
  /** Parses raw string params into the typed shape. */
  parse: (params: URLSearchParams) => T;
}

export function useUrlState<T extends Record<string, unknown>>(spec: UrlStateSpec<T>) {
  const [searchParams, setSearchParams] = useSearchParams();

  const state = useMemo(() => spec.parse(searchParams), [searchParams, spec]);

  /**
   * Merges a patch into the current state.
   *
   * Any change other than an explicit page change resets to page 1 — landing on
   * page 7 of a freshly narrowed result set is almost never what was meant.
   */
  const setState = useCallback(
    (patch: Partial<T>) => {
      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current);
          for (const [key, value] of Object.entries(patch)) {
            const isDefault = value === spec.defaults[key as keyof T];
            if (value === undefined || value === null || value === "" || isDefault) {
              next.delete(key);
            } else if (Array.isArray(value)) {
              next.delete(key);
              for (const entry of value) next.append(key, String(entry));
            } else {
              next.set(key, String(value));
            }
          }
          if (!("page" in patch)) next.delete("page");
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams, spec.defaults],
  );

  const reset = useCallback(() => setSearchParams(new URLSearchParams(), { replace: true }), [setSearchParams]);

  return { state, setState, reset };
}

export function readString(params: URLSearchParams, key: string, fallback = ""): string {
  return params.get(key) ?? fallback;
}

export function readNumber(params: URLSearchParams, key: string, fallback: number): number {
  const raw = params.get(key);
  if (raw === null) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function readBool(params: URLSearchParams, key: string, fallback = false): boolean {
  const raw = params.get(key);
  if (raw === null) return fallback;
  return raw === "true" || raw === "1";
}

/** Reads a repeated param, constrained to an allowed set. */
export function readEnumList<T extends string>(
  params: URLSearchParams,
  key: string,
  allowed: readonly T[],
  fallback: T[],
): T[] {
  const values = params.getAll(key).filter((v): v is T => (allowed as readonly string[]).includes(v));
  return values.length > 0 ? values : fallback;
}

export function readEnum<T extends string>(
  params: URLSearchParams,
  key: string,
  allowed: readonly T[],
  fallback: T,
): T {
  const raw = params.get(key);
  return raw !== null && (allowed as readonly string[]).includes(raw) ? (raw as T) : fallback;
}
