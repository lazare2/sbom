import { useEffect, useState } from "react";

/**
 * Debounces a rapidly-changing value.
 *
 * Used to keep a text input responsive while the query behind it fires at typing
 * speed. The input itself stays uncontrolled by the debounce, so keystrokes never
 * feel laggy — only the request is delayed.
 */
export function useDebounced<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}
