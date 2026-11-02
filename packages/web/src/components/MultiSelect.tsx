import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { TextInput } from "./ui.tsx";

const PANEL_WIDTH = 280;

/**
 * A filter that takes several values: a button naming what is chosen, opening a searchable
 * checklist.
 *
 * The list opens in a portal positioned against the button, like the squad list on the users
 * page, so a filter bar inside a card cannot clip it. The search filters the options given;
 * when `onSearch` is passed it is also handed the term, for option lists too long to fetch
 * whole (applications).
 */
export function MultiSelect({
  label,
  options,
  selected,
  onChange,
  onSearch,
  loading = false,
  renderOption,
}: {
  label: string;
  options: readonly string[];
  selected: readonly string[];
  onChange: (values: string[]) => void;
  onSearch?: (term: string) => void;
  loading?: boolean;
  renderOption?: (value: string) => string;
}) {
  const [open, setOpen] = useState(false);
  const [term, setTerm] = useState("");
  const [position, setPosition] = useState<{ top: number; left: number } | null>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const show = renderOption ?? ((v: string) => v);

  useEffect(() => {
    if (!open) return;
    const place = () => {
      const rect = buttonRef.current?.getBoundingClientRect();
      if (rect) setPosition({ top: rect.bottom + 4, left: Math.max(8, Math.min(rect.left, window.innerWidth - PANEL_WIDTH - 8)) });
    };
    place();
    const onDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (!panelRef.current?.contains(target) && !buttonRef.current?.contains(target)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    window.addEventListener("pointerdown", onDown);
    window.addEventListener("keydown", onKey);
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => {
      window.removeEventListener("pointerdown", onDown);
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
    };
  }, [open]);

  const needle = term.trim().toLowerCase();
  // Chosen values stay listed even when the current search or option list leaves them out,
  // so they can always be unticked.
  const listed = [
    ...selected.filter((v) => !options.includes(v)),
    ...options.filter((v) => needle === "" || show(v).toLowerCase().includes(needle)),
  ];
  const toggle = (value: string, on: boolean) =>
    onChange(on ? [...selected.filter((v) => v !== value), value] : selected.filter((v) => v !== value));

  const summary =
    selected.length === 0 ? "Any" : selected.length === 1 ? show(selected[0]!) : `${selected.length} selected`;

  return (
    <>
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className={`flex h-[34px] w-full items-center justify-between gap-2 rounded-md border px-2.5 text-left text-sm ${
          selected.length > 0
            ? "border-accent bg-accent-subtle text-text-base"
            : "border-border-strong bg-bg-raised text-text-muted"
        }`}
        title={selected.length > 0 ? selected.map(show).join(", ") : `Filter by ${label.toLowerCase()}`}
      >
        <span className="truncate">{summary}</span>
        <span aria-hidden="true" className="text-[10px] text-text-faint">
          ▼
        </span>
      </button>
      {open && position
        ? createPortal(
            <div
              ref={panelRef}
              role="dialog"
              aria-label={`Filter by ${label}`}
              style={{ top: position.top, left: position.left, width: PANEL_WIDTH }}
              className="fixed z-50 flex max-h-[360px] flex-col overflow-hidden rounded-lg border border-border-strong bg-bg-raised shadow-lg"
            >
              <div className="border-b border-border-base p-2">
                <TextInput
                  value={term}
                  onChange={(v) => {
                    setTerm(v);
                    onSearch?.(v);
                  }}
                  placeholder={`Search ${label.toLowerCase()}…`}
                  ariaLabel={`Search ${label}`}
                  autoFocus
                />
              </div>
              <ul className="min-h-0 flex-1 overflow-y-auto py-1">
                {listed.length === 0 ? (
                  <li className="px-3 py-2 text-xs text-text-faint">{loading ? "Loading…" : "Nothing matches."}</li>
                ) : (
                  listed.map((value) => (
                    <li key={value}>
                      <label className="flex cursor-pointer items-center gap-2 px-3 py-1.5 text-sm text-text-base hover:bg-bg-subtle">
                        <input
                          type="checkbox"
                          checked={selected.includes(value)}
                          onChange={(e) => toggle(value, e.target.checked)}
                          className="size-3.5 shrink-0 accent-[var(--accent)]"
                        />
                        <span className="truncate">{show(value)}</span>
                      </label>
                    </li>
                  ))
                )}
              </ul>
              {selected.length > 0 ? (
                <div className="border-t border-border-base px-3 py-1.5 text-right">
                  <button type="button" onClick={() => onChange([])} className="text-xs text-accent hover:underline">
                    Clear
                  </button>
                </div>
              ) : null}
            </div>,
            document.body,
          )
        : null}
    </>
  );
}
