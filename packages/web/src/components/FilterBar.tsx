import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button } from "./ui.tsx";

/**
 * The filter bar every list shares: a search and a few main filters on one line, the rest in a
 * side panel behind "More filters", and every filter in force shown as a chip that removes it.
 *
 * The pattern of the large design systems (GitHub Primer, IBM Carbon, Atlassian): the results
 * start right under one line of controls, nothing applied is ever out of sight, and the long
 * tail of filters is one click away rather than always on screen.
 */

/** One filter in force, shown as a removable chip. */
export interface FilterChip {
  id: string;
  /** What it filters, e.g. "Severity". */
  label: string;
  /** What it keeps, e.g. "Critical, High". */
  value: string;
  onRemove: () => void;
}

export function FilterBar({
  search,
  quick,
  chips,
  onClearAll,
  panel,
  panelCount,
  views,
  resultLabel,
}: {
  /** The search box, the widest control. */
  search: ReactNode;
  /** The few filters people use most, on the same line. */
  quick: ReactNode;
  chips: FilterChip[];
  onClearAll: () => void;
  /** Everything else, shown in the side panel. */
  panel: ReactNode;
  /** How many filters in the panel are in force - shown on its button. */
  panelCount: number;
  /** Ready-made and saved views, under the controls. */
  views?: ReactNode;
  /** "1,204 advisories", shown in the panel so its effect is visible while choosing. */
  resultLabel?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <section aria-label="Filters" className="mb-4 rounded-lg border border-border-base bg-bg-raised">
      <div className="flex flex-wrap items-end gap-2 p-3">
        <div className="min-w-[220px] flex-[2]">{search}</div>
        {quick}
        <Button variant={panelCount > 0 ? "primary" : "secondary"} onClick={() => setOpen(true)}>
          More filters{panelCount > 0 ? ` (${panelCount})` : ""}
        </Button>
      </div>
      {views ? <div className="flex flex-wrap items-center gap-1.5 border-t border-border-base px-3 py-2">{views}</div> : null}
      {chips.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5 border-t border-border-base px-3 py-2" aria-label="Filters in force">
          {chips.map((chip) => (
            <span
              key={chip.id}
              className="inline-flex max-w-[360px] items-center gap-1 rounded-full border border-accent/40 bg-accent-subtle py-0.5 pr-1 pl-2.5 text-xs text-text-base"
            >
              <span className="text-text-muted">{chip.label}:</span>
              <span className="truncate font-medium" title={chip.value}>
                {chip.value}
              </span>
              <button
                type="button"
                onClick={chip.onRemove}
                aria-label={`Remove filter ${chip.label}: ${chip.value}`}
                className="ml-0.5 rounded-full px-1.5 leading-5 text-text-muted hover:bg-bg-subtle hover:text-text-base"
              >
                ×
              </button>
            </span>
          ))}
          <button type="button" onClick={onClearAll} className="ml-1 text-xs text-accent hover:underline">
            Clear all
          </button>
        </div>
      ) : null}
      <SidePanel open={open} onClose={() => setOpen(false)} title="More filters" footerNote={resultLabel}>
        {panel}
      </SidePanel>
    </section>
  );
}

/** A labelled control in the bar or the panel. */
export function FilterField({ label, children, className = "" }: { label: string; children: ReactNode; className?: string }) {
  return (
    // Native selects size to their content; stretched so every control in a row lines up.
    <div className={`min-w-0 [&_select]:w-full ${className}`}>
      <div className="mb-1 text-[11px] font-medium text-text-muted">{label}</div>
      {children}
    </div>
  );
}

/** A titled group of controls inside the panel. */
export function PanelSection({ title, note, children }: { title: string; note?: string; children: ReactNode }) {
  return (
    <section className="border-b border-border-base px-5 py-4 last:border-b-0">
      <h3 className="text-[11px] font-semibold tracking-wide text-text-faint uppercase">{title}</h3>
      {note ? <p className="mt-0.5 text-xs text-text-muted">{note}</p> : null}
      <div className="mt-3 grid gap-3 sm:grid-cols-2">{children}</div>
    </section>
  );
}

/**
 * Pill toggles for a few values: quicker than a drop-down when there are two to five choices.
 * Each pill says whether it is pressed, for screen readers.
 */
export function TogglePills({
  label,
  options,
  selected,
  onChange,
}: {
  label: string;
  options: ReadonlyArray<{ value: string; label: string; title?: string }>;
  selected: readonly string[];
  onChange: (values: string[]) => void;
}) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {options.map((o) => {
        const on = selected.includes(o.value);
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={on}
            title={o.title}
            onClick={() => onChange(on ? selected.filter((v) => v !== o.value) : [...selected, o.value])}
            className={`rounded-full border px-2.5 py-0.5 text-xs ${
              on
                ? "border-accent bg-accent text-white"
                : "border-border-strong bg-bg-raised text-text-muted hover:border-accent hover:text-text-base"
            }`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/**
 * A panel sliding in from the right, over the page.
 *
 * Not a native modal <dialog>: the drop-downs inside it open in a portal on the page, and a
 * modal dialog's top layer would cover them. So it is a fixed layer under those pop-ups, with
 * what a dialog gives by hand - focus moved in and back, Escape and a click outside to close.
 * Changes apply as they are made; the results behind update and the footer counts them.
 */
function SidePanel({
  open,
  onClose,
  title,
  footerNote,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  footerNote?: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const before = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      // A drop-down inside handles its own Escape first; only a bare Escape closes the panel.
      if (e.key === "Escape" && !document.querySelector('[role="dialog"][aria-label^="Filter by"]')) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      before?.focus?.();
    };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40">
      <div className="absolute inset-0 bg-black/30" onClick={onClose} aria-hidden="true" />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        className="absolute inset-y-0 right-0 flex w-full max-w-[560px] flex-col bg-bg-raised shadow-2xl outline-none"
      >
        <div className="flex items-center justify-between border-b border-border-base px-5 py-3">
          <h2 className="text-base font-semibold text-text-base">{title}</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded px-2 text-lg text-text-muted hover:bg-bg-subtle">
            ×
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">{children}</div>
        <div className="flex items-center justify-between border-t border-border-base px-5 py-3">
          <span className="text-sm text-text-muted" aria-live="polite">
            {footerNote}
          </span>
          <Button variant="primary" onClick={onClose}>
            Show results
          </Button>
        </div>
      </div>
    </div>
  );
}

// --- views -----------------------------------------------------------------------------------

/** A named set of filters: ready-made, or saved by the viewer. */
export interface FilterView {
  name: string;
  /** The page's URL query for it, e.g. "severity=critical&fixState=fixed". */
  query: string;
  title?: string;
}

/**
 * Ready-made views plus the viewer's own, saved in this browser.
 *
 * Saved views are a convenience per person and per browser - the link of any filtered view
 * already shares it with anybody - so they live in localStorage, read and written defensively:
 * a private window or blocked storage just means no saved views.
 */
export function ViewsBar({
  storageKey,
  presets,
  current,
  apply,
}: {
  storageKey: string;
  presets: FilterView[];
  /** The current filters' query, to mark the matching view and to save. */
  current: string;
  apply: (query: string) => void;
}) {
  const [saved, setSaved] = useState<FilterView[]>(() => readViews(storageKey));
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");
  const store = (views: FilterView[]) => {
    setSaved(views);
    try {
      localStorage.setItem(storageKey, JSON.stringify(views));
    } catch {
      /* storage unavailable: kept for this visit only */
    }
  };
  const pill = (view: FilterView, own: boolean) => {
    const active = view.query === current;
    return (
      <span key={`${own ? "own" : "preset"}-${view.name}`} className="inline-flex items-center">
        <button
          type="button"
          onClick={() => apply(view.query)}
          aria-pressed={active}
          title={view.title}
          className={`rounded-full border px-2.5 py-0.5 text-xs ${
            active ? "border-accent bg-accent text-white" : "border-border-strong text-text-base hover:border-accent"
          } ${own ? "rounded-r-none border-r-0" : ""}`}
        >
          {view.name}
        </button>
        {own ? (
          <button
            type="button"
            onClick={() => store(saved.filter((v) => v.name !== view.name))}
            aria-label={`Delete saved view ${view.name}`}
            className="rounded-r-full border border-border-strong px-1.5 py-0.5 text-xs text-text-muted hover:text-danger"
          >
            ×
          </button>
        ) : null}
      </span>
    );
  };
  return (
    <>
      <span className="mr-1 text-[11px] font-semibold tracking-wide text-text-faint uppercase">Views</span>
      {presets.map((v) => pill(v, false))}
      {saved.map((v) => pill(v, true))}
      {naming ? (
        <form
          className="inline-flex items-center gap-1"
          onSubmit={(e) => {
            e.preventDefault();
            const trimmed = name.trim();
            if (!trimmed) return;
            store([...saved.filter((v) => v.name !== trimmed), { name: trimmed, query: current }]);
            setName("");
            setNaming(false);
          }}
        >
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={40}
            placeholder="Name this view"
            aria-label="Name of the view to save"
            className="h-6 w-40 rounded border border-border-strong bg-bg-raised px-2 text-xs"
          />
          <button type="submit" className="text-xs text-accent hover:underline">
            Save
          </button>
          <button type="button" onClick={() => setNaming(false)} className="text-xs text-text-muted hover:underline">
            Cancel
          </button>
        </form>
      ) : current !== "" && ![...presets, ...saved].some((v) => v.query === current) ? (
        <button type="button" onClick={() => setNaming(true)} className="ml-1 text-xs text-accent hover:underline">
          + Save these filters as a view
        </button>
      ) : null}
    </>
  );
}

function readViews(key: string): FilterView[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(key) ?? "[]");
    return Array.isArray(parsed)
      ? parsed.filter((v): v is FilterView => typeof v?.name === "string" && typeof v?.query === "string")
      : [];
  } catch {
    return [];
  }
}
