import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Badge, TextInput } from "./ui.tsx";

/** Squads shown inline before the rest fold into "+N". Two fit beside the access badge. */
const VISIBLE_SQUADS = 2;

/** From this many squads the pop-over gets a search box; below it, the list is shorter than a search. */
const SEARCH_FROM = 10;

const PANEL_WIDTH = 288;

/**
 * An account's squads, compact enough for a table cell.
 *
 * The cell used to render one badge per squad, which is fine for one or two and swallows the
 * row for someone on fifteen. Now the first two are shown and the rest sit behind a "+N"
 * badge that opens the full, alphabetical list - searchable once it is long enough to need it.
 *
 * The list opens in a portal positioned against the badge rather than inside the cell: a
 * resized table clips its cells, and a pop-over cut off by its own column would hide exactly
 * the names it was opened to show.
 */
export function SquadBadges({
  squads,
  title = "A squad this account is on. It reaches everything the squad is granted.",
}: {
  squads: ReadonlyArray<{ id: string; name: string }>;
  title?: string;
}) {
  const sorted = useMemo(() => [...squads].sort((a, b) => a.name.localeCompare(b.name)), [squads]);
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const [position, setPosition] = useState<{ top: number; left: number; maxHeight: number } | null>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const place = () => {
      const rect = buttonRef.current?.getBoundingClientRect();
      if (!rect) return;
      const left = Math.max(8, Math.min(rect.left, window.innerWidth - PANEL_WIDTH - 8));
      const below = window.innerHeight - rect.bottom - 12;
      const above = rect.top - 12;
      // Opens downward unless there is clearly more room above, as there is near the page foot.
      if (below >= 220 || below >= above) {
        setPosition({ top: rect.bottom + 4, left, maxHeight: Math.max(160, below) });
      } else {
        const maxHeight = Math.min(above, 420);
        setPosition({ top: rect.top - 4 - maxHeight, left, maxHeight });
      }
    };
    place();
    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (!panelRef.current?.contains(target) && !buttonRef.current?.contains(target)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    window.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("keydown", onKey);
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => {
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
    };
  }, [open]);

  if (sorted.length === 0) return null;

  const shown = sorted.slice(0, VISIBLE_SQUADS);
  const hidden = sorted.length - shown.length;
  const needle = filter.trim().toLowerCase();
  const listed = needle ? sorted.filter((s) => s.name.toLowerCase().includes(needle)) : sorted;

  return (
    <>
      {shown.map((squad) => (
        <Badge key={squad.id} tone="info" title={title}>
          {squad.name}
        </Badge>
      ))}
      {hidden > 0 ? (
        <button
          ref={buttonRef}
          type="button"
          aria-haspopup="dialog"
          aria-expanded={open}
          onClick={() => {
            setFilter("");
            setOpen((v) => !v);
          }}
          title={`Show all ${sorted.length} squads`}
          className="inline-flex items-center rounded border border-info/40 bg-info-subtle px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap text-info hover:border-info"
        >
          +{hidden} more
        </button>
      ) : null}
      {open && position
        ? createPortal(
            <div
              ref={panelRef}
              role="dialog"
              aria-label={`All ${sorted.length} squads`}
              style={{ top: position.top, left: position.left, width: PANEL_WIDTH, maxHeight: position.maxHeight }}
              className="fixed z-50 flex flex-col overflow-hidden rounded-lg border border-border-strong bg-bg-raised shadow-lg"
            >
              <div className="border-b border-border-base px-3 py-2 text-xs font-medium text-text-muted">
                On {sorted.length} squads
              </div>
              {sorted.length >= SEARCH_FROM ? (
                <div className="border-b border-border-base p-2">
                  <TextInput value={filter} onChange={setFilter} placeholder="Search squads…" ariaLabel="Search squads" autoFocus />
                </div>
              ) : null}
              <ul className="min-h-0 flex-1 overflow-y-auto py-1">
                {listed.length === 0 ? (
                  <li className="px-3 py-2 text-xs text-text-faint">No squad matches.</li>
                ) : (
                  listed.map((squad) => (
                    <li key={squad.id} className="truncate px-3 py-1 text-sm text-text-base" title={squad.name}>
                      {squad.name}
                    </li>
                  ))
                )}
              </ul>
            </div>,
            document.body,
          )
        : null}
    </>
  );
}
