import { useEffect, useRef, useState, type ReactNode } from "react";
import type { ScanSource } from "@sbom/shared";
import { STATUS_LABELS } from "../lib/format.ts";

/**
 * Shared primitives.
 *
 * Hand-written rather than pulled from a component library: the surface actually
 * needed here is small (badges, tables, pagination, empty and error states), and
 * every one of them is a few lines of Tailwind. A dependency would be more code
 * to keep current than it saves.
 */

// --- badges ----------------------------------------------------------------

type BadgeTone = "neutral" | "ok" | "warn" | "danger" | "info" | "accent";

const BADGE_TONES: Record<BadgeTone, string> = {
  neutral: "bg-neutral-subtle text-text-muted",
  ok: "bg-ok-subtle text-ok",
  warn: "bg-warn-subtle text-warn",
  danger: "bg-danger-subtle text-danger",
  info: "bg-info-subtle text-info",
  accent: "bg-accent-subtle text-accent",
};

export function Badge({
  children,
  tone = "neutral",
  title,
}: {
  children: ReactNode;
  tone?: BadgeTone;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap ${BADGE_TONES[tone]}`}
    >
      {children}
    </span>
  );
}

/**
 * Application status.
 *
 * `pending_confirmation` renders as "Unconfirmed" in a warning tone. That
 * wording is deliberate: the raw enum value reads like a workflow state, whereas
 * a reader needs to know the data is real but the application record is not yet
 * vouched for.
 */
export function StatusBadge({ status }: { status: string }) {
  const tone: BadgeTone =
    status === "active" ? "ok" : status === "pending_confirmation" ? "warn" : "neutral";
  const title =
    status === "pending_confirmation"
      ? "Auto-created from a scan whose app_name matched no known application. Awaiting admin confirmation."
      : status === "inactive"
        ? "Marked inactive by an administrator. Hidden from the default list view."
        : undefined;
  return (
    <Badge tone={tone} title={title}>
      {STATUS_LABELS[status] ?? status}
    </Badge>
  );
}

/**
 * Marks a scan whose SBOM was uploaded by hand rather than posted by a pipeline.
 *
 * Renders nothing for `ci`. Badging the overwhelming default would be noise on
 * every row of every history table, whereas a hand-uploaded build that looked
 * identical to a pipeline's would misrepresent where the data came from.
 *
 * `info`, not `warn`: a manual upload is a legitimate, fully-processed build that
 * is treated identically everywhere else in the platform, and an amber badge would
 * read as a problem with the data. The tooltip names the uploader, because "who
 * decided this is the current build" is the question the badge exists to answer.
 */
export function ScanSourceBadge({
  source,
  uploadedByEmail,
}: {
  source: ScanSource;
  uploadedByEmail?: string | null;
}) {
  if (source !== "manual") return null;
  return (
    <Badge
      tone="info"
      title={
        uploadedByEmail
          ? `Uploaded manually by ${uploadedByEmail}, not posted by a CI pipeline.`
          : "Uploaded manually, not posted by a CI pipeline."
      }
    >
      manual
    </Badge>
  );
}

export function EcosystemBadge({ ecosystem }: { ecosystem: string }) {
  return (
    <span className="inline-block rounded bg-neutral-subtle px-1.5 py-0.5 font-mono text-[11px] text-text-muted">
      {ecosystem}
    </span>
  );
}

// --- layout blocks ---------------------------------------------------------

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-border-base bg-bg-raised ${className}`}>{children}</div>
  );
}

export function CardHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border-base px-4 py-3">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-text-base">{title}</h2>
        {subtitle ? <p className="mt-0.5 text-xs text-text-muted">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-text-base">{title}</h1>
        {subtitle ? <div className="mt-1 text-sm text-text-muted">{subtitle}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** A labelled value, for detail panels. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-medium uppercase tracking-wide text-text-faint">{label}</dt>
      <dd className="mt-0.5 truncate text-sm text-text-base">{children}</dd>
    </div>
  );
}

// --- table -----------------------------------------------------------------

/**
 * Wide tables scroll inside their own container so the page body never scrolls
 * horizontally — a dependency table with long purls is easily 1400px wide.
 */
export function TableWrap({ children }: { children: ReactNode }) {
  return <div className="overflow-x-auto">{children}</div>;
}

export function Table({ children }: { children: ReactNode }) {
  return <table className="w-full border-collapse text-sm">{children}</table>;
}

export function Th({
  children,
  align = "left",
  width,
  onSort,
  sorted,
}: {
  /** Optional: a spacer column for row actions has no visible header text. */
  children?: ReactNode;
  align?: "left" | "right" | "center";
  width?: string;
  onSort?: () => void;
  sorted?: "asc" | "desc" | false;
}) {
  const alignClass = align === "right" ? "text-right" : align === "center" ? "text-center" : "text-left";
  return (
    <th
      style={width ? { width } : undefined}
      /*
        `aria-sort` belongs on the header cell, not on the button inside it. It is only
        defined for `columnheader`/`rowheader`, so on a `<button>` it is invalid ARIA that
        assistive technology ignores outright — the caret was communicating the state to
        sighted users and to nobody else. Set here it is announced with the column name, and
        it is also the one attribute a test can read to assert the rows and the arrow agree.

        Omitted entirely on a non-sortable column: `aria-sort="none"` means "sortable but not
        currently sorted", which would advertise a control that is not there.
      */
      aria-sort={
        onSort ? (sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : "none") : undefined
      }
      className={`sticky top-0 z-10 border-b border-border-base bg-bg-subtle px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-text-muted ${alignClass}`}
    >
      {onSort ? (
        <button
          type="button"
          onClick={onSort}
          className="inline-flex items-center gap-1 hover:text-text-base"
          // Names the action rather than leaving the button labelled by the column text
          // alone, which reads as "Application" with no hint that it does anything.
          title={`Sort by ${typeof children === "string" ? children : "this column"}`}
        >
          {children}
          <span aria-hidden="true" className={sorted ? "text-accent" : "text-text-faint"}>
            {sorted === "asc" ? "▲" : sorted === "desc" ? "▼" : "↕"}
          </span>
        </button>
      ) : (
        children
      )}
    </th>
  );
}

export function Td({
  children,
  align = "left",
  className = "",
  title,
}: {
  children: ReactNode;
  align?: "left" | "right" | "center";
  className?: string;
  title?: string;
}) {
  const alignClass = align === "right" ? "text-right" : align === "center" ? "text-center" : "text-left";
  return (
    <td title={title} className={`border-b border-border-base px-3 py-2 ${alignClass} ${className}`}>
      {children}
    </td>
  );
}

export function Tr({ children }: { children: ReactNode }) {
  return <tr className="hover:bg-bg-subtle">{children}</tr>;
}

// --- states ----------------------------------------------------------------

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <span role="status" aria-live="polite" className="inline-flex items-center gap-2 text-sm text-text-muted">
      <span
        aria-hidden="true"
        className="size-3.5 animate-spin rounded-full border-2 border-border-strong border-t-accent"
      />
      {label}
    </span>
  );
}

export function LoadingBlock({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center px-4 py-12">
      <Spinner label={label} />
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <div className="px-4 py-12 text-center">
      <p className="text-sm font-medium text-text-base">{title}</p>
      {hint ? <p className="mx-auto mt-1 max-w-md text-xs text-text-muted">{hint}</p> : null}
    </div>
  );
}

export function ErrorBanner({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const message = error instanceof Error ? error.message : "Something went wrong";
  return (
    <div
      role="alert"
      className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-danger bg-danger-subtle px-4 py-3"
    >
      <p className="text-sm text-danger">{message}</p>
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="rounded border border-danger px-2 py-1 text-xs font-medium text-danger hover:bg-danger/10"
        >
          Retry
        </button>
      ) : null}
    </div>
  );
}

// --- controls --------------------------------------------------------------

export function Button({
  children,
  onClick,
  type = "button",
  variant = "secondary",
  disabled,
  size = "md",
  form,
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  type?: "button" | "submit";
  variant?: "primary" | "secondary" | "ghost" | "danger";
  disabled?: boolean;
  size?: "sm" | "md";
  /**
   * Id of a form this button submits. Lets a modal's footer button submit a
   * form in the modal body — they are siblings in the DOM, not ancestor and
   * descendant, so without this the button could not submit anything.
   */
  form?: string;
  title?: string;
}) {
  const base =
    "inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50";
  const sizes = size === "sm" ? "px-2 py-1 text-xs" : "px-3 py-1.5 text-sm";
  const variants = {
    primary: "bg-accent text-white hover:bg-accent-hover",
    secondary: "border border-border-strong bg-bg-raised text-text-base hover:bg-bg-subtle",
    ghost: "text-text-muted hover:bg-bg-subtle hover:text-text-base",
    // Filled rather than outlined: a destructive action should not look like a
    // sibling of Cancel.
    danger: "bg-danger text-white hover:opacity-90",
  }[variant];
  return (
    <button
      type={type}
      form={form}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`${base} ${sizes} ${variants}`}
    >
      {children}
    </button>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  type = "text",
  id,
  autoComplete,
  required,
  autoFocus,
  ariaLabel,
  onKeyDown,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: string;
  id?: string;
  autoComplete?: string;
  required?: boolean;
  autoFocus?: boolean;
  ariaLabel?: string;
  onKeyDown?: (e: React.KeyboardEvent<HTMLInputElement>) => void;
}) {
  return (
    <input
      id={id}
      type={type}
      value={value}
      required={required}
      autoFocus={autoFocus}
      autoComplete={autoComplete}
      aria-label={ariaLabel}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={onKeyDown}
      className="w-full rounded-md border border-border-strong bg-bg-raised px-2.5 py-1.5 text-sm text-text-base placeholder:text-text-faint focus:border-accent"
    />
  );
}

export function Select<T extends string>({
  value,
  onChange,
  options,
  ariaLabel,
  id,
}: {
  value: T;
  onChange: (value: T) => void;
  options: Array<{ value: T; label: string }>;
  ariaLabel?: string;
  id?: string;
}) {
  return (
    <select
      id={id}
      value={value}
      aria-label={ariaLabel}
      onChange={(e) => onChange(e.target.value as T)}
      className="rounded-md border border-border-strong bg-bg-raised px-2 py-1.5 text-sm text-text-base focus:border-accent"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
}) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-1.5 text-sm text-text-muted select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="size-3.5 accent-[var(--accent)]"
      />
      {label}
    </label>
  );
}

// --- pagination ------------------------------------------------------------

export function Pagination({
  page,
  pageSize,
  total,
  totalPages,
  onPageChange,
  isFetching,
}: {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  isFetching?: boolean;
}) {
  if (total === 0) return null;
  const first = (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border-base px-4 py-2.5">
      <p className="nums text-xs text-text-muted">
        {first.toLocaleString()}–{last.toLocaleString()} of {total.toLocaleString()}
        {isFetching ? <span className="ml-2 text-text-faint">updating…</span> : null}
      </p>
      <div className="flex items-center gap-1.5">
        <Button size="sm" onClick={() => onPageChange(page - 1)} disabled={page <= 1}>
          ← Prev
        </Button>
        <span className="nums px-1 text-xs text-text-muted">
          {page} / {totalPages}
        </span>
        <Button size="sm" onClick={() => onPageChange(page + 1)} disabled={page >= totalPages}>
          Next →
        </Button>
      </div>
    </div>
  );
}

/** Monospace inline code, for purls, SHAs, and image refs. */
export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span title={title} className="font-mono text-xs text-text-muted">
      {children}
    </span>
  );
}

// --- forms -----------------------------------------------------------------

export function Textarea({
  value,
  onChange,
  id,
  rows = 3,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  id?: string;
  rows?: number;
  placeholder?: string;
}) {
  return (
    <textarea
      id={id}
      rows={rows}
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className="w-full rounded-md border border-border-strong bg-bg-raised px-2.5 py-1.5 text-sm text-text-base placeholder:text-text-faint focus:border-accent"
    />
  );
}

/** A labelled form row. Wires the label to the control so clicking it focuses. */
export function FormRow({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string;
  htmlFor?: string;
  hint?: ReactNode;
  error?: string | undefined;
  children: ReactNode;
}) {
  return (
    <div>
      <label htmlFor={htmlFor} className="mb-1 block text-xs font-medium text-text-muted">
        {label}
      </label>
      {children}
      {error ? (
        <p className="mt-1 text-xs text-danger">{error}</p>
      ) : hint ? (
        <p className="mt-1 text-xs text-text-faint">{hint}</p>
      ) : null}
    </div>
  );
}

// --- modal -----------------------------------------------------------------

/**
 * Dialog built on the native `<dialog>` element.
 *
 * Using the platform element rather than a div with a high z-index gets focus
 * trapping, the top layer, inert background content, and Escape-to-close from
 * the browser — all things a hand-rolled overlay gets subtly wrong.
 */
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);

  /**
   * Opens on mount and closes on unmount.
   *
   * Not `[open]`-driven: the early return below means this component only ever
   * exists while open, so an effect keyed on `open` could never observe the
   * false case — it would unmount first, leaving a still-open <dialog> to be
   * removed from the browser's top layer without ever being closed. Closing in
   * the cleanup is the only place that reliably runs.
   *
   * The early return is deliberate and worth the care: it unmounts the body,
   * which is what resets each dialog's form state and stops closed dialogs from
   * holding live queries.
   */
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog || !open) return;
    if (!dialog.open) dialog.showModal();
    return () => {
      if (dialog.open) dialog.close();
    };
  }, [open]);

  if (!open) return null;

  return (
    <dialog
      ref={ref}
      /*
       * Escape fires `cancel`, and preventing the default keeps the browser from
       * closing the dialog behind React's back — `onClose` unmounts it instead,
       * and the cleanup above performs the actual close.
       *
       * The native `close` event is deliberately NOT bound. Every way this dialog
       * can close is already React-initiated (Escape via `cancel`, the × button,
       * the footer buttons, a successful submit), so listening for `close` adds no
       * information — and it actively breaks a dialog that mounts already open.
       * `HTMLDialogElement.close()` queues its event rather than firing it
       * synchronously, and StrictMode double-invokes mount effects, so the cleanup
       * above runs once while the element is still connected: that queued `close`
       * would then arrive at a dialog React has just re-opened and tear down the
       * state that opened it. The symptom is a dialog that appears and vanishes in
       * the same frame, and only for callers that mount it open — which is why it
       * was reachable from "Accept risk" and from nowhere else.
       */
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      className={`m-auto w-[calc(100vw-2rem)] rounded-lg border border-border-base bg-bg-raised p-0 text-text-base backdrop:bg-black/50 ${
        wide ? "max-w-3xl" : "max-w-md"
      }`}
    >
      <div className="flex items-start justify-between gap-3 border-b border-border-base px-4 py-3">
        <h2 className="text-sm font-semibold text-text-base">{title}</h2>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="-mr-1 -mt-0.5 rounded px-1.5 text-lg leading-none text-text-faint hover:bg-bg-subtle hover:text-text-base"
        >
          ×
        </button>
      </div>

      <div className="max-h-[70vh] overflow-y-auto px-4 py-4">{children}</div>

      {footer ? (
        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border-base px-4 py-3">
          {footer}
        </div>
      ) : null}
    </dialog>
  );
}

/**
 * Destructive-action confirmation that requires typing the target's name.
 *
 * Reserved for operations that destroy retained history — deleting an
 * application takes its entire scan record with it. A plain "are you sure"
 * gets clicked through; typing the name does not happen by accident.
 */
export function ConfirmDeleteModal({
  open,
  onClose,
  onConfirm,
  title,
  confirmWord,
  busy,
  children,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  confirmWord: string;
  busy?: boolean;
  children: ReactNode;
}) {
  const [typed, setTyped] = useState("");

  // Reset between openings, or the previous confirmation would carry over and
  // arm the button before the user has read anything.
  useEffect(() => {
    if (open) setTyped("");
  }, [open]);

  const matches = typed.trim() === confirmWord;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" onClick={onConfirm} disabled={!matches || busy}>
            {busy ? "Deleting…" : "Delete"}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-text-muted">
        {children}
        <FormRow label={`Type ${confirmWord} to confirm`} htmlFor="confirm-word">
          <TextInput id="confirm-word" value={typed} onChange={setTyped} autoFocus />
        </FormRow>
      </div>
    </Modal>
  );
}

// --- one-time secrets -------------------------------------------------------

/**
 * Displays a credential that the server will never show again.
 *
 * The copy button matters: these are 23 characters of deliberately
 * ambiguity-free but unmemorable text, and retyping one by hand is how a
 * "the password doesn't work" ticket gets created.
 */
export function SecretReveal({ label, value, note }: { label: string; value: string; note?: ReactNode }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be refused (insecure origin, permissions policy).
      // The value is on screen and selectable, so this is not worth an error.
    }
  }

  return (
    <div className="rounded-md border border-warn bg-warn-subtle p-3">
      <p className="text-xs font-medium text-warn">{label}</p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <code className="flex-1 rounded bg-bg-raised px-2 py-1.5 font-mono text-sm break-all text-text-base select-all">
          {value}
        </code>
        <Button size="sm" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      {note ? <p className="mt-2 text-xs text-text-muted">{note}</p> : null}
    </div>
  );
}

/** Inline error for a form submission, distinct from the page-level ErrorBanner. */
export function FormError({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : "Something went wrong";
  return (
    <div role="alert" className="rounded-md border border-danger bg-danger-subtle px-3 py-2 text-xs text-danger">
      {message}
    </div>
  );
}
