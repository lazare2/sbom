import { useState } from "react";
import { createPortal } from "react-dom";
import type { AttributeDefinition, Attributes, TeamRef } from "@sbom/shared";
import { useSquads, useTribes } from "../lib/queries.ts";
import { SquadFormModal, TribeFormModal } from "./TeamForms.tsx";
import { Button, FormRow, Select, Textarea, TextInput } from "./ui.tsx";

/**
 * Renders one input per active attribute definition.
 *
 * Driven entirely by the definitions rather than by a hardcoded squad/owner/
 * severity form - that indirection is the whole reason the definitions are rows
 * in a table. Adding "cost centre" in the admin panel makes a cost-centre field
 * appear here with no code change.
 *
 * The two linked attributes, squad and tribe, get a picker instead of a text box: their value is
 * the list of squads or tribes the project is assigned to, so it can only name ones that exist,
 * and a name that does not is offered for creation on the spot.
 */
export function AttributeFields({
  definitions,
  values,
  onChange,
  idPrefix = "attr",
}: {
  definitions: AttributeDefinition[];
  values: Attributes;
  onChange: (next: Attributes) => void;
  idPrefix?: string;
}) {
  if (definitions.length === 0) {
    return (
      <p className="text-xs text-text-muted">
        No attributes are defined. Add one under Admin → Attributes to start tagging applications.
      </p>
    );
  }

  function set(key: string, value: string | number | boolean | null) {
    onChange({ ...values, [key]: value });
  }

  return (
    <div className="space-y-3">
      {definitions.map((def) => {
        const id = `${idPrefix}-${def.key}`;
        const raw = values[def.key];
        const asString = raw === null || raw === undefined ? "" : String(raw);
        const label = def.isRequired ? `${def.label} (required)` : def.label;

        if (def.linkedTo) {
          return (
            <FormRow key={def.key} label={label} htmlFor={id}>
              <TeamNamesInput
                id={id}
                kind={def.linkedTo}
                value={asString}
                onChange={(v) => set(def.key, v === "" ? null : v)}
              />
            </FormRow>
          );
        }

        return (
          <FormRow key={def.key} label={label} htmlFor={id}>
            {def.type === "select" ? (
              <Select
                id={id}
                value={asString}
                ariaLabel={def.label}
                // An explicit empty option, because "not set" is a legitimate
                // value and a select with no blank entry cannot express it.
                options={[
                  { value: "", label: "Not set" },
                  ...(def.options ?? []).map((o) => ({ value: o, label: o })),
                ]}
                onChange={(v) => set(def.key, v === "" ? null : v)}
              />
            ) : def.type === "boolean" ? (
              <Select
                id={id}
                value={raw === true ? "true" : raw === false ? "false" : ""}
                ariaLabel={def.label}
                options={[
                  { value: "", label: "Not set" },
                  { value: "true", label: "Yes" },
                  { value: "false", label: "No" },
                ]}
                onChange={(v) => set(def.key, v === "" ? null : v === "true")}
              />
            ) : def.type === "text" ? (
              <Textarea id={id} value={asString} onChange={(v) => set(def.key, v === "" ? null : v)} />
            ) : (
              <TextInput
                id={id}
                type={def.type === "number" ? "number" : "text"}
                value={asString}
                onChange={(v) =>
                  set(def.key, v === "" ? null : def.type === "number" ? Number(v) : v)
                }
              />
            )}
          </FormRow>
        );
      })}
    </div>
  );
}

/**
 * The labels of required attributes that have no value, for a form to refuse to submit with.
 * Inactive definitions are not shown on forms, so they are not counted.
 */
export function missingRequiredAttributes(definitions: AttributeDefinition[], values: Attributes): string[] {
  return definitions
    .filter((d) => d.isActive && d.isRequired)
    .filter((d) => {
      const v = values[d.key];
      return v === null || v === undefined || String(v).trim() === "";
    })
    .map((d) => d.label);
}

/** "payments, storefront" as a list, the same way the API reads it. */
function splitNames(value: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of value.split(",")) {
    const name = part.trim();
    if (name === "" || seen.has(name.toLowerCase())) continue;
    seen.add(name.toLowerCase());
    out.push(name);
  }
  return out;
}

/**
 * Squads or tribes as removable chips, with suggestions while typing.
 *
 * A name that matches no existing squad is kept and flagged rather than dropped, with a button
 * that opens the create form already filled in, so somebody typing a new team's name is one click
 * from making it instead of being sent elsewhere to do it.
 */
function TeamNamesInput({
  id,
  kind,
  value,
  onChange,
}: {
  id: string;
  kind: "squad" | "tribe";
  value: string;
  onChange: (next: string) => void;
}) {
  const squads = useSquads();
  const tribes = useTribes();
  const known: TeamRef[] = kind === "squad" ? (squads.data?.squads ?? []) : (tribes.data?.tribes ?? []);
  const loaded = kind === "squad" ? squads.isSuccess : tribes.isSuccess;
  const [draft, setDraft] = useState("");
  const [creating, setCreating] = useState<string | null>(null);

  const names = splitNames(value);
  const canonical = (name: string) => known.find((t) => t.name.toLowerCase() === name.toLowerCase());
  const unknown = loaded ? names.filter((n) => !canonical(n)) : [];
  const noun = kind === "squad" ? "squad" : "tribe";

  function commit(list: string[]) {
    onChange(list.join(", "));
  }

  function add(raw: string) {
    const added = splitNames(raw).map((n) => canonical(n)?.name ?? n);
    if (added.length === 0) return;
    commit(splitNames([...names, ...added].join(",")));
    setDraft("");
  }

  /** Swaps the typed spelling for the created team's name, keeping its place in the list. */
  function replaceTyped(createdName: string) {
    const typed = (creating ?? "").toLowerCase();
    commit(names.map((n) => (n.toLowerCase() === typed ? createdName : n)));
  }

  const suggestions = known.filter(
    (t) => !names.some((n) => n.toLowerCase() === t.name.toLowerCase()),
  );

  return (
    <div className="space-y-1.5">
      {names.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {names.map((name) => {
            const missing = loaded && !canonical(name);
            return (
              <span
                key={name}
                className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs ${
                  missing ? "bg-danger-subtle text-danger" : "bg-info-subtle text-info"
                }`}
                title={missing ? `No ${noun} is named "${name}"` : undefined}
              >
                {canonical(name)?.name ?? name}
                <button
                  type="button"
                  aria-label={`Remove ${name}`}
                  className="opacity-70 hover:opacity-100"
                  onClick={() => commit(names.filter((n) => n !== name))}
                >
                  ×
                </button>
              </span>
            );
          })}
        </div>
      ) : null}

      <div className="flex gap-1.5">
        <input
          id={id}
          list={`${id}-options`}
          value={draft}
          placeholder={names.length === 0 ? `Add a ${noun}…` : `Add another ${noun}…`}
          onChange={(e) => {
            const next = e.target.value;
            // Picking a suggestion fills the box with the whole name; take it at once.
            if (known.some((t) => t.name === next)) add(next);
            else setDraft(next);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              add(draft);
            }
          }}
          onBlur={() => add(draft)}
          className="w-full rounded-md border border-border-strong bg-bg-raised px-2.5 py-1.5 text-sm text-text-base placeholder:text-text-faint focus:border-accent"
        />
        <datalist id={`${id}-options`}>
          {suggestions.map((t) => (
            <option key={t.id} value={t.name} />
          ))}
        </datalist>
      </div>

      {unknown.map((name) => (
        <div
          key={name}
          role="alert"
          className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-danger bg-danger-subtle px-2.5 py-1.5 text-xs text-danger"
        >
          <span>
            The {noun} "{name}" does not exist. Create it, or remove it before saving.
          </span>
          <Button size="sm" onClick={() => setCreating(name)}>
            Create {noun}
          </Button>
        </div>
      ))}

      {/*
        Portalled out of the project form: a <form> inside a <form> is invalid HTML, and the
        browser would treat the create button as submitting the outer one.
      */}
      {createPortal(
        kind === "squad" ? (
          <SquadFormModal
            key={creating ?? "closed"}
            target={creating !== null ? "new" : null}
            initialName={creating ?? ""}
            onClose={() => setCreating(null)}
            onSaved={(created) => replaceTyped(created.name)}
          />
        ) : (
          <TribeFormModal
            key={creating ?? "closed"}
            target={creating !== null ? "new" : null}
            initialName={creating ?? ""}
            onClose={() => setCreating(null)}
            onSaved={(created) => replaceTyped(created.name)}
          />
        ),
        document.body,
      )}
    </div>
  );
}
