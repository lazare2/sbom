import type { AttributeDefinition, Attributes } from "@sbom/shared";
import { FormRow, Select, Textarea, TextInput } from "./ui.tsx";

/**
 * Renders one input per active attribute definition.
 *
 * Driven entirely by the definitions rather than by a hardcoded squad/owner/
 * severity form — that indirection is the whole reason the definitions are rows
 * in a table. Adding "cost centre" in the admin panel makes a cost-centre field
 * appear here with no code change.
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

        return (
          <FormRow key={def.key} label={def.label} htmlFor={id}>
            {def.type === "select" ? (
              <Select
                id={id}
                value={asString}
                ariaLabel={def.label}
                // An explicit empty option, because "not set" is a legitimate
                // value and a select with no blank entry cannot express it.
                options={[
                  { value: "", label: "— not set —" },
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
                  { value: "", label: "— not set —" },
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
