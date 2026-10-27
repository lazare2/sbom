import type { AttributeDefinitionRow } from "../../db/schema.js";
import type { Attributes } from "@sbom/shared";
import { ValidationError } from "../../lib/errors.js";

/**
 * Validate a set of attribute values against the admin-managed definitions.
 *
 * The definitions are runtime data, so this cannot be a static Zod schema - it
 * is the reason `attribute_definition` exists as a table rather than as fixed
 * columns. Adding "tier" or "cost_centre" is an admin action, not a migration.
 *
 * Unknown keys are rejected rather than stored. The jsonb column would happily
 * take them, but silently accepting `sqaud: "payments"` means the value never
 * appears in a filter and nobody finds out until someone asks why a squad's
 * application list is short.
 */
export function validateAttributes(
  definitions: readonly AttributeDefinitionRow[],
  attributes: Attributes,
): Attributes {
  const byKey = new Map(definitions.map((d) => [d.key, d]));
  const errors: Record<string, string[]> = {};
  const cleaned: Attributes = {};

  for (const [key, raw] of Object.entries(attributes)) {
    const def = byKey.get(key);
    if (!def) {
      const known = definitions.map((d) => d.key).join(", ");
      errors[key] = [`unknown attribute "${key}"${known ? `; defined keys are: ${known}` : ""}`];
      continue;
    }

    // An explicit null clears the key. Distinct from omitting it, which leaves
    // the stored value untouched - that difference is what lets the edit form
    // send a partial patch.
    if (raw === null || raw === "") {
      cleaned[key] = null;
      continue;
    }

    switch (def.type) {
      case "number": {
        const n = typeof raw === "number" ? raw : Number(raw);
        if (!Number.isFinite(n)) {
          errors[key] = [`"${def.label}" must be a number`];
        } else {
          cleaned[key] = n;
        }
        break;
      }
      case "boolean": {
        if (typeof raw === "boolean") {
          cleaned[key] = raw;
        } else if (raw === "true" || raw === "false") {
          cleaned[key] = raw === "true";
        } else {
          errors[key] = [`"${def.label}" must be true or false`];
        }
        break;
      }
      case "select": {
        const value = String(raw);
        const options = def.options ?? [];
        if (!options.includes(value)) {
          errors[key] = [`"${def.label}" must be one of: ${options.join(", ") || "(no options defined)"}`];
        } else {
          cleaned[key] = value;
        }
        break;
      }
      case "string":
      case "text":
      default: {
        cleaned[key] = String(raw);
        break;
      }
    }
  }

  if (Object.keys(errors).length > 0) {
    throw new ValidationError("Some attribute values are not valid", errors);
  }

  return cleaned;
}

/**
 * Refuses a save that leaves a required attribute empty.
 *
 * `values` is what the application will hold after the save. `onlyKeys`, when given, limits the
 * check to the keys the request actually touched: an edit that changes the owner is not refused
 * because some other required attribute was never filled on an application created by CI. Create
 * and confirm check everything, since those are the moments an administrator vouches for the
 * record as a whole.
 */
export function assertRequiredPresent(
  definitions: readonly AttributeDefinitionRow[],
  values: Attributes,
  onlyKeys?: readonly string[],
): void {
  const errors: Record<string, string[]> = {};
  for (const def of definitions) {
    if (!def.isRequired || !def.isActive) continue;
    if (onlyKeys && !onlyKeys.includes(def.key)) continue;
    const value = values[def.key];
    if (value === null || value === undefined || String(value).trim() === "") {
      errors[def.key] = [`"${def.label}" is required`];
    }
  }
  if (Object.keys(errors).length > 0) {
    throw new ValidationError("Some required attributes are empty", errors);
  }
}

/**
 * Merge a patch into stored attributes, dropping keys the patch set to null.
 *
 * Null means "remove", not "store a null": leaving nulls in the document would
 * make `attributes ? 'squad'` true for an application that has no squad, and
 * that predicate is what the attribute-values dropdown is built on.
 */
export function mergeAttributes(current: Attributes, patch: Attributes): Attributes {
  const next: Attributes = { ...current };
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) {
      delete next[key];
    } else {
      next[key] = value;
    }
  }
  return next;
}
