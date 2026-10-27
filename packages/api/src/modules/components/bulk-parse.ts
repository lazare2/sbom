import {
  BULK_SEARCH_MAX_ENTRIES,
  type BulkEntry,
  type BulkEntryVersionKind,
  type BulkParseProblem,
  type BulkParseSummary,
} from "@sbom/shared";

/**
 * Parses a pasted package list.
 *
 * Server-side rather than in the browser for three reasons: the rules become part
 * of the API contract and are testable in isolation; `curl --data-binary @list.txt`
 * works for scripting; and the response can echo back how every line was read.
 * That echo is the important one - silently misreading one line of a 200-line
 * audit is the failure nobody notices.
 *
 * Accepted per line, because these are the forms people actually have on their
 * clipboard:
 *
 *   express                                bare name
 *   express@4.19.2                         name@version
 *   @wb-track/shared-front                 scoped npm name
 *   @wb-track/shared-front@2.1.0           scoped name and version
 *   django==4.2.1                          pip pin
 *   django >= 4.2                          pip range, spaced -> version ignored
 *   express@^1.2.3                         npm range       -> version ignored
 *   express@latest                         dist-tag        -> version ignored
 *   express 4.19.2                         whitespace, tab or comma separated
 *   pkg:npm/keyv@6.0.0                     purl, carries the ecosystem
 *   com.fasterxml.jackson.core:jackson-databind:2.17.2     maven coordinate
 *   # a comment                            ignored
 *
 * Blank lines, `#` and `//` comments, and trailing punctuation are ignored.
 * Anything that survives none of these forms is reported as a problem line rather
 * than guessed at.
 */

/**
 * Version specifier operators, longest first.
 *
 * Order is load-bearing: `>=` must be tested before `>`, and `===` before `==`,
 * or the shorter operator matches first and the remainder starts with `=`.
 */
const OPERATOR_PATTERN = /^(===|==|>=|<=|!=|~=|\^|~|>|<)/;

/** Operators that name one version rather than a set of them. */
const EXACT_OPERATORS = new Set(["==", "==="]);

/** Collapses whitespace around an operator, so `django >= 4.2` becomes one field. */
const SPACED_OPERATOR = /\s*(===|==|>=|<=|!=|~=)\s*/;

/**
 * A plausible version string.
 *
 * Deliberately loose - it has to accept `1:1.2.13.dfsg-1` (deb epoch),
 * `3.0.14-1~deb12u2`, `33.3.1-jre`, and `4.5.0-rc.1`. The one thing it insists on
 * is a leading digit, which is what separates a version from a package name in
 * the ambiguous whitespace and comma forms.
 */
const VERSION_LIKE = /^\d[0-9A-Za-z.:+~_-]*$/;

const PURL_PATTERN = /^pkg:([a-zA-Z0-9.+-]+)\/(.+)$/;

export interface ParsedBulkInput {
  entries: BulkEntry[];
  summary: BulkParseSummary;
}

export function parseBulkInput(input: string): ParsedBulkInput {
  const problems: BulkParseProblem[] = [];
  const parsed: BulkEntry[] = [];
  let contentLines = 0;
  let constraintsDropped = 0;

  // \r\n and bare \r both occur: Windows clipboards and pasted terminal output.
  const lines = input.split(/\r\n|\r|\n/);

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const raw = (lines[i] ?? "").trim();

    if (raw === "" || raw.startsWith("#") || raw.startsWith("//")) continue;
    contentLines++;

    const result = parseLine(raw, lineNo);
    if ("reason" in result) {
      problems.push({ line: lineNo, raw, reason: result.reason });
      continue;
    }
    if (result.versionKind === "version-ignored") constraintsDropped++;
    parsed.push(result);
  }

  /**
   * Collapse duplicates on the matching key rather than the raw text: `Express`
   * and `express` are one query because matching is case-insensitive, and running
   * both would produce two identical rows.
   */
  const seen = new Set<string>();
  const entries: BulkEntry[] = [];
  let duplicatesCollapsed = 0;
  for (const entry of parsed) {
    const key = matchKeyOf(entry);
    if (seen.has(key)) {
      duplicatesCollapsed++;
      continue;
    }
    seen.add(key);
    entries.push(entry);
  }

  const truncated = entries.length > BULK_SEARCH_MAX_ENTRIES;

  return {
    entries: truncated ? entries.slice(0, BULK_SEARCH_MAX_ENTRIES) : entries,
    summary: {
      lines: contentLines,
      entries: truncated ? BULK_SEARCH_MAX_ENTRIES : entries.length,
      duplicatesCollapsed,
      constraintsDropped,
      problems,
      truncated,
    },
  };
}

/**
 * The key two entries must share to be considered the same query.
 *
 * A `version-ignored` entry matches on name alone, so it collapses with a bare
 * name for the same package - `express` and `express@^4` ask the same question of
 * the database.
 */
export function matchKeyOf(entry: BulkEntry): string {
  const version = entry.versionKind === "exact" ? (entry.version ?? "") : "";
  return `${entry.name.toLowerCase()}\u0000${version}\u0000${entry.ecosystem ?? ""}`;
}

type LineResult = BulkEntry | { reason: string };

function parseLine(raw: string, line: number): LineResult {
  // Trailing separators survive copying out of a JSON array or a CSV column.
  let cleaned = raw.replace(/[,;]+$/, "").trim();
  if (cleaned === "") return { reason: "no package name on this line" };

  const purl = tryPurl(cleaned, line);
  if (purl) return purl;

  // `django >= 4.2` is one specifier written with spaces. Joining it here means
  // the field split below sees two fields, not three.
  cleaned = cleaned.replace(SPACED_OPERATOR, "$1");

  const fields = cleaned.split(/[\s,\t]+/).filter((f) => f !== "");
  if (fields.length > 2) {
    return { reason: "more than two fields - put one package on each line" };
  }

  if (fields.length === 2) {
    const [first, second] = fields as [string, string];
    const named = parseNameAndSpecifier(first, raw, line);
    if ("reason" in named) return named;
    if (named.version !== null) return { reason: "two versions on one line" };

    /*
     * The second field must actually look like a version specifier. Unlike the
     * `@` form - where `express@latest` is a legitimate dist-tag worth echoing
     * back - two bare words are far more likely a sentence than a package and a
     * version, so `my package` is reported rather than read as `my` at version
     * `package`.
     */
    const spec = readVersionSpec(second);
    if (spec === null || !(OPERATOR_PATTERN.test(second) || VERSION_LIKE.test(dropLeadingV(second)))) {
      return { reason: `"${second}" does not look like a version` };
    }
    return { ...named, raw, version: spec.version, versionKind: spec.kind };
  }

  return parseNameAndSpecifier(cleaned, raw, line);
}

/** `pkg:npm/@scope/name@1.0.0` - the one input form that names its own ecosystem. */
function tryPurl(value: string, line: number): BulkEntry | null {
  const match = PURL_PATTERN.exec(value);
  if (!match) return null;

  const ecosystem = (match[1] ?? "").toLowerCase();
  // Qualifiers and subpath play no part in matching; the name and version do.
  const remainder = (match[2] ?? "").split(/[?#]/)[0] ?? "";
  const split = splitTrailingAt(remainder);
  if (split.name === "") return null;

  return {
    line,
    raw: value,
    name: decodeURIComponent(split.name),
    version: split.rest === null ? null : decodeURIComponent(split.rest),
    versionKind: split.rest === null ? "any" : "exact",
    ecosystem,
  };
}

/**
 * Reads a token as a name plus an optional version specifier.
 *
 * Order matters. The `@` separator is resolved *before* any operator, because
 * `express@^1.2.3` is a name, a separator, and a constrained version - reading
 * the `^` as the separator would leave the name as `express@`.
 */
function parseNameAndSpecifier(token: string, raw: string, line: number): LineResult {
  const maven = tryMavenCoordinate(token, raw, line);
  if (maven) return maven;

  if (looksLikeUrl(token)) return { reason: "looks like a URL, not a package name" };

  const split = splitTrailingAt(token);
  if (split.rest !== null) {
    if (split.name === "") return { reason: "no package name on this line" };
    const spec = readVersionSpec(split.rest);
    if (spec === null) {
      return { line, raw, name: split.name, version: null, versionKind: "any", ecosystem: null };
    }
    return { line, raw, name: split.name, version: spec.version, versionKind: spec.kind, ecosystem: null };
  }

  // No `@`: the pip form, `django>=4.2`.
  const operator = OPERATOR_PATTERN.exec(stripLeadingName(token));
  if (operator) {
    const at = token.indexOf(operator[0]);
    if (at > 0) {
      const name = token.slice(0, at).trim();
      const spec = readVersionSpec(token.slice(at));
      if (name !== "" && spec !== null) {
        return { line, raw, name, version: spec.version, versionKind: spec.kind, ecosystem: null };
      }
    }
  }

  // `split.name`, not `token`: a trailing `@` with nothing after it has already
  // been stripped, and returning the raw token here would search for "express@".
  if (split.name === "") return { reason: "no package name on this line" };
  return { line, raw, name: split.name, version: null, versionKind: "any", ecosystem: null };
}

/** Everything from the first operator character onward, for detecting a pip pin. */
function stripLeadingName(token: string): string {
  const at = token.search(/[=<>!~^]/);
  return at < 0 ? "" : token.slice(at);
}

/**
 * Splits a trailing `@…` off a name.
 *
 * The whole subtlety of this parser. `lastIndexOf`, because
 * `@wb-track/shared-front@2.1.0` has two; and index > 0, because an `@` in
 * position zero is an npm scope marker, not a separator. A naive `split("@")`
 * mangles both scoped names and scoped names with versions.
 */
function splitTrailingAt(token: string): { name: string; rest: string | null } {
  const at = token.lastIndexOf("@");
  if (at <= 0) return { name: token, rest: null };

  const rest = token.slice(at + 1);
  // A trailing `@` with nothing after it is a typo, not a version.
  if (rest === "") return { name: token.slice(0, at), rest: null };
  return { name: token.slice(0, at), rest };
}

/**
 * Interprets the part after the separator.
 *
 * Returns null when there is nothing usable, which the caller turns into a
 * name-only match. `version` is always populated for display - the UI shows what
 * was asked for - while `kind` alone decides how it is matched.
 */
function readVersionSpec(input: string): { version: string; kind: BulkEntryVersionKind } | null {
  let value = input.trim();
  if (value === "") return null;

  let ignored = false;
  const operator = OPERATOR_PATTERN.exec(value);
  if (operator) {
    const op = operator[0];
    value = value.slice(op.length).trim();
    if (value === "") return null;
    if (!EXACT_OPERATORS.has(op)) ignored = true;
  }

  // pip's `==4.2.*` pins a prefix, not a value.
  if (value.endsWith(".*")) {
    value = value.slice(0, -2);
    ignored = true;
  }
  if (value === "") return null;

  const normalised = dropLeadingV(value);

  // A dist-tag (`latest`, `next`) or anything else that is not a version: shown,
  // but matched as name-only, for the same reason a range is.
  if (!VERSION_LIKE.test(normalised)) {
    return { version: value, kind: "version-ignored" };
  }

  return { version: normalised, kind: ignored ? "version-ignored" : "exact" };
}

/** `com.fasterxml.jackson.core:jackson-databind:2.17.2` -> jackson-databind @ 2.17.2. */
function tryMavenCoordinate(token: string, raw: string, line: number): BulkEntry | null {
  const parts = token.split(":");
  // Exactly three parts, the last version-like. The two-part form (`a:b`) is
  // deliberately not accepted: it cannot be told apart from a package name
  // containing a colon, and guessing would produce silent mismatches.
  if (parts.length !== 3) return null;

  const [group, artifact, version] = parts as [string, string, string];
  if (group === "" || artifact === "" || !VERSION_LIKE.test(version)) return null;
  // A group id always contains a dot. Without one this is more likely something
  // else that happens to have two colons.
  if (!group.includes(".")) return null;

  return {
    line,
    raw,
    // Syft catalogues maven components under the artifact id, which is what the
    // component table holds.
    name: artifact,
    version,
    versionKind: "exact",
    /*
     * `maven`, not `java-archive`. `component.ecosystem` is derived from the purl
     * type, so a maven package is stored as `maven`; `java-archive` is Syft's
     * *package type* property, which lives elsewhere. Using it here constrained
     * every maven coordinate to an ecosystem no component has, and the lookup
     * silently returned nothing.
     */
    ecosystem: "maven",
  };
}

/**
 * `v1.2.3` -> `1.2.3`.
 *
 * The form appears in release names and changelogs. No ecosystem records a
 * literal `v` in a package version field, so dropping it is a safe normalisation
 * rather than a guess.
 */
function dropLeadingV(value: string): string {
  return /^v\d/.test(value) ? value.slice(1) : value;
}

function looksLikeUrl(name: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(name);
}
