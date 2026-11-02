/**
 * Turning an advisory's raw fields into something a reader can act on.
 *
 * Everything here works from data the platform already holds - the CVSS vector, the CWE ids,
 * the reference links - so it needs no network access and invents nothing. The CVSS sentence
 * is a translation of the vector's metrics, not a summary written by anyone.
 */

/**
 * Names for the weaknesses that account for nearly every advisory against packages.
 *
 * Not the whole CWE catalogue (nearly a thousand entries): an id that is not here is still
 * shown and still links to its MITRE page, it just has no name beside it.
 */
const CWE_NAMES: Record<string, string> = {
  "CWE-20": "Improper input validation",
  "CWE-22": "Path traversal",
  "CWE-59": "Link following",
  "CWE-74": "Injection",
  "CWE-77": "Command injection",
  "CWE-78": "OS command injection",
  "CWE-79": "Cross-site scripting (XSS)",
  "CWE-89": "SQL injection",
  "CWE-93": "CRLF injection",
  "CWE-94": "Code injection",
  "CWE-113": "HTTP response splitting",
  "CWE-116": "Improper encoding or escaping of output",
  "CWE-119": "Memory buffer bounds not enforced",
  "CWE-120": "Classic buffer overflow",
  "CWE-125": "Out-of-bounds read",
  "CWE-129": "Improper validation of array index",
  "CWE-178": "Improper handling of case sensitivity",
  "CWE-190": "Integer overflow or wraparound",
  "CWE-191": "Integer underflow",
  "CWE-200": "Exposure of sensitive information",
  "CWE-203": "Observable discrepancy",
  "CWE-208": "Observable timing discrepancy",
  "CWE-209": "Sensitive information in error messages",
  "CWE-269": "Improper privilege management",
  "CWE-276": "Incorrect default permissions",
  "CWE-284": "Improper access control",
  "CWE-285": "Improper authorization",
  "CWE-287": "Improper authentication",
  "CWE-290": "Authentication bypass by spoofing",
  "CWE-295": "Improper certificate validation",
  "CWE-306": "Missing authentication for a critical function",
  "CWE-312": "Cleartext storage of sensitive information",
  "CWE-319": "Cleartext transmission of sensitive information",
  "CWE-327": "Broken or risky cryptographic algorithm",
  "CWE-330": "Insufficiently random values",
  "CWE-345": "Insufficient verification of data authenticity",
  "CWE-352": "Cross-site request forgery (CSRF)",
  "CWE-362": "Race condition",
  "CWE-367": "Time-of-check time-of-use race",
  "CWE-369": "Divide by zero",
  "CWE-400": "Uncontrolled resource consumption",
  "CWE-401": "Memory leak",
  "CWE-404": "Improper resource shutdown or release",
  "CWE-415": "Double free",
  "CWE-416": "Use after free",
  "CWE-426": "Untrusted search path",
  "CWE-434": "Unrestricted upload of dangerous file type",
  "CWE-436": "Interpretation conflict",
  "CWE-444": "HTTP request smuggling",
  "CWE-459": "Incomplete cleanup",
  "CWE-476": "NULL pointer dereference",
  "CWE-502": "Deserialization of untrusted data",
  "CWE-522": "Insufficiently protected credentials",
  "CWE-532": "Sensitive information in log files",
  "CWE-601": "Open redirect",
  "CWE-611": "XML external entity (XXE)",
  "CWE-617": "Reachable assertion",
  "CWE-639": "Authorization bypass through user-controlled key",
  "CWE-662": "Improper synchronization",
  "CWE-665": "Improper initialization",
  "CWE-667": "Improper locking",
  "CWE-668": "Exposure of resource to wrong sphere",
  "CWE-674": "Uncontrolled recursion",
  "CWE-680": "Integer overflow to buffer overflow",
  "CWE-693": "Protection mechanism failure",
  "CWE-703": "Improper handling of exceptional conditions",
  "CWE-704": "Incorrect type conversion or cast",
  "CWE-732": "Incorrect permissions on a critical resource",
  "CWE-754": "Improper check for unusual conditions",
  "CWE-770": "Resource allocation without limits",
  "CWE-772": "Resource not released after use",
  "CWE-787": "Out-of-bounds write",
  "CWE-798": "Hard-coded credentials",
  "CWE-834": "Excessive iteration",
  "CWE-835": "Infinite loop",
  "CWE-862": "Missing authorization",
  "CWE-863": "Incorrect authorization",
  "CWE-908": "Use of uninitialized resource",
  "CWE-915": "Mass assignment",
  "CWE-916": "Weak password hashing",
  "CWE-918": "Server-side request forgery (SSRF)",
  "CWE-922": "Insecure storage of sensitive information",
  "CWE-1021": "Clickjacking",
  "CWE-1284": "Improper validation of specified quantity",
  "CWE-1321": "Prototype pollution",
  "CWE-1333": "Regular expression denial of service (ReDoS)",
  "CWE-1336": "Template injection",
};

export function cweName(id: string): string | null {
  return CWE_NAMES[id.toUpperCase()] ?? null;
}

export function cweUrl(id: string): string {
  const n = id.replace(/^CWE-/i, "");
  return `https://cwe.mitre.org/data/definitions/${encodeURIComponent(n)}.html`;
}

// --- CVSS -------------------------------------------------------------------

export interface CvssMetric {
  label: string;
  value: string;
  /** True when this value makes the flaw easier to exploit or worse when exploited. */
  severe: boolean;
}

export interface DecodedCvss {
  version: string;
  metrics: CvssMetric[];
  /** One plain-language sentence built from the metrics. */
  sentence: string;
}

const ACCESS: Record<string, string> = {
  N: "over the network",
  A: "from an adjacent network",
  L: "with local access",
  P: "with physical access",
};

const IMPACT_V3: Record<string, string> = { H: "High", L: "Low", N: "None" };
const IMPACT_V2: Record<string, string> = { C: "Complete", P: "Partial", N: "None" };

/**
 * A CVSS v2, v3.x or v4.0 vector as labelled metrics and one sentence.
 *
 * Returns null for anything it cannot read rather than a partial guess: the raw vector is
 * still on screen beside it, and a wrong translation would be worse than none.
 */
export function decodeCvss(vector: string | null | undefined): DecodedCvss | null {
  if (!vector) return null;
  const parts = vector.trim().split("/");
  let version = "2.0";
  const head = parts[0] ?? "";
  if (/^CVSS:\d/.test(head)) {
    version = head.slice(5);
    parts.shift();
  }
  const m: Record<string, string> = {};
  for (const part of parts) {
    const [key, value] = part.split(":");
    if (key && value) m[key] = value;
  }

  const av = m.AV;
  if (!av || !ACCESS[av]) return null;

  const metrics: CvssMetric[] = [];
  const add = (label: string, value: string | undefined, severe: boolean) => {
    if (value !== undefined) metrics.push({ label, value, severe });
  };

  add("Attack vector", { N: "Network", A: "Adjacent network", L: "Local", P: "Physical" }[av], av === "N");
  add("Attack complexity", m.AC === "L" ? "Low" : m.AC === "H" ? "High" : m.AC === "M" ? "Medium" : undefined, m.AC === "L");

  let privileges: string;
  let interaction: string;
  let impacts: Array<[string, string | undefined]>;

  if (version.startsWith("2")) {
    const au = { N: "None", S: "Single", M: "Multiple" }[m.Au ?? ""];
    add("Authentication", au, m.Au === "N");
    privileges = m.Au === "N" ? "without authenticating" : "after authenticating";
    interaction = "";
    impacts = [
      ["confidentiality", IMPACT_V2[m.C ?? ""]],
      ["integrity", IMPACT_V2[m.I ?? ""]],
      ["availability", IMPACT_V2[m.A ?? ""]],
    ];
  } else {
    if (version.startsWith("4")) add("Attack requirements", m.AT === "N" ? "None" : m.AT === "P" ? "Present" : undefined, m.AT === "N");
    add("Privileges required", IMPACT_V3[m.PR ?? ""], m.PR === "N");
    const ui = version.startsWith("4")
      ? { N: "None", P: "Passive", A: "Active" }[m.UI ?? ""]
      : { N: "None", R: "Required" }[m.UI ?? ""];
    add("User interaction", ui, m.UI === "N");
    if (!version.startsWith("4")) add("Scope", m.S === "C" ? "Changed" : m.S === "U" ? "Unchanged" : undefined, m.S === "C");
    privileges =
      m.PR === "N" ? "without any privileges" : m.PR === "L" ? "by a user with basic privileges" : "only with high privileges";
    interaction = m.UI === "N" ? " and without anyone else doing anything" : " but needs a user to take some action";
    const c = version.startsWith("4") ? m.VC : m.C;
    const i = version.startsWith("4") ? m.VI : m.I;
    const a = version.startsWith("4") ? m.VA : m.A;
    impacts = [
      ["confidentiality", IMPACT_V3[c ?? ""]],
      ["integrity", IMPACT_V3[i ?? ""]],
      ["availability", IMPACT_V3[a ?? ""]],
    ];
  }

  for (const [what, level] of impacts) {
    add(`${what[0]!.toUpperCase()}${what.slice(1)} impact`, level, level === "High" || level === "Complete");
  }

  const how = [ACCESS[av], m.AC === "H" ? "but only under specific conditions" : null, `${privileges}${interaction}`]
    .filter(Boolean)
    .join(", ");
  const harmed = impacts.filter(([, level]) => level && level !== "None");
  const consequence =
    harmed.length === 0
      ? "Exploiting it has no direct impact on confidentiality, integrity or availability."
      : `If exploited: ${harmed.map(([what, level]) => `${level!.toLowerCase()} impact on ${what}`).join(", ")}.`;
  const sentence = `An attacker can exploit this ${how}. ${consequence}`;

  return { version, metrics, sentence };
}

// --- references -----------------------------------------------------------------

export type ReferenceKind = "advisory" | "fix" | "report" | "other";

export const REFERENCE_KIND_LABELS: Record<ReferenceKind, string> = {
  advisory: "Advisories",
  fix: "Fixes and patches",
  report: "Issues and reports",
  other: "Other references",
};

/** A best-effort reading of what a reference link is, from its URL alone. */
export function referenceKind(url: string): ReferenceKind {
  const u = url.toLowerCase();
  if (/\/commit\/|\/commits\/|\/pull\/|\/merge_requests\/|\/compare\/|\/releases\/tag\//.test(u)) return "fix";
  if (/\/issues\/|bugzilla|\/jira\/|\/browse\/[a-z]+-\d+|hackerone\.com|huntr\.(dev|com)/.test(u)) return "report";
  if (
    /nvd\.nist\.gov|cve\.org|cve\.mitre\.org|github\.com\/advisories|github\.com\/[^/]+\/[^/]+\/security\/advisories|osv\.dev|\/security\b|security-tracker|securitytracker|access\.redhat\.com\/(errata|security)|ubuntu\.com\/security|alas\.aws|lists\.debian\.org\/debian-security|cisa\.gov/.test(
      u,
    )
  ) {
    return "advisory";
  }
  return "other";
}

export function groupReferences(urls: readonly string[]): Array<[ReferenceKind, string[]]> {
  const groups = new Map<ReferenceKind, string[]>();
  for (const url of urls) {
    const kind = referenceKind(url);
    groups.set(kind, [...(groups.get(kind) ?? []), url]);
  }
  return (["advisory", "fix", "report", "other"] as const)
    .filter((kind) => groups.has(kind))
    .map((kind) => [kind, groups.get(kind)!]);
}

/** The line to show where there is room for only one: the title, else the description's first sentence. */
export function advisoryHeadline(advisory: { summary: string | null; description: string | null }): string | null {
  if (advisory.summary) return advisory.summary;
  if (!advisory.description) return null;
  const firstLine = advisory.description.split("\n")[0]!.trim();
  const sentence = /^(.{20,240}?[.!?])\s/.exec(firstLine + " ");
  return sentence ? sentence[1]! : firstLine;
}
