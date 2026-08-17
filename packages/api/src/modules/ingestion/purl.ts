/**
 * Minimal Package URL handling.
 *
 * We deliberately do not pull in a full purl library: the only field we need to
 * extract is the type, and a normalising pass over the qualifier string. A
 * regex does both in a fraction of the time, which matters when a single
 * container SBOM can carry tens of thousands of components.
 *
 * Spec: https://github.com/package-url/purl-spec
 */

const PURL_TYPE_RE = /^pkg:\/?\/?([^/@?#]+)\//i;

/** `pkg:deb/debian/libc6@2.36?arch=amd64` -> `deb`. Null if not a parseable purl. */
export function purlType(purl: string): string | null {
  const match = PURL_TYPE_RE.exec(purl.trim());
  if (!match?.[1]) return null;
  // purl types are case-insensitive and canonically lowercase.
  return match[1].toLowerCase();
}

/**
 * Canonicalise a purl so the same package always hashes to the same identity.
 *
 * Qualifier order is not semantically meaningful in a purl, but Syft has changed
 * its emission order between versions. Without sorting, a Syft upgrade would
 * fork every OS package in the component table into a second row that looks like
 * a different package — inflating storage and, worse, making "which apps use
 * libc6 2.36" quietly return half the answer.
 *
 * Lowercases the scheme and type only. The namespace, name, and version are
 * left alone: they are case-sensitive for several ecosystems (e.g. maven
 * groupIds, golang module paths).
 */
export function normalizePurl(purl: string): string {
  const trimmed = purl.trim();
  if (trimmed === "") return trimmed;

  // Split off the subpath (#) first, then the qualifiers (?), per spec order.
  const hashAt = trimmed.indexOf("#");
  const subpath = hashAt === -1 ? "" : trimmed.slice(hashAt);
  const withoutSubpath = hashAt === -1 ? trimmed : trimmed.slice(0, hashAt);

  const qAt = withoutSubpath.indexOf("?");
  const base = qAt === -1 ? withoutSubpath : withoutSubpath.slice(0, qAt);
  const query = qAt === -1 ? "" : withoutSubpath.slice(qAt + 1);

  const normalizedBase = base.replace(/^pkg:\/?\/?([^/@?#]+)\//i, (_m, type: string) => `pkg:${type.toLowerCase()}/`);

  if (query === "") return `${normalizedBase}${subpath}`;

  const qualifiers = query
    .split("&")
    .filter((pair) => pair !== "")
    .map((pair) => {
      const eq = pair.indexOf("=");
      // Qualifier keys are case-insensitive and canonically lowercase; values are not.
      if (eq === -1) return { key: pair.toLowerCase(), value: "" };
      return { key: pair.slice(0, eq).toLowerCase(), value: pair.slice(eq + 1) };
    })
    // Per spec, an empty qualifier value means the qualifier is absent.
    .filter((q) => q.value !== "")
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

  if (qualifiers.length === 0) return `${normalizedBase}${subpath}`;

  const rebuilt = qualifiers.map((q) => `${q.key}=${q.value}`).join("&");
  return `${normalizedBase}?${rebuilt}${subpath}`;
}
