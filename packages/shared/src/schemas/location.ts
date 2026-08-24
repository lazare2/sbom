import { osPackageEcosystems } from "./vulnerability.js";

/**
 * Where a package physically sits inside the artifact that was scanned.
 *
 * ## Why this exists
 *
 * Every other part of the platform answers "what do you have" and "is it dangerous". Neither
 * answers the question somebody actually asks next, which is "where is it, so I can go and
 * remove it". A finding that names `lodash@4.17.20` and stops there leaves the reader grepping
 * a container image by hand.
 *
 * ## What the data actually looks like
 *
 * Syft records locations in the CycloneDX `properties` array as `syft:location:N:path` and
 * `syft:location:N:layerID`. Measured against two real images:
 *
 *   node:20-alpine     224 stored components, 223 carry a location  (99.6%)
 *   python:3.12-slim   104 stored components, 103 carry a location  (99.0%)
 *
 * The one component without a location in each is the `operating-system` marker, which does
 * not have a path in any meaningful sense. So coverage is effectively total.
 *
 * ## The finding that shaped the design
 *
 * For OS package managers the recorded path is the *package database*, not the package:
 *
 *   apk   /lib/apk/db/installed            identical for all 18 apk packages in the image
 *   deb   /var/lib/dpkg/info/<pkg>.list    185 of these in python:3.12-slim
 *   deb   /var/lib/dpkg/status             87 more
 *   deb   /usr/share/doc/<pkg>/copyright
 *
 * One deb package carried 81 such locations. None of them tell you where the package's files
 * are, so presenting them as "the path" would be worse than presenting nothing. OS packages
 * are therefore stored with no paths at all and labelled {@link ComponentOrigin} `os_package`,
 * which is both more correct and very much cheaper: OS packages are the overwhelming majority
 * of components in a container image, so skipping them removes almost all of the storage.
 *
 * Language-ecosystem packages are the opposite — the path is a genuine location:
 *
 *   npm      /usr/local/lib/node_modules/npm/node_modules/@isaacs/cliui/package.json
 *   binary   /usr/local/lib/python3.12/site-packages/pip/_vendor/distlib/t64.exe
 */

/**
 * How a package came to be in the artifact.
 *
 * Deliberately *not* derived from image layers. The obvious rule — "a layer that contains
 * distro packages is the base image" — was tested against real images and does not work:
 *
 *   node:20-alpine     layer A {npm: 203, binary: 1}   layer B {apk: 18, npm: 1}
 *   python:3.12-slim   every one of its three layers contains deb packages
 *
 * On the first, the rule labels Node's 203 global npm packages "application", but for anyone
 * whose Dockerfile says `FROM node:20-alpine` those are base image. On the second the rule has
 * no discriminating power at all. The layer digest is still recorded as ground truth, but it
 * cannot be turned into this label.
 */
export const componentOrigins = [
  /**
   * Installed by the distribution's package manager. Certain, not inferred: it follows from
   * the ecosystem alone, which is the same signal the vulnerability feature's base-image split
   * already uses.
   */
  "os_package",
  /**
   * Present in the image but outside the application's own tree — a language runtime's global
   * packages, something unpacked into `/opt`. Usually inherited from the base image, so the
   * fix belongs to whoever owns the Dockerfile's `FROM` line.
   */
  "image",
  /** Inside the application's own directory tree. The dependencies the application chose. */
  "application",
  /** No location was recorded, so no claim is made. Never rendered as either of the above. */
  "unknown",
] as const;
export type ComponentOrigin = (typeof componentOrigins)[number];

/**
 * Directory prefixes that mean "part of the image, not part of the app".
 *
 * A heuristic, and the only one in this feature. Two things make it acceptable:
 *
 *  1. It is small, closed and auditable — it is this list, and nothing else.
 *  2. **The label is never shown without the path beside it.** If the classification is wrong
 *     the reader sees `/usr/local/lib/node_modules/evil-pkg` and corrects it immediately. A
 *     heuristic that hides the evidence it was derived from would not be acceptable; one that
 *     always shows its working is a convenience rather than a claim.
 *
 * Note what is deliberately absent: a bare `/usr/` prefix. `/usr/src/app` is one of the most
 * common WORKDIRs there is, and folding it into "image" would misfile the app's own
 * dependencies in exactly the deployments most likely to be checking.
 */
const IMAGE_PATH_PREFIXES = [
  "/usr/lib/",
  "/usr/lib64/",
  "/usr/local/lib/",
  "/usr/local/lib64/",
  "/usr/share/",
  "/usr/local/share/",
  "/usr/bin/",
  "/usr/sbin/",
  "/usr/local/bin/",
  "/usr/local/sbin/",
  "/bin/",
  "/sbin/",
  "/lib/",
  "/lib64/",
  "/opt/",
  "/var/lib/",
  "/var/cache/",
  "/etc/",
  "/nix/store/",
] as const;

/**
 * Whether this ecosystem's recorded paths locate the package or merely its metadata.
 *
 * False for OS package managers — see the module comment. The caller skips storing paths
 * entirely in that case, so the absence is by design rather than missing data.
 *
 * Note this is not `isBaseImagePackage`: that folds in `kind === "runtime"`, and a runtime's
 * path (`/usr/local/bin/node`) is a real location worth keeping.
 */
export function ecosystemHasMeaningfulPaths(ecosystem: string): boolean {
  return !(osPackageEcosystems as readonly string[]).includes(ecosystem.trim().toLowerCase());
}

/**
 * Classify one component's origin from its ecosystem and its recorded paths.
 *
 * Derived at read time rather than stored, so the prefix list above can be corrected without a
 * migration and without a backfill. It is cheap — a handful of string comparisons per row.
 *
 * When a component sits at several paths and they disagree, **`application` wins**. A package
 * that appears in the application's own tree is a dependency the application has, whatever
 * else in the image also happens to carry a copy of it.
 */
export function classifyComponentOrigin(args: {
  ecosystem: string;
  paths: readonly string[] | null;
  /**
   * `os` short-circuits to `os_package`. This is the distro marker component, whose ecosystem
   * is recorded as `unknown` rather than as `deb`/`apk` and which would otherwise fall through
   * to `unknown` — technically true, but it is the one component whose origin is never in
   * doubt. `runtime` is deliberately not included: `/usr/local/bin/node` is a real location
   * and classifying it through the prefix list gives the better answer.
   */
  kind?: string | null;
}): ComponentOrigin {
  if (args.kind === "os") return "os_package";
  if (!ecosystemHasMeaningfulPaths(args.ecosystem)) return "os_package";
  if (!args.paths || args.paths.length === 0) return "unknown";

  let sawImagePath = false;
  for (const path of args.paths) {
    const normalized = normalizeLocationPath(path);
    if (normalized === null) continue;
    if (IMAGE_PATH_PREFIXES.some((prefix) => normalized.startsWith(prefix))) {
      sawImagePath = true;
    } else {
      // An application-tree path settles it; no need to look at the rest.
      return "application";
    }
  }

  return sawImagePath ? "image" : "unknown";
}

/**
 * Reduce a raw location string to a comparable absolute path, or null if it is unusable.
 *
 * Backslashes are folded to forward slashes because a Syft directory scan run on Windows
 * reports `\package-lock.json`, and a leading slash is added when absent so that a relative
 * path from a directory scan compares against the prefix list on the same terms. Directory
 * scans have no image to be part of, so their paths correctly fall through to `application`.
 */
export function normalizeLocationPath(raw: string): string | null {
  const trimmed = raw.trim().replace(/\\/g, "/");
  if (trimmed === "") return null;
  return trimmed.startsWith("/") ? trimmed : "/" + trimmed;
}

/**
 * Where a package was found, as returned to the client.
 *
 * `paths` is capped at {@link COMPONENT_LOCATION_PATH_CAP} while `pathCount` is the true
 * total, so a truncated list can say "3 of 81" rather than silently implying it is complete.
 * Null `paths` with a non-`os_package` origin means the SBOM carried no location — a
 * hand-written document, a non-Syft tool, or a scan ingested before this was recorded.
 */
export interface ComponentLocation {
  paths: string[] | null;
  /** Total locations before capping. Null whenever `paths` is null. */
  pathCount: number | null;
  /** Image layer digest, for image scans. Ground truth when the origin label looks wrong. */
  layerId: string | null;
  origin: ComponentOrigin;
}

/**
 * How many locations are kept per component per scan.
 *
 * Three rather than one because a package genuinely can be installed in more than one place
 * and seeing that is the point; three rather than all of them because the measured maximum on
 * a single real package was 81, and `scan_component` is the largest and hottest table in the
 * system.
 */
export const COMPONENT_LOCATION_PATH_CAP = 3;

/**
 * Wording for each origin, shared so no two screens describe the same state differently.
 *
 * `os_package` says where the information came from rather than pretending to a path, because
 * for those packages there is no path to give and saying so plainly is the honest rendering.
 */
export const COMPONENT_ORIGIN_LABELS: Record<ComponentOrigin, string> = {
  os_package: "Base image (OS package)",
  image: "Image",
  application: "Application",
  unknown: "Unknown",
};

export const COMPONENT_ORIGIN_HINTS: Record<ComponentOrigin, string> = {
  os_package:
    "Installed by the distribution's package manager. Its files are tracked in the package database rather than at a single path, so no location is recorded.",
  image:
    "Found outside the application's own directory tree, so it was almost certainly inherited from the base image rather than declared by this application.",
  application:
    "Found inside the application's own directory tree — a dependency this application pulled in.",
  unknown: "This SBOM recorded no location for the package, so no claim is made either way.",
};
