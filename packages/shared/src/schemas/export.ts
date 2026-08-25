import { z } from "zod";

/**
 * Machine-readable exports of the inventory this platform already holds.
 *
 * ## Why this exists when a raw download already does
 *
 * `GET /scans/:id/raw` returns the uploaded CycloneDX byte for byte, and that stays the
 * right answer for "what did the pipeline actually produce". It cannot answer three other
 * questions, which is what this module is for:
 *
 *   - **A different format.** Syft emitted CycloneDX. A consumer who requires SPDX cannot be
 *     served by re-running the tool, because the artifact that was scanned is long gone.
 *   - **A different subject.** The raw blob is one build of one application. "The SBOM for
 *     the payments platform" spans a group, and "the SBOM for payments-api" means whichever
 *     build is current, which is a moving target the caller should not have to resolve.
 *   - **A different content.** The uploaded document knows nothing about vulnerabilities,
 *     malicious packages, or which half of the image a package came from. This platform does.
 *
 * ## The two flavours are a disclosure boundary, not a verbosity setting
 *
 * `inventory` is what you hand to somebody outside: the packages, and nothing else.
 * `enriched` adds this platform's findings -- vulnerabilities, malicious-package matches,
 * origin -- and is for internal use. The split exists because those are different audiences
 * with different rights to the data, and a single "include everything" flag would make
 * leaking the second one to the first a matter of forgetting a query parameter.
 */

export const exportFormats = ["cyclonedx", "spdx"] as const;
export type ExportFormat = (typeof exportFormats)[number];

export const exportFlavours = ["inventory", "enriched"] as const;
export type ExportFlavour = (typeof exportFlavours)[number];

/**
 * Spec versions are pinned rather than tracking the newest release.
 *
 * An export is consumed by somebody else's tooling, and a document that silently changes
 * shape underneath them is worse than one that is a version behind. Both of these are the
 * widely-supported current majors.
 */
export const CYCLONEDX_SPEC_VERSION = "1.6";
export const SPDX_SPEC_VERSION = "SPDX-2.3";

export const EXPORT_MEDIA_TYPES: Record<ExportFormat, string> = {
  cyclonedx: "application/vnd.cyclonedx+json",
  spdx: "application/spdx+json",
};

export const EXPORT_FORMAT_LABELS: Record<ExportFormat, string> = {
  cyclonedx: "CycloneDX",
  spdx: "SPDX",
};

export const EXPORT_FLAVOUR_LABELS: Record<ExportFlavour, string> = {
  inventory: "Inventory only",
  enriched: "Inventory with findings",
};

export const EXPORT_FLAVOUR_HINTS: Record<ExportFlavour, string> = {
  inventory: "Packages and versions. Safe to send outside the organisation.",
  enriched:
    "Adds vulnerabilities, malicious-package matches and where each package came from. Internal use.",
};

/**
 * `flavour` deliberately has no effect on SPDX.
 *
 * SPDX 2.3 has no native place to put a vulnerability finding -- CycloneDX does, in
 * `vulnerabilities[]`. Rather than invent an annotation format that no SPDX consumer would
 * read, an SPDX export is always the inventory, and the route says so in the response rather
 * than silently ignoring the parameter.
 */
export const exportQuerySchema = z.object({
  format: z.enum(exportFormats).default("cyclonedx"),
  flavour: z.enum(exportFlavours).default("inventory"),
});
export type ExportQuery = z.infer<typeof exportQuerySchema>;

export function supportsFlavour(format: ExportFormat, flavour: ExportFlavour): boolean {
  return format === "cyclonedx" || flavour === "inventory";
}

/** Filename stem plus extension, so a browser download lands with a name that says what it is. */
export function exportFilename(args: {
  subject: string;
  format: ExportFormat;
  flavour: ExportFlavour;
}): string {
  const stem = args.subject
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  const safe = stem.length > 0 ? stem.slice(0, 80) : "export";
  const kind = args.format === "spdx" ? "spdx" : "cyclonedx";
  const suffix = args.flavour === "enriched" && args.format === "cyclonedx" ? "-findings" : "";
  return `${safe}-${kind}${suffix}.json`;
}
