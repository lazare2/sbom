import { SUPPORT_LIST_AS_OF, supportStatus, type ScanPlatform } from "@sbom/shared";
import { Badge } from "./ui.tsx";

/**
 * Marks a base image or runtime that is out of security support, or nearly, from the list
 * shipped with the release. Says nothing about what is not on the list: unknown is not "fine".
 */
export function SupportMarks({ platform }: { platform: ScanPlatform | null }) {
  const marks = supportStatus(platform).filter((s) => s.ended || s.endsSoon);
  if (marks.length === 0) return null;
  return (
    <span className="mt-1 flex flex-wrap gap-1">
      {marks.map((s) => (
        <Badge
          key={s.label}
          tone={s.ended ? "danger" : "warn"}
          title={`Security support ${s.ended ? "ended" : "ends"} on ${s.endsOn}. From the support list shipped with this release (as of ${SUPPORT_LIST_AS_OF}).`}
        >
          {s.label}: {s.ended ? `out of support since ${s.endsOn}` : `support ends ${s.endsOn}`}
        </Badge>
      ))}
    </span>
  );
}
