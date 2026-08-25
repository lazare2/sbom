import {
  MALICIOUS_CORROBORATION_HINTS,
  MALICIOUS_CORROBORATION_LABELS,
  type MaliciousCorroboration,
} from "@sbom/shared";
import { Badge } from "./ui.tsx";
import type { BadgeTone } from "./ui.tsx";

/**
 * How many independent parties reported a package as malicious.
 *
 * ## The tone choices are the whole design
 *
 * `corroborated` is the only tier with a positive tone, and it is `info` rather than `ok`.
 * Green would read as "this one is fine", which is the opposite of what it says: it means
 * several scanners agree the package is malware. There is no good news on this page and the
 * palette must not imply any.
 *
 * The other two are `neutral`, not `warn`. A single-source finding is not a *problem* — it is
 * the ordinary case, 77% of the feed. Colouring three quarters of every table amber would
 * teach people to ignore amber, and the day a genuinely unusual finding appears nobody would
 * see it.
 *
 * ## The reporters are always shown
 *
 * Same rule as the origin label on component locations: a derived judgement never appears
 * without the evidence it was derived from. "Corroborated" over `amazon-inspector,
 * ghsa-malware` is checkable. "Corroborated" on its own is a claim the reader has to take on
 * trust, and this platform does not ask for that anywhere else.
 */

const TONES: Record<MaliciousCorroboration, BadgeTone> = {
  corroborated: "info",
  single_source: "neutral",
  unattributed: "neutral",
};

export function CorroborationBadge({
  corroboration,
  sources,
  reporterCount,
}: {
  corroboration: MaliciousCorroboration;
  sources: string[];
  reporterCount: number;
}) {
  return (
    <div className="space-y-1">
      <Badge
        tone={TONES[corroboration]}
        title={MALICIOUS_CORROBORATION_HINTS[corroboration]}
      >
        {MALICIOUS_CORROBORATION_LABELS[corroboration]}
        {/*
          The count only appears where it adds something. "Corroborated · 3" says more than
          "Corroborated"; "Single source · 1" and "Unattributed · 0" would just be noise
          restating the label.
        */}
        {reporterCount >= 2 ? ` · ${reporterCount}` : ""}
      </Badge>

      {sources.length > 0 ? (
        <p className="text-[11px] leading-snug break-words text-text-faint">
          {sources.join(", ")}
        </p>
      ) : (
        <p className="text-[11px] leading-snug text-text-faint">no reporter recorded</p>
      )}
    </div>
  );
}
