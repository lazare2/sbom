import { useState } from "react";
import {
  exportFilename,
  exportFlavours,
  exportFormats,
  supportsFlavour,
  EXPORT_FLAVOUR_HINTS,
  EXPORT_FLAVOUR_LABELS,
  EXPORT_FORMAT_LABELS,
  type ExportFlavour,
  type ExportFormat,
} from "@sbom/shared";
import { Button, FormRow, Modal, Select } from "./ui.tsx";

/**
 * Downloading the inventory, and the assessments that go with it.
 *
 * ## Why the flavour is a visible choice rather than a sensible default
 *
 * The two flavours are a disclosure boundary, not a verbosity setting. `inventory` is what
 * goes to a customer or a regulator; `enriched` carries this platform's findings and is for
 * internal use. Defaulting to the richer one and letting people trim it would mean the
 * accident -- sending an outside party a list of every unpatched vulnerability in the product
 * -- happens by forgetting a step rather than by taking one, and the wording below says which
 * is which rather than leaving it to be inferred from the word "enriched".
 *
 * ## VEX is offered beside the SBOM, not inside it
 *
 * They are separate documents on purpose: the inventory changes when the build changes, the
 * assessments change when somebody investigates. Publishing them together is the normal case,
 * which is why both live in this one dialog.
 */
export function ExportMenu({
  subject,
  kind,
  id,
  size = "sm",
}: {
  subject: string;
  kind: "applications" | "scans" | "groups";
  id: string;
  size?: "sm" | "md";
}) {
  const [open, setOpen] = useState(false);
  const [format, setFormat] = useState<ExportFormat>("cyclonedx");
  const [flavour, setFlavour] = useState<ExportFlavour>("inventory");

  const allowed = supportsFlavour(format, flavour);
  const href = `/api/v1/exports/${kind}/${id}?format=${format}&flavour=${flavour}`;
  const vexHref = `/api/v1/exports/${kind}/${id}/vex`;

  return (
    <>
      <Button size={size} variant="secondary" onClick={() => setOpen(true)}>
        Export…
      </Button>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title={`Export ${subject}`}
        footer={<Button onClick={() => setOpen(false)}>Close</Button>}
      >
        <div className="space-y-4">
          <FormRow label="Format" htmlFor="export-format">
            <Select
              id="export-format"
              value={format}
              onChange={(v) => {
                const next = v as ExportFormat;
                setFormat(next);
                /*
                  Fall back rather than leaving an impossible pair selected. SPDX 2.3 cannot
                  carry findings, and the API refuses the combination -- so offering a Download
                  button that is guaranteed to fail would be a trap rather than a safeguard.
                */
                if (!supportsFlavour(next, flavour)) setFlavour("inventory");
              }}
              ariaLabel="Export format"
              options={exportFormats.map((f) => ({ value: f, label: EXPORT_FORMAT_LABELS[f] }))}
            />
          </FormRow>

          <FormRow label="Contents" htmlFor="export-flavour">
            <Select
              id="export-flavour"
              value={flavour}
              onChange={(v) => setFlavour(v as ExportFlavour)}
              ariaLabel="Export contents"
              options={exportFlavours
                .filter((f) => supportsFlavour(format, f))
                .map((f) => ({ value: f, label: EXPORT_FLAVOUR_LABELS[f] }))}
            />
          </FormRow>

          {/*
            A left rule rather than a full bordered box. Boxed, sunken and full-width, this
            read as a disabled text input sitting between two real ones -- which is exactly
            the wrong signal for the sentence that says whether the file is safe to send
            outside the organisation.
          */}
          <p className="border-l-2 border-border-strong pl-3 text-xs text-text-muted">
            {EXPORT_FLAVOUR_HINTS[flavour]}
          </p>

          {format === "spdx" ? (
            <p className="text-xs text-text-faint">
              SPDX 2.3 has no representation for vulnerability findings, so only the inventory
              is available in this format.
            </p>
          ) : null}

          <div className="flex items-center gap-3">
            {/*
              A plain anchor, not a router Link: these are file downloads served with
              Content-Disposition, so the browser must handle the navigation natively rather
              than the SPA intercepting it.
            */}
            <a href={href} download={exportFilename({ subject, format, flavour })}>
              <Button variant="primary" disabled={!allowed}>
                Download SBOM
              </Button>
            </a>
            <span className="text-xs text-text-faint">
              {exportFilename({ subject, format, flavour })}
            </span>
          </div>

          <hr className="border-border" />

          <div className="space-y-2">
            <h3 className="text-sm font-medium text-text">Assessments (VEX)</h3>
            <p className="text-xs text-text-muted">
              What has been decided about the findings in this {kind === "groups" ? "group" : kind === "scans" ? "build" : "application"} — accepted risks,
              false positives and findings judged not to apply. Published beside the SBOM so a
              recipient can tell which findings you have already looked at.
            </p>
            <p className="text-xs text-text-faint">
              Only assessments that state what they claim are included. Any that predate that
              field are counted in the document rather than guessed at.
            </p>
            <div className="flex items-center gap-3 pt-1">
              <a href={vexHref} download>
                <Button variant="secondary">Download VEX</Button>
              </a>
              <span className="text-xs text-text-faint">CycloneDX VEX</span>
            </div>
          </div>
        </div>
      </Modal>
    </>
  );
}
