import type { ScanSummary } from "@sbom/shared";
import { formatDateTime, formatNumber, shortSha } from "../lib/format.ts";
import { Button, FormError, Modal, Mono } from "./ui.tsx";

/**
 * Confirmation for removing one build from the history.
 *
 * A plain confirmation rather than the type-the-name gate used for deleting an
 * application. That gate exists because deleting an application destroys its entire
 * scan record at once; this destroys one build, and the routine reason to reach for
 * it — an SBOM uploaded against the wrong application, minutes earlier — should not
 * be made tedious. What the dialog owes the reader instead is precision about which
 * build is selected and what changes when it goes, both of which the history table
 * itself cannot show.
 *
 * The current-build case is called out separately because it is the one with
 * consequences beyond the row: the application's components, findings and every
 * figure derived from them revert to the previous build the moment this completes.
 */
export function DeleteScanModal({
  scan,
  applicationName,
  isOnlyScan,
  busy,
  error,
  onClose,
  onConfirm,
}: {
  scan: ScanSummary | null;
  applicationName: string;
  isOnlyScan: boolean;
  busy: boolean;
  error: unknown;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Modal
      open={scan !== null}
      onClose={onClose}
      title="Delete this build"
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" onClick={onConfirm} disabled={busy}>
            {busy ? "Deleting…" : "Delete build"}
          </Button>
        </>
      }
    >
      {scan ? (
        <div className="space-y-3 text-sm text-text-muted">
          <FormError error={error} />

          {/* Identifies the row that was clicked. The table sorts on seven columns, so
              "the one you selected" is not a safe thing to leave implicit. */}
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 rounded-md border border-border-base bg-bg-subtle px-3 py-2 text-xs">
            <dt className="text-text-faint">Scanned</dt>
            <dd className="text-text-base">{formatDateTime(scan.createdAt)}</dd>
            <dt className="text-text-faint">Build</dt>
            <dd className="text-text-base">{scan.buildNumber ?? "—"}</dd>
            <dt className="text-text-faint">Commit</dt>
            <dd>
              <Mono>{shortSha(scan.commitSha)}</Mono>
            </dd>
            <dt className="text-text-faint">Components</dt>
            <dd className="nums text-text-base">{formatNumber(scan.componentCount)}</dd>
          </dl>

          {scan.isLatest ? (
            isOnlyScan ? (
              <p>
                This is the only build{" "}
                <strong className="text-text-base">{applicationName}</strong> has. Deleting it
                returns the application to never scanned — it keeps its name, attributes and
                group membership, but has no components, no findings and no current state until
                something uploads an SBOM again.
              </p>
            ) : (
              <p>
                This is the application&rsquo;s{" "}
                <strong className="text-text-base">current build</strong>. The build before it
                becomes current, and {applicationName}&rsquo;s component list, findings and its
                contribution to the dashboard and analytics revert with it.
              </p>
            )
          ) : (
            <p>
              An older build. The application&rsquo;s current state is unaffected, but this build
              disappears from diffs, and any package it was the last to ship stops appearing in
              the removed-packages view.
            </p>
          )}

          <p>
            The scan record and its component list are removed permanently, along with the
            original uploaded SBOM unless another build holds a byte-identical copy. There is no
            undo. The deletion is recorded in the audit log.
          </p>
        </div>
      ) : null}
    </Modal>
  );
}
