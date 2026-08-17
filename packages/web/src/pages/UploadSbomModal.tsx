import { useState } from "react";
import { Link } from "react-router";
import type { DuplicateSbomDetails, ManualUploadResponse } from "@sbom/shared";
import { ApiError } from "../lib/api.ts";
import { useUploadSbom } from "../lib/mutations.ts";
import { formatBytes, formatDateTime, formatNumber } from "../lib/format.ts";
import { Button, FormError, FormRow, Modal, Mono, TextInput, Textarea } from "../components/ui.tsx";

/**
 * Manual SBOM upload for one application.
 *
 * The modal has three states, and separating them is the point: the form, the
 * duplicate warning, and the receipt. Collapsing the last two into a toast would
 * lose the two things a person actually needs after uploading — a link to the scan
 * they just created, and the component count to sanity-check against what they
 * expected.
 */
export function UploadSbomModal({
  open,
  onClose,
  applicationId,
  applicationName,
}: {
  open: boolean;
  onClose: () => void;
  applicationId: string;
  applicationName: string;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [buildNumber, setBuildNumber] = useState("");
  const [commitSha, setCommitSha] = useState("");
  const [branch, setBranch] = useState("");
  const [imageRef, setImageRef] = useState("");
  const [note, setNote] = useState("");
  const [result, setResult] = useState<ManualUploadResponse | null>(null);

  const upload = useUploadSbom();

  /**
   * The 409 the server returns when this application already holds these exact
   * bytes, pulled out of the error so the duplicate can be rendered as a decision
   * rather than as a failure.
   */
  const duplicate = duplicateDetailsOf(upload.error);

  function submit(allowDuplicate: boolean) {
    if (!file) return;
    upload.mutate(
      {
        applicationId,
        file,
        buildNumber: buildNumber.trim(),
        commitSha: commitSha.trim(),
        branch: branch.trim(),
        imageRef: imageRef.trim(),
        note: note.trim(),
        allowDuplicate,
      },
      { onSuccess: setResult },
    );
  }

  function close() {
    // Reset here rather than in an effect: the modal unmounts its body when
    // closed, but this component itself stays mounted, so nothing else clears the
    // previous upload's receipt before the next opening.
    setFile(null);
    setBuildNumber("");
    setCommitSha("");
    setBranch("");
    setImageRef("");
    setNote("");
    setResult(null);
    upload.reset();
    onClose();
  }

  if (result) {
    return (
      <Modal open={open} onClose={close} title="SBOM uploaded" footer={<Button onClick={close}>Done</Button>}>
        <UploadReceipt result={result} onClose={close} />
      </Modal>
    );
  }

  return (
    <Modal
      open={open}
      onClose={close}
      title={`Upload an SBOM for ${applicationName}`}
      wide
      footer={
        <>
          <Button onClick={close} disabled={upload.isPending}>
            Cancel
          </Button>
          {duplicate ? (
            <Button variant="danger" onClick={() => submit(true)} disabled={upload.isPending}>
              {upload.isPending ? "Uploading…" : "Upload anyway"}
            </Button>
          ) : (
            <Button variant="primary" onClick={() => submit(false)} disabled={!file || upload.isPending}>
              {upload.isPending ? "Uploading…" : "Upload SBOM"}
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-xs text-text-muted">
          The file is stored and processed exactly as one posted by a CI pipeline: its packages become
          searchable across the estate, it appears in this application's build history and diffs, and{" "}
          <strong className="font-semibold text-text-base">it becomes the current build</strong> — the
          state every other view reports for {applicationName}.
        </p>

        <FormRow
          label="CycloneDX JSON file"
          htmlFor="sbom-file"
          hint={
            <>
              Generate it with <Mono>syft &lt;image&gt; -o cyclonedx-json</Mono>. CycloneDX is the only
              format this platform reads.
            </>
          }
        >
          <input
            id="sbom-file"
            type="file"
            accept=".json,application/json"
            onChange={(e) => {
              setFile(e.target.files?.[0] ?? null);
              // A new file invalidates a duplicate warning about the previous one,
              // which would otherwise leave the footer offering "Upload anyway"
              // for bytes the user has already replaced.
              upload.reset();
            }}
            className="w-full cursor-pointer rounded-md border border-border-strong bg-bg-raised text-sm text-text-base file:mr-3 file:cursor-pointer file:border-0 file:border-r file:border-border-strong file:bg-bg-subtle file:px-3 file:py-1.5 file:text-sm file:text-text-base hover:file:bg-bg-raised"
          />
        </FormRow>

        {file ? (
          <p className="text-xs text-text-faint">
            Selected <Mono>{file.name}</Mono> · {formatBytes(file.size)}
          </p>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2">
          <FormRow label="Build number" htmlFor="up-build" hint="Optional. Shown in the history table.">
            <TextInput id="up-build" value={buildNumber} onChange={setBuildNumber} placeholder="e.g. 402" />
          </FormRow>
          <FormRow label="Branch" htmlFor="up-branch" hint="Optional.">
            <TextInput id="up-branch" value={branch} onChange={setBranch} placeholder="e.g. main" />
          </FormRow>
          <FormRow label="Commit SHA" htmlFor="up-commit" hint="Optional. Ties the build to source.">
            <TextInput id="up-commit" value={commitSha} onChange={setCommitSha} placeholder="40-char sha" />
          </FormRow>
          <FormRow
            label="Image reference"
            htmlFor="up-image"
            hint="Optional. Taken from the SBOM itself if left blank."
          >
            <TextInput
              id="up-image"
              value={imageRef}
              onChange={setImageRef}
              placeholder="registry/app:tag"
            />
          </FormRow>
        </div>

        <FormRow
          label="Why is this being uploaded by hand?"
          htmlFor="up-note"
          hint="Optional, but worth filling in — it is the only record of why this build did not come from a pipeline."
        >
          <Textarea
            id="up-note"
            rows={2}
            value={note}
            onChange={setNote}
            placeholder="e.g. pipeline not wired up yet; scanned locally from the release image"
          />
        </FormRow>

        {duplicate ? (
          <DuplicateWarning duplicate={duplicate} />
        ) : (
          <FormError error={upload.error} />
        )}
      </div>
    </Modal>
  );
}

/**
 * The already-uploaded case.
 *
 * Rendered instead of the generic error banner because it is not really an error:
 * the answer is "you may already have this", and the useful response is either to
 * go look at the existing scan or to say yes, record it twice on purpose.
 */
function DuplicateWarning({ duplicate }: { duplicate: DuplicateSbomDetails }) {
  return (
    <div role="alert" className="rounded-md border border-warn bg-warn-subtle px-3 py-2.5 text-xs text-warn">
      <p className="font-semibold">This application already has this exact SBOM.</p>
      <p className="mt-1">
        Byte-for-byte identical to{" "}
        <Link to={`/scans/${duplicate.existingScanId}`} className="underline">
          the scan from {formatDateTime(duplicate.existingScanCreatedAt)}
        </Link>
        {duplicate.existingBuildNumber ? ` (build ${duplicate.existingBuildNumber})` : ""}
        {duplicate.existingIsLatest ? ", which is the current build" : ""}. Uploading again records a
        second identical build in the history — useful only if you mean to.
      </p>
    </div>
  );
}

/** What was actually stored. The scan link is the part that matters. */
function UploadReceipt({ result, onClose }: { result: ManualUploadResponse; onClose: () => void }) {
  return (
    <div className="space-y-3 text-sm">
      <p className="text-text-muted">
        Stored as a scan of{" "}
        <span className="font-medium text-text-base">{result.applicationName}</span> with{" "}
        <span className="font-medium text-text-base">{formatNumber(result.componentCount)}</span>{" "}
        component{result.componentCount === 1 ? "" : "s"}.
      </p>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 rounded-md border border-border-base bg-bg-subtle px-3 py-2.5 text-xs">
        <dt className="text-text-muted">Current build</dt>
        <dd className="text-text-base">{result.becameLatest ? "Yes — this scan" : "No"}</dd>
        {result.skippedComponents > 0 ? (
          <>
            <dt className="text-text-muted">Entries skipped</dt>
            {/* Surfaced, not buried: a nameless or file-type component is normal,
                but a large count means the SBOM is not what the uploader thinks. */}
            <dd className="text-text-base" title="Components with no name, or of an excluded type such as `file`.">
              {formatNumber(result.skippedComponents)}
            </dd>
          </>
        ) : null}
        {result.duplicateOfScanId ? (
          <>
            <dt className="text-text-muted">Duplicate of</dt>
            <dd>
              <Link
                to={`/scans/${result.duplicateOfScanId}`}
                onClick={onClose}
                className="text-accent hover:underline"
              >
                an earlier scan
              </Link>
            </dd>
          </>
        ) : null}
      </dl>

      <Link
        to={`/scans/${result.scanId}`}
        onClick={onClose}
        className="inline-flex items-center rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-hover"
      >
        View the scan →
      </Link>
    </div>
  );
}

/**
 * Reads the duplicate payload off a 409.
 *
 * Checks the code rather than trusting the shape: `details` is `unknown` on
 * ApiError, and another 409 from the same endpoint would otherwise be rendered as
 * a duplicate warning with empty fields.
 */
function duplicateDetailsOf(error: unknown): DuplicateSbomDetails | null {
  if (!(error instanceof ApiError) || error.status !== 409) return null;
  const details = error.details;
  if (typeof details !== "object" || details === null) return null;
  const candidate = details as Partial<DuplicateSbomDetails>;
  if (typeof candidate.existingScanId !== "string") return null;
  return {
    existingScanId: candidate.existingScanId,
    existingScanCreatedAt: candidate.existingScanCreatedAt ?? "",
    existingBuildNumber: candidate.existingBuildNumber ?? null,
    existingIsLatest: candidate.existingIsLatest === true,
  };
}
