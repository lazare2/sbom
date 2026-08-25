// Jenkins shared-library step: run the vendored Python SAST scanner
// (sast-scan/) against a project's source and publish the results as a SARIF
// artifact.
//
// Independent of sbomScan.groovy on purpose: findings here are not uploaded
// to the SBOM platform or stored in its database — see sast-scan/README.md
// for why. The archived SARIF file is the deliverable.
//
// Usage in a Jenkinsfile:
//
//     sastScan()
//
// To scan a subdirectory, or to turn this into a real gate once a project has
// triaged its first set of findings:
//
//     sastScan(target: 'src', required: true)
//
// Requires:
//   - `python3` on the agent's PATH
//   - the sast-scan/ directory checked out alongside the Jenkinsfile (it lives
//     in this repo, so a multibranch pipeline sourced from here already has it;
//     other repos need it checked out as a second SCM step or a submodule)

def call(Map config = [:]) {
    String target             = config.target ?: '.'
    String severityThreshold  = config.severityThreshold ?: 'HIGH'
    String reportFile         = config.reportFile ?: 'sast-report.sarif'
    // sast-scan/tests/vulnerable_samples is deliberately vulnerable code — see
    // the GitLab template's SAST_EXCLUDE comment. Not needed once `target`
    // already points below sast-scan/.
    String exclude             = config.exclude ?: 'sast-scan'
    // Same reasoning as sbomScan's `required`: default false so this can be
    // rolled out to an existing pipeline without breaking it on day one.
    boolean required          = config.get('required', false)

    stage('SAST scan') {
        if (!fileExists('sast-scan/sast')) {
            error "sastScan: sast-scan/ not found at the repo root — check it out alongside the project first"
        }

        int scanStatus = sh(
            script: """
                set -eu
                echo "Scanning ${target} (severity >= ${severityThreshold})"
                PYTHONPATH="\$(pwd)/sast-scan" python3 -m sast "${target}" \
                    --exclude "${exclude}" \
                    --format sarif \
                    --severity-threshold "${severityThreshold}" \
                    > "${reportFile}"
            """,
            returnStatus: true
        )

        // Human-readable summary in the console log, independent of scanStatus
        // so it prints whether or not findings crossed the failing threshold.
        sh """
            PYTHONPATH="\$(pwd)/sast-scan" python3 -m sast "${target}" \
                --exclude "${exclude}" \
                --severity-threshold "${severityThreshold}" \
                --no-color || true
        """

        archiveArtifacts artifacts: reportFile, allowEmptyArchive: true

        if (scanStatus != 0) {
            String message = "sastScan: HIGH/CRITICAL findings present (see archived ${reportFile})"
            if (required) {
                error message
            }
            // Visible in the build result without failing it — same pattern as
            // sbomScan's non-required failure path.
            unstable(message + ". Pass required: true to make this a hard gate.")
        } else {
            echo "sastScan: no HIGH/CRITICAL findings"
        }
    }
}
