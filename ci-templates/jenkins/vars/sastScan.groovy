// Jenkins shared-library step: run the vendored Python SAST scanner
// (sast-scan/) against a project's source, publish the results as a SARIF
// artifact, and (when configured) post them to this platform.
//
// Usage in a Jenkinsfile:
//
//     sastScan(app: 'payments-api')
//
// To scan a subdirectory, or to turn this into a real gate once a project has
// triaged its first set of findings:
//
//     sastScan(app: 'payments-api', target: 'src', required: true)
//
// The SARIF artifact needs nothing beyond `python3` and needs no `app` at
// all — this step is a complete SAST gate on its own in a repo that has
// never heard of this platform. Posting to POST /api/v1/sast is additive:
// pass `app` (or set JOB_NAME to something usable, see defaultAppName below)
// and it uploads using the same `sbom-ingest-token` credential sbomScan.groovy
// uses by default, so a Jenkinsfile that already calls sbomScan() needs no
// new credential to add this. Requires an application named `app` already
// registered on the platform: unlike the SBOM endpoint, this one never
// auto-creates one.
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

    // --- platform upload (optional) ---------------------------------------
    String appName             = config.app ?: defaultAppName()
    String endpoint            = config.endpoint ?: (env.SAST_PLATFORM_URL ?: env.SBOM_PLATFORM_URL)
    String credentialsId       = config.credentialsId ?: 'sbom-ingest-token'
    String environmentName     = config.environment ?: ''
    // A failed upload should not normally break a release build, same
    // reasoning as sbomScan's own failure path. Independent of `required`
    // above: that one is about the *findings*, this one is about the *upload*.
    boolean uploadRequired     = config.get('uploadRequired', false)

    String jsonFile = "sast-findings-${UUID.randomUUID().toString().take(8)}.json"

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
                    --format json \
                    --severity-threshold "${severityThreshold}" \
                    > "${jsonFile}"
            """,
            returnStatus: true
        )

        // SARIF regenerated from the same scan rather than converted from the
        // JSON above — see the GitLab template's identical comment.
        sh """
            PYTHONPATH="\$(pwd)/sast-scan" python3 -m sast "${target}" \
                --exclude "${exclude}" \
                --format sarif \
                --severity-threshold "${severityThreshold}" \
                > "${reportFile}" || true
        """

        // Human-readable summary in the console log, independent of scanStatus
        // so it prints whether or not findings crossed the failing threshold.
        sh """
            PYTHONPATH="\$(pwd)/sast-scan" python3 -m sast "${target}" \
                --exclude "${exclude}" \
                --severity-threshold "${severityThreshold}" \
                --no-color || true
        """

        archiveArtifacts artifacts: reportFile, allowEmptyArchive: true

        if (endpoint) {
            try {
                withCredentials([string(credentialsId: credentialsId, variable: 'SAST_TOKEN')]) {
                    sh """
                        set -eu
                        python3 "\$(pwd)/sast-scan/ci_ingest_payload.py" \
                            "${jsonFile}" "${appName}" "${env.GIT_COMMIT ?: ''}" \
                            "${env.BRANCH_NAME ?: env.GIT_BRANCH ?: ''}" "${environmentName}" \
                            > sast-ingest-payload.json

                        CURL_CFG="\$(mktemp)"
                        trap 'rm -f "\$CURL_CFG"' EXIT
                        printf 'header = "Authorization: Bearer %s"\\n' "\$SAST_TOKEN" > "\$CURL_CFG"
                        chmod 600 "\$CURL_CFG"

                        curl -fsS \
                            --config "\$CURL_CFG" \
                            -H "Content-Type: application/json" \
                            --data @sast-ingest-payload.json \
                            --retry 3 --retry-delay 5 --retry-connrefused \
                            --max-time 60 \
                            "${endpoint}/api/v1/sast"
                    """
                }
                echo "sastScan: uploaded results for '${appName}'"
            } catch (err) {
                if (uploadRequired) {
                    throw err
                }
                unstable("sastScan: upload failed — ${err.message}. Pass uploadRequired: true to make this fatal.")
            } finally {
                sh "rm -f sast-ingest-payload.json '${jsonFile}' || true"
            }
        } else {
            echo "sastScan: no endpoint configured (set SAST_PLATFORM_URL/SBOM_PLATFORM_URL, or pass endpoint:) — SARIF artifact only"
            sh "rm -f '${jsonFile}' || true"
        }

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

/**
 * Derives the application name from the job name, when `app` is not passed.
 *
 * Deliberately duplicated from sbomScan.groovy's identical helper rather than
 * shared: Jenkins shared-library `vars/` scripts are each their own class, and
 * a `private` method in one is not reachable from another without moving it
 * into a `src/` library class — more structure than this one small function
 * justifies.
 */
private String defaultAppName() {
    List<String> parts = (env.JOB_NAME ?: '').split('/').findAll { it }
    if (!parts) {
        error "sastScan: could not derive an app name from JOB_NAME — pass app: '<name>' explicitly"
    }
    if (env.BRANCH_NAME && parts.size() > 1 && parts[-1] == env.BRANCH_NAME) {
        return parts[-2]
    }
    return parts[-1]
}
