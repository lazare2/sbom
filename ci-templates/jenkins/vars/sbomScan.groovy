// Jenkins shared-library step: generate a CycloneDX SBOM for an image and post
// it to the SBOM platform.
//
// Usage in a Jenkinsfile, after the image is built and before it is pushed or
// deployed:
//
//     sbomScan(image: "registry.internal.example.com/payments/api:${env.BUILD_NUMBER}")
//
// Override the application name when the job name does not match the platform's
// application name:
//
//     sbomScan(image: imageRef, app: "payments-api")
//
// Requires:
//   - `syft` on the agent's PATH (or set `syftImage` to run it via docker)
//   - a Secret Text credential holding the ingest token (default id: sbom-ingest-token)

def call(Map config = [:]) {
    String image = config.image
    if (!image) {
        error "sbomScan: 'image' is required — pass the image reference that was just built"
    }

    String appName       = config.app ?: defaultAppName()
    String endpoint      = config.endpoint ?: (env.SBOM_PLATFORM_URL ?: 'https://sbom.internal.example.com')
    String credentialsId = config.credentialsId ?: 'sbom-ingest-token'
    String syftImage     = config.syftImage ?: ''
    // A failed SBOM upload should not normally break a release build. Set
    // `required: true` for applications where the inventory is a gate.
    boolean required     = config.get('required', false)

    String sbomFile = "sbom-${UUID.randomUUID().toString().take(8)}.json"

    try {
        stage('SBOM scan') {
            if (syftImage) {
                // Runs syft in a container so the agent needs only docker.
                sh """
                    set -eu
                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      -v "\$(pwd):/work" -w /work \
                      ${syftImage} \
                      "${image}" -o cyclonedx-json="${sbomFile}"
                """
            } else {
                sh """
                    set -eu
                    syft "${image}" -o cyclonedx-json="${sbomFile}"
                """
            }

            withCredentials([string(credentialsId: credentialsId, variable: 'SBOM_TOKEN')]) {
                // The token goes into a curl config file rather than onto the
                // command line: arguments are visible in `ps` to anything else
                // running on the agent, and Jenkins only masks the value in
                // console output, not in the process table.
                sh """
                    set -eu
                    CURL_CFG="\$(mktemp)"
                    trap 'rm -f "\$CURL_CFG"' EXIT
                    printf 'header = "Authorization: Bearer %s"\\n' "\$SBOM_TOKEN" > "\$CURL_CFG"
                    chmod 600 "\$CURL_CFG"

                    # -f so a non-2xx fails this shell step. --retry covers a
                    # restarting platform without masking a real rejection:
                    # 4xx responses are not retried by curl.
                    curl -fsS \
                      --config "\$CURL_CFG" \
                      --retry 3 --retry-delay 5 --retry-connrefused \
                      --max-time 120 \
                      -F "sbom=@${sbomFile}" \
                      -F "app_name=${appName}" \
                      -F "commit_sha=${env.GIT_COMMIT ?: ''}" \
                      -F "build_number=${env.BUILD_NUMBER ?: ''}" \
                      -F "image_ref=${image}" \
                      -F "branch=${env.BRANCH_NAME ?: env.GIT_BRANCH ?: ''}" \
                      "${endpoint}/api/v1/scans"
                """
            }

            echo "sbomScan: uploaded SBOM for '${appName}' (${image})"
        }
    } catch (err) {
        if (required) {
            throw err
        }
        // Visible in the build result without failing it.
        unstable("sbomScan: SBOM upload failed — ${err.message}")
    } finally {
        sh "rm -f '${sbomFile}' || true"
    }
}

/**
 * Derives the application name from the job name.
 *
 * JOB_NAME carries the full folder path, e.g. `platform/payments/api/main`. For a
 * multibranch pipeline the last segment is the branch, so the application is the
 * segment before it; otherwise it is the last segment.
 */
private String defaultAppName() {
    List<String> parts = (env.JOB_NAME ?: '').split('/').findAll { it }
    if (!parts) {
        error "sbomScan: could not derive an app name from JOB_NAME — pass app: '<name>' explicitly"
    }
    if (env.BRANCH_NAME && parts.size() > 1 && parts[-1] == env.BRANCH_NAME) {
        return parts[-2]
    }
    return parts[-1]
}
