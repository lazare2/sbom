# sast-scan

A standard-library-only (plus PyYAML) static application security testing
tool for Python codebases: a file walker, regex-based secret detection,
YAML-driven AST rules (`eval`/`exec`, unsafe `pickle`, `subprocess`
`shell=True`, unsafe `yaml.load`, weak hashes, weak `random` use,
security-flavored `assert`), and basic intra-procedural taint tracking
(`input()` / `sys.argv` / `os.environ` / `request.args`/`.form` reaching
`os.system`, `subprocess.*`, `eval`/`exec`, or `cursor.execute`).

It is vendored here as its own self-contained project rather than folded into
`packages/api`'s vulnerability schema. A SAST finding is a line in a file, not
a package/version pair, and does not fit `component_vulnerability` any better
than it fits Grype's other assumptions — see "Static analysis (SAST)" in the
top-level README. Its own tables (`sast_run` / `sast_finding`), its own ingest
route (`POST /api/v1/sast`), and its own tab on the application detail page
exist alongside the vulnerability ones rather than inside them.

Runs standalone with nothing configured — a SARIF artifact is always produced
— and posts to the platform only when `SBOM_PLATFORM_URL`/`SBOM_INGEST_TOKEN`
(or `SAST_PLATFORM_URL`/`SAST_INGEST_TOKEN`) are set. See the CI templates
below for both.

## Using it

```bash
cd sast-scan
python3 -m sast <path> --format sarif --severity-threshold HIGH
```

See [`sast/cli.py`](sast/cli.py) for the full flag set (`--format
console|sarif|json`, `--severity-threshold`, `--exclude`, `--rules` for a
custom rules file), and the CI templates that drive it in
[`../ci-templates/gitlab/sast-scan.gitlab-ci.yml`](../ci-templates/gitlab/sast-scan.gitlab-ci.yml)
and
[`../ci-templates/jenkins/vars/sastScan.groovy`](../ci-templates/jenkins/vars/sastScan.groovy).

[`ci_ingest_payload.py`](ci_ingest_payload.py) is the one piece of glue those
two templates share: it turns a `--format json` report into the body
`POST /api/v1/sast` expects. A script rather than a line inlined in each
template — the same transform, needed by both a bash heredoc and a Groovy
string, is exactly the kind of thing that looks fine once and breaks on the
next edit to either.

## Running its own tests

```bash
cd sast-scan
pip install pyyaml pytest
pytest -q
```

68 tests: every rule has a vulnerable sample that triggers it and a safe
sample that doesn't (`tests/vulnerable_samples/`, `tests/safe_samples/`), an
end-to-end run of `python -m sast` against both directories checking exit
codes and finding counts, and `ci_ingest_payload.py`'s own tests.
