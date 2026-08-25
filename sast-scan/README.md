# sast-scan

A standard-library-only (plus PyYAML) static application security testing
tool for Python codebases: a file walker, regex-based secret detection,
YAML-driven AST rules (`eval`/`exec`, unsafe `pickle`, `subprocess`
`shell=True`, unsafe `yaml.load`, weak hashes, weak `random` use,
security-flavored `assert`), and basic intra-procedural taint tracking
(`input()` / `sys.argv` / `os.environ` / `request.args`/`.form` reaching
`os.system`, `subprocess.*`, `eval`/`exec`, or `cursor.execute`).

It is vendored here as its own self-contained project rather than wired into
`packages/api`. That mirrors a limitation the platform is upfront about
elsewhere in this repo (see "Vulnerability scanning" in the top-level
README): findings are stored keyed to Grype's schema, and there is no
abstraction for a second scanner type. Bolting SAST findings into that schema
would mean modifying the ingestion pipeline, `component_vulnerability`, and
the dashboard to understand a finding shape Grype never produces — a real
architectural change, not a config flag. Keeping this scanner standalone
means it can run in CI today, publish a SARIF artifact, and gate a pipeline
on its own, without that refactor being a prerequisite.

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

## Running its own tests

```bash
cd sast-scan
pip install pyyaml pytest
pytest -q
```

64 tests: every rule has a vulnerable sample that triggers it and a safe
sample that doesn't (`tests/vulnerable_samples/`, `tests/safe_samples/`),
plus an end-to-end run of `python -m sast` against both directories checking
exit codes and finding counts.
