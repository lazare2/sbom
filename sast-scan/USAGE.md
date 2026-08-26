# Using sast-scan

Three ways to run it, in increasing order of setup: on your laptop while you
work, in CI as a gate, and posting into the platform so findings show up on an
application's **Static analysis** tab.

All three run the same scanner over the same rules. Nothing below is required
for the one above it.

---

## 1. On your laptop

```bash
cd sast-scan
pip install pyyaml          # the only dependency
python3 -m sast /path/to/your/project
```

Output is grouped by file, coloured by severity, and the exit code is `1` if
anything HIGH or CRITICAL was found — so `python3 -m sast . && echo clean`
does what it reads as.

### See how to fix what it found

```bash
python3 -m sast /path/to/project --explain
```

Adds the rule's remediation under each finding. Off by default because in a CI
log the same paragraph repeated forty times buries the list it is annotating.

### Narrow it down

```bash
# only the things worth stopping for
python3 -m sast . --severity-threshold HIGH

# skip vendored or generated trees (venv/.git/__pycache__/node_modules
# are already skipped)
python3 -m sast . --exclude migrations --exclude vendor

# machine-readable
python3 -m sast . --format json
python3 -m sast . --format sarif > report.sarif
```

`--format sarif` produces SARIF 2.1.0, which GitHub code scanning, VS Code's
SARIF viewer and most IDE plugins read directly — including the remediation
text, which lands in the SARIF `help` field.

---

## 2. In CI, as a gate

Both templates live in `ci-templates/` and need nothing configured to be
useful: they run the scan, archive a SARIF artifact, and fail the job on
HIGH/CRITICAL.

**GitLab** — in the project's `.gitlab-ci.yml`:

```yaml
include:
  - project: 'platform/ci-templates'
    ref: main
    file: '/sast-scan.gitlab-ci.yml'

sast:scan:
  extends: .sast_scan
```

**Jenkins** — in the `Jenkinsfile`:

```groovy
sastScan()
```

### Rolling it out without breaking today's pipeline

An existing project usually has findings on day one. Introduce it
non-blocking, triage, then turn on the gate:

| | GitLab | Jenkins |
|---|---|---|
| Don't fail the build yet | `SAST_ALLOW_FAILURE: "true"` | *(default)* |
| Fail on HIGH/CRITICAL | *(default)* | `sastScan(required: true)` |
| Scan a subdirectory | `SAST_TARGET: "src"` | `sastScan(target: 'src')` |
| Change the bar | `SAST_SEVERITY_THRESHOLD: "CRITICAL"` | `sastScan(severityThreshold: 'CRITICAL')` |

---

## 3. Posting findings into the platform

This is what puts findings on the **Static analysis** tab of an application,
with history across runs.

**Prerequisite:** the application must already exist on the platform. Unlike
the SBOM endpoint, a SAST run never auto-creates one — a run naming an
application nobody registered is almost always a typo in the app name, and
inventing an application for it hides the mistake.

Two things to set, and it uses the same credentials as the SBOM job if that is
already wired up:

| GitLab CI variable | Jenkins | What |
|---|---|---|
| `SBOM_PLATFORM_URL` | `SBOM_PLATFORM_URL` env, or `endpoint:` | Where the platform is |
| `SBOM_INGEST_TOKEN` | `sbom-ingest-token` credential | Admin → Ingest tokens |
| `SAST_APP_NAME` | `sastScan(app: '...')` | Application name on the platform |

With those present the job posts automatically. With them absent it prints
*"skipping upload, SARIF artifact only"* and carries on — an upload failure
never fails the pipeline unless you ask it to (`SAST_REQUIRED: "true"` /
`sastScan(uploadRequired: true)`).

### By hand, to check it works

```bash
# 1. scan, as JSON
python3 -m sast /path/to/project --format json > findings.json

# 2. wrap it in the request body
python3 sast-scan/ci_ingest_payload.py findings.json "my-app" "$(git rev-parse HEAD)" "main" \
  > payload.json

# 3. post it
curl -X POST https://sbom.example.com/api/v1/sast \
  -H "Authorization: Bearer $SBOM_INGEST_TOKEN" \
  -H "Content-Type: application/json" \
  --data @payload.json
```

A `201` returns the run id and the severity breakdown. Then open the
application → **Static analysis**.

### What the endpoints answer

| | |
|---|---|
| `POST /api/v1/sast` | Ingest a run. Bearer token. |
| `GET /api/v1/sast/applications/:id` | Latest run with findings |
| `GET /api/v1/sast/applications/:id?run=<id>` | One specific historical run |
| `GET /api/v1/sast/applications/:id/runs` | Run history, newest first |

---

## Reading the findings

Each finding carries a **category** naming which of the three techniques found
it, and they fail in different ways — worth knowing which you are looking at:

| Category | How it works | Where it is weak |
|---|---|---|
| **Secrets** | Regex over each line | Flags fake values in tests and fixtures. Real keys and placeholder keys look identical to a regex. |
| **Code patterns** | Matches calls in the parsed syntax tree | Says `eval()` is present, not that it is reachable by an attacker. Judgement is still yours. |
| **Taint** | Follows untrusted input into a dangerous call | Stops at the function boundary — see below. |

### The single most important limitation

Taint tracking is **intra-procedural**. It follows a value through one
function's assignments, concatenation and f-strings — but not across a call
into another function. This is caught:

```python
def handler():
    host = input()
    os.system("ping " + host)        # flagged
```

This is **not**:

```python
def handler():
    run(input())                      # not flagged

def run(cmd):
    os.system("ping " + cmd)          # the source is in another function
```

So a clean taint result is not proof of no injection. It is proof that no
injection is visible *within a single function*.

### Suppressing a finding

There is deliberately no inline `# noqa`-style suppression. If a rule is wrong
for your project, the honest options are to narrow the scan (`--exclude`), or
to point `--rules` at your own YAML file:

```bash
python3 -m sast . --rules my-rules.yaml
```

The rule format is in `sast/rules/python.yaml`, and the engine reads it
generically — adding, removing or re-scoring a rule needs no code change. A
custom file's rules can omit `remediation`; the platform renders "this rule
ships no guidance" rather than pretending it has some.

---

## Writing a rule

Rules are data. To flag `os.chmod` with a permissive mode, no Python changes
are needed:

```yaml
rules:
  - id: PY-CHMOD-PERMISSIVE-001
    severity: MEDIUM
    cwe: 732
    category: ast
    remediation: >-
      Narrow the mode. 0o777 grants write to every user on the host, which is
      almost never intended for a file an application creates.
    message: >-
      os.chmod with a world-writable mode.
    pattern:
      node: call
      qualified_names: [os.chmod]
```

The `pattern` vocabulary the engine understands:

| Key | Matches |
|---|---|
| `call_names` | A bare call by name — `eval`, `exec` |
| `qualified_names` | A dotted path, import aliases resolved — `pickle.loads` |
| `module_wildcard` | Anything under a module — `subprocess` |
| `keywords` | A keyword argument equal to a literal — `shell=True` |
| `keyword_unsafe` | A keyword that is missing or not in a safe set — `yaml.load`'s `Loader` |
| `non_literal_positional` | An argument that is *not* a hardcoded literal |
| `node: assert` + `contains_any` | Assert statements mentioning given words |

Then run the tests — every rule is expected to have a sample that triggers it
and a safe sample that does not:

```bash
cd sast-scan && python3 -m pytest -q
```
