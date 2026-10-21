# 🕳️ Loophole

🌐 **Website:** https://loophole-sf-c596.vercel.app · 📦 **Latest release:** [v1.0.0](https://github.com/rootsiemen/loophole/releases/tag/v1.0.0)

**Loophole** is a zero-dependency static security scanner that finds the holes
in your code — hardcoded secrets, SQL injection, XSS, command injection, weak
crypto and more — across **JavaScript/TypeScript, Python, Go and PHP**.
It also explains *why* each finding matters, suggests a fix, and can print
mechanical fix suggestions as diffs without ever touching your files.

```bash
python3 loophole.py scan ./src
# or, with the wrapper on your PATH:
loophole scan ./src
```

## Why another scanner?

Most scanners are either heavyweight SaaS products or regex grep-scripts with
noisy output. Loophole sits in the middle:

- **Single file, stdlib only** — no install, no dependencies, runs anywhere
  Python 3.8+ exists. Drop it into CI in seconds.
- **Taint-aware (v1)** — it doesn't just pattern-match sinks; it tracks
  variables assigned from request/user input (`req.query`, `request.args`,
  `$_GET`, `r.URL.Query()`, …) and flags when they *flow* into dangerous
  sinks, including direct `query($_GET['id'])` usage.
- **Near-zero false positives** — parameterized queries, `textContent`,
  `execFile` with literals, `crypto.randomUUID`, env-var secrets and friends
  are all recognized as safe.
- **Fix suggestions, not just findings** — `--fix-dry` prints unified diffs
  for safe mechanical fixes. It never modifies your files.

## Quick start

```bash
# scan a directory or file
python3 loophole.py scan ./src

# JSON report for tooling
python3 loophole.py scan ./src --json report.json

# SARIF for GitHub code scanning
python3 loophole.py scan ./src --sarif results.sarif

# show suggested fixes as diffs (read-only)
python3 loophole.py scan ./src --fix-dry

# list all rules
python3 loophole.py scan --rules .

# only critical findings, skip tests
python3 loophole.py scan ./src --severity critical --exclude 'tests/*'
```

Exit code is **1** when any critical/high finding exists (CI-friendly),
**0** otherwise.

## GitHub Action

Run Loophole on every push and pull request, with findings uploaded to
GitHub code scanning (your repo's **Security** tab):

```yaml
name: Security scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  loophole:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rootsiemen/loophole@v1
```

Options (all optional):

| Input | Default | What it does |
|-------|---------|--------------|
| `path` | `.` | File or directory to scan |
| `severity` | `medium` | Minimum severity to report: `critical`, `high` or `medium` |
| `exclude` | — | Comma-separated directory names to skip |
| `upload-sarif` | `true` | Upload the SARIF report to code scanning |
| `fail-on-findings` | `true` | Fail the step when critical/high findings exist |
| `python-version` | `3.12` | Python version used to run the scanner |

Example — scan only `src`, never block the build:

```yaml
      - uses: rootsiemen/loophole@v1
        with:
          path: src
          fail-on-findings: "false"
```

## Example output

```
Loophole found 3 issue(s): 1 critical, 2 high, 0 medium

── CRITICAL (1) ──────────────────────────────────────────────
  CMD001 Command injection via child_process (JS/TS)
  src/app.js:33
  › exec(cmd, (err, out) => res.send(out));
  taint: req.query.cmd -> cmd -> exec
  why: Passing user-influenced strings to a shell lets attackers append
  commands (`; rm -rf /`, `$(...)`) that run with the app's privileges.
  fix: Avoid shells entirely: use execFile/spawn with an argument array
  (no shell). Never concatenate input into a command string.
```

## Rules (35)

| ID | Severity | What it catches |
|----|----------|-----------------|
| SEC001 | high | Hardcoded API key / token / secret (pattern + length) |
| SEC002 | high | Hardcoded password assignment |
| SEC003 | critical | Private key material in source |
| SEC004 | high | AWS access key ID (`AKIA…`) |
| SEC005 | high | High-entropy secret-like string (Shannon entropy) |
| SQLI001 | high | SQL string building — JS/TS (`"…"+`, template literals) |
| SQLI002 | high | SQL string building — Python (f-strings, `%`, `.format`) |
| SQLI003 | high | SQL string building — Go (`fmt.Sprintf`, concat) |
| SQLI004 | high | SQL string building — PHP (`.` concat) |
| XSS001 | high | Dynamic `innerHTML` / `outerHTML` assignment |
| XSS002 | medium | Dynamic `document.write()` |
| XSS003 | high | React `dangerouslySetInnerHTML` with dynamic value |
| XSS004 | high | PHP `echo`/`<?=` of `$_GET`/`$_POST`/`$_COOKIE` |
| CMD001 | critical | JS `child_process.exec/spawn` with dynamic command |
| CMD002 | critical | Python `os.system` / `shell=True` with dynamic command |
| CMD003 | critical | Go `exec.Command("sh","-c", …)` / tainted args |
| CMD004 | critical | PHP `system/exec/shell_exec/passthru` with `$` input |
| PATH001 | high | File operation on user-influenced path |
| PATH002 | medium | `..` traversal combined with user input |
| RAND001 | medium | `Math.random()` for tokens/secrets (JS) |
| RAND002 | medium | `random` module for secrets (Python) |
| RAND003 | medium | `math/rand` for secrets (Go; `crypto/rand` aware) |
| CRY001 | high | MD5 for password hashing |
| CRY002 | high | SHA-1 for password hashing |
| CRY003 | high | DES / 3DES cipher use |
| CRY004 | medium | Hardcoded IV |
| EVAL001 | critical | `eval()` with dynamic input |
| EVAL002 | high | `new Function()` with dynamic input |
| SSRF001 | high | HTTP request URL built from user input |
| AUTH001 | medium | Sensitive route without visible auth (heuristic) |
| CORS001 | medium | Wildcard CORS (`Access-Control-Allow-Origin: *`) |
| JWT001 | high | JWT decoded without verification (`jwt.decode`) |
| TLS001 | high | Disabled TLS verification |
| DBG001 | medium | Debug mode enabled (`debug=True`, `DEBUG = True`) |
| ERR001 | medium | Stack traces / exception details sent to client |

Each finding carries: rule id, severity, `file:line`, code snippet, taint
path (when tracked), *why it matters*, and a *fix suggestion*.

## Taint tracking (v1)

Loophole performs lightweight intra-file taint analysis:

1. **Sources** — assignments from `req.query` / `req.body` / `req.params`,
   `request.args` / `request.form`, `$_GET` / `$_POST` / `$_REQUEST` /
   `$_COOKIE`, `r.URL.Query()`, `os.Args`, and friends mark a variable tainted.
2. **Direct sources** — `query($_GET['id'])` (no intermediate variable) is
   caught too.
3. **Formatted strings** — variables holding interpolated SQL/HTML
   (f-strings, template literals, `fmt.Sprintf`, `"…$x"`) are tracked so
   `q = f"…{x}"; cursor.execute(q)` still flags.
4. **Sinks** — SQL calls, `exec`/`system`, `eval`, file functions, HTTP
   clients. When tainted data reaches a sink, the finding shows the path:
   `req.query.cmd -> cmd -> exec`.

Scope is deliberately small (single file, ~2 hops, no inter-procedural
analysis). It catches the common cases with very few false positives;
deeper analysis is on the roadmap.

## CI example (GitHub Actions)

```yaml
name: security-scan
on: [push, pull_request]
jobs:
  loophole:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Run Loophole
        run: python3 loophole.py scan ./src --sarif loophole.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: loophole.sarif
```

The step fails (exit 1) when critical/high findings exist, and results
appear under your repo's **Security → Code scanning** tab.

## Suppressing findings

When a finding is a false positive (or a risk you've accepted), silence it
inline — no config file needed:

```python
token = derive_token(salt)  # loophole: skip=SEC005
```

```js
// loophole: skip=CORS001  (bare form silences every rule on the line)
res.setHeader('Access-Control-Allow-Origin', '*');
```

Comma-separated rule ids are supported: `# loophole: skip=SEC001,SEC005`.
Use suppressions sparingly — each one is a hole you're choosing not to see.

## Project layout

```
loophole/
├── loophole.py            # the scanner (single file, stdlib only)
├── loophole                # shell wrapper: loophole scan <path>
├── README.md
└── tests/
    ├── selftest.py        # python3 tests/selftest.py
    └── fixtures/          # 12 fixtures (6 vulnerable + 6 clean)
```

## Contributing

1. New rules go in `loophole.py`: write a `rule_XXXnnn(ctx)` function
   returning a list of findings, register it in `RULES` with its languages.
2. Add a vulnerable fixture *and* a clean counterpart under
   `tests/fixtures/` — the clean one must produce **zero** findings.
3. Run `python3 tests/selftest.py` and the dogfood check below before
   submitting.

**Dogfood rule:** every change must keep `python3 loophole.py scan loophole.py`
clean (exit 0).

## License

MIT — see `LICENSE` (to be added).
