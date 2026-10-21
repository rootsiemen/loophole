# Contributing to Loophole

Thanks for helping make codebases safer. Loophole is a single-file Python
scanner (`loophole.py`) with zero dependencies — contributions should keep it
that way: standard library only, Python 3.8+.

## Getting started

```bash
git clone https://github.com/rootsiemen/loophole
cd loophole
python3 loophole.py scan ./some-project
python3 tests/selftest.py   # must pass before you open a PR
```

No build step, no virtualenv, no pip install. If it needs a dependency, it
doesn't belong in Loophole.

## How rules work

Every check is a function in `loophole.py` named `rule_<ID>` taking a scan
context (`ctx`):

```python
def rule_SEC042(ctx):
    ...
```

Rule IDs are grouped by family:

| Prefix  | Family                                   |
|---------|------------------------------------------|
| `SEC`   | secrets, credentials, general security   |
| `XSS`   | cross-site scripting                     |
| `CMD`   | command injection                        |
| `PATH`  | path traversal / file handling           |
| `CRY`   | weak cryptography                        |
| `RAND`  | insecure randomness                      |
| `SSRF`  | server-side request forgery              |
| others  | single-purpose families: `AUTH`, `CORS`, `DBG`, `ERR`, `EVAL`, `JWT`, `TLS` |

A rule reports a `Finding` with a rule id, severity
(`critical` / `high` / `medium` / `low`), a plain-English title, file and line,
the offending snippet — and, most importantly, **why it is dangerous and how to
fix it**. A finding without a fix suggestion is incomplete.

## Adding a new rule

1. Pick the next free ID in the family (check the existing `rule_` functions).
2. Write the rule in `loophole.py`. Prefer precise patterns and, where the
   family supports it, taint information over raw keyword matching — false
   positives are the enemy.
3. Add a fixture: a small vulnerable sample (and a safe counterpart) under
   `tests/fixtures/`, and cover the rule in `tests/selftest.py`.
4. Run the self-tests, then scan Loophole itself:
   `python3 loophole.py scan .` must stay clean.
5. Open a PR using the *New rule* issue/PR description: what it catches, the
   vulnerable pattern, and why the safe counterpart is safe.

## Reporting bugs and false positives

A false positive is a bug. Open an issue with the *Bug report* template and
include the smallest code sample that triggers it — that sample usually
becomes a regression fixture.

## Pull requests

- One rule or one fix per PR; small PRs get reviewed the same day.
- Keep the single-file design: everything ships in `loophole.py`.
- Tests must pass (`python3 tests/selftest.py`) and Loophole must scan its
  own codebase clean.
- By contributing you agree to the [Code of Conduct](CODE_OF_CONDUCT.md) and
  that your contribution is licensed under the project's MIT license.
