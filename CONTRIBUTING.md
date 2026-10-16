# Contributing to Loophole 🕳️

Thanks for wanting to help! Loophole is a zero-dependency static security scanner — one Python file, stdlib only. Here's how to get going.

## Quick start

```bash
git clone https://github.com/rootsiemen/loophole.git
cd loophole
python3 tests/selftest.py   # all 7 tests must pass
python3 loophole.py scan ./some-project
```

## Adding a new rule

Rules live in `loophole.py`. Most are a single call to the `regex_rule` helper:

```python
def rule_MY001(ctx):
    """One-line description."""
    pats = {
        "py": [r"dangerous_call\s*\("],
    }
    return regex_rule(
        ctx, "MY001", "high", "Short title", pats,
        "Why this is dangerous (shown to the user).",
        "How to fix it (shown to the user).")
```

Then register it in the `RULES` list (id, languages, function), add the rule ID to the README rules table, and add vulnerable + clean fixture snippets under `tests/fixtures/` with an `EXPECTED` entry in `tests/selftest.py`.

**Rule IDs:** pick the next free number in the right family — `SEC`, `SQLI`, `XSS`, `CMD`, `PATH`, `RAND`, `CRY`, `EVAL`, `SSRF`, `AUTH`, `CORS`, `JWT`, `TLS`, `DBG`, `ERR`, or start a new family (like `DESER`) if nothing fits.

## Code style

- Python 3.8+ compatible, **stdlib only** — no new dependencies, ever.
- Keep false positives at zero: every rule must pass the clean fixtures. If your pattern fires on safe code, tighten it (see `rule_XSS001` for the static-literal skip pattern).
- Follow the existing style: small functions, docstrings, `why`/`fix` text written for developers, not researchers.

## Tests

```bash
python3 tests/selftest.py
```

Vulnerable fixtures must be caught, clean fixtures must produce **zero** findings. Add both sides for any new rule.

## PR process

1. Fork the repo, create a branch (`feat/deser001`, `fix/...`).
2. Keep PRs focused — one rule or one fix per PR.
3. Make sure `python3 tests/selftest.py` passes and mention it in the PR.
4. Maintainer reviews, may request changes, then merges. Be kind in reviews — we're all here to learn.

## Good first issues

Look for the [`good first issue`](https://github.com/rootsiemen/loophole/labels/good%20first%20issue) label — they're scoped to be doable in one sitting. Comment on the issue to claim it so two people don't duplicate work.
