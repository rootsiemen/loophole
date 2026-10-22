# Test fixtures — intentionally vulnerable samples

The `*_vuln.*` files in this folder are **deliberately insecure code samples**.
Each one exists so the test suite (`tests/selftest.py`) can prove that
Loophole detects a specific vulnerability class: hardcoded secrets, SQL
injection, command injection, `eval()` on user input, XSS, SSRF, weak
crypto, and the rest of the rule catalog.

The matching `*_clean.*` files contain the safe version of the same code and
must always produce **zero** findings — that is how false positives are kept
in check.

Think of these files like the EICAR test file for antivirus software: the bad
code is the test data, not the product.

- Never copy fixture code into a real project.
- Never deploy or execute the `*_vuln.*` files.
- Automated scanners (Codacy, etc.) are configured via `.codacy.yml` in the
  repo root to skip this folder for exactly this reason.

The scanner itself — `loophole.py` — passes its own scan with zero findings:

```bash
python3 loophole.py scan loophole.py
# ✓ No loopholes found.
```
