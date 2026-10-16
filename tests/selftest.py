#!/usr/bin/env python3
"""Loophole self-test: vulnerable fixtures must be caught, clean ones pass.

Run:  python3 tests/selftest.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCANNER = os.path.join(ROOT, "loophole.py")
FIX = os.path.join(HERE, "fixtures")


def scan(path, *extra):
    """Run the scanner, return (exit_code, parsed_json_findings)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name
    try:
        cmd = [sys.executable, SCANNER, "scan", path,
               "--json", out, "--no-color"] + list(extra)
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
        with open(out) as fh:
            data = json.load(fh)
        return proc.returncode, data["findings"]
    finally:
        os.unlink(out)


def rule_ids(findings):
    return {f["rule_id"] for f in findings}


# rule -> fixtures that must trigger it (subset assertion: each listed rule
# must appear at least once in the fixture's findings)
EXPECTED = {
    "js_vuln.js": {"SEC001", "SQLI001", "AUTH001", "XSS001", "XSS003",
                   "CMD001", "EVAL001", "JWT001", "CORS001", "TLS001",
                   "ERR001", "RAND001"},
    "ts_vuln.ts": {"SQLI001", "SSRF001", "PATH001", "PATH002"},
    "py_vuln.py": {"SEC002", "SQLI002", "CMD002", "SSRF001", "TLS001",
                   "PATH001", "EVAL001", "RAND002", "CRY001", "AUTH001",
                   "DBG001"},
    "go_vuln.go": {"SQLI003", "CMD003", "CRY003", "CRY004", "RAND003",
                   "TLS001"},
    "php_vuln.php": {"SEC001", "SQLI004", "XSS004", "CMD004", "EVAL001",
                     "CRY001", "SSRF001", "TLS001", "PATH001"},
    "mixed_vuln.py": {"SEC003", "SEC004", "SEC005", "PATH002", "CORS001",
                      "DBG001"},
}

CLEAN = ["js_clean.js", "ts_clean.ts", "py_clean.py", "go_clean.go",
         "php_clean.php", "all_clean.js"]


class TestFixtures(unittest.TestCase):
    def test_vulnerable_fixtures(self):
        for name, expected in EXPECTED.items():
            with self.subTest(fixture=name):
                code, findings = scan(os.path.join(FIX, name))
                got = rule_ids(findings)
                missing = expected - got
                self.assertFalse(
                    missing,
                    f"{name}: expected rules not fired: {sorted(missing)} "
                    f"(got {sorted(got)})")
                self.assertEqual(
                    code, 1,
                    f"{name}: exit code should be 1 (critical/high present)")

    def test_clean_fixtures(self):
        for name in CLEAN:
            with self.subTest(fixture=name):
                code, findings = scan(os.path.join(FIX, name))
                self.assertEqual(
                    findings, [],
                    f"{name}: clean fixture produced findings: "
                    f"{[(f['rule_id'], f['line']) for f in findings]}")
                self.assertEqual(code, 0, f"{name}: exit code should be 0")

    def test_sarif_output(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif",
                                         delete=False) as tmp:
            out = tmp.name
        try:
            proc = subprocess.run(
                [sys.executable, SCANNER, "scan",
                 os.path.join(FIX, "py_vuln.py"),
                 "--sarif", out, "--no-color"],
                capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(proc.returncode, 1)
            with open(out) as fh:
                sarif = json.load(fh)
            self.assertEqual(sarif["version"], "2.1.0")
            results = sarif["runs"][0]["results"]
            self.assertTrue(results, "SARIF has no results")
            self.assertTrue(all("ruleId" in r for r in results))
        finally:
            os.unlink(out)

    def test_fix_dry_does_not_modify(self):
        target = os.path.join(FIX, "py_vuln.py")
        with open(target, "rb") as fh:
            before = fh.read()
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", target,
             "--fix-dry", "--no-color"],
            capture_output=True, text=True, cwd=ROOT)
        with open(target, "rb") as fh:
            after = fh.read()
        self.assertEqual(before, after, "--fix-dry modified the file!")
        self.assertIn("---", proc.stdout,
                      "--fix-dry printed no diff suggestions")

    def test_rules_list(self):
        proc = subprocess.run(
            [sys.executable, SCANNER, "scan", "--rules", "."],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("35 rules total", proc.stdout)

    def test_no_rule_crashes(self):
        """Every rule function must run without raising (regression net for
        bad-regex crashes that scan_file would otherwise swallow)."""
        sys.path.insert(0, ROOT)
        import loophole
        bad = []
        for rule_id, langs, func in loophole.RULES:
            for lang in langs:
                ctx = loophole.Ctx("t." + lang, lang, ["x = 1"])
                try:
                    func(ctx)
                except Exception as exc:  # noqa: BLE001
                    bad.append((rule_id, lang, repr(exc)))
        self.assertFalse(bad, f"rules crashed: {bad}")

    def test_inline_suppression(self):
        sys.path.insert(0, ROOT)
        import loophole
        with tempfile.NamedTemporaryFile(
                suffix=".py", mode="w", delete=False) as tmp:
            tmp.write('API_KEY = "sk-live-abcdef1234567890"  '
                      '# loophole: skip=SEC001\n')
            tmp.write('SECRET_KEY = "sk-live-abcdef1234567890"\n')
            path = tmp.name
        try:
            findings = loophole.scan_file(path)
            line1 = {f.rule_id for f in findings if f.line == 1}
            line2 = {f.rule_id for f in findings if f.line == 2}
            self.assertNotIn("SEC001", line1,
                             "suppression comment did not silence line 1")
            self.assertIn("SEC001", line2,
                          "unsuppressed twin line should still fire")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
