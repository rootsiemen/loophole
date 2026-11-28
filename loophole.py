#!/usr/bin/env python3
"""
Loophole — a lightweight static security scanner for catching loopholes in code.

Scans JavaScript/TypeScript, Python, Go and PHP for common security flaws:
hardcoded secrets, SQL injection, XSS, command injection, path traversal,
insecure randomness, weak crypto, eval(), SSRF, missing auth, CORS/JWT/TLS
misconfigurations and debug leaks — with lightweight taint tracking from
user-controlled input to dangerous sinks.

Usage:
    python3 loophole.py scan <path> [--json out.json] [--sarif out.sarif]
                                    [--html report.html] [--junit report.xml]
                                    [--gitlab gl-sast-report.json]
                                    [--fix-dry]
                                    [--severity critical,high]
                                    [--exclude dir1,dir2] [--no-color]
                                    [--config .loophole.json]
                                    [--baseline base.json]
                                    [--write-baseline base.json]
                                    [--cache cache.json]

Exit code is 1 when any critical/high finding exists (CI-friendly), else 0.

Taint tracking (v1): single-file, intra-procedural. Variables assigned from
request/user-controlled sources (req.query, req.body, $_GET, request.args,
r.URL.Query(), os.Args, input(), ...) are marked tainted; when a tainted
variable reaches a sink (db query, exec, eval, file open, innerHTML, fetch)
the finding is reported with the data-flow noted. Two hops max (source ->
variable -> sink); no inter-procedural or cross-file analysis yet.

Stdlib only. No dependencies.
"""

import argparse
import ast
import difflib
from datetime import datetime, timezone
import fnmatch
import hashlib
import html
import json
import math
import os
import re
import sys
import xml.etree.ElementTree as ET

VERSION = "1.2.2"

# Home of the rule docs: the README rules table carries one named anchor
# per rule (<a name="rule-sec001">), so every rule links to its own row.
RULE_DOC_URL = "https://github.com/rootsiemen/loophole"


def rule_help_uri(rule_id):
    """Doc URL for one rule, e.g. .../loophole#rule-cry002."""
    return f"{RULE_DOC_URL}#rule-{rule_id.lower()}"

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

SEVERITIES = ("critical", "high", "medium")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2}


class Finding:
    """One detected loophole."""

    __slots__ = ("rule_id", "severity", "title", "path", "line", "snippet",
                 "why", "fix", "taint")

    def __init__(self, rule_id, severity, title, path, line, snippet,
                 why, fix, taint=None):
        self.rule_id = rule_id
        self.severity = severity
        self.title = title
        self.path = path
        self.line = line            # 1-based
        self.snippet = snippet      # single source line, stripped
        self.why = why              # why it matters
        self.fix = fix              # how to fix it
        self.taint = taint          # e.g. "req.query.q -> query" or None

    def to_dict(self):
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "why": self.why,
            "fix": self.fix,
        }
        if self.taint:
            d["taint_flow"] = self.taint
        return d


# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------

class Color:
    def __init__(self, enabled):
        self.enabled = enabled

    def _w(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def red(self, t): return self._w("91", t)
    def yellow(self, t): return self._w("93", t)
    def cyan(self, t): return self._w("96", t)
    def green(self, t): return self._w("92", t)
    def bold(self, t): return self._w("1", t)
    def dim(self, t): return self._w("2", t)


def sev_color(color, sev):
    return {"critical": color.red, "high": color.yellow,
            "medium": color.cyan}[sev]


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def shannon_entropy(s):
    """Shannon entropy of a string (bits per char)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def snippet_of(lines, lineno, width=100):
    line = lines[lineno - 1].strip()
    return line if len(line) <= width else line[: width - 3] + "..."


def is_string_literal(arg):
    """True if the argument looks like a plain string literal (no interpolation)."""
    a = arg.strip()
    if len(a) >= 2 and a[0] == a[-1] and a[0] in "\"'":
        inner = a[1:-1]
        # template literal / interpolation markers inside
        if "${" in inner or "%s" in inner or "%(" in inner:
            return False
        return True
    if a.startswith("`") and a.endswith("`"):  # JS template literal
        return "${" not in a
    return False


def is_single_string_literal(arg):
    """True if arg is exactly one string literal (nothing else).

    is_string_literal() is fooled by concatenation — '"a" + x + "b"'
    starts and ends with a quote — so strip the literals first and
    require that nothing but whitespace remains. Needed by rules that
    must flag concatenations, e.g. template.HTML("<b>" + bio).
    """
    a = arg.strip()
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', a)
    code = re.sub(r'`[^`]*`', '``', code)
    code = re.sub(r"'(?:\\.|[^'\\])*'", "''", code)
    return not code.strip(" \t\"'`")


def _is_constant_payload(arg):
    """True if a PHP unserialize() payload is a constant string literal.

    Checks the payload argument alone (an options argument must not
    make a literal look dynamic). PHP double-quoted strings interpolate
    $vars, so those are dynamic, not constant.
    """
    if not is_single_string_literal(arg):
        return False
    a = arg.strip()
    if a.startswith('"') and re.search(r"\$[A-Za-z_{]", a):
        return False
    return True


def word_in(text, word):
    """Whole-word (or $var) occurrence check."""
    return re.search(r"(?<![\w$])" + re.escape(word) + r"(?![\w])", text) is not None


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

LANG_BY_EXT = {
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js",          # TypeScript handled by the JS engine
    ".mts": "js", ".cts": "js",         # explicit ESM / CJS TypeScript modules
    ".py": "py",
    ".go": "go",
    ".php": "php", ".phtml": "php",
}

DEFAULT_EXCLUDES = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "target", "coverage",
}


def detect_lang(path):
    _, ext = os.path.splitext(path)
    return LANG_BY_EXT.get(ext.lower())


# ---------------------------------------------------------------------------
# Taint tracking (v1) — lightweight, single-file, intra-procedural
# ---------------------------------------------------------------------------
#
# Pass 1: find variables assigned from user-controlled sources.
# Pass 2: sink rules check whether a tainted variable name flows into a
#         dangerous call. Findings note the flow, e.g. "req.query.id -> query".
#
# Sources are request/user input per language. Sinks are the dangerous calls
# each rule watches. Two hops max: source -> var -> sink.

TAINT_SOURCES = {
    # JS/TS: express-style request objects, CLI args
    "js": [
        r"req\.(query|body|params|headers|cookies)\b",
        r"process\.argv\b",
        r"location\.search\b",
        r"new\s+URLSearchParams\b",
    ],
    # Python: web frameworks + stdin/argv
    "py": [
        r"request\.(args|form|json|data|values|cookies)\b",
        # Django: request.GET/POST/FILES/body/COOKIES/META/headers.
        # The lookbehind keeps myrequest.GET out while still matching
        # self.request.GET; the trailing \b keeps request.GETTER out.
        r"(?<![A-Za-z0-9_])request\.(GET|POST|FILES|body|COOKIES|META|headers)\b",
        # FastAPI / Django REST framework request object.
        r"(?<![A-Za-z0-9_])request\.(query_params|path_params)\b",
        r"await\s+request\.(json|form)\s*\(",
        r"flask\s*\.\s*request\b",
        r"(?<![\w.])input\s*\(",
        r"sys\.argv\b",
        r"os\.environ\.get\s*\(\s*['\"]HTTP_",
    ],
    # Go: net/http request + CLI args
    "go": [
        r"r\.URL\.Query\(\)",
        r"r\.FormValue\s*\(",
        r"r\.PostFormValue\s*\(",
        r"os\.Args\b",
    ],
    # PHP: superglobals
    "php": [
        r"\$_(GET|POST|REQUEST|COOKIE)\b",
        r"\$_FILES\b",
        r"php://input\b",
    ],
}

# (variable-name pattern, assignment regex) per language. Group 1 = var name.
ASSIGN_PATTERNS = {
    "js": [
        # const user = req.query.user   /   let x = req.body
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)",
        # destructuring: const {a, b} = req.query
        r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*(.+)",
        # plain re-assign: x = req.query.x
        r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*(?![=>])(.+)",
    ],
    "py": [
        r"([A-Za-z_]\w*)\s*=\s*(.+)",
    ],
    "go": [
        r"([A-Za-z_]\w*)\s*:?=\s*(.+)",
    ],
    "php": [
        r"(\$[A-Za-z_]\w*)\s*=\s*(.+)",
    ],
}


def _source_hit(rhs, lang):
    return any(re.search(p, rhs) for p in TAINT_SOURCES[lang])


def find_tainted_vars(lines, lang):
    """Return {var_name: source_description} for tainted variables."""
    tainted = {}
    for line in lines:
        code = line.split("//")[0] if lang == "go" else line
        for pat in ASSIGN_PATTERNS[lang]:
            m = re.search(pat, code)
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if not _source_hit(rhs, lang):
                continue
            # destructuring: mark each name
            if lang == "js" and "{" in pat:
                for name in lhs.split(","):
                    name = name.strip().split(":")[0].split("=")[0].strip()
                    if re.match(r"^[A-Za-z_$][\w$]*$", name):
                        tainted[name] = rhs.strip()[:60]
            else:
                # avoid `==`, `!=`, `<=`, `>=` false matches
                before = code[m.start():]
                if re.match(r"[A-Za-z_$\w]*\s*[=!<>]=\s*", before):
                    continue
                tainted[lhs] = rhs.strip()[:60]
            break
    return tainted


def _php_tainted_asof(lines, upto_line):
    """Tainted PHP vars as of a given call line (1-based, inclusive).

    DESER001-only view of taint: assignments are replayed in order, so
    a reassignment to trusted data — or an assignment that only happens
    after the call — does not count. Taint propagates through plain
    copies ($b = $a) but not through function calls, which may validate
    or sanitize (e.g. path.resolve). Line comments are stripped first
    so a source named only in a comment cannot taint a variable.
    """
    tainted = {}
    pat = ASSIGN_PATTERNS["php"][0]
    for line in lines[:upto_line]:
        code = line.split("//")[0].split("#")[0]
        m = re.search(pat, code)
        if not m:
            continue
        lhs, rhs = m.group(1), m.group(2)
        # avoid `==`, `!=`, `<=`, `>=` false matches
        before = code[m.start():]
        if re.match(r"[A-Za-z_$\w]*\s*[=!<>]=\s*", before):
            continue
        if _source_hit(rhs, "php"):
            tainted[lhs] = rhs.strip()[:60]
        else:
            src_var = tainted_in_call(rhs, tainted)
            if src_var and "(" not in rhs:
                # plain copy of a tainted variable: propagate its source
                tainted[lhs] = tainted[src_var]
            elif lhs in tainted:
                # reassigned to untainted data: taint no longer flows
                del tainted[lhs]
    return tainted


def tainted_in_call(arg_text, tainted):
    """Return the tainted var name flowing into this call, or None."""
    for var in tainted:
        if word_in(arg_text, var):
            return var
    return None


def _flow_in(args, tainted, lang):
    """Taint flow into call arguments against an explicit tainted map.

    Returns (var_name_or_None, source_text_or_None). Detects variables
    assigned from tainted sources AND direct source usage such as
    query($_GET['id']) (1-hop).
    """
    if args is None:
        return None, None
    var = tainted_in_call(args, tainted)
    if var:
        return var, tainted[var]
    for pat in TAINT_SOURCES[lang]:
        m = re.search(pat, args)
        if m:
            return None, m.group(0)
    return None, None


def call_args(line, func_pat):
    """Extract the argument text of the first func_pat( ... ) call on a line.

    Handles one level of nested parens. Returns None if no call found.
    """
    m = re.search(func_pat + r"\s*\(", line)
    if not m:
        return None
    i = m.end()
    depth = 1
    start = i
    in_str = None
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "\"'`":
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return line[start:i]
        i += 1
    return line[start:]  # unterminated; return what we have


def _first_arg(args):
    """Return the first top-level comma-separated argument."""
    parts = _split_top_level_args(args)
    return parts[0] if parts else args


def _split_top_level_args(args):
    """Split argument text on top-level commas (nesting/string aware)."""
    parts = []
    depth = 0
    in_str = None
    start = 0
    i = 0
    while i < len(args):
        ch = args[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "\"'`":
            in_str = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(args[start:i])
            start = i + 1
        i += 1
    parts.append(args[start:])
    return parts


def _iter_call_args(lines, start_line, func_pat):
    """Yield the argument text of every func_pat(...) call starting on
    start_line (1-based), collecting across physical lines until the
    parens balance. Handles several calls on one line.
    """
    text = "\n".join(lines[start_line - 1:])
    first_line = lines[start_line - 1]
    for m in re.finditer(func_pat + r"\s*\(", first_line):
        start = m.end()  # just after '('; same offset in joined text
        depth = 1
        in_str = None
        i = start
        while i < len(text):
            ch = text[i]
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
            elif ch in "\"'`":
                in_str = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    yield text[start:i]
                    break
            i += 1
        else:
            yield text[start:]  # unterminated; return what we have


def find_formatted_vars(lines, lang):
    """Variables assigned a dynamically-built string.

    q = f"SELECT ...{x}" / q = `...${x}` / q := fmt.Sprintf(...) /
    $q = "...$x..." — string-built before reaching a sink (SQLi-relevant).
    """
    pats = {
        "js": r"([A-Za-z_$][\w$]*)\s*=\s*`[^`]*\$\{",
        "py": r"([A-Za-z_]\w*)\s*=\s*f['\"]",
        "go": r"([A-Za-z_]\w*)\s*:?=\s*fmt\.Sprintf\s*\(",
        "php": r"(\$[A-Za-z_]\w*)\s*=\s*\"[^\"]*\$",
    }
    found = set()
    pat = pats.get(lang)
    if not pat:
        return found
    for line in lines:
        m = re.search(pat, line)
        if m:
            found.add(m.group(1))
    return found


def _taint_note(var, src, sink):
    """Human-readable taint flow note, or None."""
    if var:
        return f"{src} -> {var} -> {sink}"
    if src:
        return f"{src} -> {sink}"
    return None


# ---------------------------------------------------------------------------
# Rule context + generic helpers
# ---------------------------------------------------------------------------

class Ctx:
    """Per-file scan context."""

    def __init__(self, path, lang, lines):
        self.path = path
        self.lang = lang
        self.lines = lines
        self.tainted = find_tainted_vars(lines, lang)
        self.formatted = find_formatted_vars(lines, lang)

    def hit(self, rule_id, severity, title, lineno, why, fix, taint=None):
        return Finding(rule_id, severity, title, self.path, lineno,
                       snippet_of(self.lines, lineno), why, fix, taint)

    def flow(self, args):
        """Taint flow into call arguments.

        Returns (var_name_or_None, source_text_or_None). Detects variables
        assigned from tainted sources AND direct source usage such as
        query($_GET['id']) (1-hop).
        """
        return _flow_in(args, self.tainted, self.lang)


def regex_rule(ctx, rule_id, severity, title, patterns, why, fix,
               exclude=None):
    """Generic regex-per-line rule. patterns: {lang: [regex, ...]}."""
    findings = []
    for i, line in enumerate(ctx.lines, 1):
        for pat in patterns.get(ctx.lang, []):
            if re.search(pat, line):
                if exclude and exclude(line):
                    continue
                findings.append(ctx.hit(rule_id, severity, title, i, why, fix))
                break  # one finding per line per rule
    return findings


# Lines that are clearly test/example placeholders, not real secrets.
PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?|test[_-]?|example[_-]?|sample[_-]?|xxx+|changeme|"
    r"placeholder|dummy|fake|<[^>]+>|\{[^}]*\}|\$\{|\bpassword123\b|"
    r"\b123456\b|\bqwerty\b)")


def _secret_value_ok(value):
    v = value.strip()
    if PLACEHOLDER_RE.search(v):
        return False
    if len(set(v)) < 4:          # "aaaaaaa", "xxxxxxxx"
        return False
    return True


# ---------------------------------------------------------------------------
# SEC — hardcoded secrets
# ---------------------------------------------------------------------------

def rule_SEC001(ctx):
    """Hardcoded API key / token / secret."""
    pats = {
        "js": [r"(?i)(?<![A-Za-z0-9])(api[_-]?key|apikey|api[_-]?secret|auth[_-]?token|"  # loophole: skip=SEC005
               r"access[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*"
               r"['\"]([^'\"\s]{12,})['\"]"],
        "py": [r"(?i)(?<![A-Za-z0-9])(api[_-]?key|apikey|api[_-]?secret|auth[_-]?token|"  # loophole: skip=SEC005
               r"access[_-]?token|secret[_-]?key|client[_-]?secret)\s*=\s*"
               r"['\"]([^'\"\s]{12,})['\"]"],
        "go": [r"(?i)(?<![A-Za-z0-9])(api[_-]?key|apikey|api[_-]?secret|auth[_-]?token|"  # loophole: skip=SEC005
               r"access[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*"
               r"\"([^\"]{12,})\""],
        "php": [r"(?i)(?<![A-Za-z0-9])(api[_-]?key|apikey|api[_-]?secret|auth[_-]?token|"  # loophole: skip=SEC005
                r"access[_-]?token|secret[_-]?key|client[_-]?secret)\s*=>?\s*"
                r"['\"]([^'\"\s]{12,})['\"]"],
    }

    def exclude(line):
        if re.search(r"(?i)(process\.env|os\.environ|getenv|getenv\s*\()", line):
            return True
        m = re.search(r"['\"]([^'\"]+)['\"]\s*$", line)
        return m is not None and not _secret_value_ok(m.group(1))

    return regex_rule(
        ctx, "SEC001", "high", "Hardcoded API key / token / secret", pats,
        "Secrets baked into source leak through version control, logs and "
        "build artifacts. Anyone with read access owns the credential.",
        "Load secrets from environment variables or a secrets manager "
        "(e.g. process.env.API_KEY, os.environ[\"API_KEY\"]). Rotate any "
        "exposed key immediately.",
        exclude=exclude)


def rule_SEC002(ctx):
    """Hardcoded password."""
    pats = {
        "js": [r"(?i)(?<![A-Za-z0-9])(passw(or)?d|passwd|pwd)(?![A-Za-z])\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]"],
        "py": [r"(?i)(?<![A-Za-z0-9])(passw(or)?d|passwd|pwd)(?![A-Za-z])\s*=\s*['\"]([^'\"\s]{4,})['\"]"],
        "go": [r"(?i)(?<![A-Za-z0-9])(passw(or)?d|passwd|pwd)(?![A-Za-z])\s*[:=]\s*\"([^\"]{4,})\""],
        "php": [r"(?i)(?<![A-Za-z0-9])(passw(or)?d|passwd|pwd)(?![A-Za-z])\s*=>?\s*['\"]([^'\"\s]{4,})['\"]"],
    }

    def exclude(line):
        if re.search(r"(?i)(process\.env|os\.environ|getenv|getpass|prompt\s*\()", line):
            return True
        m = re.search(r"['\"]([^'\"]+)['\"]", line)
        return m is not None and not _secret_value_ok(m.group(1))

    return regex_rule(
        ctx, "SEC002", "high", "Hardcoded password", pats,
        "Passwords in source are visible to everyone with repo access and "
        "persist in git history forever.",
        "Read credentials from env vars or a vault at runtime. Rotate any "
        "exposed password.",
        exclude=exclude)


def rule_SEC003(ctx):
    """Private key material committed to source."""
    pats = {lang: [r"-----BEGIN (?:RSA )?PRIVATE KEY-----"]
            for lang in ("js", "py", "go", "php")}
    return regex_rule(
        ctx, "SEC003", "critical", "Private key in source code", pats,
        "A committed private key is a fully compromised identity. Cloning "
        "the repo (or any leak of it) hands attackers the key.",
        "Delete the key from the repo AND from git history (e.g. git filter-"
        "repo), revoke/replace the keypair, load keys from a secrets manager.",
        exclude=lambda line: "BEGIN PUBLIC KEY" in line)


def rule_SEC004(ctx):
    """AWS access key ID."""
    pats = {lang: [r"\bAKIA[0-9A-Z]{16}\b"]
            for lang in ("js", "py", "go", "php")}
    return regex_rule(
        ctx, "SEC004", "high", "Hardcoded AWS access key ID", pats,
        "AWS keys in code get harvested by scanners within minutes of a "
        "public push and abused for cryptomining / data theft.",
        "Use IAM roles / instance profiles or env vars. Deactivate the "
        "exposed key in the AWS console immediately.")


def rule_SEC005(ctx):
    """High-entropy string assigned to a secret-looking variable."""
    name_pat = re.compile(
        r"(?i)(token|secret|api[_-]?key|password|passwd|private[_-]?key)")
    str_pat = {
        "js": re.compile(r"['\"`]([^'\"`\s]{20,})['\"`]"),
        "py": re.compile(r"['\"]([^'\"\s]{20,})['\"]"),
        "go": re.compile(r"\"([^\"]{20,})\""),
        "php": re.compile(r"['\"]([^'\"\s]{20,})['\"]"),
    }
    # don't double-report lines already caught by SEC001/SEC002
    findings = []
    lit = str_pat[ctx.lang]
    for i, line in enumerate(ctx.lines, 1):
        if not name_pat.search(line):
            continue
        if re.search(r"(?i)(process\.env|os\.environ|getenv|getpass)", line):
            continue
        m = lit.search(line)
        if not m:
            continue
        val = m.group(1)
        if not _secret_value_ok(val):
            continue
        if shannon_entropy(val) >= 4.5:
            findings.append(ctx.hit(
                "SEC005", "medium", "High-entropy secret-like string", i,
                "A long, random-looking string stored under a secret-like "
                "name is almost certainly a real credential baked into code.",
                "Move it to an environment variable or secrets manager and "
                "rotate it."))
    return findings


# ---------------------------------------------------------------------------
# SQLI — SQL injection
# ---------------------------------------------------------------------------

SQLI_WHY = ("User input concatenated into a SQL string lets attackers break "
            "out of the query — classic `' OR '1'='1` — to read, modify or "
            "delete data, or escalate to OS command execution.")
SQLI_FIX = ("Use parameterized queries / prepared statements with bound "
            "parameters (?, $1, %s, :name). Never build SQL by concatenating "
            "strings.")


def _sqli_js(ctx):
    out = []
    for i, line in enumerate(ctx.lines, 1):
        args = call_args(line, r"\.(query|execute)")
        if args is None:
            continue
        first = _first_arg(args).strip()
        taint_var, taint_src = ctx.flow(args)
        if ("${" in first
                or re.search(r"['\"`]\s*\+\s*|\+\s*['\"`]", first)
                or first in ctx.formatted):
            out.append(ctx.hit("SQLI001", "high",
                               "SQL injection via string building (JS/TS)", i,
                               SQLI_WHY, SQLI_FIX,
                               taint=_taint_note(taint_var, taint_src,
                                                 "query")))
        elif taint_var and "?" not in first and "$1" not in first:
            out.append(ctx.hit(
                "SQLI001", "high", "Tainted input into SQL query (JS/TS)", i,
                SQLI_WHY, SQLI_FIX,
                taint=_taint_note(taint_var, taint_src, "query")))
    return out


def _sqli_py(ctx):
    out = []
    for i, line in enumerate(ctx.lines, 1):
        args = call_args(line, r"\.(execute|executemany|executescript)")
        if args is None:
            continue
        first = _first_arg(args).strip()
        taint_var, taint_src = ctx.flow(args)
        dynamic = (re.match(r"""f['"]""", first) is not None
                   or re.search(r"""['"]\s*%\s*(\(|\w)""", first) is not None
                   or ".format(" in first
                   or re.search(r"""['"]\s*\+\s*|\+\s*['"]""", first)
                   is not None
                   or first in ctx.formatted)
        has_placeholder = ("?" in first or "%s" in first
                           or re.search(r":\w|%\(", first) is not None)
        if dynamic:
            out.append(ctx.hit("SQLI002", "high",
                               "SQL injection via string formatting (Python)",
                               i, SQLI_WHY, SQLI_FIX,
                               taint=_taint_note(taint_var, taint_src,
                                                 "execute")))
        elif taint_var and not has_placeholder:
            out.append(ctx.hit(
                "SQLI002", "high", "Tainted input into SQL execute (Python)",
                i, SQLI_WHY, SQLI_FIX,
                taint=_taint_note(taint_var, taint_src, "execute")))
    return out


def _sqli_go(ctx):
    out = []
    for i, line in enumerate(ctx.lines, 1):
        args = call_args(line, r"\.(Query|QueryRow|Exec)\b")
        if args is None:
            continue
        first = _first_arg(args).strip()
        taint_var, taint_src = ctx.flow(args)
        if ("fmt.Sprintf" in first
                or re.search(r'"\s*\+\s*|\+\s*"', first) is not None
                or first in ctx.formatted):
            out.append(ctx.hit("SQLI003", "high",
                               "SQL injection via string building (Go)", i,
                               SQLI_WHY, SQLI_FIX,
                               taint=_taint_note(taint_var, taint_src,
                                                 "Query")))
        elif taint_var and "?" not in first and "$1" not in first:
            out.append(ctx.hit(
                "SQLI003", "high", "Tainted input into SQL query (Go)", i,
                SQLI_WHY, SQLI_FIX,
                taint=_taint_note(taint_var, taint_src, "Query")))
    return out


def _sqli_php(ctx):
    out = []
    for i, line in enumerate(ctx.lines, 1):
        args = call_args(line, r"(mysql_query|mysqli_query|->query)")
        if args is None:
            continue
        # mysqli_query($conn, $sql): the query may be the 2nd arg
        taint_var, taint_src = ctx.flow(args)
        formatted_hit = any(word_in(args, v) for v in ctx.formatted)
        if (re.search(r"""\$\w+\s*\.\s*['"]|['"]\s*\.\s*\$\w+""", args)
                or formatted_hit):
            out.append(ctx.hit("SQLI004", "high",
                               "SQL injection via string concat (PHP)", i,
                               SQLI_WHY, SQLI_FIX,
                               taint=_taint_note(taint_var, taint_src,
                                                 "query")))
        elif taint_var and "?" not in args:
            out.append(ctx.hit(
                "SQLI004", "high", "Tainted input into SQL query (PHP)", i,
                SQLI_WHY, SQLI_FIX,
                taint=_taint_note(taint_var, taint_src, "query")))
    return out


# ---------------------------------------------------------------------------
# XSS — cross-site scripting
# ---------------------------------------------------------------------------

def rule_XSS001(ctx):
    """innerHTML / outerHTML assigned (+=) dynamic content."""
    pats = {"js": [r"\.(innerHTML|outerHTML)\s*\+?=(?!=)\s*(?![\"'`]\s*;)"]}
    findings = []
    for i, line in enumerate(ctx.lines, 1):
        m = re.search(pats["js"][0], line)
        if not m:
            continue
        rhs = line[m.end():]
        rhs_code = re.sub(r"\s*//.*$", "", rhs)  # ignore trailing comment
        if is_string_literal(rhs_code.rstrip(" ;")):
            continue  # static HTML string: safe
        taint_var, taint_src = ctx.flow(rhs)
        findings.append(ctx.hit(
            "XSS001", "high", "Dynamic HTML via innerHTML", i,
            "Assigning attacker-influenced strings to innerHTML executes "
            "arbitrary JavaScript in the victim's browser (session theft, "
            "defacement, malware).",
            "Use textContent for text, or sanitize HTML with DOMPurify before "
            "assigning to innerHTML.",
            taint=_taint_note(taint_var, taint_src, "innerHTML")))
    return findings


def rule_XSS002(ctx):
    """document.write with dynamic content."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        args = call_args(line, r"document\.write(?:ln)?")
        if args is None or is_string_literal(args):
            continue
        taint_var, taint_src = ctx.flow(args)
        out.append(ctx.hit(
            "XSS002", "medium", "Dynamic document.write()", i,
            "document.write with dynamic content is an XSS sink and also "
            "blocks page rendering.",
            "Build DOM with createElement/textContent or sanitize first.",
            taint=_taint_note(taint_var, taint_src, "document.write")))
    return out


def rule_XSS003(ctx):
    """React dangerouslySetInnerHTML."""
    pats = {"js": [r"dangerouslySetInnerHTML\s*="]}
    return regex_rule(
        ctx, "XSS003", "high", "dangerouslySetInnerHTML used", pats,
        "The name says it all: raw HTML is injected into the DOM. If any "
        "part of __html comes from user input, it is stored/reflected XSS.",
        "Avoid it; render text/JSX instead, or sanitize with DOMPurify.")


def rule_XSS004(ctx):
    """PHP echo/print of superglobals without escaping."""
    pats = {"php": [r"<\?=\s*\$_(GET|POST|REQUEST|COOKIE)\b",
                    r"\b(echo|print)\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)\b"]}
    findings = []
    for i, line in enumerate(ctx.lines, 1):
        for pat in pats["php"]:
            m = re.search(pat, line)
            if not m:
                continue
            if "htmlspecialchars" in line or "htmlentities" in line:
                break  # escaped: safe
            findings.append(ctx.hit(
                "XSS004", "high", "Unescaped echo of user input (PHP)", i,
                "Printing $_GET/$_POST directly reflects attacker input into "
                "the page — reflected XSS.",
                "Escape with htmlspecialchars($v, ENT_QUOTES, 'UTF-8')."))
            break
    return findings


# ---------------------------------------------------------------------------
# CMD — command injection
# ---------------------------------------------------------------------------

CMD_WHY = ("Passing user-influenced strings to a shell lets attackers append "
           "commands (`; rm -rf /`, `$(...)`, `&& ...`) that run with the "
           "app's privileges — full server compromise.")
CMD_FIX = ("Avoid shells entirely: use execFile/spawn with an argument array "
           "(no shell), or shlex.quote() / escapeshellarg(). Never "
           "concatenate input into a command string.")


def _cmd_dynamic(args, tainted):
    if args is None:
        return False, None
    if is_string_literal(args):
        return False, None
    taint_var = tainted_in_call(args, tainted)
    # variable / concat / interpolation present
    if (re.search(r"\+\s*['\"]|['\"]\s*\+|\$\{|`[^`]*\$\{", args)
            or taint_var
            or re.search(r"[A-Za-z_$][\w$]*", args)):
        return True, taint_var
    return False, None


def rule_CMD001(ctx):
    """JS child_process exec/spawn with dynamic command."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        for func in (r"(?:child_process\.|cp\.)?(exec|execSync)\b",
                     r"(?:child_process\.|cp\.)?(spawn|spawnSync)\b"):
            if not re.search(func + r"\s*\(", line):
                continue
            args = call_args(line, func)
            if args is None:
                continue
            first = _first_arg(args).strip()
            taint_var, taint_src = ctx.flow(args)
            shell_true = re.search(r"shell\s*:\s*true", args) is not None
            # the *command* (first arg) must be dynamic to be injectable;
            # execFile("ls") with a literal is safe
            dynamic = (not is_string_literal(first)
                       or "${" in first
                       or taint_var is not None)
            if dynamic or (shell_true and taint_var):
                out.append(ctx.hit(
                    "CMD001", "critical",
                    "Command injection via child_process (JS/TS)", i,
                    CMD_WHY, CMD_FIX,
                    taint=_taint_note(taint_var, taint_src, "exec")))
                break
    return out


def rule_CMD002(ctx):
    """Python os.system / shell=True with dynamic command."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        for func in (r"os\.system", r"os\.popen",
                     r"subprocess\.(call|run|Popen|check_output)"):
            args = call_args(line, func)
            if args is None:
                continue
            if "subprocess" in func and not re.search(
                    r"shell\s*=\s*True", args):
                continue  # list-form subprocess without shell: safe
            dyn, taint_var = _cmd_dynamic(args, ctx.tainted)
            if dyn:
                out.append(ctx.hit(
                    "CMD002", "critical",
                    "Command injection via shell (Python)", i,
                    CMD_WHY,
                    "Use subprocess.run([...]) with an argument list and "
                    "shell=False (the default).",
                    taint=(f"{ctx.tainted[taint_var]} -> {func.split('.')[-1]}"
                           if taint_var else None)))
                break
    return out


def rule_CMD003(ctx):
    """Go exec.Command with dynamic args / sh -c."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        args = call_args(line, r"exec\.Command")
        if args is None:
            continue
        taint_var, taint_src = ctx.flow(args)
        if re.search(r'"sh"\s*,\s*"-c"', args) and (
                taint_var or re.search(r",\s*[a-zA-Z_]\w*\s*\)?\s*$", args)):
            out.append(ctx.hit(
                "CMD003", "critical", "Shell invocation via exec.Command (Go)",
                i, CMD_WHY,
                "Call the binary directly with exec.Command(name, args...) "
                "and never route user input through sh -c.",
                taint=_taint_note(taint_var, taint_src, "exec.Command")))
        elif taint_var:
            out.append(ctx.hit(
                "CMD003", "high", "Tainted arg to exec.Command (Go)", i,
                "User input reaches a process argument. Lower risk than "
                "sh -c, but argument injection is still possible.",
                "Validate/allowlist the argument; avoid sh -c entirely.",
                taint=_taint_note(taint_var, taint_src, "exec.Command")))
    return out


def rule_CMD004(ctx):
    """PHP exec/system/shell_exec/passthru with dynamic command."""
    pats = {"php": [r"(?i)\b(exec|system|shell_exec|passthru|popen|"
                    r"proc_open)\s*\("]}
    out = []
    for i, line in enumerate(ctx.lines, 1):
        m = re.search(pats["php"][0], line)
        if not m:
            continue
        args = call_args(line, r"(?i)\b" + m.group(1))
        if args is None or is_string_literal(args):
            continue
        taint_var, taint_src = ctx.flow(args)
        if "$" in args or taint_var:
            out.append(ctx.hit(
                "CMD004", "critical",
                f"Command injection via {m.group(1)}() (PHP)", i,
                CMD_WHY,
                "Use escapeshellarg() on every argument, or avoid shell "
                "functions entirely.",
                taint=_taint_note(taint_var, taint_src,
                                     m.group(1) + "()")))
    return out


# ---------------------------------------------------------------------------
# PATH — path traversal / local file inclusion
# ---------------------------------------------------------------------------

FILE_SINKS = {
    "js": [r"(?:fs\.)?(readFile|readFileSync|writeFile|writeFileSync|"
           r"createReadStream|createWriteStream)\s*\("],
    "py": [r"(?<![\w.])open\s*\("],
    "go": [r"(?:os|ioutil)\.(Open|OpenFile|ReadFile|WriteFile|Create)\s*\("],
    "php": [r"(?i)\b(file_get_contents|file_put_contents|fopen|readfile|"
            r"include|include_once|require|require_once)\s*\(?"],
}


def rule_PATH001(ctx):
    """File operation on user-influenced path."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        for pat in FILE_SINKS[ctx.lang]:
            m = re.search(pat, line)
            if not m:
                continue
            func = m.group(0)
            fname = re.sub(r"\s*\($", "", func)
            args = call_args(line, re.escape(fname))
            if args is None:
                # PHP allows paren-less: include $file; / require "x.php";
                rest = line[m.end():].strip().rstrip(";").strip()
                args = rest if rest else None
            if args is None or is_string_literal(args):
                continue
            taint_var, taint_src = ctx.flow(args)
            dynamic = (taint_var is not None or taint_src is not None
                       or re.search(r"\+\s*|\.\s*\$|\$\{", args)
                       is not None)
            if dynamic and ".." not in args:
                out.append(ctx.hit(
                    "PATH001", "high",
                    "File access with user-influenced path", i,
                    "An attacker-controlled path reaches a file operation: "
                    "read arbitrary files (/etc/passwd), overwrite code, or "
                    "include remote/local payloads.",
                    "Resolve against an allowlisted base directory "
                    "(realpath + startswith check), reject '..' and absolute "
                    "paths, map input through an allowlist.",
                    taint=_taint_note(taint_var, taint_src, fname + "()")))
                break
    return out


def rule_PATH002(ctx):
    """'..' traversal sequence combined with user input."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        for pat in FILE_SINKS[ctx.lang]:
            m = re.search(pat, line)
            if not m:
                continue
            func = m.group(0)
            fname = re.sub(r"\s*\($", "", func)
            args = call_args(line, re.escape(fname))
            if args is None:
                # PHP allows paren-less: include $file;
                rest = line[m.end():].strip().rstrip(";").strip()
                args = rest if rest else None
            if args is None or ".." not in args:
                continue
            taint_var, taint_src = ctx.flow(args)
            if taint_var or taint_src or re.search(
                    r"\+\s*|\.\s*\$|\$\{", args):
                out.append(ctx.hit(
                    "PATH002", "medium",
                    "Directory traversal ('..') with user input", i,
                    "'..' sequences let attackers escape the intended "
                    "directory and read/write files elsewhere on disk.",
                    "Canonicalize the path (realpath) and verify it stays "
                    "inside the intended base directory.",
                    taint=_taint_note(taint_var, taint_src, fname + "()")))
                break
    return out


# ---------------------------------------------------------------------------
# RAND — insecure randomness
# ---------------------------------------------------------------------------

def rule_RAND001(ctx):
    """Math.random() used for security-sensitive values (JS/TS)."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        if not re.search(r"Math\.random\s*\(\)", line):
            continue
        context = line if i == 1 else ctx.lines[i - 2] + chr(10) + line
        if not re.search(r"(?i)(token|secret|password|passwd|key|nonce|otp|"
                         r"session|uuid|captcha|salt)", context):
            continue
        out.append(ctx.hit(
            "RAND001", "medium",
            "Math.random() for security-sensitive value", i,
            "Math.random() is predictable (not cryptographically secure). "
            "Tokens/sessions built on it can be guessed.",
            "Use crypto.randomUUID(), crypto.randomBytes() or "
            "crypto.randomInt() from node:crypto / WebCrypto."))
    return out


def rule_RAND002(ctx):
    """random module used for secrets (Python)."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        if not re.search(r"\brandom\.(random|randint|choice|randrange|"
                         r"uniform)\s*\(", line):
            continue
        if "secrets" in line:
            continue
        context = line if i == 1 else ctx.lines[i - 2] + chr(10) + line
        if not re.search(r"(?i)(token|secret|password|passwd|key|nonce|otp|"
                         r"session|uuid|captcha|salt)", context):
            continue
        out.append(ctx.hit(
            "RAND002", "medium",
            "random module for security-sensitive value (Python)", i,
            "The random module is deterministic/Mersenne-Twister based — "
            "unsuitable for tokens, passwords or salts.",
            "Use the secrets module: secrets.token_urlsafe(), "
            "secrets.randbelow(), secrets.choice()."))
    return out


def rule_RAND003(ctx):
    """math/rand used for secrets (Go)."""
    out = []
    # rand.X resolves to crypto/rand when that is the only rand import
    imports_crypto = any('"crypto/rand"' in l for l in ctx.lines)
    imports_math = any('"math/rand"' in l for l in ctx.lines)
    if imports_crypto and not imports_math:
        return out
    for i, line in enumerate(ctx.lines, 1):
        if not re.search(r"\brand\.(Intn|Int|Float64|Read|Shuffle)\s*\(",
                         line):
            continue
        if "crypto/rand" in line:
            continue
        context = line if i == 1 else ctx.lines[i - 2] + "\n" + line
        if not re.search(r"(?i)(token|secret|password|passwd|key|nonce|otp|"
                         r"session|uuid|captcha|salt)", context):
            continue
        out.append(ctx.hit(
            "RAND003", "medium",
            "math/rand for security-sensitive value (Go)", i,
            "math/rand is predictable. Tokens built on it can be brute-"
            "forced.",
            "Use crypto/rand: rand.Int(rand.Reader, big.NewInt(n))."))
    return out


# ---------------------------------------------------------------------------
# CRY — weak crypto
# ---------------------------------------------------------------------------

def rule_CRY001(ctx):
    """MD5 used with passwords."""
    pats = {
        "js": [r"(?i)(md5|createHash\s*\(\s*['\"]md5['\"]).{0,60}password|"
               r"password.{0,60}(md5|createHash\s*\(\s*['\"]md5['\"])"],
        "py": [r"(?i)(hashlib\.md5|md5\s*\().{0,60}password|"
               r"password.{0,60}(hashlib\.md5|\bmd5\s*\()"],
        "go": [r"(?i)(md5\.New|md5\.Sum).{0,60}password|"
               r"password.{0,60}(md5\.New|md5\.Sum)"],
        "php": [r"(?i)(md5\s*\().{0,60}password|"
               r"password.{0,60}\bmd5\s*\("],
    }
    return regex_rule(
        ctx, "CRY001", "high", "MD5 used for password hashing", pats,
        "MD5 is broken (collisions in seconds) and far too fast — password "
        "hashes fall to brute force almost instantly.",
        "Use bcrypt, scrypt or Argon2id (never fast hashes) for passwords.")


def rule_CRY002(ctx):
    """SHA-1 used with passwords."""
    pats = {
        "js": [r"(?i)(sha1|createHash\s*\(\s*['\"]sha1['\"]).{0,60}password|"
               r"password.{0,60}(sha1|createHash\s*\(\s*['\"]sha1['\"])"],
        "py": [r"(?i)(hashlib\.sha1|\bsha1\s*\().{0,60}password|"
               r"password.{0,60}(hashlib\.sha1|\bsha1\s*\()"],
        "go": [r"(?i)(sha1\.New|sha1\.Sum).{0,60}password|"
               r"password.{0,60}(sha1\.New|sha1\.Sum)"],
        "php": [r"(?i)(sha1\s*\().{0,60}password|"
               r"password.{0,60}\bsha1\s*\("],
    }
    return regex_rule(
        ctx, "CRY002", "high", "SHA-1 used for password hashing", pats,
        "SHA-1 is shattered (practical collisions) and too fast for password "
        "storage.",
        "Use bcrypt, scrypt or Argon2id for passwords.")


def rule_CRY003(ctx):
    """DES / 3DES / RC4 / deprecated ciphers."""
    pats = {
        "js": [r"createCipher\s*\(", r"(?i)['\"]des(-ede3?)?['\"]",  # loophole: skip=CRY003
               r"(?i)['\"]rc4['\"]"],
        "py": [r"(?i)\bDES(\.new|_new)?\s*\(", r"(?i)\bARC4\s*\("],
        "go": [r"\bdes\.NewCipher\b", r"\bdes\.NewTripleDESCipher\b",
               r"\brc4\.NewCipher\b"],
        "php": [r"(?i)['\"]des(-ede3?)?['\"]", r"MCRYPT_DES\b"],  # loophole: skip=CRY003
    }
    return regex_rule(
        ctx, "CRY003", "medium", "Weak cipher (DES/3DES/RC4)", pats,
        "DES has a 56-bit key (brute-forced); RC4 is biased and broken. "
        "Data encrypted with them is recoverable.",
        "Use AES-256-GCM (or ChaCha20-Poly1305) via a modern library.")


def rule_CRY004(ctx):
    """Hardcoded initialization vector."""
    pats = {
        "js": [r"createCipheriv\s*\([^,]+,\s*['\"][^'\"]{8,}['\"]",
               r"(?i)\biv\s*=\s*['\"][0-9a-fA-F]{16,}['\"]"],
        "py": [r"(?i)\biv\s*=\s*[b]?['\"][^'\"]{8,}['\"]"],
        "go": [r"(?i)\biv\s*:?=\s*\[\]byte\s*\(\s*\"[^\"]{8,}\""],
        "php": [r"(?i)\$iv\s*=\s*['\"][^'\"]{8,}['\"]"],
    }
    return regex_rule(
        ctx, "CRY004", "medium", "Hardcoded IV", pats,
        "Reusing a fixed IV with CBC/GCM leaks plaintext patterns and, for "
        "GCM, can destroy confidentiality entirely.",
        "Generate a fresh random IV per encryption (crypto.randomBytes / "
        "os.urandom / crypto/rand) and store it with the ciphertext.")


# ---------------------------------------------------------------------------
# EVAL — dynamic code execution
# ---------------------------------------------------------------------------

def rule_EVAL001(ctx):
    """eval() / exec() / compile() with dynamic input."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        for builtin in ("eval", "exec", "compile"):
            # exec()/compile() are Python builtins: JS exec is child_process
            # (CMD001's territory) and PHP has no builtin by these names.
            if builtin != "eval" and ctx.lang != "py":
                continue
            m = re.search(r"(?<![\w.])" + builtin + r"\s*\(", line)
            if not m:
                continue
            args = call_args(line, r"(?<![\w.])" + builtin)
            if args is None:
                continue
            if builtin == "compile":
                # Only the source argument matters; the mode/filename args
                # are literals by construction.
                args = _first_arg(args)
            if is_string_literal(args):
                continue  # eval("1+1") — smelly but not exploitable
            taint_var, taint_src = ctx.flow(args)
            if re.search(r"\$\w+|\+\s*['\"]|['\"]\s*\+|\$\{|%s|f['\"]", args) \
                    or taint_var or taint_src or re.search(r"[A-Za-z_$][\w$]*", args):
                out.append(ctx.hit(
                    "EVAL001", "critical", f"{builtin}() with dynamic input", i,
                    f"{builtin}() runs attacker-controlled strings as code "
                    "in the app's context — arbitrary code execution.",
                    f"Never {builtin}() dynamic input. Use JSON.parse, "
                    "ast.literal_eval, or a proper parser instead.",
                    taint=_taint_note(taint_var, taint_src, f"{builtin}()")))
    return out


def rule_EVAL002(ctx):
    """new Function() with dynamic input (JS/TS)."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        m = re.search(r"\bnew\s+Function\s*\(", line)
        if not m:
            continue
        args = call_args(line, r"\bnew\s+Function")
        if args is None or is_string_literal(args):
            continue
        taint_var, taint_src = ctx.flow(args)
        out.append(ctx.hit(
            "EVAL002", "high", "new Function() with dynamic input", i,
            "new Function() compiles strings to code — same arbitrary-code-"
            "execution risk class as eval().",
            "Refactor to static functions or a lookup table.",
            taint=_taint_note(taint_var, taint_src, "new Function()")))
    return out


# ---------------------------------------------------------------------------
# SSRF — server-side request forgery
# ---------------------------------------------------------------------------

def rule_SSRF001(ctx):
    """Outbound request to a user-influenced URL."""
    sinks = {
        "js": [r"(?<![\w.])fetch\s*\(", r"axios\.(get|post|request)\s*\(",
               r"request\s*\(\s*['\"]?https?"],
        "py": [r"requests\.(get|post|put|delete|request)\s*\(",
               r"urllib\.request\.urlopen\s*\("],
        "go": [r"http\.Get\s*\(", r"http\.Post\s*\(",
               r"http\.NewRequest\s*\("],
        "php": [r"curl_init\s*\(",
                r"file_get_contents\s*\(\s*['\"]https?://"],
    }
    out = []
    for i, line in enumerate(ctx.lines, 1):
        for pat in sinks[ctx.lang]:
            m = re.search(pat, line)
            if not m:
                continue
            fname = re.sub(r"\s*\($", "", m.group(0))
            args = call_args(line, re.escape(fname))
            if args is None:
                continue
            if is_string_literal(args):
                continue  # fixed URL: safe
            taint_var, taint_src = ctx.flow(args)
            dynamic = (taint_var is not None or taint_src is not None
                       or re.search(r"\+\s*['\"]|['\"]\s*\+|\.\s*\$|\$\{|"
                                   r"%\s*\(|f['\"]", args) is not None)
            if dynamic:
                out.append(ctx.hit(
                    "SSRF001", "high",
                    "SSRF: user-influenced URL in outbound request", i,
                    "An attacker-controlled URL makes the server issue "
                    "requests to internal services (169.254.169.254 cloud "
                    "metadata, intranet) — credential and network theft.",
                    "Validate against an allowlist of hosts/schemes, block "
                    "private/reserved IP ranges, disable redirects or "
                    "re-validate after each hop.",
                    taint=_taint_note(taint_var, taint_src,
                                                 fname + "()")))
                break
    return out


# ---------------------------------------------------------------------------
# AUTH — missing authentication (heuristic)
# ---------------------------------------------------------------------------

_SENSITIVE_PATH = re.compile(
    r"(?i)/(admin|administrator|private|internal|dashboard|manage|"
    r"management|settings|config|account)(/|$|\?)")


def rule_AUTH001(ctx):
    """Sensitive route without visible auth middleware (heuristic)."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        # Express-style: app.get('/admin/...', handler) or with middleware
        m = re.search(
            r"(?:app|router)\.(get|post|put|patch|delete|all|use)\s*\(\s*"
            r"['\"]([^'\"]+)['\"]\s*,(.*)", line)
        if m and ctx.lang == "js":
            path, rest = m.group(2), m.group(3)
            if _SENSITIVE_PATH.search(path) and not re.search(
                    r"(?i)(auth|requireAuth|isAuthenticated|ensureAuth|"
                    r"verifyToken|checkAuth|passport\.authenticate)", rest):
                # same-line arrow handler with no middleware
                out.append(ctx.hit(
                    "AUTH001", "medium",
                    "Sensitive route without auth middleware?", i,
                    "A route under /admin (or similar) shows no auth "
                    "middleware in its handler chain — it may be exposed to "
                    "anonymous users. (Heuristic: verify manually.)",
                    "Add authentication/authorization middleware "
                    "(e.g. requireAuth) before the handler."))
            continue
        # Flask-style: @app.route('/admin/...') — check decorator above  # loophole: skip=AUTH001
        m2 = re.search(r"@(?:app|bp|blueprint)\.route\s*\(\s*['\"]([^'\"]+)['\"]",
                       line)
        if m2 and ctx.lang == "py":
            path = m2.group(1)
            if _SENSITIVE_PATH.search(path):
                # auth decorator may sit above the route OR between the
                # route and its def (Flask applies decorators top-down):
                #   @app.route('/admin') / @login_required / def view()
                nearby = "\n".join(ctx.lines[max(0, i - 4): i + 3])
                if not re.search(r"(?i)(login_required|requires_auth|"
                                 r"@auth\.|permission_required)", nearby):
                    out.append(ctx.hit(
                        "AUTH001", "medium",
                        "Sensitive route without auth decorator?", i,
                        "A Flask route under /admin (or similar) has no "
                        "@login_required (or equivalent) nearby. "
                        "(Heuristic: verify manually.)",
                        "Add @login_required plus a role/permission check."))
    return out


# ---------------------------------------------------------------------------
# CORS / JWT / TLS
# ---------------------------------------------------------------------------

def rule_CORS001(ctx):
    """Wildcard CORS origin."""
    pats = {
        "js": [r"(?i)Access-Control-Allow-Origin['\"]?\s*\]?\s*[,=:]\s*['\"]\*['\"]",
               r"origin\s*:\s*['\"]\*['\"]"],
        "py": [r"(?i)Access-Control-Allow-Origin['\"]?\s*\]?\s*[,=:]\s*['\"]\*['\"]",
               r"allow_origins\s*=\s*\[[^\]]*\*[^\]]*\]",
               r"CORS\s*\([^)]*origins\s*=\s*['\"]\*['\"]"],
        "go": [r"Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*",
               r"AllowedOrigins\s*:\s*\[\]string\{\s*\"\*\""],
        "php": [r"Access-Control-Allow-Origin:\s*\*",
                r"header\s*\(\s*['\"]Access-Control-Allow-Origin:\s*\*"],
    }
    return regex_rule(
        ctx, "CORS001", "medium", "Wildcard CORS origin (*)", pats,
        "Any website can read responses from this API, enabling CSRF-style "
        "data theft when credentials are involved.",
        "Allowlist explicit origins instead of '*'.")


def rule_JWT001(ctx):
    """JWT decoded without verification."""
    pats = {
        "js": [r"(?i)\bjwt\.decode\s*\("],
        "py": [r"(?i)\bjwt\.decode\s*\("],
        "go": [],
        "php": [r"(?i)JWT::decode\s*\("],
    }
    out = []
    for i, line in enumerate(ctx.lines, 1):
        for pat in pats[ctx.lang]:
            if re.search(pat, line):
                # jwt.decode(..., {complete:true}) style is fine for header  # loophole: skip=JWT001
                # peeking; flag the risky verify-less trust pattern
                out.append(ctx.hit(
                    "JWT001", "high", "JWT decoded without verification", i,
                    "jwt.decode() does NOT verify the signature. Trusting "  # loophole: skip=JWT001
                    "its claims for auth lets attackers forge tokens "
                    "(alg=none / key confusion).",
                    "Always use jwt.verify() (or equivalent) with an "
                    "explicit algorithms allowlist."))
                break
    return out


def rule_TLS001(ctx):
    """TLS certificate verification disabled."""
    pats = {
        "js": [r"rejectUnauthorized\s*:\s*false"],
        "py": [r"\bverify\s*=\s*False\b"],
        "php": [r"CURLOPT_SSL_VERIFYPEER\s*,\s*false"],
    }
    return regex_rule(
        ctx, "TLS001", "high", "TLS verification disabled", pats,
        "Disabling certificate verification opens every HTTPS call to "
        "man-in-the-middle interception and credential theft.",
        "Keep verification enabled; pin or properly provision CA certs "
        "instead of disabling the check.")


# ---------------------------------------------------------------------------
# DBG — debug mode / error leaks
# ---------------------------------------------------------------------------

def rule_DBG001(ctx):
    """Debug mode enabled."""
    pats = {
        "js": [r"(?i)\bdebug\s*:\s*true\b"],
        "py": [r"\bapp\.run\s*\([^)]*debug\s*=\s*True",
               r"(?i)^DEBUG\s*=\s*True"],
        "go": [],
        "php": [r"ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?1",
                r"(?i)\bdisplay_errors\s*=\s*On"],
    }
    return regex_rule(
        ctx, "DBG001", "medium", "Debug mode enabled", pats,
        "Debug mode exposes stack traces, the interactive debugger and "
        "config values to anyone who triggers an error.",
        "Disable debug in production (env-gated config, DEBUG=False).")


def rule_ERR001(ctx):
    """Stack traces / exception details sent to the client."""
    pats = {
        "js": [r"\.(send|json)\s*\([^)]*err\.stack",
               r"\.(send|json)\s*\([^)]*\.stack\b"],
        "py": [r"(return|send)[^;\n]*traceback\.format_exc\s*\("],
        "go": [r"(?i)(http\.Error|WriteHeader)[^;\n]*err\.Error\(\)"],
        "php": [r"\b(die|echo|print)\s*\(\s*\$e->getMessage\s*\(\s*\)",
                r"\becho\s+\$e->getMessage\s*\(\s*\)"],
    }
    return regex_rule(
        ctx, "ERR001", "medium", "Exception details leaked to client", pats,
        "Stack traces and raw exception messages disclose paths, library "
        "versions and internals that help attackers aim exploits.",
        "Log the full error server-side; return a generic message and "
        "correlation ID to the client.")


# ---------------------------------------------------------------------------
# PROTO — prototype pollution (JS/TS)
# ---------------------------------------------------------------------------

def rule_PROTO001(ctx):
    """Prototype pollution via deep-merge / assign of user-controlled keys."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        hit = False
        # lodash-style deep merges are the classic pollution vector
        if re.search(r"(?:_|\blodash)\.(?:merge|mergeWith|defaultsDeep|set)"
                     r"\s*\(", line):
            hit = True
        # Object.assign into a fresh object with request data flowing in
        args = call_args(line, r"Object\.assign")
        if args is not None and ctx.flow(args) != (None, None):
            hit = True
        # direct __proto__ writes
        if re.search(r"\.__proto__\b|\[\s*['\"]__proto__['\"]\s*\]", line):
            hit = True
        if hit:
            out.append(ctx.hit(
                "PROTO001", "high", "Possible prototype pollution (JS/TS)",
                i,
                "Deep-merging attacker-controlled JSON (keys like "
                "__proto__) mutates Object.prototype, corrupting every "
                "object in the process — auth checks and defaults can be "
                "silently rewritten.",
                "Never deep-merge untrusted input. Reject __proto__ / "
                "constructor / prototype keys, use Object.create(null) "
                "maps, or merge with a schema-validated allowlist."))
    return out


# ---------------------------------------------------------------------------
# DESER — unsafe deserialization
# ---------------------------------------------------------------------------

def rule_DESER001(ctx):
    """Untrusted data fed to native object deserializers."""
    out = []
    if ctx.lang == "py":
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"\b(pickle|marshal|dill)\.loads?\s*\(", line) \
                    or re.search(r"\bcpickle\.loads?\s*\(", line):
                out.append(ctx.hit(
                    "DESER001", "high",
                    "Unsafe deserialization (pickle/marshal)", i,
                    "Unpickling attacker-controlled bytes is arbitrary "
                    "code execution — the pickle opcodes run during load, "
                    "before any validation can happen.",
                    "Never unpickle untrusted data. Use JSON (or sign the "
                    "payload with HMAC and verify before loading)."))
            elif re.search(r"\byaml\.load\s*\(", line) \
                    and not re.search(r"(SafeLoader|CSafeLoader)", line):
                out.append(ctx.hit(
                    "DESER001", "high", "yaml.load without SafeLoader", i,
                    "yaml.load with the default Loader constructs arbitrary "
                    "Python objects from YAML tags — code execution from a "
                    "crafted document.",
                    "Use yaml.safe_load(), or pass Loader=yaml.SafeLoader "
                    "explicitly."))
            elif re.search(r"\bshelve\.open\s*\(", line):
                args = call_args(line, r"\bshelve\.open")
                if args is None or is_string_literal(_first_arg(args)):
                    continue
                out.append(ctx.hit(
                    "DESER001", "high",
                    "shelve DB opened on dynamic path", i,
                    "shelve stores values pickled — opening a database "
                    "file chosen by user input lets an attacker point it "
                    "at a crafted db whose values execute code on read.",
                    "Never let untrusted input choose the shelve path — "
                    "use a fixed path under your data directory, and "
                    "prefer JSON or SQLite for untrusted data."))
    elif ctx.lang == "php":
        for i, line in enumerate(ctx.lines, 1):
            # Every unserialize() call starting on this line, with its
            # full argument list even when the call spans lines.
            for args in _iter_call_args(ctx.lines, i, r"\bunserialize"):
                first = _first_arg(args)
                rest = _split_top_level_args(args)
                # Only a locked-down options argument silences the call:
                # ['allowed_classes' => false]. Any other value (true,
                # a class list) — or the text appearing only in a
                # comment — leaves the payload reportable.
                if len(rest) > 1 and re.search(
                        r"""['"]allowed_classes['"]\s*=>\s*false\b""",
                        rest[1]):
                    continue
                if _is_constant_payload(first):
                    continue  # unserializing a constant string: inert
                # Taint as of this call only: assignments after it, and
                # reassignments to trusted data before it, do not count.
                # Flow is checked on the payload argument alone, so
                # tainted options cannot implicate a clean payload.
                tainted_here = _php_tainted_asof(ctx.lines, i)
                taint_var, taint_src = _flow_in(first, tainted_here,
                                                ctx.lang)
                if taint_var or taint_src:
                    # Confirmed user-controlled input (direct superglobal or
                    # a variable assigned from one): object injection.
                    out.append(ctx.hit(
                        "DESER001", "high",
                        "unserialize() on user-controlled input", i,
                        "PHP unserialize() on attacker-controlled strings "
                        "enables object injection — magic methods "
                        "(__wakeup/__unserialize) in any loaded class become "
                        "attacker-controlled.",
                        "Never unserialize user input; use json_decode/"
                        "json_encode, or sign the payload (HMAC) and verify "
                        "before unserializing.",
                        taint=_taint_note(taint_var, taint_src,
                                          "unserialize")))
                else:
                    # Dynamic data whose origin is not visible in this file:
                    # dangerous if it is ever attacker-controlled, so still
                    # flagged, at lower severity than confirmed taint.
                    out.append(ctx.hit(
                        "DESER001", "medium",
                        "unserialize() on dynamic data", i,
                        "PHP unserialize() on a string of unknown origin "
                        "enables object injection if the data is ever "
                        "attacker-controlled — magic methods "
                        "(__wakeup/__unserialize) in any loaded class become "
                        "attacker-controlled.",
                        "Use json_decode() for untrusted data, or pass "
                        "['allowed_classes' => false] to unserialize()."))
    elif ctx.lang == "js":
        pats = [r"\bserialize\.unserialize\s*\(",
                r"require\s*\(\s*['\"]node-serialize['\"]\s*\)"]
        out = regex_rule(
            ctx, "DESER001", "high",
            "Unsafe deserialization (node-serialize)", {"js": pats},
            "node-serialize's unserialize() evaluates embedded functions "
            "in the payload — remote code execution from a crafted string.",
            "Use JSON.parse() for untrusted data; never a deserializer "
            "that revives functions/objects.")
    return out


# ---------------------------------------------------------------------------
# NOSQL — NoSQL injection
# ---------------------------------------------------------------------------

_NOSQL_SINKS = {
    "js": r"\.(find|findOne|findById|updateOne|updateMany|deleteOne|"
          r"deleteMany|replaceOne|aggregate|countDocuments)\s*\(",
    "py": r"\.(find|find_one|update_one|update_many|delete_one|"
          r"delete_many|aggregate|count_documents)\s*\(",
}


def rule_NOSQL001(ctx):
    """User input flowing into a MongoDB-style query."""
    out = []
    sink = _NOSQL_SINKS.get(ctx.lang)
    if not sink:
        return out
    for i, line in enumerate(ctx.lines, 1):
        m = re.search(sink, line)
        if not m:
            continue
        args = line[m.start():]
        taint_var, taint_src = ctx.flow(args)
        if taint_var or taint_src or "$where" in args:
            out.append(ctx.hit(
                "NOSQL001", "high", "NoSQL injection (query from input)",
                i,
                "Passing request data straight into a MongoDB-style query "
                "lets attackers inject operators ($ne, $gt, $where) — the "
                "classic login bypass is {user: x, pass: {$ne: null}}.",
                "Build queries from validated scalar values only; reject "
                "objects/arrays from request bodies (e.g. with a schema "
                "validator) and cast ids explicitly (ObjectId(...)).",
                taint=_taint_note(taint_var, taint_src, "find")))
    return out


# ---------------------------------------------------------------------------
# XXE — XML external entity
# ---------------------------------------------------------------------------

def rule_XXE001(ctx):
    """XML parsing with external entities enabled / not hardened."""
    out = []
    text = "\n".join(ctx.lines)
    if ctx.lang == "py":
        if "defusedxml" in text:
            return out
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"lxml\.etree\.(parse|fromstring|XML|XMLParser)"
                         r"\s*\(", line) \
                    and "resolve_entities=False" not in line:
                out.append(ctx.hit(
                    "XXE001", "high", "lxml parsing (entities resolvable)",
                    i,
                    "lxml resolves external entities by default in several "
                    "entry points — a crafted XML file can read local files "
                    "(file:///etc/passwd) or hit internal services (SSRF).",
                    "Parse with resolve_entities=False, no_network=True — "
                    "or switch to defusedxml."))
            elif re.search(r"xml\.dom\.minidom\.(parse|parseString)\s*\(",
                           line) \
                    or re.search(r"xml\.sax\.(parse|parseString|make_parser)"
                                 r"\b", line):
                out.append(ctx.hit(
                    "XXE001", "high", "XML parser without XXE hardening", i,
                    "The stdlib SAX/minidom parsers can expand external "
                    "entities in untrusted XML — local file disclosure and "
                    "SSRF from an uploaded document.",
                    "Use defusedxml, or disable DTDs/external entities on "
                    "the parser before parsing untrusted XML."))
    elif ctx.lang == "php":
        hardened = "libxml_disable_entity_loader" in text \
            or "LIBXML_NONET" in text
        if hardened:
            return out
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"simplexml_load_(string|file)\s*\(", line) \
                    or re.search(r"->\s*loadXML?\s*\(", line):
                out.append(ctx.hit(
                    "XXE001", "high", "XML load without XXE hardening", i,
                    "Loading untrusted XML without disabling external "
                    "entities lets a crafted document read local files or "
                    "call internal URLs (XXE / SSRF).",
                    "Pass LIBXML_NONET (and LIBXML_NOENT off) to the load "
                    "call, or disable the entity loader on PHP < 8."))
    return out


# ---------------------------------------------------------------------------
# REDIR — open redirect
# ---------------------------------------------------------------------------

_REDIR_SINKS = {
    "js": [r"\.redirect\s*\("],
    "py": [r"(?<![\w.])redirect\s*\(", r"HttpResponseRedirect\s*\(",
           r"RedirectResponse\s*\("],
    "php": [r"\bheader\s*\("],
    "go": [r"http\.Redirect\s*\("],
}


def rule_REDIR001(ctx):
    """Redirect target taken from user input."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        for pat in _REDIR_SINKS[ctx.lang]:
            m = re.search(pat, line)
            if not m:
                continue
            args = line[m.start():]
            if ctx.lang == "php" and "Location:" not in args:
                continue
            if is_string_literal(_first_arg(
                    args[args.find("(") + 1:]) if "(" in args else args):
                continue  # fixed target: safe
            taint_var, taint_src = ctx.flow(args)
            dynamic = (taint_var or taint_src
                       or re.search(r"\+\s*['\"\$]|['\"]\s*\+\s*\$|\$\{"
                                    r"|%\s*\(|f['\"]|\.\s*\$", args))
            if dynamic:
                out.append(ctx.hit(
                    "REDIR001", "medium",
                    "Open redirect (target from user input)", i,
                    "Redirecting to a user-supplied URL turns your trusted "
                    "domain into a phishing springboard and can bypass "
                    "allowlist checks on OAuth/SSO flows.",
                    "Redirect only to paths from an allowlist, or require "
                    "the target to be a local path (starts with a single "
                    "'/' and contains no host).",
                    taint=_taint_note(taint_var, taint_src, "redirect")))
            break
    return out


# ---------------------------------------------------------------------------
# ZIP — Zip Slip (archive extraction path traversal)
# ---------------------------------------------------------------------------

_ZIP_GUARD = re.compile(
    r"(commonpath|abspath|is_within|resolve\s*\(\s*\)|startsWith\s*\(|"
    r"beginPath|canonical)")


def rule_ZIP001(ctx):
    """Archive extraction without validating member paths."""
    text = "\n".join(ctx.lines)
    guarded = _ZIP_GUARD.search(text) is not None
    out = []
    if ctx.lang == "py":
        if guarded:
            return out
        archive_ctx = "zipfile" in text or "tarfile" in text
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"\.extractall\s*\(", line) \
                    or (archive_ctx and re.search(r"\.extract\s*\(", line)):
                out.append(ctx.hit(
                    "ZIP001", "high",
                    "Archive extraction without path validation (Zip Slip)",
                    i,
                    "extractall()/extract() trust member names inside the "
                    "archive — a crafted zip/tar entry named '../../evil' "
                    "writes outside the destination folder (Zip Slip).",
                    "Validate each member: resolve its absolute target "
                    "path and require it to stay inside the destination "
                    "directory (os.path.commonpath check) before writing."))
    elif ctx.lang == "php":
        if guarded:
            return out
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"->\s*extractTo\s*\(", line):
                out.append(ctx.hit(
                    "ZIP001", "high",
                    "ZipArchive::extractTo without path validation", i,
                    "extractTo() writes archive member names verbatim — "
                    "entries with '../' escape the target directory and "
                    "can overwrite application files.",
                    "Iterate entries, resolve each target path, and "
                    "reject any that escape the destination directory."))
    elif ctx.lang == "js":
        if guarded:
            return out
        pats = [r"\.extractAllTo\s*\(", r"extract-zip",
                r"createReadStream\s*\([^)]*\)\s*\.pipe\s*\(\s*unzip"]
        out = regex_rule(
            ctx, "ZIP001", "high",
            "Archive extraction without path validation (Zip Slip)",
            {"js": pats},
            "Bulk-extract helpers write member names verbatim — a "
            "crafted archive entry ('../../evil.js') escapes the target "
            "folder and overwrites files.",
            "Extract entry-by-entry, resolve each output path, and "
            "reject anything outside the destination directory.")
    return out


# ---------------------------------------------------------------------------
# CSRF — cross-site request forgery protection missing (app-level)
# ---------------------------------------------------------------------------

_CSRF_MARKERS = re.compile(
    r"(?i)(csurf|csrf|xsrf|flask_wtf|validate_on_submit|FlaskForm|"
    r"csrf_exempt_check|authenticity_token)")


def rule_CSRF001(ctx):
    """State-changing routes with no CSRF defence anywhere in the file."""
    text = "\n".join(ctx.lines)
    if _CSRF_MARKERS.search(text):
        return []
    out = []
    if ctx.lang == "js":
        if not re.search(r"express\s*\(|require\s*\(\s*['\"]express", text):
            return out
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"\.(post|put|patch|delete)\s*\(", line):
                out.append(ctx.hit(
                    "CSRF001", "medium",
                    "State-changing routes, no CSRF protection (Express)",
                    i,
                    "This Express app mutates state on POST/PUT/DELETE "
                    "but no CSRF token middleware (csurf, csrf-csrf, …) "
                    "appears anywhere in the file — a malicious page can "
                    "ride a logged-in victim's session. (Heuristic.)",
                    "Add CSRF token middleware for cookie-authenticated "
                    "routes, or use SameSite=Lax/Strict cookies plus "
                    "origin checks."))
                break
    elif ctx.lang == "py":
        if "django" in text and "MIDDLEWARE" in text:
            for i, line in enumerate(ctx.lines, 1):
                if "MIDDLEWARE" in line \
                        and "CsrfViewMiddleware" not in text:
                    out.append(ctx.hit(
                        "CSRF001", "medium",
                        "Django MIDDLEWARE without CsrfViewMiddleware", i,
                        "Django's CSRF middleware is absent from "
                        "MIDDLEWARE — POST forms lose Django's built-in "
                        "forgery protection.",
                        "Restore 'django.middleware.csrf."
                        "CsrfViewMiddleware' to MIDDLEWARE."))
                    break
            return out
        if not re.search(r"Flask\s*\(", text):
            return out
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"methods\s*=\s*\[[^\]]*(POST|PUT|PATCH|DELETE)",
                         line) or re.search(r"\.(post|put|delete)\s*\(",
                                             line):
                out.append(ctx.hit(
                    "CSRF001", "medium",
                    "State-changing routes, no CSRF protection (Flask)",
                    i,
                    "This Flask app accepts state-changing requests but "
                    "no CSRF protection (Flask-WTF CSRFProtect, csrf "
                    "tokens, …) appears anywhere in the file. "
                    "(Heuristic.)",
                    "Enable Flask-WTF's CSRFProtect(app) or validate a "
                    "per-session CSRF token on every mutating route."))
                break
    return out


# ---------------------------------------------------------------------------
# UPL — file upload without type validation
# ---------------------------------------------------------------------------

_UPL_MARKERS = re.compile(
    r"(?i)(allowed_file|ALLOWED_EXTENSIONS|fileFilter|mimetype|"
    r"content_type|magic|finfo|getimagesize|pathinfo\s*\([^)]*PATHINFO_EXTENSION"
    r"|extension\s+in|allowedExtensions)")


def rule_UPL001(ctx):
    """Uploads accepted/saved with no file-type validation in the file."""
    text = "\n".join(ctx.lines)
    if _UPL_MARKERS.search(text):
        return []
    out = []
    if ctx.lang == "js":
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"\bmulter\s*\(", line) \
                    or re.search(r"\.single\s*\(|\.array\s*\(", line):
                out.append(ctx.hit(
                    "UPL001", "high",
                    "File upload (multer) without type validation", i,
                    "multer is configured with no fileFilter and no type "
                    "allowlist anywhere in the file — attackers can upload "
                    "executable scripts or oversized files.",
                    "Add a fileFilter that allowlists extensions/MIME "
                    "types, set limits.fileSize, and store uploads "
                    "outside the web root with generated names."))
                break
    elif ctx.lang == "py":
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"request\.files\s*(\[|\.get\s*\()", line):
                out.append(ctx.hit(
                    "UPL001", "high",
                    "File upload saved without type validation", i,
                    "request.files is consumed with no extension/MIME "
                    "allowlist anywhere in the file — a visitor can "
                    "upload a script or malicious payload. "
                    "(secure_filename() alone only sanitizes the name.)",
                    "Validate against an extension allowlist "
                    "(allowed_file()), verify content type, cap size, "
                    "and save with a generated name outside the web root."))
                break
    elif ctx.lang == "php":
        if "$_FILES" not in text:
            return out
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"\bmove_uploaded_file\s*\(", line):
                out.append(ctx.hit(
                    "UPL001", "high",
                    "move_uploaded_file without type validation", i,
                    "$_FILES uploads are stored with no extension/MIME "
                    "validation anywhere in the file — the classic route "
                    "to uploading a web shell.",
                    "Allowlist extensions, verify with finfo/"
                    "mime_content_type, rename uploads randomly, and "
                    "store them outside the web root."))
                break
    return out


# ---------------------------------------------------------------------------
# REDOS — catastrophic-backtracking regex
# ---------------------------------------------------------------------------

_REDOS_CONTEXT = {
    "js": re.compile(r"new\s+RegExp\s*\(|=\s*/[^/\n]+/[gimsuy]*|"
                     r"\.(test|match|replace|split)\s*\("),
    "py": re.compile(r"\bre\.(compile|match|search|fullmatch|findall|sub)"
                     r"\s*\("),
    "go": re.compile(r"regexp\.(Compile|MustCompile)\s*\("),
    "php": re.compile(r"preg_(match|replace|split|grep)\s*\("),
}


def _string_literals(line):
    """Contents of quoted literals on a line (quotes/backticks)."""
    lits = []
    i = 0
    in_str = None
    start = 0
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                lits.append(line[start:i])
                in_str = None
        elif ch in "\"'`":
            in_str = ch
            start = i + 1
        i += 1
    return lits


def _nested_quantifier(rx):
    """True when a (…) group holding + or * is itself repeated — the
    classic catastrophic-backtracking shape, e.g. (a+)+ or (\\w*)*."""
    i = 0
    while i < len(rx):
        if rx[i] == "(" and (i == 0 or rx[i - 1] != "\\"):
            depth = 1
            j = i + 1
            while j < len(rx) and depth:
                if rx[j] == "\\":
                    j += 2
                    continue
                if rx[j] == "(":
                    depth += 1
                elif rx[j] == ")":
                    depth -= 1
                j += 1
            if depth:
                return False
            body = rx[i + 1:j - 1]
            after = rx[j] if j < len(rx) else ""
            if after and after in "+*{":
                inner = re.sub(r"\[[^\]]*\]", "", body)
                inner = re.sub(r"\\.", "", inner)
                if "+" in inner or "*" in inner:
                    return True
            i = j
        else:
            i += 1
    return False


def rule_REDOS001(ctx):
    """Regex with nested quantifiers (ReDoS)."""
    out = []
    pat = _REDOS_CONTEXT[ctx.lang]
    for i, line in enumerate(ctx.lines, 1):
        if not pat.search(line):
            continue
        candidates = _string_literals(line)
        m = re.search(r"=+\s*/(.+?)/[gimsuy]*", line)
        if m:
            candidates.append(m.group(1))
        if any(_nested_quantifier(c) for c in candidates):
            out.append(ctx.hit(
                "REDOS001", "medium",
                "ReDoS-prone regex (nested quantifiers)", i,
                "A repeated group that itself repeats — (a+)+, (\\w*)* — "
                "backtracks exponentially on near-miss input. One crafted "
                "string can pin a CPU and hang the process.",
                "Rewrite without nested quantifiers (possessive/atomic "
                "groups, character classes, or a bounded length + simple "
                "pattern), and cap input length."))
    return out


# ---------------------------------------------------------------------------
# JWT002 — JWT 'none' algorithm / weak secret accepted
# ---------------------------------------------------------------------------

def rule_JWT002(ctx):
    """JWT verification weakened: alg=none allowed or a trivial secret."""
    out = []
    none_pat = re.compile(
        r"(?i)algorithms?\s*[:=]\s*\[[^\]]*['\"]none['\"]")
    weak_pat = re.compile(
        r"(?i)\bjwt\.(verify|decode|sign|encode)\b[^\n]*"
        r"['\"](secret|changeme|password|123456|key)['\"]")
    verify_off = re.compile(
        r"['\"]verify_signature['\"]\s*:\s*False")
    for i, line in enumerate(ctx.lines, 1):
        if none_pat.search(line) or weak_pat.search(line) \
                or verify_off.search(line):
            out.append(ctx.hit(
                "JWT002", "high",
                "JWT 'none' algorithm or weak secret accepted", i,
                "Allowing the 'none' algorithm, disabling signature "
                "verification, or signing with a guessable secret "
                "('secret', 'changeme') lets anyone forge tokens for any "
                "user — full authentication bypass.",
                "Pin algorithms to ['HS256'] (or your RS256), remove "
                "'none', keep verification on, and use a long random "
                "secret from the environment / a KMS."))
    return out


# ---------------------------------------------------------------------------
# TLS002 — weak / outdated TLS protocol versions
# ---------------------------------------------------------------------------

def rule_TLS002(ctx):
    """Outdated TLS protocol versions pinned or negotiated."""
    pats = {
        "js": [r"minVersion\s*:\s*['\"](TLSv1|TLSv1\.1|SSLv3)['\"]",
               r"secureProtocol\s*:\s*['\"](SSLv3|TLSv1)(_method)?['\"]"],
        "py": [r"PROTOCOL_(SSLv2|SSLv3|TLSv1|TLSv1_1)\b",
               r"ssl\.wrap_socket\s*\(",
               r"minimum_version\s*=\s*ssl\.TLSVersion\.TLSv1\b"],
        "go": [r"MinVersion\s*:\s*tls\.VersionTLS1[01]\b",
               r"MaxVersion\s*:\s*tls\.VersionTLS1[01]\b"],
        "php": [r"(?i)\bsslv3\b", r"(?i)\btlsv1\.0\b",
                r"STREAM_CRYPTO_METHOD_(SSLv|TLSv1_0)"],
    }
    return regex_rule(
        ctx, "TLS002", "medium", "Weak/outdated TLS version allowed", pats,
        "TLS 1.0/1.1 and SSLv3 are broken (BEAST, POODLE) and rejected by "
        "modern browsers and compliance regimes — pinning them downgrades "
        "every connection.",
        "Require TLS 1.2+ (prefer 1.3): ssl.PROTOCOL_TLS_CLIENT / "
        "MinVersion: tls.VersionTLS12 / minVersion: 'TLSv1.2'.")


# ---------------------------------------------------------------------------
# CRY005 — ECB mode / zero or static IV beyond CRY004's literal patterns
# ---------------------------------------------------------------------------

def rule_CRY005(ctx):
    """ECB mode, or a zero/derived-static IV feeding a cipher."""
    pats = {
        "js": [r"(?i)createCipheriv\s*\(\s*['\"][^'\"]*-ecb['\"]",
               r"createCipheriv\s*\([^;)]*Buffer\.alloc\s*\(",
               r"(?i)\biv\s*[:=]\s*Buffer\.alloc\s*\("],
        "py": [r"MODE_ECB\b",  # loophole: skip=CRY005
               r"(?i)\biv\s*=\s*bytes\s*\(\s*\d+\s*\)",
               r"(?i)\biv\s*=\s*b['\"]0+['\"]"],
        "php": [r"(?i)['\"][a-z0-9-]*-ecb['\"]",
                r"(?i)openssl_encrypt\s*\([^)]*['\"][^'\"]*ecb['\"]",
                r"(?i)\$iv\s*=\s*str_repeat\s*\("],
    }
    return regex_rule(
        ctx, "CRY005", "medium", "ECB mode or zero/static IV", pats,
        "ECB encrypts identical plaintext blocks identically (the famous "
        "ECB penguin), and a zero or fixed IV destroys CBC/GCM "
        "confidentiality the same way a hardcoded one does.",
        "Use AES-256-GCM with a fresh random IV per message "
        "(crypto.randomBytes / os.urandom), stored beside the "
        "ciphertext.")


# ---------------------------------------------------------------------------
# LOG — sensitive data written to logs
# ---------------------------------------------------------------------------

_LOG_SINKS = {
    "js": re.compile(r"console\.(log|info|debug|warn|error)\s*\(|"
                     r"\blogger\.\w+\s*\("),
    "py": re.compile(r"\bprint\s*\(|\blogging\.\w+\s*\(|"
                     r"\blogger\.\w+\s*\("),
    "go": re.compile(r"\blog\.(Print|Printf|Println|Fatal|Fatalf)\s*\(|"
                     r"\bfmt\.(Print|Printf|Println)\s*\("),
    "php": re.compile(r"\berror_log\s*\(|\bvar_dump\s*\(|"
                      r"\bprint_r\s*\("),
}
_LOG_SENSITIVE = re.compile(
    r"(?i)(?<![\w])(password|passwd|pwd|token|secret|api[_-]?key|"
    r"apikey|authorization|credential|private[_-]?key)(?![\w])")  # loophole: skip=SEC005


def _strip_strings(line):
    """Line with quoted-literal contents removed (code left behind)."""
    out = []
    i = 0
    in_str = None
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
                out.append(ch)
        elif ch in "\"'`":
            in_str = ch
            out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _interpolated(line):
    """Names interpolated into template/f-strings on the line."""
    names = re.findall(r"\$\{\s*([A-Za-z_$][\w$.]*)", line)
    names += re.findall(r"\{\s*([A-Za-z_][\w.]*)\s*\}", line)
    return " ".join(names)


def rule_LOG001(ctx):
    """Passwords / tokens / secrets passed to logging calls."""
    out = []
    sink = _LOG_SINKS[ctx.lang]
    for i, line in enumerate(ctx.lines, 1):
        if not sink.search(line):
            continue
        code = _strip_strings(line)
        if _LOG_SENSITIVE.search(code) \
                or _LOG_SENSITIVE.search(_interpolated(line)):
            out.append(ctx.hit(
                "LOG001", "medium", "Sensitive data written to logs", i,
                "Logs are copied everywhere — aggregators, backups, "
                "support tickets — and rarely encrypted. Passwords and "
                "tokens in logs become standing credentials for anyone "
                "with log access.",
                "Never log secrets or full tokens/passwords. Log "
                "redacted values (user id, token fingerprint) instead."))
    return out


# ---------------------------------------------------------------------------
# LDAP — LDAP injection
# ---------------------------------------------------------------------------

_LDAP_SINKS = {
    "js": r"\.search\s*\(",
    "py": r"\.(search_s|search_ext_s|search|search_ext)\s*\(",
    "php": r"\bldap_search\s*\(|\bldap_list\s*\(|\bldap_read\s*\(",
}

# A bare ".search(" only counts as an LDAP sink when the file actually
# uses an LDAP library (otherwise it matches re.search() and friends).
_LDAP_GATE = re.compile(
    r"(^\s*import\s+ldap|^\s*from\s+ldap|ldap\.initialize|import\s+ldap3|"
    r"require\s*\(\s*['\"][^'\"]*ldap|from\s+['\"][^'\"]*ldap)",
    re.MULTILINE)


def rule_LDAP001(ctx):
    """LDAP filter/DN built from unescaped user input."""
    out = []
    sink = _LDAP_SINKS.get(ctx.lang)
    if not sink:
        return out
    gated = _LDAP_GATE.search("\n".join(ctx.lines)) is not None
    for i, line in enumerate(ctx.lines, 1):
        m = re.search(sink, line)
        if not m:
            continue
        if ctx.lang in ("js", "py") and not gated \
                and not re.search(r"search_(s|ext)\s*\(", line):
            continue  # generic .search( without any LDAP library in play
        region = line[m.start():]
        if ctx.lang == "js":
            region = line
            if not re.search(r"filter\s*[:=]", line):
                continue
        args = call_args(line, sink) or region
        if is_string_literal(_first_arg(args)):
            continue  # static filter: safe
        taint_var, taint_src = ctx.flow(args)
        dynamic = (taint_var or taint_src
                   or re.search(r"\$\{|['\"]\s*\+|\+\s*['\"]|%\s*\(|"
                                r"f['\"]|\.\s*\$", args))
        if dynamic:
            out.append(ctx.hit(
                "LDAP001", "high", "LDAP injection via unescaped input",
                i,
                "Building LDAP filters from raw input lets attackers "
                "inject wildcards and boolean clauses ((|(uid=*))) to "
                "enumerate the directory or bypass authentication.",
                "Escape filter values (ldap.filter.escape_filter_chars "
                "/ RFC 4515 escaping) and DN components; never concat "
                "raw input into a filter.",
                taint=_taint_note(taint_var, taint_src, "ldap_search")))
    return out


# ---------------------------------------------------------------------------
# HDR — missing security headers (app-level heuristic)
# ---------------------------------------------------------------------------

_HDR_MARKERS = re.compile(
    r"(?i)(helmet|Content-Security-Policy|X-Frame-Options|"
    r"X-Content-Type-Options|Strict-Transport-Security|talisman)")


def rule_HDR001(ctx):
    """Web app with no security-header protection anywhere in the file."""
    text = "\n".join(ctx.lines)
    if _HDR_MARKERS.search(text):
        return []
    out = []
    if ctx.lang == "js":
        if not re.search(r"express\s*\(|require\s*\(\s*['\"]express", text):
            return out
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"\bexpress\s*\(\s*\)", line):
                out.append(ctx.hit(
                    "HDR001", "medium",
                    "No security headers configured (Express)", i,
                    "No helmet and no manual Content-Security-Policy / "
                    "X-Frame-Options / HSTS headers anywhere in the file "
                    "— the app misses the baseline browser protections "
                    "against clickjacking and MIME sniffing. (Heuristic.)",
                    "Add helmet (app.use(helmet())) or set CSP, "
                    "X-Frame-Options, X-Content-Type-Options and HSTS "
                    "headers in middleware."))
                break
    elif ctx.lang == "py":
        if not re.search(r"Flask\s*\(", text):
            return out
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"Flask\s*\(", line):
                out.append(ctx.hit(
                    "HDR001", "medium",
                    "No security headers configured (Flask)", i,
                    "No Content-Security-Policy / X-Frame-Options (or "
                    "flask-talisman) anywhere in the file — the app "
                    "misses the baseline browser protections against "
                    "clickjacking and MIME sniffing. (Heuristic.)",
                    "Add an @app.after_request hook setting CSP, "
                    "X-Frame-Options, X-Content-Type-Options and HSTS — "
                    "or use flask-talisman."))
                break
    return out


# ---------------------------------------------------------------------------
# SSTI — server-side template injection
# ---------------------------------------------------------------------------

def _dynamic_arg(ctx, args):
    """True when the FIRST call argument is not a plain literal: tainted,
    concatenated, interpolated or a bare variable/expression. (Only the
    first argument is judged — later arguments are usually data.)"""
    if args is None:
        return False
    first = _first_arg(args).strip()
    if is_string_literal(first):
        return False
    taint_var, taint_src = ctx.flow(first)
    if taint_var or taint_src:
        return True
    return bool(re.search(r"\+\s*['\"]|['\"]\s*\+|\$\{|%\s*\(|\.\s*\$",
                          first)
                or re.match(r"f['\"]", first))


_SSTI_SINKS = {
    "js": [r"\bejs\.(?:render|compile)", r"\bpug\.(?:render|compile)",
           r"\bnunjucks\.renderString", r"\bHandlebars\.compile",
           r"_\.template"],
    "php": [r"->\s*createTemplate", r"Blade::render"],
}

_SSTI_WHY = ("Template engines execute the expressions inside the "
             "template string itself. When user input becomes the "
             "template — instead of data passed to a fixed one — "
             "attackers inject {{ }} / <% %> payloads that evaluate on "
             "the server: full remote code execution.")
_SSTI_FIX = ("Render only fixed, developer-written templates and pass "
             "user input as context data. If users need markup, use a "
             "plain-text or sandboxed renderer, never the raw engine.")


def rule_SSTI001(ctx):
    """User input rendered AS a template (SSTI)."""
    out = []
    if ctx.lang == "py":
        text = "\n".join(ctx.lines)
        if "jinja2" not in text and "render_template_string" not in text:
            return out
        sinks = [r"render_template_string", r"\bTemplate"]
    elif ctx.lang == "go":
        text = "\n".join(ctx.lines)
        if "text/template" not in text and "html/template" not in text:
            return out
        for i, line in enumerate(ctx.lines, 1):
            if not re.search(r"(?:\b\w*[Tt]emplate\w*|\btmpl\b|\btpl\b|\bt)"
                             r"\s*\.\s*Parse\s*\("
                             r"|\.New\s*\([^)]*\)\s*\.Parse\s*\(", line):
                continue
            if _dynamic_arg(ctx, call_args(line, r"\.Parse")):
                out.append(ctx.hit(
                    "SSTI001", "high",
                    "Server-side template injection (input parsed as "
                    "template)", i, _SSTI_WHY, _SSTI_FIX))
        return out
    else:
        sinks = _SSTI_SINKS[ctx.lang]
    for i, line in enumerate(ctx.lines, 1):
        for pat in sinks:
            args = call_args(line, pat)
            if args is not None and _dynamic_arg(ctx, args):
                out.append(ctx.hit(
                    "SSTI001", "high",
                    "Server-side template injection (input used as "
                    "template)", i, _SSTI_WHY, _SSTI_FIX))
                break
    return out


# ---------------------------------------------------------------------------
# COOKIE — session cookies without HttpOnly / Secure
# ---------------------------------------------------------------------------

_COOKIE_WHY = ("Cookies without HttpOnly are readable from JavaScript, "
               "so any XSS becomes session theft; without Secure they "
               "also travel over plain HTTP. Several frameworks default "
               "HttpOnly OFF for hand-set cookies.")
_COOKIE_FIX = ("Set HttpOnly, Secure and SameSite on session cookies: "
               "res.cookie(..., { httpOnly: true, secure: true, "
               "sameSite: 'lax' }) / set_cookie(..., httponly=True, "
               "secure=True, samesite='Lax') / setcookie(..., "
               "['httponly' => true, 'secure' => true, "
               "'samesite' => 'Lax']).")


def rule_COOKIE001(ctx):
    """Cookies set without HttpOnly (explicit off, or not mentioned)."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        low = line.lower()
        if ctx.lang == "py" and re.search(
                r"\b(SESSION|CSRF)_COOKIE_(HTTPONLY|SECURE)\s*=\s*False",
                line):
            out.append(ctx.hit(
                "COOKIE001", "medium",
                "Session cookie flag disabled in settings", i,
                _COOKIE_WHY, _COOKIE_FIX))
            continue
        if re.search(r"(?i)httponly['\"]?\s*(?::|=>)\s*false", line):
            out.append(ctx.hit(
                "COOKIE001", "medium", "Cookie HttpOnly explicitly off",
                i, _COOKIE_WHY, _COOKIE_FIX))
            continue
        heuristic = False
        if ctx.lang == "js":
            heuristic = bool(
                re.search(r"\.cookie\s*\(", line)
                or re.search(r"setHeader\s*\(\s*['\"]Set-Cookie", line))
        elif ctx.lang == "py":
            heuristic = bool(re.search(r"\.set_cookie\s*\(", line))
        elif ctx.lang == "php":
            heuristic = bool(re.search(r"\bset(raw)?cookie\s*\(", line))
        if heuristic and "httponly" not in low:
            out.append(ctx.hit(
                "COOKIE001", "medium",
                "Cookie set without HttpOnly flag", i,
                _COOKIE_WHY + " (Heuristic: options set on a following "
                "line are not seen by this check.)", _COOKIE_FIX))
    return out


# ---------------------------------------------------------------------------
# RAND004 — weak randomness (PHP)
# ---------------------------------------------------------------------------

def rule_RAND004(ctx):
    """rand()/mt_rand()/uniqid() used for security-sensitive values (PHP)."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        if not re.search(r"\b(rand|mt_rand|uniqid|lcg_value|array_rand|"
                         r"str_shuffle)\s*\(", line):
            continue
        context = line if i == 1 else ctx.lines[i - 2] + "\n" + line
        if not re.search(r"(?i)(token|secret|password|passwd|key|nonce|"
                         r"otp|session|uuid|captcha|salt)", context):
            continue
        out.append(ctx.hit(
            "RAND004", "medium",
            "Weak PHP randomness for security-sensitive value", i,
            "rand()/mt_rand() are seeded PRNGs and uniqid() is just the "
            "microsecond clock — tokens, OTPs and reset codes built on "
            "them can be predicted or brute-forced.",
            "Use the CSPRNG: random_bytes() / random_int() — e.g. "
            "bin2hex(random_bytes(32)) for tokens."))
    return out


# ---------------------------------------------------------------------------
# TLS003 — certificate validation off via CERT_NONE & friends
# ---------------------------------------------------------------------------

def rule_TLS003(ctx):
    """Cert validation disabled via CERT_NONE / unverified context /
    VERIFYHOST=0 / NODE_TLS_REJECT_UNAUTHORIZED=0 (TLS001's siblings)."""
    pats = {
        "js": [r"process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*"
               r"['\"]?0['\"]?",
               r"strictSSL\s*:\s*false"],
        "py": [r"ssl\.CERT_NONE\b", r"_create_unverified_context\s*\(",
               r"check_hostname\s*=\s*False"],
        "php": [r"(?i)CURLOPT_SSL_VERIFYHOST\s*,\s*(0|false)\b",
                r"['\"]verify['\"]\s*=>\s*false"],
    }
    return regex_rule(
        ctx, "TLS003", "high",
        "TLS certificate validation disabled (CERT_NONE / unverified)",
        pats,
        "CERT_NONE, unverified SSL contexts, VERIFYHOST=0 and friends "
        "switch off the check that proves you are talking to the real "
        "server — every HTTPS call becomes interceptable (MITM), the "
        "same hole as verify=False.",  # loophole: skip=TLS001
        "Validate certificates: use the default SSL context "
        "(CERT_REQUIRED + hostname checking), keep VERIFYPEER on and "
        "VERIFYHOST=2, and never ship NODE_TLS_REJECT_UNAUTHORIZED=0.")


# ---------------------------------------------------------------------------
# TLS004 — Go tls.Config with InsecureSkipVerify
# ---------------------------------------------------------------------------

def rule_TLS004(ctx):
    """Go tls.Config disables certificate verification."""
    pats = {
        "go": [r"InsecureSkipVerify\s*:\s*true"],
    }
    return regex_rule(
        ctx, "TLS004", "high", "Go TLS verification disabled (InsecureSkipVerify)", pats,
        "InsecureSkipVerify: true turns off certificate validation, so "
        "any man-in-the-middle can impersonate the server.",
        "Remove InsecureSkipVerify and configure proper root CAs instead.")


# ---------------------------------------------------------------------------
# CORS002 — reflected Origin / credentials combined with wildcard
# ---------------------------------------------------------------------------

_CORS_REFLECT = {
    "js": r"Access-Control-Allow-Origin['\"]?\s*\]?\s*[,=:]\s*[^;\n]*"
          r"req\.(headers\.origin|get\s*\(|header\s*\()",
    "py": r"Access-Control-Allow-Origin['\"]?\s*\]?\s*[,=:]\s*[^;\n]*"
          r"request\.(headers|get_header)",
    "go": r"Access-Control-Allow-Origin[\"']?\s*[,;:=]\s*[^;\n]*"
          r"\.Header\.Get\(\"Origin\"\)",
    "php": r"Access-Control-Allow-Origin[^;\n]*"
           r"\$_SERVER\[['\"]HTTP_ORIGIN['\"]\]",
}

_CORS_CRED = {
    "js": r"credentials\s*:\s*true",
    "py": r"(?i)(supports_credentials\s*=\s*True|allow_credentials\s*=\s*"
          r"True|CORS_ALLOW_CREDENTIALS\s*=\s*True)",
    "go": r"AllowCredentials\s*:\s*true",
    "php": r"(?i)Access-Control-Allow-Credentials['\"]?\s*:\s*true",
}

_CORS_WILD = {
    "js": r"(origin\s*:\s*['\"]\*['\"]|Access-Control-Allow-Origin"
          r"['\"]?\s*\]?\s*[,=:]\s*['\"]\*['\"])",
    "py": r"(allow_origins\s*=\s*\[[^\]]*\*|origins\s*=\s*['\"]\*['\"]|"
          r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True)",
    "go": r"(AllowedOrigins\s*:\s*\[\]string\{\s*\"\*\"|"
          r"Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*)",
    "php": r"Access-Control-Allow-Origin:\s*\*",
}

_CORS002_WHY = ("Reflecting any Origin — or combining credentials with "
                "a wildcard origin — lets ANY website make credentialed "
                "cross-origin requests with the victim's session and "
                "read the responses: cross-site data theft, worse than "
                "a plain wildcard (CORS001).")
_CORS002_FIX = ("Allowlist exact trusted origins and echo back only "
                "those; never reflect arbitrary Origin values, and "
                "never combine credentials with '*'.")


def rule_CORS002(ctx):
    """CORS that reflects any Origin, or credentials + wildcard origin."""
    out = []
    reflect = re.compile(_CORS_REFLECT[ctx.lang])
    hit_lines = set()
    for i, line in enumerate(ctx.lines, 1):
        if reflect.search(line):
            hit_lines.add(i)
            out.append(ctx.hit(
                "CORS002", "high",
                "CORS: request Origin reflected to any site", i,
                _CORS002_WHY, _CORS002_FIX))
    text = "\n".join(ctx.lines)
    cred = re.search(_CORS_CRED[ctx.lang], text)
    wild = re.search(_CORS_WILD[ctx.lang], text)
    if cred and wild:
        for i, line in enumerate(ctx.lines, 1):
            if i not in hit_lines and re.search(_CORS_CRED[ctx.lang],
                                                line):
                out.append(ctx.hit(
                    "CORS002", "high",
                    "CORS: credentials allowed with wildcard origin", i,
                    _CORS002_WHY, _CORS002_FIX))
                break
    return out


# ---------------------------------------------------------------------------
# CRLF — HTTP header injection / response splitting
# ---------------------------------------------------------------------------

def rule_CRLF001(ctx):
    """User-influenced value written into a response header."""
    out = []
    why = ("A value containing CR/LF written into a response header "
           "lets attackers inject whole new headers or split the "
           "response — session fixation, cache poisoning, and XSS via "
           "a forged Content-Type or Location.")
    fix = ("Strip or reject CR and LF in any value placed in a header, "
           "and validate values against an allowlist where they have a "
           "known shape (ids, tokens, filenames).")
    for i, line in enumerate(ctx.lines, 1):
        args = None
        if ctx.lang == "js":
            if re.search(r"\.(setHeader|writeHead)\s*\(", line):
                args = call_args(line, r"\.(?:setHeader|writeHead)")
        elif ctx.lang == "py":
            m = re.search(r"\.headers\s*\[[^\]]*\]\s*=\s*(.+)$", line)
            if m:
                args = m.group(1)
            elif re.search(r"\bset_header\s*\(", line):
                args = call_args(line, r"set_header")
        elif ctx.lang == "php":
            if re.search(r"\bheader\s*\(", line) \
                    and "Location:" not in line:
                args = call_args(line, r"\bheader")
        if args is None:
            continue
        if is_string_literal(args.strip().rstrip(";")):
            continue  # static value (e.g. a fixed CSP header): safe
        taint_var, taint_src = ctx.flow(args)
        dynamic = (taint_var or taint_src
                   or re.search(r"\+\s*['\"]|['\"]\s*\+|\.\s*\$|\$\{|"
                                r"%\s*\(|\bf['\"]", args))
        if dynamic:
            out.append(ctx.hit(
                "CRLF001", "medium",
                "HTTP header injection (value from user input)", i,
                why, fix,
                taint=_taint_note(taint_var, taint_src, "header")))
    return out


# ---------------------------------------------------------------------------
# CMP — secrets compared with == / === (timing side channel)
# ---------------------------------------------------------------------------

_CMP_SAFE = re.compile(
    r"(?i)(compare_digest|timingSafeEqual|hash_equals|"
    r"ConstantTimeCompare|secure_compare)")
_CMP_NAME = re.compile(
    r"(?i)(token|secret|password|passwd|api[_-]?key|apikey|signature|"
    r"hmac|digest|otp)")


def _operand_left(text):
    """The operand expression immediately left of a comparison operator."""
    text = text.rstrip()
    m = re.search(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|"
                  r"\[[^\]]*\]|\([^()]*\))*)$", text)
    return m.group(1) if m else text[-24:]


def _operand_right(text):
    """The operand expression immediately right of a comparison operator."""
    text = text.lstrip()
    m = re.match(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|"
                 r"\[[^\]]*\]|\([^()]*\))*)", text)
    return m.group(1) if m else text[:24]


def _is_literal_operand(op):
    op = op.strip()
    if not op:
        return True
    if op[0] in "\"'`" or op[0].isdigit():
        return True
    return re.match(r"(?i)(none|true|false|null|undefined|nil)\b",
                    op) is not None


def rule_CMP001(ctx):
    """Secret/token compared with == or === instead of constant-time."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        if _CMP_SAFE.search(line):
            continue
        m = re.search(r"(?<![=!<>])={2,3}(?![=])", line)
        if not m:
            continue
        left = _operand_left(line[:m.start()])
        right = _operand_right(line[m.end():])
        if _is_literal_operand(left) or _is_literal_operand(right):
            continue  # constant check (== "", == null, == 0): not this
        if not (_CMP_NAME.search(left) or _CMP_NAME.search(right)):
            continue
        out.append(ctx.hit(
            "CMP001", "medium",
            "Secret compared with == (timing side channel)", i,
            "== / === returns on the first differing byte, leaking how "
            "much of a guess was right — over many requests an attacker "
            "recovers tokens and HMACs byte by byte. In PHP, loose == "
            "also invites type-juggling bypasses ('0e123' == '0').",
            "Compare in constant time: hmac.compare_digest (Python), "
            "crypto.timingSafeEqual (JS), hash_equals (PHP), "
            "subtle.ConstantTimeCompare (Go)."))
    return out


# ---------------------------------------------------------------------------
# REDIR002 — DOM open redirect (client-side)
# ---------------------------------------------------------------------------

def rule_REDIR002(ctx):
    """location assigned / navigated to a user-influenced URL (JS/TS)."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        hit = False
        m = re.search(r"(?<![\w$.])(?:window\.|document\.)?location"
                      r"(?:\.href)?\s*=\s*(.+)$", line)
        if m and not re.search(r"\b(const|let|var)\s+(window\.)?location"
                               r"\b", line):
            rhs = m.group(1).strip().rstrip(";")
            if not is_string_literal(rhs):
                taint_var, taint_src = ctx.flow(rhs)
                hit = bool(taint_var or taint_src
                           or re.search(r"\+|\$\{|`", rhs))
        if not hit:
            for pat in (r"location\.assign", r"location\.replace"):
                args = call_args(line, pat)
                if args is not None and _dynamic_arg(ctx, args):
                    hit = True
                    break
        if hit:
            out.append(ctx.hit(
                "REDIR002", "medium",
                "DOM open redirect (location set from input)", i,
                "Assigning location from URL parameters or other input "
                "(location.search, document.referrer, postMessage data) "
                "sends victims to attacker sites from your trusted "
                "origin — phishing and OAuth token theft. (Server-side "
                "redirects are REDIR001.)",
                "Only navigate to allowlisted local paths: parse the "
                "target, require same-origin and a path starting with "
                "a single '/'."))
    return out


# ---------------------------------------------------------------------------
# XXE002 — libxmljs entity expansion (JS/TS)
# ---------------------------------------------------------------------------

def rule_XXE002(ctx):
    """libxmljs parsing with DTD loading / entity expansion enabled."""
    pats = {"js": [r"\bnoent\s*:\s*true", r"\bdtdload\s*:\s*true",
                   r"\bnonet\s*:\s*false"]}
    return regex_rule(
        ctx, "XXE002", "high",
        "XXE: libxmljs entity expansion enabled (noent/dtdload)", pats,
        "The libxmljs options noent/dtdload (or nonet off) switch on "
        "DTD loading and entity substitution — the two switches that "
        "turn an XML parser into an XXE file-reading / SSRF weapon "
        "(the JS sibling of XXE001).",
        "Parse with noent: false, dtdload: false, nonet: true — or "
        "use a parser that never resolves external entities.")


# ---------------------------------------------------------------------------
# XSS005 — framework HTML-injection sinks beyond innerHTML (JS), plus Go
# html/template escaping bypass via template.HTML
# ---------------------------------------------------------------------------

def rule_XSS005(ctx):
    """insertAdjacentHTML, Vue v-html, Angular bypassSecurityTrust* (js);
    template.HTML() on dynamic values (go)."""
    out = []
    if ctx.lang == "go":
        go_why = ("template.HTML marks a string as trusted HTML, "
                  "switching off html/template's automatic escaping. "
                  "Anything user-controlled flowing into it is "
                  "stored/reflected XSS — the same hole as innerHTML "
                  "(XSS001) through a Go door.")
        go_fix = ("Pass the value to the template as plain data and let "
                  "html/template escape it; only wrap strings you fully "
                  "control in template.HTML, or sanitize with bluemonday "
                  "first.")
        for i, line in enumerate(ctx.lines, 1):
            args = call_args(line, r"template\.HTML")
            if args is None:
                continue
            if is_single_string_literal(args):
                continue  # static HTML string: safe
            taint_var, taint_src = ctx.flow(args)
            out.append(ctx.hit(
                "XSS005", "high",
                "Dynamic content via template.HTML (escaping bypass)", i,
                go_why, go_fix,
                taint=_taint_note(taint_var, taint_src, "template.HTML")))
        return out
    why = ("These APIs inject raw HTML into the DOM, bypassing the "
           "framework's automatic escaping. With user-influenced "
           "content they are stored/reflected XSS — the same hole as "
           "innerHTML (XSS001) through a framework door.")
    fix = ("Render text through the framework's normal interpolation; "
           "if HTML is unavoidable, sanitize with DOMPurify first and "
           "treat bypassSecurityTrust* / v-html as code-review flags.")
    for i, line in enumerate(ctx.lines, 1):
        args = call_args(line, r"\.insertAdjacentHTML")
        if args is not None:
            rest = args.split(",", 1)[1] if "," in args else args
            if not is_string_literal(rest.strip()):
                out.append(ctx.hit(
                    "XSS005", "high",
                    "Dynamic HTML via insertAdjacentHTML", i, why, fix))
            continue
        if re.search(r"v-html\s*=", line):
            out.append(ctx.hit(
                "XSS005", "high", "Vue v-html (raw HTML rendering)", i,
                why, fix))
        elif re.search(r"bypassSecurityTrust\w*\s*\(", line):
            out.append(ctx.hit(
                "XSS005", "high",
                "Angular bypassSecurityTrust* (sanitizer disabled)", i,
                why, fix))
    return out


# ---------------------------------------------------------------------------
# DESER002 — jsonpickle / Node v8 deserialization
# ---------------------------------------------------------------------------

def rule_DESER002(ctx):
    """jsonpickle.decode (py) / v8.deserialize (js) on dynamic data."""  # loophole: skip=DESER002
    out = []
    why = ("jsonpickle reconstructs arbitrary Python objects from JSON "
           "tags, and Node's v8.deserialize runs the V8 serializer on "
           "attacker bytes with known gadget chains — both turn "
           "untrusted input into code execution (DESER001's extended "
           "family).")
    fix = ("Use plain json.loads() / JSON.parse() for untrusted data; "
           "never an object-reviving deserializer.")
    if ctx.lang == "py":
        for i, line in enumerate(ctx.lines, 1):
            if re.search(r"\bjsonpickle\.(decode|loads)\s*\(", line):
                out.append(ctx.hit(
                    "DESER002", "high",
                    "Unsafe deserialization (jsonpickle)", i, why, fix))
    elif ctx.lang == "js":
        for i, line in enumerate(ctx.lines, 1):
            args = call_args(line, r"\bv8\.deserialize")
            if args is not None \
                    and not is_string_literal(_first_arg(args)):
                out.append(ctx.hit(
                    "DESER002", "high",
                    "Unsafe deserialization (v8.deserialize)", i,
                    why, fix))
    return out


# ---------------------------------------------------------------------------
# Rule registry — 62 rules
# ---------------------------------------------------------------------------

RULES = [
    # id,       languages,        check function
    ("SEC001", ("js", "py", "go", "php"), rule_SEC001),
    ("SEC002", ("js", "py", "go", "php"), rule_SEC002),
    ("SEC003", ("js", "py", "go", "php"), rule_SEC003),
    ("SEC004", ("js", "py", "go", "php"), rule_SEC004),
    ("SEC005", ("js", "py", "go", "php"), rule_SEC005),
    ("SQLI001", ("js",), _sqli_js),
    ("SQLI002", ("py",), _sqli_py),
    ("SQLI003", ("go",), _sqli_go),
    ("SQLI004", ("php",), _sqli_php),
    ("XSS001", ("js",), rule_XSS001),
    ("XSS002", ("js",), rule_XSS002),
    ("XSS003", ("js",), rule_XSS003),
    ("XSS004", ("php",), rule_XSS004),
    ("CMD001", ("js",), rule_CMD001),
    ("CMD002", ("py",), rule_CMD002),
    ("CMD003", ("go",), rule_CMD003),
    ("CMD004", ("php",), rule_CMD004),
    ("PATH001", ("js", "py", "go", "php"), rule_PATH001),
    ("PATH002", ("js", "py", "go", "php"), rule_PATH002),
    ("RAND001", ("js",), rule_RAND001),
    ("RAND002", ("py",), rule_RAND002),
    ("RAND003", ("go",), rule_RAND003),
    ("CRY001", ("js", "py", "go", "php"), rule_CRY001),
    ("CRY002", ("js", "py", "go", "php"), rule_CRY002),
    ("CRY003", ("js", "py", "go", "php"), rule_CRY003),
    ("CRY004", ("js", "py", "go", "php"), rule_CRY004),
    ("EVAL001", ("js", "py", "go", "php"), rule_EVAL001),
    ("EVAL002", ("js",), rule_EVAL002),
    ("SSRF001", ("js", "py", "go", "php"), rule_SSRF001),
    ("AUTH001", ("js", "py"), rule_AUTH001),
    ("CORS001", ("js", "py", "go", "php"), rule_CORS001),
    ("JWT001", ("js", "py", "php"), rule_JWT001),
    ("TLS001", ("js", "py", "php"), rule_TLS001),
    ("DBG001", ("js", "py", "php"), rule_DBG001),
    ("ERR001", ("js", "py", "go", "php"), rule_ERR001),
    ("PROTO001", ("js",), rule_PROTO001),
    ("DESER001", ("js", "py", "php"), rule_DESER001),
    ("NOSQL001", ("js", "py"), rule_NOSQL001),
    ("XXE001", ("py", "php"), rule_XXE001),
    ("REDIR001", ("js", "py", "go", "php"), rule_REDIR001),
    ("ZIP001", ("js", "py", "php"), rule_ZIP001),
    ("CSRF001", ("js", "py"), rule_CSRF001),
    ("UPL001", ("js", "py", "php"), rule_UPL001),
    ("REDOS001", ("js", "py", "go", "php"), rule_REDOS001),
    ("JWT002", ("js", "py", "php"), rule_JWT002),
    ("TLS002", ("js", "py", "go", "php"), rule_TLS002),
    ("CRY005", ("js", "py", "php"), rule_CRY005),
    ("LOG001", ("js", "py", "go", "php"), rule_LOG001),
    ("LDAP001", ("js", "py", "php"), rule_LDAP001),
    ("HDR001", ("js", "py"), rule_HDR001),
    ("SSTI001", ("js", "py", "go", "php"), rule_SSTI001),
    ("COOKIE001", ("js", "py", "php"), rule_COOKIE001),
    ("RAND004", ("php",), rule_RAND004),
    ("TLS003", ("js", "py", "php"), rule_TLS003),
    ("TLS004", ("go",), rule_TLS004),
    ("CORS002", ("js", "py", "go", "php"), rule_CORS002),
    ("CRLF001", ("js", "py", "php"), rule_CRLF001),
    ("CMP001", ("js", "py", "go", "php"), rule_CMP001),
    ("REDIR002", ("js",), rule_REDIR002),
    ("XXE002", ("js",), rule_XXE002),
    ("XSS005", ("js", "go"), rule_XSS005),
    ("DESER002", ("js", "py"), rule_DESER002),
]


# ---------------------------------------------------------------------------
# Rule metadata for `scan --explain`
#
# The rule functions are the single source of truth for their own
# metadata: each one passes its title, severity, why and fix to
# ctx.hit() or regex_rule(). The helpers below re-read those literals
# from this file's AST at runtime, so the text --explain prints can
# never drift from what a scan actually reports.
# ---------------------------------------------------------------------------

def _static_str(node, consts, local):
    """Best-effort static string for an AST node, else None.

    Handles plain literals, implicit concatenation, f-strings (with
    {expr} kept visible), names bound to string constants and
    "a" + "b" joins. Anything else returns None.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                parts.append("{" + ast.unparse(val.value) + "}")
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.Name):
        if node.id in local:
            return local[node.id]
        return consts.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_str(node.left, consts, local)
        right = _static_str(node.right, consts, local)
        if left is not None and right is not None:
            return left + right
        return None
    return None


class _RuleMetaVisitor(ast.NodeVisitor):
    """Collect (severity, title, why, fix) variants from one rule
    function, in source order. Nested function definitions are not
    descended into, so their locals cannot leak into the rule's own
    metadata. Local string assignments seen before a hit call are
    used to resolve names such as `why` and `fix`."""

    def __init__(self, consts, rule_id):
        self.consts = consts
        self.rule_id = rule_id
        self.local = {}
        self.variants = []

    def visit_FunctionDef(self, node):
        return

    def visit_AsyncFunctionDef(self, node):
        return

    def visit_Lambda(self, node):
        return

    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            val = _static_str(node.value, self.consts, self.local)
            if val is not None:
                self.local[node.targets[0].id] = val
        self.generic_visit(node)

    def _arg(self, call, pos, name):
        for kw in call.keywords:
            if kw.arg == name:
                return kw.value
        if len(call.args) > pos:
            return call.args[pos]
        return None

    def _record(self, rule_id, severity, title, why, fix):
        if not (severity and title and why and fix):
            return
        variant = {"severity": severity, "title": title,
                   "why": why, "fix": fix}
        if variant not in self.variants:
            self.variants.append(variant)

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "hit":
            rid = _static_str(self._arg(node, 0, "rule_id"),
                              self.consts, self.local)
            sev = _static_str(self._arg(node, 1, "severity"),
                              self.consts, self.local)
            title = _static_str(self._arg(node, 2, "title"),
                                self.consts, self.local)
            why = _static_str(self._arg(node, 4, "why"),
                              self.consts, self.local)
            fix = _static_str(self._arg(node, 5, "fix"),
                              self.consts, self.local)
            if rid == self.rule_id:
                self._record(rid, sev, title, why, fix)
        elif isinstance(func, ast.Name) and func.id == "regex_rule":
            rid = _static_str(self._arg(node, 1, "rule_id"),
                              self.consts, self.local)
            sev = _static_str(self._arg(node, 2, "severity"),
                              self.consts, self.local)
            title = _static_str(self._arg(node, 3, "title"),
                                self.consts, self.local)
            why = _static_str(self._arg(node, 5, "why"),
                              self.consts, self.local)
            fix = _static_str(self._arg(node, 6, "fix"),
                              self.consts, self.local)
            if rid == self.rule_id:
                self._record(rid, sev, title, why, fix)
        self.generic_visit(node)


_ALL_RULE_META = None


def _load_all_rule_meta():
    """Metadata variants for every rule in RULES, parsed once.

    Returns {rule_id: [{severity, title, why, fix}, ...]} in source
    order. The rule functions stay the single source of truth — the
    literals are re-read from this file's AST — but the file is parsed
    a single time and the result cached, so emitting SARIF (which needs
    all 62 rules, fired or not) stays fast. Returns {} when the file
    cannot be read.
    """
    global _ALL_RULE_META
    if _ALL_RULE_META is not None:
        return _ALL_RULE_META
    meta = {}
    try:
        with open(__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
    except OSError:
        _ALL_RULE_META = meta
        return meta
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            val = _static_str(node.value, consts, {})
            if val is not None:
                consts[node.targets[0].id] = val
    funcs = {node.name: node for node in tree.body
             if isinstance(node, ast.FunctionDef)}
    for rule_id, _langs, func in RULES:
        node = funcs.get(func.__name__)
        if node is None:
            continue
        visitor = _RuleMetaVisitor(consts, rule_id)
        for stmt in node.body:
            visitor.visit(stmt)
        if visitor.variants:
            meta[rule_id] = visitor.variants
    _ALL_RULE_META = meta
    return meta


def _extract_rule_meta(func, rule_id):
    """Variants of one rule function, in source order.

    Returns a list of {severity, title, why, fix} dicts read from the
    ctx.hit() / regex_rule() calls inside the function, or [] when
    nothing could be extracted. Only hits for this rule's own ID are
    kept. Backed by the single-parse cache in _load_all_rule_meta().
    """
    return list(_load_all_rule_meta().get(rule_id, []))


def get_rule_info(rule_id):
    """Metadata for one rule ID, or None when the ID is unknown.

    Returns id, languages, severity (the first variant's severity),
    description (the rule function's docstring, or "") and variants,
    a list of {severity, title, why, fix} in source order.
    """
    rid = rule_id.strip().upper()
    for _rid, langs, func in RULES:
        if _rid != rid:
            continue
        doc = (func.__doc__ or "").strip()
        variants = _extract_rule_meta(func, rid)
        return {"id": rid, "languages": list(langs),
                "severity": variants[0]["severity"] if variants else "",
                "description": doc,
                "variants": variants}
    return None


def explain_rule(rule_id):
    """Print one rule's detail for `scan --explain`. Returns exit code."""
    info = get_rule_info(rule_id)
    if info is None:
        valid = [r for r, _, _ in RULES]
        close = difflib.get_close_matches(rule_id.strip().upper(), valid,
                                          n=3, cutoff=0.6)
        print(f"loophole: unknown rule '{rule_id}'", file=sys.stderr)
        if close:
            print(f"did you mean: {', '.join(close)}?", file=sys.stderr)
        print("run `loophole scan --rules` to list all rule IDs.",
              file=sys.stderr)
        return 2
    if not info["variants"]:
        print(f"loophole: no metadata found for rule {info['id']} "
              "(internal error)", file=sys.stderr)
        return 2
    print(info["id"])
    print(f"  Languages: {', '.join(info['languages'])}")
    print(f"  Severity: {info['severity']}")
    if info["description"]:
        print(f"  Description: {info['description']}")
    if len(info["variants"]) == 1:
        variant = info["variants"][0]
        print(f"  Title: {variant['title']}")
        print(f"  Why: {variant['why']}")
        print(f"  Fix: {variant['fix']}")
    else:
        for i, variant in enumerate(info["variants"], 1):
            print(f"  [{i}] {variant['title']} — {variant['severity']}")
            print(f"      Why: {variant['why']}")
            print(f"      Fix: {variant['fix']}")
    return 0


# ---------------------------------------------------------------------------
# Inline suppressions:
#   # loophole: skip              -> every rule on the line
#   # loophole: skip=SEC001,CRY003
#   // loophole:ignore SEC001     -> space form, same effect ("ignore"
#                                    is an alias of "skip")
# ---------------------------------------------------------------------------

_SKIP_RE = re.compile(r"loophole\s*:\s*(?:skip|ignore)\b(.*)",
                      re.IGNORECASE)
_RULE_ID_TOKEN = re.compile(r"[A-Za-z]{2,}\d{3}")


def _suppressed(line, rule_id):
    """True when the line carries a loophole skip/ignore comment that
    covers this rule."""
    m = _SKIP_RE.search(line)
    if not m:
        return False
    rest = m.group(1).strip().lstrip("=").strip()
    if not rest:
        return True  # bare skip/ignore silences every rule on the line
    ids = {t.upper() for t in _RULE_ID_TOKEN.findall(rest)}
    if not ids:
        return True  # free-text reason only ("ignore, because ...")
    return rule_id.upper() in ids


# ---------------------------------------------------------------------------
# Config file (.loophole.json)
# ---------------------------------------------------------------------------

def load_config(explicit_path, root):
    """Load scan config: {"exclude": [...], "disable": [rule ids],
    "severity": {rule id: level}}.

    --config wins; otherwise a .loophole.json in the scanned root (or
    the scanned file's directory) is picked up automatically. A broken
    config warns on stderr and is ignored — a scan must never die
    because of its config file.
    """
    path = explicit_path
    if not path:
        base = root if os.path.isdir(root) else os.path.dirname(
            os.path.abspath(root))
        cand = os.path.join(base, ".loophole.json")
        path = cand if os.path.isfile(cand) else None
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"loophole: warning: cannot read config {path}: {exc}",
              file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        print(f"loophole: warning: config {path} is not a JSON object",
              file=sys.stderr)
        return {}
    cfg = {"exclude": [], "disable": set(), "severity": {}}
    if "exclude" in data and not isinstance(data["exclude"], list):
        print(f"loophole: warning: config {path}: ignoring invalid "
              f"exclude {data['exclude']!r} (expected a list)",
              file=sys.stderr)
    elif isinstance(data.get("exclude"), list):
        cfg["exclude"] = [str(x) for x in data["exclude"]]
    if "disable" in data and not isinstance(data["disable"], list):
        print(f"loophole: warning: config {path}: ignoring invalid "
              f"disable {data['disable']!r} (expected a list)",
              file=sys.stderr)
    elif isinstance(data.get("disable"), list):
        cfg["disable"] = {str(x).upper() for x in data["disable"]}
    if "severity" in data and not isinstance(data["severity"], dict):
        print(f"loophole: warning: config {path}: ignoring invalid "
              f"severity {data['severity']!r} (expected an object)",
              file=sys.stderr)
    elif isinstance(data.get("severity"), dict):
        known = {r for r, _, _ in RULES}
        for rid, level in data["severity"].items():
            rule = str(rid).upper()
            norm = str(level).strip().lower()
            if rule not in known:
                print(f"loophole: warning: config {path}: ignoring "
                      f"unknown rule {rule}", file=sys.stderr)
            elif norm in SEV_ORDER:
                cfg["severity"][rule] = norm
            else:
                print(f"loophole: warning: config {path}: ignoring "
                      f"invalid severity {level!r} for rule "
                      f"{rule} (choose from critical, high, "
                      f"medium)", file=sys.stderr)
    return cfg


def load_ignore_patterns(root):
    """Read .loopholeignore from the scanned root (or the scanned
    file's directory): gitignore-style patterns, one per line. Blank
    lines and '#' comments are ignored. A broken file warns on stderr
    and is ignored — a scan must never die because of its ignore file.
    Returns the pattern list (empty when no file exists).
    """
    base = root if os.path.isdir(root) else os.path.dirname(
        os.path.abspath(root))
    path = os.path.join(base, ".loopholeignore")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        print(f"loophole: warning: cannot read ignore file {path}: {exc}",
              file=sys.stderr)
        return []
    patterns = []
    for line in lines:
        pat = line.strip()
        if not pat or pat.startswith("#"):
            continue
        patterns.append(pat)
    return patterns


def ignore_match(rel, patterns):
    """True if a gitignore-style pattern matches a '/'-separated
    path relative to the scanned root.

    - 'name' matches a file or directory name at any depth.
    - 'path/' matches everything under that directory.
    - '*', '?' globs match a path component ('*.min.js') or, when the
      pattern contains '/', the relative path ('generated/*').
    """
    parts = rel.split("/")
    for pat in patterns:
        if pat.endswith("/"):
            prefix = pat.rstrip("/")
            if rel == prefix or rel.startswith(prefix + "/"):
                return True
            continue
        if "/" not in pat:
            if "*" in pat or "?" in pat:
                if any(fnmatch.fnmatch(p, pat) for p in parts):
                    return True
            elif pat in parts:
                return True
            continue
        if fnmatch.fnmatch(rel, pat):
            return True
    return False


def _count_scannable(path):
    """Count scannable source files under a directory (for the
    ignored tally when an ignored directory is pruned from the walk)."""
    n = 0
    for _dirpath, _dirnames, filenames in os.walk(path):
        for fn in filenames:
            if detect_lang(os.path.join(_dirpath, fn)):
                n += 1
    return n


def scan_file(path, config=None):
    """Scan one file. Returns a list of Findings."""
    lang = detect_lang(path)
    if not lang:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    disabled = config.get("disable", ()) if config else ()
    overrides = config.get("severity", {}) if config else {}
    ctx = Ctx(path, lang, lines)
    findings = []
    for rule_id, langs, func in RULES:
        if lang in langs and rule_id not in disabled:
            try:
                findings.extend(func(ctx))
            except Exception:
                # a broken rule must never kill a scan
                continue
    # config severity overrides (before sorting / suppression)
    for f in findings:
        if f.rule_id in overrides:
            f.severity = overrides[f.rule_id]
    # honor inline suppressions:  # loophole: skip  /  loophole:ignore ID
    findings = [f for f in findings
                if not _suppressed(lines[f.line - 1], f.rule_id)]
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], f.path, f.line))
    return findings


def iter_source_files(root, excludes, ignore_patterns=None, stats=None):
    """Yield scannable files under root. Directory names in `excludes`
    (plus the built-ins) are pruned; file paths matching an exclude
    glob are skipped. Patterns from .loopholeignore are applied the
    same way — ignored directories are pruned and their scannable
    files counted in stats["ignored"], ignored files are skipped and
    counted too.
    """
    excluded = set(DEFAULT_EXCLUDES) | set(excludes or [])
    ignore_patterns = ignore_patterns or []
    if os.path.isfile(root):
        if detect_lang(root):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        keep = []
        for d in dirnames:
            rel = d if rel_dir == "." else rel_dir + "/" + d
            if d in excluded or d.startswith("."):
                continue
            if ignore_patterns and ignore_match(rel, ignore_patterns):
                if stats is not None:
                    stats["ignored"] += _count_scannable(
                        os.path.join(dirpath, d))
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if not detect_lang(p):
                continue
            rel = os.path.relpath(p, root)
            if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(fn, pat)
                   for pat in (excludes or [])):
                continue
            if ignore_patterns and ignore_match(rel, ignore_patterns):
                if stats is not None:
                    stats["ignored"] += 1
                continue
            yield p


def _finding_from_dict(d):
    """Rebuild a Finding from its to_dict() form, or None if malformed."""
    if not isinstance(d, dict):
        return None
    try:
        return Finding(d["rule_id"], d["severity"], d["title"], d["path"],
                       d["line"], d["snippet"], d["why"], d["fix"],
                       d.get("taint_flow"))
    except (KeyError, TypeError):
        return None


def _file_cache_key(path):
    """Fingerprint a file for the cache: path is the dict key; the value
    is size + mtime + SHA-256 of the contents. Any content change — even
    one that keeps size and mtime — changes the hash, so a stale entry
    can never be served. Returns None when the file cannot be read."""
    try:
        st = os.stat(path)
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None
    return {"size": st.st_size, "mtime_ns": st.st_mtime_ns,
            "sha256": digest}


def _config_fingerprint(config):
    """Hash of the scan config, so a changed config (disabled rules,
    severity overrides) invalidates the whole cache."""
    blob = json.dumps(config or {}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def load_cache(path, config_hash):
    """Load a cache file. Returns {file_path: entry} or {} on any doubt:
    missing/unreadable/corrupt file, a version mismatch (a Loophole
    upgrade invalidates old entries automatically) or a config change."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    if data.get("tool") != "loophole" or data.get("version") != VERSION:
        return {}
    if data.get("config") != config_hash:
        return {}
    entries = data.get("entries")
    return entries if isinstance(entries, dict) else {}


def save_cache(path, entries, config_hash):
    """Write the cache atomically (temp file + rename in the same
    directory). A cache that cannot be written is a warning, never a
    failed scan."""
    data = {"tool": "loophole", "version": VERSION,
            "config": config_hash, "entries": entries}
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        print(f"loophole: cannot write cache {path}: {exc}",
              file=sys.stderr)
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _dedupe_findings(findings):
    """Collapse exact duplicate findings, keeping the first occurrence.

    Two rules — or a pattern check and a taint check inside one rule —
    can flag the same construct, so the same finding may be emitted
    twice. The key is (path, line, rule_id, title, snippet, taint):
    identical findings collapse to one, while two genuinely different
    messages from the same rule on the same line are kept. Baseline
    keys are (rule_id, path, snippet), so non-duplicate findings keep
    exactly the same keys as before.
    """
    seen = set()
    deduped = []
    for f in findings:
        key = (f.path, f.line, f.rule_id, f.title, f.snippet, f.taint)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def scan_path(root, excludes, config=None, ignore_patterns=None,
              cache_path=None, stats=None):
    """Scan root; returns (findings, ignored_count). --exclude and
    config 'exclude' combine with .loopholeignore patterns.

    With cache_path, repeat scans reuse stored findings for files whose
    fingerprint (size + mtime + content hash) is unchanged; anything
    else is rescanned. Cached findings are the raw per-file results,
    so baseline and severity filtering — applied by the caller, after
    this returns — behave exactly as for fresh findings. stats, when
    given, gains stats["cached"], the number of files served from the
    cache. Without --cache, behaviour is unchanged.
    """
    findings = []
    excludes = list(excludes or [])
    if config:
        excludes += config.get("exclude", [])
    if stats is None:
        stats = {"ignored": 0}
    stats.setdefault("ignored", 0)
    cache = {}
    config_hash = None
    cache_abs = os.path.abspath(cache_path) if cache_path else None
    if cache_path:
        config_hash = _config_fingerprint(config)
        cache = load_cache(cache_path, config_hash)
    kept = {}  # entries for files seen on this run only (prunes deletions)
    cached = 0
    for path in sorted(iter_source_files(root, excludes, ignore_patterns,
                                         stats)):
        if cache_abs and os.path.abspath(path) == cache_abs:
            continue  # never scan the cache file itself
        key = _file_cache_key(path) if cache_path else None
        entry = cache.get(path) if key is not None else None
        if (isinstance(entry, dict) and entry.get("key") == key
                and isinstance(entry.get("findings"), list)):
            restored = [_finding_from_dict(d)
                        for d in entry["findings"]]
            if all(f is not None for f in restored):
                findings.extend(restored)
                kept[path] = entry
                cached += 1
                continue
        fresh = scan_file(path, config)
        findings.extend(fresh)
        if cache_path and key is not None:
            kept[path] = {"key": key,
                          "findings": [f.to_dict() for f in fresh]}
    if cache_path:
        save_cache(cache_path, kept, config_hash)
    stats["cached"] = cached
    findings = _dedupe_findings(findings)
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], f.path, f.line))
    return findings, stats["ignored"]


# ---------------------------------------------------------------------------
# Output: terminal
# ---------------------------------------------------------------------------

def print_report(findings, color, min_sev="medium"):
    sev_ok = lambda s: SEV_ORDER[s] <= SEV_ORDER[min_sev]
    shown = [f for f in findings if sev_ok(f.severity)]
    if not shown:
        print(color.green("✓ No loopholes found."))
        return
    counts = {}
    for f in shown:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(
        f"{sev_color(color, s)(str(counts.get(s, 0)) + ' ' + s)}"
        for s in SEVERITIES if counts.get(s))
    print(color.bold(f"Loophole found {len(shown)} issue(s): {summary}\n"))
    for sev in SEVERITIES:
        group = [f for f in shown if f.severity == sev]
        if not group:
            continue
        print(sev_color(color, sev)(f"── {sev.upper()} ({len(group)}) " +
                                   "─" * 50))
        for f in group:
            print(f"  {color.bold(f.rule_id)} {f.title}")
            print(f"  {color.dim(f.path)}:{color.bold(str(f.line))}")
            print(f"  {color.dim('›')} {f.snippet}")
            if f.taint:
                print(f"  {color.red('taint:')} {f.taint}")
            print(f"  {color.dim('why:')} {f.why}")
            print(f"  {color.green('fix:')} {f.fix}\n")


# ---------------------------------------------------------------------------
# Output: GitHub workflow-command annotations (issue #27)
# ---------------------------------------------------------------------------

def _escape_workflow_data(text):
    """Escape message data for a GitHub workflow command.

    The workflow-command spec escapes ``%`` first, then carriage
    return and line feed.
    """
    return (text.replace("%", "%25")
                .replace("\r", "%0D")
                .replace("\n", "%0A"))


def _escape_workflow_property(text):
    """Escape a workflow-command property value.

    Properties escape ``%``, ``\r`` and ``\n`` like message data, plus
    ``:`` and ``,`` — which would otherwise end the property list.
    The ``%`` step runs first (via _escape_workflow_data) so the
    ``%`` introduced by e.g. ``%3A`` is not escaped a second time.
    """
    return (_escape_workflow_data(text)
            .replace(":", "%3A")
            .replace(",", "%2C"))


_ANNOTATION_COMMAND = {"critical": "error", "high": "error",
                       "medium": "warning"}


def annotation_line(finding):
    """One workflow command for a finding, e.g.::

        ::error file=app.py,line=3,title=SEC002::Hardcoded password — ...

    Critical/high findings become ``::error``, medium ones
    ``::warning`` — the same mapping write_sarif uses for SARIF
    levels. The message is the rule title plus the offending source
    line, with workflow-command escaping applied.
    """
    command = _ANNOTATION_COMMAND[finding.severity]
    props = ("file=" + _escape_workflow_property(finding.path) +
             ",line=" + str(finding.line) +
             ",title=" + _escape_workflow_property(finding.rule_id))
    message = _escape_workflow_data(
        f"{finding.title} — {finding.snippet}")
    return f"::{command} {props}::{message}"


def print_annotations(findings, min_sev="medium"):
    """Print one workflow command per finding (issue #27).

    Replaces the human report when ``--format annotations`` is used,
    so a GitHub Actions step annotates the PR diff with no SARIF
    upload step. The ``--severity`` filter applies exactly as it
    does to the human report, and the exit code is unchanged.
    """
    sev_ok = lambda s: SEV_ORDER[s] <= SEV_ORDER[min_sev]
    for f in findings:
        if sev_ok(f.severity):
            print(annotation_line(f))


# ---------------------------------------------------------------------------
# Output: JSON / SARIF
# ---------------------------------------------------------------------------

def write_json(findings, out_path, ignored=0, cached=0):
    data = {
        "tool": "loophole",
        "version": VERSION,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            s: sum(1 for f in findings if f.severity == s)
            for s in SEVERITIES
        },
    }
    data["summary"]["ignored"] = ignored
    data["summary"]["cached"] = cached
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return out_path


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning"}


def write_sarif(findings, out_path):
    """SARIF 2.1.0 report.

    The `rules` array carries full metadata for EVERY rule in RULES —
    shortDescription, fullDescription (why), help (fix), helpUri and
    defaultConfiguration — even when a scan finds nothing, so code
    scanning always shows a complete rule card. The rule functions
    stay the single source of truth: metadata is re-read from their
    own literals via _load_all_rule_meta(). Multi-variant rules (e.g.
    DESER001, XSS005) use their first variant for the rule card; each
    individual result still carries its own variant's title and fix
    in its message text.
    """
    meta = _load_all_rule_meta()
    rules = []
    for rid, _langs, _fn in RULES:
        variants = meta.get(rid, [])
        entry = {"id": rid, "helpUri": rule_help_uri(rid)}
        if variants:
            first = variants[0]
            entry["name"] = first["title"]
            entry["shortDescription"] = {"text": first["title"]}
            entry["fullDescription"] = {"text": first["why"]}
            entry["help"] = {"text": first["fix"]}
            entry["defaultConfiguration"] = {
                "level": _SARIF_LEVEL[first["severity"]]}
            entry["properties"] = {"severity": first["severity"]}
        else:
            # No metadata could be extracted for this rule; keep the
            # bare stub (with its doc link) rather than dropping it.
            entry["name"] = rid
            entry["shortDescription"] = {"text": rid}
        rules.append(entry)
    level = _SARIF_LEVEL
    results = [{
        "ruleId": f.rule_id,
        "level": level[f.severity],
        "message": {"text": f"{f.title} — {f.fix}"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.path},
                "region": {"startLine": f.line,
                           "snippet": {"text": f.snippet}},
            }
        }],
    } for f in findings]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Loophole",
                "version": VERSION,
                "informationUri": RULE_DOC_URL,
                "rules": rules,
            }},
            "results": results,
        }],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return out_path


# ---------------------------------------------------------------------------
# Output: HTML report (single file, inline CSS, no external assets)
# ---------------------------------------------------------------------------

_HTML_CSS = (
    "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:"
    "60rem;padding:0 1rem;color:#1a1a1a}h1{font-size:1.5rem}"
    ".summary{color:#555}.finding{border:1px solid #ddd;border-left:"
    "6px solid #999;border-radius:4px;padding:.6rem 1rem;margin:.8rem 0}"
    ".finding.critical{border-left-color:#c0392b}.finding.high{"
    "border-left-color:#e67e22}.finding.medium{border-left-color:#2980b9}"
    ".loc{color:#555;font-family:ui-monospace,monospace}pre{background:"
    "#f6f6f6;padding:.5rem;overflow-x:auto}.taint{color:#c0392b}"
    "h2.critical{color:#c0392b}h2.high{color:#e67e22}h2.medium{"
    "color:#2980b9}")


def write_html(findings, out_path):
    """Self-contained HTML report: findings grouped by severity."""
    esc = html.escape
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in SEVERITIES}
    summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES
                        if counts[s]) or "no findings"
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>Loophole scan report</title>",
        f"<style>{_HTML_CSS}</style></head><body>",
        f"<h1>Loophole v{esc(VERSION)} — scan report</h1>",
        f'<p class="summary">{len(findings)} finding(s): '
        f"{esc(summary)}</p>",
    ]
    for sev in SEVERITIES:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        parts.append(f'<h2 class="{sev}">{sev.upper()} '
                     f"({len(group)})</h2>")
        for f in group:
            parts.append(f'<div class="finding {sev}">')
            parts.append(f"<h3>{esc(f.rule_id)} — {esc(f.title)}</h3>")
            parts.append(f'<p class="loc">{esc(f.path)}:{f.line}</p>')
            parts.append(f"<pre>{esc(f.snippet)}</pre>")
            if f.taint:
                parts.append(f'<p class="taint">taint: '
                             f"{esc(f.taint)}</p>")
            parts.append(f"<p><strong>Why:</strong> {esc(f.why)}</p>")
            parts.append(f"<p><strong>Fix:</strong> {esc(f.fix)}</p>")
            parts.append("</div>")
    parts.append("</body></html>")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))
    return out_path


# ---------------------------------------------------------------------------
# Output: JUnit XML report (test-style results for CI dashboards)
# ---------------------------------------------------------------------------

def write_junit(findings, out_path):
    """JUnit XML report: one testsuite, one testcase per finding.

    ElementTree escapes all text and attribute values, so the output is
    always well-formed. A clean scan emits an empty suite with
    tests="0" failures="0".
    """
    suite = ET.Element("testsuite", {
        "name": "loophole",
        "tests": str(len(findings)),
        "failures": str(len(findings)),
        "errors": "0",
        "skipped": "0",
    })
    for f in findings:
        case = ET.SubElement(suite, "testcase", {
            "classname": f.rule_id,
            "name": f"{f.path}:{f.line}",
        })
        failure = ET.SubElement(case, "failure", {
            "message": f"[{f.severity}] {f.rule_id}: {f.title}",
            "type": f.rule_id,
        })
        failure.text = (f"{f.path}:{f.line}: {f.title}\n"
                        f"{f.why}\nFix: {f.fix}\n{f.snippet}")
    ET.ElementTree(suite).write(out_path, encoding="utf-8",
                                xml_declaration=True)
    return out_path


# ---------------------------------------------------------------------------
# Output: GitLab SAST report (schema 15.x, for the GitLab Security
# Dashboard / merge request widget)
# ---------------------------------------------------------------------------

_GITLAB_SEVERITY = {"critical": "Critical", "high": "High",
                    "medium": "Medium"}
_GITLAB_SCHEMA_VERSION = "15.0.0"
_GITLAB_SCHEMA_URL = (
    "https://gitlab.com/gitlab-org/security-products/"
    "security-report-schemas/-/raw/v15.0.0/dist/sast-report-format.json")


def _gitlab_vuln_id(f):
    """Stable vulnerability id: sha256 of the baseline key
    (rule id, path, snippet) — so the same finding keeps the same id
    across scans, and a finding survives small line shifts."""
    key = "|".join((f.rule_id, f.path, f.snippet))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def write_gitlab(findings, out_path):
    """GitLab SAST report (schema 15.x).

    One vulnerability entry per finding: `id` is the stable hash of
    the baseline key, `category` is always "sast", `severity` maps
    Loophole's critical/high/medium onto GitLab's Critical/High/
    Medium, and `identifiers` carries the Loophole rule id (with a
    link to the rule docs; a CWE identifier is added once rules
    carry CWE ids). `confidence` is High for taint-tracked findings
    and Medium otherwise. A clean scan emits an empty
    `vulnerabilities` list with the same `scan` block.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    vulns = [{
        "id": _gitlab_vuln_id(f),
        "category": "sast",
        "name": f.title,
        "message": f.why,
        "description": f.why,
        "severity": _GITLAB_SEVERITY[f.severity],
        "confidence": "High" if f.taint else "Medium",
        "solution": f.fix,
        "scanner": {"id": "loophole", "name": "Loophole"},
        "identifiers": [{
            "type": "loophole_rule",
            "name": f"Loophole {f.rule_id}",
            "value": f.rule_id,
            "url": rule_help_uri(f.rule_id),
        }],
        "location": {"file": f.path, "start_line": f.line,
                     "end_line": f.line},
    } for f in findings]
    report = {
        "version": _GITLAB_SCHEMA_VERSION,
        "schema": _GITLAB_SCHEMA_URL,
        "scan": {
            "type": "sast",
            "status": "success",
            "start_time": now,
            "end_time": now,
            "scanner": {
                "id": "loophole",
                "name": "Loophole",
                "version": VERSION,
                "vendor": {"name": "Loophole"},
            },
        },
        "vulnerabilities": vulns,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return out_path


# ---------------------------------------------------------------------------
# Baseline: known findings you accept today, so CI only fails on NEW ones
# ---------------------------------------------------------------------------

def _baseline_key(f):
    # snippet (not just line) so a finding survives small line shifts
    return (f.rule_id, f.path, f.snippet)


def write_baseline(findings, out_path):
    data = {
        "tool": "loophole",
        "version": VERSION,
        "entries": [
            {"rule_id": f.rule_id, "path": f.path, "line": f.line,
             "snippet": f.snippet}
            for f in findings
        ],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return out_path


def load_baseline(path):
    """Return the set of (rule_id, path, snippet) keys in a baseline."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {(e["rule_id"], e["path"], e["snippet"])
            for e in data.get("entries", [])}


# ---------------------------------------------------------------------------
# --fix-dry: suggested patches as unified diffs (never modifies files)
# ---------------------------------------------------------------------------

def _one_line_diff(path, lineno, old_line, new_line):
    return "".join(difflib.unified_diff(
        [old_line + "\n"], [new_line + "\n"],
        fromfile=f"{path}:{lineno} (current)",
        tofile=f"{path}:{lineno} (suggested)"))


def suggest_fix(finding, lines):
    """Return (old_line, new_line, note) or None if no safe suggestion."""
    raw = lines[finding.line - 1]
    rid = finding.rule_id
    if rid == "RAND001" and "Math.random()" in raw:
        new = raw.replace("Math.random()",
                          "crypto.randomInt(0, Number.MAX_SAFE_INTEGER)")
        return raw, new, "needs: import { randomInt } from 'node:crypto'"
    if rid == "RAND002" and "random.random()" in raw:
        new = raw.replace("random.random()", "secrets.SystemRandom().random()")
        return raw, new, "needs: import secrets"
    if rid == "CRY001" and "md5" in raw:
        new = re.sub(r"md5", "sha256", raw)
        return raw, new, ("mechanical rename only — for passwords use "
                         "bcrypt/argon2, not SHA-256")
    if rid == "CRY002" and "sha1" in raw:
        new = re.sub(r"sha1", "sha256", raw, flags=re.IGNORECASE)
        return raw, new, ("mechanical rename only — for passwords use "
                         "bcrypt/argon2, not SHA-256")
    if rid == "DBG001" and "debug=True" in raw:
        return raw, raw.replace("debug=True", "debug=False"), None
    if rid == "DBG001" and "DEBUG = True" in raw:
        return raw, raw.replace("DEBUG = True", "DEBUG = False"), None
    if rid == "TLS001":
        for a, b in (("verify=False", "verify=True"),  # loophole: skip=TLS001
                     ("rejectUnauthorized: false",
                      "rejectUnauthorized: true"),
                     ("InsecureSkipVerify: true",
                      "InsecureSkipVerify: false")):
            if a in raw:
                return raw, raw.replace(a, b), None
    if rid == "TLS004" and "InsecureSkipVerify: true" in raw:
        return raw, raw.replace("InsecureSkipVerify: true",
                                "InsecureSkipVerify: false"), None
    if rid == "XSS001" and ".innerHTML =" in raw:
        return raw, raw.replace(".innerHTML =", ".textContent ="), \
            "only safe when you meant to insert text, not HTML"
    return None


def print_fix_dry(findings, files_lines):
    any_fix = False
    for f in findings:
        lines = files_lines.get(f.path)
        if not lines:
            continue
        sug = suggest_fix(f, lines)
        if not sug:
            continue
        any_fix = True
        old, new, note = sug
        print(f"### {f.rule_id} {f.title} — {f.path}:{f.line}")
        print(_one_line_diff(f.path, f.line, old.rstrip("\n"), new.rstrip("\n")),
              end="")
        if note:
            print(f"# note: {note}")
        print()
    if not any_fix:
        print("No safe mechanical fixes suggested for these findings "
              "(they need human judgment).")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="loophole",
        description="Loophole v%s — static security scanner for "
                    "JS/TS, Python, Go and PHP." % VERSION)
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path", nargs="?",
                   help="file or directory to scan (not needed with "
                        "--rules or --explain)")
    s.add_argument("--json", dest="json_out", metavar="FILE",
                   help="write findings as JSON")
    s.add_argument("--sarif", dest="sarif_out", metavar="FILE",
                   help="write findings as SARIF 2.1.0")
    s.add_argument("--format", default="text",
                   choices=["text", "annotations"],
                   help="output format: text (default) or annotations "
                        "(GitHub workflow commands, one ::error/::warning "
                        "per finding — no SARIF upload needed)")
    s.add_argument("--annotations", action="store_true",
                   help="shorthand for --format annotations")
    s.add_argument("--fix-dry", action="store_true",
                   help="print suggested patches as diffs (never modifies)")
    s.add_argument("--severity", default="medium",
                   choices=["critical", "high", "medium"],
                   help="minimum severity to display: "
                        "critical, high or medium (default: medium)")
    s.add_argument("--exclude", default="",
                   help="comma-separated dir names to skip")
    s.add_argument("--no-color", action="store_true",
                   help="disable colored output")
    s.add_argument("--config", metavar="FILE",
                   help="config file (default: .loophole.json in the "
                        "scanned root, if present)")
    s.add_argument("--baseline", metavar="FILE",
                   help="baseline file: findings recorded in it are "
                        "hidden (see --write-baseline)")
    s.add_argument("--write-baseline", metavar="FILE",
                   dest="write_baseline",
                   help="scan, write all findings to this baseline "
                        "file, exit 0")
    s.add_argument("--html", metavar="FILE", dest="html_out",
                   help="also write a self-contained HTML report")
    s.add_argument("--junit", metavar="FILE", dest="junit_out",
                   help="also write a JUnit XML report (for CI dashboards)")
    s.add_argument("--gitlab", metavar="FILE", dest="gitlab_out",
                   help="also write a GitLab SAST report (schema 15.x)")
    s.add_argument("--cache", metavar="FILE",
                   help="opt-in incremental cache file: repeat scans "
                        "reuse findings for unchanged files (see README)")
    s.add_argument("--rules", action="store_true",
                   help="list all rule IDs and exit")
    s.add_argument("--explain", metavar="RULEID",
                   help="show detail for one rule ID and exit")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan" and args.explain:
        return explain_rule(args.explain)

    if args.command == "scan" and args.rules:
        for rid, langs, _fn in RULES:
            print(f"{rid:10} {','.join(langs)}")
        print(f"\n{len(RULES)} rules total.")
        return 0

    if args.path is None:
        parser.error("the following arguments are required: path")

    use_color = not args.no_color and sys.stdout.isatty()
    color = Color(use_color)

    excludes = [e.strip() for e in args.exclude.split(",") if e.strip()]
    config = load_config(args.config, args.path)
    ignore_patterns = load_ignore_patterns(args.path)
    stats = {}
    findings, ignored = scan_path(args.path, excludes, config,
                                  ignore_patterns,
                                  cache_path=args.cache, stats=stats)
    cached = stats.get("cached", 0)

    if args.write_baseline:
        write_baseline(findings, args.write_baseline)
        print(f"Baseline written: {args.write_baseline} "
              f"({len(findings)} findings recorded)")
        return 0
    if args.baseline:
        try:
            known = load_baseline(args.baseline)
        except (OSError, ValueError, KeyError) as exc:
            print(f"loophole: cannot read baseline {args.baseline}: "
                  f"{exc}", file=sys.stderr)
            return 2
        findings = [f for f in findings
                    if _baseline_key(f) not in known]

    if args.format == "annotations" or args.annotations:
        print_annotations(findings, args.severity)
    else:
        print_report(findings, color, args.severity)
    if ignored:
        print(color.dim(f"{ignored} file(s) skipped by .loopholeignore"))
    if args.cache:
        print(color.dim(f"{cached} file(s) served from cache "
                        f"({args.cache})"))

    if args.json_out:
        write_json(findings, args.json_out, ignored, cached=cached)
        print(f"JSON report: {args.json_out}")
    if args.sarif_out:
        write_sarif(findings, args.sarif_out)
        print(f"SARIF report: {args.sarif_out}")
    if args.html_out:
        write_html(findings, args.html_out)
        print(f"HTML report: {args.html_out}")
    if args.junit_out:
        write_junit(findings, args.junit_out)
        print(f"JUnit report: {args.junit_out}")
    if args.gitlab_out:
        write_gitlab(findings, args.gitlab_out)
        print(f"GitLab SAST report: {args.gitlab_out}")
    if args.fix_dry:
        print(color.bold("\n── Suggested fixes (dry run — nothing modified) ──\n"))
        files_lines = {}
        for path in {f.path for f in findings}:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    files_lines[path] = fh.read().splitlines()
            except OSError:
                continue
        print_fix_dry(findings, files_lines)

    bad = any(f.severity in ("critical", "high") for f in findings)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

