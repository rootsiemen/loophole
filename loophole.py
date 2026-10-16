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
                                    [--fix-dry] [--severity critical,high]
                                    [--exclude dir1,dir2] [--no-color]

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
import difflib
import fnmatch
import json
import math
import os
import re
import sys

VERSION = "0.1.0"

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


def word_in(text, word):
    """Whole-word (or $var) occurrence check."""
    return re.search(r"(?<![\w$])" + re.escape(word) + r"(?![\w])", text) is not None


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

LANG_BY_EXT = {
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js",          # TypeScript handled by the JS engine
    ".py": "py",
    ".go": "go",
    ".php": "php",
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


def tainted_in_call(arg_text, tainted):
    """Return the tainted var name flowing into this call, or None."""
    for var in tainted:
        if word_in(arg_text, var):
            return var
    return None


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
    depth = 0
    in_str = None
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
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            return args[:i]
        i += 1
    return args


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
        if args is None:
            return None, None
        var = tainted_in_call(args, self.tainted)
        if var:
            return var, self.tainted[var]
        for pat in TAINT_SOURCES[self.lang]:
            m = re.search(pat, args)
            if m:
                return None, m.group(0)
        return None, None


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
    """innerHTML / outerHTML assigned dynamic content."""
    pats = {"js": [r"\.(innerHTML|outerHTML)\s*=\s*(?![\"'`]\s*;)"]}
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
        args = call_args(line, r"document\.writeln?")
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
    """eval() with dynamic input."""
    out = []
    for i, line in enumerate(ctx.lines, 1):
        m = re.search(r"(?<![\w.])eval\s*\(", line)
        if not m:
            continue
        args = call_args(line, r"(?<![\w.])eval")
        if args is None or is_string_literal(args):
            continue  # eval("1+1") — smelly but not exploitable
        taint_var, taint_src = ctx.flow(args)
        if re.search(r"\$\w+|\+\s*['\"]|['\"]\s*\+|\$\{|%s|f['\"]", args) \
                or taint_var or taint_src or re.search(r"[A-Za-z_$][\w$]*", args):
            out.append(ctx.hit(
                "EVAL001", "critical", "eval() with dynamic input", i,
                "eval() runs attacker-controlled strings as code in the "
                "app's context — arbitrary code execution.",
                "Never eval() dynamic input. Use JSON.parse, ast.literal_eval"
                ", or a proper parser instead.",
                taint=_taint_note(taint_var, taint_src, "eval()")))
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
        "go": [r"InsecureSkipVerify\s*:\s*true"],
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
# Rule registry — 35 rules
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
    ("TLS001", ("js", "py", "go", "php"), rule_TLS001),
    ("DBG001", ("js", "py", "php"), rule_DBG001),
    ("ERR001", ("js", "py", "go", "php"), rule_ERR001),
]


# ---------------------------------------------------------------------------
# Inline suppressions:  # loophole: skip   or   # loophole: skip=SEC001,CRY003
# ---------------------------------------------------------------------------

_SKIP_RE = re.compile(r"loophole\s*:\s*skip(?:\s*=\s*([A-Za-z0-9_, ]+))?",
                      re.IGNORECASE)


def _suppressed(line, rule_id):
    """True when the line carries a loophole: skip comment for this rule."""
    m = _SKIP_RE.search(line)
    if not m:
        return False
    ids = m.group(1)
    if not ids:  # bare "loophole: skip" silences every rule on the line
        return True
    return rule_id.upper() in {x.strip().upper()
                               for x in ids.split(",") if x.strip()}


def scan_file(path):
    """Scan one file. Returns a list of Findings."""
    lang = detect_lang(path)
    if not lang:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    ctx = Ctx(path, lang, lines)
    findings = []
    for rule_id, langs, func in RULES:
        if lang in langs:
            try:
                findings.extend(func(ctx))
            except Exception:
                # a broken rule must never kill a scan
                continue
    # honor inline suppressions:  # loophole: skip  /  # loophole: skip=SEC001
    findings = [f for f in findings
                if not _suppressed(lines[f.line - 1], f.rule_id)]
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], f.path, f.line))
    return findings


def iter_source_files(root, excludes):
    excluded = set(DEFAULT_EXCLUDES) | set(excludes or [])
    if os.path.isfile(root):
        if detect_lang(root):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in excluded and not d.startswith(".")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if not detect_lang(p):
                continue
            rel = os.path.relpath(p, root)
            if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(fn, pat)
                   for pat in (excludes or [])):
                continue
            yield p


def scan_path(root, excludes):
    findings = []
    for path in sorted(iter_source_files(root, excludes)):
        findings.extend(scan_file(path))
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], f.path, f.line))
    return findings


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
# Output: JSON / SARIF
# ---------------------------------------------------------------------------

def write_json(findings, out_path):
    data = {
        "tool": "loophole",
        "version": VERSION,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            s: sum(1 for f in findings if f.severity == s)
            for s in SEVERITIES
        },
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return out_path


def write_sarif(findings, out_path):
    rules = []
    seen = set()
    for _rid, _langs, _fn in RULES:
        seen.add(_rid)
    # rule metadata is embedded in findings; build a static index instead
    for f in findings:
        if f.rule_id not in [r["id"] for r in rules]:
            rules.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.why},
                "help": {"text": f.fix},
                "properties": {"severity": f.severity},
            })
    for rid in sorted(seen - {r["id"] for r in rules}):
        rules.append({"id": rid, "name": rid,
                      "shortDescription": {"text": rid}})
    level = {"critical": "error", "high": "error", "medium": "warning"}
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
                "informationUri": "https://github.com/rootsiemen/loophole",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return out_path


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
    s.add_argument("path", help="file or directory to scan")
    s.add_argument("--json", dest="json_out", metavar="FILE",
                   help="write findings as JSON")
    s.add_argument("--sarif", dest="sarif_out", metavar="FILE",
                   help="write findings as SARIF 2.1.0")
    s.add_argument("--fix-dry", action="store_true",
                   help="print suggested patches as diffs (never modifies)")
    s.add_argument("--severity", default="medium",
                   help="minimum severity to display: "
                        "critical, high or medium (default: medium)")
    s.add_argument("--exclude", default="",
                   help="comma-separated dir names to skip")
    s.add_argument("--no-color", action="store_true",
                   help="disable colored output")
    s.add_argument("--rules", action="store_true",
                   help="list all rule IDs and exit")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.command == "scan" and args.rules:
        for rid, langs, _fn in RULES:
            print(f"{rid:10} {','.join(langs)}")
        print(f"\n{len(RULES)} rules total.")
        return 0

    use_color = not args.no_color and sys.stdout.isatty()
    color = Color(use_color)

    excludes = [e.strip() for e in args.exclude.split(",") if e.strip()]
    findings = scan_path(args.path, excludes)

    print_report(findings, color, args.severity)

    if args.json_out:
        write_json(findings, args.json_out)
        print(f"JSON report: {args.json_out}")
    if args.sarif_out:
        write_sarif(findings, args.sarif_out)
        print(f"SARIF report: {args.sarif_out}")
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
