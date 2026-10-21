# Security Policy

## Supported versions

Only the latest release of Loophole is supported with security fixes.
The scanner itself is a single stdlib-only Python file with no runtime
dependencies, which keeps its own attack surface small by design.

## Reporting a vulnerability

Please report vulnerabilities **privately** — do not open a public issue
for a security problem.

- Preferred: use GitHub's private vulnerability reporting — go to the
  **Security** tab of this repository and choose
  **"Report a vulnerability"**.

Include, where you can:

- the rule ID or component involved (e.g. `SQL001`, the taint engine),
- a minimal code sample that reproduces the problem,
- the impact as you see it (missed detection, crash on hostile input,
  incorrect fix suggestion, …).

You can expect an acknowledgement within 7 days. Confirmed issues are
fixed in a patch release and credited to the reporter in the release
notes, unless you ask to stay anonymous.

## Scope notes

Loophole analyzes source code; it never executes the code it scans.
Crashes or hangs caused by malformed input files are treated as
security-relevant bugs, because the scanner is meant to run on
untrusted repositories in CI.
