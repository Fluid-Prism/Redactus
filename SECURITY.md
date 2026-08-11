# Security Policy

Exposure Auditor runs entirely on your own machine. It reads local files
looking for exposed credentials and writes only its own scan history to a
local SQLite file. There is no network code in the package — nothing is
uploaded, nothing is looked up, and there is no telemetry to disable.

It is read-only. It never edits, moves, quarantines or deletes anything it
finds; every fix is a command you run yourself.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for a security report.

Use GitHub's private vulnerability reporting instead: repo → Security →
Report a vulnerability.

If that isn't available, email **developers@fluidprism.com** with a
description and, if possible, a minimal reproduction. We'll acknowledge
within a few days and aim to have a fix or mitigation out within 30 days for
confirmed issues, sooner for anything actively exploitable.

## In scope

Anything that causes this tool to leak what it finds. Specifically:

- **A raw secret reaching any output** — the terminal, the GUI, the JSON, the
  history database, or an exception traceback. Everything goes through
  `redact.py`, and `selftest.py` plants real-shaped secrets and fails if any
  survive to a rendered surface. A path around that is the most serious bug
  this project can have.
- **The history database being readable by another local account**, or being
  created at permissive modes before being narrowed.
- **Escaping the scan roots** — a symlink, `..` path, or crafted filename that
  makes the scanner read outside the directory it was pointed at.
- **Anything that turns a scan into a write**, or that gets a crafted filename
  or file content executed or interpreted rather than read.
- **A crafted file that hangs or crashes the scan**, since an aborted scan
  reports nothing found for everything it never reached.

## Not vulnerabilities by themselves

- **False positives.** The rules deliberately prefer precision, but a
  vendor-prefixed string in documentation will still match. Please do report
  a pattern that's noisy in ordinary use — that's a real bug in a tool like
  this, just not a security one.
- **False negatives from an unknown format.** This has no entropy heuristics
  by design (see the README), so a homegrown or internal-format credential
  will be missed. A new rule is a feature request, not a report.
- **Findings inside skipped directories.** Package caches and editor
  extensions are excluded by default; `--include-caches` scans them.
- **Needing no elevation.** It reads what your own account can read. Running
  it as root is warned against, not blocked, and is not the intended use.

## Supported versions

Pre-1.0 and unreleased; only the latest commit on the default branch is
supported.
