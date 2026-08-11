"""scanner.py — walk the disk once, safely, and hand what it finds to the rules.

Three constraints shape everything here.

**Never leave the roots.** Directory symlinks aren't followed, and every
file is re-checked against its scan root after resolution. A symlink in a
scanned directory pointing at /etc or at another user's home would
otherwise turn "scan my home directory" into something else entirely, and
the report would then name paths the user never asked about.

**Always finish.** A home directory can hold a million files, and an
unbounded walk that gets killed halfway through reports "no findings" for
everything it never reached. There's a file-size ceiling, a total-bytes-read
ceiling, and a wall-clock budget, and any of them being hit is recorded and
reported rather than quietly changing what a clean result means.

**Say what wasn't looked at.** `ScanReport` carries the skip counts, and
every surface that displays findings displays those too. "Nothing found in
what I could read" and "nothing found" are different claims, and only the
first one is ever true here.
"""
import os
import stat
import time
from dataclasses import dataclass, field
from typing import List

from .redact import sanitize
from .rules import ALL_DETECTORS
from .rules.base import FileFacts

# Directories full of files somebody else wrote. Two reasons to skip them,
# and the second matters more than the first.
#
# They're enormous, so walking them is the difference between a scan that
# takes seconds and one that takes an hour. But mainly, a credential found
# inside a package cache, an editor extension, or a tool's own history is not
# the user's credential and not theirs to rotate — it's a test fixture that
# shipped with a dependency, or a copy of a file they already have. Reporting
# those buries the handful of real findings under dozens of unactionable ones,
# which is how a security tool teaches people to close it.
#
# `--include-caches` scans them anyway; nothing here is permanently hidden.
SKIP_DIRS = {
    # version control and build output
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    "build", "dist", ".next", ".nuxt", ".tox", ".terraform",
    # dependency trees and package caches
    "node_modules", "site-packages", "dist-packages", "vendor", "Pods",
    ".npm", ".yarn", ".pnpm-store", ".bun", ".deno", ".gradle", ".m2",
    ".cargo", ".rustup", ".nvm", ".gem", ".cpan", ".cache", "_cacache",
    "venv", ".venv", "env",
    # editor / IDE / tooling state
    ".vscode", ".vscode-server", ".cursor", ".idea", ".antigravity",
    ".antigravity-ide", ".gemini", ".claude",
    # OS-level caches and trash
    "Caches", "CachedData", "Code Cache", "GPUCache", "Library",
    ".Trash", ".local/share/Trash",
}

# Anything below is content-scanned; anything above is only checked for
# permissions. A real credential file is measured in kilobytes.
MAX_TEXT_BYTES = 1 * 1024 * 1024
MAX_TOTAL_READ_BYTES = 512 * 1024 * 1024
DEFAULT_TIME_BUDGET_SECONDS = 90

# Extensions that are never worth reading as text. Checking the first bytes
# for NUL catches the rest; this just avoids opening the obvious ones at all.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".tiff", ".bmp", ".ico",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".m4a",
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".dmg", ".iso", ".pkg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".so", ".dylib", ".dll", ".exe", ".o", ".a", ".class", ".pyc", ".wasm",
    ".sqlite", ".db", ".woff", ".woff2", ".ttf", ".otf",
}

# Files worth reading wherever they turn up, regardless of the sweep's rules.
ALWAYS_READ_NAMES = {
    ".netrc", "_netrc", ".git-credentials", ".pgpass", ".npmrc", ".pypirc",
    ".env", "credentials", "config.json", "config",
    ".bash_history", ".zsh_history", ".sh_history", ".history",
    ".python_history", ".psql_history", ".mysql_history", ".node_repl_history",
}


@dataclass
class ScanReport:
    findings: List[object] = field(default_factory=list)
    files_seen: int = 0
    files_read: int = 0
    skipped_unreadable: int = 0
    skipped_too_large: int = 0
    detector_errors: int = 0
    stopped_early: bool = False
    stop_reason: str = ""
    roots: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def coverage_is_partial(self):
        return bool(self.stopped_early or self.skipped_unreadable
                    or self.skipped_too_large or self.detector_errors)


def default_roots():
    """Where credentials actually accumulate. Not the whole disk: system
    directories aren't the user's to fix, and scanning them would produce a
    report full of findings whose remediation is 'this is fine, leave it'."""
    home = os.path.expanduser("~")
    return [home]


def display_path(path):
    """The ~-relative form shown to the user — sanitised, because a filename
    is attacker-influenced and this string reaches a terminal."""
    home = os.path.expanduser("~")
    if path == home:
        shown = "~"
    elif path.startswith(home + os.sep):
        shown = "~" + path[len(home):]
    else:
        shown = path
    return sanitize(shown)


def _looks_binary(chunk):
    return b"\x00" in chunk


def _read_text(path, size):
    """(text, reason). text is None when the file wasn't read; reason is one
    of '', 'too_large', 'unreadable', 'binary' so the caller can count it."""
    if size > MAX_TEXT_BYTES:
        return None, "too_large"
    _, ext = os.path.splitext(path)
    if ext.lower() in BINARY_EXTENSIONS:
        return None, "binary"
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_TEXT_BYTES)
    except OSError:
        return None, "unreadable"
    if _looks_binary(raw[:4096]):
        return None, "binary"
    return raw.decode("utf-8", errors="replace"), ""


def _within(real_root, path):
    """Containment check, run once per directory rather than once per file —
    realpath is a syscall-heavy call and a home directory has far more files
    than directories. os.walk(followlinks=False) plus the per-file islink
    check already prevent escaping; this is the belt to their braces, and
    catches the case where a scan root is itself given as a symlink."""
    real_path = os.path.realpath(path)
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def scan(roots=None, time_budget=DEFAULT_TIME_BUDGET_SECONDS, detectors=None,
         progress=None, include_caches=False):
    """Walk `roots`, run every detector over each file, return a ScanReport."""
    roots = roots or default_roots()
    detectors = detectors if detectors is not None else ALL_DETECTORS
    wants_text = any(d.needs_text for d in detectors)
    skip_dirs = set() if include_caches else SKIP_DIRS

    report = ScanReport(roots=[display_path(r) for r in roots])
    started = time.monotonic()
    bytes_read = 0

    for root in roots:
        if not os.path.isdir(root):
            continue
        real_root = os.path.realpath(root)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Pruning in place is what makes os.walk skip these subtrees.
            dirnames[:] = [d for d in dirnames
                           if d not in skip_dirs and not d.endswith(".app")]

            if time.monotonic() - started > time_budget:
                report.stopped_early = True
                report.stop_reason = (
                    f"Stopped after {time_budget:.0f}s — this machine has more files than "
                    "the time budget allows. Findings below are real; the parts not reached "
                    "were not checked.")
                break

            if not _within(real_root, dirpath):
                dirnames[:] = []
                continue

            for filename in filenames:
                # Checked per file, not only per directory: a single file that
                # takes a pathological amount of time to examine would
                # otherwise run the whole budget out inside one directory, and
                # everything after it would go unscanned while the report still
                # looked complete.
                if time.monotonic() - started > time_budget:
                    report.stopped_early = True
                    report.stop_reason = (
                        f"Stopped after {time_budget:.0f}s — this machine has more files "
                        "than the time budget allows. Findings below are real; the parts "
                        "not reached were not checked.")
                    break

                path = os.path.join(dirpath, filename)
                report.files_seen += 1

                try:
                    stat_result = os.stat(path, follow_symlinks=False)
                except OSError:
                    report.skipped_unreadable += 1
                    continue
                if not stat.S_ISREG(stat_result.st_mode):
                    continue   # symlinks, sockets, fifos: nothing to read, nothing to own

                text = None
                if wants_text and bytes_read < MAX_TOTAL_READ_BYTES:
                    text, reason = _read_text(path, stat_result.st_size)
                    if reason == "too_large":
                        report.skipped_too_large += 1
                    elif reason == "unreadable":
                        report.skipped_unreadable += 1
                    if text is not None:
                        bytes_read += min(stat_result.st_size, MAX_TEXT_BYTES)
                        report.files_read += 1

                facts = FileFacts(
                    path=path,
                    name=filename,
                    mode=stat_result.st_mode & 0o777,
                    size=stat_result.st_size,
                    display_path=display_path(path),
                    text=text,
                )

                for detector in detectors:
                    try:
                        report.findings.extend(detector.examine(facts))
                    except Exception:
                        # A bug in one detector must not lose every other
                        # detector's findings for this file, or end the run.
                        # Counted separately so a broken detector shows up as
                        # a coverage gap instead of hiding behind a clean report.
                        report.detector_errors += 1

                if progress and report.files_seen % 2000 == 0:
                    progress(report.files_seen, len(report.findings))
        if report.stopped_early:
            break

    if bytes_read >= MAX_TOTAL_READ_BYTES and not report.stopped_early:
        report.stopped_early = True
        report.stop_reason = ("Stopped after reading 512 MB of file contents. Findings below "
                              "are real; the parts not reached were not checked.")

    report.duration_seconds = time.monotonic() - started
    return report
