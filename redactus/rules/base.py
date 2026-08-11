"""base.py — the shapes every rule conforms to.

Two separate concepts, because conflating them forces awkward code:

A **detector** looks. It receives everything already read from disk (path,
permission bits, size, and the file's text if it was readable) and returns
findings. It never opens a file, never shells out, never decides what to
scan — the scanner does all of that once and hands the result to every
detector. That keeps the interesting part, deciding what counts as an
exposure, testable against synthetic input with no filesystem involved.

A **rule** describes one *kind* of finding: what it's called, why it
matters, how to fix it. One detector often produces several kinds (reading
a private key tells you both whether others can read it and whether it has
a passphrase — one parse, two unrelated problems, two different fixes), so
detectors and rules deliberately aren't one-to-one.

Confidence is carried on the finding, not implied by severity. A
world-readable private key is `certain`: the mode bits either say that or
they don't. A high-entropy string in a .env file is `likely` at best.
Presenting the second as if it were the first is how a tool teaches people
to ignore it.
"""
from dataclasses import dataclass
from typing import Callable, List, Optional

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

CONFIDENCE_CERTAIN = "certain"     # verifiable fact (permission bits, parsed file format)
CONFIDENCE_LIKELY = "likely"        # vendor-prefixed token, recognised credential file
CONFIDENCE_POSSIBLE = "possible"     # shape/heuristic match, expect false positives

CONFIDENCE_ORDER = [CONFIDENCE_CERTAIN, CONFIDENCE_LIKELY, CONFIDENCE_POSSIBLE]


@dataclass(frozen=True)
class FileFacts:
    """Everything the scanner learned about one file, read exactly once."""
    path: str                        # absolute, resolved, confined to a scan root
    name: str                        # basename
    mode: int                        # st_mode permission bits only
    size: int
    display_path: str                # ~/-relative where possible; what a user recognises
    text: Optional[str] = None       # None when unread: binary, oversized, or unreadable


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    display_path: str
    detail: str                      # generated prose; never contains raw matched material
    confidence: str = CONFIDENCE_CERTAIN
    evidence: str = ""               # masked via redact.py, or empty
    line_no: Optional[int] = None


@dataclass(frozen=True)
class Detector:
    id: str
    examine: Callable[[FileFacts], List[Finding]]
    needs_text: bool = False


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    rationale: str                   # why someone who found this could hurt you
    severity: str                    # nominal; a finding may override for its own context
    remediation: Callable[[Finding], str]


def group_readable(mode):
    return bool(mode & 0o040)


def other_readable(mode):
    return bool(mode & 0o004)


def too_open(mode):
    """True when anyone other than the owner can read this."""
    return group_readable(mode) or other_readable(mode)


def mode_str(mode):
    return format(mode & 0o777, "04o")
