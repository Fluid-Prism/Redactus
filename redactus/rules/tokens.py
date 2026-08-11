"""tokens.py — API tokens sitting in files that aren't meant to hold them.

Every pattern here is a vendor-defined prefix with a fixed shape: `AKIA`
followed by exactly 16 uppercase-alphanumerics is an AWS access key ID and
essentially nothing else. That constraint is the whole design. The obvious
alternative — flagging any long high-entropy string — finds far more, and
almost all of it is git hashes, base64 images, minified JavaScript and UUIDs.
A scanner that cries wolf on a hundred of those teaches you to skim past the
one real finding, which leaves you worse off than not scanning.

So: no entropy scoring, no "this looks secret-ish". If a match here fires,
a specific company issued a specific credential in that exact format, and
the fix is to go rotate it there. False positives are still possible (a
token in documentation, a deliberately-revoked example), which is why these
are `likely` rather than `certain`.
"""
import re

from ..redact import mask
from .base import CONFIDENCE_LIKELY, CONFIDENCE_POSSIBLE, Detector, Finding, Rule

# (slug, pattern, label, severity, where to rotate it)
_TOKEN_SPECS = [
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b", "AWS long-lived access key ID", "high",
     "IAM → Users → Security credentials. Delete the key, then `aws configure sso` for "
     "short-lived sessions instead of minting another permanent one."),
    ("github-pat", r"\bghp_[A-Za-z0-9]{36}\b", "GitHub personal access token", "high",
     "github.com/settings/tokens — revoke it there, then reissue with an expiry set."),
    ("github-pat-fine", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", "GitHub fine-grained token", "high",
     "github.com/settings/tokens — revoke it there, then reissue with an expiry set."),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token", "high",
     "api.slack.com/apps → your app → OAuth & Permissions → revoke and reinstall."),
    ("stripe-live", r"\bsk_live_[A-Za-z0-9]{16,}\b", "Stripe live secret key", "critical",
     "dashboard.stripe.com/apikeys — roll it immediately. A live Stripe secret key can "
     "move real money."),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key", "medium",
     "console.cloud.google.com → APIs & Services → Credentials. Regenerate, and add an "
     "application restriction while you're there."),
    ("openai-key", r"\bsk-[A-Za-z0-9]{32,}\b", "OpenAI-style API key", "high",
     "platform.openai.com/api-keys — revoke and reissue."),
    ("slack-webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/+_-]{20,}",
     "Slack incoming webhook URL", "medium",
     "Anyone with the URL can post to that channel. Regenerate it in the Slack app config."),
]

_COMPILED = [(slug, re.compile(pattern), label, severity)
             for slug, pattern, label, severity, _ in _TOKEN_SPECS]

_ROTATION_HELP = {slug: help_text for slug, _, _, _, help_text in _TOKEN_SPECS}

# Shell histories get their own detector, with its own remediation — a secret
# in a history file needs the history cleaned too, not just the token rotated.
_HISTORY_NAMES = {".bash_history", ".zsh_history", ".sh_history", ".history",
                  ".python_history", ".psql_history", ".mysql_history", ".node_repl_history"}

_MAX_FINDINGS_PER_FILE = 25

# Values that are documentation rather than credentials. `AKIAIOSFODNN7EXAMPLE`
# is AWS's own key from their docs and appears in a large fraction of every
# tutorial ever written about AWS; treating it as a live credential is how a
# scanner ends up flagging half the Markdown on a developer's disk.
_PLACEHOLDER_MARKERS = (
    "example", "placeholder", "your", "yours", "changeme", "change_me",
    "dummy", "redacted", "xxxx", "notarealkey", "insert", "replaceme",
)


def is_placeholder(value):
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    # Runs like AKIA0000000000000000 or ghp_aaaa... are fillers, not keys.
    body = lowered[4:] if len(lowered) > 8 else lowered
    return len(set(body)) <= 2


# Paths whose whole purpose is holding fake credentials. Findings here are
# demoted rather than dropped: a real key does sometimes get committed into a
# test fixture, and silently hiding that would be the worse mistake.
_TEST_PATH_MARKERS = ("/test", "/tests/", "/fixtures/", "/samples/", "/sample/",
                      "/mocks/", "/mock/", "/testdata/", "/spec/", "/__tests__/",
                      "/examples/", "/demo/")


def looks_like_test_material(path):
    lowered = path.lower().replace("\\", "/")
    return any(marker in lowered for marker in _TEST_PATH_MARKERS)


def find_tokens(text):
    """[(slug, label, severity, matched_value, line_no), ...] for one file.

    Deliberately capped: a fixture file or a checked-in test corpus can hold
    hundreds of the same shape, and a report that's 400 rows of one file is
    a report nobody reads.
    """
    if not text:
        return []
    found = []
    seen = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        for slug, pattern, label, severity in _COMPILED:
            for match in pattern.finditer(line):
                value = match.group(0)
                if value in seen or is_placeholder(value):
                    continue
                seen.add(value)
                found.append((slug, label, severity, value, line_no))
                if len(found) >= _MAX_FINDINGS_PER_FILE:
                    return found
    return found


def examine(facts):
    if facts.name in _HISTORY_NAMES or facts.text is None:
        return []
    in_test_material = looks_like_test_material(facts.path)
    findings = []
    for slug, label, severity, value, line_no in find_tokens(facts.text):
        detail = f"{label} found in this file."
        confidence = CONFIDENCE_LIKELY
        if in_test_material:
            detail += " This looks like test or sample data, so it may be deliberate."
            confidence = CONFIDENCE_POSSIBLE
            severity = "low"
        findings.append(Finding(
            rule_id="exposed-token-" + slug,
            severity=severity,
            display_path=facts.display_path,
            detail=detail,
            confidence=confidence,
            evidence=mask(value),
            line_no=line_no,
        ))
    return findings


def _make_remediation(slug):
    def remediate(finding):
        return ("Treat this one as already leaked and rotate it — you can't know what has "
                "read the file since it was written.\n\n"
                f"  1. {_ROTATION_HELP[slug]}\n"
                f"  2. Remove it from {finding.display_path}\n"
                "  3. If that file is in a git repo, rotating is not optional: the value "
                "stays in the history even after you delete the line.\n\n"
                "Then put the replacement somewhere that isn't a file in your home "
                "directory — your OS keychain, or an environment variable set by your "
                "shell profile with mode 600.")
    return remediate


DETECTOR = Detector(id="tokens", examine=examine, needs_text=True)

RULES = [
    Rule(
        id="exposed-token-" + slug,
        title=label,
        rationale=f"A {label} in a file on disk is a working credential to anything that "
                 "reads it, and it keeps working until someone revokes it.",
        severity=severity,
        remediation=_make_remediation(slug),
    )
    for slug, _, label, severity in _COMPILED
]
