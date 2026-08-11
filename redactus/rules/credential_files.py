"""credential_files.py — files whose entire job is holding a credential.

These aren't heuristic finds. `.git-credentials` exists to store
`https://user:password@host` in plaintext; `.netrc` stores a password per
machine in plaintext; `.pgpass` the same for Postgres. Their presence isn't
a bug — plenty of tooling needs them — but each one is a file where reading
it is the whole attack, so the permission bits carry all the weight.

Two findings come out of this, for different reasons. That a file is
readable by other local accounts is a `certain` fact about mode bits. That
it currently *contains* a live credential is `likely`: the format matched,
but a `.netrc` can hold a `default` entry with nothing sensitive in it, and
an `.npmrc` can be entirely registry configuration.

Nothing here parses the credential itself. Recognising that a line looks
like `password ...` is enough to report it; extracting the value would mean
carrying it around for no benefit to the person reading the report.
"""
import re

from .base import (CONFIDENCE_CERTAIN, CONFIDENCE_LIKELY, Detector, Finding,
                   Rule, mode_str, too_open)

# basename -> (label, compiled content pattern or None, severity when content matches)
_CREDENTIAL_FILES = {
    ".netrc": ("netrc", re.compile(r"\bpassword\s+\S+"), "high"),
    "_netrc": ("netrc", re.compile(r"\bpassword\s+\S+"), "high"),
    ".git-credentials": ("git credential store",
                         re.compile(r"://[^/\s:]+:[^/\s@]+@"), "high"),
    ".pgpass": ("Postgres password file", re.compile(r"(?m)^[^#\n]*:[^:\n]*:[^:\n]*:[^:\n]*:\S+"), "high"),
    ".npmrc": ("npm config", re.compile(r"(?m)^\s*(//.*:)?_(auth|authToken|password)\s*="), "high"),
    ".pypirc": ("PyPI config", re.compile(r"(?m)^\s*password\s*[:=]"), "high"),
    ".env": ("environment file", None, "medium"),
}

# Matched on the path tail instead, since these basenames alone are ambiguous —
# plenty of things are called `config` or `credentials`.
_CREDENTIAL_PATHS = {
    ".aws/credentials": ("AWS credentials", re.compile(r"(?m)^\s*aws_secret_access_key\s*="), "high"),
    ".docker/config.json": ("Docker registry auth", re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]+"'), "medium"),
    ".kube/config": ("Kubernetes config", re.compile(r"(?m)^\s*(client-key-data|token):"), "medium"),
}


# `.env.example` exists to be committed and shared — it holds the *names* of
# the variables with placeholder values, which is the opposite of a secret.
# Flagging these was the single largest source of noise on a real machine.
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")


def _is_template(name):
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in _TEMPLATE_SUFFIXES)


def _match_target(facts):
    """(label, pattern, severity) for a recognised credential file, else None."""
    if _is_template(facts.name):
        return None
    if facts.name in _CREDENTIAL_FILES:
        return _CREDENTIAL_FILES[facts.name]
    # `.env.production` and friends are the same kind of file as `.env`.
    if facts.name.startswith(".env."):
        return _CREDENTIAL_FILES[".env"]
    normalised = facts.path.replace("\\", "/")
    for tail, value in _CREDENTIAL_PATHS.items():
        if normalised.endswith("/" + tail):
            return value
    return None


def examine(facts):
    target = _match_target(facts)
    if target is None:
        return []
    label, pattern, content_severity = target

    findings = []

    if too_open(facts.mode):
        findings.append(Finding(
            rule_id="credential-file-permissions",
            severity="high",
            display_path=facts.display_path,
            detail=(f"{label} is readable by other accounts on this machine "
                    f"(mode {mode_str(facts.mode)})."),
            confidence=CONFIDENCE_CERTAIN,
            evidence=mode_str(facts.mode),
        ))

    # No text means the scanner couldn't read it (oversized, binary, denied) —
    # absence of a content match then says nothing, so don't claim it's clean.
    if facts.text is not None and pattern is not None and pattern.search(facts.text):
        findings.append(Finding(
            rule_id="plaintext-credential-store",
            severity=content_severity,
            display_path=facts.display_path,
            detail=f"{label} holds at least one credential in plaintext.",
            confidence=CONFIDENCE_LIKELY,
        ))

    return findings


def _remediate_permissions(finding):
    return ("Restrict it to your account only:\n\n"
            f"    chmod 600 {finding.display_path}\n\n"
            "If other accounts on this machine could already read it, rotate whatever it "
            "holds as well — fixing the mode now doesn't un-read it.")


def _remediate_plaintext(finding):
    return ("Nothing is broken here, but this file is plaintext by design, so it's worth "
            "moving off it where a better option exists:\n\n"
            "  • git      use a credential helper that stores in your OS keychain\n"
            "             (macOS: git config --global credential.helper osxkeychain)\n"
            "  • AWS      replace long-lived keys with short-lived SSO sessions\n"
            "             (aws configure sso)\n"
            "  • npm/PyPI scope tokens to publish-only, and set an expiry\n"
            "  • .netrc   check whether the tool reading it supports a keychain instead\n\n"
            "Where none of those apply, keeping it at mode 600 and rotating on a schedule "
            "is a reasonable place to stop.")


DETECTOR = Detector(id="credential-files", examine=examine, needs_text=True)

RULES = [
    Rule(
        id="credential-file-permissions",
        title="Credential file readable by others",
        rationale="These files hold working credentials in plaintext, so reading one is the "
                 "whole attack — no cracking, no escalation, nothing else needed.",
        severity="high",
        remediation=_remediate_permissions,
    ),
    Rule(
        id="plaintext-credential-store",
        title="Credential stored in plaintext",
        rationale="Anything that can read one file as you — a backup, a sync client, a "
                 "malicious dependency — gets a usable credential rather than a hashed or "
                 "encrypted blob it still has to break.",
        severity="high",
        remediation=_remediate_plaintext,
    ),
]
