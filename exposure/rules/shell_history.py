"""shell_history.py — secrets typed on a command line and kept forever.

This is its own detector rather than part of tokens.py because the fix is
different in a way that matters. Rotating the credential isn't enough: the
history file keeps the old value until someone edits it out, and the next
person to read the file learns both the secret *and* exactly which command
it belonged to. Shell history is also one of the first things anything
poking around a home directory reads, precisely because people paste
credentials into terminals and forget.

Beyond vendor-prefixed tokens, this looks for the handful of command shapes
that put a secret on the command line as an argument — `mysql -pHUNTER2`,
`curl -u user:pass`, `export SOME_TOKEN=...`. Those are `possible`, not
`likely`: `export EDITOR=vim` matches the same shape as `export
API_TOKEN=real-secret` and there's no way to tell from the text alone which
one holds something worth stealing, so the name has to carry the signal.
"""
import re

from ..redact import mask, mask_line
from .base import (CONFIDENCE_LIKELY, CONFIDENCE_POSSIBLE, Detector, Finding,
                   Rule, mode_str, too_open)
from .tokens import find_tokens

HISTORY_NAMES = {".bash_history", ".zsh_history", ".sh_history", ".history",
                 ".python_history", ".psql_history", ".mysql_history", ".node_repl_history"}

# Only names that plainly describe a secret. Something like `export PATH=...`
# or `export EDITOR=vim` must not match, or every history file on earth fires.
_SECRET_NAME = r"[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*"

_COMMAND_SHAPES = [
    (re.compile(rf"\b(?:export|set)\s+({_SECRET_NAME})\s*=\s*(\S+)"),
     "a secret assigned to {name} on the command line"),
    (re.compile(r"\bmysql\b[^\n]*\s-p(\S+)"),
     "a MySQL password passed as -p on the command line"),
    (re.compile(r"\bcurl\b[^\n]*\s-u\s+(\S+:\S+)"),
     "credentials passed to curl with -u"),
    (re.compile(r"\bcurl\b[^\n]*[Aa]uthorization:\s*(?:Bearer|Basic)\s+(\S+)"),
     "an Authorization header passed to curl"),
]

_MAX_FINDINGS = 20


def find_command_secrets(text):
    """[(description, matched_value, line_no), ...] — command shapes that put
    a credential in argv, where the variable name says it's a credential."""
    if not text:
        return []
    found = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern, template in _COMMAND_SHAPES:
            m = pattern.search(line)
            if not m:
                continue
            groups = m.groups()
            name = groups[0] if len(groups) > 1 else ""
            value = groups[-1]
            found.append((template.format(name=name), value, line_no, line))
            if len(found) >= _MAX_FINDINGS:
                return found
    return found


def examine(facts):
    if facts.name not in HISTORY_NAMES:
        return []

    findings = []

    if too_open(facts.mode):
        findings.append(Finding(
            rule_id="shell-history-permissions",
            severity="medium",
            display_path=facts.display_path,
            detail=(f"Shell history is readable by other accounts on this machine "
                    f"(mode {mode_str(facts.mode)})."),
            evidence=mode_str(facts.mode),
        ))

    if facts.text is None:
        return findings

    for slug, label, severity, value, line_no in find_tokens(facts.text):
        findings.append(Finding(
            rule_id="secret-in-shell-history",
            severity=severity,
            display_path=facts.display_path,
            detail=f"{label} recorded in shell history.",
            confidence=CONFIDENCE_LIKELY,
            evidence=mask(value),
            line_no=line_no,
        ))

    for description, value, line_no, line in find_command_secrets(facts.text):
        findings.append(Finding(
            rule_id="secret-in-shell-history",
            severity="medium",
            display_path=facts.display_path,
            detail=description[0].upper() + description[1:] + ".",
            confidence=CONFIDENCE_POSSIBLE,
            evidence=mask_line(line, value),
            line_no=line_no,
        ))

    return findings


def _remediate_history_permissions(finding):
    return ("Restrict it to your account only:\n\n"
            f"    chmod 600 {finding.display_path}\n\n"
            "Worth doing regardless of whether anything sensitive is in it today — history "
            "accumulates, and you won't be thinking about file modes the day you paste a "
            "token into a terminal.")


def _remediate_secret_in_history(finding):
    line_hint = f" (around line {finding.line_no})" if finding.line_no else ""
    return ("Rotate the credential first — it's been sitting in a plaintext file, and you "
            "can't know what has read it.\n\n"
            f"Then remove the line{line_hint} from {finding.display_path}. Your shell keeps "
            "history in memory too, so edit the file and start a fresh shell rather than "
            "editing and continuing in the same one:\n\n"
            f"    ${{EDITOR:-nano}} {finding.display_path}\n\n"
            "To avoid the next one: a command starting with a space isn't recorded, as long "
            "as your shell is configured for it.\n\n"
            "    zsh:  setopt HIST_IGNORE_SPACE\n"
            "    bash: HISTCONTROL=ignorespace\n\n"
            "Better still, read secrets from a file or your keychain so they never appear "
            "in argv at all — on a shared or multi-user box, another account can see the "
            "full command line of a running process.")


DETECTOR = Detector(id="shell-history", examine=examine, needs_text=True)

RULES = [
    Rule(
        id="shell-history-permissions",
        title="Shell history readable by others",
        rationale="Command history is a running record of what you do on this machine, and "
                 "one of the first files anything looking for credentials will read.",
        severity="medium",
        remediation=_remediate_history_permissions,
    ),
    Rule(
        id="secret-in-shell-history",
        title="Secret recorded in shell history",
        rationale="A credential typed on a command line is written to disk in plaintext and "
                 "kept indefinitely, long after whatever you were doing with it is done.",
        severity="high",
        remediation=_remediate_secret_in_history,
    ),
]
