"""redact.py — the one rule this tool can't get wrong.

This app finds secrets. That means at some point it holds one in memory,
and everything downstream of that moment — the terminal, the GUI, the
history database, a screenshot someone pastes into a bug report — is a
place a secret can escape to. Nothing outside this module is allowed to
put raw matched material into any of them.

Masking keeps a few characters at each end because that's what makes a
finding actionable: enough to recognise *which* key it is when you go to
rotate it, never enough to use it. Anything short enough that keeping
those ends would give away a meaningful fraction of it gets covered
completely instead.
"""

REDACT_CHAR = "█"

_MAX_BARS = 12
_KEEP = 4


def mask(secret, keep=_KEEP):
    """Return a display-safe form of `secret`. Never returns it intact."""
    s = "" if secret is None else str(secret)
    if not s:
        return ""
    # Below this length, showing `keep` at each end would reveal most of it.
    if len(s) <= keep * 3:
        return REDACT_CHAR * min(len(s), _MAX_BARS)
    hidden = min(len(s) - keep * 2, _MAX_BARS)
    return f"{s[:keep]}{REDACT_CHAR * hidden}{s[-keep:]}"


def mask_line(line, secret, keep=_KEEP):
    """Mask `secret` where it appears inside a surrounding line, so a finding
    can show context (`export AWS_KEY=AKIA████████abcd`) without the value.
    The line itself is truncated — a long line can carry a second secret this
    rule didn't match, and shipping the untouched remainder would leak it."""
    text = (line or "").strip()
    if secret and secret in text:
        text = text.replace(secret, mask(secret, keep))
    if len(text) > 120:
        text = text[:117] + "..."
    return text
