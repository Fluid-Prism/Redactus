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

# Everything C0 except tab, plus DEL and the C1 range. ESC (0x1B) is the one
# that matters: it starts the sequences a terminal acts on.
_CONTROL = {c: "�" for c in list(range(0x00, 0x09)) + list(range(0x0A, 0x20))
            + [0x7F] + list(range(0x80, 0xA0))}


def sanitize(text):
    """Strip terminal control characters out of anything that came from disk.

    File names and file contents are attacker-influenced — you clone a repo,
    unpack an archive, or something writes into your home directory — and both
    end up printed to a terminal by the CLI. A name carrying ANSI escapes can
    move the cursor, clear the screen, or repaint lines that were already
    printed, which in a security report means hiding a finding or forging a
    reassuring one. The GUI escapes HTML at its own boundary; this closes the
    same hole for the terminal, at the point the data enters the program so
    every surface benefits rather than each one remembering to.
    """
    if not text:
        return text
    return str(text).translate(_CONTROL)


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


# There is deliberately no "mask this secret inside its surrounding line"
# helper here. One existed, and it was wrong in a way that's easy to miss:
# masking the value you matched does not make the rest of the line safe.
# `export AWS_KEY=… GITHUB=ghp_…` matches once and prints the second
# credential in full. Findings now rebuild context from a matched variable
# name plus a masked value instead of quoting the file, so nothing verbatim
# from disk reaches a display. If a future rule needs context, build it the
# same way rather than reintroducing this.
