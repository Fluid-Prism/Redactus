"""redactus — find the credentials sitting unprotected on this machine.

Answers one question: what's on this disk that would immediately be useful
to whoever got hold of it. Private keys other accounts can read, keys with
no passphrase, plaintext credential stores, API tokens in .env files and
shell history — all found by reading local files and nothing else.

Nothing is uploaded, nothing is looked up, no network code exists in this
package at all. That isn't a privacy feature bolted on; it's the only way a
tool like this makes sense. Something that scans your home directory for
secrets and then talks to a server is a worse version of the problem it
claims to solve.

Read-only: it never edits, moves, quarantines or deletes anything it finds.
Every fix is a command you run yourself, with an explanation of what it does.

Runs as a CLI (`python3 -m redactus.audit`) or a desktop app
(`python3 -m redactus`).
"""
import os
import sys


def warn_if_root():
    """Running as root makes this tool worse, not better: it would read every
    account's files and report them as findings you can't act on, while
    widening the blast radius of any bug to the whole system."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Warning: running as root. This tool is meant to audit your own account — "
              "as root it will surface other users' files as your findings, and it needs "
              "no elevation to do its job.", file=sys.stderr)
