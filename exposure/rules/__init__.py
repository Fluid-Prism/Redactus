"""The rule registry.

Detectors run against every file the scanner reads; rules describe the
kinds of finding they can produce, and are looked up by id when a report
needs a title, a rationale, or a fix. Adding a rule means writing one
module and adding it to both lists here — there's no plugin discovery,
because importing whatever happens to be in a directory is a strange thing
for a security tool to do.
"""
from . import credential_files, private_keys, shell_history, tokens

ALL_DETECTORS = [
    private_keys.DETECTOR,
    credential_files.DETECTOR,
    shell_history.DETECTOR,
    tokens.DETECTOR,
]

ALL_RULES = (private_keys.RULES + credential_files.RULES
             + shell_history.RULES + tokens.RULES)

RULES_BY_ID = {rule.id: rule for rule in ALL_RULES}
