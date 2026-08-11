# Contributing to Exposure Auditor

## Dev setup

```bash
git clone <this repo>
cd exposure-auditor
pip install -r requirements.txt

python3 -m exposure                  # desktop app
python3 -m exposure.audit            # headless CLI
python3 -m exposure.selftest         # offline tests, run these before every PR
```

## Tests

`exposure/selftest.py` is fully offline: no network, and no reliance on what's
actually on your machine. Every fixture is built at runtime.

The one to understand before changing anything is
`check_no_raw_secret_reaches_any_output`. It plants real-shaped secrets in a
temporary directory, runs the whole pipeline, renders every output surface,
and fails if a single raw value survives to any of them. If that test fails,
nothing else about the tool matters.

**Every new rule needs a negative case.** False positives are the failure mode
that kills a tool like this, so a rule that only proves it fires on a real
secret is half-tested. Add ordinary content that must *not* match.

## Code style

Same discipline as its two siblings, [Kevscope](https://github.com/Fluid-Prism/Kevscope)
and [VigilvCheck](https://github.com/Fluid-Prism/VigilvCheck):

- Don't comment what the code does — good names do that. Comment the
  non-obvious why: a format quirk, an invariant, the real-world false positive
  a check exists to prevent.
- Detectors stay pure. They take `FileFacts` and return findings; they don't
  open files, shell out, or decide what to scan. The scanner owns all I/O.
- Nothing outside `redact.py` decides how a secret is displayed.
- State confidence honestly. `certain`, `likely` and `possible` mean different
  things, and collapsing them for a tidier report is exactly the false
  confidence this tool exists to avoid.
- No new runtime dependencies in the engine without a strong reason. Code that
  reads every file in someone's home directory should have as little
  third-party surface as possible.

## Pull requests

Keep them scoped to one thing and say why in the description.

If you add a rule, say in the PR whether you ran it against a real machine and
what the false-positive rate looked like. "Found 3 real things and 40 fixtures
from dependencies" is useful information and has changed the design here
before — the cache-directory skip list and the placeholder filter both exist
because a real run produced 95 findings of which almost none were actionable.

Don't add auto-remediation. Read-only is a deliberate line, not a missing
feature: this tool already reads everything you own, and giving it write
access to fix things is a much larger promise than it currently makes.
