# Redactus

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Finds the credentials sitting unprotected on your disk — private keys other
accounts can read, keys with no passphrase, plaintext credential stores, and
API tokens in files that were never meant to hold them. It reads local files
and does nothing else.

It's the third of three, and the one about your **data**:

| | Question it answers |
| --- | --- |
| [Kevscope](https://github.com/Fluid-Prism/Kevscope) | What vulnerable **software** is installed here? |
| [VigilvCheck](https://github.com/Fluid-Prism/VigilvCheck) | Is this machine **configured** to resist an attack? |
| **Redactus** | What's sitting on this **disk** that's immediately useful to whoever gets it? |

![Redactus](./docs/preview.png)

## Air-gapped, and not as a feature

There is no network code in this package. Not disabled, not opt-out — none:
no `requests`, no `urllib`, no `socket`, nothing to configure and no telemetry
to turn off. A tool that reads every file in your home directory looking for
secrets and *then* talks to a server is a worse version of the problem it
claims to solve, so this one can't.

That also makes it usable in the places this kind of check matters most:
air-gapped machines, regulated environments, and anywhere else you wouldn't
paste a file into a web scanner to see if it contains a key.

## What it looks for

| Finding | Confidence | How it's decided |
| --- | --- | --- |
| Private key readable by other accounts | certain | permission bits |
| Private key with no passphrase | certain | parsed: OpenSSH cipher field, PKCS#8 header, PEM `Proc-Type` |
| Credential file readable by other accounts | certain | permission bits |
| Plaintext credential store | likely | `.netrc`, `.git-credentials`, `.pgpass`, `.npmrc`, `.pypirc`, AWS/Docker/Kubernetes configs |
| API token in a file | likely | vendor-defined prefixes: AWS, GitHub, Slack, Stripe, Google, OpenAI |
| Secret in shell history | likely / possible | tokens, plus command shapes like `mysql -p…` and `curl -u …` |

**Confidence is reported, not implied.** A world-readable private key is a
fact about mode bits. A token that matches a vendor prefix is a strong guess.
Those are shown as different things, because a tool that presents them
identically is one you learn to stop reading.

## No entropy scoring, on purpose

The usual approach is to flag any long high-entropy string. It finds more, and
almost all of what it finds is git hashes, UUIDs, base64 images and minified
JavaScript. A scanner that cries wolf a hundred times teaches you to skim past
the one real finding, which leaves you worse off than not scanning at all.

So every rule here is either a **fact** (permission bits, a parsed key format)
or a **vendor-defined prefix** — `AKIA` plus exactly 16 uppercase alphanumerics
is an AWS access key ID and essentially nothing else. Documentation
placeholders like AWS's own `AKIAIOSFODNN7EXAMPLE` are excluded, and findings
in `tests/`, `fixtures/` and `samples/` directories are demoted rather than
dropped — a real key does occasionally get committed into a test fixture, and
silently hiding that would be the worse mistake.

This is the main trade-off in the tool: it will miss a homegrown or
internal-format credential that no pattern here knows about. It's built to be
worth reading rather than to be exhaustive.

## Run it

```bash
pip install -r requirements.txt      # PySide6 (Qt) for the GUI; the engine is stdlib only
# or: pip install -e .

python3 -m redactus                  # desktop app
python3 -m redactus.audit            # headless CLI
python3 -m redactus.audit --json     # same data, for scripting
python3 -m redactus.selftest         # offline tests
```

Useful flags:

```
--path DIR          scan somewhere other than your home directory (repeatable)
--time-budget SECS  stop after this long (default 90)
--include-caches    also scan package caches, editor extensions and tool state
--forget            delete the local history database
```

## What it doesn't do

**It never changes anything.** No file is edited, moved, quarantined or
deleted. Every fix is a command you run yourself, with an explanation of what
it does and why. A tool that reads your whole home directory has enough
privilege already without also being able to write to it.

**It never shows you the secret.** Findings display a masked form
(`AKIA████████RTBV`) with a few characters at each end — enough to recognise
which credential it is when you go to rotate it, never enough to use. The
masking is enforced in one module that everything else goes through, and
there's a test that plants real-shaped secrets, renders every output surface,
and fails if a single raw value survives to any of them.

**It doesn't read your files anywhere but here.** See above.

## The history database is sensitive

A list of every place on this machine holding an exposed credential is exactly
the file an attacker would most like to find, so:

- It lives in your per-user data directory, not next to the package —
  `~/Library/Application Support/Redactus` on macOS,
  `$XDG_DATA_HOME/redactus` on Linux.
- The directory and file are created at `0700` / `0600` *at creation*, rather
  than made private with a follow-up `chmod` — that ordering leaves a window
  where another local account can open the file.
- **Masked evidence is never written to it.** It exists in memory for the
  report you're looking at and is discarded.
- `--forget` (or "Forget history" in the app) deletes it outright.

## Coverage is reported honestly

A scan can be incomplete for boring reasons: files too large to read, files it
lacks permission to open, or a time budget that ran out on a very full disk.
When any of that happens it's stated next to the results, in both the CLI and
the app.

"Nothing found in what could be read" is a different claim from "nothing
found," and only the first one is ever true here.

Package caches, editor extensions and tool state directories (`node_modules`,
`.npm`, `.cache`, `.vscode`, and similar) are skipped by default. A key inside
a dependency's test fixtures isn't yours to rotate, and on a real machine
those directories produced dozens of unactionable findings that buried the
handful of real ones. `--include-caches` scans them anyway.

## Files

```
redactus/
  gui.py          desktop app         (python3 -m redactus)
  audit.py        headless CLI        (python3 -m redactus.audit)
  scanner.py      the walk: bounded, symlink-safe, honest about what it skipped
  redact.py       masking; the one thing this tool cannot get wrong
  scoring.py      ranking and grouping
  store.py        SQLite history, deliberately minimal about what it keeps
  selftest.py     offline tests, synthetic fixtures only
  rules/
    base.py             Detector / Rule / Finding / FileFacts
    private_keys.py     permissions + passphrase state
    credential_files.py .netrc, .git-credentials, cloud configs, .env
    tokens.py           vendor-prefixed API tokens
    shell_history.py    secrets typed on a command line
```

## Adding a rule

A **detector** is a pure function from `FileFacts` (path, mode, size, text) to
a list of `Finding`s. It never opens a file — the scanner does that once and
hands the result to every detector, which is what makes the interesting part
testable against synthetic input with no filesystem involved.

A **rule** describes one kind of finding: title, rationale, severity, and a
`remediation(finding)` that returns plain-English instructions. One detector
often produces several kinds, so the two aren't one-to-one.

Write the module, add it to both lists in `rules/__init__.py`, and add cases
to `selftest.py` — including at least one that proves it *doesn't* fire on
ordinary content. False positives are the failure mode that matters here.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup and code style, and
[SECURITY.md](./SECURITY.md) to report a vulnerability.

## Roadmap

- GPG secret keyrings, and `age`/`sops` identity files.
- Optional entropy pass, off by default, clearly labelled `possible`, for
  people who want recall over precision.
- Detect credentials committed to a local git repo's history, not just its
  working tree — deleting the line doesn't remove the value.
- Windows support: the scanner is portable, but the permission model that most
  findings rest on is not.
