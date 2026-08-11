"""selftest.py — offline checks. No network, no reliance on this machine's
actual contents; every fixture is synthetic and built at runtime.

    python3 -m exposure.selftest

The detectors are pure functions over FileFacts, so almost all of this runs
without touching a disk. The exceptions are the scanner tests, which build a
throwaway tree under tempfile to exercise symlink handling and the size
ceiling, and the leak test, which is the one that matters most: it plants
known secrets, runs the whole pipeline, renders every output surface, and
asserts none of the raw values survive to any of them.
"""
import base64
import contextlib
import io
import os
import tempfile

from .redact import REDACT_CHAR, mask, mask_line
from .rules import ALL_DETECTORS, ALL_RULES, RULES_BY_ID
from .rules import credential_files, private_keys, shell_history, tokens
from .rules.base import (CONFIDENCE_CERTAIN, CONFIDENCE_LIKELY, SEVERITY_WEIGHT,
                         FileFacts, Finding)
from .scanner import scan
from .scoring import by_severity, group_by_file, ranked, weighted_total, worst_severity


def _facts(name, text=None, mode=0o600, path=None):
    path = path or f"/home/someone/{name}"
    return FileFacts(path=path, name=name, mode=mode, size=len(text or ""),
                     display_path="~/" + name, text=text)


# Fixture tokens must look like real credentials, not like documentation:
# anything containing "example" or a long filler run is now deliberately
# ignored by the scanner, so using AWS's docs key here would test nothing.
FAKE = {
    "aws": "AKIA" "2E4XZ7QPLMN3RTBV",
    "github": "ghp" "_9fK2mQ7xL4vB8nR3tY6wZ1sD5gHjC7bV2eA4",
    "github_fine": "github" "_pat_9fK2mQ7xL4vB8nR3tY6wZ1sD5gHjC7bV2eA4uP8kN6mT3rW7yXqL9fK2mQ7xL4",
    "slack": "xoxb" "-274839201847-hTq9Zm4KpX2vLnR8",
    "stripe": "sk" "_live_51HqZ8mKp3XvNb7RtY2wLdG9f",
    "google": "AIza" "SyD3xK9mQ7pL2vBn8RtY4wZ6sHjC1bV5eA0",
    "openai": "sk" "-proj7Hq9Zm4KpX2vLnR8tY6wZ1sD5gHjC7bV2eA4uP8k",
    "webhook": "https://hooks.slack.com/services/" "T7Hq9Zm4K/B2vLnR8tY/6wZ1sD5gHjC7bV2eA4uP8kN",
}


def _openssh_key(cipher):
    """A synthetic OpenSSH v1 key carrying `cipher` in the field the parser
    reads. 'none' is what OpenSSH writes when there's no passphrase."""
    body = (b"openssh-key-v1\x00" + len(cipher).to_bytes(4, "big")
            + cipher.encode() + b"\x00\x00\x00\x07ssh-rsa" + b"padding" * 8)
    encoded = base64.b64encode(body).decode()
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + encoded + "\n-----END OPENSSH PRIVATE KEY-----\n")


# ── redaction ────────────────────────────────────────────────────────────────

def check_mask_never_returns_the_secret():
    secrets = ["AKIAIOSFODNN7EXAMPLE", "ghp_" + "a" * 36, "short", "x", "",
               "a" * 200, "sk_live_" + "9" * 40]
    for secret in secrets:
        masked = mask(secret)
        assert secret == "" or masked != secret, f"mask() returned {secret!r} unchanged"
        if len(secret) > 12:
            assert secret not in masked, f"mask() leaked the full value of {secret!r}"
            assert REDACT_CHAR in masked, f"mask({secret!r}) produced no redaction"
    return len(secrets)


def check_short_secrets_are_fully_covered():
    # Keeping 4 chars at each end of a 10-char secret would show 80% of it.
    for secret in ("hunter2", "abcd1234", "12", "abcdefghijkl"):
        masked = mask(secret)
        assert set(masked) == {REDACT_CHAR}, f"mask({secret!r}) = {masked!r} exposed characters"
    return 4


def check_mask_line_keeps_context_and_truncates():
    line = "export API_TOKEN=" + "s" * 60
    masked = mask_line(line, "s" * 60)
    assert "export API_TOKEN=" in masked, "mask_line dropped the context that makes it useful"
    assert "s" * 60 not in masked, "mask_line leaked the secret"

    long_line = "a" * 400
    assert len(mask_line(long_line, "")) <= 120, "mask_line failed to truncate a long line"
    return 3


# ── private keys ─────────────────────────────────────────────────────────────

def check_openssh_cipher_parsing():
    assert private_keys.parse_openssh_cipher(_openssh_key("none")) == "none"
    assert private_keys.parse_openssh_cipher(_openssh_key("aes256-ctr")) == "aes256-ctr"
    assert private_keys.parse_openssh_cipher("not a key at all") is None
    assert private_keys.parse_openssh_cipher(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n!!!not base64!!!\n"
        "-----END OPENSSH PRIVATE KEY-----") is None
    return 4


def check_key_encryption_states():
    cases = [
        (_openssh_key("none"), "unencrypted"),
        (_openssh_key("aes256-ctr"), "encrypted"),
        ("-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc\n-----END ENCRYPTED PRIVATE KEY-----", "encrypted"),
        ("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "unencrypted"),
        ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nabc\n"
         "-----END RSA PRIVATE KEY-----", "encrypted"),
        ("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "unencrypted"),
        ("just some text", "unknown"),
        # A truncated OpenSSH body must not be called passphrase-less.
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nQQ==\n-----END OPENSSH PRIVATE KEY-----", "unknown"),
    ]
    for text, expected in cases:
        state, _ = private_keys.key_encryption(text)
        assert state == expected, f"key_encryption() = {state}, want {expected} for {text[:40]!r}"
    return len(cases)


def check_embedded_keys_are_not_key_files():
    """The regression that made the first real-machine run useless: a PEM
    block inside a minified bundle or a cache blob is a shipped test fixture,
    not the user's key. 95 findings on a real home directory were almost
    entirely this."""
    key = _openssh_key("none")

    bundle = "var x=1;" * 40000 + key + ";module.exports=x;"
    assert not private_keys.is_private_key(bundle, len(bundle)), \
        "a key embedded in a large JS bundle was treated as a key file"
    assert private_keys.examine(_facts("extension.js", bundle, mode=0o644)) == []

    # Truncated read of a huge file: text looks key-shaped, size says otherwise.
    assert not private_keys.is_private_key(key, size=5_000_000), \
        "size must override a truncated read that happens to look like a key"

    # A key file with a comment header in front is still a key file.
    with_header = "# my deploy key, generated 2024\n" + key
    assert private_keys.is_private_key(with_header, len(with_header))

    # Plain, unadorned key file: the case that must never regress.
    assert private_keys.is_private_key(key, len(key))
    return 5


def check_private_key_findings():
    open_unencrypted = private_keys.examine(_facts("id_rsa", _openssh_key("none"), mode=0o644))
    ids = {f.rule_id for f in open_unencrypted}
    assert ids == {"private-key-permissions", "private-key-no-passphrase"}, ids
    perms = [f for f in open_unencrypted if f.rule_id == "private-key-permissions"][0]
    assert perms.severity == "critical", "readable + no passphrase should be the worst case"

    locked = private_keys.examine(_facts("id_rsa", _openssh_key("aes256-ctr"), mode=0o600))
    assert locked == [], f"a 0600 encrypted key is not a finding, got {locked}"

    open_encrypted = private_keys.examine(_facts("id_rsa", _openssh_key("aes256-ctr"), mode=0o644))
    assert [f.rule_id for f in open_encrypted] == ["private-key-permissions"]
    assert open_encrypted[0].severity == "high", "encrypted key: bad perms, but not critical"

    # known_hosts sits in ~/.ssh and is not a key
    assert private_keys.examine(_facts("known_hosts", "github.com ssh-rsa AAAA", mode=0o644)) == []
    return 6


# ── credential files ─────────────────────────────────────────────────────────

def check_credential_file_detection():
    netrc = credential_files.examine(
        _facts(".netrc", "machine example.com login me password hunter2\n", mode=0o600))
    assert [f.rule_id for f in netrc] == ["plaintext-credential-store"]

    netrc_open = credential_files.examine(
        _facts(".netrc", "machine example.com login me password hunter2\n", mode=0o644))
    assert {f.rule_id for f in netrc_open} == {"credential-file-permissions",
                                              "plaintext-credential-store"}

    # A .netrc with no password line is configuration, not a credential store.
    assert credential_files.examine(_facts(".netrc", "machine example.com login me\n")) == []

    git_creds = credential_files.examine(
        _facts(".git-credentials", "https://user:ghp_secret@github.com\n"))
    assert [f.rule_id for f in git_creds] == ["plaintext-credential-store"]

    npmrc_plain = credential_files.examine(_facts(".npmrc", "registry=https://registry.npmjs.org/\n"))
    assert npmrc_plain == [], "an .npmrc with no token is just configuration"

    npmrc_token = credential_files.examine(
        _facts(".npmrc", "//registry.npmjs.org/:_authToken=abc123\n"))
    assert [f.rule_id for f in npmrc_token] == ["plaintext-credential-store"]
    return 6


def check_credential_path_matching():
    aws = credential_files.examine(FileFacts(
        path="/home/me/.aws/credentials", name="credentials", mode=0o600, size=10,
        display_path="~/.aws/credentials",
        text="[default]\naws_access_key_id = " + FAKE["aws"] + "\n"
             "aws_secret_access_key = wJalrXUtnFEMI\n"))
    assert [f.rule_id for f in aws] == ["plaintext-credential-store"]

    # A file merely *named* credentials elsewhere shouldn't match the AWS path rule.
    unrelated = credential_files.examine(FileFacts(
        path="/home/me/notes/credentials", name="credentials", mode=0o600, size=5,
        display_path="~/notes/credentials", text="nothing here"))
    assert unrelated == [], f"path rule matched too broadly: {unrelated}"

    # .env.production is the same kind of file as .env
    env = credential_files.examine(_facts(".env.production", "A=1\n", mode=0o644))
    assert [f.rule_id for f in env] == ["credential-file-permissions"]
    return 3


def check_unreadable_file_makes_no_content_claim():
    """text=None means the scanner couldn't read it. Absence of a content
    match then proves nothing and must not be reported as clean."""
    findings = credential_files.examine(_facts(".netrc", None, mode=0o644))
    assert [f.rule_id for f in findings] == ["credential-file-permissions"], findings
    return 1


# ── tokens ───────────────────────────────────────────────────────────────────

def check_token_patterns_match():
    samples = {
        FAKE["aws"]: "aws-access-key",
        FAKE["github"]: "github-pat",
        FAKE["github_fine"]: "github-pat-fine",
        FAKE["slack"]: "slack-token",
        FAKE["stripe"]: "stripe-live",
        FAKE["google"]: "google-api-key",
        FAKE["openai"]: "openai-key",
        FAKE["webhook"]: "slack-webhook",
    }
    for value, expected_slug in samples.items():
        found = tokens.find_tokens(f"SECRET={value}\n")
        assert found, f"no match for {expected_slug} sample"
        assert found[0][0] == expected_slug, f"{value[:12]} matched {found[0][0]}, want {expected_slug}"
    return len(samples)


def check_tokens_ignore_ordinary_noise():
    """The whole design rests on not firing here. Every string below is
    something a normal home directory is full of."""
    noise = [
        "d3486ae9136e7856bc42212385ea797094475802",              # git sha-1
        "550e8400-e29b-41d4-a716-446655440000",                   # uuid
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQV",  # base64 png
        "export PATH=/usr/local/bin:/usr/bin:/bin",
        "https://example.com/some/normal/path?query=value",
        "sha256-Ab3dEfGh1234567890abcdefghijklmnopqrstuvwxyz=",
        "The quick brown fox jumps over the lazy dog",
    ]
    for line in noise:
        found = tokens.find_tokens(line)
        assert not found, f"false positive on {line[:40]!r}: {found}"
    return len(noise)


def check_documentation_placeholders_are_ignored():
    """AWS's own docs key turns up in a large share of tutorials and READMEs.
    On a real machine this and `.env.example` were the top two noise sources."""
    placeholders = [
        "AKIAIOSFODNN7EXAMPLE",       # AWS's canonical documentation key
        "AKIAI44QH8DHBEXAMPLE",
        "AKIA0000000000000000",
        "ghp_" + "a" * 36,             # filler run
        "sk-" + "x" * 40,
    ]
    for value in placeholders:
        assert tokens.is_placeholder(value), f"{value} should be treated as a placeholder"
        assert not tokens.find_tokens(f"KEY={value}"), f"placeholder {value} produced a finding"

    # A realistic-looking key must still fire.
    real = "AKIA" "2E4XZ7QPLMN3RTBV"
    assert not tokens.is_placeholder(real)
    assert tokens.find_tokens(f"KEY={real}"), "a realistic key stopped matching"
    return len(placeholders) + 2


def check_template_files_are_not_credential_stores():
    """`.env.example` exists to be committed and shared. It was 14 of 84
    findings on a real home directory."""
    for name in (".env.example", ".env.sample", ".env.template", ".env.dist"):
        assert credential_files.examine(_facts(name, "API_KEY=\n", mode=0o644)) == [], \
            f"{name} is a template, not a credential store"
    # The real thing still fires.
    assert credential_files.examine(_facts(".env", "API_KEY=x\n", mode=0o644))
    return 5


def check_test_material_is_demoted_not_hidden():
    """A planted fixture shouldn't outrank a real leaked key — but a genuine
    key committed into a test directory is a real finding, so demote rather
    than drop."""
    real = "AKIA" "2E4XZ7QPLMN3RTBV"
    in_tests = FileFacts(path="/home/me/proj/tests/test_detector.py", name="test_detector.py",
                         mode=0o644, size=40, display_path="~/proj/tests/test_detector.py",
                         text=f"KEY = '{real}'\n")
    findings = tokens.examine(in_tests)
    assert findings, "test-directory findings must be demoted, not dropped"
    assert findings[0].severity == "low", findings[0].severity
    assert findings[0].confidence == "possible"

    in_source = FileFacts(path="/home/me/proj/app/settings.py", name="settings.py",
                          mode=0o644, size=40, display_path="~/proj/app/settings.py",
                          text=f"KEY = '{real}'\n")
    assert tokens.examine(in_source)[0].severity == "high", "real source must stay high"
    return 4


def check_token_findings_are_masked():
    secret = FAKE["aws"]
    findings = tokens.examine(_facts(".env", f"AWS_ACCESS_KEY_ID={secret}\n"))
    assert len(findings) == 1
    assert secret not in findings[0].evidence, "raw token in evidence"
    assert secret not in findings[0].detail, "raw token in detail"
    assert findings[0].line_no == 1
    return 3


def check_tokens_skip_shell_history():
    """History files are handled by their own detector, which gives different
    advice. Both firing would double-report the same line."""
    facts = _facts(".zsh_history", "export API_TOKEN=" + FAKE["github"] + "\n")
    assert tokens.examine(facts) == []
    return 1


# ── shell history ────────────────────────────────────────────────────────────

def check_shell_history_findings():
    hist = shell_history.examine(_facts(".zsh_history", "aws configure\nexport GITHUB_TOKEN="
                                        + FAKE["github"] + "\n", mode=0o600))
    assert any(f.rule_id == "secret-in-shell-history" for f in hist), hist

    perms = shell_history.examine(_facts(".bash_history", "ls -la\n", mode=0o644))
    assert [f.rule_id for f in perms] == ["shell-history-permissions"]
    return 2


def check_command_shapes():
    matched = shell_history.find_command_secrets("mysql -u root -phunter2 mydb")
    assert matched, "missed a password passed to mysql with -p"

    matched = shell_history.find_command_secrets("curl -u admin:s3cret https://example.com")
    assert matched, "missed credentials passed to curl with -u"

    # The name is what carries the signal — these must not fire.
    for benign in ("export PATH=/usr/bin", "export EDITOR=vim", "export LANG=en_US.UTF-8",
                   "set -euo pipefail"):
        assert not shell_history.find_command_secrets(benign), f"false positive on {benign!r}"
    return 6


# ── scoring ──────────────────────────────────────────────────────────────────

def _finding(severity, path="~/a", confidence=CONFIDENCE_CERTAIN, rule_id="r"):
    return Finding(rule_id=rule_id, severity=severity, display_path=path,
                   detail="d", confidence=confidence)


def check_severity_counts_include_zeroes():
    counts = by_severity([_finding("high"), _finding("high"), _finding("low")])
    assert counts == {"critical": 0, "high": 2, "medium": 0, "low": 1}, counts
    return 1


def check_ranking_orders_by_severity_then_confidence():
    findings = [
        _finding("high", "~/b", CONFIDENCE_LIKELY),
        _finding("critical", "~/c"),
        _finding("high", "~/a", CONFIDENCE_CERTAIN),
        _finding("low", "~/d"),
    ]
    order = [(f.severity, f.confidence) for f in ranked(findings)]
    assert order == [("critical", CONFIDENCE_CERTAIN), ("high", CONFIDENCE_CERTAIN),
                     ("high", CONFIDENCE_LIKELY), ("low", CONFIDENCE_CERTAIN)], order
    return 1


def check_worst_severity_and_weighting():
    assert worst_severity([]) is None, "no findings means no worst severity, not 'low'"
    assert worst_severity([_finding("low"), _finding("critical")]) == "critical"
    assert weighted_total([_finding("critical"), _finding("low")]) == (
        SEVERITY_WEIGHT["critical"] + SEVERITY_WEIGHT["low"])
    return 3


def check_grouping_puts_worst_file_first():
    findings = [_finding("low", "~/mild"), _finding("critical", "~/bad"),
                _finding("medium", "~/mild")]
    grouped = group_by_file(findings)
    assert grouped[0][0] == "~/bad", [path for path, _ in grouped]
    assert len(grouped) == 2
    return 2


# ── registry ─────────────────────────────────────────────────────────────────

def check_registry_integrity():
    ids = [rule.id for rule in ALL_RULES]
    assert len(ids) == len(set(ids)), f"duplicate rule ids: {ids}"
    for rule in ALL_RULES:
        assert rule.severity in SEVERITY_WEIGHT, f"{rule.id}: unknown severity {rule.severity}"
        assert rule.title and rule.rationale, f"{rule.id} is missing required text"
        assert callable(rule.remediation), f"{rule.id}.remediation isn't callable"
        text = rule.remediation(_finding("high", "~/example", rule_id=rule.id))
        assert text and len(text) > 20, f"{rule.id} has no usable remediation text"
    for detector in ALL_DETECTORS:
        assert callable(detector.examine), f"{detector.id}.examine isn't callable"
        assert detector.examine(_facts("nothing-special.txt", "ordinary content")) == []
    return len(ALL_RULES) + len(ALL_DETECTORS)


def check_every_emitted_rule_id_has_a_rule():
    """A finding whose rule_id isn't in the registry renders with no title and
    no fix — the detector and the rule list drifting apart is the likely cause,
    so pin it here rather than discovering it in the GUI."""
    emitted = set()
    for facts in [
        _facts("id_rsa", _openssh_key("none"), mode=0o644),
        _facts(".netrc", "machine x login y password z\n", mode=0o644),
        _facts(".env", "AWS=" + FAKE["aws"] + "\n", mode=0o644),
        _facts(".zsh_history", "export API_TOKEN=" + FAKE["github"] + "\n", mode=0o644),
    ]:
        for detector in ALL_DETECTORS:
            emitted.update(f.rule_id for f in detector.examine(facts))
    assert emitted, "fixtures produced no findings at all"
    missing = emitted - set(RULES_BY_ID)
    assert not missing, f"findings with no matching rule: {missing}"
    return len(emitted)


# ── scanner, against a real throwaway tree ───────────────────────────────────

def check_scanner_finds_and_bounds():
    with tempfile.TemporaryDirectory() as root:
        key_path = os.path.join(root, "id_rsa")
        with open(key_path, "w") as handle:
            handle.write(_openssh_key("none"))
        os.chmod(key_path, 0o644)

        # Skipped by name: proves SKIP_DIRS actually prunes.
        noisy = os.path.join(root, "node_modules")
        os.makedirs(noisy)
        with open(os.path.join(noisy, ".env"), "w") as handle:
            handle.write("AWS=" + FAKE["aws"] + "\n")

        report = scan(roots=[root], time_budget=30)
        paths = {f.display_path for f in report.findings}
        assert any(p.endswith("id_rsa") for p in paths), paths
        assert not any("node_modules" in p for p in paths), "SKIP_DIRS didn't prune"
        assert report.files_seen >= 1
    return 3


def check_scanner_does_not_follow_symlinks_out():
    with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as root:
        secret_path = os.path.join(outside, "id_rsa")
        with open(secret_path, "w") as handle:
            handle.write(_openssh_key("none"))
        os.chmod(secret_path, 0o644)

        try:
            os.symlink(outside, os.path.join(root, "escape"))
            os.symlink(secret_path, os.path.join(root, "escape_file"))
        except (OSError, NotImplementedError):
            return 0   # platform without symlink support; nothing to assert

        report = scan(roots=[root], time_budget=30)
        assert not report.findings, f"scan escaped its root via a symlink: {report.findings}"
    return 2


def check_scanner_reports_partial_coverage_honestly():
    with tempfile.TemporaryDirectory() as root:
        with open(os.path.join(root, "ordinary.txt"), "w") as handle:
            handle.write("nothing here")
        clean = scan(roots=[root], time_budget=30)
        assert not clean.findings
        assert not clean.coverage_is_partial, "a clean, complete scan claimed partial coverage"

        unreadable = os.path.join(root, "locked.env")
        with open(unreadable, "w") as handle:
            handle.write("AWS=" + FAKE["aws"] + "\n")
        os.chmod(unreadable, 0o000)
        if os.access(unreadable, os.R_OK):
            return 2   # running as root, or a filesystem ignoring modes
        report = scan(roots=[root], time_budget=30)
        assert report.skipped_unreadable >= 1, "an unreadable file wasn't counted"
        assert report.coverage_is_partial, "unreadable files must make coverage partial"
        os.chmod(unreadable, 0o600)
    return 4


# ── the invariant that matters most ──────────────────────────────────────────

def check_no_raw_secret_reaches_any_output():
    """Plant real-shaped secrets, run the whole pipeline, render every output
    surface this tool has, and assert not one raw value survives to any of
    them. If this test fails, nothing else about the tool matters."""
    from .audit import _print_report

    planted = {
        "aws": FAKE["aws"],
        "github": FAKE["github"],
        "stripe": FAKE["stripe"],
    }
    with tempfile.TemporaryDirectory() as root:
        env_path = os.path.join(root, ".env")
        with open(env_path, "w") as handle:
            for name, value in planted.items():
                handle.write(f"{name.upper()}_KEY={value}\n")
        os.chmod(env_path, 0o644)

        hist_path = os.path.join(root, ".zsh_history")
        with open(hist_path, "w") as handle:
            handle.write(f"export GITHUB_TOKEN={planted['github']}\n")

        key_path = os.path.join(root, "id_rsa")
        with open(key_path, "w") as handle:
            handle.write(_openssh_key("none"))
        os.chmod(key_path, 0o644)

        report = scan(roots=[root], time_budget=30)
        assert report.findings, "fixtures produced no findings; this test would pass vacuously"

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            _print_report(report)
        rendered = buffer.getvalue()

        # Every field that any surface (CLI, GUI, JSON) could display.
        rendered += "".join(f"{f.detail}{f.evidence}{f.display_path}{f.rule_id}"
                            for f in report.findings)
        for rule in ALL_RULES:
            for finding in report.findings:
                if finding.rule_id == rule.id:
                    rendered += rule.remediation(finding)

        for name, value in planted.items():
            assert value not in rendered, f"the raw {name} secret leaked into output"
    return len(planted)


def check_masked_evidence_is_never_persisted():
    """The history DB is a map of where this machine's secrets live. Evidence
    stays out of it by design; this pins that so a future column addition
    can't quietly reintroduce it."""
    from . import store
    with store.conn() as c:
        columns = {row[1] for row in c.execute("PRAGMA table_info(finding)")}
    assert "evidence" not in columns, "evidence is being persisted to the history database"
    assert {"rule_id", "severity", "path", "confidence"} <= columns, columns
    return 1


CHECKS = [
    ("redact: never returns the secret", check_mask_never_returns_the_secret),
    ("redact: short secrets fully covered", check_short_secrets_are_fully_covered),
    ("redact: line context kept, value masked", check_mask_line_keeps_context_and_truncates),
    ("keys: OpenSSH cipher parsing", check_openssh_cipher_parsing),
    ("keys: encryption state per format", check_key_encryption_states),
    ("keys: embedded keys are not key files", check_embedded_keys_are_not_key_files),
    ("keys: findings and severities", check_private_key_findings),
    ("creds: recognised credential files", check_credential_file_detection),
    ("creds: path-scoped matching", check_credential_path_matching),
    ("creds: unreadable makes no claim", check_unreadable_file_makes_no_content_claim),
    ("tokens: vendor patterns match", check_token_patterns_match),
    ("tokens: ordinary noise ignored", check_tokens_ignore_ordinary_noise),
    ("tokens: doc placeholders ignored", check_documentation_placeholders_are_ignored),
    ("creds: template files aren't stores", check_template_files_are_not_credential_stores),
    ("tokens: test material demoted not hidden", check_test_material_is_demoted_not_hidden),
    ("tokens: findings are masked", check_token_findings_are_masked),
    ("tokens: shell history left to its own rule", check_tokens_skip_shell_history),
    ("history: findings and permissions", check_shell_history_findings),
    ("history: command shapes, no false positives", check_command_shapes),
    ("scoring: counts include zeroes", check_severity_counts_include_zeroes),
    ("scoring: severity then confidence", check_ranking_orders_by_severity_then_confidence),
    ("scoring: worst severity and weighting", check_worst_severity_and_weighting),
    ("scoring: worst file first", check_grouping_puts_worst_file_first),
    ("registry: integrity", check_registry_integrity),
    ("registry: every emitted id has a rule", check_every_emitted_rule_id_has_a_rule),
    ("scanner: finds keys, prunes noise", check_scanner_finds_and_bounds),
    ("scanner: won't follow symlinks out", check_scanner_does_not_follow_symlinks_out),
    ("scanner: partial coverage reported", check_scanner_reports_partial_coverage_honestly),
    ("NO RAW SECRET REACHES OUTPUT", check_no_raw_secret_reaches_any_output),
    ("evidence is never persisted", check_masked_evidence_is_never_persisted),
]


def main():
    total = 0
    for name, fn in CHECKS:
        count = fn()
        total += count
        print(f"  ok  {name:<48} {count} case(s)")
    print(f"\n  All {total} checks passed.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
