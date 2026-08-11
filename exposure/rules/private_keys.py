"""private_keys.py — private keys readable by others, or carrying no
passphrase at all.

Two independent problems from one parse, reported separately because the
fixes have nothing to do with each other.

Permissions are the easy half: the mode bits either let another local
account read the key or they don't, so those findings are `certain`.

Whether a key is passphrase-protected takes actually parsing it, and it
matters more than it looks. An unencrypted key is usable the instant it's
copied, so anything that gets one file off this disk — a backup that syncs
somewhere, a stolen laptop, a malicious dependency running as you — ends up
with a working credential rather than a file it still has to crack. All
three formats in common use are decidable offline:

  PEM/PKCS#1    a `Proc-Type: 4,ENCRYPTED` header means encrypted
  PKCS#8        the BEGIN line itself says ENCRYPTED, or doesn't
  OpenSSH v1    the cipher name is a field inside the key; "none" means none
"""
import base64
import binascii
import re

from .base import CONFIDENCE_CERTAIN, Detector, Finding, Rule, mode_str, too_open

_PEM_BEGIN = re.compile(r"-----BEGIN ([A-Z0-9 ]*?)PRIVATE KEY-----")
_OPENSSH_BODY = re.compile(
    r"-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----", re.S)

# These live alongside keys in ~/.ssh but aren't keys.
_SSH_NON_KEYS = {"config", "known_hosts", "known_hosts.old", "authorized_keys"}


def parse_openssh_cipher(text):
    """Cipher name from an OpenSSH v1 private key, or None if `text` isn't
    one / is truncated. 'none' is the literal value OpenSSH writes for a key
    with no passphrase."""
    m = _OPENSSH_BODY.search(text or "")
    if not m:
        return None
    try:
        raw = base64.b64decode("".join(m.group(1).split()))
    except (ValueError, binascii.Error):
        return None
    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic):
        return None
    rest = raw[len(magic):]
    if len(rest) < 4:
        return None
    length = int.from_bytes(rest[:4], "big")
    if length <= 0 or len(rest) < 4 + length:
        return None
    try:
        return rest[4:4 + length].decode("ascii")
    except UnicodeDecodeError:
        return None


_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S)

# A real key file starts with the key, give or take a comment or a bag
# attribute block that some tools prepend.
_MAX_HEADER_BYTES = 512
# ...and is substantially nothing but the key.
_MIN_KEY_FRACTION = 0.5


def is_private_key(text, size=None):
    """True when this file *is* a private key, not merely a file that contains
    one somewhere inside it.

    That distinction is the whole rule. Scanning a real home directory turns
    up PEM blocks inside minified JavaScript bundles, package-manager cache
    blobs, and test fixtures shipped by dependencies — none of which are the
    user's key, none of which they can act on, and all of which drown the one
    finding that matters. Requiring the key material to start near the top of
    the file and account for most of it separates 'this is my id_rsa' from
    'this is a 4 MB bundle with a test key at byte 900,000' without needing a
    list of every tool that ships fixtures.
    """
    if not text:
        return False
    match = _PEM_BEGIN.search(text)
    if not match or match.start() > _MAX_HEADER_BYTES:
        return False
    key_bytes = sum(len(block) for block in _PEM_BLOCK.findall(text))
    # `size` is the real file size; `text` may have been truncated by the
    # scanner's read ceiling, and a file too big to read whole is not a key.
    total = max(size or 0, len(text)) or 1
    return key_bytes / total >= _MIN_KEY_FRACTION


def key_encryption(text):
    """('encrypted'|'unencrypted'|'unknown', format name).

    'unknown' is a real answer, not a placeholder: an unrecognised or
    truncated key body must not be reported as passphrase-less, since that
    accuses a perfectly safe key of being exposed.
    """
    m = _PEM_BEGIN.search(text or "")
    if not m:
        return "unknown", "unrecognised"
    kind = (m.group(1) or "").strip()

    if kind == "OPENSSH":
        cipher = parse_openssh_cipher(text)
        if cipher is None:
            return "unknown", "OpenSSH"
        return ("unencrypted" if cipher == "none" else "encrypted"), "OpenSSH"
    if kind == "ENCRYPTED":
        return "encrypted", "PKCS#8"
    if "Proc-Type: 4,ENCRYPTED" in text:
        return "encrypted", "PEM"
    if kind == "":
        return "unencrypted", "PKCS#8"
    return "unencrypted", "PEM/" + kind


def examine(facts):
    if facts.name in _SSH_NON_KEYS or not is_private_key(facts.text, facts.size):
        return []

    findings = []
    state, fmt = key_encryption(facts.text)

    if too_open(facts.mode):
        findings.append(Finding(
            rule_id="private-key-permissions",
            # Both problems at once is the case worth pulling to the top of the
            # list: readable by anyone here, and usable the moment it's read.
            severity="critical" if state == "unencrypted" else "high",
            display_path=facts.display_path,
            detail=(f"{fmt} private key is readable by other accounts on this machine "
                    f"(mode {mode_str(facts.mode)})."),
            confidence=CONFIDENCE_CERTAIN,
            evidence=mode_str(facts.mode),
        ))

    if state == "unencrypted":
        findings.append(Finding(
            rule_id="private-key-no-passphrase",
            severity="high",
            display_path=facts.display_path,
            detail=f"{fmt} private key has no passphrase — it works immediately if copied.",
            confidence=CONFIDENCE_CERTAIN,
        ))

    return findings


def _remediate_permissions(finding):
    return ("Restrict it to your account only:\n\n"
            f"    chmod 600 {finding.display_path}\n\n"
            "SSH itself refuses to use a key this permissive, for exactly this reason. If "
            "another account on this machine could already read it, treat the key as "
            "compromised and generate a replacement rather than only fixing the mode.")


def _remediate_passphrase(finding):
    return ("Add a passphrase to the existing key. The public key doesn't change, so nothing "
            "you've already authorised it with needs updating:\n\n"
            f"    ssh-keygen -p -f {finding.display_path}\n\n"
            "Your agent holds it unlocked for the session, so this costs one prompt per login "
            "rather than one per connection. A key you can't add a passphrase to without "
            "breaking automation is worth replacing with one scoped to just that job.")


DETECTOR = Detector(id="private-keys", examine=examine, needs_text=True)

RULES = [
    Rule(
        id="private-key-permissions",
        title="Private key readable by others",
        rationale="Any other account on this machine can copy a key it can read, and a copied "
                 "private key is indistinguishable from the original to everything that trusts it.",
        severity="critical",
        remediation=_remediate_permissions,
    ),
    Rule(
        id="private-key-no-passphrase",
        title="Private key with no passphrase",
        rationale="An unencrypted key is a working credential the moment the file leaves this "
                 "machine — through a backup, a sync folder, a stolen laptop, or anything "
                 "running under your account.",
        severity="high",
        remediation=_remediate_passphrase,
    ),
]
