"""store.py — local history, written as carefully as possible.

This database is the most sensitive thing this tool produces. A list of
every place on this machine holding an exposed credential is exactly the
file an attacker would want to find first — it turns a search into a
shopping list. That shapes three decisions:

**Masked evidence is never persisted.** It exists in memory for the report
you're currently looking at and is discarded. It's already masked, so the
risk is small, but the benefit of keeping it is smaller: history answers
"is this getting better", and that question needs counts and paths, not
values.

**Per-user directory, not the package directory.** A system-wide install
would otherwise share one history file across every account on the box,
which for this tool means handing your findings to the other accounts.

**Created private, not made private.** The file and its directory are
opened at 0600/0700 from the moment they exist, rather than created at the
default mode and narrowed with a follow-up chmod — that ordering leaves a
window, however brief, where another account can open the file.
"""
import os
import platform
import sqlite3
import threading
import time


def _data_dir():
    if platform.system() == "Darwin":
        return os.path.join(os.path.expanduser("~/Library/Application Support"), "ExposureAuditor")
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "exposure-auditor")


DATA_DIR = _data_dir()
DB_PATH = os.path.join(DATA_DIR, "history.db")
_lock = threading.Lock()


def _create_private(path, mode, is_dir=False):
    if is_dir:
        os.makedirs(path, mode=mode, exist_ok=True)
    elif not os.path.exists(path):
        # O_CREAT with an explicit mode is the only way to have the file
        # exist at the right permissions rather than merely end up there.
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, mode))
    try:
        os.chmod(path, mode)   # makedirs' mode is masked by umask; enforce it
    except OSError:
        pass


def conn():
    c = sqlite3.connect(DB_PATH, timeout=20)
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init():
    _create_private(DATA_DIR, 0o700, is_dir=True)
    _create_private(DB_PATH, 0o600)
    with _lock, conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan(
              ts           INTEGER PRIMARY KEY,
              finding_count INTEGER NOT NULL,
              weighted     INTEGER NOT NULL,
              files_seen   INTEGER NOT NULL,
              files_read   INTEGER NOT NULL,
              partial      INTEGER NOT NULL   -- 1 when coverage was incomplete
            );
            CREATE TABLE IF NOT EXISTS finding(
              ts        INTEGER NOT NULL,
              rule_id   TEXT NOT NULL,
              severity  TEXT NOT NULL,
              path      TEXT NOT NULL,
              confidence TEXT NOT NULL
              -- evidence is deliberately not stored; see the module docstring
            );
            CREATE INDEX IF NOT EXISTS idx_finding_ts ON finding(ts);
            """
        )


def record_scan(report, weighted):
    """Returns the scan timestamp."""
    ts = int(time.time())
    with _lock, conn() as c:
        c.execute(
            "INSERT INTO scan(ts, finding_count, weighted, files_seen, files_read, partial) "
            "VALUES(?,?,?,?,?,?)",
            (ts, len(report.findings), weighted, report.files_seen, report.files_read,
             1 if report.coverage_is_partial else 0),
        )
        c.executemany(
            "INSERT INTO finding(ts, rule_id, severity, path, confidence) VALUES(?,?,?,?,?)",
            [(ts, f.rule_id, f.severity, f.display_path, f.confidence)
             for f in report.findings],
        )
    return ts


def history(limit=30):
    """Most recent first: [(ts, finding_count, weighted, partial), ...]."""
    with _lock, conn() as c:
        return c.execute(
            "SELECT ts, finding_count, weighted, partial FROM scan ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()


def paths_from_previous_scan():
    """(rule_id, path) pairs from the scan before the latest one, so the
    current report can mark what's new rather than making you diff two lists
    by eye."""
    with _lock, conn() as c:
        rows = c.execute("SELECT ts FROM scan ORDER BY ts DESC LIMIT 2").fetchall()
        if len(rows) < 2:
            return set()
        previous_ts = rows[1][0]
        return {(r, p) for r, p in
                c.execute("SELECT rule_id, path FROM finding WHERE ts = ?", (previous_ts,))}


def forget_everything():
    """Delete the history database. Offered because a file that maps this
    machine's exposed credentials is a reasonable thing to not want lying
    around once you've acted on it."""
    with _lock:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(DB_PATH + suffix)
            except OSError:
                pass


init()
