"""Persistent, append only audit log (task K08, criterion S1-08, threat T8).

Every LLM call the gateway attempts, sent or blocked, is stored here, so the
user can always see exactly what left the machine.

Protections:

* Append only. SQLite triggers refuse any UPDATE or DELETE on the log.
* Tamper evident. Each row stores a SHA-256 hash of the previous row's hash
  plus its own content, forming a chain. Editing or removing a row from
  outside the app (for example with a SQLite tool) breaks the chain, and
  verify() reports it. This detects tampering; it cannot prevent someone
  with full access to the file from deleting it.
* Private files. On Linux and macOS the folder is created readable only by
  the owner (0700) and the database file 0600.
* Last line of defence. A record that contains anything that looks like a
  secret is refused, even though the gateway should never produce one.

Controls: OWASP ASVS V7 (logging), NIST CSF 2.0 DE.CM and PR.DS.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

from core.audit import AuditEntry
from core.secret_scan import find_secrets

DB_NAME = "audit.sqlite"
GENESIS = "0" * 64
MAX_PAGE = 200

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    entry     TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append only'); END;
"""


class AuditIntegrityError(Exception):
    pass


@dataclass(frozen=True)
class StoredEntry:
    id: int
    entry: AuditEntry


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    checked: int
    first_bad_id: int | None = None


def _chain_hash(prev_hash: str, entry_json: str) -> str:
    return hashlib.sha256((prev_hash + "\n" + entry_json).encode("utf-8")).hexdigest()


def _make_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(stat.S_IRWXU)


class SqliteAuditStore:
    """Implements the AuditSink protocol from core.audit."""

    def __init__(self, workspace_dir: Path) -> None:
        _make_private_dir(workspace_dir)
        self.path = workspace_dir / DB_NAME
        new_file = not self.path.exists()
        if new_file and os.name == "posix":
            # Create the file with owner only permissions before SQLite opens it.
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---------------------------------------------------------------- write

    def record(self, entry: AuditEntry) -> None:
        entry_json = entry.model_dump_json()
        if find_secrets(entry_json):
            raise AuditIntegrityError("refusing to store an audit record that looks like a secret")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
                prev = row[0] if row else GENESIS
                self._db.execute(
                    "INSERT INTO audit (entry, prev_hash, hash) VALUES (?, ?, ?)",
                    (entry_json, prev, _chain_hash(prev, entry_json)),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    # ----------------------------------------------------------------- read

    def page(self, limit: int = 50, before_id: int | None = None) -> list[StoredEntry]:
        """Newest first. Pass the smallest id you have as before_id for the next page."""
        limit = max(1, min(limit, MAX_PAGE))
        with self._lock:
            if before_id is None:
                rows = self._db.execute(
                    "SELECT id, entry FROM audit ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT id, entry FROM audit WHERE id < ? ORDER BY id DESC LIMIT ?",
                    (before_id, limit),
                ).fetchall()
        return [StoredEntry(r[0], AuditEntry.model_validate_json(r[1])) for r in rows]

    def count(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0])

    def verify(self) -> ChainReport:
        """Recompute the hash chain from the first row."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, entry, prev_hash, hash FROM audit ORDER BY id"
            ).fetchall()
        prev = GENESIS
        for checked, (row_id, entry_json, prev_hash, row_hash) in enumerate(rows):
            if prev_hash != prev or row_hash != _chain_hash(prev, entry_json):
                return ChainReport(ok=False, checked=checked, first_bad_id=row_id)
            try:
                json.loads(entry_json)
            except ValueError:
                return ChainReport(ok=False, checked=checked, first_bad_id=row_id)
            prev = row_hash
        return ChainReport(ok=True, checked=len(rows))
