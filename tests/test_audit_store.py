"""Audit store tests (task K08, criterion S1-08, threat T8)."""

from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import SecretStr

from core.audit import AuditEntry
from core.audit_store import AuditIntegrityError, SqliteAuditStore
from core.gateway import Gateway, Message, ProviderError, SecretDetected
from core.server import CSRF_HEADER, create_app

TENANT = "8f3c2a1e-1111-2222-3333-444455556666"
API_KEY = SecretStr("test-provider-key-" + "0000aaaa")
GITHUB_TOKEN = "ghp" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # pragma: allowlist secret


def entry(n: int = 0, **kw: object) -> AuditEntry:
    fields: dict[str, object] = {
        "purpose": f"test {n}",
        "provider": "anthropic",
        "model": "m",
        "host": "api.anthropic.com",
        "outcome": "sent",
        "request": [{"role": "user", "content": f"message {n}"}],
        "response": "ok",
    }
    fields.update(kw)
    return AuditEntry.model_validate(fields)


class StoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name) / "workspace"
        self.store = SqliteAuditStore(self.dir)
        self.addCleanup(self.store.close)


class StoreTest(StoreTestCase):
    def test_records_survive_a_restart(self) -> None:
        self.store.record(entry(1))
        self.store.close()
        reopened = SqliteAuditStore(self.dir)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.count(), 1)
        self.assertEqual(reopened.page()[0].entry.purpose, "test 1")

    def test_newest_first_with_paging(self) -> None:
        for n in range(5):
            self.store.record(entry(n))
        first = self.store.page(limit=2)
        self.assertEqual([e.entry.purpose for e in first], ["test 4", "test 3"])
        second = self.store.page(limit=2, before_id=first[-1].id)
        self.assertEqual([e.entry.purpose for e in second], ["test 2", "test 1"])

    def test_page_size_is_capped(self) -> None:
        for n in range(3):
            self.store.record(entry(n))
        self.assertEqual(len(self.store.page(limit=0)), 1)
        self.assertEqual(len(self.store.page(limit=10_000)), 3)

    def test_secret_looking_record_is_refused(self) -> None:
        with self.assertRaises(AuditIntegrityError):
            self.store.record(entry(request=[{"role": "user", "content": GITHUB_TOKEN}]))
        self.assertEqual(self.store.count(), 0)


class AppendOnlyTest(StoreTestCase):
    def raw(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.store.path)
        self.addCleanup(conn.close)
        return conn

    def test_update_and_delete_are_refused(self) -> None:
        self.store.record(entry(1))
        conn = self.raw()
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE audit SET entry = '{}'")
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM audit")
        self.assertEqual(self.store.count(), 1)

    def test_chain_is_valid_after_normal_use(self) -> None:
        for n in range(4):
            self.store.record(entry(n))
        report = self.store.verify()
        self.assertTrue(report.ok)
        self.assertEqual(report.checked, 4)

    def test_tampering_from_outside_is_detected(self) -> None:
        """Someone drops the triggers with a SQLite tool and edits a row."""
        for n in range(3):
            self.store.record(entry(n))
        conn = self.raw()
        conn.execute("DROP TRIGGER audit_no_update")
        conn.execute("UPDATE audit SET entry = replace(entry, 'message 1', 'edited') WHERE id = 2")
        conn.commit()
        report = self.store.verify()
        self.assertFalse(report.ok)
        self.assertEqual(report.first_bad_id, 2)

    def test_removed_row_is_detected(self) -> None:
        for n in range(3):
            self.store.record(entry(n))
        conn = self.raw()
        conn.execute("DROP TRIGGER audit_no_delete")
        conn.execute("DELETE FROM audit WHERE id = 2")
        conn.commit()
        report = self.store.verify()
        self.assertFalse(report.ok)
        self.assertEqual(report.first_bad_id, 3)


@unittest.skipUnless(os.name == "posix", "POSIX permissions only")
class PermissionsTest(StoreTestCase):
    def test_folder_and_all_files_are_private(self) -> None:
        self.store.record(entry(1))
        self.assertEqual(stat.S_IMODE(self.dir.stat().st_mode), 0o700)
        files = [p for p in self.dir.iterdir() if p.is_file()]
        self.assertGreaterEqual(len(files), 2, "database plus its side files")
        for path in files:
            with self.subTest(file=path.name):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


class FakeTransport:
    def __init__(self, reply: str = "Use CIDR_1 for TENANT_1", fail: bool = False) -> None:
        self.reply = reply
        self.fail = fail

    def send(
        self,
        model: str,
        messages: list[dict[str, str]],
        api_key: str | None,
        api_base: str,
        max_tokens: int,
        timeout: int,
    ) -> str:
        if self.fail:
            raise RuntimeError("provider down")
        return self.reply


class EveryCallIsLoggedTest(StoreTestCase):
    """Done when: every LLM call has an entry showing redacted text only."""

    def gateway(self, fail: bool = False) -> Gateway:
        gw = Gateway(
            provider="anthropic",
            model="m",
            api_key=API_KEY,
            transport=FakeTransport(fail=fail),
            audit=self.store,
        )
        gw.redactor.register(TENANT, "TENANT")
        return gw

    def test_sent_blocked_and_failed_calls_are_all_logged(self) -> None:
        gw = self.gateway()
        reply = gw.complete([Message("user", f"tenant {TENANT} net 10.20.0.0/16")], "discovery")
        self.assertIn(TENANT, reply, "the user sees real values")

        with self.assertRaises(SecretDetected):
            gw.complete([Message("user", f"token {GITHUB_TOKEN}")], "discovery")
        with self.assertRaises(ProviderError):
            self.gateway(fail=True).complete([Message("user", "hello")], "discovery")

        outcomes = [e.entry.outcome for e in self.store.page()]
        self.assertEqual(outcomes, ["error", "blocked", "sent"])

        # Read every file SQLite wrote, including the -wal and -shm side files.
        on_disk = b"".join(p.read_bytes() for p in self.dir.iterdir() if p.is_file())
        self.assertTrue(any(p.name.endswith("-wal") for p in self.dir.iterdir()))
        for real in (TENANT, "10.20.0.0", GITHUB_TOKEN, API_KEY.get_secret_value()):
            self.assertNotIn(real.encode(), on_disk, "real values never reach the disk")
        sent = self.store.page()[-1].entry
        self.assertEqual(sent.request[0]["content"], "tenant TENANT_1 net CIDR_1")
        self.assertEqual(sent.response, "Use CIDR_1 for TENANT_1")
        self.assertTrue(self.store.verify().ok)


class AuditApiTest(StoreTestCase):
    def client(self, store: SqliteAuditStore | None) -> TestClient:
        return TestClient(
            create_app(8765, csrf_token="t", audit_store=store), base_url="http://127.0.0.1:8765"
        )

    def test_lists_entries_newest_first(self) -> None:
        for n in range(3):
            self.store.record(entry(n))
        data = self.client(self.store).get("/api/audit?limit=2").json()
        self.assertEqual([e["purpose"] for e in data["entries"]], ["test 2", "test 1"])
        self.assertEqual(data["total"], 3)
        more = self.client(self.store).get(f"/api/audit?before_id={data['next_before_id']}").json()
        self.assertEqual([e["purpose"] for e in more["entries"]], ["test 0"])

    def test_verify_endpoint(self) -> None:
        self.store.record(entry(1))
        self.assertEqual(
            self.client(self.store).get("/api/audit/verify").json(),
            {"ok": True, "checked": 1, "first_bad_id": None},
        )

    def test_no_way_to_change_or_delete_records(self) -> None:
        self.store.record(entry(1))
        client = self.client(self.store)
        for method in ("post", "put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(client, method)("/api/audit", headers={CSRF_HEADER: "t"})
                self.assertEqual(response.status_code, 405)
        self.assertEqual(self.store.count(), 1)

    def test_audit_api_keeps_request_guards(self) -> None:
        response = self.client(self.store).get(
            "/api/audit", headers={"Origin": "http://evil.example"}
        )
        self.assertEqual(response.status_code, 403)

    def test_missing_store_gives_clear_error(self) -> None:
        self.assertEqual(self.client(None).get("/api/audit").status_code, 503)


if __name__ == "__main__":
    unittest.main()
