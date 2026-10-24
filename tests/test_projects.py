"""Project versioning tests (task K10, criteria S1-05 and S1-06, threat T8)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from core.blueprints import all_blueprints, draft_spec
from core.discovery import Discovery
from core.projects import SPEC_FILE, ProjectError, ProjectExists, ProjectStore
from core.server import CSRF_HEADER, create_app
from core.spec import Spec

GROUPS = {"GROUP_1": "Platform Team", "GROUP_2": "Contoso-Ops"}
ROUND_ANSWERS = [
    {"tenant": "existing", "subscription": "existing", "region": "westeurope"},
    {"os": "linux", "backend_port": "443", "gateway_sku": "WAF_v2"},
    {"address_space": "10.20.0.0/16", "operator_role": "Reader"},
    {"operators": "Platform Team, Contoso-Ops"},
]


def draft(project_id: str = "web-shop") -> Spec:
    return draft_spec(all_blueprints()["vm_behind_app_gateway"], project_id, "westeurope")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    ).stdout.strip()


class StoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workspace = Path(self._tmp.name) / "ws"
        self.store = ProjectStore(self.workspace)
        self.addCleanup(self.store.close)


class ApproveTest(StoreTestCase):
    def test_approval_creates_commit_and_v1_tag(self) -> None:
        saved = self.store.approve_new(draft(), local_values=GROUPS)
        self.assertEqual(saved.version, "v1")
        repo = saved.path
        self.assertEqual(git(repo, "rev-parse", "HEAD"), saved.commit)
        self.assertEqual(git(repo, "log", "--format=%s"), "v1: approved spec")
        self.assertEqual(git(repo, "cat-file", "-t", "v1"), "tag", "annotated tag")
        self.assertEqual(git(repo, "rev-list", "-n", "1", "v1"), saved.commit)
        self.assertEqual(git(repo, "status", "--porcelain"), "", "nothing left uncommitted")
        self.assertEqual(git(repo, "log", "--format=%an <%ae>"), "app <app@localhost>")

    def test_saved_spec_is_approved_valid_and_canonical(self) -> None:
        saved = self.store.approve_new(draft())
        text = (saved.path / SPEC_FILE).read_text(encoding="utf-8")
        spec = Spec.model_validate_json(text)
        self.assertTrue(spec.approval.approved)
        self.assertEqual(spec.approval.version, "v1")
        self.assertIsNotNone(spec.approval.approved_at)
        self.assertEqual(text, json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n")

    def test_versions_and_spec_can_be_read_back(self) -> None:
        self.store.approve_new(draft())
        versions = self.store.versions("web-shop")
        self.assertEqual([v.version for v in versions], ["v1"])
        self.assertEqual(self.store.spec_at("web-shop", "v1").approval.version, "v1")
        self.assertEqual(self.store.list_projects()[0]["latest_version"], "v1")

    def test_existing_project_is_never_overwritten(self) -> None:
        self.store.approve_new(draft())
        with self.assertRaises(ProjectExists):
            self.store.approve_new(draft())
        self.assertEqual(len(self.store.versions("web-shop")), 1)

    def test_already_approved_spec_is_refused(self) -> None:
        data = draft().model_dump(mode="json")
        data["approval"] = {
            "approved": True,
            "approved_at": "2026-10-23T10:00:00Z",
            "version": "v1",
        }
        with self.assertRaises(ProjectError):
            self.store.approve_new(Spec.model_validate(data))


class LocalValuesTest(StoreTestCase):
    def test_real_values_stay_out_of_git(self) -> None:
        saved = self.store.approve_new(draft(), local_values=GROUPS)
        everything = git(saved.path, "log", "--all", "-p", "--format=%B")
        everything += (saved.path / SPEC_FILE).read_text(encoding="utf-8")
        for real in GROUPS.values():
            self.assertNotIn(real, everything)
        self.assertEqual(self.store.local_values("web-shop"), GROUPS)

    def test_refuses_when_a_real_value_would_enter_git(self) -> None:
        data = draft().model_dump(mode="json")
        data["decisions"] = [{"question": "Who needs access?", "answer": "Platform Team"}]
        with self.assertRaises(ProjectError):
            self.store.approve_new(Spec.model_validate(data), local_values=GROUPS)
        self.assertFalse(self.store.exists("web-shop"), "nothing half saved")

    def test_group_names_that_match_resource_or_role_words_are_fine(self) -> None:
        """A group called "app", "web" or "Reader" is not a leak."""
        values = {"GROUP_1": "app", "GROUP_2": "web", "GROUP_3": "Reader"}
        saved = self.store.approve_new(draft("my-app"), local_values=values)
        self.assertEqual(saved.version, "v1")

    def test_refuses_a_spec_that_looks_like_it_holds_a_secret(self) -> None:
        data = draft().model_dump(mode="json")
        token = "ghp" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # pragma: allowlist secret
        data["decisions"] = [{"question": "Anything else?", "answer": token}]
        with self.assertRaises(ProjectError):
            self.store.approve_new(Spec.model_validate(data))
        self.assertFalse(self.store.exists("web-shop"))

    @unittest.skipUnless(os.name == "posix", "POSIX permissions only")
    def test_workspace_and_metadata_are_private(self) -> None:
        self.store.approve_new(draft(), local_values=GROUPS)
        for path, mode in (
            (self.workspace, 0o700),
            (self.workspace / "projects", 0o700),
            (self.workspace / "projects" / "web-shop", 0o700),
            (self.workspace / "projects.sqlite", 0o600),
        ):
            with self.subTest(path=path.name):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)


class SafetyTest(StoreTestCase):
    def test_path_tricks_are_refused(self) -> None:
        for bad in ("../escape", "web-shop/../../x", "WEB", "a", "x" * 70):
            with self.subTest(project_id=bad):
                with self.assertRaises(ProjectError):
                    self.store.project_path(bad)

    def test_bad_version_names_are_refused(self) -> None:
        self.store.approve_new(draft())
        for bad in ("HEAD", "v0", "v1:../../etc", "main"):
            with self.subTest(version=bad):
                with self.assertRaises(ProjectError):
                    self.store.spec_at("web-shop", bad)

    @unittest.skipUnless(os.name == "posix", "shell hook needs POSIX")
    def test_git_hooks_never_run(self) -> None:
        """A planted hook in a tampered workspace must not execute."""
        saved = self.store.approve_new(draft("hook-test"))
        marker = Path(self._tmp.name) / "hook-ran"
        for name in ("pre-commit", "post-commit", "commit-msg"):
            hook = saved.path / ".git" / "hooks" / name
            hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
            hook.chmod(0o755)

        self.store._git(saved.path, "commit", "--quiet", "--allow-empty", "-m", "through wrapper")
        self.assertFalse(marker.exists(), "hooks are off inside the tool")

        # Control: plain Git does run the planted hook, so the test is meaningful.
        git(
            saved.path,
            "-c",
            "user.name=x",
            "-c",
            "user.email=x@x",
            "commit",
            "--allow-empty",
            "-m",
            "plain git",
        )
        self.assertTrue(marker.exists())

    def test_users_global_git_settings_are_ignored(self) -> None:
        with mock.patch.dict(os.environ, {"GIT_AUTHOR_NAME": "Real Person"}):
            saved = self.store.approve_new(draft("env-test"))
        self.assertEqual(git(saved.path, "log", "--format=%an"), "app")

    def test_missing_git_gives_clear_error(self) -> None:
        with mock.patch("core.projects.shutil.which", return_value=None):
            with self.assertRaises(ProjectError) as ctx:
                ProjectStore(self.workspace)
        self.assertIn("Git is not installed", str(ctx.exception))


class ApproveApiTest(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.discovery = Discovery()
        self.client = TestClient(
            create_app(8765, csrf_token="t", discovery=self.discovery, projects=self.store),
            base_url="http://127.0.0.1:8765",
        )
        self.headers = {CSRF_HEADER: "t"}

    def start(self) -> str:
        body = self.client.post(
            "/api/discovery",
            json={
                "cloud": "azure",
                "requirement": "Deploy my app on Azure on a server",
                "project_id": "api-shop",
            },
            headers=self.headers,
        ).json()
        return str(body["session_id"])

    def finish(self, sid: str) -> None:
        for answers in ROUND_ANSWERS:
            self.client.post(
                f"/api/discovery/{sid}/answers", json={"answers": answers}, headers=self.headers
            )

    def approve(self, sid: str, body: object | None = None) -> tuple[int, dict[str, object]]:
        r = self.client.post(
            f"/api/discovery/{sid}/approve",
            json={"confirm": True} if body is None else body,
            headers=self.headers,
        )
        return r.status_code, r.json()

    def test_approval_over_http_saves_v1(self) -> None:
        sid = self.start()
        self.finish(sid)
        status, body = self.approve(sid)
        self.assertEqual(status, 200)
        self.assertEqual((body["project_id"], body["version"]), ("api-shop", "v1"))
        versions = self.client.get("/api/projects/api-shop/versions").json()["versions"]
        self.assertEqual(versions[0]["commit"], body["commit"])
        spec = self.client.get("/api/projects/api-shop/versions/v1").json()["spec"]
        self.assertTrue(spec["approval"]["approved"])
        self.assertEqual(self.store.local_values("api-shop"), GROUPS)

    def test_cannot_approve_before_questions_are_done(self) -> None:
        sid = self.start()
        status, _ = self.approve(sid)
        self.assertEqual(status, 409)
        self.assertFalse(self.store.exists("api-shop"))

    def test_cannot_approve_twice(self) -> None:
        sid = self.start()
        self.finish(sid)
        self.assertEqual(self.approve(sid)[0], 200)
        self.assertEqual(self.approve(sid)[0], 409)

    def test_approval_needs_explicit_confirm_and_csrf(self) -> None:
        sid = self.start()
        self.finish(sid)
        for bad in ({}, {"confirm": False}, {"confirm": True, "version": "v9"}):
            with self.subTest(body=bad):
                self.assertEqual(self.approve(sid, bad)[0], 422)
        no_csrf = self.client.post(f"/api/discovery/{sid}/approve", json={"confirm": True})
        self.assertEqual(no_csrf.status_code, 403)
        self.assertFalse(self.store.exists("api-shop"))

    def test_unknown_project_is_404(self) -> None:
        self.assertEqual(self.client.get("/api/projects/nope-nope/versions").status_code, 404)


if __name__ == "__main__":
    unittest.main()
