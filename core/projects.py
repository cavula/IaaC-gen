"""Approved specs saved as versions (task K10, criteria S1-05 and S1-06; threat T8).

Each project is its own Git repository under <workspace>/projects/<project id>.
Approving a draft writes spec.json, commits it and adds an annotated tag
(v1, v2, ...). Later slices add Terraform files, the diagram and the trust
report to the same commit.

What goes where:

* The Git repository holds only what is safe to share: the spec, which uses
  placeholders such as GROUP_1. A repository may be pushed somewhere later.
* Real values the user typed, such as group names, go in a private SQLite
  database in the workspace (folder 0700, file 0600 on Linux and macOS).
  They never enter Git.

Git is run safely: no shell, a fixed argument list, a timeout, the user's
global and system Git settings ignored, and hooks switched off, so a tampered
workspace cannot run code when a version is saved.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess  # noqa: S404
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from core.secret_scan import find_secrets
from core.spec import Spec

SPEC_FILE = "spec.json"
PROJECTS_DIR = "projects"
META_DB = "projects.sqlite"
GIT_TIMEOUT = 30
VERSION_TAG = re.compile(r"^v([1-9][0-9]{0,5})$")
# Neutral identity for commits made by the tool. Never the brand name.
GIT_IDENTITY = ("app", "app@localhost")

META_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    project_id     TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL,
    latest_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS local_values (
    project_id  TEXT NOT NULL,
    placeholder TEXT NOT NULL,
    value       TEXT NOT NULL,
    PRIMARY KEY (project_id, placeholder)
);
"""


class ProjectError(Exception):
    pass


class ProjectExists(ProjectError):
    pass


@dataclass(frozen=True)
class SavedVersion:
    project_id: str
    version: str
    commit: str
    path: Path


@dataclass(frozen=True)
class VersionInfo:
    version: str
    commit: str
    message: str


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(stat.S_IRWXU)


def canonical_json(spec: Spec) -> str:
    return json.dumps(spec.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


class ProjectStore:
    def __init__(self, workspace_dir: Path) -> None:
        git = shutil.which("git")
        if git is None:
            raise ProjectError("Git is not installed. Install Git to save project versions.")
        self._git_path = git
        _private_dir(workspace_dir)
        self.root = workspace_dir / PROJECTS_DIR
        _private_dir(self.root)
        db_path = workspace_dir / META_DB
        if not db_path.exists() and os.name == "posix":
            os.close(os.open(db_path, os.O_CREAT | os.O_WRONLY, 0o600))
        self._lock = threading.Lock()
        self._db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._db.executescript(META_SCHEMA)

    def close(self) -> None:
        self._db.close()

    # ------------------------------------------------------------------ git

    def _git(self, repo: Path, *args: str) -> str:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(repo),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
        if os.name == "nt":
            env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
        command = [
            self._git_path,
            "-c",
            "core.hooksPath=.git/no-hooks",
            "-c",
            f"user.name={GIT_IDENTITY[0]}",
            "-c",
            f"user.email={GIT_IDENTITY[1]}",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            *args,
        ]
        try:
            result = subprocess.run(  # noqa: S603
                command,
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
                timeout=GIT_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ProjectError("Git took too long to respond") from None
        if result.returncode != 0:
            raise ProjectError(f"Git failed: {args[0]} (exit {result.returncode})")
        return result.stdout.strip()

    # ---------------------------------------------------------------- paths

    def project_path(self, project_id: str) -> Path:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", project_id):
            raise ProjectError("invalid project id")
        path = (self.root / project_id).resolve()
        if path.parent != self.root.resolve():
            raise ProjectError("invalid project id")
        return path

    def exists(self, project_id: str) -> bool:
        return (self.project_path(project_id) / ".git").is_dir()

    # ---------------------------------------------------------------- write

    def approve_new(self, draft: Spec, local_values: dict[str, str] | None = None) -> SavedVersion:
        """Approve a draft as version 1 of a new project."""
        if draft.approval.approved:
            raise ProjectError("this spec is already approved")
        project_id = draft.project_id
        repo = self.project_path(project_id)
        with self._lock:
            if repo.exists():
                raise ProjectExists(
                    f"a project called '{project_id}' already exists. Choose another name."
                )
            version = "v1"
            approved = Spec.model_validate(
                {
                    **draft.model_dump(mode="json"),
                    "approval": {
                        "approved": True,
                        "approved_at": datetime.now(UTC).isoformat(),
                        "version": version,
                    },
                }
            )
            text = canonical_json(approved)
            if find_secrets(text):
                raise ProjectError("refusing to save: the spec looks like it contains a secret")
            for value in (local_values or {}).values():
                if value and value in text:
                    raise ProjectError("refusing to save: a real value would enter Git")

            _private_dir(repo)
            try:
                self._git(repo, "init", "--quiet", "--initial-branch=main")
                (repo / SPEC_FILE).write_text(text, encoding="utf-8")
                self._git(repo, "add", "--", SPEC_FILE)
                self._git(repo, "commit", "--quiet", "-m", f"{version}: approved spec")
                self._git(repo, "tag", "-a", version, "-m", f"Approved version {version}")
                commit = self._git(repo, "rev-parse", "HEAD")
            except ProjectError:
                shutil.rmtree(repo, ignore_errors=True)
                raise

            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    "INSERT INTO projects (project_id, created_at, latest_version) "
                    "VALUES (?, ?, ?)",
                    (project_id, datetime.now(UTC).isoformat(), version),
                )
                self._db.executemany(
                    "INSERT INTO local_values (project_id, placeholder, value) VALUES (?, ?, ?)",
                    [(project_id, k, v) for k, v in (local_values or {}).items()],
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return SavedVersion(project_id, version, commit, repo)

    # ----------------------------------------------------------------- read

    def list_projects(self) -> list[dict[str, str]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT project_id, created_at, latest_version FROM projects ORDER BY created_at"
            ).fetchall()
        return [{"project_id": r[0], "created_at": r[1], "latest_version": r[2]} for r in rows]

    def versions(self, project_id: str) -> list[VersionInfo]:
        repo = self.project_path(project_id)
        if not self.exists(project_id):
            raise ProjectError("unknown project")
        out = self._git(
            repo,
            "tag",
            "--list",
            "v*",
            "--format=%(refname:short)|%(objectname)|%(contents:subject)",
        )
        infos = []
        for line in out.splitlines():
            tag, _, rest = line.partition("|")
            if VERSION_TAG.fullmatch(tag):
                commit = self._git(repo, "rev-list", "-n", "1", tag)
                infos.append(VersionInfo(tag, commit, rest.partition("|")[2]))
        return sorted(infos, key=lambda v: int(v.version[1:]))

    def spec_at(self, project_id: str, version: str) -> Spec:
        if not VERSION_TAG.fullmatch(version):
            raise ProjectError("invalid version")
        repo = self.project_path(project_id)
        text = self._git(repo, "show", f"{version}:{SPEC_FILE}")
        return Spec.model_validate_json(text)

    def local_values(self, project_id: str) -> dict[str, str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT placeholder, value FROM local_values WHERE project_id = ?", (project_id,)
            ).fetchall()
        return {r[0]: r[1] for r in rows}
