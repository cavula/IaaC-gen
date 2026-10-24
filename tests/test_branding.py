"""Branding tests (task K01, acceptance criterion S1-10).

The product name must appear nowhere outside branding.json and assets/brand.
Uses only the Python standard library.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path

from core.branding import REPO_ROOT, REQUIRED_KEYS, load_branding

ALLOWED_FILES = {REPO_ROOT / "branding.json"}
ALLOWED_DIRS = {REPO_ROOT / "assets" / "brand"}
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".terraform",
    "workspace",
}


def iter_scannable_files(root: Path = REPO_ROOT) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path in ALLOWED_FILES or any(d in path.parents for d in ALLOWED_DIRS):
            continue
        yield path


def find_name(name: str, root: Path = REPO_ROOT) -> list[str]:
    """Return files under root that contain name, case insensitive."""
    needle = name.lower().encode("utf-8")
    hits = []
    for path in iter_scannable_files(root):
        try:
            if needle in path.read_bytes().lower():
                hits.append(str(path.relative_to(root)))
        except OSError:
            continue
    return hits


class BrandScanTest(unittest.TestCase):
    def test_product_name_only_in_branding_config(self) -> None:
        offenders = find_name(load_branding().product_name)
        self.assertEqual(offenders, [], f"product name found outside branding config: {offenders}")

    def test_short_name_only_in_branding_config(self) -> None:
        offenders = find_name(load_branding().short_name)
        self.assertEqual(offenders, [], f"short name found outside branding config: {offenders}")

    def test_scanner_catches_a_leak(self) -> None:
        """The scan must actually fail when the name is hardcoded somewhere."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "module.py").write_text('TITLE = "Examplename"\n', encoding="utf-8")
            self.assertEqual(find_name("examplename", root), ["module.py"])


class LoadBrandingTest(unittest.TestCase):
    def _write(self, tmp: str, data: dict[str, str]) -> Path:
        path = Path(tmp) / "branding.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_current_config_is_valid(self) -> None:
        branding = load_branding()
        self.assertTrue(branding.product_name.strip())

    def test_missing_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                load_branding(self._write(tmp, {"product_name": "X"}))

    def test_empty_name_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = {key: "" for key in REQUIRED_KEYS}
            with self.assertRaises(ValueError):
                load_branding(self._write(tmp, data))


class SecretHygieneTest(unittest.TestCase):
    def test_env_file_is_ignored_by_git(self) -> None:
        lines = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(".env", lines)

    def test_env_example_has_no_values(self) -> None:
        for line in (REPO_ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#"):
                key, _, value = line.partition("=")
                self.assertTrue(key.startswith("APP_"), f"{key} must use the APP_ prefix")
                self.assertEqual(value, "", f"{key} must be empty in .env.example")


if __name__ == "__main__":
    unittest.main()
