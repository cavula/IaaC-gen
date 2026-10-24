"""Serving the screen (task K11, criterion S1-01, threat T5)."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from core.branding import get_branding
from core.server import WEB_DIST, create_app

LOCAL = "http://127.0.0.1:8765"


def client(dist: Path | None) -> TestClient:
    return TestClient(create_app(8765, csrf_token="t", web_dist=dist), base_url=LOCAL)


class ServingTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dist = Path(self._tmp.name)
        (self.dist / "assets").mkdir()
        (self.dist / "index.html").write_text(
            '<!doctype html><script type="module" src="/assets/app.js"></script>',
            encoding="utf-8",
        )
        (self.dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")

    def test_screen_and_assets_are_served_with_security_headers(self) -> None:
        c = client(self.dist)
        for path in ("/", "/assets/app.js"):
            with self.subTest(path=path):
                r = c.get(path)
                self.assertEqual(r.status_code, 200)
                self.assertIn("script-src 'self'", r.headers["content-security-policy"])
                self.assertEqual(r.headers["x-content-type-options"], "nosniff")
                self.assertEqual(r.headers["x-frame-options"], "DENY")

    def test_api_still_works_next_to_the_screen(self) -> None:
        self.assertEqual(client(self.dist).get("/api/health").json(), {"status": "ok"})

    def test_screen_keeps_the_host_and_origin_guards(self) -> None:
        bad_host = TestClient(create_app(8765, web_dist=self.dist), base_url="http://evil.example")
        self.assertEqual(bad_host.get("/").status_code, 400)
        r = client(self.dist).get("/", headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_files_outside_the_build_cannot_be_read(self) -> None:
        secret = self.dist.parent / "outside.txt"
        secret.write_text("private", encoding="utf-8")
        self.addCleanup(secret.unlink)
        for path in ("/../outside.txt", "/assets/../../outside.txt", "/%2e%2e/outside.txt"):
            with self.subTest(path=path):
                r = client(self.dist).get(path)
                self.assertNotIn("private", r.text)

    def test_clear_message_when_screen_is_not_built(self) -> None:
        r = client(None).get("/")
        self.assertEqual(r.status_code, 503)
        self.assertIn("npm run build", r.json()["error"])


@unittest.skipUnless((WEB_DIST / "index.html").is_file(), "web app not built")
class BuiltScreenTest(unittest.TestCase):
    """Checks the real build. CI builds the web app before running these."""

    def setUp(self) -> None:
        self.html = (WEB_DIST / "index.html").read_text(encoding="utf-8")

    def test_no_inline_scripts_or_styles(self) -> None:
        scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", self.html, flags=re.DOTALL)
        self.assertTrue(scripts)
        for attrs, body in scripts:
            self.assertIn("src=", attrs, "every script loads from a file (CSP script-src 'self')")
            self.assertEqual(body.strip(), "")
        self.assertNotIn("<style", self.html)
        self.assertIsNone(re.search(r"\sstyle=", self.html))

    def test_nothing_loads_from_another_site(self) -> None:
        for url in re.findall(r'(?:src|href)="([^"]+)"', self.html):
            self.assertTrue(url.startswith("/"), url)

    def test_every_referenced_asset_is_served(self) -> None:
        c = client(WEB_DIST)
        self.assertEqual(c.get("/").status_code, 200)
        for url in re.findall(r'(?:src|href)="(/assets/[^"]+)"', self.html):
            with self.subTest(asset=url):
                self.assertEqual(c.get(url).status_code, 200)

    def test_built_files_hold_no_brand_name(self) -> None:
        """The name comes from /api/session at run time, so a rebrand needs no rebuild."""
        name = get_branding().product_name.lower()
        for path in WEB_DIST.rglob("*"):
            if path.is_file():
                with self.subTest(file=path.name):
                    self.assertNotIn(
                        name, path.read_text(encoding="utf-8", errors="ignore").lower()
                    )


if __name__ == "__main__":
    unittest.main()
