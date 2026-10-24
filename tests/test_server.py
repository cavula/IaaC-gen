"""Server tests (task K04, criterion S1-01, threat T5)."""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import unittest

import uvicorn
from fastapi.testclient import TestClient

from core.branding import get_branding
from core.server import CSRF_HEADER, MAX_BODY_BYTES, check_bind_host, create_app

PORT = 8765
TOKEN = "test-csrf-token"  # pragma: allowlist secret
LOCAL = f"http://127.0.0.1:{PORT}"


def make_client(base_url: str = LOCAL) -> TestClient:
    app = create_app(PORT, csrf_token=TOKEN)

    # A state changing route, only for these tests.
    @app.post("/api/test-write")
    async def write() -> dict[str, bool]:
        return {"written": True}

    return TestClient(app, base_url=base_url)


class HostHeaderTest(unittest.TestCase):
    def test_localhost_names_are_accepted(self) -> None:
        for base in (LOCAL, f"http://localhost:{PORT}"):
            with self.subTest(base=base):
                self.assertEqual(make_client(base).get("/api/health").status_code, 200)

    def test_other_hosts_are_refused(self) -> None:
        """DNS rebinding: an attacker domain pointed at 127.0.0.1."""
        for base in ("http://attacker.example", "http://192.168.1.10:8765", "http://0.0.0.0"):
            with self.subTest(base=base):
                self.assertEqual(make_client(base).get("/api/health").status_code, 400)


class CrossOriginTest(unittest.TestCase):
    def test_foreign_origin_is_refused_even_for_reads(self) -> None:
        response = make_client().get("/api/session", headers={"Origin": "http://evil.example"})
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(TOKEN, response.text)

    def test_cross_site_fetch_is_refused(self) -> None:
        response = make_client().get("/api/session", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(response.status_code, 403)

    def test_own_origin_is_allowed(self) -> None:
        response = make_client().get("/api/health", headers={"Origin": LOCAL})
        self.assertEqual(response.status_code, 200)

    def test_no_cors_headers_are_ever_sent(self) -> None:
        client = make_client()
        preflight = client.options(
            "/api/test-write",
            headers={"Origin": LOCAL, "Access-Control-Request-Method": "POST"},
        )
        normal = client.get("/api/health")
        for response in (preflight, normal):
            self.assertNotIn("access-control-allow-origin", response.headers)


class CsrfTest(unittest.TestCase):
    def test_write_without_token_is_refused(self) -> None:
        self.assertEqual(make_client().post("/api/test-write").status_code, 403)

    def test_write_with_wrong_token_is_refused(self) -> None:
        response = make_client().post("/api/test-write", headers={CSRF_HEADER: "wrong"})
        self.assertEqual(response.status_code, 403)

    def test_write_with_token_is_allowed(self) -> None:
        response = make_client().post("/api/test-write", headers={CSRF_HEADER: TOKEN})
        self.assertEqual(response.json(), {"written": True})

    def test_token_from_session_endpoint_works(self) -> None:
        client = make_client()
        token = client.get("/api/session").json()["csrf_token"]
        self.assertEqual(
            client.post("/api/test-write", headers={CSRF_HEADER: token}).status_code, 200
        )

    def test_each_process_gets_a_new_random_token(self) -> None:
        a = create_app(PORT).state.csrf_token
        b = create_app(PORT).state.csrf_token
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a), 40)

    def test_oversized_body_is_refused(self) -> None:
        response = make_client().post(
            "/api/test-write",
            headers={CSRF_HEADER: TOKEN},
            content=b"x" * (MAX_BODY_BYTES + 1),
        )
        self.assertEqual(response.status_code, 413)


class HardeningTest(unittest.TestCase):
    def test_security_headers_on_success_and_error(self) -> None:
        client = make_client()
        for response in (client.get("/api/health"), client.post("/api/test-write")):
            with self.subTest(status=response.status_code):
                self.assertEqual(response.headers["x-content-type-options"], "nosniff")
                self.assertEqual(response.headers["x-frame-options"], "DENY")
                self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
                self.assertEqual(response.headers["cache-control"], "no-store")

    def test_api_docs_pages_are_disabled(self) -> None:
        client = make_client()
        for path in ("/docs", "/redoc", "/openapi.json"):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 404)

    def test_session_reads_name_from_branding_config(self) -> None:
        data = make_client().get("/api/session").json()
        self.assertEqual(data["product_name"], get_branding().product_name)


class BindAddressTest(unittest.TestCase):
    def test_non_loopback_addresses_are_refused(self) -> None:
        for host in ("0.0.0.0", "192.168.1.10", "::"):  # noqa: S104
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    check_bind_host(host)
        check_bind_host("127.0.0.1")

    def test_real_server_listens_on_loopback_only(self) -> None:
        config = uvicorn.Config(
            create_app(PORT), host="127.0.0.1", port=0, log_level="error", server_header=False
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(server.started)
            addresses = [s.getsockname() for srv in server.servers for s in srv.sockets]
            self.assertTrue(addresses)
            for address in addresses:
                self.assertEqual(address[0], "127.0.0.1")
            port = addresses[0][1]

            # Reachable on loopback.
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                pass

            # Not reachable on this machine's network address, if it has one.
            outward = _outward_ip()
            if outward:
                with self.assertRaises(OSError):
                    socket.create_connection((outward, port), timeout=2).close()
        finally:
            server.should_exit = True
            thread.join(timeout=10)


def _outward_ip() -> str | None:
    """This machine's non loopback address, without sending any packets."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("10.255.255.255", 1))
            ip: str = probe.getsockname()[0]
    except OSError:
        return None
    return None if ip.startswith("127.") else ip


if __name__ == "__main__":
    unittest.main()
