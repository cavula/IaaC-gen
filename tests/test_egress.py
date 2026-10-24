"""Egress guard tests (task K07, threat T6).

The guard cannot be removed once installed, so each test runs in a fresh
Python process.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import unittest

from core.branding import REPO_ROOT
from core.egress import EgressPolicy, host_of, is_loopback


def run(code: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    full_env = {k: v for k, v in os.environ.items() if "PROXY" not in k.upper()}
    full_env.update(env or {})
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=REPO_ROOT,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


class PolicyTest(unittest.TestCase):
    def test_policy(self) -> None:
        policy = EgressPolicy(["api.anthropic.com"])
        self.assertTrue(policy.allows("api.anthropic.com"))
        self.assertTrue(policy.allows("API.Anthropic.com."))
        self.assertTrue(policy.allows("localhost"))
        self.assertTrue(policy.allows("127.0.0.1"))
        self.assertFalse(policy.allows("evil.example"))
        self.assertFalse(policy.allows("api.anthropic.com.evil.example"))

    def test_helpers(self) -> None:
        self.assertEqual(host_of("https://API.example.com:443/v1"), "api.example.com")
        self.assertTrue(is_loopback("::1"))
        self.assertFalse(is_loopback("10.0.0.1"))


class GuardTest(unittest.TestCase):
    def test_blocks_lookups_and_connections_off_the_list(self) -> None:
        result = run(
            """
            import socket
            from core.egress import EgressDenied, EgressPolicy, install_guard
            install_guard(EgressPolicy(["allowed.invalid"]))

            def attempt(fn):
                try:
                    fn()
                    return "allowed"
                except EgressDenied:
                    return "denied"
                except OSError:
                    return "allowed"  # passed the guard, failed for network reasons

            print("lookup", attempt(lambda: socket.getaddrinfo("example.com", 443)))
            print("byname", attempt(lambda: socket.gethostbyname("example.com")))
            target = ("203.0.113.5", 443)
            print("rawip", attempt(lambda: socket.create_connection(target, timeout=1)))
            print("localhost", attempt(lambda: socket.getaddrinfo("localhost", 80)))
            print("listed", attempt(lambda: socket.getaddrinfo("allowed.invalid", 443)))
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = dict(line.split() for line in result.stdout.splitlines())
        self.assertEqual(
            lines,
            {
                "lookup": "denied",
                "byname": "denied",
                "rawip": "denied",
                "localhost": "allowed",
                "listed": "allowed",
            },
        )

    def test_loopback_connections_still_work(self) -> None:
        result = run(
            """
            import socket
            from core.egress import EgressPolicy, install_guard
            server = socket.socket()
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            install_guard(EgressPolicy([]))
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            client.close()
            print("ok")
            """
        )
        self.assertEqual(result.stdout.strip(), "ok", result.stderr)

    def test_guard_cannot_be_installed_twice(self) -> None:
        result = run(
            """
            from core.egress import EgressPolicy, install_guard
            install_guard(EgressPolicy([]))
            try:
                install_guard(EgressPolicy(["evil.example"]))
            except RuntimeError:
                print("refused")
            """
        )
        self.assertEqual(result.stdout.strip(), "refused", result.stderr)

    def test_litellm_import_makes_no_network_calls(self) -> None:
        """With the guard on, importing LiteLLM through our transport must not
        try to reach the internet (it fetches a price list unless told not to)."""
        result = run(
            """
            import socket
            from core.egress import EgressPolicy, install_guard
            attempts = []
            original = socket.getaddrinfo
            def spy(host, *a, **k):
                attempts.append(host)
                return original(host, *a, **k)
            socket.getaddrinfo = spy
            install_guard(EgressPolicy([]))
            from core.gateway import LiteLLMTransport
            LiteLLMTransport()
            print("lookups:", [h for h in attempts if h not in ("localhost", "127.0.0.1")])
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertIn("lookups: []", result.stdout)

    def test_app_startup_allows_only_llm_and_registry(self) -> None:
        result = run(
            """
            import socket
            from core.egress import EgressDenied
            from core.server import install_egress_guard
            print(sorted(install_egress_guard("anthropic", None)))
            try:
                socket.getaddrinfo("raw.githubusercontent.com", 443)
            except EgressDenied:
                print("other hosts denied")
            """
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("['api.anthropic.com', 'registry.terraform.io']", result.stdout)
        self.assertIn("other hosts denied", result.stdout)


if __name__ == "__main__":
    unittest.main()
