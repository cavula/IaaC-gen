"""LLM gateway tests (task K07; criteria S1-07, S1-09; threats T1, T2, T6, T10)."""

from __future__ import annotations

import os
import unittest
from typing import Any
from unittest import mock

from pydantic import SecretStr

from core.audit import MemoryAuditSink
from core.gateway import (
    MAX_TOTAL_CHARS,
    Gateway,
    GatewayError,
    LiteLLMTransport,
    Message,
    ProviderError,
    RequestTooLarge,
    SecretDetected,
)

API_KEY = SecretStr("test-provider-key-" + "0000aaaa")
TENANT = "8f3c2a1e-1111-2222-3333-444455556666"
GITHUB_TOKEN = "ghp" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # pragma: allowlist secret


class FakeTransport:
    def __init__(self, reply: str = "ok", error: Exception | None = None) -> None:
        self.reply = reply
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def send(
        self,
        model: str,
        messages: list[dict[str, str]],
        api_key: str | None,
        api_base: str,
        max_tokens: int,
        timeout: int,
    ) -> str:
        self.calls.append(
            {"model": model, "messages": messages, "api_key": api_key, "api_base": api_base}
        )
        if self.error:
            raise self.error
        return self.reply


def make(transport: FakeTransport, **kwargs: Any) -> tuple[Gateway, MemoryAuditSink]:
    audit = MemoryAuditSink()
    gw = Gateway(
        provider=kwargs.pop("provider", "anthropic"),
        model="some-model",
        api_key=kwargs.pop("api_key", API_KEY),
        transport=transport,
        audit=audit,
        **kwargs,
    )
    return gw, audit


def user(text: str) -> list[Message]:
    return [Message("user", text)]


class HappyPathTest(unittest.TestCase):
    def test_only_redacted_text_leaves_and_reply_is_restored(self) -> None:
        transport = FakeTransport(reply="Put the VM in CIDR_1 under TENANT_1.")
        gw, audit = make(transport)
        gw.redactor.register(TENANT, "TENANT")
        out = gw.complete(user(f"Tenant {TENANT}, network 10.20.0.0/16"), purpose="discovery")

        sent = transport.calls[0]["messages"][0]["content"]
        self.assertEqual(sent, "Tenant TENANT_1, network CIDR_1")
        self.assertEqual(out, f"Put the VM in 10.20.0.0/16 under {TENANT}.")

        entry = audit.entries[0]
        self.assertEqual(entry.outcome, "sent")
        self.assertEqual(entry.request[0]["content"], sent)
        self.assertEqual(entry.response, "Put the VM in CIDR_1 under TENANT_1.")
        self.assertEqual(entry.redactions, {"TENANT": 1, "CIDR": 1})
        self.assertNotIn(TENANT, entry.model_dump_json())
        self.assertNotIn("10.20.0.0", entry.model_dump_json())

    def test_endpoint_and_model_are_explicit(self) -> None:
        transport = FakeTransport()
        gw, _ = make(transport)
        gw.complete(user("hello"), purpose="test")
        call = transport.calls[0]
        self.assertEqual(call["api_base"], "https://api.anthropic.com")
        self.assertEqual(call["model"], "anthropic/some-model")
        self.assertEqual(call["api_key"], API_KEY.get_secret_value())

    def test_local_model_needs_no_key(self) -> None:
        transport = FakeTransport()
        gw, _ = make(transport, provider="ollama", api_key=None)
        gw.complete(user("hello"), purpose="test")
        self.assertEqual(transport.calls[0]["api_base"], "http://localhost:11434")


class BlockingTest(unittest.TestCase):
    def assert_blocked(self, text: str) -> MemoryAuditSink:
        transport = FakeTransport()
        gw, audit = make(transport)
        with self.assertRaises(SecretDetected) as ctx:
            gw.complete(user(text), purpose="test")
        self.assertEqual(transport.calls, [], "nothing may be sent")
        self.assertEqual(audit.entries[0].outcome, "blocked")
        self.assertEqual(audit.entries[0].request, [], "blocked content is not recorded")
        for value in (API_KEY.get_secret_value(), GITHUB_TOKEN):
            self.assertNotIn(value, str(ctx.exception))
            self.assertNotIn(value, audit.entries[0].model_dump_json())
        return audit

    def test_secret_in_message_is_blocked(self) -> None:
        self.assert_blocked(f"my token is {GITHUB_TOKEN}")

    def test_configured_api_key_is_blocked(self) -> None:
        self.assert_blocked(f"why does {API_KEY.get_secret_value()} not work?")

    def test_pasted_env_file_is_blocked(self) -> None:
        env = f"APP_LLM_PROVIDER=anthropic\nAPP_LLM_API_KEY={API_KEY.get_secret_value()}\n"
        self.assert_blocked(env)

    def test_secret_in_system_or_history_is_blocked(self) -> None:
        transport = FakeTransport()
        gw, _ = make(transport)
        messages = [
            Message("system", "You are helpful."),
            Message("assistant", f"earlier reply {GITHUB_TOKEN}"),
            Message("user", "continue"),
        ]
        with self.assertRaises(SecretDetected):
            gw.complete(messages, purpose="test")
        self.assertEqual(transport.calls, [])

    def test_oversized_request_is_blocked(self) -> None:
        transport = FakeTransport()
        gw, audit = make(transport)
        with self.assertRaises(RequestTooLarge):
            gw.complete(user("x" * (MAX_TOTAL_CHARS + 1)), purpose="test")
        self.assertEqual(transport.calls, [])
        self.assertEqual(audit.entries[0].reason, "request size limit")

    def test_empty_request_is_blocked(self) -> None:
        gw, _ = make(FakeTransport())
        with self.assertRaises(RequestTooLarge):
            gw.complete([], purpose="test")


class EndpointTest(unittest.TestCase):
    def test_plain_http_to_remote_host_is_refused(self) -> None:
        with self.assertRaises(GatewayError):
            make(
                FakeTransport(), provider="openai_compatible", api_base="http://llm.example.net/v1"
            )

    def test_compatible_provider_needs_a_base_url(self) -> None:
        with self.assertRaises(GatewayError):
            make(FakeTransport(), provider="openai_compatible")

    def test_https_compatible_endpoint_is_allowed_and_used(self) -> None:
        transport = FakeTransport()
        gw, _ = make(transport, provider="openai_compatible", api_base="https://llm.example.net/v1")
        gw.complete(user("hi"), purpose="test")
        self.assertEqual(transport.calls[0]["api_base"], "https://llm.example.net/v1")
        self.assertEqual(gw.policy.hosts, frozenset({"llm.example.net"}))

    def test_abacus_routellm_settings_are_accepted(self) -> None:
        """README settings for Abacus RouteLLM (documented OpenAI compatible API)."""
        transport = FakeTransport()
        gw, _ = make(
            transport, provider="openai_compatible", api_base="https://routellm.abacus.ai/v1"
        )
        gw.complete(user("hi"), purpose="test")
        self.assertEqual(transport.calls[0]["model"], "openai/some-model")
        self.assertEqual(transport.calls[0]["api_base"], "https://routellm.abacus.ai/v1")
        self.assertEqual(gw.policy.hosts, frozenset({"routellm.abacus.ai"}))

    def test_unknown_provider_is_refused(self) -> None:
        with self.assertRaises(GatewayError):
            make(FakeTransport(), provider="mystery")

    def test_cloud_provider_without_key_is_refused(self) -> None:
        with self.assertRaises(GatewayError):
            make(FakeTransport(), api_key=None)


class ProviderFailureTest(unittest.TestCase):
    def test_error_is_recorded_by_type_without_content(self) -> None:
        echo = RuntimeError(f"bad request containing {API_KEY.get_secret_value()}")
        gw, audit = make(FakeTransport(error=echo))
        with self.assertRaises(ProviderError) as ctx:
            gw.complete(user("hello"), purpose="test")
        self.assertNotIn(API_KEY.get_secret_value(), str(ctx.exception))
        self.assertEqual(audit.entries[0].outcome, "error")
        self.assertEqual(audit.entries[0].reason, "RuntimeError")
        self.assertNotIn(API_KEY.get_secret_value(), audit.entries[0].model_dump_json())


class LiteLLMTransportTest(unittest.TestCase):
    def test_disables_remote_price_list_and_passes_explicit_endpoint(self) -> None:
        transport = LiteLLMTransport()
        self.assertEqual(os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP"), "True")
        fake_reply = mock.Mock()
        fake_reply.choices = [mock.Mock(message=mock.Mock(content="pong"))]
        with mock.patch.object(transport._litellm, "completion", return_value=fake_reply) as call:
            out = transport.send(
                model="anthropic/m",
                messages=[{"role": "user", "content": "hi"}],
                api_key="k",
                api_base="https://api.anthropic.com",
                max_tokens=10,
                timeout=5,
            )
        self.assertEqual(out, "pong")
        kwargs = call.call_args.kwargs
        self.assertEqual(kwargs["api_base"], "https://api.anthropic.com")
        self.assertEqual(kwargs["num_retries"], 0)


if __name__ == "__main__":
    unittest.main()
