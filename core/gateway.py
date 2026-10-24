"""The LLM gateway: the only way any code reaches a model (task K07).

Criteria S1-07 and S1-09; threats T1, T2, T6 and T10.

Every call goes through these steps, in order:

1. Size limits, so a runaway loop cannot send huge amounts of data.
2. Secret scan. Any finding blocks the call. The audit record notes the
   kind of secret and line, never the text.
3. Redaction. Real identifiers become placeholders.
4. Leak check. The redacted text is checked again for every real value the
   redactor knows and for every configured secret.
5. Egress check. The endpoint host must be on the allowlist.
6. The call itself, through a transport (LiteLLM in production).
7. Audit record of exactly what was sent and received, still redacted.
8. Placeholders in the reply are restored locally.

Errors from the model are recorded by type only, because error messages from
some providers can echo request content.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import SecretStr

from core.audit import AuditEntry, AuditSink
from core.egress import EgressDenied, EgressPolicy, host_of, is_loopback
from core.redaction import Redactor
from core.secret_scan import find_secrets

MAX_MESSAGES = 50
MAX_TOTAL_CHARS = 60_000
MAX_REPLY_TOKENS = 4_000
TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class ProviderInfo:
    litellm_prefix: str
    default_base: str | None
    needs_key: bool = True


# Default endpoints confirmed in the LiteLLM 1.106.2 source on 2026-10-23.
# "openai_compatible" has no default: the owner must set APP_LLM_API_BASE.
PROVIDERS: dict[str, ProviderInfo] = {
    "anthropic": ProviderInfo("anthropic", "https://api.anthropic.com"),
    "openai": ProviderInfo("openai", "https://api.openai.com/v1"),
    "google": ProviderInfo("gemini", "https://generativelanguage.googleapis.com"),
    "ollama": ProviderInfo("ollama", "http://localhost:11434", needs_key=False),
    "openai_compatible": ProviderInfo("openai", None),
}


class GatewayError(Exception):
    """Base class. Messages never contain request content or secrets."""


class SecretDetected(GatewayError):
    def __init__(self, kinds: list[str]) -> None:
        super().__init__("blocked: possible secret found (" + ", ".join(kinds) + ")")
        self.kinds = kinds


class RequestTooLarge(GatewayError):
    pass


class LeakDetected(GatewayError):
    pass


class ProviderError(GatewayError):
    pass


@dataclass(frozen=True)
class Message:
    role: Literal["system", "user", "assistant"]
    content: str


class Transport(Protocol):
    def send(
        self,
        model: str,
        messages: list[dict[str, str]],
        api_key: str | None,
        api_base: str,
        max_tokens: int,
        timeout: int,
    ) -> str: ...


class LiteLLMTransport:
    """Sends through LiteLLM with its remote downloads switched off."""

    def __init__(self) -> None:
        # Without this, LiteLLM downloads a model price list at import time.
        os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
        import litellm

        self._litellm = litellm

    def send(
        self,
        model: str,
        messages: list[dict[str, str]],
        api_key: str | None,
        api_base: str,
        max_tokens: int,
        timeout: int,
    ) -> str:
        response = self._litellm.completion(
            model=model,
            messages=messages,
            api_key=api_key,
            api_base=api_base,
            max_tokens=max_tokens,
            timeout=timeout,
            num_retries=0,
        )
        content = response.choices[0].message.content
        return str(content or "")


def resolve_endpoint(provider: str, api_base: str | None) -> tuple[ProviderInfo, str]:
    info = PROVIDERS.get(provider)
    if info is None:
        raise GatewayError(f"unsupported provider '{provider}'. Choose one of: {sorted(PROVIDERS)}")
    base = api_base or info.default_base
    if not base:
        raise GatewayError(f"provider '{provider}' needs APP_LLM_API_BASE")
    scheme = base.split(":", 1)[0].lower()
    if scheme != "https" and not (scheme == "http" and is_loopback(host_of(base))):
        raise GatewayError("LLM endpoint must use HTTPS unless it runs on this machine")
    return info, base


class Gateway:
    def __init__(
        self,
        provider: str,
        model: str,
        api_key: SecretStr | None,
        transport: Transport,
        audit: AuditSink,
        redactor: Redactor | None = None,
        api_base: str | None = None,
        extra_allowed_hosts: Iterable[str] = (),
        known_secrets: Iterable[SecretStr] = (),
    ) -> None:
        self.provider = provider
        self.model = model
        self.info, self.api_base = resolve_endpoint(provider, api_base)
        if self.info.needs_key and api_key is None:
            raise GatewayError(f"provider '{provider}' needs an API key")
        self._api_key = api_key
        self.host = host_of(self.api_base)
        self.policy = EgressPolicy([self.host, *extra_allowed_hosts])
        self._transport = transport
        self._audit = audit
        self.redactor = redactor or Redactor()
        secrets = list(known_secrets)
        if api_key is not None:
            secrets.append(api_key)
        self._known_secrets = secrets

    # --------------------------------------------------------------- helpers

    def _entry(self, purpose: str, **fields: object) -> AuditEntry:
        return AuditEntry(
            purpose=purpose,
            provider=self.provider,
            model=self.model,
            host=self.host,
            **fields,
        )

    def _block(self, purpose: str, reason: str, error: GatewayError) -> GatewayError:
        self._audit.record(self._entry(purpose, outcome="blocked", reason=reason))
        return error

    # ------------------------------------------------------------------ call

    def complete(
        self, messages: list[Message], purpose: str, redactor: Redactor | None = None
    ) -> str:
        """Send messages through every check. Pass a redactor to keep
        placeholders stable for one conversation; otherwise the gateway's own
        redactor is used."""
        r = redactor or self.redactor
        # 1. Size limits.
        total = sum(len(m.content) for m in messages)
        if not messages or len(messages) > MAX_MESSAGES or total > MAX_TOTAL_CHARS:
            raise self._block(
                purpose, "request size limit", RequestTooLarge("request is empty or too large")
            )

        # 2. Secret scan on the original text.
        kinds: list[str] = []
        for m in messages:
            kinds += [f.kind for f in find_secrets(m.content, self._known_secrets)]
        if kinds:
            unique = sorted(set(kinds))
            raise self._block(
                purpose, "secret detected: " + ", ".join(unique), SecretDetected(unique)
            )

        # 3. Redaction.
        before = dict(r.counts)
        outgoing = [{"role": m.role, "content": r.redact(m.content)} for m in messages]
        redactions = {k: v - before.get(k, 0) for k, v in r.counts.items() if v - before.get(k, 0)}

        # 4. Leak check on what would actually be sent.
        sent_text = "\n".join(m["content"] for m in outgoing)
        lowered = sent_text.lower()
        if any(real.lower() in lowered for real in r.real_values()):
            raise self._block(
                purpose, "leak check failed", LeakDetected("redaction left a real value")
            )
        if find_secrets(sent_text, self._known_secrets):
            raise self._block(purpose, "leak check failed", LeakDetected("secret after redaction"))

        # 5. Egress check.
        if not self.policy.allows(self.host):
            raise self._block(purpose, "host not allowed", GatewayError("endpoint not allowed"))

        # 6. Call.
        try:
            reply = self._transport.send(
                model=f"{self.info.litellm_prefix}/{self.model}",
                messages=outgoing,
                api_key=self._api_key.get_secret_value() if self._api_key else None,
                api_base=self.api_base,
                max_tokens=MAX_REPLY_TOKENS,
                timeout=TIMEOUT_SECONDS,
            )
        except EgressDenied:
            self._audit.record(
                self._entry(purpose, outcome="blocked", reason="egress guard", request=outgoing)
            )
            raise
        except Exception as exc:  # noqa: BLE001  # provider errors may echo content
            self._audit.record(
                self._entry(
                    purpose,
                    outcome="error",
                    reason=type(exc).__name__,
                    request=outgoing,
                    redactions=redactions,
                )
            )
            raise ProviderError(f"the model call failed ({type(exc).__name__})") from None

        # 7. Audit exactly what crossed the wire, still redacted.
        self._audit.record(
            self._entry(
                purpose, outcome="sent", request=outgoing, response=reply, redactions=redactions
            )
        )

        # 8. Restore locally.
        return r.restore(reply)


def gateway_from_settings(audit: AuditSink, transport: Transport | None = None) -> Gateway:
    """Build the production gateway from .env and the OS keychain."""
    from core.config import get_api_key, load_settings

    settings = load_settings()
    info = PROVIDERS.get(settings.llm_provider)
    key: SecretStr | None = None
    if info is None or info.needs_key:
        key, _ = get_api_key(settings)
    return Gateway(
        provider=settings.llm_provider,
        model=settings.llm_model,
        api_key=key,
        transport=transport or LiteLLMTransport(),
        audit=audit,
        api_base=settings.llm_api_base or None,
    )
