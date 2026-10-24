"""Redaction and tokenisation before any LLM call (threat T2, criterion S1-07).

Sensitive values are swapped for placeholders such as SUBSCRIPTION_1 before
text leaves the machine. The map from placeholder to real value stays in
memory on this machine and is never logged or sent anywhere. Replies from the
LLM have placeholders swapped back locally.

Detected automatically: email addresses, domain names, GUIDs (tenant,
subscription and object IDs), network ranges and IPv4 addresses.
Registered by the caller: values the code cannot recognise on its own, such
as company names, or GUIDs whose role is known (tenant or subscription).
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter

PLACEHOLDER_KINDS = (
    "TENANT",
    "SUBSCRIPTION",
    "ID",
    "EMAIL",
    "DOMAIN",
    "CIDR",
    "IP",
    "COMPANY",
    "GROUP",
)

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
_GUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_CIDR = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w.])")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w./])")
_DOMAIN = re.compile(
    r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w-])"
)

# Last labels that are file extensions in this project, not domains.
FILE_EXTENSIONS = frozenset(
    {
        "tf",
        "tfvars",
        "hcl",
        "json",
        "py",
        "md",
        "yaml",
        "yml",
        "txt",
        "sh",
        "xml",
        "html",
        "js",
        "ts",
        "tsx",
        "css",
        "toml",
        "cfg",
        "ini",
        "lock",
        "log",
        "drawio",
        "csv",
        "env",
    }
)
# Public documentation and registry domains that reveal nothing about the user.
PUBLIC_DOMAINS = (
    "learn.microsoft.com",
    "microsoft.com",
    "azure.com",
    "terraform.io",
    "hashicorp.com",
    "github.com",
)


def _is_public(domain: str) -> bool:
    d = domain.lower()
    return any(d == p or d.endswith("." + p) for p in PUBLIC_DOMAINS)


class Redactor:
    """One redactor per conversation, so placeholders stay stable across turns."""

    def __init__(self) -> None:
        self._to_placeholder: dict[str, str] = {}
        self._to_real: dict[str, str] = {}
        self._next: Counter[str] = Counter()
        self._registered: dict[str, str] = {}  # real value -> kind
        self._seen_text_tokens: set[str] = set()
        self.counts: Counter[str] = Counter()

    # ------------------------------------------------------------ registration

    def register(self, value: str, kind: str) -> str:
        """Register a value the detectors cannot find, such as a company name."""
        if kind not in PLACEHOLDER_KINDS:
            raise ValueError(f"unknown placeholder kind {kind}")
        value = value.strip()
        if len(value) < 2:
            raise ValueError("value to redact is too short")
        self._registered[value] = kind
        return self._placeholder_for(value, kind)

    # ------------------------------------------------------------------- core

    def _placeholder_for(self, value: str, kind: str) -> str:
        key = value.lower() if kind in ("EMAIL", "DOMAIN", "COMPANY", "ID") else value
        if key in self._to_placeholder:
            return self._to_placeholder[key]
        while True:
            self._next[kind] += 1
            token = f"{kind}_{self._next[kind]}"
            # Never issue a token the user has typed themselves.
            if token not in self._seen_text_tokens:
                break
        self._to_placeholder[key] = token
        self._to_real[token] = value
        return token

    def _sub(self, pattern: re.Pattern[str], text: str, kind_for: object) -> str:
        def replace(match: re.Match[str]) -> str:
            value = match.group(0)
            kind = kind_for(value) if callable(kind_for) else kind_for
            if kind is None:
                return value
            self.counts[str(kind)] += 1
            return self._placeholder_for(value, str(kind))

        return pattern.sub(replace, text)

    def redact(self, text: str) -> str:
        self._seen_text_tokens.update(
            re.findall(r"\b(?:" + "|".join(PLACEHOLDER_KINDS) + r")_\d+\b", text)
        )
        # Registered literal values first, longest first, whole words only.
        for value in sorted(self._registered, key=len, reverse=True):
            kind = self._registered[value]
            pattern = re.compile(r"(?<!\w)" + re.escape(value) + r"(?!\w)", re.IGNORECASE)
            text = self._sub(pattern, text, kind)
        text = self._sub(_EMAIL, text, "EMAIL")
        text = self._sub(_GUID, text, self._guid_kind)
        text = self._sub(_CIDR, text, self._cidr_kind)
        text = self._sub(_IPV4, text, self._ip_kind)
        text = self._sub(_DOMAIN, text, self._domain_kind)
        return text

    def restore(self, text: str) -> str:
        """Swap placeholders this redactor issued back to real values (local only)."""
        if not self._to_real:
            return text
        tokens = sorted(self._to_real, key=len, reverse=True)
        pattern = re.compile(r"\b(?:" + "|".join(re.escape(t) for t in tokens) + r")\b")
        return pattern.sub(lambda m: self._to_real[m.group(0)], text)

    def real_values(self) -> list[str]:
        """Every real value this redactor has hidden. For leak checks only."""
        return list(self._to_real.values())

    # ------------------------------------------------------------- detectors

    def _guid_kind(self, value: str) -> str:
        for real, kind in self._registered.items():
            if real.lower() == value.lower():
                return kind
        return "ID"

    @staticmethod
    def _cidr_kind(value: str) -> str | None:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        return "CIDR"

    @staticmethod
    def _ip_kind(value: str) -> str | None:
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            return None
        return "IP"

    @staticmethod
    def _domain_kind(value: str) -> str | None:
        last = value.rsplit(".", 1)[-1].lower()
        if last in FILE_EXTENSIONS or last.isdigit() or _is_public(value):
            return None
        return "DOMAIN"
