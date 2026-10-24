"""Secret scanning for anything that may leave the machine (threat T1, criterion S1-09).

Two layers:

1. Named detectors from detect-secrets (AWS keys, private keys, Azure storage
   keys, JSON web tokens, GitHub tokens, password assignments and more), plus
   a few extra patterns. The generic "high entropy" detectors are not used:
   on plain text they flag ordinary English.
2. Exact match against secrets this app knows about, such as the configured
   LLM API key, so it can never be sent even if no pattern recognises it.

Findings name the kind and line, never the secret itself.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from detect_secrets.core.scan import scan_line
from detect_secrets.settings import default_settings
from pydantic import SecretStr

IGNORED_TYPES = frozenset({"Base64 High Entropy String", "Hex High Entropy String"})

EXTRA_PATTERNS: dict[str, re.Pattern[str]] = {
    "Private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Azure connection string key": re.compile(
        r"(?i)\b(AccountKey|SharedAccessKey)\s*=\s*[^;\s]{16,}"
    ),
    "Azure SAS signature": re.compile(r"(?i)[?&]sig=[A-Za-z0-9%+/=]{20,}"),
    "Anthropic API key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI style API key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
}


@dataclass(frozen=True)
class Finding:
    kind: str
    line: int


def find_secrets(text: str, known: Iterable[SecretStr] = ()) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines() or [text]
    with default_settings():
        for number, line in enumerate(lines, start=1):
            for found in scan_line(line):
                if found.type not in IGNORED_TYPES:
                    findings.append(Finding(found.type, number))
            for kind, pattern in EXTRA_PATTERNS.items():
                if pattern.search(line):
                    findings.append(Finding(kind, number))
    for secret in known:
        value = secret.get_secret_value()
        if len(value) >= 8 and value in text:
            line_no = text[: text.index(value)].count("\n") + 1
            findings.append(Finding("Configured secret", line_no))
    # One finding per kind and line is enough.
    return sorted(set(findings), key=lambda f: (f.line, f.kind))
