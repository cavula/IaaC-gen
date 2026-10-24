"""Outbound audit records (criterion S1-08, threat T8).

The gateway writes one record for every attempted LLM call, including calls
it blocks. Records hold only what actually left the machine, after
redaction. Real values and the redaction map are never recorded.

Task K07 defines the record and an in memory sink. Task K08 adds the
persistent, append only store and the audit screen API.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


class AuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    purpose: str
    provider: str
    model: str
    host: str
    outcome: Literal["sent", "blocked", "error"]
    reason: str | None = None
    request: list[dict[str, str]] = Field(default_factory=list)
    response: str | None = None
    redactions: dict[str, int] = Field(default_factory=dict)


class AuditSink(Protocol):
    def record(self, entry: AuditEntry) -> None: ...


class MemoryAuditSink:
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)
