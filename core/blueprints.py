"""Reference blueprints (task K06, criteria S1-02 and S1-03).

A blueprint is a reviewed starting design for a common requirement. It lists:

* the resources, their dependencies and a plain English explanation of each,
  with the official source that backs it;
* the facts the design relies on, each with its source and the date checked;
* the questions discovery must ask, in rounds;
* secure default network rules.

Blueprints are data files under blueprints/<cloud>/. They are validated when
loaded, and a blueprint must be able to produce a valid draft spec from its
defaults, so a broken blueprint can never reach a user.
"""

from __future__ import annotations

import json
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from core.branding import REPO_ROOT
from core.spec import (
    Access,
    Approval,
    Explanation,
    HttpsUrl,
    Id,
    Identity,
    Kind,
    Network,
    Resource,
    Scope,
    SettingValue,
    ShortText,
    Spec,
    Strict,
)

BLUEPRINT_DIR = REPO_ROOT / "blueprints"
OFFICIAL_SOURCE_PREFIXES = ("https://learn.microsoft.com/",)
NameTemplate = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9-]{0,20}\{project\}[a-z0-9-]{0,20}$")
]


class Fact(Strict):
    id: Id
    statement: Annotated[str, StringConstraints(min_length=1, max_length=600)]
    source: HttpsUrl
    checked: date


class BlueprintResource(Strict):
    id: Id
    kind: Kind
    name_template: NameTemplate
    depends_on: list[Id] = Field(default_factory=list, max_length=50)
    settings: dict[Id, SettingValue] = Field(default_factory=dict, max_length=50)
    facts: list[Id] = Field(default_factory=list, max_length=20)
    explanation: Explanation


class Option(Strict):
    value: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    label: ShortText


class Question(Strict):
    id: Id
    round: int = Field(ge=1, le=5)
    text: ShortText
    why: ShortText
    answer: Literal["choice", "text", "region", "cidr", "port", "principal_list"]
    options: list[Option] = Field(default_factory=list, max_length=20)
    default: str | None = None
    required: bool = True

    @model_validator(mode="after")
    def options_match_answer(self) -> Question:
        if self.answer == "choice":
            if len(self.options) < 2:
                raise ValueError(f"question '{self.id}' is a choice but has fewer than 2 options")
            values = [o.value for o in self.options]
            if len(set(values)) != len(values):
                raise ValueError(f"question '{self.id}' has duplicate option values")
            if self.default is not None and self.default not in values:
                raise ValueError(f"question '{self.id}' default is not one of its options")
        elif self.options:
            raise ValueError(f"question '{self.id}' has options but is not a choice")
        return self


class Blueprint(Strict):
    blueprint_version: Literal["1.0"]
    id: Id
    cloud: Literal["azure"]
    title: ShortText
    summary: Annotated[str, StringConstraints(min_length=1, max_length=2000)]
    match_phrases: list[ShortText] = Field(min_length=1, max_length=50)
    facts: list[Fact] = Field(min_length=1, max_length=100)
    resources: list[BlueprintResource] = Field(min_length=1, max_length=100)
    default_network: Network
    default_access: list[Access] = Field(default_factory=list, max_length=20)
    questions: list[Question] = Field(min_length=1, max_length=100)
    known_gaps: list[ShortText] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def internal_checks(self) -> Blueprint:
        problems: list[str] = []
        fact_ids = [f.id for f in self.facts]
        if len(set(fact_ids)) != len(fact_ids):
            problems.append("duplicate fact id")
        for fact in self.facts:
            if not fact.source.startswith(OFFICIAL_SOURCE_PREFIXES):
                problems.append(f"fact '{fact.id}' must cite official documentation")
        for res in self.resources:
            for fid in res.facts:
                if fid not in fact_ids:
                    problems.append(f"resource '{res.id}' cites unknown fact '{fid}'")
            if not res.explanation.verified:
                problems.append(f"resource '{res.id}' explanation must be verified")
            for src in res.explanation.sources:
                if not src.startswith(OFFICIAL_SOURCE_PREFIXES):
                    problems.append(f"resource '{res.id}' must cite official documentation")
        question_ids = [q.id for q in self.questions]
        if len(set(question_ids)) != len(question_ids):
            problems.append("duplicate question id")
        if problems:
            raise ValueError("; ".join(problems))
        # The blueprint must produce a valid spec from its own defaults. This
        # reuses every spec check: ids, dependencies, loops, network, guardrails.
        draft_spec(self, project_id="blueprint-self-check", region="selfcheck")
        return self


def draft_spec(
    blueprint: Blueprint,
    project_id: str,
    region: str,
    tenant: Identity | None = None,
    subscription: Identity | None = None,
) -> Spec:
    """Build an unapproved draft spec from the blueprint's defaults."""
    resources = [
        Resource(
            id=r.id,
            kind=r.kind,
            name=r.name_template.replace("{project}", project_id),
            depends_on=list(r.depends_on),
            settings=dict(r.settings),
            explanation=r.explanation,
        )
        for r in blueprint.resources
    ]
    return Spec(
        schema_version="1.0",
        project_id=project_id,
        cloud=blueprint.cloud,
        blueprint=blueprint.id,
        region=region,
        scope=Scope(
            tenant=tenant or Identity(placeholder="TENANT_1", mode="existing"),
            subscription=subscription or Identity(placeholder="SUBSCRIPTION_1", mode="existing"),
        ),
        resources=resources,
        network=blueprint.default_network,
        access=list(blueprint.default_access),
        approval=Approval(),
    )


def load_blueprint(path: Path) -> Blueprint:
    return Blueprint.model_validate_json(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def all_blueprints() -> dict[str, Blueprint]:
    """Load and validate every blueprint file. Raises on the first bad one."""
    found: dict[str, Blueprint] = {}
    for path in sorted(BLUEPRINT_DIR.glob("*/*.json")):
        bp = load_blueprint(path)
        if bp.id in found:
            raise ValueError(f"duplicate blueprint id '{bp.id}'")
        if path.stem != bp.id or path.parent.name != bp.cloud:
            raise ValueError(f"{path.name} must live at blueprints/{bp.cloud}/{bp.id}.json")
        found[bp.id] = bp
    return found


def blueprint_json_schema() -> str:
    return json.dumps(Blueprint.model_json_schema(), indent=2, sort_keys=True) + "\n"
