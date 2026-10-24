"""Infrastructure spec: the single source of truth (task K05, criterion S1-05).

The spec is the agreed design. Terraform code and diagrams are generated from
it in later slices. It is validated in two layers:

1. Structure: strict Pydantic models. Unknown fields, wrong types and
   oversized values are rejected, so malformed LLM output can never become a
   spec (OWASP Top 10 for LLM Applications: LLM05 improper output handling).
2. Meaning: cross checks such as unique ids, dependencies that exist and do
   not loop, subnets inside the network and not overlapping, and secure
   default guardrails (no public IP on compute, no SSH or RDP open to the
   internet: CIS Microsoft Azure Foundations, networking section).

Resource kinds are logical names, not Terraform types. Mapping kinds to
verified provider resource types happens in Slice 2.

Azure security rule facts below were checked on Microsoft Learn on 2026-10-23:
https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups/securityrules
(API version 2026-03-01: priority 100 to 4096, protocols, ports 0 to 65535)
https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview
(rule names, priority unique within the inbound set and within the outbound set)
https://learn.microsoft.com/azure/application-gateway/configuration-infrastructure
(GatewayManager service tag for Application Gateway v2)
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------- basic types

Id = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
Name = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")]
# Security rule names: up to 80 characters, start with a word character, end
# with a word character or underscore (Microsoft Learn, NSG overview).
RuleName = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9_]([A-Za-z0-9._-]{0,78}[A-Za-z0-9_])?$")
]
Placeholder = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z]*(_[A-Z]+)*_[0-9]{1,4}$")]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=500)]
LongText = Annotated[str, StringConstraints(min_length=1, max_length=2000)]
Region = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]{1,39}$")]
HttpsUrl = Annotated[str, StringConstraints(pattern=r"^https://[^\s]{1,300}$")]
SettingValue = str | int | bool

GUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# Service tags confirmed in the Microsoft Learn pages cited above. Add others
# only after checking official docs.
SERVICE_TAGS = frozenset({"VirtualNetwork", "AzureLoadBalancer", "Internet", "GatewayManager"})
ANY_SOURCE = frozenset({"*", "Internet", "0.0.0.0/0"})
MANAGEMENT_PORTS = (22, 3389)
PRIVATE_RANGES = tuple(
    ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


# --------------------------------------------------------------------- models


class Kind(StrEnum):
    RESOURCE_GROUP = "resource_group"
    VIRTUAL_NETWORK = "virtual_network"
    SUBNET = "subnet"
    NETWORK_SECURITY_GROUP = "network_security_group"
    VIRTUAL_MACHINE = "virtual_machine"
    APPLICATION_GATEWAY = "application_gateway"
    PUBLIC_IP = "public_ip"
    ROLE_ASSIGNMENT = "role_assignment"


class Explanation(Strict):
    what: LongText
    why: LongText
    region_notes: LongText | None = None
    cost_note: LongText | None = None
    verified: bool = False
    sources: list[HttpsUrl] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def verified_needs_sources(self) -> Explanation:
        if self.verified and not self.sources:
            raise ValueError("an explanation marked verified must cite at least one source")
        return self


class Resource(Strict):
    id: Id
    kind: Kind
    name: Name
    depends_on: list[Id] = Field(default_factory=list, max_length=50)
    settings: dict[Id, SettingValue] = Field(default_factory=dict, max_length=50)
    explanation: Explanation


class Identity(Strict):
    placeholder: Placeholder
    mode: Literal["existing", "new"]


class Scope(Strict):
    tenant: Identity
    subscription: Identity


class Subnet(Strict):
    resource_id: Id
    cidr: str
    nsg_id: Id | None = None


class NsgRule(Strict):
    nsg_id: Id
    name: RuleName
    description: Annotated[str, StringConstraints(max_length=140)] = ""
    priority: int = Field(ge=100, le=4096)
    direction: Literal["Inbound", "Outbound"]
    access: Literal["Allow", "Deny"]
    protocol: Literal["Tcp", "Udp", "Icmp", "Esp", "Ah", "*"]
    source: str
    source_ports: str = "*"
    destination: str
    destination_ports: str


class Network(Strict):
    vnet_id: Id
    address_space: list[str] = Field(min_length=1, max_length=10)
    subnets: list[Subnet] = Field(default_factory=list, max_length=50)
    nsg_rules: list[NsgRule] = Field(default_factory=list, max_length=200)


class Access(Strict):
    principal: Placeholder
    role: Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9 ._-]{1,99}$")]
    scope_resource: Id


class Decision(Strict):
    question: ShortText
    answer: ShortText


class Approval(Strict):
    approved: bool = False
    approved_at: datetime | None = None
    version: Annotated[str, StringConstraints(pattern=r"^v[1-9][0-9]{0,5}$")] | None = None

    @model_validator(mode="after")
    def consistent(self) -> Approval:
        if self.approved and (self.approved_at is None or self.version is None):
            raise ValueError("an approved spec needs approved_at and version")
        if not self.approved and (self.approved_at is not None or self.version is not None):
            raise ValueError("a draft spec must not carry approved_at or version")
        return self


class Spec(Strict):
    schema_version: Literal["1.0"]
    project_id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")]
    cloud: Literal["azure"]
    blueprint: Id
    region: Region
    scope: Scope
    resources: list[Resource] = Field(min_length=1, max_length=200)
    network: Network | None = None
    access: list[Access] = Field(default_factory=list, max_length=100)
    decisions: list[Decision] = Field(default_factory=list, max_length=200)
    approval: Approval = Field(default_factory=Approval)

    @model_validator(mode="after")
    def cross_checks(self) -> Spec:
        problems: list[str] = []
        by_id = _check_ids_and_dependencies(self.resources, problems)
        for access in self.access:
            if access.scope_resource not in by_id:
                problems.append(f"access scope '{access.scope_resource}' is not a resource")
        if self.network is not None:
            _check_network(self.network, by_id, problems)
        _check_guardrails(self, by_id, problems)
        if problems:
            raise ValueError("; ".join(problems))
        return self


# ------------------------------------------------------------- cross checks


def _check_ids_and_dependencies(
    resources: list[Resource], problems: list[str]
) -> dict[str, Resource]:
    by_id: dict[str, Resource] = {}
    for res in resources:
        if res.id in by_id:
            problems.append(f"duplicate resource id '{res.id}'")
        by_id[res.id] = res
    for res in resources:
        for dep in res.depends_on:
            if dep not in by_id:
                problems.append(f"'{res.id}' depends on unknown resource '{dep}'")
            elif dep == res.id:
                problems.append(f"'{res.id}' depends on itself")
    cycle = _find_cycle(by_id)
    if cycle:
        problems.append("dependency loop: " + " -> ".join(cycle))
    return by_id


def _find_cycle(by_id: dict[str, Resource]) -> list[str] | None:
    state: dict[str, int] = {}  # 1 = visiting, 2 = done
    path: list[str] = []

    def visit(node: str) -> list[str] | None:
        state[node] = 1
        path.append(node)
        for dep in by_id[node].depends_on:
            if dep not in by_id or dep == node:
                continue
            if state.get(dep) == 1:
                return path[path.index(dep) :] + [dep]
            if dep not in state:
                found = visit(dep)
                if found:
                    return found
        path.pop()
        state[node] = 2
        return None

    for node in by_id:
        if node not in state:
            found = visit(node)
            if found:
                return found
    return None


def _require_kind(
    ref: str, kind: Kind, by_id: dict[str, Resource], what: str, problems: list[str]
) -> None:
    res = by_id.get(ref)
    if res is None:
        problems.append(f"{what} '{ref}' is not a resource")
    elif res.kind != kind:
        problems.append(f"{what} '{ref}' must be a {kind.value}, not {res.kind.value}")


def _parse_cidr(value: str, what: str, problems: list[str]) -> ipaddress.IPv4Network | None:
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError:
        problems.append(f"{what} '{value}' is not a valid network range")
        return None
    if not isinstance(net, ipaddress.IPv4Network):
        problems.append(f"{what} '{value}' must be IPv4 in this version")
        return None
    return net


def _check_network(network: Network, by_id: dict[str, Resource], problems: list[str]) -> None:
    _require_kind(network.vnet_id, Kind.VIRTUAL_NETWORK, by_id, "vnet_id", problems)

    spaces = []
    for cidr in network.address_space:
        net = _parse_cidr(cidr, "address space", problems)
        if net is None:
            continue
        if not any(net.subnet_of(r) for r in PRIVATE_RANGES):
            problems.append(f"address space '{cidr}' must be a private range (RFC 1918)")
        spaces.append(net)

    subnets: list[tuple[str, ipaddress.IPv4Network]] = []
    for subnet in network.subnets:
        _require_kind(subnet.resource_id, Kind.SUBNET, by_id, "subnet", problems)
        if subnet.nsg_id is not None:
            _require_kind(subnet.nsg_id, Kind.NETWORK_SECURITY_GROUP, by_id, "nsg", problems)
        net = _parse_cidr(subnet.cidr, f"subnet '{subnet.resource_id}' range", problems)
        if net is None:
            continue
        if spaces and not any(net.subnet_of(space) for space in spaces):
            problems.append(f"subnet '{subnet.resource_id}' {net} is outside the address space")
        for other_id, other in subnets:
            if net.overlaps(other):
                problems.append(f"subnets '{other_id}' and '{subnet.resource_id}' overlap")
        subnets.append((subnet.resource_id, net))

    seen_priorities: set[tuple[str, str, int]] = set()
    for rule in network.nsg_rules:
        label = f"rule '{rule.name}'"
        _require_kind(rule.nsg_id, Kind.NETWORK_SECURITY_GROUP, by_id, f"{label} nsg", problems)
        key = (rule.nsg_id, rule.direction, rule.priority)
        if key in seen_priorities:
            problems.append(
                f"{label}: priority {rule.priority} is already used for "
                f"{rule.direction.lower()} rules in that group"
            )
        seen_priorities.add(key)
        for field, value in (("source", rule.source), ("destination", rule.destination)):
            if not _valid_prefix(value):
                problems.append(f"{label}: {field} '{value}' is not a range, '*' or known tag")
        for field, value in (
            ("source_ports", rule.source_ports),
            ("destination_ports", rule.destination_ports),
        ):
            if parse_ports(value) is None:
                problems.append(f"{label}: {field} '{value}' is not a valid port or range")


def _valid_prefix(value: str) -> bool:
    if value == "*" or value in SERVICE_TAGS:
        return True
    try:
        ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False
    return True


def parse_ports(value: str) -> tuple[int, int] | None:
    """'*' -> (0, 65535); '443' -> (443, 443); '1000-2000' -> (1000, 2000)."""
    if value == "*":
        return (0, 65535)
    match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", value)
    if not match:
        return None
    low = int(match.group(1))
    high = int(match.group(2) or low)
    if not 0 <= low <= high <= 65535:
        return None
    return (low, high)


def _check_guardrails(spec: Spec, by_id: dict[str, Resource], problems: list[str]) -> None:
    # No public IP on compute (project guardrail: private by default).
    for res in spec.resources:
        if res.kind is Kind.VIRTUAL_MACHINE:
            for dep in res.depends_on:
                if dep in by_id and by_id[dep].kind is Kind.PUBLIC_IP:
                    problems.append(f"virtual machine '{res.id}' must not use a public IP")

    # No SSH or RDP open to the whole internet (CIS Azure Foundations).
    if spec.network is not None:
        for rule in spec.network.nsg_rules:
            if rule.direction != "Inbound" or rule.access != "Allow":
                continue
            if rule.source not in ANY_SOURCE or rule.protocol not in ("Tcp", "*"):
                continue
            ports = parse_ports(rule.destination_ports)
            if ports and any(ports[0] <= p <= ports[1] for p in MANAGEMENT_PORTS):
                problems.append(
                    f"rule '{rule.name}' opens SSH or RDP to the internet; use a bastion "
                    "or a restricted source range"
                )

    # Identifiers are stored as placeholders, never as real IDs.
    for path in _find_guids(spec.model_dump(mode="json")):
        problems.append(f"real looking ID found at {path}; use a placeholder such as TENANT_1")


def _find_guids(value: Any, path: str = "spec") -> list[str]:
    if isinstance(value, str):
        return [path] if GUID_PATTERN.search(value) else []
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _find_guids(v, f"{path}.{k}")]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _find_guids(v, f"{path}[{i}]")]
    return []


# ------------------------------------------------------------------- helpers


def json_schema() -> dict[str, Any]:
    schema = Spec.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "Infrastructure spec"
    return schema


def schema_text() -> str:
    return json.dumps(json_schema(), indent=2, sort_keys=True) + "\n"


def load_spec(text: str) -> Spec:
    """Parse and validate a spec from JSON text. Raises pydantic.ValidationError."""
    return Spec.model_validate_json(text)
