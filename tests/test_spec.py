"""Spec tests (task K05, criterion S1-05, threats T3 and T4)."""

from __future__ import annotations

import copy
import json
import unittest
from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from core.branding import REPO_ROOT
from core.spec import Spec, load_spec, parse_ports, schema_text

EXAMPLE = REPO_ROOT / "examples" / "specs" / "vm-behind-gateway.json"
SCHEMA_FILE = REPO_ROOT / "schemas" / "spec.schema.json"

Spec_ = dict[str, Any]


def example() -> Spec_:
    data: Spec_ = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    return data


def resource(data: Spec_, rid: str) -> dict[str, Any]:
    return next(r for r in data["resources"] if r["id"] == rid)


def rule(data: Spec_, name: str) -> dict[str, Any]:
    return next(r for r in data["network"]["nsg_rules"] if r["name"] == name)


class ValidSpecTest(unittest.TestCase):
    def test_example_spec_is_valid(self) -> None:
        spec = load_spec(EXAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(spec.cloud, "azure")
        self.assertFalse(spec.approval.approved)

    def test_round_trip_is_lossless(self) -> None:
        spec = load_spec(EXAMPLE.read_text(encoding="utf-8"))
        again = load_spec(spec.model_dump_json())
        self.assertEqual(spec, again)

    def test_approved_spec_is_valid(self) -> None:
        data = example()
        data["approval"] = {
            "approved": True,
            "approved_at": "2026-10-23T10:00:00Z",
            "version": "v1",
        }
        Spec.model_validate(data)

    def test_spec_objects_are_read_only(self) -> None:
        spec = load_spec(EXAMPLE.read_text(encoding="utf-8"))
        with self.assertRaises(ValidationError):
            spec.region = "eastus"  # type: ignore[misc]


class SchemaFileTest(unittest.TestCase):
    def test_committed_schema_matches_models(self) -> None:
        """Run scripts/export_schema.py after changing the models."""
        self.assertEqual(SCHEMA_FILE.read_text(encoding="utf-8"), schema_text())


Mutation = Callable[[Spec_], None]


def _set(path: list[Any], value: Any) -> Mutation:
    def apply(data: Spec_) -> None:
        target: Any = data
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return apply


def _do(fn: Callable[[Spec_], Any]) -> Mutation:
    def apply(data: Spec_) -> None:
        fn(data)

    return apply


INVALID: dict[str, Mutation] = {
    # Structure
    "unknown top level field": _set(["surprise"], True),
    "unknown nested field": _do(lambda d: resource(d, "vm").__setitem__("size", "huge")),
    "wrong schema version": _set(["schema_version"], "9.9"),
    "cloud not in MVP": _set(["cloud"], "aws"),
    "unknown resource kind": _do(lambda d: resource(d, "vm").__setitem__("kind", "mainframe")),
    "bad region format": _set(["region"], "West Europe"),
    "no resources": _set(["resources"], []),
    "missing explanation": _do(lambda d: resource(d, "vm").pop("explanation")),
    "oversized text": _do(
        lambda d: resource(d, "vm")["explanation"].__setitem__("why", "x" * 5000)
    ),
    "verified without source": _do(
        lambda d: resource(d, "vm")["explanation"].__setitem__("verified", True)
    ),
    "script in a name": _do(lambda d: resource(d, "vm").__setitem__("name", "<script>")),
    "nested setting value": _do(lambda d: resource(d, "vm")["settings"].__setitem__("x", {"a": 1})),
    # Identity and approval
    "real tenant id": _set(
        ["scope", "tenant", "placeholder"], "8f3c2a1e-1111-2222-3333-444455556666"
    ),
    "guid hidden in text": _do(
        lambda d: d["decisions"].append(
            {"question": "Subscription?", "answer": "8f3c2a1e-1111-2222-3333-444455556666"}
        )
    ),
    "email as principal": _do(lambda d: d["access"][0].__setitem__("principal", "a@b.com")),
    "approved without version": _set(["approval"], {"approved": True}),
    "draft with version": _set(["approval"], {"approved": False, "version": "v1"}),
    # Dependencies and references
    "duplicate id": _do(lambda d: d["resources"].append(copy.deepcopy(resource(d, "vm")))),
    "unknown dependency": _do(lambda d: resource(d, "vm")["depends_on"].append("ghost")),
    "self dependency": _do(lambda d: resource(d, "vm")["depends_on"].append("vm")),
    "dependency loop": _do(lambda d: resource(d, "rg").setdefault("depends_on", []).append("vm")),
    "access on unknown resource": _do(lambda d: d["access"][0].__setitem__("scope_resource", "x")),
    "vnet id wrong kind": _set(["network", "vnet_id"], "rg"),
    "subnet wrong kind": _do(lambda d: d["network"]["subnets"][0].__setitem__("resource_id", "vm")),
    # Addresses
    "invalid cidr": _do(lambda d: d["network"]["subnets"][0].__setitem__("cidr", "10.20.1.0/33")),
    "host bits set": _do(lambda d: d["network"]["subnets"][0].__setitem__("cidr", "10.20.1.5/24")),
    "public address space": _set(["network", "address_space"], ["8.8.0.0/16"]),
    "subnet outside vnet": _do(
        lambda d: d["network"]["subnets"][0].__setitem__("cidr", "10.99.0.0/24")
    ),
    "overlapping subnets": _do(
        lambda d: d["network"]["subnets"][1].__setitem__("cidr", "10.20.1.128/25")
    ),
    # Security rules (Microsoft Learn, API 2026-03-01)
    "priority below 100": _do(
        lambda d: rule(d, "allow-http-from-gateway").__setitem__("priority", 99)
    ),
    "priority above 4096": _do(
        lambda d: rule(d, "deny-internet-inbound").__setitem__("priority", 4097)
    ),
    "duplicate priority": _do(
        lambda d: rule(d, "deny-internet-inbound").__setitem__("priority", 100)
    ),
    "unknown protocol": _do(
        lambda d: rule(d, "allow-http-from-gateway").__setitem__("protocol", "Http")
    ),
    "port too high": _do(
        lambda d: rule(d, "allow-http-from-gateway").__setitem__("destination_ports", "70000")
    ),
    "reversed port range": _do(
        lambda d: rule(d, "allow-http-from-gateway").__setitem__("destination_ports", "90-80")
    ),
    "made up service tag": _do(
        lambda d: rule(d, "allow-http-from-gateway").__setitem__("source", "Office")
    ),
    "rule name ends with dash": _do(
        lambda d: rule(d, "allow-http-from-gateway").__setitem__("name", "allow-")
    ),
    "description over 140": _do(
        lambda d: rule(d, "allow-http-from-gateway").__setitem__("description", "x" * 141)
    ),
    # Secure default guardrails
    "public ip on vm": _do(lambda d: resource(d, "vm")["depends_on"].append("pip_gateway")),
    "ssh open to internet": _do(
        lambda d: d["network"]["nsg_rules"].append(
            {
                "nsg_id": "nsg_app",
                "name": "ssh",
                "priority": 200,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "source": "*",
                "destination": "*",
                "destination_ports": "22",
            }
        )
    ),
    "rdp inside open range": _do(
        lambda d: d["network"]["nsg_rules"].append(
            {
                "nsg_id": "nsg_app",
                "name": "wide",
                "priority": 300,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "*",
                "source": "Internet",
                "destination": "*",
                "destination_ports": "3000-4000",
            }
        )
    ),
}


class InvalidSpecTest(unittest.TestCase):
    def test_each_invalid_spec_is_rejected(self) -> None:
        for label, mutate in INVALID.items():
            with self.subTest(label):
                data = example()
                mutate(data)
                with self.assertRaises(ValidationError):
                    Spec.model_validate(data)

    def test_not_json_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            load_spec("this is not json")

    def test_ssh_from_a_restricted_range_is_allowed(self) -> None:
        data = example()
        data["network"]["nsg_rules"].append(
            {
                "nsg_id": "nsg_app",
                "name": "ssh-from-admin-range",
                "priority": 200,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "source": "10.20.9.0/24",
                "destination": "*",
                "destination_ports": "22",
            }
        )
        Spec.model_validate(data)

    def test_same_priority_allowed_in_other_direction(self) -> None:
        """Priority is unique within the inbound set and within the outbound set."""
        data = example()
        data["network"]["nsg_rules"].append(
            {
                "nsg_id": "nsg_app",
                "name": "allow-outbound-http",
                "priority": 100,
                "direction": "Outbound",
                "access": "Allow",
                "protocol": "Tcp",
                "source": "10.20.2.0/24",
                "destination": "Internet",
                "destination_ports": "443",
            }
        )
        Spec.model_validate(data)

    def test_error_names_the_problem(self) -> None:
        data = example()
        resource(data, "rg").setdefault("depends_on", []).append("vm")
        with self.assertRaises(ValidationError) as ctx:
            Spec.model_validate(data)
        self.assertIn("dependency loop", str(ctx.exception))


class PortParsingTest(unittest.TestCase):
    def test_ports(self) -> None:
        self.assertEqual(parse_ports("*"), (0, 65535))
        self.assertEqual(parse_ports("443"), (443, 443))
        self.assertEqual(parse_ports("1000-2000"), (1000, 2000))
        for bad in ("", "-1", "65536", "80-", "a", "80,443", " 80"):
            with self.subTest(bad=bad):
                self.assertIsNone(parse_ports(bad))


if __name__ == "__main__":
    unittest.main()
