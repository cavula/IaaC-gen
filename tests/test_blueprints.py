"""Blueprint tests (task K06, criteria S1-02 and S1-03)."""

from __future__ import annotations

import json
import unittest
from typing import Any

from pydantic import ValidationError

from core.blueprints import BLUEPRINT_DIR, Blueprint, all_blueprints, draft_spec
from core.spec import Kind, parse_ports

PATH = BLUEPRINT_DIR / "azure" / "vm_behind_app_gateway.json"


def raw() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(PATH.read_text(encoding="utf-8"))
    return data


def blueprint() -> Blueprint:
    return all_blueprints()["vm_behind_app_gateway"]


class LoadTest(unittest.TestCase):
    def test_all_blueprints_load_and_validate(self) -> None:
        self.assertIn("vm_behind_app_gateway", all_blueprints())

    def test_draft_spec_from_defaults_is_valid(self) -> None:
        spec = draft_spec(blueprint(), project_id="my-shop", region="westeurope")
        self.assertEqual(spec.blueprint, "vm_behind_app_gateway")
        self.assertFalse(spec.approval.approved)
        self.assertEqual(spec.resources[0].name, "rg-my-shop")


class FactsAreSourcedTest(unittest.TestCase):
    def test_every_fact_cites_official_docs_with_a_date(self) -> None:
        for fact in blueprint().facts:
            with self.subTest(fact=fact.id):
                self.assertTrue(fact.source.startswith("https://learn.microsoft.com/"))
                self.assertIsNotNone(fact.checked)

    def test_every_resource_is_explained_verified_and_sourced(self) -> None:
        for res in blueprint().resources:
            with self.subTest(resource=res.id):
                self.assertTrue(res.explanation.verified)
                self.assertTrue(res.explanation.sources)
                self.assertTrue(res.facts, "each resource should cite at least one fact")

    def test_unverified_explanation_is_rejected(self) -> None:
        data = raw()
        data["resources"][0]["explanation"]["verified"] = False
        with self.assertRaises(ValidationError):
            Blueprint.model_validate(data)

    def test_unofficial_source_is_rejected(self) -> None:
        data = raw()
        data["facts"][0]["source"] = "https://some-blog.example/azure-tips"
        with self.assertRaises(ValidationError):
            Blueprint.model_validate(data)

    def test_unknown_fact_reference_is_rejected(self) -> None:
        data = raw()
        data["resources"][0]["facts"].append("made_up_fact")
        with self.assertRaises(ValidationError):
            Blueprint.model_validate(data)


class DesignRulesTest(unittest.TestCase):
    """The defaults follow the Microsoft Learn facts the blueprint cites."""

    def setUp(self) -> None:
        self.bp = blueprint()
        self.rules = self.bp.default_network.nsg_rules

    def test_gateway_subnet_allows_gateway_manager_ports(self) -> None:
        match = [
            r
            for r in self.rules
            if r.nsg_id == "nsg_gateway"
            and r.source == "GatewayManager"
            and r.access == "Allow"
            and r.protocol == "Tcp"
            and parse_ports(r.destination_ports) == (65200, 65535)
        ]
        self.assertEqual(len(match), 1)

    def test_gateway_subnet_allows_azure_load_balancer_and_never_denies_it(self) -> None:
        gateway = [r for r in self.rules if r.nsg_id == "nsg_gateway"]
        self.assertTrue(
            any(r.source == "AzureLoadBalancer" and r.access == "Allow" for r in gateway)
        )
        self.assertFalse(
            any(r.source == "AzureLoadBalancer" and r.access == "Deny" for r in gateway)
        )

    def test_gateway_outbound_is_never_denied(self) -> None:
        self.assertFalse(
            any(
                r.nsg_id == "nsg_gateway" and r.direction == "Outbound" and r.access == "Deny"
                for r in self.rules
            )
        )

    def test_gateway_subnet_is_at_least_a_slash_24(self) -> None:
        subnet = next(s for s in self.bp.default_network.subnets if s.resource_id == "snet_gateway")
        self.assertLessEqual(int(subnet.cidr.split("/")[1]), 24)

    def test_only_the_gateway_has_a_public_ip(self) -> None:
        users = [r.id for r in self.bp.resources if "pip_gateway" in r.depends_on]
        self.assertEqual(users, ["agw"])

    def test_public_ip_is_standard_and_static(self) -> None:
        pip = next(r for r in self.bp.resources if r.kind is Kind.PUBLIC_IP)
        self.assertEqual(pip.settings, {"sku": "Standard", "allocation": "Static"})

    def test_server_only_accepts_traffic_from_the_gateway_subnet(self) -> None:
        gateway_cidr = next(
            s.cidr for s in self.bp.default_network.subnets if s.resource_id == "snet_gateway"
        )
        allows = [
            r
            for r in self.rules
            if r.nsg_id == "nsg_app" and r.direction == "Inbound" and r.access == "Allow"
        ]
        self.assertTrue(allows)
        for r in allows:
            self.assertEqual(r.source, gateway_cidr)

    def test_secure_defaults_are_the_default_answers(self) -> None:
        defaults = {q.id: q.default for q in self.bp.questions}
        self.assertEqual(defaults["backend_port"], "443")
        self.assertEqual(defaults["gateway_sku"], "WAF_v2")
        self.assertEqual(defaults["operator_role"], "Reader")


class QuestionsTest(unittest.TestCase):
    def test_required_topics_are_asked(self) -> None:
        """Context file section 3: tenant, subscription, region, access."""
        ids = {q.id for q in blueprint().questions}
        self.assertLessEqual({"tenant", "subscription", "region", "operators"}, ids)

    def test_rounds_start_at_one_without_gaps(self) -> None:
        rounds = sorted({q.round for q in blueprint().questions})
        self.assertEqual(rounds, list(range(1, len(rounds) + 1)))

    def test_choice_default_must_be_an_option(self) -> None:
        data = raw()
        question = next(q for q in data["questions"] if q["id"] == "os")
        question["default"] = "beos"
        with self.assertRaises(ValidationError):
            Blueprint.model_validate(data)

    def test_choice_with_one_option_is_rejected(self) -> None:
        data = raw()
        question = next(q for q in data["questions"] if q["id"] == "os")
        question["options"] = question["options"][:1]
        with self.assertRaises(ValidationError):
            Blueprint.model_validate(data)

    def test_duplicate_question_is_rejected(self) -> None:
        data = raw()
        data["questions"].append(data["questions"][0])
        with self.assertRaises(ValidationError):
            Blueprint.model_validate(data)


class BrokenDesignTest(unittest.TestCase):
    """A blueprint whose defaults break spec rules must fail to load."""

    def test_dependency_loop_is_rejected(self) -> None:
        data = raw()
        data["resources"][0]["depends_on"] = ["vm"]
        with self.assertRaises(ValidationError):
            Blueprint.model_validate(data)

    def test_public_ip_on_server_is_rejected(self) -> None:
        data = raw()
        vm = next(r for r in data["resources"] if r["id"] == "vm")
        vm["depends_on"].append("pip_gateway")
        with self.assertRaises(ValidationError):
            Blueprint.model_validate(data)

    def test_known_gaps_are_recorded(self) -> None:
        gaps = " ".join(blueprint().known_gaps).lower()
        self.assertIn("logging", gaps)


if __name__ == "__main__":
    unittest.main()
