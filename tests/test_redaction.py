"""Redaction tests (task K07, threat T2, criterion S1-07)."""

from __future__ import annotations

import unittest

from core.redaction import Redactor

TENANT = "8f3c2a1e-1111-2222-3333-444455556666"
SUB = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
OTHER = "11111111-2222-3333-4444-555555555555"


class RedactionTest(unittest.TestCase):
    def test_registered_tenant_and_subscription_get_named_placeholders(self) -> None:
        r = Redactor()
        r.register(TENANT, "TENANT")
        r.register(SUB, "SUBSCRIPTION")
        out = r.redact(f"tenant {TENANT}, subscription {SUB}, object {OTHER}")
        self.assertEqual(out, "tenant TENANT_1, subscription SUBSCRIPTION_1, object ID_1")

    def test_detected_values(self) -> None:
        r = Redactor()
        out = r.redact(
            "Email ops@contoso-corp.com, site shop.contoso-corp.com, "
            "network 10.20.0.0/16, server 10.20.2.4, office 203.0.113.7"
        )
        self.assertEqual(
            out, "Email EMAIL_1, site DOMAIN_1, network CIDR_1, server IP_1, office IP_2"
        )

    def test_company_name_is_case_insensitive_and_whole_word(self) -> None:
        r = Redactor()
        r.register("Contoso", "COMPANY")
        self.assertEqual(
            r.redact("CONTOSO and contoso but not Contosoville"),
            "COMPANY_1 and COMPANY_1 but not Contosoville",
        )

    def test_placeholders_are_stable_across_turns(self) -> None:
        r = Redactor()
        first = r.redact("use 10.20.0.0/16")
        second = r.redact("again 10.20.0.0/16 and 10.30.0.0/16")
        self.assertEqual(first, "use CIDR_1")
        self.assertEqual(second, "again CIDR_1 and CIDR_2")

    def test_restore_round_trip(self) -> None:
        r = Redactor()
        r.register(TENANT, "TENANT")
        original = f"Tenant {TENANT} uses 10.20.0.0/16 and mail a@b-corp.com"
        reply = "I will place CIDR_1 under TENANT_1 and notify EMAIL_1."
        r.redact(original)
        self.assertEqual(
            r.restore(reply), f"I will place 10.20.0.0/16 under {TENANT} and notify a@b-corp.com."
        )

    def test_restore_handles_ten_and_one(self) -> None:
        r = Redactor()
        r.redact(" ".join(f"10.0.{i}.1" for i in range(10)))
        self.assertEqual(r.restore("IP_10 IP_1"), "10.0.9.1 10.0.0.1")

    def test_unknown_tokens_are_left_alone(self) -> None:
        r = Redactor()
        r.redact("10.0.0.1")
        self.assertEqual(r.restore("IP_1 and IP_99"), "10.0.0.1 and IP_99")

    def test_user_typed_token_is_never_reused(self) -> None:
        r = Redactor()
        out = r.redact("I named my server IP_1, its address is 10.0.0.9")
        self.assertEqual(out, "I named my server IP_1, its address is IP_2")
        self.assertEqual(r.restore("IP_1 at IP_2"), "IP_1 at 10.0.0.9")

    def test_file_names_versions_and_public_docs_are_not_redacted(self) -> None:
        r = Redactor()
        text = (
            "Edit main.tf and terraform.tfvars, see learn.microsoft.com and "
            "registry.terraform.io, Terraform 1.9.8, provider 4.1.0"
        )
        self.assertEqual(r.redact(text), text)

    def test_counts_by_kind(self) -> None:
        r = Redactor()
        r.redact("10.0.0.1 10.0.0.2 a@b-corp.com")
        self.assertEqual(r.counts["IP"], 2)
        self.assertEqual(r.counts["EMAIL"], 1)

    def test_unknown_kind_or_tiny_value_is_rejected(self) -> None:
        r = Redactor()
        with self.assertRaises(ValueError):
            r.register("x", "COMPANY")
        with self.assertRaises(ValueError):
            r.register("Contoso", "SECRET")


if __name__ == "__main__":
    unittest.main()
