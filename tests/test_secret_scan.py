"""Secret scanner tests (task K07, threat T1, criterion S1-09).

Fake secrets are assembled at run time so none appear as literals in the repo.
"""

from __future__ import annotations

import unittest

from pydantic import SecretStr

from core.secret_scan import find_secrets

FAKES = {
    "AWS Access Key": "aws_key = " + "AKIA" + "IOSFODNN7EXAMPLE",
    "Private key block": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "Azure connection string key": "AccountName=x;Account" + "Key=" + "Q" * 40 + "==",
    "Azure SAS signature": "https://x.blob.core.windows.net/c?sv=2024&s" + "ig=" + "A1b2" * 10,
    "Anthropic API key": "key: sk-" + "ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2",
    "Google API key": "AI"
    + "za"
    + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",  # pragma: allowlist secret
    "GitHub Token": "ghp"
    + "_"
    + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",  # pragma: allowlist secret
    "Secret Keyword": "pass" + 'word = "Hunter2Hunter2!"',
}


class SecretScanTest(unittest.TestCase):
    def test_each_kind_is_found(self) -> None:
        for expected, text in FAKES.items():
            with self.subTest(expected):
                kinds = {f.kind for f in find_secrets(text)}
                self.assertIn(expected, kinds)

    def test_plain_requirements_are_clean(self) -> None:
        for text in (
            "Deploy my app on Azure on a server.",
            "Use 10.20.0.0/16 for the network and westeurope as the region.",
            "Subscription SUBSCRIPTION_1 in tenant TENANT_1, group GROUP_1 gets Reader.",
            'resource "azurerm_resource_group" "rg" { name = "rg-shop" }',
        ):
            with self.subTest(text=text):
                self.assertEqual(find_secrets(text), [])

    def test_known_secret_is_found_even_without_a_pattern(self) -> None:
        key = SecretStr("plain-looking-value-" + "1234")
        findings = find_secrets("here it is: plain-looking-value-1234 ok", [key])
        self.assertEqual([f.kind for f in findings], ["Configured secret"])

    def test_findings_report_line_not_value(self) -> None:
        text = "line one\n" + FAKES["GitHub Token"]
        findings = find_secrets(text)
        self.assertTrue(all(f.line == 2 for f in findings))
        self.assertNotIn("A1b2C3", repr(findings))


if __name__ == "__main__":
    unittest.main()
