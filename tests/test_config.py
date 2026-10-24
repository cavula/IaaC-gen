"""Config tests (task K03, threat T9)."""

from __future__ import annotations

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import keyring
from keyring.backend import KeyringBackend
from keyring.errors import NoKeyringError, PasswordDeleteError
from pydantic import ValidationError

from core import config
from core.config import ConfigError, get_api_key, load_settings, set_api_key

FAKE_KEY = "test-key-not-real-0000"  # pragma: allowlist secret


class MemoryKeyring(KeyringBackend):
    """In memory keychain so tests never touch the real one."""

    priority = 1

    def __init__(self) -> None:
        super().__init__()  # type: ignore[no-untyped-call]  # keyring base class is untyped
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if self.store.pop((service, username), None) is None:
            raise PasswordDeleteError("not found")


class NoKeychain(KeyringBackend):
    """Behaves like a container with no keychain available."""

    priority = 1

    def __init__(self) -> None:
        super().__init__()  # type: ignore[no-untyped-call]  # keyring base class is untyped

    def get_password(self, service: str, username: str) -> str | None:
        raise NoKeyringError("no backend")

    def set_password(self, service: str, username: str, password: str) -> None:
        raise NoKeyringError("no backend")

    def delete_password(self, service: str, username: str) -> None:
        raise NoKeyringError("no backend")


class ConfigTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._previous_keyring = keyring.get_keyring()
        self.keychain = MemoryKeyring()
        keyring.set_keyring(self.keychain)
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("APP_")}
        patcher = mock.patch.dict(os.environ, clean_env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def tearDown(self) -> None:
        keyring.set_keyring(self._previous_keyring)

    def env_file(self, text: str, mode: int = 0o600) -> Path:
        path = Path(self._tmp.name) / ".env"
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path


class SettingsTest(ConfigTestCase):
    def test_reads_app_prefixed_values_from_env_file(self) -> None:
        path = self.env_file("APP_LLM_PROVIDER=anthropic\nAPP_LLM_MODEL=some-model-1\n")
        settings = load_settings(path)
        self.assertEqual(settings.llm_provider, "anthropic")
        self.assertEqual(settings.llm_model, "some-model-1")

    def test_ignores_variables_without_prefix(self) -> None:
        path = self.env_file("LLM_PROVIDER=openai\n")
        self.assertEqual(load_settings(path).llm_provider, "")

    def test_environment_overrides_env_file(self) -> None:
        path = self.env_file("APP_LLM_PROVIDER=anthropic\n")
        with mock.patch.dict(os.environ, {"APP_LLM_PROVIDER": "ollama"}):
            self.assertEqual(load_settings(path).llm_provider, "ollama")

    def test_missing_env_file_is_fine(self) -> None:
        self.assertEqual(load_settings(Path(self._tmp.name) / "absent").llm_provider, "")

    def test_rejects_unsafe_provider_and_model_values(self) -> None:
        for line in (
            "APP_LLM_PROVIDER=anthropic; rm -rf /",
            "APP_LLM_PROVIDER=Has Space",
            "APP_LLM_MODEL=model`whoami`",
            "APP_LLM_MODEL=../../etc/passwd x",
        ):
            with self.subTest(line=line):
                with self.assertRaises(ConfigError) as ctx:
                    load_settings(self.env_file(line + "\n"))
                self.assertIn(line.split("=")[0], str(ctx.exception))
                self.assertNotIn(line.split("=", 1)[1], str(ctx.exception))

    def test_abacus_api_base_is_accepted(self) -> None:
        path = self.env_file(
            "APP_LLM_PROVIDER=openai_compatible\n"
            "APP_LLM_API_BASE=https://routellm.abacus.ai/v1\n"
            "APP_LLM_MODEL=route-llm\n"
        )
        settings = load_settings(path)
        self.assertEqual(settings.llm_api_base, "https://routellm.abacus.ai/v1")

    def test_blank_values_fall_back_to_defaults(self) -> None:
        path = self.env_file("APP_WORKSPACE_DIR=\nAPP_PORT=\n")
        settings = load_settings(path)
        self.assertEqual(settings.workspace_dir, Path.home() / "app-workspace")
        self.assertEqual(settings.port, 8765)

    def test_settings_are_read_only(self) -> None:
        settings = load_settings(None)
        with self.assertRaises(ValidationError):
            settings.llm_provider = "changed"  # type: ignore[misc]


class ApiKeyTest(ConfigTestCase):
    def test_keychain_is_preferred_over_env(self) -> None:
        set_api_key(FAKE_KEY)
        path = self.env_file("APP_LLM_API_KEY=from-env-file\n")
        key, source = get_api_key(load_settings(path))
        self.assertEqual((key.get_secret_value(), source), (FAKE_KEY, "keychain"))

    def test_env_fallback_when_keychain_is_empty(self) -> None:
        path = self.env_file(f"APP_LLM_API_KEY={FAKE_KEY}\n")
        key, source = get_api_key(load_settings(path))
        self.assertEqual((key.get_secret_value(), source), (FAKE_KEY, "env"))

    def test_env_fallback_when_no_keychain_exists(self) -> None:
        keyring.set_keyring(NoKeychain())
        path = self.env_file(f"APP_LLM_API_KEY={FAKE_KEY}\n")
        _, source = get_api_key(load_settings(path))
        self.assertEqual(source, "env")

    def test_clear_error_when_no_key_anywhere(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            get_api_key(load_settings(None))
        self.assertIn("set-key", str(ctx.exception))

    def test_empty_key_is_not_stored(self) -> None:
        with self.assertRaises(ConfigError):
            set_api_key("   ")
        self.assertEqual(self.keychain.store, {})

    def test_set_key_without_keychain_gives_clear_error(self) -> None:
        keyring.set_keyring(NoKeychain())
        with self.assertRaises(ConfigError) as ctx:
            set_api_key(FAKE_KEY)
        self.assertIn("APP_LLM_API_KEY", str(ctx.exception))

    def test_delete_removes_key(self) -> None:
        set_api_key(FAKE_KEY)
        config.delete_api_key()
        self.assertEqual(self.keychain.store, {})

    def test_key_never_appears_in_repr_str_or_logs(self) -> None:
        path = self.env_file(f"APP_LLM_API_KEY={FAKE_KEY}\n")
        settings = load_settings(path)
        with self.assertLogs("core.config", level=logging.DEBUG) as logs:
            logging.getLogger("core.config").debug("settings: %s", settings)
            key, _ = get_api_key(settings)
            logging.getLogger("core.config").debug("key: %s", key)
        for text in (repr(settings), str(settings), repr(key), str(key), *logs.output):
            self.assertNotIn(FAKE_KEY, text)

    def test_key_is_not_in_error_messages(self) -> None:
        keyring.set_keyring(NoKeychain())
        with self.assertRaises(ConfigError) as ctx:
            set_api_key(FAKE_KEY)
        self.assertNotIn(FAKE_KEY, str(ctx.exception))


class EnvFilePermissionTest(ConfigTestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX permissions only")
    def test_warns_when_env_file_is_readable_by_others(self) -> None:
        path = self.env_file("APP_LLM_PROVIDER=ollama\n", mode=0o644)
        with self.assertLogs("core.config", level=logging.WARNING) as logs:
            load_settings(path)
        self.assertTrue(any("chmod 600" in line for line in logs.output))

    @unittest.skipUnless(os.name == "posix", "POSIX permissions only")
    def test_no_warning_when_env_file_is_private(self) -> None:
        path = self.env_file("APP_LLM_PROVIDER=ollama\n", mode=0o600)
        self.assertFalse(config.env_file_is_too_open(path))


class CommandLineTest(ConfigTestCase):
    def test_set_key_reads_hidden_prompt_not_arguments(self) -> None:
        with mock.patch("getpass.getpass", return_value=FAKE_KEY) as prompt:
            self.assertEqual(config._main(["set-key"]), 0)
        prompt.assert_called_once()
        self.assertEqual(self.keychain.get_password("app-core", "llm_api_key"), FAKE_KEY)

    def test_unknown_command_shows_usage(self) -> None:
        self.assertEqual(config._main(["set-key", FAKE_KEY]), 2)
        self.assertEqual(self.keychain.store, {})


if __name__ == "__main__":
    unittest.main()
