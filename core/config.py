"""Application settings (task K03, threat T9).

Settings come from APP_ prefixed environment variables or a local .env file.
The LLM API key is read from the OS keychain first and from APP_LLM_API_KEY
only as a fallback, for example inside a container where no keychain exists.

The key is held as a SecretStr, so it never shows up in logs, reprs or errors.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

import keyring
from keyring.errors import KeyringError
from pydantic import Field, SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from core.branding import REPO_ROOT

log = logging.getLogger(__name__)

# Neutral internal names. They never change with the brand.
KEYCHAIN_SERVICE = "app-core"
KEYCHAIN_ACCOUNT = "llm_api_key"
DEFAULT_ENV_FILE = REPO_ROOT / ".env"

# Empty is allowed (not configured yet). Otherwise only letters, digits and a
# few separators: no spaces, quotes or shell characters. Mapping provider
# values to LiteLLM provider names happens in task K07.
_PROVIDER_PATTERN = r"^$|^[a-z0-9][a-z0-9_-]{0,49}$"
_MODEL_PATTERN = r"^$|^[A-Za-z0-9][A-Za-z0-9._:/-]{0,149}$"


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=DEFAULT_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        # A blank line such as APP_WORKSPACE_DIR= means "use the default".
        env_ignore_empty=True,
    )

    llm_provider: str = Field(default="", pattern=_PROVIDER_PATTERN)
    llm_model: str = Field(default="", pattern=_MODEL_PATTERN)
    llm_api_key: SecretStr | None = None
    # Port for the local web app. The bind address is fixed to 127.0.0.1
    # in core.server and is deliberately not configurable (threat T5).
    port: int = Field(default=8765, ge=1024, le=65535)
    # Local workspace: project repositories, the metadata database and the
    # audit log. Neutral folder name that never changes with the brand.
    workspace_dir: Path = Path.home() / "app-workspace"
    # Only needed for providers without a built in endpoint, such as an
    # OpenAI compatible service. HTTPS is enforced by the LLM gateway.
    llm_api_base: str = Field(
        default="", pattern=r"^$|^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$"
    )


def env_file_is_too_open(path: Path) -> bool:
    """True if a POSIX .env file can be read by group or others."""
    if os.name != "posix" or not path.exists():
        return False
    mode = path.stat().st_mode
    return bool(mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH))


def load_settings(env_file: Path | None = DEFAULT_ENV_FILE) -> Settings:
    if env_file is not None and env_file_is_too_open(env_file):
        log.warning(
            "%s can be read by other users. Run: chmod 600 %s",
            env_file.name,
            env_file.name,
        )
    try:
        return Settings(_env_file=env_file)
    except ValidationError as exc:
        # Name the bad settings without echoing their values back.
        fields = sorted({"APP_" + str(err["loc"][0]).upper() for err in exc.errors()})
        raise ConfigError(f"Invalid setting(s): {', '.join(fields)}. See .env.example.") from None


def get_api_key(settings: Settings) -> tuple[SecretStr, str]:
    """Return the API key and where it came from: "keychain" or "env".

    The keychain wins. If no keychain is available (common in containers),
    the APP_LLM_API_KEY value is used. Raises ConfigError if neither is set.
    """
    try:
        stored = keyring.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    except KeyringError as exc:
        log.info("OS keychain not available (%s); trying environment", type(exc).__name__)
        stored = None
    if stored:
        return SecretStr(stored), "keychain"
    if settings.llm_api_key and settings.llm_api_key.get_secret_value():
        return settings.llm_api_key, "env"
    raise ConfigError(
        "No LLM API key found. Store one in the OS keychain with "
        "'python -m core.config set-key', or set APP_LLM_API_KEY."
    )


def set_api_key(value: str) -> None:
    """Store the API key in the OS keychain. Raises ConfigError if unavailable."""
    if not value.strip():
        raise ConfigError("API key must not be empty")
    try:
        keyring.set_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, value.strip())
    except KeyringError as exc:
        raise ConfigError(
            f"Could not write to the OS keychain ({type(exc).__name__}). "
            "Use APP_LLM_API_KEY in .env instead."
        ) from exc


def delete_api_key() -> None:
    try:
        keyring.delete_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    except KeyringError as exc:
        raise ConfigError(f"Could not remove the key ({type(exc).__name__})") from exc


def _main(argv: list[str]) -> int:
    import getpass

    usage = "usage: python -m core.config [set-key | delete-key | check]"
    if len(argv) != 1:
        print(usage)
        return 2
    command = argv[0]
    try:
        if command == "set-key":
            # Read from a hidden prompt, never from arguments, so the key
            # does not land in shell history or process listings.
            set_api_key(getpass.getpass("LLM API key (input hidden): "))
            print("Key stored in the OS keychain.")
        elif command == "delete-key":
            delete_api_key()
            print("Key removed from the OS keychain.")
        elif command == "check":
            settings = load_settings()
            _, source = get_api_key(settings)
            print(f"provider={settings.llm_provider or '(not set)'}")
            print(f"model={settings.llm_model or '(not set)'}")
            print(f"api key found in: {source}")
        else:
            print(usage)
            return 2
    except ConfigError as exc:
        print(f"error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv[1:]))
