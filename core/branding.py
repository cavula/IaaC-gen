"""Single access point for user facing brand values.

Every user facing string that names the product must come from here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANDING_FILE = REPO_ROOT / "branding.json"

REQUIRED_KEYS = (
    "product_name",
    "short_name",
    "tagline",
    "logo_path",
    "icon_path",
    "website_url",
    "repository_url",
    "support_contact",
)


@dataclass(frozen=True)
class Branding:
    product_name: str
    short_name: str
    tagline: str
    logo_path: str
    icon_path: str
    website_url: str
    repository_url: str
    support_contact: str


def load_branding(path: Path = BRANDING_FILE) -> Branding:
    data = json.loads(path.read_text(encoding="utf-8"))
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        raise ValueError(f"branding config missing keys: {missing}")
    if not str(data["product_name"]).strip():
        raise ValueError("product_name must not be empty")
    return Branding(**{k: str(data[k]) for k in REQUIRED_KEYS})


@lru_cache(maxsize=1)
def get_branding() -> Branding:
    return load_branding()
