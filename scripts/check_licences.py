"""Fail if any installed package has a licence outside the allow list.

Allow list: permissive licences compatible with Apache 2.0. Copyleft
licences such as GPL or AGPL are not allowed and must be reviewed by the owner.
"""

from __future__ import annotations

import json
import re
import subprocess  # noqa: S404
import sys

ALLOWED = (
    "apache",
    "mit",
    "bsd",
    "isc",
    "python software foundation",
    "psf",
    "mozilla public license 2.0",
    "mpl-2.0",
    "unlicense",
    "cc0",
    "zlib",
)

# Packages whose metadata is reviewed by hand. Keep each entry with a reason.
REVIEWED: dict[str, str] = {}


def is_allowed(licence: str) -> bool:
    text = licence.lower()
    if re.search(r"\b(a?gpl|lgpl|sspl|eupl)\b", text) and " or " not in text:
        return False
    return any(token in text for token in ALLOWED)


def main() -> int:
    raw = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "piplicenses", "--format=json", "--from=mixed"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    problems = []
    for pkg in json.loads(raw):
        name, licence = pkg["Name"], pkg["License"]
        if name.lower() in REVIEWED:
            continue
        if not is_allowed(licence):
            problems.append(f"{name} {pkg['Version']}: {licence}")
    if problems:
        print("Licences needing owner review:")
        print("\n".join(f"  {p}" for p in problems))
        return 1
    print("All licences are on the allow list.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
