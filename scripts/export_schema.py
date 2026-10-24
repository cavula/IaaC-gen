"""Write the spec JSON Schema to schemas/spec.schema.json.

Run after changing core/spec.py. A test fails if the file is out of date.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.spec import schema_text  # noqa: E402

TARGET = Path(__file__).resolve().parent.parent / "schemas" / "spec.schema.json"

if __name__ == "__main__":
    TARGET.parent.mkdir(exist_ok=True)
    TARGET.write_text(schema_text(), encoding="utf-8")
    print(f"wrote {TARGET.relative_to(TARGET.parent.parent)}")
