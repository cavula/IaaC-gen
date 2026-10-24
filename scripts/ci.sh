#!/usr/bin/env bash
# Runs every check in one place, locally and in CI. Any failure stops the run.
# Assumes requirements.txt and requirements-dev.txt are installed (pip install --require-hashes)
# and Node.js 22.12 or newer for the web app.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 0. Web app: install (locked, no install scripts), audit, licences, types, tests, build"
(
  cd web
  npm ci --ignore-scripts --no-fund --no-audit
  npm audit --audit-level=low
  npm run --silent licences
  npm run --silent typecheck
  npm test --silent
  npm run --silent build
)

echo "== 1. Lint and security lint (ruff)"
ruff check .
ruff format --check .

echo "== 2. Type check (mypy, strict)"
mypy

echo "== 3. Tests"
python -m unittest discover -s tests -t . -v

echo "== 4. Secret scan (detect-secrets against the reviewed baseline)"
git ls-files -z | xargs -0 detect-secrets-hook --baseline .secrets.baseline

echo "== 5. Dependency vulnerability audit (pip-audit)"
pip-audit --strict --require-hashes --disable-pip -r requirements.txt
pip-audit --strict --require-hashes --disable-pip -r requirements-dev.txt

echo "== 6. Licence check (only permissive, Apache 2.0 compatible licences allowed)"
python scripts/check_licences.py

echo "== 7. Software bill of materials (CycloneDX)"
mkdir -p build
cyclonedx-py environment --output-format JSON --output-file build/sbom.cdx.json
echo "SBOM written to build/sbom.cdx.json"

echo "All checks passed."
