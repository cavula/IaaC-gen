# Friendly cloud architect (working title)

The product name is held in branding.json and is not final.

An open source, local first tool that turns a plain language infrastructure requirement into a secure, validated Terraform project, with explanations, diagrams, a trust report and version history.

## Status

Phase 1, Slice 1. Tasks K01 (repository skeleton), K02 (CI pipeline), K03 (configuration), K04 (local web server), K05 (spec format), K06 (first blueprint), K07 (LLM gateway), K08 (audit log), K09 (discovery) and K10 (approval and versions) complete.

## Layout

* core: shared logic, including the branding loader
* engine: infrastructure as code engine (Terraform first, pluggable)
* web: frontend (added in task K11)
* assets/brand: logos and icons, referenced only through branding.json
* blueprints: reviewed starting designs, one JSON file per blueprint. Every fact cites official documentation and the date it was checked.
* schemas: JSON Schema for the infrastructure spec (generated, do not edit by hand)
* examples/specs: a valid sample spec
* tests: automated tests

## Run all checks

Requires Python 3.13. Dependencies and tools are pinned with hashes in requirements.txt and requirements-dev.txt.

    python3 -m venv .venv
    . .venv/bin/activate
    pip install --require-hashes --no-deps -r requirements.txt -r requirements-dev.txt
    ./scripts/ci.sh

The same script runs in GitHub Actions on every push and pull request. It runs lint, a strict type check, tests, a secret scan, a dependency vulnerability audit, a licence check and builds an SBOM. Any failure stops the run.

## Configure your LLM

Copy .env.example to .env, set APP_LLM_PROVIDER and APP_LLM_MODEL, and make it private with chmod 600 .env.

Store the API key in your OS keychain (recommended). You will be asked for it at a hidden prompt:

    python -m core.config set-key
    python -m core.config check

Supported APP_LLM_PROVIDER values: anthropic, openai, google, ollama (local, no key needed) and openai_compatible. For openai_compatible, also set APP_LLM_API_BASE to the service's HTTPS address.

### Using Abacus RouteLLM

Abacus documents RouteLLM as an OpenAI compatible API ([RouteLLM API reference](https://abacus.ai/help/developer-platform/route-llm/)), so it works through the openai_compatible provider. In .env:

    APP_LLM_PROVIDER=openai_compatible
    APP_LLM_API_BASE=https://routellm.abacus.ai/v1
    APP_LLM_MODEL=route-llm

Then store your Abacus key with python -m core.config set-key. Things to know:

* With the model set to route-llm, Abacus picks the underlying model for each message, so your redacted text may reach a further provider. Name a specific model if you need to know whose data policy applies.
* A public report says RouteLLM did not return tool calls in the standard format ([issue](https://github.com/openclaw/openclaw/issues/6661)). Discovery does not use tool calls yet.
* Not yet tested against the live service.

Inside a container, where no keychain exists, pass APP_LLM_API_KEY as an environment variable at run time. Never bake it into an image.

## How your data is protected

Every call to an LLM goes through one gateway (core/gateway.py). It blocks any message that looks like it holds a secret, swaps real identifiers such as tenant IDs, IP ranges, domains and email addresses for placeholders, checks the result again, and records exactly what was sent. Replies have the placeholders swapped back on your machine only.

Every call, including blocked ones, is saved to an audit log in your workspace folder (~/app-workspace by default, set APP_WORKSPACE_DIR to change it). The log is append only, readable only by you, and hash chained so any outside edit is detected. View it at /api/audit and check its integrity at /api/audit/verify.

When the app starts, a network guard allows connections only to your LLM endpoint, the Terraform Registry and this machine. It also stops libraries from reaching the internet on their own.

## How discovery works

You describe what you need and pick a cloud. The tool matches it to a reviewed blueprint, explains every resource involved with its official source, and asks its questions in rounds, listing what is still unknown each time.

The AI never writes the design. Code owns the questions, the answers and the spec. The AI is only asked to read a free text answer into one of a question's allowed values, every value it returns is checked, and you are shown how each answer was understood. Group names are never sent to the AI. Without an LLM configured, discovery still works through direct answers.

## Approval and versions

When the questions are done you review the draft. Nothing is saved until you explicitly approve it. Approval saves the spec as version v1 in its own Git repository under your workspace (projects/<project name>), as one commit with an annotated tag.

The repository holds placeholders only, such as GROUP_1, so it is safe to push somewhere later. The real values you typed, such as group names, stay in a private database in your workspace. An existing project is never overwritten. Git runs without your global settings and with hooks switched off.

## The infrastructure spec

The spec is the single source of truth for a design. Its rules live in core/spec.py, and the JSON Schema in schemas/spec.schema.json is generated from them. After changing the models, run:

    python scripts/export_schema.py

## Start the local server

    python -m core.server

It listens on http://127.0.0.1:8765 only (change the port with APP_PORT). It cannot be reached from other machines, refuses requests from other websites, and requires a CSRF token for any change. There is no user interface yet; that arrives in task K11.

## Licence

Apache License 2.0. See LICENSE.
