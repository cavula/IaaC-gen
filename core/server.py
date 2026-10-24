"""Local web server (task K04, criteria S1-01, threat T5).

Defences against other machines and against malicious websites in your browser:

1. Bind to 127.0.0.1 only. The address is fixed, not configurable.
2. Host header must be 127.0.0.1 or localhost. Blocks DNS rebinding,
   where an attacker's domain is pointed at 127.0.0.1.
3. Cross origin requests are refused. No CORS headers are ever sent, so other
   websites cannot read responses, and any request with a foreign Origin or a
   cross site Sec-Fetch-Site header is rejected before it reaches a route.
4. Every state changing request (POST, PUT, PATCH, DELETE) must carry the
   per process CSRF token in the X-CSRF-Token header.
5. Strict security headers, no API docs pages (they load scripts from a CDN),
   no server version header, request body size limit.

Controls: OWASP ASVS V3 (session), V4 (access control), V13 (API), V14
(configuration); NIST CSF 2.0 PR.AA and PR.PS.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import secrets
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from core.audit_store import SqliteAuditStore
from core.branding import get_branding
from core.discovery import Discovery, DiscoveryError
from core.gateway import Gateway
from core.projects import ProjectError, ProjectExists, ProjectStore

BIND_HOST = "127.0.0.1"
ALLOWED_HOSTS = ("127.0.0.1", "localhost")
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_HEADER = "X-CSRF-Token"
MAX_BODY_BYTES = 1_000_000

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}

CallNext = Callable[[Request], Awaitable[Response]]


def _deny(status: int, reason: str) -> JSONResponse:
    return JSONResponse({"error": reason}, status_code=status, headers=SECURITY_HEADERS)


def allowed_origins(port: int) -> frozenset[str]:
    return frozenset(f"http://{host}:{port}" for host in ALLOWED_HOSTS)


class StartDiscovery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cloud: Literal["azure", "aws", "gcp"]
    requirement: str = Field(min_length=1, max_length=4000)
    project_id: str = Field(default="my-app", max_length=31)


class ApproveDiscovery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: Literal[True]


class AnswerDiscovery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answers: dict[str, str] | None = Field(default=None, max_length=20)
    text: str | None = Field(default=None, max_length=4000)


def create_app(
    port: int,
    csrf_token: str | None = None,
    audit_store: SqliteAuditStore | None = None,
    discovery: Discovery | None = None,
    projects: ProjectStore | None = None,
) -> FastAPI:
    """Build the app. Pass csrf_token only in tests."""
    token = csrf_token or secrets.token_urlsafe(32)
    origins = allowed_origins(port)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, debug=False)
    app.state.csrf_token = token
    app.state.audit_store = audit_store
    app.state.discovery = discovery or Discovery()
    app.state.projects = projects

    @app.middleware("http")
    async def guard(request: Request, call_next: CallNext) -> Response:
        origin = request.headers.get("origin")
        if origin is not None and origin not in origins:
            return _deny(403, "cross origin request refused")
        if request.headers.get("sec-fetch-site") == "cross-site":
            return _deny(403, "cross site request refused")

        if request.method not in SAFE_METHODS:
            sent = request.headers.get(CSRF_HEADER, "")
            if not hmac.compare_digest(sent.encode(), token.encode()):
                return _deny(403, "missing or invalid CSRF token")
            length = request.headers.get("content-length")
            if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
                return _deny(413, "request body too large")

        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    # Added last so it runs first: bad Host headers never reach the guard.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ALLOWED_HOSTS))

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/session")
    async def session() -> dict[str, Any]:
        branding = get_branding()
        return {
            "csrf_token": token,
            "csrf_header": CSRF_HEADER,
            "product_name": branding.product_name,
            "tagline": branding.tagline,
        }

    # Audit screen API (criterion S1-08). Read only: there is no route that
    # changes or deletes audit records.
    @app.get("/api/audit")
    def audit_page(limit: int = 50, before_id: int | None = None) -> dict[str, Any]:
        store = _audit_store(app)
        items = store.page(limit=limit, before_id=before_id)
        return {
            "entries": [{"id": i.id, **i.entry.model_dump(mode="json")} for i in items],
            "next_before_id": items[-1].id if items else None,
            "total": store.count(),
        }

    @app.get("/api/audit/verify")
    def audit_verify() -> dict[str, Any]:
        report = _audit_store(app).verify()
        return {"ok": report.ok, "checked": report.checked, "first_bad_id": report.first_bad_id}

    # Discovery API (criteria S1-02 to S1-04). POST routes need the CSRF token.
    @app.post("/api/discovery")
    def discovery_start(body: StartDiscovery) -> dict[str, Any]:
        try:
            session_id, reply = app.state.discovery.start(
                body.requirement, body.cloud, project_id=body.project_id
            )
        except DiscoveryError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"session_id": session_id or None, **reply.model_dump(mode="json")}

    @app.post("/api/discovery/{session_id}/answers")
    def discovery_answer(session_id: str, body: AnswerDiscovery) -> dict[str, Any]:
        try:
            reply = app.state.discovery.answer(session_id, answers=body.answers, text=body.text)
        except DiscoveryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        return {"session_id": session_id, **reply.model_dump(mode="json")}

    # Approval (criterion S1-06): an explicit confirm saves the draft as v1.
    @app.post("/api/discovery/{session_id}/approve")
    def discovery_approve(session_id: str, body: ApproveDiscovery) -> dict[str, Any]:
        store = _projects(app)
        try:
            session = app.state.discovery.get(session_id)
        except DiscoveryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        if session.approved_version is not None:
            raise HTTPException(status_code=409, detail="this design is already approved")
        if session.spec is None or session.current_round() is not None:
            raise HTTPException(status_code=409, detail="finish the questions before approving")
        try:
            saved = store.approve_new(session.spec, local_values=session.local_values)
        except ProjectExists as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except ProjectError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from None
        session.approved_version = saved.version
        return {"project_id": saved.project_id, "version": saved.version, "commit": saved.commit}

    @app.get("/api/projects")
    def projects_list() -> dict[str, Any]:
        return {"projects": _projects(app).list_projects()}

    @app.get("/api/projects/{project_id}/versions")
    def project_versions(project_id: str) -> dict[str, Any]:
        try:
            versions = _projects(app).versions(project_id)
        except ProjectError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        return {"versions": [v.__dict__ for v in versions]}

    @app.get("/api/projects/{project_id}/versions/{version}")
    def project_spec(project_id: str, version: str) -> dict[str, Any]:
        try:
            spec = _projects(app).spec_at(project_id, version)
        except ProjectError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        return {"spec": spec.model_dump(mode="json")}

    return app


def _projects(app: FastAPI) -> ProjectStore:
    store: ProjectStore | None = app.state.projects
    if store is None:
        raise HTTPException(status_code=503, detail="project storage is not available")
    return store


def _audit_store(app: FastAPI) -> SqliteAuditStore:
    store: SqliteAuditStore | None = app.state.audit_store
    if store is None:
        raise HTTPException(status_code=503, detail="audit log is not available")
    return store


def check_bind_host(host: str) -> None:
    """Refuse any address that is not loopback."""
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError(f"refusing to bind to non loopback address {host}")


def install_egress_guard(provider: str, api_base: str | None) -> list[str]:
    """Allow only the configured LLM endpoint and the Terraform Registry (T6)."""
    from core.egress import TERRAFORM_REGISTRY, EgressPolicy, host_of, install_guard
    from core.gateway import PROVIDERS, resolve_endpoint

    hosts = [TERRAFORM_REGISTRY]
    if provider in PROVIDERS:
        _, base = resolve_endpoint(provider, api_base)
        hosts.append(host_of(base))
    install_guard(EgressPolicy(hosts))
    return hosts


def _gateway_or_none(store: SqliteAuditStore) -> Gateway | None:
    """Discovery still works through the screen's buttons without an LLM."""
    from core.config import ConfigError
    from core.gateway import GatewayError, gateway_from_settings

    try:
        return gateway_from_settings(store)
    except (ConfigError, GatewayError) as exc:
        logging.getLogger(__name__).warning("LLM not configured, free text disabled: %s", exc)
        return None


def run() -> None:
    import uvicorn

    from core.config import load_settings

    settings = load_settings()
    check_bind_host(BIND_HOST)
    install_egress_guard(settings.llm_provider, settings.llm_api_base or None)
    store = SqliteAuditStore(settings.workspace_dir)
    discovery = Discovery(_gateway_or_none(store))
    projects = ProjectStore(settings.workspace_dir)
    uvicorn.run(
        create_app(settings.port, audit_store=store, discovery=discovery, projects=projects),
        host=BIND_HOST,
        port=settings.port,
        server_header=False,
        proxy_headers=False,
        log_level="info",
    )


if __name__ == "__main__":
    run()
