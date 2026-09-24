"""Sentrik API application factory and wiring."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.core.config import get_settings
from app.core.db import init_db
from app.core.observability import (
    CorrelationIdMiddleware,
    configure_logging,
    metrics,
    request_id_var,
)
from app.security.scope import ScopeViolation

_settings = get_settings()
configure_logging(
    json_logs=(
        os.environ.get("SENTINEL_JSON_LOGS", "").lower() == "true"
        or _settings.environment == "production"
    )
)
log = logging.getLogger("sentrik")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail-fast on insecure defaults in production.
    problems = get_settings().production_secret_problems()
    if problems:
        raise RuntimeError(
            "refusing to start in production with insecure config: "
            + "; ".join(problems)
        )
    await init_db()
    from app.agents.registry import seed_builtin_skills
    from app.core.db import get_sessionmaker

    async with get_sessionmaker()() as session:
        try:
            await seed_builtin_skills(session)
            await session.commit()
        except Exception:
            log.warning("skill seeding skipped", exc_info=True)
    try:
        from app.orchestration.engine import resume_incomplete_assessments

        resumed = await resume_incomplete_assessments()
        if resumed:
            log.info("resumed %d interrupted assessment(s): %s", len(resumed), resumed)
    except Exception:
        log.warning("assessment resume sweep skipped", exc_info=True)
    log.info("Sentrik %s started (env=%s)", __version__, get_settings().environment)
    yield


def _error_envelope(
    status_code: int, code: str, detail, request: Request
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "detail": detail,
                "request_id": request_id_var.get(),
            }
        },
    )


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sentrik — Authorized Autonomous AppSec Testing Platform",
        version=__version__,
        description=(
            "Backend-only platform for authorized autonomous application & API security "
            "testing. Full lifecycle: onboarding → authorization → discovery → planning → "
            "policy → sandboxed execution → validation → findings → reporting → remediation "
            "→ regression retesting. Authorization is enforced outside the LLM."
        ),
        lifespan=lifespan,
    )
    app.add_middleware(CorrelationIdMiddleware)

    from app.api.routers import assessments, chat, connectors, identity, memory, targets

    app.include_router(identity.router)
    app.include_router(targets.router)
    app.include_router(assessments.router)
    app.include_router(chat.router)
    app.include_router(connectors.router)
    app.include_router(memory.router)

    # ---- uniform error envelope across the API ----
    @app.exception_handler(ScopeViolation)
    async def _scope_handler(request: Request, exc: ScopeViolation):
        return _error_envelope(403, exc.code or "scope_violation", exc.reason, request)

    @app.exception_handler(StarletteHTTPException)
    async def _http_handler(request: Request, exc: StarletteHTTPException):
        return _error_envelope(
            exc.status_code, f"http_{exc.status_code}", exc.detail, request
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        return _error_envelope(422, "validation_error", exc.errors(), request)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.exception("unhandled error")
        return _error_envelope(500, "internal_error", str(exc), request)

    # ---- meta / ops endpoints ----
    @app.get("/health", tags=["meta"])
    async def health():
        return {"status": "ok", "version": __version__}

    @app.get("/ready", tags=["meta"])
    async def ready():
        from app.core.db import get_sessionmaker

        try:
            async with get_sessionmaker()() as session:
                await session.execute(text("SELECT 1"))
            return {"status": "ready", "db": "ok"}
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                status_code=503, content={"status": "not_ready", "db": f"error: {exc}"}
            )

    @app.get("/metrics", tags=["meta"])
    async def metrics_endpoint():
        return PlainTextResponse(metrics.render_prometheus())

    @app.get("/", tags=["meta"])
    async def root():
        return {"service": "sentrik", "version": __version__, "docs": "/docs"}

    return app


app = create_app()
