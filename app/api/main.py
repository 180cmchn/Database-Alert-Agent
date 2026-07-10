from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.adapters.persistence import SQLAlchemyAlertRepository
from app.application.factory import Runtime, build_runtime
from app.config import Settings, get_settings
from app.domain.errors import (
    AlertNotFoundError,
    AnalysisFailedError,
    InvalidAlertPayloadError,
    UnknownAlertSourceError,
)
from app.domain.models import StoredAlert

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None, runtime: Runtime | None = None) -> FastAPI:
    settings = settings or get_settings()
    runtime = runtime or build_runtime(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
        await runtime.repository.initialize()
        app.state.runtime = runtime
        yield
        if isinstance(runtime.repository, SQLAlchemyAlertRepository):
            await runtime.repository.close()

    app = FastAPI(
        title="Database Alert AI Agent",
        version="0.1.0",
        description="可插拔的数据库告警分析、手册检索与管理升级框架。",
        lifespan=lifespan,
    )
    app.state.runtime = runtime

    @app.exception_handler(UnknownAlertSourceError)
    async def unknown_source_handler(
        _request: Request, exc: UnknownAlertSourceError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"code": "UNKNOWN_ALERT_SOURCE", "message": str(exc), "source": exc.source},
        )

    @app.exception_handler(InvalidAlertPayloadError)
    async def invalid_payload_handler(
        _request: Request, exc: InvalidAlertPayloadError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"code": "INVALID_ALERT_PAYLOAD", "message": str(exc)},
        )

    @app.exception_handler(AlertNotFoundError)
    async def not_found_handler(_request: Request, exc: AlertNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"code": "ALERT_NOT_FOUND", "message": str(exc)},
        )

    @app.exception_handler(AnalysisFailedError)
    async def analysis_failed_handler(
        _request: Request, exc: AnalysisFailedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=502,
            content={
                "code": "ALERT_ANALYSIS_FAILED",
                "message": exc.message,
                "alert_id": exc.alert_id,
                "detail_url": f"/api/v1/alerts/{exc.alert_id}",
            },
        )

    @app.get("/health/live", tags=["health"])
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", tags=["health"])
    async def readiness() -> JSONResponse:
        issues = settings.readiness_issues()
        try:
            await runtime.repository.ping()
        except Exception as exc:
            issues.append(f"Database unavailable: {exc}")
        status_code = 200 if not issues else 503
        return JSONResponse(
            status_code=status_code,
            content={"status": "ready" if not issues else "not_ready", "issues": issues},
        )

    @app.post(
        "/api/v1/alerts/{source}/analyze",
        response_model=StoredAlert,
        tags=["alerts"],
    )
    async def analyze_alert(source: str, payload: dict[str, Any]) -> StoredAlert:
        return await runtime.service.analyze(source, payload)

    @app.get(
        "/api/v1/alerts/{alert_id}", response_model=StoredAlert, tags=["alerts"]
    )
    async def get_alert(alert_id: str) -> StoredAlert:
        return await runtime.service.get(alert_id)

    return app


app = create_app()
