from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

from app.adapters.persistence import SQLAlchemyAlertRepository
from app.api.schemas import (
    AlertAccepted,
    FeedbackRequest,
    RunbookListResponse,
    RuntimeSettingsPatch,
    RuntimeSettingsResponse,
)
from app.application.admin import (
    AdminAuditLogger,
    RuntimeSettingsConflictError,
    RuntimeSettingsManager,
)
from app.application.factory import Runtime, apply_runtime_settings, build_runtime
from app.application.scheduler import (
    InMemoryAnalysisScheduler,
    KafkaAnalysisScheduler,
    ManualAnalysisScheduler,
)
from app.config import Settings, get_settings
from app.domain.errors import (
    AlertNotFoundError,
    AnalysisFailedError,
    InvalidAlertPayloadError,
    InvalidRunbookIdError,
    RunbookNotFoundError,
    UnknownAlertSourceError,
)
from app.domain.models import (
    AlertListResult,
    AlertStatus,
    DashboardSummary,
    FeedbackRecord,
    RunbookDocument,
    Severity,
    StoredAlert,
)
from app.domain.ports import AnalysisJobScheduler
from app.logging_config import configure_logging

logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    runtime: Runtime | None = None,
    scheduler: AnalysisJobScheduler | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    runtime = runtime or build_runtime(settings)
    runtime_settings = RuntimeSettingsManager(settings.runtime_settings_path)
    runbook_store = runtime.runbook_store
    audit_logger = AdminAuditLogger(settings.runtime_settings_path)
    if scheduler is None:
        if settings.http_scheduler == "kafka":
            scheduler = KafkaAnalysisScheduler(settings, runtime.service)
        elif settings.http_scheduler == "manual":
            scheduler = ManualAnalysisScheduler()
        else:
            scheduler = InMemoryAnalysisScheduler(
                runtime.service, workers=settings.scheduler_workers
            )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(settings.log_level)
        await runtime.repository.initialize()
        app.state.runtime = runtime
        app.state.scheduler = scheduler
        await scheduler.start()
        yield
        await scheduler.stop()
        if isinstance(runtime.repository, SQLAlchemyAlertRepository):
            await runtime.repository.close()

    app = FastAPI(
        title="Database Alert AI Agent",
        version="0.1.0",
        description="数据库告警接入、本地 PDF 手册匹配、AI 分析与企微结果发送服务。",
        lifespan=lifespan,
    )
    app.state.runtime = runtime
    app.state.scheduler = scheduler
    app.state.runtime_settings = runtime_settings
    app.state.runbook_store = runbook_store
    app.state.audit_logger = audit_logger
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    bearer = HTTPBearer(auto_error=False)

    def authenticate_admin(
        credentials: HTTPAuthorizationCredentials | None,
    ) -> str:
        expected = runtime.settings.admin_api_token
        if not expected:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "ADMIN_AUTH_NOT_CONFIGURED",
                    "message": "ADMIN_API_TOKEN is not configured",
                },
            )
        if (
            credentials is None
            or credentials.scheme.casefold() != "bearer"
            or not secrets.compare_digest(
                credentials.credentials.encode("utf-8"), expected.encode("utf-8")
            )
        ):
            raise HTTPException(
                status_code=401,
                detail={"code": "UNAUTHORIZED", "message": "Invalid admin bearer token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return "admin"

    async def require_admin(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),  # noqa: B008
    ) -> str:
        return authenticate_admin(credentials)

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

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(
        request: Request, exc: RequestValidationError
    ) -> Response:
        # FastAPI's default 422 body includes the rejected input. Runtime settings
        # contain write-only secrets, so their validation errors must never echo it.
        if request.url.path == "/api/v1/admin/settings":
            return JSONResponse(
                status_code=422,
                content={
                    "code": "INVALID_RUNTIME_SETTINGS",
                    "message": "Runtime settings validation failed",
                },
            )
        return await request_validation_exception_handler(request, exc)

    @app.get("/health/live", tags=["health"])
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", tags=["health"])
    async def readiness() -> JSONResponse:
        issues = runtime.settings.readiness_issues()
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
        response_model=AlertAccepted,
        status_code=202,
        tags=["alerts"],
    )
    async def analyze_alert(source: str, payload: dict[str, Any]) -> AlertAccepted:
        stored, created = await runtime.service.ingest(source, payload)
        if created or stored.status in {
            AlertStatus.QUEUED,
            AlertStatus.FAILED,
        }:
            await scheduler.enqueue(str(stored.alert.id))
        return AlertAccepted(
            alert_id=stored.alert.id,
            event_id=stored.alert.external_id,
            status=stored.status,
            detail_url=f"/api/v1/alerts/{stored.alert.id}",
            deduplicated=not created,
        )

    @app.get(
        "/api/v1/alerts",
        response_model=AlertListResult,
        tags=["alerts"],
    )
    async def list_alerts(
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=100)] = 20,
        statuses: Annotated[
            list[AlertStatus] | None, Query(alias="status")
        ] = None,
        severities: Annotated[
            list[Severity] | None, Query(alias="severity")
        ] = None,
        source: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
        environment: Annotated[
            str | None, Query(min_length=1, max_length=100)
        ] = None,
        search: Annotated[str | None, Query(max_length=300)] = None,
    ) -> AlertListResult:
        return await runtime.service.list_alerts(
            page=page,
            page_size=page_size,
            statuses=set(statuses) if statuses else None,
            severities={item.value for item in severities} if severities else None,
            source=source,
            environment=environment,
            search=search,
        )

    @app.get(
        "/api/v1/dashboard/summary",
        response_model=DashboardSummary,
        tags=["dashboard"],
    )
    async def dashboard_summary() -> DashboardSummary:
        return await runtime.service.dashboard_summary()

    @app.get(
        "/api/v1/alerts/{alert_id}", response_model=StoredAlert, tags=["alerts"]
    )
    async def get_alert(alert_id: str) -> StoredAlert:
        return await runtime.service.get(alert_id)

    @app.post(
        "/api/v1/alerts/{alert_id}/feedback",
        response_model=FeedbackRecord,
        status_code=201,
        tags=["alerts"],
    )
    async def submit_feedback(
        alert_id: str,
        feedback: FeedbackRequest,
        actor: str = Depends(require_admin),  # noqa: B008
    ) -> FeedbackRecord:
        saved = await runtime.service.submit_feedback(
            alert_id,
            idempotency_key=feedback.idempotency_key,
            verdict=feedback.verdict,
            reviewer=actor,
            final_root_cause=feedback.final_root_cause,
            actual_resolution=feedback.actual_resolution,
            recovered=feedback.recovered,
        )
        await audit_logger.record(
            action="feedback",
            target=f"alert:{alert_id}",
            fields=["verdict", "final_root_cause", "actual_resolution", "recovered"],
            actor=actor,
        )
        return saved

    @app.get(
        "/api/v1/admin/runbooks",
        response_model=RunbookListResponse,
        tags=["admin"],
        dependencies=[Depends(require_admin)],
    )
    async def list_runbooks() -> RunbookListResponse:
        items = await runbook_store.list()
        return RunbookListResponse(items=items, total=len(items))

    @app.get(
        "/api/v1/admin/runbooks/{runbook_id}",
        response_model=RunbookDocument,
        tags=["admin"],
        dependencies=[Depends(require_admin)],
    )
    async def get_runbook(runbook_id: str) -> RunbookDocument:
        try:
            return await runbook_store.get(runbook_id)
        except InvalidRunbookIdError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except RunbookNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get(
        "/api/v1/admin/settings",
        response_model=RuntimeSettingsResponse,
        tags=["admin"],
        dependencies=[Depends(require_admin)],
    )
    async def read_runtime_settings() -> RuntimeSettingsResponse:
        updated, changed, revision = await runtime_settings.reload_if_changed(
            runtime.settings
        )
        if changed:
            apply_runtime_settings(runtime, updated)
        return RuntimeSettingsResponse.from_settings(
            runtime.settings, revision=revision
        )

    @app.patch(
        "/api/v1/admin/settings",
        response_model=RuntimeSettingsResponse,
        tags=["admin"],
        dependencies=[Depends(require_admin)],
    )
    async def update_runtime_settings(
        payload: RuntimeSettingsPatch,
    ) -> RuntimeSettingsResponse:
        updates = payload.updates()
        try:
            updated, revision, changed_fields = await runtime_settings.patch(
                runtime.settings,
                updates,
                expected_revision=payload.expected_revision,
            )
        except RuntimeSettingsConflictError as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "RUNTIME_SETTINGS_REVISION_CONFLICT",
                    "message": "Runtime settings changed; reload before retrying",
                    "expected_revision": exc.expected_revision,
                    "current_revision": exc.current_revision,
                },
            ) from exc
        except (ValidationError, ValueError) as exc:
            logger.info("Rejected invalid runtime settings update: %s", type(exc).__name__)
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "INVALID_RUNTIME_SETTINGS",
                    "message": "Runtime settings validation failed",
                },
            ) from exc
        apply_runtime_settings(runtime, updated)
        await audit_logger.record(
            action="update",
            target="runtime-settings",
            fields=changed_fields,
        )
        return RuntimeSettingsResponse.from_settings(
            updated, revision=revision, changed_fields=changed_fields
        )

    return app


app = create_app()
