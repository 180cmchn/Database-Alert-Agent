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
from app.agent_runtime.trace import trace_entry_from_event
from app.api.schemas import (
    AgentTraceResponse,
    AlertAccepted,
    CancelRunResponse,
    FlashDutyPollAlertItem,
    FlashDutyPollResponse,
    ReanalyzeRequest,
    ReanalyzeResponse,
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
    FlashDutyAlertPoller,
    InMemoryAnalysisScheduler,
    KafkaAnalysisScheduler,
    ManualAnalysisScheduler,
    WeeklyAlertRetentionCleaner,
)
from app.config import Settings, get_settings
from app.domain.errors import (
    AlertNotFoundError,
    AnalysisFailedError,
    InvalidAlertPayloadError,
    UnknownAlertSourceError,
)
from app.domain.models import (
    AlertListResult,
    AlertStatus,
    DashboardSummary,
    Severity,
    StoredAlert,
)
from app.domain.ports import AnalysisJobScheduler, RunCancellationConflict
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
    # Snapshot the deployment (.env) baseline before any runtime overrides are
    # applied so the reset endpoint can revert editable keys to it.
    deployment_baseline = settings.model_copy(deep=True)
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
    flashduty_poller = FlashDutyAlertPoller(
        settings, runtime.service, scheduler, runtime.flashduty_client
    )
    retention_cleaner = WeeklyAlertRetentionCleaner(settings, runtime.repository)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(settings.log_level)
        await runtime.repository.initialize()
        app.state.runtime = runtime
        app.state.scheduler = scheduler
        app.state.flashduty_poller = flashduty_poller
        app.state.retention_cleaner = retention_cleaner
        await scheduler.start()
        await flashduty_poller.start()
        await retention_cleaner.start()
        try:
            yield
        finally:
            await retention_cleaner.stop()
            await flashduty_poller.stop()
            await scheduler.stop()
            await runtime.service.close()
            if isinstance(runtime.repository, SQLAlchemyAlertRepository):
                await runtime.repository.close()

    app = FastAPI(
        title="Database Alert AI Agent",
        version="0.1.0",
        description="数据库告警接入、多知识源匹配、证据化 AI 分析与企微结果发送服务。",
        lifespan=lifespan,
    )
    app.state.runtime = runtime
    app.state.scheduler = scheduler
    app.state.runtime_settings = runtime_settings
    app.state.audit_logger = audit_logger
    app.state.flashduty_poller = flashduty_poller
    app.state.retention_cleaner = retention_cleaner
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
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
    async def analysis_failed_handler(_request: Request, exc: AnalysisFailedError) -> JSONResponse:
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
    async def request_validation_handler(request: Request, exc: RequestValidationError) -> Response:
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
        if source.casefold() == "flashduty":
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "FLASHDUTY_POLLING_ONLY",
                    "message": "FlashDuty alerts are ingested only by the API poller.",
                },
            )
        stored, created = await runtime.service.ingest(source, payload)
        if created or stored.status in {
            AlertStatus.RECEIVED,
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
        statuses: Annotated[list[AlertStatus] | None, Query(alias="status")] = None,
        severities: Annotated[list[Severity] | None, Query(alias="severity")] = None,
        source: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
        environment: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
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

    @app.get("/api/v1/alerts/{alert_id}", response_model=StoredAlert, tags=["alerts"])
    async def get_alert(
        alert_id: str,
        run_id: Annotated[str | None, Query(min_length=1, max_length=36)] = None,
    ) -> StoredAlert:
        return await runtime.service.get(alert_id, run_id=run_id)

    @app.get(
        "/api/v1/alerts/{alert_id}/runs/{run_id}/trace",
        response_model=AgentTraceResponse,
        tags=["alerts"],
    )
    async def get_agent_trace(
        alert_id: str,
        run_id: str,
        after_sequence: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> AgentTraceResponse:
        # This also verifies that the requested run belongs to the alert.
        await runtime.service.get(alert_id, run_id=run_id)
        events = await runtime.repository.list_agent_events(
            run_id,
            after_sequence=after_sequence,
            limit=limit + 1,
        )
        has_more = len(events) > limit
        page = events[:limit]
        items = [item for event in page if (item := trace_entry_from_event(event))]
        return AgentTraceResponse(
            run_id=run_id,
            after_sequence=after_sequence,
            next_sequence=max((event.sequence for event in page), default=after_sequence),
            has_more=has_more,
            items=items,
        )

    @app.get(
        "/api/v1/admin/settings",
        response_model=RuntimeSettingsResponse,
        tags=["admin"],
        dependencies=[Depends(require_admin)],
    )
    async def read_runtime_settings() -> RuntimeSettingsResponse:
        updated, changed, revision = await runtime_settings.reload_if_changed(runtime.settings)
        if changed:
            apply_runtime_settings(runtime, updated)
            await scheduler.sync_workers(updated.scheduler_workers)
            await flashduty_poller.sync_settings(updated)
        return RuntimeSettingsResponse.from_settings(runtime.settings, revision=revision)

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
        await scheduler.sync_workers(updated.scheduler_workers)
        await flashduty_poller.sync_settings(updated)
        await audit_logger.record(
            action="update",
            target="runtime-settings",
            fields=changed_fields,
        )
        return RuntimeSettingsResponse.from_settings(
            updated, revision=revision, changed_fields=changed_fields
        )

    @app.delete(
        "/api/v1/admin/settings/runtime-overrides",
        response_model=RuntimeSettingsResponse,
        tags=["admin"],
        dependencies=[Depends(require_admin)],
    )
    async def reset_runtime_settings(
        expected_revision: Annotated[str, Query(min_length=1)],
    ) -> RuntimeSettingsResponse:
        try:
            updated, revision = await runtime_settings.reset(
                deployment_baseline,
                expected_revision=expected_revision,
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
            logger.info("Rejected invalid runtime settings reset: %s", type(exc).__name__)
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "INVALID_RUNTIME_SETTINGS",
                    "message": "Runtime settings validation failed",
                },
            ) from exc
        apply_runtime_settings(runtime, updated)
        await scheduler.sync_workers(updated.scheduler_workers)
        await flashduty_poller.sync_settings(updated)
        await audit_logger.record(
            action="reset",
            target="runtime-settings",
        )
        return RuntimeSettingsResponse.from_settings(updated, revision=revision)

    @app.post(
        "/api/v1/alerts/{alert_id}/reanalyze",
        response_model=ReanalyzeResponse,
        status_code=202,
        tags=["alerts"],
    )
    async def reanalyze_alert(
        alert_id: str,
        request: ReanalyzeRequest,
        actor: str = Depends(require_admin),  # noqa: B008
    ) -> ReanalyzeResponse:
        """Re-analyze an alert with current runtime settings.

        This endpoint allows debugging by re-running analysis with different
        runtime configurations. The configuration snapshot is saved for tracking
        and comparison across multiple re-analyses.
        """
        run, config_snapshot = await runtime.service.reanalyze(
            alert_id,
            force=request.force,
        )
        await audit_logger.record(
            action="reanalyze",
            target=f"alert:{alert_id}",
            fields=["force", "config_snapshot"],
            actor=actor,
        )
        return ReanalyzeResponse(
            alert_id=run.alert_id,
            run_id=run.id,
            attempt=run.attempt,
            config_snapshot=config_snapshot,
            message=f"Re-analysis started with attempt {run.attempt}",
        )

    @app.post(
        "/api/v1/alerts/{alert_id}/runs/{run_id}/cancel",
        response_model=CancelRunResponse,
        status_code=202,
        tags=["alerts"],
    )
    async def cancel_analysis_run(
        alert_id: str,
        run_id: str,
        actor: str = Depends(require_admin),  # noqa: B008
    ) -> CancelRunResponse:
        try:
            run = await runtime.service.cancel_run(
                alert_id,
                run_id,
                requested_by=actor,
            )
        except RunCancellationConflict as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "RUN_CANCELLATION_CONFLICT",
                    "message": "Only a running analysis can be cancelled",
                    "run_id": exc.run_id,
                    "status": exc.status,
                },
            ) from exc
        await audit_logger.record(
            action="cancel",
            target=f"alert:{alert_id}:run:{run_id}",
            actor=actor,
        )
        if run.cancel_requested_at is None:
            raise RuntimeError("cancelled run is missing cancel_requested_at")
        return CancelRunResponse(
            alert_id=run.alert_id,
            run_id=run.id,
            status=run.status,
            cancel_requested_at=run.cancel_requested_at,
            message="Analysis cancellation request accepted",
        )

    @app.post(
        "/api/v1/admin/flashduty/poll",
        response_model=FlashDutyPollResponse,
        tags=["admin"],
        dependencies=[Depends(require_admin)],
    )
    async def poll_flashduty_alerts() -> FlashDutyPollResponse:
        """Manually run the same configured window used by the background poller.

        This endpoint fetches alerts from FlashDuty API, persists new alerts,
        enqueues their analysis, and returns the deduplication result.
        """
        if not runtime.flashduty_client:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "FLASHDUTY_NOT_CONFIGURED",
                    "message": "FlashDuty is not enabled or app key is not configured",
                },
            )

        channel_ids = runtime.settings.flashduty_poll_channel_ids
        if not channel_ids:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "FLASHDUTY_CHANNEL_NOT_CONFIGURED",
                    "message": "FLASHDUTY_POLL_CHANNEL_IDS is not configured",
                },
            )

        try:
            result = await flashduty_poller.poll_window(client=runtime.flashduty_client)
        except Exception as exc:
            logger.exception("flashduty_poll_failed error=%s", type(exc).__name__)
            raise HTTPException(
                status_code=502,
                detail={
                    "code": "FLASHDUTY_POLL_FAILED",
                    "message": f"Failed to poll FlashDuty: {type(exc).__name__}",
                },
            ) from exc

        items = [
            FlashDutyPollAlertItem.from_normalized(
                item.stored.alert,
                deduplicated=not item.created,
                created=item.created,
            )
            for item in result.items
        ]
        return FlashDutyPollResponse(
            total_count=result.total_count,
            new_count=result.new_count,
            deduplicated_count=result.deduplicated_count,
            time_range_seconds=runtime.settings.flashduty_poll_lookback_seconds,
            start_time=result.start_time,
            end_time=result.end_time,
            channel_ids=channel_ids,
            items=items,
        )

    return app


app = create_app()
