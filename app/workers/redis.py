from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from app.application.admin import RuntimeSettingsManager
from app.application.factory import Runtime, apply_runtime_settings, build_runtime
from app.application.sanitization import sanitize
from app.application.service import AlertAnalysisService
from app.config import Settings, get_deployment_settings
from app.domain.errors import (
    InvalidAlertPayloadError,
    InvestigationLeaseUnavailableError,
    UnknownAlertSourceError,
)
from app.domain.models import AlertStatus, StoredAlert
from app.logging_config import configure_logging

logger = logging.getLogger(__name__)

DlqSender = Callable[[dict[str, Any]], Awaitable[None]]
StreamId = bytes | str
StreamFields = dict[bytes | str, bytes | str]
StreamMessage = tuple[StreamId, StreamFields]

_ACK_AND_DELETE_SCRIPT = """
local acknowledged = redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
redis.call('XDEL', KEYS[1], ARGV[2])
return acknowledged
"""

_DEAD_LETTER_SCRIPT = """
local dead_letter_id = redis.call(
    'XADD', KEYS[2], 'MAXLEN', '~', ARGV[4], '*', 'envelope', ARGV[3]
)
local acknowledged = redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
local deleted = redis.call('XDEL', KEYS[1], ARGV[2])
return {dead_letter_id, acknowledged, deleted}
"""


def parse_envelope(value: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidAlertPayloadError("Redis message is not valid UTF-8") from exc
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise InvalidAlertPayloadError(f"Redis message is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise InvalidAlertPayloadError("Redis message must be an object")
    if value.get("job_type") == "investigate":
        alert_id = value.get("alert_id")
        if not isinstance(alert_id, str) or not alert_id:
            raise InvalidAlertPayloadError("Investigation job requires alert_id")
        return {
            "schema_version": value.get("schema_version", 1),
            "job_type": "investigate",
            "alert_id": alert_id,
        }
    source = value.get("source")
    payload = value.get("payload")
    if not isinstance(source, str) or not source.strip():
        raise InvalidAlertPayloadError("Redis envelope requires a non-empty source")
    if not isinstance(payload, dict):
        raise InvalidAlertPayloadError("Redis envelope requires an object payload")
    return {"source": source, "payload": payload}


async def process_envelope(service: AlertAnalysisService, envelope: dict[str, Any]) -> StoredAlert:
    parsed = parse_envelope(envelope)
    if parsed.get("job_type") == "investigate":
        result = await service.analyze_by_id(parsed["alert_id"])
    else:
        result = await service.analyze(parsed["source"], parsed["payload"], retry_failed=True)
    if result.status == AlertStatus.FAILED:
        raise RuntimeError(result.error or "Previously failed alert analysis")
    if result.status in {AlertStatus.QUEUED, AlertStatus.ANALYZING}:
        raise InvestigationLeaseUnavailableError(str(result.alert.id))
    return result


async def process_with_retries(
    service: AlertAnalysisService,
    envelope: dict[str, Any],
    *,
    max_retries: int,
    dlq_sender: DlqSender,
) -> StoredAlert | None:
    error: Exception | None = None
    attempts = 0
    for attempt in range(1, max_retries + 1):
        attempts = attempt
        try:
            return await process_envelope(service, envelope)
        except InvestigationLeaseUnavailableError:
            # A live worker still owns this alert. Preserve the message in the
            # pending entries list without consuming retries or dead-lettering it.
            raise
        except (InvalidAlertPayloadError, UnknownAlertSourceError) as exc:
            error = exc
            break
        except Exception as exc:
            error = exc
            if attempt < max_retries:
                await asyncio.sleep(min(2 ** (attempt - 1), 10))

    error_summary = sanitize(f"{type(error).__name__}: {error}") if error else "Unknown error"
    await dlq_sender(
        {
            "original": sanitize(envelope),
            "error": error_summary,
            "attempts": attempts,
        }
    )
    return None


class RedisAlertWorker:
    def __init__(
        self,
        settings: Settings,
        service: AlertAnalysisService,
        *,
        runtime: Runtime | None = None,
        runtime_settings_manager: RuntimeSettingsManager | None = None,
        client: Redis | None = None,
        consumer_name: str | None = None,
    ) -> None:
        self.runtime = runtime
        self.runtime_settings = runtime_settings_manager
        if runtime is not None:
            deployment_baseline = runtime.deployment_settings or settings
            self.runtime_settings = self.runtime_settings or RuntimeSettingsManager(
                deployment_baseline.runtime_settings_path,
                deployment_baseline=deployment_baseline,
            )
            effective_settings = self.runtime_settings.effective_settings()
            if runtime.settings.model_dump(mode="python") != effective_settings.model_dump(
                mode="python"
            ):
                apply_runtime_settings(runtime, effective_settings)
            settings = effective_settings
            service = runtime.service

        self.settings = settings
        self.service = service
        self.client = client
        self.consumer_name = consumer_name or self._default_consumer_name()
        self._claim_cursor: StreamId = "0-0"
        self._in_flight: set[asyncio.Task[None]] = set()

    async def run(self) -> None:
        await self._connect()
        try:
            await self._ensure_consumer_group()
            logger.info(
                "Redis worker started stream=%s group=%s consumer=%s concurrency=%s",
                self.settings.redis_stream_name,
                self.settings.redis_consumer_group,
                self.consumer_name,
                self.settings.scheduler_workers,
            )
            while True:
                await self._collect_finished()
                await self._refresh_runtime_settings()
                capacity = self.settings.scheduler_workers - len(self._in_flight)
                if capacity <= 0:
                    await self._wait_for_slot()
                    continue

                messages = await self._claim_stale(capacity)
                remaining = capacity - len(messages)
                if remaining > 0:
                    messages.extend(await self._read_new(remaining))
                for message_id, fields in messages:
                    task = asyncio.create_task(
                        self._handle_message(message_id, fields),
                        name=f"redis-alert-{self._message_id_text(message_id)}",
                    )
                    self._in_flight.add(task)
        finally:
            for task in self._in_flight:
                task.cancel()
            await asyncio.gather(*self._in_flight, return_exceptions=True)
            self._in_flight.clear()
            client = self.client
            self.client = None
            if client is not None:
                await client.aclose()

    async def _connect(self) -> None:
        client = self.client or Redis.from_url(
            self.settings.redis_url,
            username=self.settings.redis_username or None,
            password=self.settings.redis_password or None,
            decode_responses=False,
            protocol=2,
        )
        self.client = client
        try:
            await client.ping()
        except BaseException:
            self.client = None
            await client.aclose()
            raise

    async def _ensure_consumer_group(self) -> None:
        client = self._require_client()
        try:
            await client.xgroup_create(
                self.settings.redis_stream_name,
                self.settings.redis_consumer_group,
                id="0-0",
                mkstream=True,
            )
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def _claim_stale(self, count: int) -> list[StreamMessage]:
        if count <= 0:
            return []
        response = await self._require_client().xautoclaim(
            self.settings.redis_stream_name,
            self.settings.redis_consumer_group,
            self.consumer_name,
            self.settings.redis_claim_idle_seconds * 1000,
            start_id=self._claim_cursor,
            count=count,
        )
        if not isinstance(response, (list, tuple)) or len(response) < 2:
            raise RuntimeError("Redis XAUTOCLAIM returned an invalid response")
        self._claim_cursor = response[0]
        return self._normalize_messages(response[1])

    async def _read_new(self, count: int) -> list[StreamMessage]:
        if count <= 0:
            return []
        response = await self._require_client().xreadgroup(
            self.settings.redis_consumer_group,
            self.consumer_name,
            {self.settings.redis_stream_name: ">"},
            count=count,
            block=1000,
        )
        messages: list[StreamMessage] = []
        for _stream_name, entries in response or []:
            messages.extend(self._normalize_messages(entries))
        return messages

    async def _handle_message(self, message_id: StreamId, fields: StreamFields) -> None:
        try:
            await self._process_message(message_id, fields)
        except InvestigationLeaseUnavailableError as exc:
            logger.info(
                "Deferring leased investigation message_id=%s alert_id=%s",
                self._message_id_text(message_id),
                exc.alert_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "Redis message processing failed message_id=%s",
                self._message_id_text(message_id),
            )

    async def _process_message(self, message_id: StreamId, fields: StreamFields) -> None:
        try:
            raw_envelope = self._extract_envelope(fields)
            envelope = parse_envelope(raw_envelope)
        except InvalidAlertPayloadError as exc:
            await self._dead_letter(
                message_id,
                {
                    "original": sanitize(self._raw_message_for_dlq(fields)),
                    "error": sanitize(str(exc)),
                    "attempts": 1,
                },
            )
            return

        async def send_dlq(payload: dict[str, Any]) -> None:
            await self._dead_letter(message_id, payload)

        result = await process_with_retries(
            self.service,
            envelope,
            max_retries=self.settings.redis_max_retries,
            dlq_sender=send_dlq,
        )
        if result is not None:
            await self._ack_and_delete(message_id)

    async def _ack_and_delete(self, message_id: StreamId) -> None:
        await self._require_client().eval(
            _ACK_AND_DELETE_SCRIPT,
            1,
            self.settings.redis_stream_name,
            self.settings.redis_consumer_group,
            message_id,
        )

    async def _dead_letter(self, message_id: StreamId, failure: dict[str, Any]) -> None:
        envelope = json.dumps(
            {
                "schema_version": 1,
                "source_message_id": self._message_id_text(message_id),
                "failed_at": datetime.now(UTC).isoformat(),
                "failure": sanitize(failure),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        await self._require_client().eval(
            _DEAD_LETTER_SCRIPT,
            2,
            self.settings.redis_stream_name,
            self.settings.redis_dlq_stream_name,
            self.settings.redis_consumer_group,
            message_id,
            envelope,
            self.settings.redis_dlq_maxlen,
        )

    async def _refresh_runtime_settings(self) -> None:
        if not self.runtime or not self.runtime_settings:
            return
        updated, changed, revision = await self.runtime_settings.reload_if_changed(
            self.runtime.settings
        )
        if changed:
            apply_runtime_settings(self.runtime, updated)
            self.settings = updated
            logger.info("Applied runtime settings revision=%s", revision)

    async def _collect_finished(self) -> None:
        finished = {task for task in self._in_flight if task.done()}
        if not finished:
            return
        self._in_flight.difference_update(finished)
        await asyncio.gather(*finished, return_exceptions=True)

    async def _wait_for_slot(self) -> None:
        finished, _pending = await asyncio.wait(
            self._in_flight,
            return_when=asyncio.FIRST_COMPLETED,
        )
        self._in_flight.difference_update(finished)
        await asyncio.gather(*finished, return_exceptions=True)

    def _require_client(self) -> Redis:
        if self.client is None:
            raise RuntimeError("Redis worker client is not connected")
        return self.client

    @staticmethod
    def _normalize_messages(value: Any) -> list[StreamMessage]:
        messages: list[StreamMessage] = []
        for message_id, fields in value or []:
            if not isinstance(fields, dict):
                raise RuntimeError("Redis stream entry fields must be an object")
            messages.append((message_id, fields))
        return messages

    @staticmethod
    def _extract_envelope(fields: StreamFields) -> bytes | str:
        if b"envelope" in fields:
            return fields[b"envelope"]
        if "envelope" in fields:
            return fields["envelope"]
        raise InvalidAlertPayloadError("Redis stream entry requires an envelope field")

    @classmethod
    def _raw_message_for_dlq(cls, fields: StreamFields) -> Any:
        try:
            value = cls._extract_envelope(fields)
        except InvalidAlertPayloadError:
            return {
                cls._decode_redis_value(key): cls._decode_redis_value(value)
                for key, value in fields.items()
            }
        decoded = cls._decode_redis_value(value)
        try:
            return json.loads(decoded)
        except json.JSONDecodeError:
            return decoded

    @staticmethod
    def _decode_redis_value(value: bytes | str) -> str:
        return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value

    @staticmethod
    def _message_id_text(message_id: StreamId) -> str:
        return (
            message_id.decode("utf-8", errors="replace")
            if isinstance(message_id, bytes)
            else message_id
        )

    @staticmethod
    def _default_consumer_name() -> str:
        hostname = socket.gethostname().strip() or "worker"
        return f"{hostname}-{os.getpid()}-{uuid4().hex[:8]}"


async def main() -> None:
    deployment_settings = get_deployment_settings()
    runtime_settings = RuntimeSettingsManager(
        deployment_settings.runtime_settings_path,
        deployment_baseline=deployment_settings,
    )
    settings = runtime_settings.effective_settings()
    configure_logging(settings.log_level)
    if not settings.redis_enabled:
        raise RuntimeError("REDIS_ENABLED must be true to start the Redis worker")
    runtime = build_runtime(settings, deployment_settings=deployment_settings)
    await runtime.repository.initialize()
    worker = RedisAlertWorker(
        settings,
        runtime.service,
        runtime=runtime,
        runtime_settings_manager=runtime_settings,
    )
    try:
        await worker.run()
    finally:
        await runtime.service.close()
        close = getattr(runtime.repository, "close", None)
        if close:
            await close()


if __name__ == "__main__":
    asyncio.run(main())
