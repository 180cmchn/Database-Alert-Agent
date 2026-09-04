from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from app.agent_runtime.contracts import ArtifactRef
from app.application.sanitization import sanitize
from app.domain.errors import AdvisorError
from app.domain.models import ToolResultAnalysis, ToolResultObservation

TOOL_RESULT_ANALYSIS_PROMPT_VERSION = "program-fact-projection-v9"
_MAX_SNIPPET_CHARS = 800
_MAX_SELECTED_ITEMS = 20
_PROMETHEUS_WINDOW_SECONDS = 300
_PROMETHEUS_PUBLIC_METRIC_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PROMETHEUS_PUBLIC_METRIC_NAME = re.compile(r"^[A-Za-z_:][A-Za-z0-9_:]*$")
_PROMETHEUS_PUBLIC_METRIC_MAX_KEYS = 8
_PROMETHEUS_PUBLIC_METRIC_MAX_JSON_CHARS = 2_000
_PROMETHEUS_VALUE_SEMANTICS = frozenset(
    {"aggregate", "expression", "increase", "rate", "raw", "unknown"}
)
_LEGACY_PROMETHEUS_SEMANTIC_LABEL_KEYS = frozenset(
    {"command", "metric", "operation", "pool", "quantile", "state", "type"}
)
_HOST_LABEL_KEYS = frozenset(
    {"address", "addr", "endpoint", "host", "hostname", "instance", "ip", "server", "target"}
)
_PORT_LABEL_KEYS = frozenset({"port", "service_port", "server_port"})
_DATABASE_LABEL_KEYS = frozenset(
    {"database", "database_name", "datname", "db", "dbname", "db_name", "schema"}
)
_ENGINE_LABEL_KEYS = frozenset(
    {"__name__", "database_engine", "database_type", "db_engine", "db_type", "engine", "job"}
)
_ENGINE_ALIASES = {
    "mysql": ("mysql", "mysqld"),
    "oceanbase": ("oceanbase", "obcluster", "obproxy", "observer"),
    "postgresql": ("postgres", "postgresql"),
    "tidb": ("tidb", "tikv", "tiflash"),
}


class ToolResultTransportCategory(StrEnum):
    """Explicit transport/provider family used to select a projection contract."""

    ARCHERY_MCP = "ARCHERY_MCP"
    PROMETHEUS_MCP = "PROMETHEUS_MCP"
    GENERIC_MCP = "GENERIC_MCP"
    FLASHDUTY_API = "FLASHDUTY_API"
    ALERT_CONTEXT = "ALERT_CONTEXT"


@dataclass(frozen=True, slots=True)
class ToolResultProjectionRoute:
    transport_category: ToolResultTransportCategory
    subtype: str


_FLASHDUTY_ALERT_SOURCES = frozenset({"flashduty_alert", "flashduty_alert_detail"})
_FLASHDUTY_SIMILAR_SOURCES = frozenset({"flashduty_similar"})
_FLASHDUTY_API_SOURCES = frozenset(
    {
        "alert_platform",
        "flashduty",
        "flashduty_api",
        "flashduty_monitors",
        *_FLASHDUTY_ALERT_SOURCES,
        *_FLASHDUTY_SIMILAR_SOURCES,
    }
)
_FLASHDUTY_ALERT_TOOLS = frozenset({"alert_context", "flashduty_alert", "flashduty_alert_info"})
_FLASHDUTY_SIMILAR_TOOLS = frozenset({"flashduty_similar", "query_similar_incidents"})


def is_context_only_tool_result(*, tool_name: str, source_system: str) -> bool:
    """Return whether a known API result may be shown but never support a root cause."""

    normalized_source = source_system.strip().casefold()
    return normalized_source in _FLASHDUTY_SIMILAR_SOURCES or (
        normalized_source in _FLASHDUTY_API_SOURCES
        and tool_name.strip().casefold() in _FLASHDUTY_SIMILAR_TOOLS
    )


@dataclass(frozen=True, slots=True)
class _PrometheusSample:
    timestamp: Any
    value: float
    source_index: int


@dataclass(frozen=True, slots=True)
class _PrometheusWindow:
    start: datetime
    end: datetime


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _bounded_json(value: Any, *, limit: int = _MAX_SNIPPET_CHARS) -> str:
    text = json.dumps(
        sanitize(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...[omitted,total_chars:{len(text)}]"


_INTERNAL_PROVENANCE_KEYS = frozenset(
    {
        "artifact",
        "artifact_id",
        "artifact_uri",
        "digest",
        "hash",
        "request_id",
        "request_ids",
        "sha256",
        "source_artifact",
        "source_artifact_id",
        "source_sha256",
        "uri",
        "usage",
    }
)


def _model_visible_projection(value: Any) -> Any:
    """Remove audit provenance from an already bounded program projection."""

    if isinstance(value, Mapping):
        visible: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = str(raw_key)
            normalized = key.strip().casefold()
            if (
                normalized.startswith("raw_")
                or normalized in _INTERNAL_PROVENANCE_KEYS
                or normalized.endswith("_request_id")
                or normalized.endswith("_request_ids")
            ):
                continue
            projected = _model_visible_projection(child)
            if projected is not None:
                visible[key] = projected
        return visible
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            projected
            for item in value
            if (projected := _model_visible_projection(item)) is not None
        ]
    if isinstance(value, str) and value.strip().casefold().startswith("agent-artifact://"):
        return None
    return value


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _display_number(value: float) -> int | float:
    return int(value) if value.is_integer() else round(value, 6)


def _analysis(
    *,
    artifact: ArtifactRef,
    summary: str,
    observations: list[ToolResultObservation],
    limitations: list[str],
    analysis_usable: bool | None = None,
    passthrough_payload: dict[str, Any] | None = None,
    passthrough_parse_failed: bool = False,
    slow_query_analysis: dict[str, Any] | None = None,
) -> ToolResultAnalysis:
    if artifact.sha256 is None:
        raise AdvisorError("tool-result artifact must have a SHA-256 before processing")
    return ToolResultAnalysis(
        summary=summary,
        observations=observations,
        anomalies=[],
        limitations=limitations,
        analysis_usable=(bool(observations) if analysis_usable is None else analysis_usable),
        source_coverage_complete=True,
        source_artifact_id=artifact.artifact_id,
        source_sha256=artifact.sha256,
        provider="deterministic_host",
        model="none",
        request_id=None,
        prompt_version=TOOL_RESULT_ANALYSIS_PROMPT_VERSION,
        usage={},
        passthrough_payload=passthrough_payload,
        passthrough_parse_failed=passthrough_parse_failed,
        slow_query_analysis=slow_query_analysis,
    )


class DeterministicToolResultProcessor:
    """Project complete tool results into bounded, traceable facts in program code.

    The raw EvidenceRecord is retained in its immutable artifact. This program fact
    projection applies provider-specific extraction rules and never makes a causal
    judgment.
    """

    async def analyze(
        self,
        *,
        tool_name: str,
        source_system: str,
        request: dict[str, Any],
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis:
        del request
        if not isinstance(raw_result, dict):
            raise AdvisorError("complete tool result must be a JSON object")
        route = self._projection_route(
            tool_name=tool_name,
            source_system=source_system,
            raw_result=raw_result,
        )
        if route.transport_category == ToolResultTransportCategory.ARCHERY_MCP:
            return self._process_archery(raw_result, artifact)
        if route.transport_category == ToolResultTransportCategory.PROMETHEUS_MCP:
            return self._process_prometheus(raw_result, artifact)
        if route.transport_category == ToolResultTransportCategory.FLASHDUTY_API:
            if route.subtype == "alert":
                return self._process_flashduty_alert(raw_result, artifact)
            if route.subtype == "similar":
                return self._process_flashduty_similar(raw_result, artifact)
            return self._process_flashduty_api(
                raw_result,
                artifact,
                tool_name=route.subtype,
            )
        if route.transport_category == ToolResultTransportCategory.ALERT_CONTEXT:
            return self._process_local_alert_context(raw_result, artifact)
        return self._process_generic_mcp(
            raw_result,
            artifact,
            source_system=source_system,
        )

    @classmethod
    def _projection_route(
        cls,
        *,
        tool_name: str,
        source_system: str,
        raw_result: dict[str, Any],
    ) -> ToolResultProjectionRoute:
        normalized_tool = tool_name.strip().casefold()
        normalized_source = source_system.strip().casefold()
        if normalized_source in {"archery", "archery_mcp"}:
            return ToolResultProjectionRoute(
                ToolResultTransportCategory.ARCHERY_MCP,
                "query",
            )
        if normalized_source in {"prometheus", "prometheus_mcp"}:
            return ToolResultProjectionRoute(
                ToolResultTransportCategory.PROMETHEUS_MCP,
                "query",
            )
        if normalized_source in _FLASHDUTY_API_SOURCES:
            if (
                normalized_source in _FLASHDUTY_SIMILAR_SOURCES
                or normalized_tool in _FLASHDUTY_SIMILAR_TOOLS
            ):
                return ToolResultProjectionRoute(
                    ToolResultTransportCategory.FLASHDUTY_API,
                    "similar",
                )
            if (
                normalized_source in _FLASHDUTY_ALERT_SOURCES
                or normalized_tool in _FLASHDUTY_ALERT_TOOLS
            ):
                data = cls._structured_data(raw_result)
                if (
                    normalized_source == "alert_platform"
                    and normalized_tool == "alert_context"
                    and "flashduty" not in data
                ):
                    return ToolResultProjectionRoute(
                        ToolResultTransportCategory.ALERT_CONTEXT,
                        "local",
                    )
                return ToolResultProjectionRoute(
                    ToolResultTransportCategory.FLASHDUTY_API,
                    "alert",
                )
            return ToolResultProjectionRoute(
                ToolResultTransportCategory.FLASHDUTY_API,
                normalized_tool or "unknown",
            )
        if normalized_source.endswith("_mcp") or cls._has_generic_mcp_contract(raw_result):
            return ToolResultProjectionRoute(
                ToolResultTransportCategory.GENERIC_MCP,
                "generic",
            )
        safe_source = str(sanitize(source_system))[:128]
        safe_tool = str(sanitize(tool_name))[:128]
        raise AdvisorError(
            "unsupported tool-result projection route: "
            f"source_system={safe_source!r}, tool_name={safe_tool!r}"
        )

    @classmethod
    def _has_generic_mcp_contract(cls, raw_result: dict[str, Any]) -> bool:
        observations = cls._structured_data(raw_result).get("observations")
        if not isinstance(observations, list) or not observations:
            return False
        return all(
            isinstance(item, Mapping)
            and isinstance(item.get("projection"), Mapping)
            and item["projection"].get("projection_type") == "deterministic_fact_projection"
            and isinstance(item.get("has_data"), bool)
            and isinstance(item.get("is_error"), bool)
            for item in observations
        )

    @staticmethod
    def _structured_data(raw_result: dict[str, Any]) -> dict[str, Any]:
        value = raw_result.get("structured_data")
        return value if isinstance(value, dict) else {}

    def _process_archery(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis:
        """Pass the Archery final query result through with format conversion only.

        The program converts the JSON embedded in the Archery ``result`` text into
        a JSON object (positional rows are labeled with ``column_list`` upstream)
        and forwards it unchanged: no filtering, aggregation, sorting, truncation,
        or size limit is applied. The projection never judges causality.
        """

        data = self._structured_data(raw_result)
        base = "/structured_data"
        raw_slow_query_analysis = data.get("slow_query_analysis")
        slow_query_analysis = (
            _model_visible_projection(raw_slow_query_analysis)
            if isinstance(raw_slow_query_analysis, Mapping)
            else None
        )

        if data.get("final_result_parse_failed") is True:
            raw_text = data.get("final_result_text")
            text = raw_text if isinstance(raw_text, str) and raw_text else None
            return _analysis(
                artifact=artifact,
                summary=(
                    "Archery 最终查询结果的内嵌 JSON 无法解析；原始文本已原样放入 "
                    "passthrough_payload.final_result_text，未做删改，"
                    "该结果不能用于根因判断。"
                ),
                observations=[
                    ToolResultObservation(
                        statement=(
                            "Archery MCP 最终查询结果的内嵌 JSON 解析失败；原始文本已原样"
                            "放入 passthrough_payload.final_result_text（未删改）。"
                            "该文本未经程序结构化校验，不能用于根因判断。"
                        ),
                        source_paths=[f"{base}/final_result_text"],
                    )
                ],
                limitations=[
                    "Archery 最终查询结果文本未能转换为 JSON；已原样保留原始文本，"
                    "该结果不能用于根因判断。"
                ],
                analysis_usable=False,
                passthrough_payload=({"final_result_text": text} if text else None),
                passthrough_parse_failed=True,
                slow_query_analysis=slow_query_analysis,
            )

        payload = data.get("final_result_payload")
        if isinstance(payload, Mapping):
            rows = payload.get("rows")
            row_text = f"rows 共 {len(rows)} 行" if isinstance(rows, list) else "rows 行数未知"
            limitations: list[str] = []
            if not (isinstance(rows, list) and rows):
                limitations.append("Archery 最终查询结果没有数据行。")
            return _analysis(
                artifact=artifact,
                summary=(
                    "Archery 最终查询结果（若因内容过长被 MCP 截断，则为按 id 分次查询后"
                    f"合并的结果）已仅做格式转换为 JSON 并完整透传：{row_text}；"
                    "程序只更改事实格式为 JSON，不判断因果。"
                ),
                observations=[
                    ToolResultObservation(
                        statement=(
                            "Archery MCP 最终查询结果的完整内容位于 "
                            "passthrough_payload.final_result_payload：程序仅将 result 文本"
                            "中的内嵌 JSON 按 column_list 转换为 JSON 格式，不过滤、"
                            f"不聚合、不排序、不截断、不设大小限制；{row_text}。"
                            "程序只更改事实格式为 JSON，不判断因果。"
                        ),
                        source_paths=[f"{base}/final_result_payload"],
                    )
                ],
                limitations=limitations,
                analysis_usable=isinstance(rows, list) and bool(rows),
                passthrough_payload=dict(payload),
                slow_query_analysis=slow_query_analysis,
            )

        return _analysis(
            artifact=artifact,
            summary="Archery 本次调查没有产生可透传的最终查询结果。",
            observations=[],
            limitations=["Archery 本次调查没有产生最终查询结果，没有可透传的内容。"],
            analysis_usable=False,
            slow_query_analysis=slow_query_analysis,
        )

    def _process_prometheus(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis:
        data = self._structured_data(raw_result)
        results = data.get("monitoring_results")
        results = results if isinstance(results, list) else []
        schema_version = data.get("schema_version")
        if schema_version in {
            "prometheus-evidence-v3",
            "prometheus-evidence-v4",
            "prometheus-evidence-v5",
        } or any(isinstance(item, Mapping) and "projection_kind" in item for item in results):
            return self._process_prometheus_range_projections(
                data,
                results,
                artifact,
            )
        required_target = data.get("required_target")
        required_target = required_target if isinstance(required_target, Mapping) else {}
        required_window, window_error = self._prometheus_required_window(data)
        selected: list[
            tuple[
                int,
                Mapping[str, Any],
                str,
                dict[str, Any],
                list[tuple[datetime, float, int]],
            ]
        ] = []
        no_sample_results: list[tuple[int, Mapping[str, Any]]] = []
        excluded: Counter[str] = Counter()
        target_mismatch_dimensions: Counter[str] = Counter()
        unverified_target_dimensions: Counter[str] = Counter()
        total_series_count = 0
        total_numeric_sample_count = 0
        excluded_sample_count = 0
        has_required_target = self._prometheus_has_required_target(required_target)
        for index, item in enumerate(results):
            if not isinstance(item, Mapping):
                excluded["invalid_result"] += 1
                continue
            if self._is_catalog_or_metadata_result(item):
                excluded["catalog_or_metadata"] += 1
                continue
            series = self._metric_series(item.get("result"))
            if not series:
                excluded["no_numeric_samples"] += 1
                no_sample_results.append((index, item))
                continue
            for relative_path, metric, samples in series:
                total_series_count += 1
                total_numeric_sample_count += len(samples)
                if not has_required_target:
                    excluded["target_context_missing_series"] += 1
                    excluded_sample_count += len(samples)
                    continue
                mismatches, unverified = self._prometheus_target_assessment(
                    metric,
                    required_target,
                )
                if mismatches:
                    excluded["target_mismatch_series"] += 1
                    target_mismatch_dimensions.update(mismatches)
                    excluded_sample_count += len(samples)
                    continue
                if unverified:
                    excluded["target_unverified_series"] += 1
                    unverified_target_dimensions.update(unverified)
                    excluded_sample_count += len(samples)
                    continue
                if required_window is None:
                    excluded["window_unverifiable_series"] += 1
                    excluded["timestamp_unverifiable_samples"] += len(samples)
                    excluded_sample_count += len(samples)
                    continue

                included_samples: list[tuple[datetime, float, int]] = []
                for sample in samples:
                    timestamp = self._prometheus_timestamp(sample.timestamp)
                    if timestamp is None:
                        excluded["timestamp_unverifiable_samples"] += 1
                        excluded_sample_count += 1
                        continue
                    if not required_window.start <= timestamp <= required_window.end:
                        excluded["outside_required_window_samples"] += 1
                        excluded_sample_count += 1
                        continue
                    included_samples.append((timestamp, sample.value, sample.source_index))
                if not included_samples:
                    excluded["no_samples_in_required_window_series"] += 1
                    continue
                included_samples.sort(key=lambda sample: (sample[0], sample[2]))
                selected.append((index, item, relative_path, metric, included_samples))

        observations: list[ToolResultObservation] = [
            ToolResultObservation(
                statement=(
                    f"Prometheus 返回 {len(results)} 项、{total_series_count} 条数值时序，"
                    f"选择 {len(selected)} 条时序；排除统计 "
                    f"{_bounded_json(dict(sorted(excluded.items())))}；目标不匹配维度 "
                    f"{_bounded_json(dict(sorted(target_mismatch_dimensions.items())))}；"
                    "目标无法核验维度 "
                    f"{_bounded_json(dict(sorted(unverified_target_dimensions.items())))}。"
                    "程序投影只使用 FlashDuty 详情形成的告警目标和告警发生前五分钟窗口；"
                    "MCP 原始响应、辅助目录和目标发现内容仅保存在审计工件。"
                ),
                source_paths=self._prometheus_context_paths(data),
            )
        ]
        series_count = 0
        sample_count = 0
        omitted_series_count = max(len(selected) - _MAX_SELECTED_ITEMS, 0)
        for result_index, item, relative_path, metric, samples in selected[:_MAX_SELECTED_ITEMS]:
            result_path = f"/structured_data/monitoring_results/{result_index}/result"
            series_count += 1
            sample_count += len(samples)
            values = [value for _timestamp, value, _source_index in samples]
            latest = values[-1]
            statement = {
                "tool_name": item.get("tool_name"),
                "capability": item.get("capability"),
                "metric": self._prometheus_metric_identity(metric),
                "sample_count": len(values),
                "first_timestamp": samples[0][0].isoformat(),
                "latest_timestamp": samples[-1][0].isoformat(),
                "min": _display_number(min(values)),
                "max": _display_number(max(values)),
                "avg": _display_number(sum(values) / len(values)),
                "latest": _display_number(latest),
                "delta": _display_number(latest - values[0]),
            }
            observations.append(
                ToolResultObservation(
                    statement=(
                        "Prometheus 告警目标五分钟窗口内时序聚合（按时间戳升序计算 "
                        f"latest/delta）：{_bounded_json(statement)}"
                    ),
                    source_paths=[
                        f"{result_path}{relative_path}",
                        "/structured_data/required_target",
                        "/structured_data/window_start",
                        "/structured_data/window_end",
                    ],
                )
            )
        for result_index, item in no_sample_results[:_MAX_SELECTED_ITEMS]:
            source_path = f"/structured_data/monitoring_results/{result_index}"
            if "result" in item:
                source_path += "/result"
            observations.append(
                ToolResultObservation(
                    statement=(
                        "Prometheus 调用返回中未发现可解析的数值时序样本："
                        f"tool_name={item.get('tool_name')!s}。该事实不包含根因判断。"
                    ),
                    source_paths=[source_path],
                )
            )
        limitations: list[str] = []
        if window_error is not None:
            limitations.append(window_error)
        if not has_required_target:
            limitations.append(
                "告警详情没有可用于 Prometheus 结果归属的数据库目标；数值返回未进入主 Agent 事实。"
            )
        if unverified_target_dimensions:
            limitations.append(
                "已排除未携带完整目标标签、无法归属到告警数据库的时序；未核对维度统计 "
                f"{_bounded_json(dict(sorted(unverified_target_dimensions.items())))}。"
                "程序不根据缺失标签猜测目标。"
            )
        if target_mismatch_dimensions:
            limitations.append(
                "已排除与告警 alarm_host/alarm_port/database 明确不匹配的时序；"
                f"维度统计 {_bounded_json(dict(sorted(target_mismatch_dimensions.items())))}。"
            )
        if excluded_sample_count:
            limitations.append(
                f"已从主 Agent 投影排除 {excluded_sample_count}/{total_numeric_sample_count} "
                "个目标不匹配、时间戳不可验证或位于五分钟窗口外的数值样本；"
                "完整返回保存在源工件。"
            )
        if omitted_series_count:
            limitations.append(
                f"主 Agent 投影仅展示稳定排序后的前 {_MAX_SELECTED_ITEMS} 条匹配时序；"
                f"另有 {omitted_series_count} 条匹配时序保存在源工件。"
            )
        if no_sample_results:
            limitations.append(
                f"{len(no_sample_results)} 项 Prometheus 非目录返回没有可解析的数值时序"
                "样本；已记录为无样本，完整返回保存在源工件。"
            )
        if len(no_sample_results) > _MAX_SELECTED_ITEMS:
            limitations.append(f"程序事实投影仅展示前 {_MAX_SELECTED_ITEMS} 项无样本记录。")
        if not results:
            limitations.append("Prometheus MCP 没有返回可供程序事实投影的调用结果。")
        elif not selected:
            limitations.append("Prometheus 返回中没有可聚合的数值时序样本。")
        return _analysis(
            artifact=artifact,
            summary=(
                "Prometheus 告警目标五分钟窗口程序事实投影："
                f"匹配 {len(selected)}/{total_series_count} 条数值时序；"
                f"向主 Agent 展示 {series_count} 条时序、{sample_count} 个数值样本。"
            ),
            observations=observations if results else [],
            limitations=limitations,
            analysis_usable=(
                series_count > 0 and required_window is not None and has_required_target
            ),
        )

    def _process_prometheus_range_projections(
        self,
        data: Mapping[str, Any],
        results: list[Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis:
        """Validate public projections without reinterpreting their semantic fields."""

        raw_range_query_success_count = data.get("range_query_success_count")
        range_query_success_count = (
            raw_range_query_success_count
            if isinstance(raw_range_query_success_count, int)
            and not isinstance(raw_range_query_success_count, bool)
            and raw_range_query_success_count >= 0
            else 0
        )
        raw_range_query_empty_count = data.get("range_query_empty_count")
        range_query_empty_count = (
            raw_range_query_empty_count
            if isinstance(raw_range_query_empty_count, int)
            and not isinstance(raw_range_query_empty_count, bool)
            and raw_range_query_empty_count >= 0
            else 0
        )

        required_window, window_error = self._prometheus_required_window(data)
        required_target = data.get("required_target")
        required_target = required_target if isinstance(required_target, Mapping) else {}
        has_required_target = self._prometheus_has_required_target(required_target)
        required_host = self._normalized_identity(required_target.get("host"))
        requires_value_semantics = data.get("schema_version") == "prometheus-evidence-v5"
        excluded: Counter[str] = Counter()
        selected: list[
            tuple[
                int,
                int,
                Mapping[str, Any],
                Mapping[str, Any],
                dict[str, Any],
                str,
            ]
        ] = []
        provider_omitted_series_count = 0

        for result_index, item in enumerate(results):
            if not isinstance(item, Mapping):
                excluded["invalid_result"] += 1
                continue
            if item.get("projection_kind") != "alert_window_range":
                excluded["non_range_projection"] += 1
                continue
            projection = item.get("projection")
            if not isinstance(projection, Mapping):
                excluded["invalid_projection"] += 1
                continue
            if projection.get("projection_kind") != "alert_window_range":
                excluded["projection_kind_mismatch"] += 1
                continue
            projected_window = projection.get("window")
            if not isinstance(projected_window, Mapping):
                excluded["window_missing"] += 1
                continue
            projected_start = self._prometheus_timestamp(projected_window.get("start"))
            projected_end = self._prometheus_timestamp(projected_window.get("end"))
            if (
                required_window is None
                or projected_start != required_window.start
                or projected_end != required_window.end
            ):
                excluded["window_mismatch"] += 1
                continue
            target_match = projection.get("target_match")
            matched_fields = (
                target_match.get("authoritative_fields")
                if isinstance(target_match, Mapping) and target_match.get("matched") is True
                else None
            )
            if (
                not has_required_target
                or not isinstance(matched_fields, list)
                or not matched_fields
                or (required_host is not None and "database.host" not in matched_fields)
                or not all(
                    isinstance(field, str)
                    and field
                    in {
                        "cluster",
                        "database.database",
                        "database.endpoint",
                        "database.host",
                        "database.instance",
                    }
                    for field in matched_fields
                )
            ):
                excluded["target_match_invalid"] += 1
                continue
            timeseries = projection.get("timeseries")
            series = timeseries.get("series") if isinstance(timeseries, Mapping) else None
            if not isinstance(series, list):
                excluded["series_missing"] += 1
                continue

            selected_start = len(selected)
            accepted_samples = 0
            for series_index, summary in enumerate(series):
                if not isinstance(summary, Mapping):
                    excluded["invalid_series_summary"] += 1
                    continue
                sample_count = summary.get("sample_count")
                values = {
                    key: _number(summary.get(key))
                    for key in ("min", "max", "avg", "latest", "delta")
                }
                if (
                    not isinstance(sample_count, int)
                    or isinstance(sample_count, bool)
                    or sample_count <= 0
                    or any(value is None for value in values.values())
                    or values["min"] > values["max"]
                    or not values["min"] <= values["avg"] <= values["max"]
                ):
                    excluded["invalid_series_summary"] += 1
                    continue
                metric_identity = self._prometheus_public_metric_identity(summary.get("metric"))
                if metric_identity is None:
                    excluded["metric_identity_missing_or_invalid_series"] += 1
                    continue
                raw_value_semantics = summary.get("value_semantics")
                if raw_value_semantics is None and not requires_value_semantics:
                    value_semantics = "unknown"
                elif (
                    isinstance(raw_value_semantics, str)
                    and raw_value_semantics in _PROMETHEUS_VALUE_SEMANTICS
                ):
                    value_semantics = raw_value_semantics
                else:
                    excluded["invalid_value_semantics_series"] += 1
                    continue
                selected.append(
                    (
                        result_index,
                        series_index,
                        item,
                        summary,
                        metric_identity,
                        value_semantics,
                    )
                )
                accepted_samples += sample_count

            declared_series_count = timeseries.get("series_count")
            declared_sample_count = timeseries.get("sample_count")
            omitted_series_count = timeseries.get("omitted_series_count", 0)
            identity_missing_count = timeseries.get("excluded_metric_identity_missing_count", 0)
            identity_collision_count = timeseries.get("excluded_metric_identity_collision_count", 0)
            if (
                not isinstance(declared_series_count, int)
                or isinstance(declared_series_count, bool)
                or not isinstance(declared_sample_count, int)
                or isinstance(declared_sample_count, bool)
                or declared_sample_count < accepted_samples
                or not isinstance(omitted_series_count, int)
                or isinstance(omitted_series_count, bool)
                or omitted_series_count < 0
                or declared_series_count != len(series) + omitted_series_count
                or not isinstance(identity_missing_count, int)
                or isinstance(identity_missing_count, bool)
                or identity_missing_count < 0
                or not isinstance(identity_collision_count, int)
                or isinstance(identity_collision_count, bool)
                or identity_collision_count < 0
            ):
                del selected[selected_start:]
                excluded["inconsistent_projection_counts"] += 1
                continue
            provider_omitted_series_count += omitted_series_count
            if identity_missing_count:
                excluded["metric_identity_missing_series"] += identity_missing_count
            if identity_collision_count:
                excluded["metric_identity_collision_series"] += identity_collision_count

        identity_counts = Counter(
            json.dumps(
                {"metric": metric_identity, "value_semantics": value_semantics},
                ensure_ascii=True,
                sort_keys=True,
            )
            for (
                _result_index,
                _series_index,
                _item,
                _summary,
                metric_identity,
                value_semantics,
            ) in selected
        )
        colliding_identities = {
            identity for identity, count in identity_counts.items() if count > 1
        }
        if colliding_identities:
            retained = []
            for candidate in selected:
                identity = json.dumps(
                    {"metric": candidate[4], "value_semantics": candidate[5]},
                    ensure_ascii=True,
                    sort_keys=True,
                )
                if identity in colliding_identities:
                    excluded["metric_identity_collision_series"] += 1
                else:
                    retained.append(candidate)
            selected = retained

        total_projected_samples = sum(int(candidate[3]["sample_count"]) for candidate in selected)
        observations: list[ToolResultObservation] = []
        if results:
            observations.append(
                ToolResultObservation(
                    statement=(
                        f"Prometheus 公开投影共 {len(results)} 项；通过协议校验的时序 "
                        f"{len(selected)} 条、数值样本 {total_projected_samples} 个；"
                        f"排除统计 {_bounded_json(dict(sorted(excluded.items())))}。"
                        "目标发现、服务发现、指标目录、元数据和 MCP 原始响应未进入主 Agent。"
                    ),
                    source_paths=self._prometheus_context_paths(data),
                )
            )
        globally_omitted = max(len(selected) - _MAX_SELECTED_ITEMS, 0)
        exposed_samples = 0
        for (
            result_index,
            series_index,
            item,
            summary,
            metric_identity,
            value_semantics,
        ) in selected[:_MAX_SELECTED_ITEMS]:
            sample_count = int(summary["sample_count"])
            exposed_samples += sample_count
            raw_tool_name = item.get("tool_name")
            tool_name = sanitize(str(raw_tool_name or "prometheus_range"))[:200]
            statement = {
                "tool_name": tool_name,
                "metric": metric_identity,
                "value_semantics": value_semantics,
                "sample_count": sample_count,
                "min": summary.get("min"),
                "max": summary.get("max"),
                "avg": summary.get("avg"),
                "latest": summary.get("latest"),
                "delta": summary.get("delta"),
            }
            statement_json = json.dumps(
                sanitize(statement),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            base = f"/structured_data/monitoring_results/{result_index}/projection"
            observations.append(
                ToolResultObservation(
                    statement=(f"Prometheus 告警目标五分钟窗口内时序聚合：{statement_json}"),
                    source_paths=[
                        f"{base}/timeseries/series/{series_index}",
                        f"{base}/window",
                        f"{base}/target_match",
                    ],
                )
            )

        limitations: list[str] = []
        if window_error is not None:
            limitations.append(window_error)
        if not has_required_target:
            limitations.append(
                "告警详情没有可用于 Prometheus 结果归属的数据库目标；公开投影未进入主 Agent 事实。"
            )
        if excluded:
            limitations.append(
                "已排除未通过公开投影协议校验的 Prometheus 项："
                f"{_bounded_json(dict(sorted(excluded.items())))}。"
            )
        if provider_omitted_series_count:
            limitations.append(
                f"Provider 公开投影按完整时序项省略 {provider_omitted_series_count} 条；"
                "完整响应仅保存在源工件。"
            )
        if globally_omitted:
            limitations.append(
                f"主 Agent 仅展示稳定顺序中的前 {_MAX_SELECTED_ITEMS} 条时序；"
                f"另有 {globally_omitted} 条合格投影保留在源工件。"
            )
        if not results:
            if range_query_success_count:
                limitations.append(
                    "Prometheus MCP 已成功执行范围查询，但没有生成合格的告警窗口数值投影。"
                )
                if range_query_empty_count:
                    limitations.append("空结果不证明目标未被监控。")
            else:
                limitations.append("Prometheus MCP 没有返回合格的告警窗口范围投影。")
        elif not selected:
            limitations.append("Prometheus 公开返回中没有通过协议校验的范围时序投影。")
        query_summary = (
            f"成功范围查询 {range_query_success_count} 次；" if range_query_success_count else ""
        )
        return _analysis(
            artifact=artifact,
            summary=(
                "Prometheus 告警目标五分钟窗口程序事实投影："
                f"{query_summary}通过校验 {len(selected)} 条时序；向主 Agent 展示 "
                f"{min(len(selected), _MAX_SELECTED_ITEMS)} 条时序、"
                f"{exposed_samples} 个数值样本。"
            ),
            observations=observations,
            limitations=limitations,
            analysis_usable=bool(selected) and required_window is not None and has_required_target,
        )

    @staticmethod
    def _prometheus_context_paths(data: Mapping[str, Any]) -> list[str]:
        paths = ["/structured_data/monitoring_results"]
        for key in ("required_target", "window_start", "window_end"):
            if key in data:
                paths.append(f"/structured_data/{key}")
        return paths

    @classmethod
    def _prometheus_required_window(
        cls,
        data: Mapping[str, Any],
    ) -> tuple[_PrometheusWindow | None, str | None]:
        start = cls._prometheus_timestamp(data.get("window_start"))
        end = cls._prometheus_timestamp(data.get("window_end"))
        if start is None or end is None:
            return None, (
                "Prometheus 证据缺少可验证的告警五分钟窗口起止时间；"
                "所有数值样本均未进入主 Agent 事实。"
            )
        duration = (end - start).total_seconds()
        if duration != _PROMETHEUS_WINDOW_SECONDS:
            return None, (
                "Prometheus 证据中的窗口不是告警发生前精确五分钟"
                f"（实际 {duration:g} 秒）；所有数值样本均未进入主 Agent 事实。"
            )
        return _PrometheusWindow(start=start, end=end), None

    @staticmethod
    def _prometheus_has_required_target(target: Mapping[str, Any]) -> bool:
        return any(
            value is not None
            for value in (
                DeterministicToolResultProcessor._normalized_engine(target.get("database_engine")),
                DeterministicToolResultProcessor._normalized_identity(target.get("database")),
                DeterministicToolResultProcessor._normalized_identity(target.get("host")),
                DeterministicToolResultProcessor._port(target.get("port")),
            )
        )

    @classmethod
    def _prometheus_target_assessment(
        cls,
        metric: Mapping[str, Any],
        target: Mapping[str, Any],
    ) -> tuple[list[str], list[str]]:
        mismatches: list[str] = []
        unverified: list[str] = []

        required_host = cls._normalized_identity(target.get("host"))
        host_values = cls._label_values(metric, _HOST_LABEL_KEYS)
        parsed_endpoints = [cls._endpoint_parts(value) for value in host_values]
        candidate_hosts = {host for host, _port in parsed_endpoints if host}
        if required_host:
            if candidate_hosts and required_host not in candidate_hosts:
                mismatches.append("alarm_host")
            elif not candidate_hosts:
                unverified.append("alarm_host")

        required_port = cls._port(target.get("port"))
        explicit_ports = {
            port
            for value in cls._label_values(metric, _PORT_LABEL_KEYS)
            if (port := cls._port(value)) is not None
        }
        endpoint_ports = {
            port
            for host, port in parsed_endpoints
            if port is not None and (not required_host or host == required_host)
        }
        candidate_ports = explicit_ports | endpoint_ports
        if required_port is not None:
            if candidate_ports and required_port not in candidate_ports:
                mismatches.append("alarm_port")
            elif not candidate_ports:
                unverified.append("alarm_port")

        required_database = cls._normalized_identity(target.get("database"))
        candidate_databases = {
            value
            for raw in cls._label_values(metric, _DATABASE_LABEL_KEYS)
            if (value := cls._normalized_identity(raw))
        }
        if required_database:
            if candidate_databases and required_database not in candidate_databases:
                mismatches.append("database")
            elif not candidate_databases:
                unverified.append("database")

        required_engine = cls._normalized_engine(target.get("database_engine"))
        candidate_engines = {
            engine
            for raw in cls._label_values(metric, _ENGINE_LABEL_KEYS)
            if (engine := cls._normalized_engine(raw))
        }
        if required_engine:
            if candidate_engines and required_engine not in candidate_engines:
                mismatches.append("database_engine")
            elif not candidate_engines:
                unverified.append("database_engine")
        return mismatches, unverified

    @staticmethod
    def _label_values(metric: Mapping[str, Any], keys: frozenset[str]) -> list[Any]:
        return [
            value
            for key, value in metric.items()
            if str(key).strip().casefold() in keys and value not in (None, "")
        ]

    @staticmethod
    def _normalized_identity(value: Any) -> str | None:
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return None
        normalized = str(value).strip().strip("[]").casefold().rstrip(".")
        return normalized or None

    @classmethod
    def _endpoint_parts(cls, value: Any) -> tuple[str | None, int | None]:
        normalized = cls._normalized_identity(value)
        if not normalized:
            return None, None
        candidate = normalized.rsplit("/", 1)[-1]
        if candidate.startswith("[") and "]:" in candidate:
            host, raw_port = candidate[1:].rsplit("]:", 1)
        elif candidate.count(":") == 1:
            host, raw_port = candidate.rsplit(":", 1)
        else:
            return candidate.strip("[]"), None
        port = cls._port(raw_port)
        return (host.rstrip(".") or None), port

    @staticmethod
    def _port(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        try:
            port = int(str(value).strip())
        except (TypeError, ValueError):
            return None
        return port if 1 <= port <= 65_535 else None

    @staticmethod
    def _normalized_engine(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = re.sub(r"[^a-z0-9]+", " ", value.casefold())
        for engine, aliases in _ENGINE_ALIASES.items():
            if any(re.search(rf"\b{re.escape(alias)}\b", normalized) for alias in aliases):
                return engine
        return None

    @staticmethod
    def _prometheus_public_metric_identity(value: Any) -> dict[str, Any] | None:
        if not isinstance(value, Mapping):
            return None
        visible = _model_visible_projection(value)
        if not isinstance(visible, Mapping) or not visible:
            return None
        if len(visible) > _PROMETHEUS_PUBLIC_METRIC_MAX_KEYS:
            return None

        identity: dict[str, Any] = {}
        for raw_key, raw_value in sorted(visible.items(), key=lambda item: str(item[0])):
            if not isinstance(raw_key, str) or not _PROMETHEUS_PUBLIC_METRIC_KEY.fullmatch(raw_key):
                return None
            if not isinstance(raw_value, str) or not raw_value.strip():
                return None
            projected_value = sanitize(raw_value)
            if not isinstance(projected_value, str) or len(projected_value) > 200:
                return None
            if raw_key == "__name__" and not _PROMETHEUS_PUBLIC_METRIC_NAME.fullmatch(
                projected_value
            ):
                return None
            identity[raw_key] = projected_value

        serialized = json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(serialized) > _PROMETHEUS_PUBLIC_METRIC_MAX_JSON_CHARS:
            return None
        return identity

    @staticmethod
    def _prometheus_metric_identity(metric: Mapping[str, Any]) -> dict[str, Any]:
        visible_keys = (
            _HOST_LABEL_KEYS
            | _PORT_LABEL_KEYS
            | _DATABASE_LABEL_KEYS
            | _ENGINE_LABEL_KEYS
            | _LEGACY_PROMETHEUS_SEMANTIC_LABEL_KEYS
            | frozenset({"cluster", "namespace"})
        )
        return {
            str(key): sanitize(value)
            for key, value in sorted(metric.items(), key=lambda item: str(item[0]))
            if str(key).strip().casefold() in visible_keys
        }

    @staticmethod
    def _prometheus_timestamp(value: Any) -> datetime | None:
        if isinstance(value, bool) or value is None:
            return None
        numeric: float | None = None
        if isinstance(value, (int, float)):
            numeric = float(value)
        elif isinstance(value, str):
            stripped = value.strip()
            try:
                numeric = float(stripped)
            except ValueError:
                try:
                    parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
                except ValueError:
                    return None
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    return None
                return parsed.astimezone(UTC)
        if numeric is None or not math.isfinite(numeric):
            return None
        magnitude = abs(numeric)
        if magnitude >= 1e17:
            numeric /= 1e9
        elif magnitude >= 1e14:
            numeric /= 1e6
        elif magnitude >= 1e11:
            numeric /= 1e3
        try:
            return datetime.fromtimestamp(numeric, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None

    @staticmethod
    def _is_catalog_or_metadata_result(item: Mapping[str, Any]) -> bool:
        capability = str(item.get("capability") or "").casefold()
        tool_name = str(item.get("tool_name") or "").casefold()
        return any(
            marker in capability or marker in tool_name
            for marker in (
                "catalog",
                "metadata",
                "list_metric",
                "discover_metric",
                "target_discovery",
                "list_target",
                "get_target",
                "discover_target",
            )
        )

    def _metric_series(
        self,
        value: Any,
        *,
        path: str = "",
    ) -> list[tuple[str, dict[str, Any], list[_PrometheusSample]]]:
        found: list[tuple[str, dict[str, Any], list[_PrometheusSample]]] = []
        if isinstance(value, Mapping):
            metric = value.get("metric")
            metric = dict(metric) if isinstance(metric, Mapping) else {}
            samples = self._samples(value)
            if samples:
                sample_key = "values" if isinstance(value.get("values"), list) else "value"
                found.append((f"{path}/{sample_key}", metric, samples))
                return found
            for key, child in value.items():
                found.extend(self._metric_series(child, path=f"{path}/{_pointer_token(str(key))}"))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                found.extend(self._metric_series(child, path=f"{path}/{index}"))
        return found

    @staticmethod
    def _samples(value: Mapping[str, Any]) -> list[_PrometheusSample]:
        raw_values = value.get("values")
        candidates = raw_values if isinstance(raw_values, list) else [value.get("value")]
        result: list[_PrometheusSample] = []
        for source_index, sample in enumerate(candidates):
            if isinstance(sample, Sequence) and not isinstance(sample, (str, bytes)):
                if len(sample) < 2:
                    continue
                timestamp, raw_number = sample[0], sample[1]
            else:
                timestamp, raw_number = None, sample
            number = _number(raw_number)
            if number is not None:
                result.append(
                    _PrometheusSample(
                        timestamp=timestamp,
                        value=number,
                        source_index=source_index,
                    )
                )
        return result

    @staticmethod
    def _visible_fact(value: Any) -> Any | None:
        projected = _model_visible_projection(value)
        if projected in (None, "", [], {}):
            return None
        return projected

    def _process_local_alert_context(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis:
        data = self._structured_data(raw_result)
        visible = self._visible_fact(data)
        observations = (
            [
                ToolResultObservation(
                    statement=(f"告警事件随附的本地上下文={_bounded_json(visible)}"),
                    source_paths=["/structured_data"],
                )
            ]
            if visible is not None
            else []
        )
        return _analysis(
            artifact=artifact,
            summary=(
                "已确定性处理告警事件随附的本地上下文。"
                if observations
                else "告警事件没有可投影的本地上下文。"
            ),
            observations=observations,
            limitations=([] if observations else ["告警事件没有可投影的本地上下文。"]),
            analysis_usable=bool(observations),
        )

    def _process_flashduty_alert(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis:
        data = self._structured_data(raw_result)
        observations: list[ToolResultObservation] = []

        def append_fact(*, label: str, value: Any, path: str) -> None:
            visible = self._visible_fact(value)
            if visible is None:
                return
            observations.append(
                ToolResultObservation(
                    statement=f"FlashDuty API {label}={_bounded_json(visible)}",
                    source_paths=[path],
                )
            )

        append_fact(
            label="告警的标准化本地上下文",
            value=data.get("local"),
            path="/structured_data/local",
        )
        flashduty = data.get("flashduty")
        partial_errors: Mapping[str, Any] | None = None
        if isinstance(flashduty, Mapping):
            for field, label in (
                ("alert", "告警详情"),
                ("events", "告警事件"),
                ("feed", "告警动态"),
                ("incident", "关联故障上下文"),
            ):
                append_fact(
                    label=label,
                    value=flashduty.get(field),
                    path=f"/structured_data/flashduty/{field}",
                )
            raw_partial_errors = flashduty.get("partial_errors")
            if isinstance(raw_partial_errors, Mapping) and raw_partial_errors:
                partial_errors = raw_partial_errors

        for field, label in (
            ("flashduty_alert_info", "权威告警详情"),
            ("alert_detail", "标准化告警详情"),
        ):
            append_fact(
                label=label,
                value=data.get(field),
                path=f"/structured_data/{field}",
            )

        limitations: list[str] = []
        if partial_errors is not None:
            limitations.append(f"FlashDuty API 部分辅助查询不可用={_bounded_json(partial_errors)}")
        if not observations:
            limitations.append("FlashDuty API 没有返回可投影的告警上下文。")
        return _analysis(
            artifact=artifact,
            summary=(
                f"已确定性处理 FlashDuty API 告警上下文：{len(observations)} 个事实单元进入投影。"
            ),
            observations=observations,
            limitations=limitations,
            analysis_usable=bool(observations),
        )

    def _process_flashduty_similar(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis:
        data = self._structured_data(raw_result)
        raw_items = data.get("items")
        items = raw_items if isinstance(raw_items, list) else []
        observations: list[ToolResultObservation] = []
        for index, item in enumerate(items[:_MAX_SELECTED_ITEMS]):
            visible = self._visible_fact(item)
            if visible is None:
                continue
            observations.append(
                ToolResultObservation(
                    statement=(f"FlashDuty API 历史相似告警上下文={_bounded_json(visible)}"),
                    source_paths=[f"/structured_data/items/{index}"],
                )
            )

        limitations = ["FlashDuty API 历史相似告警仅作为调查上下文，不能作为当前告警的根因证据。"]
        if len(items) > _MAX_SELECTED_ITEMS:
            limitations.append(
                f"主 Agent 仅展示前 {_MAX_SELECTED_ITEMS} 条历史相似告警；"
                "完整响应保留在审计工件中。"
            )
        if not observations:
            limitations.append("FlashDuty API 没有返回可投影的历史相似告警。")
        return _analysis(
            artifact=artifact,
            summary=(
                "已确定性处理 FlashDuty API 历史相似告警："
                f"{len(observations)}/{len(items)} 条进入上下文投影。"
            ),
            observations=observations,
            limitations=limitations,
            analysis_usable=bool(observations),
        )

    def _process_flashduty_api(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
        *,
        tool_name: str,
    ) -> ToolResultAnalysis:
        """Project a native FlashDuty API result without MCP-specific assumptions."""

        visible_data = self._visible_fact(self._structured_data(raw_result))
        fields = (
            sorted(visible_data.items(), key=lambda item: str(item[0]).casefold())
            if isinstance(visible_data, Mapping)
            else []
        )
        selected = fields[:_MAX_SELECTED_ITEMS]
        observations = [
            ToolResultObservation(
                statement=(
                    f"FlashDuty API tool_name={tool_name} 字段 {field}={_bounded_json(value)}"
                ),
                source_paths=[f"/structured_data/{_pointer_token(str(field))}"],
            )
            for field, value in selected
        ]
        limitations: list[str] = []
        if len(fields) > _MAX_SELECTED_ITEMS:
            limitations.append(
                f"主 Agent 仅展示前 {_MAX_SELECTED_ITEMS} 个 FlashDuty API 事实字段；"
                "完整响应保留在审计工件中。"
            )
        if not observations:
            limitations.append(f"FlashDuty API 工具 {tool_name} 没有返回可投影的事实字段。")
        return _analysis(
            artifact=artifact,
            summary=(
                f"已确定性处理 FlashDuty API 工具 {tool_name}："
                f"{len(observations)}/{len(fields)} 个事实字段进入投影。"
            ),
            observations=observations,
            limitations=limitations,
            analysis_usable=bool(observations),
        )

    def _process_generic_mcp(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
        *,
        source_system: str,
    ) -> ToolResultAnalysis:
        data = self._structured_data(raw_result)
        raw_observations = data.get("observations")
        raw_observations = raw_observations if isinstance(raw_observations, list) else []

        def has_projected_facts(item: Mapping[str, Any]) -> bool:
            projection = item.get("projection")
            if not isinstance(projection, Mapping):
                return False
            if "numeric_aggregates" in projection or "scalar_groups" in projection:
                return bool(projection.get("numeric_aggregates") or projection.get("scalar_groups"))
            visible = _model_visible_projection(projection)
            if not isinstance(visible, Mapping):
                return False
            control_keys = {
                "has_data",
                "ignored_metadata_field_count",
                "is_error",
                "payload_shape",
                "projection_type",
                "source_json_chars",
                "source_path",
            }
            return any(key not in control_keys for key in visible)

        selected = [
            (index, item)
            for index, item in enumerate(raw_observations)
            if isinstance(item, Mapping)
            and item.get("has_data") is True
            and item.get("is_error") is not True
            and has_projected_facts(item)
        ]
        observations: list[ToolResultObservation] = []
        if raw_observations:
            observations.append(
                ToolResultObservation(
                    statement=(
                        f"MCP provider={source_system!s} 返回 {len(raw_observations)} 次调用，"
                        f"选择 {len(selected)} 次；"
                        "保守选择规则：仅 has_data=true 且 is_error!=true 的调用进入主 Agent 投影。"
                    ),
                    source_paths=["/structured_data/observations"],
                )
            )
        for index, item in selected[:_MAX_SELECTED_ITEMS]:
            projection = _model_visible_projection(item["projection"])
            observations.append(
                ToolResultObservation(
                    statement=(
                        f"MCP provider={source_system!s} 成功调用 "
                        f"tool_name={item.get('tool_name')!s}；"
                        f"程序过滤、聚合和排序后的可追溯事实={_bounded_json(projection)}"
                    ),
                    source_paths=[f"/structured_data/observations/{index}/projection"],
                )
            )
        limitations: list[str] = []
        if len(selected) > _MAX_SELECTED_ITEMS:
            limitations.append(
                f"主 Agent 仅展示前 {_MAX_SELECTED_ITEMS} 次成功调用的程序事实投影；"
                "远端原始响应不进入主 Agent 上下文。"
            )
        if not selected:
            limitations.append(
                f"MCP provider={source_system!s} 没有满足保守选择规则的成功数据调用。"
            )
        return _analysis(
            artifact=artifact,
            summary=(
                f"已确定性处理 MCP provider={source_system!s} 返回："
                f"{len(selected)}/{len(raw_observations)} "
                "次调用进入投影。"
            ),
            observations=observations,
            limitations=limitations,
            analysis_usable=bool(selected),
        )


class FakeToolResultAnalyzer(DeterministicToolResultProcessor):
    """Backward-compatible deterministic processor for offline runtimes."""


class OpenAICompatibleToolResultAnalyzer(DeterministicToolResultProcessor):
    """Compatibility adapter for the program fact projection implementation."""

    def __init__(self, **legacy_ai_configuration: Any) -> None:
        del legacy_ai_configuration

    async def aclose(self) -> None:
        return None
