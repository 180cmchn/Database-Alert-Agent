from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.agent_runtime.contracts import ArtifactRef
from app.application.sanitization import sanitize
from app.domain.errors import AdvisorError
from app.domain.models import ToolResultAnalysis, ToolResultObservation

TOOL_RESULT_ANALYSIS_PROMPT_VERSION = "program-fact-projection-v3"
_MAX_SNIPPET_CHARS = 800
_MAX_SELECTED_ITEMS = 20
_ARCHERY_FINAL_TABLE = "mysql_slow_query_review_history"
_PROMETHEUS_WINDOW_SECONDS = 300
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
        "sha256",
        "source_artifact",
        "source_artifact_id",
        "source_sha256",
        "uri",
    }
)


def _model_visible_projection(value: Any) -> Any:
    """Remove audit provenance from an already bounded program projection."""

    if isinstance(value, Mapping):
        visible: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = str(raw_key)
            normalized = key.strip().casefold()
            if normalized.startswith("raw_") or normalized in _INTERNAL_PROVENANCE_KEYS:
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
    )


class DeterministicToolResultProcessor:
    """Project complete MCP results into bounded, traceable facts in program code.

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
        del tool_name, request
        if not isinstance(raw_result, dict):
            raise AdvisorError("complete tool result must be a JSON object")
        normalized_source = source_system.casefold()
        if normalized_source in {"archery", "archery_mcp"}:
            return self._process_archery(raw_result, artifact)
        if normalized_source in {"prometheus", "prometheus_mcp"}:
            return self._process_prometheus(raw_result, artifact)
        return self._process_generic(raw_result, artifact)

    @staticmethod
    def _structured_data(raw_result: dict[str, Any]) -> dict[str, Any]:
        value = raw_result.get("structured_data")
        return value if isinstance(value, dict) else {}

    def _process_archery(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis:
        data = self._structured_data(raw_result)
        rows = data.get("rows")
        rows = rows if isinstance(rows, list) else []
        base = "/structured_data"
        observations: list[ToolResultObservation] = []
        limitations: list[str] = []

        count_fields = (
            "reported_row_count",
            "parsed_row_count",
            "included_row_count",
            "omitted_row_count",
        )
        counts = {key: data.get(key) for key in count_fields if key in data}
        count_paths = [f"{base}/{key}" for key in counts]
        if count_paths:
            observations.append(
                ToolResultObservation(
                    statement=(
                        "Archery 最终慢查询结果计数："
                        f"{_bounded_json(counts)}；选择规则：仅使用 rows 中由最终 "
                        f"{_ARCHERY_FINAL_TABLE} 查询形成的语义行，登录、实例解析和"
                        "目录调用仅保留在原始审计工件。"
                    ),
                    source_paths=count_paths,
                )
            )

        fingerprints: Counter[tuple[str, str]] = Counter()
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            identity = row.get("checksum")
            if isinstance(identity, str) and identity.strip():
                fingerprints[("checksum", identity.strip())] += 1
                continue
            sample = row.get("sample")
            if isinstance(sample, str) and sample.strip():
                # The full sample is used only as an in-process equality key. It
                # is never copied into the grouping summary or replaced by a
                # program-generated digest.
                fingerprints[("sample", sample)] += 1
        if fingerprints:
            groups = []
            for index, ((kind, identity), count) in enumerate(
                sorted(fingerprints.items(), key=lambda item: item[0]),
                start=1,
            ):
                group: dict[str, Any] = {
                    "group": f"sql_group_{index}",
                    "record_count": count,
                    "identity_source": kind,
                }
                if kind == "checksum":
                    group["checksum"] = identity
                groups.append(group)
            observations.append(
                ToolResultObservation(
                    statement=(
                        f"慢查询语义行共 {len(rows)} 行、{len(fingerprints)} 个 SQL 分组；"
                        "分组规则为优先使用业务 checksum，否则只在程序内按完整 sample 等值分组："
                        f"{_bounded_json(groups)}"
                    ),
                    source_paths=[f"{base}/rows"],
                )
            )

        ranked: list[tuple[float, int, Mapping[str, Any], str]] = []
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                continue
            numeric = [
                (str(key), number)
                for key, value in row.items()
                if str(key).casefold().startswith("query_time_")
                and (number := _number(value)) is not None
            ]
            if numeric:
                field, score = max(numeric, key=lambda item: (item[1], item[0]))
            else:
                field, score = "row_order", 0.0
            ranked.append((score, index, row, field))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        for rank, (score, index, row, field) in enumerate(ranked[:_MAX_SELECTED_ITEMS], start=1):
            safe_fields = {
                key: value for key, value in row.items() if str(key).casefold() != "sample"
            }
            sample = row.get("sample")
            if isinstance(sample, str):
                safe_fields["sample_snippet"] = _bounded_json(sample, limit=400)
            observations.append(
                ToolResultObservation(
                    statement=(
                        f"慢查询样本排名 {rank}；稳定选择规则：query_time_* 最大值降序、"
                        f"原始行号升序；排序字段={field}，值={_display_number(score)}，"
                        f"事实={_bounded_json(safe_fields)}"
                    ),
                    source_paths=[f"{base}/rows/{index}"],
                )
            )
        if len(ranked) > _MAX_SELECTED_ITEMS:
            limitations.append(
                f"主 Agent 投影仅展示排序前 {_MAX_SELECTED_ITEMS} 行；"
                f"完整 {len(ranked)} 行保存在源工件。"
            )
        if not rows:
            limitations.append("Archery 最终慢查询结果没有可投影的语义行。")
        return _analysis(
            artifact=artifact,
            summary=(
                f"已确定性处理 Archery 最终慢查询结果：{len(rows)} 行；"
                "辅助认证、实例解析和目录返回未进入主 Agent 上下文。"
            ),
            observations=observations,
            limitations=limitations,
            analysis_usable=bool(rows),
        )

    def _process_prometheus(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
    ) -> ToolResultAnalysis:
        data = self._structured_data(raw_result)
        results = data.get("monitoring_results")
        results = results if isinstance(results, list) else []
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
    def _prometheus_metric_identity(metric: Mapping[str, Any]) -> dict[str, Any]:
        visible_keys = (
            _HOST_LABEL_KEYS
            | _PORT_LABEL_KEYS
            | _DATABASE_LABEL_KEYS
            | _ENGINE_LABEL_KEYS
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

    def _process_generic(
        self,
        raw_result: dict[str, Any],
        artifact: ArtifactRef,
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
                        f"通用 MCP 返回 {len(raw_observations)} 次调用，选择 {len(selected)} 次；"
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
                        f"通用 MCP 成功调用 tool_name={item.get('tool_name')!s}；"
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
            limitations.append("通用 MCP 没有满足保守选择规则的成功数据调用。")
        return _analysis(
            artifact=artifact,
            summary=(
                f"已确定性处理通用 MCP 返回：{len(selected)}/{len(raw_observations)} "
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
