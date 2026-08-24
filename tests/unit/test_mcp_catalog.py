from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from app.mcp_catalog import MCPCatalogConfigurationError, load_mcp_catalog

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _write_prompts(directory: Path, *, prefix: str = "server") -> dict[str, str]:
    prompt_directory = directory / "prompts" / prefix
    prompt_directory.mkdir(parents=True)
    references: dict[str, str] = {}
    for prompt_name in ("role", "purpose", "workflow", "safety"):
        prompt_path = prompt_directory / f"{prompt_name}.md"
        prompt_path.write_text(f"{prefix} {prompt_name}\n", encoding="utf-8")
        references[prompt_name] = str(prompt_path.relative_to(directory))
    return references


def _write_settings(directory: Path, servers: dict[str, object]) -> Path:
    path = directory / "settings.json"
    path.write_text(
        json.dumps({"mcpServers": servers}, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def _server_config(directory: Path, **overrides: object) -> dict[str, object]:
    config: dict[str, object] = {
        "url": "${EXAMPLE_MCP_URL}",
        "headers": {"Authorization": "${EXAMPLE_MCP_API_KEY}"},
        "prompts": _write_prompts(directory),
    }
    config.update(overrides)
    return config


def test_project_catalog_loads_secret_free_selection_and_execution_metadata() -> None:
    catalog = load_mcp_catalog(PROJECT_ROOT / "config/mcp/settings.json")

    assert tuple(server.name for server in catalog.servers) == (
        "archery",
        "prometheus",
    )
    candidates = catalog.selection_candidates()
    assert tuple(candidate.name for candidate in candidates) == ("archery", "prometheus")
    assert all(not hasattr(candidate, "read_only") for candidate in candidates)
    assert all(not hasattr(candidate, "url_template") for candidate in candidates)

    archery = catalog.require("archery")
    assert archery.url_template == "${ARCHERY_MCP_URL}"
    assert archery.header_templates == {
        "X-Archery-Token": "${ARCHERY_MCP_TOKEN}"
    }
    assert archery.referenced_environment_variables == (
        "ARCHERY_MCP_URL",
        "ARCHERY_MCP_TOKEN",
    )
    assert "慢查询日志" in archery.prompts.purpose
    assert "t_instance_member" in archery.prompts.workflow
    assert "mysql_slow_query_review_history" in archery.prompts.workflow
    assert "<!-- directive:" not in archery.prompts.workflow
    assert "<!-- /directive -->" not in archery.prompts.workflow
    authored_archery_workflow = (
        PROJECT_ROOT / "config/mcp/prompts/archery/workflow.md"
    ).read_text(encoding="utf-8").strip()
    assert archery.prompts.workflow_revision == sha256(
        authored_archery_workflow.encode("utf-8")
    ).hexdigest()
    assert archery.prompts.workflow_directives[
        "archery.history.truncation.fetch_single_id"
    ].startswith("取得完整 id 清单后")
    assert archery.prompts.workflow_directives[
        "archery.history.truncation.project_sample_prefix"
    ].endswith("绝不能进入 EXPLAIN。")
    assert set(archery.prompts.workflow_directives) == {
        "archery.alert.scope",
        "archery.tools.dynamic_contract",
        "archery.metadata.archery_target",
        "archery.metadata.alert_endpoint_mapping",
        "archery.history.window_query",
        "archery.history.truncation.list_ids",
        "archery.history.truncation.fetch_single_id",
        "archery.history.truncation.retry_high_limit",
        "archery.history.truncation.project_sample_prefix",
        "archery.history.complete_before_supplemental",
        "archery.history.time_bounds",
        "archery.supplemental.sample_selection",
        "archery.supplemental.target_binding",
        "archery.supplemental.table_structure",
        "archery.supplemental.explain",
        "archery.supplemental.indexes_and_scope",
        "archery.supplemental.response_binding",
        "archery.supplemental.failure_isolation",
        "archery.history.error_or_empty_completion",
    }
    assert "read_only: true" in archery.prompts.safety
    assert not hasattr(archery, "read_only")

    prometheus = catalog.require("prometheus")
    assert prometheus.url_template == "${PROMETHEUS_MCP_SSE_URL}"
    assert prometheus.header_templates == {}
    assert prometheus.optional_header_templates == {
        "${PROMETHEUS_MCP_API_KEY_HEADER}": "${PROMETHEUS_MCP_API_KEY}"
    }
    assert prometheus.referenced_environment_variables == (
        "PROMETHEUS_MCP_SSE_URL",
    )
    assert prometheus.optional_environment_variables == (
        "PROMETHEUS_MCP_API_KEY_HEADER",
        "PROMETHEUS_MCP_API_KEY",
    )
    assert "occurred_at - 5 分钟" in prometheus.prompts.workflow
    assert "database_not_monitored" in prometheus.prompts.workflow
    assert all(
        tool_suffix in prometheus.prompts.workflow
        for tool_suffix in (
            "*_execute_query",
            "*_execute_range_query",
            "*_list_metrics",
            "*_get_targets",
        )
    )
    assert all(
        routing_rule in prometheus.prompts.workflow
        for routing_rule in (
            "MySQL 优先 `mysql_*`",
            "MongoDB/Mongo 优先 `mongo_*`",
            "OceanBase/OB 优先 `prod_ob4_*`",
            "TiDB 优先 `mcd_tidb_*`",
        )
    )
    assert all(
        instance_prefix in prometheus.prompts.workflow
        for instance_prefix in (
            "mcd_tidb_coupon_*",
            "mcd_tidb_oms_*",
            "mcd_tidb_analytics_*",
            "mcd_tidb_crm_mbr_3az_*",
            "mcd_tidb_crm_pnt_*",
            "mcd_tidb_oms_cold_*",
            "mcd_tidb_payment_*",
            "mcd_tidb_stld_*",
        )
    )
    assert all(
        prometheus_usage in prometheus.prompts.workflow
        for prometheus_usage in (
            'node_cpu_seconds_total{mode="idle"}',
            "node_memory_MemAvailable_bytes",
            "node_filesystem_avail_bytes",
            'ALERTS{alertstate="firing"}',
            "mysql_global_status_slow_queries",
            "tidb_server_uptime",
        )
    )
    assert "动态 Schema 为参数契约" in prometheus.prompts.workflow
    assert "不得执行手册中的 Docker、配置、重启、健康检查等运维命令" in (
        prometheus.prompts.workflow
    )
    assert "`*_get_targets` 是可选的目标发现手段" in prometheus.prompts.workflow
    assert "返回 404" in prometheus.prompts.workflow
    assert "不设固定的 provider 调用顺序、重试次数上限" in prometheus.prompts.workflow
    assert "`target=\"<alarm_host>:<alarm_port>\"`" in prometheus.prompts.workflow
    assert "`instance` 可能是同主机的采集端口" in prometheus.prompts.workflow
    assert "`mysql:cpu:usage` 是累计 CPU tick" in prometheus.prompts.workflow
    assert "`mysql:cpu:limit`" in prometheus.prompts.workflow
    assert "`*_execute_range_query`" in prometheus.prompts.workflow
    assert prometheus.provider_options == {}


def test_enabled_server_needs_only_connection_and_prompt_configuration(
    tmp_path: Path,
) -> None:
    descriptor = load_mcp_catalog(
        _write_settings(tmp_path, {"example": _server_config(tmp_path)})
    ).require("example")

    assert not hasattr(descriptor, "read_only")
    assert descriptor.provider_options == {}


@pytest.mark.parametrize("legacy_field", ["readOnly", "maxAgentSteps", "toolPolicies"])
def test_removed_policy_and_step_fields_are_rejected(
    tmp_path: Path,
    legacy_field: str,
) -> None:
    server = _server_config(tmp_path)
    server[legacy_field] = True if legacy_field == "readOnly" else 8
    path = _write_settings(tmp_path, {"example": server})

    with pytest.raises(
        MCPCatalogConfigurationError,
        match=f"unsupported configuration fields: {legacy_field}",
    ):
        load_mcp_catalog(path)


def test_disabled_server_still_rejects_checked_in_connection_values(
    tmp_path: Path,
) -> None:
    path = _write_settings(
        tmp_path,
        {
            "disabled": {
                "disabled": True,
                "url": "https://literal-secret.example.test/mcp",
            }
        },
    )

    with pytest.raises(MCPCatalogConfigurationError, match="url must be exactly one"):
        load_mcp_catalog(path)


def test_disabled_server_with_environment_references_is_not_loaded(tmp_path: Path) -> None:
    path = _write_settings(
        tmp_path,
        {
            "disabled": {
                "disabled": True,
                "url": "${DISABLED_MCP_URL}",
                "headers": {"Authorization": "${DISABLED_MCP_KEY}"},
            }
        },
    )

    assert load_mcp_catalog(path).servers == ()


@pytest.mark.parametrize(
    ("overrides", "expected_message"),
    [
        ({"url": "https://mcp.example.test"}, "url must be exactly one"),
        (
            {"headers": {"Authorization": "literal-api-key"}},
            "headers 'Authorization' must be exactly one",
        ),
    ],
)
def test_connection_values_must_be_environment_references(
    tmp_path: Path,
    overrides: dict[str, object],
    expected_message: str,
) -> None:
    path = _write_settings(
        tmp_path,
        {"example": _server_config(tmp_path, **overrides)},
    )

    with pytest.raises(MCPCatalogConfigurationError, match=expected_message):
        load_mcp_catalog(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("apiKey", "literal-secret"),
        ("endpoint", "https://mcp.example.test/private"),
        ("authorization", "Bearer literal-secret"),
    ],
)
def test_catalog_rejects_unknown_fields_that_could_hide_connection_values(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    path = _write_settings(
        tmp_path,
        {"example": _server_config(tmp_path, **{field: value})},
    )

    with pytest.raises(MCPCatalogConfigurationError, match="unsupported configuration fields"):
        load_mcp_catalog(path)


def test_disabled_catalog_server_uses_the_same_strict_top_level_allowlist(
    tmp_path: Path,
) -> None:
    path = _write_settings(
        tmp_path,
        {
            "disabled": {
                "disabled": True,
                "url": "${DISABLED_MCP_URL}",
                "apiKey": "literal-secret",
            }
        },
    )

    with pytest.raises(MCPCatalogConfigurationError, match="unsupported configuration fields"):
        load_mcp_catalog(path)


def test_optional_header_is_omitted_when_name_and_credential_are_empty(
    tmp_path: Path,
) -> None:
    path = _write_settings(
        tmp_path,
        {
            "example": _server_config(
                tmp_path,
                headers={},
                optionalHeaders={"${HEADER_NAME}": "${OPTIONAL_API_KEY}"},
            )
        },
    )
    descriptor = load_mcp_catalog(path).require("example")

    connection = descriptor.resolve_connection(
        {
            "EXAMPLE_MCP_URL": "https://mcp.example.test",
            "HEADER_NAME": "",
            "OPTIONAL_API_KEY": "",
        }
    )

    assert connection.headers == {}


def test_optional_header_is_resolved_when_fully_configured(tmp_path: Path) -> None:
    path = _write_settings(
        tmp_path,
        {
            "example": _server_config(
                tmp_path,
                headers={},
                optionalHeaders={"${HEADER_NAME}": "${OPTIONAL_API_KEY}"},
            )
        },
    )
    descriptor = load_mcp_catalog(path).require("example")

    connection = descriptor.resolve_connection(
        {
            "EXAMPLE_MCP_URL": "https://mcp.example.test",
            "HEADER_NAME": "X-API-Key",
            "OPTIONAL_API_KEY": "secret",
        }
    )

    assert connection.headers == {"X-API-Key": "secret"}


@pytest.mark.parametrize(
    "environment",
    [
        {
            "EXAMPLE_MCP_URL": "https://mcp.example.test",
            "HEADER_NAME": "Authorization",
            "OPTIONAL_API_KEY": "",
        },
        {
            "EXAMPLE_MCP_URL": "https://mcp.example.test",
            "HEADER_NAME": "",
            "OPTIONAL_API_KEY": "secret",
        },
    ],
)
def test_optional_header_rejects_half_configuration(
    tmp_path: Path,
    environment: dict[str, str],
) -> None:
    path = _write_settings(
        tmp_path,
        {
            "example": _server_config(
                tmp_path,
                headers={},
                optionalHeaders={"${HEADER_NAME}": "${OPTIONAL_API_KEY}"},
            )
        },
    )
    descriptor = load_mcp_catalog(path).require("example")

    with pytest.raises(
        MCPCatalogConfigurationError,
        match=(
            r"name and value must both be configured.*"
            r"\$\{HEADER_NAME\}/\$\{OPTIONAL_API_KEY\}"
        ),
    ):
        descriptor.resolve_connection(environment)


@pytest.mark.parametrize(
    "url",
    [
        "mcp.example.test/endpoint",
        "ftp://mcp.example.test/endpoint",
        "https://user:password@mcp.example.test/endpoint",
        "https://mcp.example.test/endpoint?token=secret",
        "https://mcp.example.test/endpoint#fragment",
    ],
)
def test_resolved_mcp_url_rejects_unsafe_shapes(tmp_path: Path, url: str) -> None:
    descriptor = load_mcp_catalog(
        _write_settings(tmp_path, {"example": _server_config(tmp_path)})
    ).require("example")

    with pytest.raises(MCPCatalogConfigurationError, match=r"absolute HTTP\(S\)"):
        descriptor.resolve_connection(
            {
                "EXAMPLE_MCP_URL": url,
                "EXAMPLE_MCP_API_KEY": "secret",
            }
        )


def test_resolved_mcp_url_requires_https_in_production(tmp_path: Path) -> None:
    descriptor = load_mcp_catalog(
        _write_settings(tmp_path, {"example": _server_config(tmp_path)})
    ).require("example")

    with pytest.raises(MCPCatalogConfigurationError, match="HTTPS in production"):
        descriptor.resolve_connection(
            {
                "EXAMPLE_MCP_URL": "http://mcp.example.test/endpoint",
                "EXAMPLE_MCP_API_KEY": "secret",
            },
            require_https=True,
        )


def test_header_cannot_be_both_required_and_optional(tmp_path: Path) -> None:
    path = _write_settings(
        tmp_path,
        {
            "example": _server_config(
                tmp_path,
                optionalHeaders={"Authorization": "${OPTIONAL_API_KEY}"},
            )
        },
    )

    with pytest.raises(MCPCatalogConfigurationError, match="repeats headers"):
        load_mcp_catalog(path)


def test_prompt_path_cannot_escape_mcp_config_directory(tmp_path: Path) -> None:
    settings_directory = tmp_path / "mcp"
    settings_directory.mkdir()
    prompts = _write_prompts(settings_directory)
    prompts["workflow"] = "../../outside.md"
    path = _write_settings(
        settings_directory,
        {
            "example": {
                "url": "${EXAMPLE_MCP_URL}",
                "prompts": prompts,
            }
        },
    )

    with pytest.raises(MCPCatalogConfigurationError, match="escapes"):
        load_mcp_catalog(path)


def test_each_prompt_requires_a_distinct_non_empty_file(tmp_path: Path) -> None:
    prompts = _write_prompts(tmp_path)
    prompts["safety"] = prompts["role"]
    path = _write_settings(
        tmp_path,
        {
            "example": {
                "url": "${EXAMPLE_MCP_URL}",
                "prompts": prompts,
            }
        },
    )

    with pytest.raises(MCPCatalogConfigurationError, match="separate file"):
        load_mcp_catalog(path)


def test_workflow_directives_are_extracted_without_changing_rendered_text(
    tmp_path: Path,
) -> None:
    prompts = _write_prompts(tmp_path)
    workflow_path = tmp_path / prompts["workflow"]
    authored_workflow = (
        "Before.\n"
        "<!-- directive:id=example.history.list_ids -->\n"
        "List ids first.\n"
        "Keep the bounded window.\n"
        "<!-- /directive -->\n"
        "After."
    )
    workflow_path.write_text(authored_workflow + "\n", encoding="utf-8")
    path = _write_settings(
        tmp_path,
        {
            "example": {
                "url": "${EXAMPLE_MCP_URL}",
                "headers": {"Authorization": "${EXAMPLE_MCP_API_KEY}"},
                "prompts": prompts,
            }
        },
    )

    bundle = load_mcp_catalog(path).require("example").prompts

    assert bundle.workflow == (
        "Before.\nList ids first.\nKeep the bounded window.\nAfter."
    )
    assert bundle.workflow_directives == {
        "example.history.list_ids": "List ids first.\nKeep the bounded window."
    }
    assert "<!-- directive:" not in bundle.workflow
    assert "<!-- /directive -->" not in bundle.workflow
    assert bundle.workflow_revision == sha256(
        authored_workflow.encode("utf-8")
    ).hexdigest()

    renamed_workflow = authored_workflow.replace(
        "example.history.list_ids",
        "example.history.enumerate_ids",
    )
    workflow_path.write_text(renamed_workflow + "\n", encoding="utf-8")
    renamed_bundle = load_mcp_catalog(path).require("example").prompts

    assert renamed_bundle.workflow == bundle.workflow
    assert renamed_bundle.workflow_revision != bundle.workflow_revision
    assert tuple(renamed_bundle.workflow_directives) == (
        "example.history.enumerate_ids",
    )


@pytest.mark.parametrize(
    ("workflow", "expected_message"),
    (
        (
            "<!-- directive:id=example.one -->\nOne.\n<!-- /directive -->\n"
            "<!-- directive:id=example.one -->\nAgain.\n<!-- /directive -->",
            "directive 'example.one' is duplicated",
        ),
        (
            "<!-- directive:id=example.one -->\n"
            "<!-- directive:id=example.two -->\nTwo.\n<!-- /directive -->\n"
            "<!-- /directive -->",
            "directives cannot be nested",
        ),
        (
            "<!-- directive:id=example.one -->\n \n<!-- /directive -->",
            "directive 'example.one' is empty",
        ),
        (
            "<!-- directive:id=example.one -->\nOne.",
            "directive 'example.one' is not closed",
        ),
        (
            "Before.\n<!-- /directive -->",
            "unmatched directive end",
        ),
        (
            "<!-- directive:id=Example.Invalid -->\nOne.\n<!-- /directive -->",
            "malformed directive marker",
        ),
        (
            "<!-- directive:id=example.one -->\nOne.\n<!-- /directive-->",
            "malformed directive marker",
        ),
    ),
)
def test_catalog_rejects_malformed_workflow_directives(
    tmp_path: Path,
    workflow: str,
    expected_message: str,
) -> None:
    prompts = _write_prompts(tmp_path)
    (tmp_path / prompts["workflow"]).write_text(workflow, encoding="utf-8")
    path = _write_settings(
        tmp_path,
        {
            "example": {
                "url": "${EXAMPLE_MCP_URL}",
                "headers": {"Authorization": "${EXAMPLE_MCP_API_KEY}"},
                "prompts": prompts,
            }
        },
    )

    with pytest.raises(MCPCatalogConfigurationError, match=expected_message):
        load_mcp_catalog(path)


def test_safety_prompt_does_not_require_read_only_marker(tmp_path: Path) -> None:
    prompts = _write_prompts(tmp_path)
    (tmp_path / prompts["safety"]).write_text(
        "Use the server according to its configured role.\n",
        encoding="utf-8",
    )
    path = _write_settings(
        tmp_path,
        {
            "example": {
                "url": "${EXAMPLE_MCP_URL}",
                "prompts": prompts,
            }
        },
    )

    descriptor = load_mcp_catalog(path).require("example")

    assert descriptor.prompts.safety == "Use the server according to its configured role."
