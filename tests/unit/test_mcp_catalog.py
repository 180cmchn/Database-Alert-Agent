from __future__ import annotations

import json
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
        content = (
            f"{prefix} {prompt_name}\nread_only: true\n"
            if prompt_name == "safety"
            else f"{prefix} {prompt_name}\n"
        )
        prompt_path.write_text(content, encoding="utf-8")
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
        "readOnly": True,
        "url": "${EXAMPLE_MCP_URL}",
        "headers": {"Authorization": "${EXAMPLE_MCP_API_KEY}"},
        "prompts": _write_prompts(directory),
        "toolPolicies": {"query": {"capability": "range_query"}},
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
    assert all(candidate.read_only for candidate in candidates)
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
    assert "查询慢查询日志" in archery.prompts.purpose
    assert "t_instance_member" in archery.prompts.workflow
    assert "mysql_slow_query_review_history" in archery.prompts.workflow
    assert "read_only: true" in archery.prompts.safety

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
    assert "toolPolicies" in prometheus.provider_options


@pytest.mark.parametrize("read_only", [None, False, "true", 1])
def test_enabled_server_requires_literal_read_only_true(
    tmp_path: Path, read_only: object
) -> None:
    server = _server_config(tmp_path)
    if read_only is None:
        server.pop("readOnly")
    else:
        server["readOnly"] = read_only
    path = _write_settings(tmp_path, {"example": server})

    with pytest.raises(
        MCPCatalogConfigurationError,
        match="must explicitly declare readOnly: true",
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


@pytest.mark.parametrize(
    "fixed_arguments",
    [
        {"endpoint": "internal-service"},
        {"nested": {"apiKey": "literal-secret"}},
        {"target": "https://private.example.test/mcp"},
        {"header": "Bearer literal-secret"},
    ],
)
def test_tool_policy_rejects_nested_connection_or_credential_values(
    tmp_path: Path,
    fixed_arguments: dict[str, object],
) -> None:
    path = _write_settings(
        tmp_path,
        {
            "example": _server_config(
                tmp_path,
                toolPolicies={
                    "query": {
                        "capability": "catalog",
                        "fixedArguments": fixed_arguments,
                    }
                },
            )
        },
    )

    with pytest.raises(
        MCPCatalogConfigurationError,
        match="connection or credential|connection URL or inline credential",
    ):
        load_mcp_catalog(path)


def test_tool_policy_allows_existing_non_secret_fixed_arguments(tmp_path: Path) -> None:
    path = _write_settings(
        tmp_path,
        {
            "example": _server_config(
                tmp_path,
                toolPolicies={
                    "query": {
                        "capability": "range_query",
                        "startArgument": "window.start",
                        "endArgument": "window.end",
                        "timestampEncoding": "rfc3339",
                        "fixedArguments": {"operation": "query", "limit": 100},
                    }
                },
            )
        },
    )

    descriptor = load_mcp_catalog(path).require("example")
    assert descriptor.provider_options["toolPolicies"]["query"]["fixedArguments"] == {
        "operation": "query",
        "limit": 100,
    }


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
                "readOnly": True,
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
                "readOnly": True,
                "url": "${EXAMPLE_MCP_URL}",
                "prompts": prompts,
            }
        },
    )

    with pytest.raises(MCPCatalogConfigurationError, match="separate file"):
        load_mcp_catalog(path)


def test_safety_prompt_must_explicitly_declare_read_only(tmp_path: Path) -> None:
    prompts = _write_prompts(tmp_path)
    (tmp_path / prompts["safety"]).write_text(
        "All tools should probably be safe.\n",
        encoding="utf-8",
    )
    path = _write_settings(
        tmp_path,
        {
            "example": {
                "readOnly": True,
                "url": "${EXAMPLE_MCP_URL}",
                "prompts": prompts,
            }
        },
    )

    with pytest.raises(MCPCatalogConfigurationError, match="read_only: true"):
        load_mcp_catalog(path)
