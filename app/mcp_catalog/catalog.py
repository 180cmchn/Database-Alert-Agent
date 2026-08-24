"""Declarative MCP server catalog used by Agent selection and execution.

The catalog deliberately keeps connection values as environment-variable
templates. Secret expansion belongs to the transport boundary, never to Agent
selection or prompt construction.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

_ENV_REFERENCE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
_SERVER_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_PROMPT_NAMES = ("role", "purpose", "workflow", "safety")
_PROVIDER_OPTION_NAMES = {
    "toolTimeoutSeconds",
    "transport",
}
_SENSITIVE_OPTION_TOKENS = {
    "auth",
    "authorization",
    "credential",
    "endpoint",
    "key",
    "password",
    "passwd",
    "secret",
    "token",
    "url",
}
_CONNECTION_VALUE = re.compile(
    r"(?i)(?:[a-z][a-z0-9+.-]*://|\bbearer\s+|\bbasic\s+[A-Za-z0-9+/=]+)"
)
_DIRECTIVE_START = re.compile(
    r"^<!--\s*directive:id=(?P<id>[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*)\s*-->$"
)
_DIRECTIVE_END = "<!-- /directive -->"


class MCPCatalogConfigurationError(ValueError):
    """The checked-in MCP catalog is incomplete or unsafe."""


@dataclass(frozen=True, slots=True)
class MCPPromptBundle:
    """Deployment-authored instructions for one MCP integration."""

    role: str
    purpose: str
    workflow: str
    safety: str
    workflow_directives: Mapping[str, str] = field(default_factory=dict)
    workflow_revision: str = ""

    @property
    def execution_instructions(self) -> str:
        """Return the complete prompt used after the Agent selects this MCP."""

        return "\n\n".join(
            (
                f"[role]\n{self.role}",
                f"[purpose]\n{self.purpose}",
                f"[workflow]\n{self.workflow}",
                f"[safety]\n{self.safety}",
            )
        )


@dataclass(frozen=True, slots=True)
class MCPSelectionCandidate:
    """Secret-free MCP metadata exposed to the Agent's relevance selector."""

    name: str
    role: str
    purpose: str


@dataclass(frozen=True, slots=True)
class MCPServerDescriptor:
    """One enabled MCP integration."""

    name: str
    url_template: str
    header_templates: Mapping[str, str]
    optional_header_templates: Mapping[str, str]
    prompts: MCPPromptBundle
    provider_options: Mapping[str, Any]
    referenced_environment_variables: tuple[str, ...]
    optional_environment_variables: tuple[str, ...]
    explicitly_enabled: bool = False

    @property
    def selection_candidate(self) -> MCPSelectionCandidate:
        return MCPSelectionCandidate(
            name=self.name,
            role=self.prompts.role,
            purpose=self.prompts.purpose,
        )

    def resolve_connection(
        self,
        environment: Mapping[str, str],
        *,
        require_https: bool = False,
    ) -> ResolvedMCPConnection:
        """Resolve deployment values at the transport boundary only."""

        url = _resolve_template(self.url_template, environment, optional=False)
        headers: dict[str, str] = {}
        for raw_name, raw_value in self.header_templates.items():
            name = _resolve_header_name(raw_name, environment, optional=False)
            value = _resolve_template(raw_value, environment, optional=False)
            _add_resolved_header(headers, name, value, server_name=self.name)
        for raw_name, raw_value in self.optional_header_templates.items():
            name = _resolve_header_name(raw_name, environment, optional=True)
            value = _resolve_template(raw_value, environment, optional=True)
            if bool(name) != bool(value):
                configured_pair = f"{raw_name}/{raw_value}"
                raise MCPCatalogConfigurationError(
                    f"MCP server {self.name!r} optional header name and value must "
                    "both be configured or both be empty "
                    f"(configuration: {configured_pair})"
                )
            if not name:
                continue
            _add_resolved_header(headers, name, value, server_name=self.name)
        return ResolvedMCPConnection(
            url=_validate_resolved_url(
                url,
                server_name=self.name,
                require_https=require_https,
            ),
            headers=MappingProxyType(headers),
        )


@dataclass(frozen=True, slots=True)
class ResolvedMCPConnection:
    """Secret-bearing values scoped to an MCP transport constructor."""

    url: str
    headers: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class MCPCatalog:
    """Immutable collection of enabled MCP descriptors."""

    servers: tuple[MCPServerDescriptor, ...]

    def get(self, name: str) -> MCPServerDescriptor | None:
        """Return a descriptor by its configured name."""

        return next((server for server in self.servers if server.name == name), None)

    def require(self, name: str) -> MCPServerDescriptor:
        """Return a descriptor or fail with a configuration-oriented error."""

        descriptor = self.get(name)
        if descriptor is None:
            raise MCPCatalogConfigurationError(
                f"MCP catalog does not contain an enabled server {name!r}"
            )
        return descriptor

    def selection_candidates(self) -> tuple[MCPSelectionCandidate, ...]:
        """Return only the role and purpose data needed for relevance selection."""

        return tuple(server.selection_candidate for server in self.servers)


def load_mcp_catalog(settings_path: Path | str) -> MCPCatalog:
    """Load every enabled MCP descriptor without resolving deployment secrets."""

    path = Path(settings_path)
    raw = _load_json(path)
    servers = raw.get("mcpServers") if isinstance(raw, dict) else None
    if not isinstance(servers, dict):
        raise MCPCatalogConfigurationError(
            "MCP settings must define an object named 'mcpServers'"
        )

    descriptors: list[MCPServerDescriptor] = []
    for raw_name, raw_server in servers.items():
        if not isinstance(raw_name, str) or _SERVER_NAME.fullmatch(raw_name) is None:
            raise MCPCatalogConfigurationError(
                f"MCP server name {raw_name!r} contains unsupported characters"
            )
        if not isinstance(raw_server, dict):
            raise MCPCatalogConfigurationError(
                f"MCP server {raw_name!r} must be configured as an object"
            )
        _validate_server_fields(raw_name, raw_server)
        _validate_provider_options(raw_name, raw_server)
        if not _is_enabled(raw_name, raw_server):
            _validate_disabled_connection_templates(raw_name, raw_server)
            continue
        descriptors.append(
            _parse_server(
                name=raw_name,
                raw_server=raw_server,
                settings_directory=path.parent,
            )
        )
    return MCPCatalog(servers=tuple(descriptors))


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except FileNotFoundError as exc:
        raise MCPCatalogConfigurationError(
            f"MCP settings file does not exist: {path}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise MCPCatalogConfigurationError(
            f"MCP settings file is not valid UTF-8: {path}"
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise MCPCatalogConfigurationError(
            f"MCP settings file is not valid JSON: {path}"
        ) from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MCPCatalogConfigurationError(
                f"MCP settings contain duplicate JSON key {key!r}"
            )
        result[key] = value
    return result


def _is_enabled(name: str, raw_server: Mapping[str, Any]) -> bool:
    enabled = raw_server.get("enabled")
    disabled = raw_server.get("disabled")
    if enabled is not None and type(enabled) is not bool:
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} enabled must be a boolean when present"
        )
    if disabled is not None and type(disabled) is not bool:
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} disabled must be a boolean when present"
        )
    if enabled is True and disabled is True:
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} cannot be both enabled and disabled"
        )
    return enabled is not False and disabled is not True


def _parse_server(
    *,
    name: str,
    raw_server: Mapping[str, Any],
    settings_directory: Path,
) -> MCPServerDescriptor:
    url_template = _environment_reference(
        raw_server.get("url"), field=f"MCP server {name!r} url"
    )
    raw_headers = raw_server.get("headers", {})
    if not isinstance(raw_headers, dict):
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} headers must be an object"
        )
    headers, header_variables = _parse_header_templates(name, raw_headers)
    raw_optional_headers = raw_server.get("optionalHeaders", {})
    if not isinstance(raw_optional_headers, dict):
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} optionalHeaders must be an object"
        )
    optional_headers, optional_header_variables = _parse_header_templates(
        name, raw_optional_headers, field_name="optionalHeaders"
    )
    duplicate_headers = set(headers) & set(optional_headers)
    if duplicate_headers:
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} repeats headers in headers and optionalHeaders: "
            + ", ".join(sorted(duplicate_headers))
        )
    prompts = _load_prompts(
        name=name,
        raw_prompts=raw_server.get("prompts"),
        settings_directory=settings_directory,
    )
    provider_options = {
        key: deepcopy(raw_server[key])
        for key in _PROVIDER_OPTION_NAMES
        if key in raw_server
    }
    url_variable = _ENV_REFERENCE.fullmatch(url_template)
    assert url_variable is not None
    referenced_variables = tuple(
        dict.fromkeys((url_variable.group(1), *header_variables))
    )
    return MCPServerDescriptor(
        name=name,
        url_template=url_template,
        header_templates=MappingProxyType(headers),
        optional_header_templates=MappingProxyType(optional_headers),
        prompts=prompts,
        provider_options=MappingProxyType(provider_options),
        referenced_environment_variables=referenced_variables,
        optional_environment_variables=tuple(dict.fromkeys(optional_header_variables)),
        explicitly_enabled=raw_server.get("enabled") is True,
    )


def _validate_server_fields(name: str, raw_server: Mapping[str, Any]) -> None:
    known_keys = {
        "disabled",
        "enabled",
        "headers",
        "optionalHeaders",
        "prompts",
        "url",
    }
    unknown_options = set(raw_server) - known_keys - _PROVIDER_OPTION_NAMES
    if unknown_options:
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} contains unsupported configuration fields: "
            + ", ".join(sorted(str(key) for key in unknown_options))
        )


def _validate_provider_options(name: str, raw_server: Mapping[str, Any]) -> None:
    if "toolTimeoutSeconds" in raw_server:
        value = raw_server["toolTimeoutSeconds"]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 1 <= value <= 1200
        ):
            raise MCPCatalogConfigurationError(
                f"MCP server {name!r} toolTimeoutSeconds must be between 1 and 1200"
            )
    if "transport" in raw_server and raw_server["transport"] not in {
        "sse",
        "streamable_http",
    }:
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} transport must be sse or streamable_http"
        )


def _option_name_tokens(value: str) -> set[str]:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return {
        token.casefold()
        for token in re.split(r"[^A-Za-z0-9]+", separated)
        if token
    }


def _reject_embedded_connection_values(value: Any, *, field: str) -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = str(raw_key)
            if _option_name_tokens(key) & _SENSITIVE_OPTION_TOKENS:
                raise MCPCatalogConfigurationError(
                    f"{field} must not contain connection or credential field {key!r}"
                )
            _reject_embedded_connection_values(nested, field=f"{field}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _reject_embedded_connection_values(nested, field=f"{field}[{index}]")
        return
    if isinstance(value, str) and _CONNECTION_VALUE.search(value):
        raise MCPCatalogConfigurationError(
            f"{field} must not contain a connection URL or inline credential"
        )


def _validate_disabled_connection_templates(
    name: str,
    raw_server: Mapping[str, Any],
) -> None:
    """Reject checked-in connection values even when a server is disabled."""

    if "url" in raw_server:
        _environment_reference(raw_server.get("url"), field=f"MCP server {name!r} url")
    for field_name in ("headers", "optionalHeaders"):
        raw_headers = raw_server.get(field_name, {})
        if not isinstance(raw_headers, dict):
            raise MCPCatalogConfigurationError(
                f"MCP server {name!r} {field_name} must be an object"
            )
        _parse_header_templates(name, raw_headers, field_name=field_name)


def _environment_reference(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _ENV_REFERENCE.fullmatch(value.strip()) is None:
        raise MCPCatalogConfigurationError(
            f"{field} must be exactly one ${{ENVIRONMENT_VARIABLE}} reference"
        )
    return value.strip()


def _resolve_template(
    template: str,
    environment: Mapping[str, str],
    *,
    optional: bool,
) -> str:
    match = _ENV_REFERENCE.fullmatch(template)
    if match is None:
        raise MCPCatalogConfigurationError(
            "MCP connection template is not an environment reference"
        )
    value = str(environment.get(match.group(1), "")).strip()
    if not value and not optional:
        raise MCPCatalogConfigurationError(
            f"MCP connection requires environment variable {match.group(1)}"
        )
    return value


def _validate_resolved_url(
    url: str,
    *,
    server_name: str,
    require_https: bool = False,
) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise MCPCatalogConfigurationError(
            f"MCP server {server_name!r} URL must be an absolute HTTP(S) endpoint "
            "without embedded credentials, query, or fragment"
        )
    if require_https and parsed.scheme != "https":
        raise MCPCatalogConfigurationError(
            f"MCP server {server_name!r} URL must use HTTPS in production"
        )
    return url


def _resolve_header_name(
    template: str,
    environment: Mapping[str, str],
    *,
    optional: bool,
) -> str:
    if _ENV_REFERENCE.fullmatch(template) is not None:
        value = _resolve_template(template, environment, optional=optional)
    else:
        value = template
    if value and _HEADER_NAME.fullmatch(value) is None:
        raise MCPCatalogConfigurationError(
            f"Resolved MCP header name {value!r} is invalid"
        )
    return value


def _add_resolved_header(
    headers: dict[str, str],
    name: str,
    value: str,
    *,
    server_name: str,
) -> None:
    if any(existing.casefold() == name.casefold() for existing in headers):
        raise MCPCatalogConfigurationError(
            f"MCP server {server_name!r} resolves duplicate header {name!r}"
        )
    headers[name] = value


def _parse_header_templates(
    name: str,
    raw_headers: Mapping[Any, Any],
    *,
    field_name: str = "headers",
) -> tuple[dict[str, str], tuple[str, ...]]:
    headers: dict[str, str] = {}
    environment_variables: list[str] = []
    for raw_name, raw_value in raw_headers.items():
        if not isinstance(raw_name, str):
            raise MCPCatalogConfigurationError(
                f"MCP server {name!r} {field_name} names must be strings"
            )
        header_name = raw_name.strip()
        name_reference = _ENV_REFERENCE.fullmatch(header_name)
        if name_reference is None and _HEADER_NAME.fullmatch(header_name) is None:
            raise MCPCatalogConfigurationError(
                f"MCP server {name!r} {field_name} name {raw_name!r} is invalid"
            )
        header_value = _environment_reference(
            raw_value,
            field=f"MCP server {name!r} {field_name} {header_name!r}",
        )
        value_reference = _ENV_REFERENCE.fullmatch(header_value)
        assert value_reference is not None
        if name_reference is not None:
            environment_variables.append(name_reference.group(1))
        environment_variables.append(value_reference.group(1))
        headers[header_name] = header_value
    return headers, tuple(environment_variables)


def _load_prompts(
    *,
    name: str,
    raw_prompts: Any,
    settings_directory: Path,
) -> MCPPromptBundle:
    if not isinstance(raw_prompts, dict):
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} prompts must reference separate prompt files"
        )
    missing = [prompt_name for prompt_name in _PROMPT_NAMES if prompt_name not in raw_prompts]
    extra = sorted(set(raw_prompts) - set(_PROMPT_NAMES))
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unsupported " + ", ".join(extra))
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} prompt references are invalid: {'; '.join(details)}"
        )

    contents: dict[str, str] = {}
    resolved_paths: list[Path] = []
    for prompt_name in _PROMPT_NAMES:
        prompt_path = _resolve_prompt_path(
            name=name,
            prompt_name=prompt_name,
            raw_path=raw_prompts[prompt_name],
            settings_directory=settings_directory,
        )
        if prompt_path in resolved_paths:
            raise MCPCatalogConfigurationError(
                f"MCP server {name!r} must use a separate file for each prompt"
            )
        resolved_paths.append(prompt_path)
        try:
            content = prompt_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError as exc:
            raise MCPCatalogConfigurationError(
                f"MCP server {name!r} {prompt_name} prompt does not exist: {prompt_path}"
            ) from exc
        except UnicodeDecodeError as exc:
            raise MCPCatalogConfigurationError(
                f"MCP server {name!r} {prompt_name} prompt is not valid UTF-8"
            ) from exc
        except OSError as exc:
            raise MCPCatalogConfigurationError(
                f"MCP server {name!r} {prompt_name} prompt cannot be read: {prompt_path}"
            ) from exc
        if not content:
            raise MCPCatalogConfigurationError(
                f"MCP server {name!r} {prompt_name} prompt must not be empty"
            )
        contents[prompt_name] = content
    authored_workflow = contents["workflow"]
    workflow, directives = _parse_workflow_directives(
        authored_workflow,
        server_name=name,
    )
    contents["workflow"] = workflow
    return MCPPromptBundle(
        **contents,
        workflow_directives=MappingProxyType(directives),
        workflow_revision=(
            sha256(authored_workflow.encode("utf-8")).hexdigest()
            if directives
            else ""
        ),
    )


def _parse_workflow_directives(
    workflow: str,
    *,
    server_name: str,
) -> tuple[str, dict[str, str]]:
    """Extract trusted runtime prompt fragments while preserving the workflow text."""

    rendered: list[str] = []
    directives: dict[str, str] = {}
    active_id: str | None = None
    active_lines: list[str] = []
    for raw_line in workflow.splitlines():
        line = raw_line.strip()
        marker = _DIRECTIVE_START.fullmatch(line)
        if marker is not None:
            if active_id is not None:
                raise MCPCatalogConfigurationError(
                    f"MCP server {server_name!r} workflow directives cannot be nested"
                )
            active_id = marker.group("id")
            if active_id in directives:
                raise MCPCatalogConfigurationError(
                    f"MCP server {server_name!r} workflow directive {active_id!r} is duplicated"
                )
            active_lines = []
            continue
        if line == _DIRECTIVE_END:
            if active_id is None:
                raise MCPCatalogConfigurationError(
                    f"MCP server {server_name!r} workflow has an unmatched directive end"
                )
            instruction = "\n".join(active_lines).strip()
            if not instruction:
                raise MCPCatalogConfigurationError(
                    f"MCP server {server_name!r} workflow directive {active_id!r} is empty"
                )
            directives[active_id] = instruction
            active_id = None
            active_lines = []
            continue
        if line.casefold().startswith(("<!-- directive", "<!-- /directive")):
            raise MCPCatalogConfigurationError(
                f"MCP server {server_name!r} workflow has a malformed directive marker"
            )
        rendered.append(raw_line)
        if active_id is not None:
            active_lines.append(raw_line)
    if active_id is not None:
        raise MCPCatalogConfigurationError(
            f"MCP server {server_name!r} workflow directive {active_id!r} is not closed"
        )
    return "\n".join(rendered).strip(), directives


def _resolve_prompt_path(
    *,
    name: str,
    prompt_name: str,
    raw_path: Any,
    settings_directory: Path,
) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} {prompt_name} prompt path must be a relative path"
        )
    relative_path = Path(raw_path.strip())
    if relative_path.is_absolute():
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} {prompt_name} prompt path must be relative"
        )
    base = settings_directory.resolve()
    candidate = (base / relative_path).resolve()
    if not candidate.is_relative_to(base):
        raise MCPCatalogConfigurationError(
            f"MCP server {name!r} {prompt_name} prompt path escapes the MCP config directory"
        )
    return candidate
