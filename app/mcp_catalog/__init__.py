"""Declarative, provider-neutral MCP integration catalog."""

from app.mcp_catalog.catalog import (
    DEFAULT_MCP_TRANSPORT,
    MCP_TRANSPORTS,
    MCPCatalog,
    MCPCatalogConfigurationError,
    MCPPromptBundle,
    MCPSelectionCandidate,
    MCPServerDescriptor,
    MCPTransport,
    ResolvedMCPConnection,
    load_mcp_catalog,
)

__all__ = [
    "DEFAULT_MCP_TRANSPORT",
    "MCP_TRANSPORTS",
    "MCPTransport",
    "MCPCatalog",
    "MCPCatalogConfigurationError",
    "MCPPromptBundle",
    "ResolvedMCPConnection",
    "MCPSelectionCandidate",
    "MCPServerDescriptor",
    "load_mcp_catalog",
]
