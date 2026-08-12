"""Declarative, provider-neutral MCP integration catalog."""

from app.mcp_catalog.catalog import (
    MCPCatalog,
    MCPCatalogConfigurationError,
    MCPPromptBundle,
    MCPSelectionCandidate,
    MCPServerDescriptor,
    ResolvedMCPConnection,
    load_mcp_catalog,
)

__all__ = [
    "MCPCatalog",
    "MCPCatalogConfigurationError",
    "MCPPromptBundle",
    "ResolvedMCPConnection",
    "MCPSelectionCandidate",
    "MCPServerDescriptor",
    "load_mcp_catalog",
]
