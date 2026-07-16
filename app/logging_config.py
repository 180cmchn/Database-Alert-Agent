from __future__ import annotations

import logging


def configure_logging(level: str) -> None:
    """Configure logs without exposing credentials embedded in request URLs."""

    configured_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(level=configured_level)

    # HTTPX logs full request URLs at INFO and HTTP Core emits request details at
    # DEBUG. A WeCom group robot URL carries its credential in `?key=`, so routine
    # transport logs are suppressed. Adapter failures use credential-free messages.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
