#!/bin/sh
# Container entrypoint: optionally reset runtime-settings.json before the
# application process starts, so the deployment (.env) baseline is always
# honoured on a fresh `docker compose up`.
#
# Set RESET_RUNTIME_SETTINGS_ON_START=true to clear persisted admin overrides
# (runtime-settings.json) at container start. This makes `.env` the single
# source of truth for editable keys whenever the stack is recreated.

set -e

RESET_FLAG="${RESET_RUNTIME_SETTINGS_ON_START:-false}"
SETTINGS_PATH="${RUNTIME_SETTINGS_PATH:-/app/data/runtime-settings.json}"

if [ "$RESET_FLAG" = "true" ] && [ -f "$SETTINGS_PATH" ]; then
    echo "[entrypoint] Resetting $SETTINGS_PATH to {}"
    printf '{}\n' > "$SETTINGS_PATH"
fi

exec "$@"