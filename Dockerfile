# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Keep the dependency layer independent of application source files.  This is
# reused for ordinary code/config changes made before `docker compose up --build`.
COPY pyproject.toml README.md ./
# Hatchling validates the declared `app` package while installing this project.
# Copying only its package marker preserves the dependency-layer cache.
COPY app/__init__.py ./app/__init__.py
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/venv \
    && /opt/venv/bin/pip install '.[postgres,mysql]'

COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
COPY runbooks ./runbooks
COPY config ./config
COPY entrypoint.sh ./
# The repository may be checked out on Windows with CRLF line endings.  A CR in
# the shebang makes Linux look for `/bin/sh\r`, preventing every container
# command (including migrations) from starting.  Normalize the copied script
# within the Linux build environment so the image is independent of checkout
# settings.
RUN python -c "from pathlib import Path; path = Path('entrypoint.sh'); path.write_bytes(path.read_bytes().replace(b'\r\n', b'\n'))"

# Install the project after copying its source without resolving dependencies
# again: they were installed by the cacheable layer above.
RUN --mount=type=cache,target=/root/.cache/pip \
    /opt/venv/bin/pip install --no-deps .

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The internal OpenAI-compatible gateway presents a certificate signed by this
# private CA. Register it with the Linux system trust store so the application
# keeps strict TLS verification enabled inside the container.
COPY certs/kiro-gw-export.crt /usr/local/share/ca-certificates/kiro-gw-export.crt

RUN update-ca-certificates \
    && chmod +x /app/entrypoint.sh \
    && useradd --create-home appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
