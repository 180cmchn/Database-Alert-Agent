FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
COPY runbooks ./runbooks
COPY config ./config
COPY entrypoint.sh ./

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir '.[postgres,mysql]'

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
