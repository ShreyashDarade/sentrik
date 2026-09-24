# Sentrik API — backend-only container image
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps kept minimal; psycopg[binary] provides its own libpq.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app ./app

# Install the full stack (agents/observability/postgres extras) so the container has
# LangChain/LangGraph/MCP/OpenTelemetry — not just core deps (F-03).
RUN pip install --upgrade pip && pip install ".[agents,observability,postgres]" gunicorn

# Non-root runtime user
RUN useradd -m -u 10001 sentrik && chown -R sentrik:sentrik /app
USER sentrik

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# The app creates its own schema on startup (init_db). Single worker: the in-process
# orchestrator uses asyncio background tasks + a per-process concurrency semaphore;
# for horizontal scale, front with a durable queue and run multiple workers.
CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000", "--workers", "1", "--timeout", "120"]
