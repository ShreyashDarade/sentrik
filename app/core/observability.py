"""Structured logging, request correlation IDs, and lightweight in-process metrics.

- JSON logs (opt-in via SENTINEL_JSON_LOGS or always in production) with a correlation id.
- A `CorrelationIdMiddleware` that assigns/propagates `X-Request-ID` and binds it to a
  contextvar so log records carry it.
- A tiny counter/histogram registry exposed at `/metrics` (Prometheus text format) —
  dependency-free, good enough for basic ops; swap for prometheus_client/OTel at scale.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


def configure_logging(json_logs: bool) -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    handler.addFilter(_ContextFilter())
    if json_logs:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s [req=%(request_id)s] %(message)s"
            )
        )
    root.addHandler(handler)
    root.setLevel(logging.INFO)


class Metrics:
    """Minimal thread-unsafe-but-asyncio-fine counters/histograms."""

    def __init__(self):
        self.counters: dict[str, float] = {}
        self.hist: dict[str, list[float]] = {}

    def inc(self, name: str, value: float = 1.0, **labels) -> None:
        self.counters[_key(name, labels)] = (
            self.counters.get(_key(name, labels), 0.0) + value
        )

    def observe(self, name: str, value: float, **labels) -> None:
        self.hist.setdefault(_key(name, labels), []).append(value)

    def render_prometheus(self) -> str:
        lines: list[str] = []
        for k, v in sorted(self.counters.items()):
            lines.append(f"{k} {v}")
        for k, vals in sorted(self.hist.items()):
            if vals:
                lines.append(f"{k}_count {len(vals)}")
                lines.append(f"{k}_sum {sum(vals)}")
                lines.append(f"{k}_avg {sum(vals) / len(vals)}")
        return "\n".join(lines) + "\n"


def _key(name: str, labels: dict) -> str:
    if not labels:
        return name
    lbl = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return f"{name}{{{lbl}}}"


metrics = Metrics()


# --------------------------------------------------------------------------- #
# Distributed tracing (OpenTelemetry). Spans are always captured to an in-memory
# exporter (readable by /observability tooling and tests); when SENTINEL_OTLP_ENDPOINT
# is set an OTLP exporter is added so traces flow to a real collector (Jaeger/Tempo/…).
# Degrades to no-op if opentelemetry is not installed.
# --------------------------------------------------------------------------- #
_tracer = None
memory_span_exporter = None
_TRACING_READY = False


def configure_tracing() -> None:
    global _tracer, memory_span_exporter, _TRACING_READY
    if _TRACING_READY:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )
    except Exception:  # noqa: BLE001  pragma: no cover
        _TRACING_READY = True
        return

    provider = TracerProvider(resource=Resource.create({"service.name": "sentinel"}))
    memory_span_exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(memory_span_exporter))

    import os

    endpoint = os.environ.get("SENTINEL_OTLP_ENDPOINT", "")
    if endpoint:
        try:  # pragma: no cover - only when a collector is configured
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
            )
        except Exception:  # noqa: BLE001
            log = logging.getLogger("sentinel.tracing")
            log.warning("OTLP exporter unavailable; traces captured in-memory only")

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("sentinel")
    _TRACING_READY = True


class _NoopSpan:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def set_attribute(self, *a, **k):
        pass


def span(name: str, **attributes):
    """Start a span (context manager). No-op when tracing is unavailable."""
    if not _TRACING_READY:
        configure_tracing()
    if _tracer is None:
        return _NoopSpan()
    ctx = _tracer.start_as_current_span(name)
    # attach attributes + correlation id after entering handled by caller via 'with'
    span_cm = _AttrSpan(ctx, attributes)
    return span_cm


class _AttrSpan:
    def __init__(self, ctx, attributes):
        self._ctx = ctx
        self._attrs = attributes

    def __enter__(self):
        s = self._ctx.__enter__()
        try:
            s.set_attribute("request_id", request_id_var.get())
            for k, v in self._attrs.items():
                s.set_attribute(k, v)
        except Exception:  # noqa: BLE001
            pass
        return s

    def __exit__(self, *a):
        return self._ctx.__exit__(*a)


# configure at import so spans are captured even without the app lifespan (tests)
configure_tracing()


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        token = request_id_var.set(rid)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            elapsed = (time.perf_counter() - start) * 1000.0
            metrics.inc(
                "http_requests_total",
                path=_norm(request.url.path),
                method=request.method,
            )
            metrics.observe("http_request_ms", elapsed, path=_norm(request.url.path))
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        return response


def _norm(path: str) -> str:
    # collapse ids to keep cardinality low
    import re

    return re.sub(r"/[0-9a-f]{32}", "/{id}", path)
