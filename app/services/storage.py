"""Pluggable object-storage backend for evidence/report blobs.

Large evidence/report payloads can optionally live outside the primary database.
The backend is chosen by :class:`~app.core.config.Settings.storage_backend`:

* ``"db"`` (default) — no external storage. ``put`` returns an :class:`ObjectRef`
  whose ``inline`` field carries the payload (base64, or verbatim UTF-8 text). The
  caller keeps persisting the reference (JSON) in the DB exactly as before.
* ``"local"`` — writes to ``{storage_local_dir}/{key}`` on the filesystem.
* ``"s3"`` — writes to S3/MinIO via ``boto3`` (built from Settings, MinIO-friendly).

Every backend returns a JSON-serialisable :class:`ObjectRef` the caller can persist
and later hand back to :meth:`StorageBackend.get`. Nothing here is hardcoded: buckets,
paths, endpoints and credentials all come from :func:`~app.core.config.get_settings`.
"""

from __future__ import annotations

import asyncio
import base64
from abc import ABC, abstractmethod
from pathlib import Path, PurePosixPath
from typing import Optional, TypedDict

from app.core.config import Settings, get_settings

__all__ = [
    "ObjectRef",
    "StorageBackend",
    "DbBackend",
    "LocalBackend",
    "S3Backend",
    "get_storage",
    "reset_storage",
]


class ObjectRef(TypedDict):
    """A JSON-serialisable reference to a stored object.

    * ``backend`` — which backend produced/owns this ref ("db" | "local" | "s3").
    * ``key`` — logical object key (``None`` for the db backend).
    * ``url`` — a locator (``file://…`` or ``s3://bucket/key``); ``None`` for db.
    * ``inline`` — the payload itself when ``backend == "db"``; ``None`` otherwise.
      A ``str`` means verbatim UTF-8 text; a base64 str is used for binary data and
      flagged via ``inline_encoding``.
    * ``inline_encoding`` — ``"utf-8"`` or ``"base64"`` when ``inline`` is set.
    """

    backend: str
    key: Optional[str]
    url: Optional[str]
    inline: Optional[str]
    inline_encoding: Optional[str]


def _coerce_bytes(data: object) -> bytes:
    """Best-effort coercion of caller input to ``bytes``."""
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError(f"unsupported data type for storage: {type(data)!r}")


def _sanitize_key(key: str) -> PurePosixPath:
    """Validate a storage key and return a safe, relative POSIX path.

    Rejects absolute paths, ``..`` traversal, drive letters and empty keys so a key
    can never escape the storage root.
    """
    if not key or not isinstance(key, str):
        raise ValueError("storage key must be a non-empty string")
    # Normalise separators; disallow Windows drive/absolute forms.
    normalized = key.replace("\\", "/").strip()
    if not normalized:
        raise ValueError("storage key must not be blank")
    if normalized.startswith("/"):
        raise ValueError("storage key must not be absolute (leading '/')")
    if len(normalized) >= 2 and normalized[1] == ":":
        raise ValueError("storage key must not contain a drive letter")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if not parts:
        raise ValueError("storage key resolves to an empty path")
    if any(p == ".." for p in parts):
        raise ValueError("storage key must not contain '..' path traversal")
    return PurePosixPath(*parts)


class StorageBackend(ABC):
    """Abstract object store. Implementations must be safe to share per-process."""

    name: str = "abstract"

    @abstractmethod
    async def put(
        self, key: str, data: bytes, content_type: str = "application/octet-stream"
    ) -> ObjectRef:
        """Store ``data`` under ``key`` and return a persistable :class:`ObjectRef`."""
        raise NotImplementedError

    @abstractmethod
    async def get(self, ref: ObjectRef) -> bytes:
        """Return the bytes referenced by ``ref``."""
        raise NotImplementedError


class DbBackend(StorageBackend):
    """No-op passthrough: the payload is carried inline in the returned ref.

    The caller keeps storing the (JSON) reference in the DB. Binary payloads are
    base64-encoded; valid UTF-8 text is stored verbatim to keep refs human-readable.
    """

    name = "db"

    async def put(
        self, key: str, data: bytes, content_type: str = "application/octet-stream"
    ) -> ObjectRef:
        raw = _coerce_bytes(data)
        try:
            text = raw.decode("utf-8")
            inline, encoding = text, "utf-8"
        except UnicodeDecodeError:
            inline = base64.b64encode(raw).decode("ascii")
            encoding = "base64"
        return ObjectRef(
            backend="db",
            key=None,
            url=None,
            inline=inline,
            inline_encoding=encoding,
        )

    async def get(self, ref: ObjectRef) -> bytes:
        inline = ref.get("inline")
        if inline is None:
            return b""
        encoding = ref.get("inline_encoding") or "utf-8"
        if encoding == "base64":
            return base64.b64decode(inline)
        if encoding == "utf-8":
            return inline.encode("utf-8")
        raise ValueError(f"unknown inline_encoding: {encoding!r}")


class LocalBackend(StorageBackend):
    """Filesystem backend rooted at ``settings.storage_local_dir``."""

    name = "local"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self._settings = settings

    def _root(self) -> Path:
        settings = self._settings or get_settings()
        root = settings.storage_local_dir or "./sentrik_storage"
        return Path(root).expanduser()

    def _resolve(self, key: str) -> Path:
        safe = _sanitize_key(key)
        return self._root().joinpath(*safe.parts)

    async def put(
        self, key: str, data: bytes, content_type: str = "application/octet-stream"
    ) -> ObjectRef:
        raw = _coerce_bytes(data)
        path = self._resolve(key)

        def _write() -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

        await asyncio.to_thread(_write)
        return ObjectRef(
            backend="local",
            key=str(_sanitize_key(key)),
            url=path.resolve().as_uri(),
            inline=None,
            inline_encoding=None,
        )

    async def get(self, ref: ObjectRef) -> bytes:
        key = ref.get("key")
        if not key:
            raise ValueError("local ref is missing 'key'")
        path = self._resolve(key)

        def _read() -> bytes:
            return path.read_bytes()

        return await asyncio.to_thread(_read)


class S3Backend(StorageBackend):
    """S3/MinIO backend built from Settings. boto3 calls run in a worker thread."""

    name = "s3"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        import importlib.util

        if importlib.util.find_spec("boto3") is None:  # pragma: no cover - needs boto3 absent
            raise RuntimeError(
                "S3 storage backend requires boto3; install it with "
                "`pip install boto3` or set SENTINEL_STORAGE_BACKEND to 'db'/'local'."
            )

        self._settings = settings or get_settings()
        if not self._settings.s3_bucket:
            raise RuntimeError(
                "S3 storage backend requires SENTINEL_S3_BUCKET to be set."
            )
        self._bucket = self._settings.s3_bucket
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3

            s = self._settings
            kwargs: dict[str, object] = {}
            if s.s3_endpoint_url:
                kwargs["endpoint_url"] = s.s3_endpoint_url
            if s.s3_region:
                kwargs["region_name"] = s.s3_region
            if s.s3_access_key:
                kwargs["aws_access_key_id"] = s.s3_access_key
            if s.s3_secret_key:
                kwargs["aws_secret_access_key"] = s.s3_secret_key
            self._client = boto3.client("s3", **kwargs)
        return self._client

    async def put(
        self, key: str, data: bytes, content_type: str = "application/octet-stream"
    ) -> ObjectRef:
        raw = _coerce_bytes(data)
        safe_key = str(_sanitize_key(key))

        def _put() -> None:
            client = self._get_client()
            client.put_object(
                Bucket=self._bucket,
                Key=safe_key,
                Body=raw,
                ContentType=content_type or "application/octet-stream",
            )

        await asyncio.to_thread(_put)
        return ObjectRef(
            backend="s3",
            key=safe_key,
            url=f"s3://{self._bucket}/{safe_key}",
            inline=None,
            inline_encoding=None,
        )

    async def get(self, ref: ObjectRef) -> bytes:
        key = ref.get("key")
        if not key:
            raise ValueError("s3 ref is missing 'key'")
        safe_key = str(_sanitize_key(key))

        def _get() -> bytes:
            client = self._get_client()
            resp = client.get_object(Bucket=self._bucket, Key=safe_key)
            body = resp["Body"]
            try:
                return body.read()
            finally:
                close = getattr(body, "close", None)
                if callable(close):
                    close()

        return await asyncio.to_thread(_get)


_STORAGE: Optional[StorageBackend] = None


def get_storage() -> StorageBackend:
    """Return the process-wide storage backend selected by Settings (cached)."""
    global _STORAGE
    if _STORAGE is not None:
        return _STORAGE
    settings = get_settings()
    backend = (settings.storage_backend or "db").strip().lower()
    if backend == "local":
        _STORAGE = LocalBackend(settings)
    elif backend == "s3":
        _STORAGE = S3Backend(settings)
    elif backend == "db":
        _STORAGE = DbBackend()
    else:
        raise ValueError(
            f"unknown storage_backend {backend!r} (expected 'db', 'local' or 's3')"
        )
    return _STORAGE


def reset_storage() -> None:
    """Clear the cached backend (tests toggle settings then rebuild)."""
    global _STORAGE
    _STORAGE = None
