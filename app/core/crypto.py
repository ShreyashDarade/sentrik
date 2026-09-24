"""Symmetric encryption for secrets at rest (test-account creds, ownership tokens).

Uses Fernet (AES-128-CBC + HMAC). The key is derived from settings; if the
operator did not supply one, a random key is generated per process (fine for
dev/test, but secrets will not decrypt across restarts — logged as a warning).
"""

from __future__ import annotations

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

log = logging.getLogger("sentinel.crypto")

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        raw = get_settings().secret_encryption_key
        if raw:
            # derive a stable 32-byte urlsafe key from the provided secret
            digest = hashlib.sha256(raw.encode()).digest()
            key = base64.urlsafe_b64encode(digest)
        else:
            key = Fernet.generate_key()
            log.warning(
                "SENTINEL_SECRET_ENCRYPTION_KEY not set; using ephemeral key. "
                "Encrypted secrets will not survive a restart."
            )
        _fernet = Fernet(key)
    return _fernet


def encrypt(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        raise ValueError("could not decrypt secret (wrong key or corrupted data)")
