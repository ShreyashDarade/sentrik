"""Authenticated session establishment for test accounts.

Supports:
  * bearer  — POST credentials to a login URL, extract a token via a JSON path.
  * form    — POST credentials, capture session cookies.
  * basic   — HTTP Basic auth header (no login round-trip).
  * header  — a static header (e.g. a long-lived API token) from the encrypted secret.

MFA handoff: if a login response signals `mfa_required`, the session is returned in a
PENDING_MFA state carrying an mfa_token; the operator supplies the code out-of-band via
the API, and `complete_mfa` finishes login. Session expiry is detected on use and can
trigger re-authentication.

Login traffic goes to the (in-scope) target host but uses a dedicated client; it is
accounted separately from attack traffic. Credentials are decrypted only here, in
memory, and are never written to evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx

from app.checks.context import AuthSession
from app.core.crypto import decrypt
from app.models import TestAccount


@dataclass
class SessionState:
    account_id: str
    role_name: str
    label: str
    status: str  # "active" | "pending_mfa" | "failed" | "expired"
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    owns_object_ids: list = field(default_factory=list)
    mfa_token: str | None = None
    mfa_url: str | None = None
    expires_at: datetime | None = None
    detail: str = ""

    def to_auth_session(self) -> AuthSession:
        return AuthSession(
            role_name=self.role_name,
            label=self.label,
            headers=dict(self.headers),
            cookies=dict(self.cookies),
            owns_object_ids=list(self.owns_object_ids),
            expired=self.status != "active" or self._is_expired(),
        )

    def _is_expired(self) -> bool:
        return bool(self.expires_at and datetime.now(timezone.utc) >= self.expires_at)


def _json_path(data: dict, path: str):
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


async def establish_session(account: TestAccount) -> SessionState:
    """Resolve a TestAccount into a live session. Never raises on target errors."""
    state = SessionState(
        account_id=account.id,
        role_name=account.role_name,
        label=account.label,
        status="failed",
        owns_object_ids=list(account.owns_object_ids or []),
    )
    cfg = account.login_config or {}
    try:
        secret = decrypt(account.secret_enc) if account.secret_enc else ""
    except ValueError as exc:
        state.detail = f"could not decrypt credentials: {exc}"
        return state

    auth_type = account.auth_type
    try:
        if auth_type == "basic":
            import base64

            raw = base64.b64encode(f"{account.username}:{secret}".encode()).decode()
            state.headers = {"Authorization": f"Basic {raw}"}
            state.status = "active"
            state.detail = "basic auth header set"
        elif auth_type == "header":
            header_name = cfg.get("header_name", "Authorization")
            template = cfg.get("value_template", "Bearer {secret}")
            state.headers = {header_name: template.format(secret=secret)}
            state.status = "active"
            state.detail = "static header set"
        elif auth_type in ("bearer", "form"):
            await _login(account, secret, cfg, state)
        else:
            state.detail = f"unsupported auth_type {auth_type!r}"
    except httpx.HTTPError as exc:
        state.detail = f"login request failed: {exc}"
    return state


async def _login(
    account: TestAccount, secret: str, cfg: dict, state: SessionState
) -> None:
    login_url = cfg.get("login_url")
    if not login_url:
        state.detail = "login_config.login_url required for bearer/form auth"
        return
    user_field = cfg.get("username_field", "username")
    pass_field = cfg.get("password_field", "password")
    payload = {user_field: account.username, pass_field: secret}
    payload.update(cfg.get("extra_fields", {}))

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        if cfg.get("send_json", account.auth_type == "bearer"):
            resp = await client.post(login_url, json=payload)
        else:
            resp = await client.post(login_url, data=payload)

    body = _safe_json(resp)

    # MFA handoff
    if isinstance(body, dict) and body.get(cfg.get("mfa_flag_field", "mfa_required")):
        state.status = "pending_mfa"
        state.mfa_token = body.get(cfg.get("mfa_token_field", "mfa_token"))
        state.mfa_url = cfg.get("mfa_url", login_url)
        state.detail = "MFA required; supply code via complete_mfa"
        return

    if resp.status_code >= 400:
        state.detail = f"login failed with status {resp.status_code}"
        return

    _apply_success(account, cfg, state, resp, body)


def _apply_success(account, cfg, state, resp, body) -> None:
    if account.auth_type == "bearer":
        token_path = cfg.get("token_json_path", "token")
        token = _json_path(body, token_path) if isinstance(body, dict) else None
        if not token:
            state.detail = f"login succeeded but no token at {token_path!r}"
            return
        header_name = cfg.get("token_header", "Authorization")
        template = cfg.get("token_template", "Bearer {token}")
        state.headers = {header_name: template.format(token=token)}
    else:  # form
        cookies = {c.name: c.value for c in resp.cookies.jar}
        if not cookies:
            state.detail = "login succeeded but no session cookie set"
            return
        state.cookies = cookies
        state.headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())}

    ttl = int(cfg.get("session_ttl_seconds", 3600))
    state.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    state.status = "active"
    state.detail = "authenticated"
    # allow account config to override owned object ids after login (dynamic ids)
    dyn = (
        _json_path(body, cfg["owns_object_json_path"])
        if cfg.get("owns_object_json_path") and isinstance(body, dict)
        else None
    )
    if dyn is not None:
        state.owns_object_ids = dyn if isinstance(dyn, list) else [dyn]


async def complete_mfa(
    account: TestAccount, state: SessionState, code: str, cfg: dict | None = None
) -> SessionState:
    """Finish an MFA-gated login with an operator-supplied code."""
    cfg = cfg or account.login_config or {}
    if state.status != "pending_mfa" or not state.mfa_url:
        state.detail = "no pending MFA challenge"
        return state
    payload = {
        cfg.get("mfa_code_field", "code"): code,
        cfg.get("mfa_token_field", "mfa_token"): state.mfa_token,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.post(state.mfa_url, json=payload)
        body = _safe_json(resp)
        if resp.status_code >= 400:
            state.status = "failed"
            state.detail = f"MFA verification failed ({resp.status_code})"
            return state
        _apply_success(account, cfg, state, resp, body)
    except httpx.HTTPError as exc:
        state.status = "failed"
        state.detail = f"MFA request failed: {exc}"
    return state


def _safe_json(resp: httpx.Response):
    try:
        return resp.json()
    except (ValueError, TypeError):
        return {"_raw": resp.text[:2000]}
