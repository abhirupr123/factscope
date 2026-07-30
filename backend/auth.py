"""Signed anonymous installation sessions for the public extension API."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import uuid

from config import SESSION_SIGNING_SECRET, SESSION_TTL_DAYS
from db import (
    create_installation_session,
    get_installation_session,
    touch_installation_session,
)


class SessionAuthError(Exception):
    """Raised when an installation bearer token cannot be authenticated."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AuthContext:
    subject_id: str
    token_hash: str
    expires_at: str


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(encoded_payload: str) -> str:
    digest = hmac.new(
        SESSION_SIGNING_SECRET.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return _b64encode(digest)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_installation_session(now: datetime | None = None) -> tuple[str, AuthContext]:
    now = now or datetime.now(timezone.utc)
    expires = now + timedelta(days=SESSION_TTL_DAYS)
    subject_id = str(uuid.uuid4())
    payload = {
        "v": 1,
        "sid": subject_id,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "nonce": secrets.token_urlsafe(16),
    }
    encoded = _b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    token = f"{encoded}.{_sign(encoded)}"
    token_hash = hash_token(token)
    created_at = now.isoformat()
    expires_at = expires.isoformat()
    create_installation_session(token_hash, subject_id, created_at, expires_at)
    return token, AuthContext(subject_id, token_hash, expires_at)


def authenticate_installation_token(
    token: str, now: datetime | None = None
) -> AuthContext:
    now = now or datetime.now(timezone.utc)
    try:
        encoded, supplied_signature = token.split(".", 1)
    except (AttributeError, ValueError):
        raise SessionAuthError("invalid_session", "The installation session is invalid")

    if not hmac.compare_digest(supplied_signature, _sign(encoded)):
        raise SessionAuthError("invalid_session", "The installation session is invalid")

    try:
        payload = json.loads(_b64decode(encoded))
        subject_id = str(uuid.UUID(payload["sid"]))
        expires_epoch = int(payload["exp"])
        version = int(payload["v"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise SessionAuthError("invalid_session", "The installation session is invalid")

    if version != 1:
        raise SessionAuthError("invalid_session", "The installation session is invalid")
    if expires_epoch <= int(now.timestamp()):
        raise SessionAuthError("session_expired", "The installation session has expired")

    token_hash = hash_token(token)
    stored = get_installation_session(token_hash)
    if not stored or stored.get("revoked") or stored.get("subject_id") != subject_id:
        raise SessionAuthError("invalid_session", "The installation session is invalid")

    try:
        stored_expiry = datetime.fromisoformat(stored["expires_at"])
        last_seen = datetime.fromisoformat(stored["last_seen"])
    except (KeyError, TypeError, ValueError):
        raise SessionAuthError("invalid_session", "The installation session is invalid")
    if stored_expiry <= now:
        raise SessionAuthError("session_expired", "The installation session has expired")

    # Avoid a database write on every request while retaining useful activity data.
    if now - last_seen >= timedelta(hours=1):
        touch_installation_session(token_hash, now.isoformat())

    return AuthContext(subject_id, token_hash, stored["expires_at"])
