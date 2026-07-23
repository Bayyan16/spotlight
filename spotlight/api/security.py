"""Production access controls and HTTP security policy.

The Console is served as a public static shell, but workspace data and every
mutation require either a workspace API key or a short-lived, HttpOnly session
cookie.  Local development and tests remain auth-disabled unless explicitly
enabled.  Railway/production environments fail closed when the key is absent.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, WebSocket


AUTH_COOKIE = "spotlight_session"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_PUBLIC_EXACT = frozenset(
    {"/", "/healthz", "/cmul8.svg", "/auth/session", "/webhooks/github"}
)
_PUBLIC_PREFIXES = ("/assets/",)
_LOGIN_LOCK = threading.Lock()
_LOGIN_FAILURES: dict[str, deque[float]] = defaultdict(deque)


def is_production() -> bool:
    explicit = os.environ.get("SPOTLIGHT_ENV", "").strip().lower()
    if explicit:
        return explicit in {"prod", "production"}
    return bool(os.environ.get("RAILWAY_ENVIRONMENT"))


def auth_required() -> bool:
    mode = os.environ.get("SPOTLIGHT_AUTH_MODE", "auto").strip().lower()
    if mode not in {"auto", "required", "disabled"}:
        raise RuntimeError("SPOTLIGHT_AUTH_MODE must be auto, required, or disabled")
    return mode == "required" or (mode == "auto" and is_production())


def workspace_api_key() -> str | None:
    value = os.environ.get("SPOTLIGHT_API_KEY", "").strip()
    return value or None


def cors_origins() -> list[str]:
    raw = os.environ.get("SPOTLIGHT_CORS_ORIGINS", "")
    origins: list[str] = []
    for item in raw.split(","):
        origin = item.strip().rstrip("/")
        if not origin:
            continue
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RuntimeError(f"invalid SPOTLIGHT_CORS_ORIGINS entry: {origin!r}")
        origins.append(origin)
    return origins


def validate_security_configuration() -> None:
    if auth_required() and not workspace_api_key():
        raise RuntimeError(
            "production authentication is enabled but SPOTLIGHT_API_KEY is not set"
        )
    # Parse now so a malformed origin fails startup instead of silently opening.
    cors_origins()


def is_public_path(path: str) -> bool:
    return path in _PUBLIC_EXACT or path.startswith(_PUBLIC_PREFIXES)


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _session_secret(api_key: str) -> bytes:
    return hashlib.sha256(f"spotlight-session-v1:{api_key}".encode()).digest()


def create_session_token(api_key: str, *, ttl_seconds: int = 8 * 60 * 60) -> str:
    payload = {
        "v": 1,
        "sub": "workspace-user",
        "exp": int(time.time()) + max(60, int(ttl_seconds)),
    }
    encoded = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(_session_secret(api_key), encoded.encode(), hashlib.sha256).digest()
    return f"{encoded}.{_b64encode(signature)}"


def verify_session_token(token: str, api_key: str) -> str | None:
    try:
        encoded, supplied_sig = token.split(".", 1)
        expected = hmac.new(
            _session_secret(api_key), encoded.encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, _b64decode(supplied_sig)):
            return None
        payload = json.loads(_b64decode(encoded))
        if payload.get("v") != 1 or int(payload.get("exp", 0)) <= int(time.time()):
            return None
        return str(payload.get("sub") or "workspace-user")
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


@dataclass(frozen=True)
class AuthResult:
    subject: str
    mechanism: str


def authenticate_headers(
    *, authorization: str | None, api_key_header: str | None, cookie: str | None
) -> AuthResult | None:
    if not auth_required():
        return AuthResult(subject="local-development", mechanism="disabled")
    expected = workspace_api_key()
    if not expected:
        return None
    candidate = ""
    if authorization and authorization.lower().startswith("bearer "):
        candidate = authorization[7:].strip()
    elif api_key_header:
        candidate = api_key_header.strip()
    if candidate and hmac.compare_digest(candidate, expected):
        return AuthResult(subject="workspace-api-key", mechanism="api-key")
    if cookie:
        subject = verify_session_token(cookie, expected)
        if subject:
            return AuthResult(subject=subject, mechanism="cookie")
    return None


def authenticate_request(request: Request) -> AuthResult | None:
    return authenticate_headers(
        authorization=request.headers.get("authorization"),
        api_key_header=request.headers.get("x-spotlight-api-key"),
        cookie=request.cookies.get(AUTH_COOKIE),
    )


def authenticate_websocket(ws: WebSocket) -> AuthResult | None:
    return authenticate_headers(
        authorization=ws.headers.get("authorization"),
        api_key_header=ws.headers.get("x-spotlight-api-key"),
        cookie=ws.cookies.get(AUTH_COOKIE),
    )


def request_origin_is_allowed(request: Request) -> bool:
    """Cookie-authenticated mutations must be same-origin (CSRF defense)."""
    if request.method.upper() in _SAFE_METHODS:
        return True
    origin = request.headers.get("origin")
    if not origin:
        # Non-browser clients using cookies are unusual; require a bearer key.
        return False
    request_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
    allowed = {request_origin, *cors_origins()}
    return origin.rstrip("/") in allowed


def record_failed_login(principal: str) -> None:
    """Bound online key guessing without penalizing successful sessions."""
    now = time.monotonic()
    window_seconds = max(60, int(os.environ.get("SPOTLIGHT_LOGIN_WINDOW_SECONDS", "900")))
    limit = max(
        1,
        int(os.environ.get("SPOTLIGHT_LOGIN_FAILURE_LIMIT", "10" if is_production() else "1000")),
    )
    with _LOGIN_LOCK:
        failures = _LOGIN_FAILURES[principal]
        while failures and failures[0] <= now - window_seconds:
            failures.popleft()
        failures.append(now)
        if len(failures) >= limit:
            retry = max(1, int(window_seconds - (now - failures[0])))
            raise HTTPException(
                429,
                "too many failed authentication attempts",
                headers={"Retry-After": str(retry)},
            )


def clear_login_failures(principal: str) -> None:
    with _LOGIN_LOCK:
        _LOGIN_FAILURES.pop(principal, None)


def reset_login_failures() -> None:
    with _LOGIN_LOCK:
        _LOGIN_FAILURES.clear()


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self' https: wss:; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
}
