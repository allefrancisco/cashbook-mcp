"""Environment-derived settings and file-based secrets."""

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Callbacks of claude.ai custom connectors; the default allowlist when ALLOWED_REDIRECT_URIS is unset.
DEFAULT_REDIRECT_URIS: tuple[str, ...] = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)

_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_HHMM = re.compile(r"(\d{1,2}):(\d{2})")


class ConfigError(Exception):
    """Invalid or missing configuration; the message names the variable or file."""


TRANSPORTS = ("http", "stdio")
LOCAL_OWNER_EMAIL = "owner@local"  # the single identity of the local-token admin sign-in


@dataclass(frozen=True)
class Settings:
    public_url: str
    allowed_emails: frozenset[str]
    allowed_redirect_uris: tuple[str, ...]
    secrets_dir: Path
    db_path: Path
    port: int
    refresh_at: time
    tz: ZoneInfo
    history_months: int
    log_level: str
    max_reclassify_per_day: int = 1000
    review_min_amount: Decimal = Decimal("500.00")
    transport: str = "http"
    admin_host: str = "0.0.0.0"  # stdio mode: where the local-token admin page listens

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ, *, google: bool = True) -> "Settings":
        """`google=False` (no google-oauth.json): PUBLIC_URL and ALLOWED_EMAILS are optional, as the
        admin page then signs in with a local token and the MCP server runs over stdio only."""
        port = _int(env, "PORT", 8743)
        public_url = env.get("PUBLIC_URL", "").strip().rstrip("/")
        if not public_url:
            if google:
                raise ConfigError("PUBLIC_URL is required")
            public_url = f"http://localhost:{port}"
        emails = frozenset(e.strip().lower() for e in env.get("ALLOWED_EMAILS", "").split(",") if e.strip())
        if not emails and google:
            raise ConfigError("ALLOWED_EMAILS must list at least one email")
        transport = (env.get("MCP_TRANSPORT") or "http").strip().lower()
        if transport not in TRANSPORTS:
            raise ConfigError(f"MCP_TRANSPORT must be one of {', '.join(TRANSPORTS)}, got {transport!r}")
        if transport == "http" and not google:
            raise ConfigError(
                "MCP_TRANSPORT=http needs google-oauth.json: without it the MCP endpoint would be "
                "unauthenticated. Use MCP_TRANSPORT=stdio"
            )
        history_months = _int(env, "HISTORY_MONTHS", 12)
        if history_months < 1:
            raise ConfigError(f"HISTORY_MONTHS must be a positive integer, got {history_months!r}")
        max_reclassify = _int(env, "MAX_RECLASSIFY_PER_DAY", 1000)
        if max_reclassify < 1:
            raise ConfigError(f"MAX_RECLASSIFY_PER_DAY must be a positive integer, got {max_reclassify!r}")
        return cls(
            public_url=public_url,
            allowed_emails=emails,
            allowed_redirect_uris=_redirect_uris(env, "ALLOWED_REDIRECT_URIS"),
            secrets_dir=Path(env.get("SECRETS_DIR") or "/secrets"),
            db_path=Path(env.get("DB_PATH") or "/data/cashbook.duckdb"),
            port=port,
            refresh_at=_refresh_at(env.get("REFRESH_AT") or "06:00"),
            tz=_tz(env.get("TZ") or "America/Sao_Paulo"),
            history_months=history_months,
            log_level=(env.get("LOG_LEVEL") or "INFO").strip().upper(),
            max_reclassify_per_day=max_reclassify,
            review_min_amount=_decimal(env, "REVIEW_MIN_AMOUNT", Decimal("500.00")),
            transport=transport,
            admin_host=(env.get("ADMIN_HOST") or "0.0.0.0").strip(),
        )


@dataclass(frozen=True)
class Secrets:
    # repr=False everywhere: a logged or traced Secrets must not leak values.
    pluggy_client_id: str = field(repr=False)
    pluggy_client_secret: str = field(repr=False)
    # None without google-oauth.json: no Google sign-in, the admin page then uses admin_token.
    google_client_id: str | None = field(repr=False)
    google_client_secret: str | None = field(repr=False)
    db_key: str = field(repr=False)
    session_key: str = field(repr=False)
    admin_token: str | None = field(default=None, repr=False)

    @property
    def has_google(self) -> bool:
        return self.google_client_id is not None and self.google_client_secret is not None


def secrets_dir_from_env(env: Mapping[str, str] = os.environ) -> Path:
    return Path(env.get("SECRETS_DIR") or "/secrets")


def load_secrets(secrets_dir: Path) -> Secrets:
    pluggy = _read_json(secrets_dir / "pluggy.json")
    try:
        p_id, p_secret = pluggy["clientId"], pluggy["clientSecret"]
    except (KeyError, TypeError):
        raise ConfigError("pluggy.json needs clientId/clientSecret") from None
    if not all(isinstance(v, str) and v.strip() for v in (p_id, p_secret)):
        raise ConfigError("pluggy.json values must be non-empty strings")
    g_id = g_secret = None
    google_path = secrets_dir / "google-oauth.json"
    if google_path.exists():  # present means it must be valid: a typo must not silently drop Google
        google = _read_json(google_path)
        try:
            web = google["web"]
            g_id, g_secret = web["client_id"], web["client_secret"]
        except (KeyError, TypeError):
            raise ConfigError("google-oauth.json needs web.client_id/client_secret") from None
        if not all(isinstance(v, str) and v.strip() for v in (g_id, g_secret)):
            raise ConfigError("google-oauth.json values must be non-empty strings")
        g_id, g_secret = g_id.strip(), g_secret.strip()
    db_key = _read_text(secrets_dir / "db.key")
    if not _HEX64.fullmatch(db_key):
        raise ConfigError("db.key must be 64 hex characters")
    session_key = _read_text(secrets_dir / "session.key")
    if not session_key:
        raise ConfigError("session.key is empty")
    token_path = secrets_dir / "admin.token"
    admin_token = _read_text(token_path) if token_path.exists() else None
    if admin_token is not None and len(admin_token) < 32:
        raise ConfigError("admin.token must have at least 32 characters")
    return Secrets(p_id.strip(), p_secret.strip(), g_id, g_secret, db_key, session_key, admin_token)


def _read_text(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        raise ConfigError(f"cannot read secret file {path.name} in {path.parent}") from None


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(_read_text(path))
    except ValueError:
        raise ConfigError(f"{path.name} is not valid JSON") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name} must contain a JSON object")
    return data


def _int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None


def _decimal(env: Mapping[str, str], name: str, default: Decimal) -> Decimal:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = Decimal(raw.strip())
    except InvalidOperation:
        raise ConfigError(f"{name} must be a decimal number, got {raw!r}") from None
    if not value.is_finite() or value < 0:
        raise ConfigError(f"{name} must be a number >= 0, got {raw!r}")
    return value


def _refresh_at(raw: str) -> time:
    m = _HHMM.fullmatch(raw.strip())
    if not m or int(m[1]) > 23 or int(m[2]) > 59:
        raise ConfigError(f"REFRESH_AT must be HH:MM (24h), got {raw!r}")
    return time(int(m[1]), int(m[2]))


def _tz(raw: str) -> ZoneInfo:
    try:
        return ZoneInfo(raw.strip())
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ConfigError(f"TZ is not a known IANA time zone, got {raw!r}") from None


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1"})


def _check_redirect_uri(name: str, entry: str) -> None:
    """Accept only exact, unambiguous callbacks.

    FastMCP treats entries as patterns (`*` wildcards; an entry with an empty or "/" path matches every
    path on that host; a loopback entry without a port matches any port), so entries that would silently
    widen the allowlist are refused here.
    """
    bad = ConfigError(
        f"{name} entry {entry!r} is not valid: use an absolute https:// callback URL with a path "
        "(or http://localhost / http://127.0.0.1 with an optional port), without wildcards, user info, "
        "query or fragment"
    )
    if any(c in entry for c in "*?[]\\") or any(c.isspace() or ord(c) < 32 for c in entry):
        raise bad
    try:
        parts = urlsplit(entry)
        host = parts.hostname
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        raise bad from None
    if not host or parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise bad
    if "#" in entry or "?" in entry:
        raise bad
    if any(seg in (".", "..") for seg in parts.path.split("/")) or "%" in parts.path:
        raise bad
    if parts.scheme == "https":
        if host in _LOOPBACK_HOSTS or parts.path in ("", "/"):
            raise bad
    elif parts.scheme == "http":
        if host not in _LOOPBACK_HOSTS:
            raise bad
    else:
        raise bad


def _redirect_uris(env: Mapping[str, str], name: str) -> tuple[str, ...]:
    raw = env.get(name)
    if raw is None:
        return DEFAULT_REDIRECT_URIS
    entries = tuple(dict.fromkeys(e.strip() for e in raw.split(",") if e.strip()))
    if not entries:
        raise ConfigError(
            f"{name} is set but empty, which would lock every MCP client out; list at least one "
            "callback URL or unset it to use the Claude defaults"
        )
    for entry in entries:
        _check_redirect_uri(name, entry)
    return entries
