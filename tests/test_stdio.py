"""The server without Google credentials: stdio only, and the admin page signs in by local token."""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from cashbook_mcp.config import ConfigError, Secrets, Settings
from cashbook_mcp.server import ALL_TOOL_NAMES, admin_app, build_app, register_admin

KEY = "ab" * 32


def _secrets(token: str | None = "t" * 43, google: bool = False) -> Secrets:
    return Secrets("pid", "psecret", "gid" if google else None, "gs" if google else None, KEY, "k" * 64, token)


def _settings(tmp_path: Path, transport: str = "stdio") -> Settings:
    env = {"MCP_TRANSPORT": transport, "DB_PATH": str(tmp_path / "c.duckdb"), "SECRETS_DIR": str(tmp_path)}
    return Settings.from_env(env, google=False) if transport == "stdio" else Settings.from_env(
        {**env, "PUBLIC_URL": "https://x.example", "ALLOWED_EMAILS": "a@example.com"}
    )


def test_stdio_build_has_no_auth_and_an_admin_page_with_a_token(tmp_path):
    mcp, context = build_app(_settings(tmp_path), _secrets())
    try:
        assert mcp.auth is None
        assert admin_app(context) is not None
    finally:
        context.db.close()


def test_without_google_and_without_token_there_is_no_admin_page(tmp_path):
    _, context = build_app(_settings(tmp_path), _secrets(token=None))
    try:
        assert admin_app(context) is None
    finally:
        context.db.close()


def test_http_without_google_cannot_be_built(tmp_path):
    settings = _settings(tmp_path, "http")
    with pytest.raises(ConfigError, match="google-oauth.json"):
        build_app(settings, _secrets())


def test_register_admin_needs_google(tmp_path):
    mcp, context = build_app(_settings(tmp_path), _secrets())
    try:
        with pytest.raises(ConfigError):
            register_admin(mcp, context)
    finally:
        context.db.close()


async def test_hermes_style_stdio_subprocess_serves_the_tools_without_google(tmp_path):
    (tmp_path / "pluggy.json").write_text(json.dumps({"clientId": "cid", "clientSecret": "cs"}))
    (tmp_path / "db.key").write_text(KEY)
    (tmp_path / "session.key").write_text("k" * 64)
    env = {
        **{k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "DUCKDB_EXTENSION_DIR")},
        "SECRETS_DIR": str(tmp_path),
        "DB_PATH": str(tmp_path / "c.duckdb"),
        "MCP_TRANSPORT": "stdio",
    }
    transport = StdioTransport(sys.executable, ["-m", "cashbook_mcp.server"], env=env)
    async with Client(transport) as client:
        names = {t.name for t in await client.list_tools()}
    assert names == ALL_TOOL_NAMES


async def test_stdio_process_also_serves_the_token_admin_page(tmp_path):
    import socket

    import httpx

    (tmp_path / "pluggy.json").write_text(json.dumps({"clientId": "cid", "clientSecret": "cs"}))
    (tmp_path / "db.key").write_text(KEY)
    (tmp_path / "session.key").write_text("k" * 64)
    (tmp_path / "admin.token").write_text("t" * 43)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {
        **{k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "DUCKDB_EXTENSION_DIR")},
        "SECRETS_DIR": str(tmp_path),
        "DB_PATH": str(tmp_path / "c.duckdb"),
        "MCP_TRANSPORT": "stdio",
        "PORT": str(port),
        "ADMIN_HOST": "127.0.0.1",
    }
    transport = StdioTransport(sys.executable, ["-m", "cashbook_mcp.server"], env=env)
    async with Client(transport) as client:
        await client.list_tools()
        base = f"http://127.0.0.1:{port}"
        async with httpx.AsyncClient() as http:
            for _ in range(50):  # the admin server starts with the lifespan
                try:
                    health = await http.get(f"{base}/health")
                    break
                except httpx.TransportError:
                    await asyncio.sleep(0.1)
            assert health.json() == {"ok": True}
            login = await http.get(f"{base}/admin/auth/login", follow_redirects=False)
            assert login.status_code == 303
            assert login.headers["location"].startswith("/admin/auth/token?state=")
            assert (await http.get(f"{base}/admin/api/session")).status_code == 401
            assert (await http.get(f"{base}/mcp")).status_code == 404  # no MCP endpoint on this port
