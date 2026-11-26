"""Admin sign-in with the local admin token (no Google credentials configured)."""

from dataclasses import replace
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from admin_support import (
    CLIENT_BASE,
    KEY,
    SESSION_KEY,
    Clock,
    FakePluggy,
    FakeScheduler,
    FakeSyncer,
    cookie_value,
    populate,
    settings,
)
from starlette.applications import Starlette
from starlette.testclient import TestClient

from cashbook_mcp.admin_web.api import AdminContext, admin_routes
from cashbook_mcp.admin_web.identity import LocalTokenIdentity
from cashbook_mcp.admin_web.session import FLOW_COOKIE, SESSION_COOKIE
from cashbook_mcp.config import LOCAL_OWNER_EMAIL, Secrets
from cashbook_mcp.store.db import Database

TOKEN = "local-admin-token-" + "x" * 30
LOCAL_URL = "http://localhost:8743"


@pytest.fixture
def local(tmp_path, static_dir):
    db = Database.open(tmp_path / "data.duckdb", KEY)
    populate(db)
    s = replace(settings(tmp_path), public_url=LOCAL_URL, allowed_emails=frozenset())
    ctx = AdminContext(
        settings=s,
        secrets=Secrets("pid", "psecret", None, None, KEY, SESSION_KEY, TOKEN),
        syncer=FakeSyncer(),  # type: ignore[arg-type]
        scheduler=FakeScheduler(),  # type: ignore[arg-type]
        db=db,
        pluggy=FakePluggy(),  # type: ignore[arg-type]
        identity=LocalTokenIdentity(TOKEN, LOCAL_OWNER_EMAIL),
        now=Clock(),
    )
    with TestClient(Starlette(routes=admin_routes(ctx)), base_url=CLIENT_BASE) as client:
        yield ctx, client
    db.close()


def _start(client):
    resp = client.get("/admin/auth/login", follow_redirects=False)
    assert resp.status_code == 303
    target = urlsplit(resp.headers["location"])
    assert target.path == "/admin/auth/token" and not target.netloc  # never leaves this server
    return cookie_value(resp, FLOW_COOKIE), parse_qs(target.query)["state"][0]


def _submit(client, flow, state, token):
    client.cookies.clear()
    client.cookies.set(FLOW_COOKIE, flow)
    return client.post(
        "/admin/auth/token",
        content=urlencode({"state": state, "token": token}),
        headers={"content-type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )


def test_correct_token_signs_the_owner_in(local):
    _, client = local
    flow, state = _start(client)
    form = client.get(f"/admin/auth/token?state={state}")
    assert form.status_code == 200
    assert 'type="password"' in form.text and f'value="{state}"' in form.text
    resp = _submit(client, flow, state, TOKEN)
    assert resp.status_code == 200 and "Signed in" in resp.text
    session = cookie_value(resp, SESSION_COOKIE)
    assert session
    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE, session)
    info = client.get("/admin/api/session").json()
    assert info["email"] == LOCAL_OWNER_EMAIL
    # A write goes through with the CSRF token and the local origin.
    reload = client.post(
        "/admin/api/reload",
        headers={"X-CSRF-Token": info["csrf"], "Origin": LOCAL_URL},
        follow_redirects=False,
    )
    assert reload.status_code in (202, 409)


@pytest.mark.parametrize("bad", ["", "wrong", TOKEN + "x", TOKEN[:-1]])
def test_wrong_token_is_refused_and_leaves_no_session(local, bad):
    _, client = local
    flow, state = _start(client)
    resp = _submit(client, flow, state, bad)
    assert resp.status_code == 400
    assert cookie_value(resp, SESSION_COOKIE) is None
    assert TOKEN not in resp.text


def test_state_is_single_use_and_must_match(local):
    _, client = local
    flow, state = _start(client)
    assert _submit(client, flow, "other-state", TOKEN).status_code == 400
    assert _submit(client, flow, state, TOKEN).status_code == 200
    assert _submit(client, flow, state, TOKEN).status_code == 400  # replay


def test_without_the_flow_cookie_the_token_alone_does_nothing(local):
    _, client = local
    _, state = _start(client)
    client.cookies.clear()
    resp = client.post(
        "/admin/auth/token",
        content=urlencode({"state": state, "token": TOKEN}),
        headers={"content-type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert resp.status_code == 400 and cookie_value(resp, SESSION_COOKIE) is None


def test_google_mode_has_no_token_form(env):
    assert env.client.get("/admin/auth/token").status_code == 404
