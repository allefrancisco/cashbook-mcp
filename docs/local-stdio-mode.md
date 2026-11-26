# Running without Google or a network: stdio mode

For a deployment where the MCP client (Hermes, Claude Desktop, ...) starts the server as a subprocess, no port
has to be reachable by anyone and no Google OAuth client is needed.

## What changes without `google-oauth.json`

- `google-oauth.json` is optional. If the file exists it must still be valid (a typo does not silently turn
  Google off); if it is absent the server starts anyway.
- `PUBLIC_URL` and `ALLOWED_EMAILS` are only required when Google is configured.
- `MCP_TRANSPORT=stdio` runs `create_mcp(..., auth=None)` with `mcp.run(transport="stdio")`: the MCP server
  speaks over stdin/stdout and opens no socket. `MCP_TRANSPORT=http` (the default) is refused without Google,
  because the MCP endpoint would be unauthenticated.
- Logs go to stderr (stdout is the protocol channel). The audit log records tool arguments (search text, SQL),
  so treat the container's logs as sensitive and keep them inside the vault.

```bash
docker run -i --rm -e MCP_TRANSPORT=stdio -v "$PWD/data:/data" -v "$PWD/secrets:/secrets:ro" cashbook-mcp:local
```

## The admin page (MeuPluggy connect widget)

Connecting a bank needs a browser, so `/admin` still exists. In stdio mode the same process also serves it on
`PORT` (default 8743, bound to `ADMIN_HOST`, default `0.0.0.0` so the container network can reach it). Nothing
else is served there: no MCP endpoint. Run it with no published port and reach it through a temporary tunnel
that you start on purpose, for example `docker exec` + `socat`, or `docker run -p 127.0.0.1:8743:8743` for the
duration of the connection.

Sign-in is a form that takes the local admin token, not Google:

- `cashbook-admin init` creates `admin.token` next to `db.key` and `session.key` (mode 0600, never printed).
  The file must hold at least 32 characters.
- Without `admin.token` (and without Google) the admin page is off.
- If Google is configured the Google sign-in is used and the token form does not exist.
- Without `PUBLIC_URL` the admin origin defaults to `http://localhost:<PORT>`, which is what the same-origin
  check on writes compares against: open the tunnel on that host and port. Session cookies are `Secure`;
  browsers accept them on `localhost`.

## Build and supply chain

- `docker-compose.yml` builds this checkout (`build: .`); it does not reference the published image.
- Transitive dependencies `httpx2` and `httpcore2` (from `mcp` / `fastmcp-slim`), checked on PyPI and GitHub:
  both are published by Tom Christie (author of `httpx`) from the `pydantic/httpx2` repository (created
  2026-05-11, ~1.7k stars, contributors include the httpx maintainers), BSD-3-Clause, 24 releases. `uv.lock`
  pins them by hash and the image installs with `uv sync --frozen`. PyPI shows no provenance attestation for
  them.

## Not covered here

Restricting the container's egress to `api.pluggy.ai`, `cdn.pluggy.ai` and `connect.pluggy.ai` is a property of
the deployment (firewall or network policy of whoever runs the container), not of this code.
