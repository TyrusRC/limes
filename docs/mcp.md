# Limes MCP server

## What it is

A native [Model Context Protocol](https://modelcontextprotocol.io) server so AI agents can query and analyze Limes data as you. It speaks Streamable HTTP at `/mcp` (behind nginx and TLS) and stdio.

Read tools (all take a `project` slug where relevant; lists are paginated, 50 by default, 200 at most, with an opaque cursor):

- `list_projects`, `get_project_summary`: the projects you can read and their score, counts and monitoring state.
- `list_assets`, `get_asset`, `list_review_queue`: inventory, one asset in detail, and candidates awaiting a decision.
- `list_issues`, `get_issue`, `forecast_score`, `get_score_history`: issues with waivers and notes, the "if fixed" score, and daily scores.
- `list_vulnerabilities`, `get_vulnerability`, `search`: scanner findings and a project-wide search.
- `list_scans`, `get_scan`, `get_scan_logs`, `list_changes`: scans, their stages and redacted logs, and the change feed.
- `get_system_status`: workers, queues and versions. System administrators only.

Write tools (off unless enabled, see below): `add_assets` (candidates only, 50 entries at most), `start_asm_scan`, `set_asset_cadence`, `waive_issue`, `revoke_waiver`, `add_issue_note`. They call the same services as the web UI and take explicit ids or values, never a filter.

Free text that came from scanned hosts, scan tools or users is returned as `{"untrusted_text": "..."}` with control characters removed and a length cap, and every result carries a notice to treat it as data only. Read tools declare `readOnlyHint`; `revoke_waiver` and `set_asset_cadence` also declare `destructiveHint`.

## Enable

Add to `.env`:

```
LIMES_MCP_ENABLED=true
# optional
LIMES_MCP_WRITES_ENABLED=true
LIMES_MCP_ALLOWED_ORIGINS=https://claude.ai
LIMES_MCP_ALLOWED_HOSTS=limes.example.com
LIMES_MCP_RATE_PER_MIN=60
LIMES_MCP_WRITE_RATE_PER_MIN=10
```

Then `make build`, `make up MCP=1` and `make migrate`. Both switches are needed: `MCP=1` starts the `mcp` service, and `LIMES_MCP_ENABLED` turns the feature on (token page, menu link, `/mcp`). Requests with an `Origin` header must match `LIMES_MCP_ALLOWED_ORIGINS`; requests with no `Origin` (CLI clients) are allowed. The accepted `Host` values are `DOMAIN_NAME` plus `LIMES_MCP_ALLOWED_HOSTS`.

## Create a token

Sign in, open the account menu (top right) and choose **API tokens**. Give it a name, an expiry (30, 90 or 365 days, default 90) and a scope (`read`, or `read_write` when writes are enabled). The token (`lmk_<id>_<secret>`) is shown once, on that page only. Limes stores a SHA-256 of it and nothing else, so a lost token cannot be recovered: revoke it and create another.

## Connect Claude Code

```
claude mcp add --transport http limes https://<host>/mcp --header "Authorization: Bearer <token>"
```

The token goes in the `Authorization` header, never in the URL.

## Connect Claude Desktop

Either through stdio, with the token in the environment of the client process:

```
docker compose exec -T -e LIMES_MCP_TOKEN mcp python3 manage.py mcp_stdio
```

Do not type the token into `docker compose exec -e LIMES_MCP_TOKEN=...` on a shell: it lands in shell history and `ps`. Export it from a file or secret store (`-e LIMES_MCP_TOKEN` alone passes the variable already set in your environment). The command removes the variable from its own environment after reading it.

(run it as the command of a stdio server entry, with `LIMES_MCP_TOKEN` set in that entry's `env`), or add a remote HTTP connector pointing at `https://<host>/mcp` if your Claude Desktop version supports custom bearer headers.

## Self-signed certificates

The bundled proxy uses a self-signed certificate unless you replace it. Node-based clients reject it; point them at the chain:

```
NODE_EXTRA_CA_CERTS=<path to limes_chain.pem>
```

## Security model

- **Per-call authority.** Every call re-checks the token (not revoked, not expired), that the user is active, and the user's role permission for that tool. Deactivating a user or revoking a token takes effect on the next call. Limes has no per-project access control, so any active user reads any project, as in the UI.
- **Writes need three keys:** the server setting `LIMES_MCP_WRITES_ENABLED`, a token with `read_write` scope, and the user's own permission for that action. When the setting is off the write tools are not registered and are also refused per call.
- **Rate limits.** Per token, 60 `tools/call` per minute and 10 write calls per minute (`LIMES_MCP_RATE_PER_MIN`, `LIMES_MCP_WRITE_RATE_PER_MIN`). Over the limit a call returns `rate_limited` with `retry_after_seconds`.
- **Audit log.** Every call is recorded (user, token id, tool, project, arguments cut to 1 KB with secrets scrubbed, outcome, duration). Rows older than 90 days are purged. Changes made by a write tool show "via MCP" in the issue history.
- **Never exposed:** credentials and API keys, configuration secrets, token hashes, session data. Request/response bodies and scan logs pass through a best-effort redactor; treat them as potentially sensitive. There is no tool that runs commands, fetches URLs or reads files.
- **Prompt injection.** Scanned hosts control some of the text an agent reads (banners, page titles, finding names). Keep your client's confirmation prompt on for write tools, and prefer `read` tokens unless you need writes.

## Deploy notes

- A new dependency (the MCP SDK): rebuild the image (`make build`).
- A new migration (`dashboard 0005`): run `make migrate`.
- The nginx config changed: recreate the proxy (`docker compose up -d --force-recreate proxy`).
- With the `mcp` profile off, `/mcp` answers 404.

## Limits and upgrade path

Authentication is a static personal token, not OAuth 2.1. That is enough for Claude Code and stdio; a browser-based connector that requires OAuth will not work yet. The upgrade path is an OAuth authorization server in front of the same `BearerAuth` check, with these tokens kept for headless use. Tool calls have their own rate limit; every authenticated request also draws on a looser per-token request budget, and at most 4 requests per token run at once. A token sent in a URL is revoked on sight, because proxies and clients log URLs.
