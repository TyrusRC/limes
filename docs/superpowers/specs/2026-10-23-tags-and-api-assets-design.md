# Tags for assets, and API assets

Status: requested by the user on 2026-10-23 ("it should tag for asset and api"), defaults approved ("go"). Every detail is my call unless marked otherwise.

## Intent

Today `Asset.tags` exists but is useless: `Tag.name` is unique across all projects (a cross-project leak), nothing can edit it, and APIs are not tracked at all. People need to group assets ("payments", "prod", "eu") and filter, score and alert on those groups, and they need exposed APIs in the inventory.

## Part A: project-scoped tags on assets

- `Tag` gains `project` (FK, cascade); unique on `(project, name)`. Names are normalised to lower case and must match `[a-z0-9][a-z0-9._:/-]{0,39}`. Limits: 20 tags per asset, 200 per project; over the limit is a 400, never a silent drop.
- One migration converts the existing global rows: for every project that has assets using a tag, create the tag in that project and re-point the M2M; then delete the global rows. Reversible is not required.
- REST (same permission and project-scoping rules as the other asset actions; every query scoped to the caller's project):
  - `GET /api/tags/` → the project's tags with asset counts.
  - `POST /api/action/asset/tags/` with `{"assets": [ids], "add": [...], "remove": [...]}` (max 200 assets per call). Assets from another project are a 404 for the whole call. Unknown tags in `add` are created; empty tags are deleted when nothing uses them.
  - The assets list API and the Issues API gain `tag=<name>` (issues: the issue's asset carries the tag). The asset serializer exposes `tags` as a list of names.
  - `GET /api/tag_scores/` → for each of the project's top 10 tags by asset count: score (0–950), grade, asset count, open issue count, computed with the same model and roll-up as `limes/scoring.py` restricted to those assets (reuse; no second scoring model). A tag with no assessed asset is "Not assessed". The headline score does not change.
- UI: Assets page shows tags as chips (escaped), a tag filter, multi-select with "Tag selected" / "Untag selected", and a per-row editor. The Overview gets a read-only "Tags" card from `tag_scores`. Issues page gets the tag filter.
- MCP: inventory tools return `tags` and accept a `tag` filter; a write tool `tag_assets` (add/remove) follows the pattern of the existing write tools in `limes/mcp/tools/writes.py`: per-call authorisation, audit log, rate limits, untrusted-text wrapping.
- Alert rules by tag are out of scope for now.

## Part B: API assets

- New asset kind `api`. Value is the canonical base URL `scheme://host[:port]/base/path` (lower-case host, no query or fragment, no trailing slash). Parent is the hostname asset. It inherits `scope_tier`; it never makes a candidate look owned. `sources` contains `api_discovery`.
- Discovery (a stage after the web probe, reusing `safe_fetch` and `limes.intel.ratelimit` budgets; only for owned, active-authorised hosts that answered over HTTP): fetch at most 12 well-known documentation paths (`/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger/v1/swagger.json`, `/api/openapi.json`, `/api/swagger.json`, `/docs`, `/redoc`, `/swagger-ui/`, `/graphql`) with GET only, body capped at 2 MB, parsed as JSON with no code execution. A valid OpenAPI/Swagger document creates one `api` asset per distinct server base, with `enrichment` = `{spec_url, title, version, endpoints, methods, auth_schemes}`. A `/graphql` GET that answers like a GraphQL endpoint creates an `api` asset with `enrichment.protocol = "graphql"`. Documentation UIs (`/docs`, `/redoc`, `/swagger-ui/`) are recorded as evidence only.
- Checks (all **provisional**: 0 points, headline bit-identical, like the P3 checks): `api.exposed_docs` (specification publicly readable), `api.no_auth_declared` (spec declares no security scheme), `api.unauthenticated_access` (at most 20 documented GET paths without path parameters are fetched once each, unauthenticated; flagged when one answers 200 with a JSON body while the spec declares security). Evidence stores status code and size only, never response bodies.
- UI: Assets page kind filter includes `api`; the row shows title, version, endpoint count and auth schemes (escaped). Overview attack-surface counts include APIs.
- Not in scope: authenticated testing, fuzzing, POST requests, GraphQL introspection queries.

## Anti-goals

- A tag from one project visible in another. Untrusted text (tags, spec titles, paths) breaking a page. An API check moving the headline score. Active requests to hosts that are not owned and authorised.
