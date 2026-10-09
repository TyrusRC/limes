# ASM module — Slice A2: Assets inventory UI + API + manual add

Status: design drafted 2026-10-08; awaits user review before planning.
Parent: Limes ASM platform. Builds on A1 (ASM pipeline → inventory, merged `2907e84a`) and A0 (Asset models).
Spec basis: `docs/superpowers/specs/2026-10-07-asm-2a-asset-inventory-design.md` (UI/API + manual-add sections), `docs/superpowers/specs/2026-10-08-asm-module-a1-pipeline-inventory-design.md` (module context), research report `reports/UpGuard replacement ASM design.md`.
Platform: Django 3.2 + DRF + Celery + PostgreSQL, branded Limes (internal package `limes`/`startScan`/`api`/`dashboard`).

## Module context

Limes ASM module slices: A0 inventory ✓ · A1 pipeline→inventory ✓ · **A2 this slice** · A3 discovery depth + graph · A4 risk scoring · A-dash dashboard redesign (after A4) · A5 continuous. The dashboard redesign is its own later slice; **A2 does not touch the dashboard**.

## Goal

Make the `Asset` inventory usable by a team: an **Assets** page to list/filter assets, inspect one (current state + `sources`/evidence + the "why is this mine" parent chain), **confirm/reject** candidates, **manually add** assets (one or bulk/CSV), and trigger an **ASM rescan** on an owned root. All project-scoped, following Limes's existing Django-template + DataTables + DRF conventions.

## Scope

**In:**
- DRF **Asset API** in the existing `api/` app: a lean `AssetSerializer`, an `AssetDatatableViewSet` (server-side datatables, project + facet filters), and `APIView` action endpoints for confirm / reject / manual-add / rescan — all using the house `{'status': bool, 'message': str}` + HTTP 200 convention and `HasPermission`.
- An **Assets page** (`<slug:slug>/assets`) extending `base/base.html`: a filterable server-side DataTable, facet filter controls (kind / scope_tier / state / tag), a **detail modal**, an **Add-assets modal**, and a new "Assets" nav entry in `top_nav.html`.
- **Manual add** with validation: punycode/IDN normalize, kind validation (root_domain/hostname/ip/cidr), rejection of private/reserved/loopback IPs and wildcards, owned_* (or co_brand) tier, auto-confirm with `added_by`+`decision_reason`, and a warning when a hostname's registrable domain isn't an owned root.
- **Confirm/Reject** a `candidate`: confirm → `owned_host` (or `co_brand` if chosen) with `active_authorized` optional; reject → `rejected`; both set `added_by`+`decision_reason` and call `dashboard.stats.invalidate(project_id)`.
- **Rescan** limited to `root_domain` assets: map to the matching `Domain` (same project+name) and fire `initiate_scan(scan_mode='asm')` via `create_scan_object` + `apply_async`, mirroring `start_scan_ui`.

**Out (later slices):** any dashboard change (A-dash); per-asset rescan of a bare hostname/ip/cidr (no scan entry point until the Scanner module / 2b scheduler) — A2 returns a clear "not supported yet" for those; the attack-surface graph and provider pivots (A3); scoring (A4); continuous cadence (A5); bulk edit/tagging beyond add/confirm/reject; per-user project ACLs (not present in the platform today).

## API design (`web/api/`)

Follows the existing one-app layout (`api/views.py`, `api/serializers.py`, `api/urls.py`, `api/permissions.py`).

### AssetSerializer (`api/serializers.py`)
A `ModelSerializer` over `Asset`, **lean** (no per-row `.exists()`/count `SerializerMethodField`s — the Subdomain serializer's N+1 is explicitly not copied). Fields: `id, kind, value, scope_tier, active_authorized, state, first_seen, last_seen, missed_count, http_status, page_title, webserver, cname, is_cdn, cdn_name, screenshot_path, sources, decision_reason`; `parent_value = source='parent.value'` (read-only); `technologies`/`ip_addresses`/`tags` via the existing nested serializers (`TechnologySerializer`, `IpSerializer`) or slim name lists; `vuln_count` as a single annotated field from the queryset (annotated in the view with `Count('vulnerabilities')`, NOT a method field).

### AssetDatatableViewSet (`api/views.py`, registered `router.register(r'listDatatableAsset', AssetDatatableViewSet, basename='asset')`)
- `queryset = Asset.objects.none()`; `serializer_class = AssetSerializer`; read-only usage.
- `get_queryset`: require `?project=<slug>` → `Asset.objects.filter(project__slug=project)`; apply optional facet params `kind`, `scope_tier`, `state`, `tag` (tag by `tags__name`); `.select_related('parent')` + `.prefetch_related('technologies','ip_addresses','tags')` + `.annotate(vuln_count=Count('vulnerabilities'))`. No project → empty queryset (never all projects).
- `filter_queryset`: mirror `SubdomainDatatableViewSet`'s server-side datatables search/order (read `search[value]`, `order[0][column]`/`dir` from `request.GET`); map column index→field for the A2 columns; a simple `Q`-based search over `value`/`page_title`/`webserver` (the `= & | > < !` mini-DSL is NOT required for A2 — a plain icontains search across those fields is enough; keep it simpler than the subdomain one).
- Pagination: inherit the global `DatatablesPageNumberPagination`; support `?no_page`.

### Action endpoints (`api/views.py`, `APIView`, `{'status','message'}` + HTTP 200)
- `ConfirmAsset` (`POST action/asset/confirm/`): body `asset_id`, optional `tier` (`owned_host` default | `co_brand`), optional `active_authorized`, optional `reason`. Loads the project-scoped Asset, sets `scope_tier`, `active_authorized`, `added_by=request.user`, `decision_reason=reason`, `state='active'`; saves; `invalidate(project_id)`. `permission_classes=[HasPermission]`, `permission_required = PERM_MODIFY_TARGETS`.
- `RejectAsset` (`POST action/asset/reject/`): body `asset_id`, optional `reason`. Sets `scope_tier='rejected'`, `added_by`, `decision_reason`; saves; `invalidate`. Same permission.
- `AddAssets` (`POST add/assets/`): body `project` (slug), `entries` (list, or a newline/CSV blob), optional `tier`/`active_authorized`/`reason`. For each entry: normalize + validate (below); upsert via a shared helper; set `added_by`, `decision_reason`, tier, `state='active'`. Returns counts `{added, skipped, warnings:[...]}` in `message`. `invalidate`. Permission `PERM_MODIFY_TARGETS`.
- `RescanAsset` (`POST action/asset/rescan/`): body `asset_id`, optional `engine_id`. If the Asset is `kind='root_domain'`: find `Domain.objects.filter(project=asset.project, name=asset.value).first()`; if found, `scan_history_id = create_scan_object(host_id=domain.id, engine_id=engine_id, initiated_by_id=request.user.id)` then `initiate_scan.apply_async(kwargs={... , 'scan_mode':'asm', 'initiated_by_id':request.user.id})` (mirror `start_scan_ui`'s kwargs). Else (non-root, or no Domain) return `{'status': False, 'message': 'Per-asset rescan is not supported yet (root domains only in A2).'}`. Permission `PERM_INITATE_SCANS_SUBSCANS`.
- URLs added in `api/urls.py` beside the existing `action/...` / `add/...` paths; the viewset via the router.

### Manual-add validation (shared helper, e.g. `api/asset_add.py` or in `limes/` utils)
Per entry: strip; **punycode/IDN-normalize** (idna encode → `normalize_host`); classify `kind` using the platform's `validators` (domain → root_domain *or* hostname by registrable-domain membership; `ipv4`/`ipv6` → ip; `ipv4_cidr`/ipv6 cidr → cidr). **Reject** (skip with a warning): wildcards (`*` in value), and IPs that are private/reserved/loopback/link-local (`ipaddress.ip_address(...).is_private/is_reserved/is_loopback/is_link_local`) or CIDRs that are private/reserved. A hostname whose registrable domain is not among the project's `owned_root` Assets → still added as `owned_host` but a warning is returned suggesting the `co_brand` tier. No duplicate rows (get_or_create on `(project,kind,value)`).

### Permissions / auth
Reuse existing constants (no new role permission): `PERM_MODIFY_TARGETS` (confirm/reject/add), `PERM_INITATE_SCANS_SUBSCANS` (rescan). Login is already enforced globally by `LoginRequiredMiddleware`. Read endpoints (the viewset) stay unauthenticated-at-DRF-level like the other list viewsets (middleware still requires a session).

## UI design

Django templates + Bootstrap 5 + jQuery + DataTables (no Vue), matching the subdomains page.

- **Page**: `startScan/views.py` gets an `assets(request, slug)` view rendering `startScan/templates/startScan/assets.html` (extends `base/base.html`); URL `<slug:slug>/assets` in `startScan/urls.py`, name `assets`. Context flag `assets_active` for the nav.
- **Table**: a server-side DataTable (`serverSide: true`, `ajax.url = /api/listDatatableAsset/?project={{current_project.slug}}&format=datatables`), columns: checkbox, value (links to detail modal), kind (badge), scope_tier (badge), state (badge), http_status, page_title, technologies, IPs, last_seen, tags, actions. Column `render` functions inline, mirroring `subdomains.html`.
- **Facet filters**: dropdowns/pills above the table for `kind`, `scope_tier`, `state`, `tag` that append the matching query param and reload the table (`table.ajax.url(...).load()`).
- **Detail modal**: reuse the `base/_items/` modal pattern (`get_asset_modal(project, asset_id)` JS in a new `static/custom/asset.js`) fetching the serialized Asset and rendering: current state, `sources` (source/evidence/confidence/seen_at), the **parent chain** ("why is this mine": asset → parent → … → root), linked vulnerabilities count, and action buttons — **Confirm/Reject** (shown for `candidate`), **Rescan** (shown for `root_domain`). Buttons POST to the action endpoints and toast the `{status,message}`.
- **Add-assets modal**: a modal on the Assets page with a single-entry field, a bulk-paste textarea, and a CSV file input (parsed client-side or posted as text), a tier select (owned / co-brand), and a reason field; POSTs to `AddAssets`; shows the returned counts + warnings.
- **Nav**: add an "Assets" item to `templates/base/_items/top_nav.html` (near the History dropdown's `All Subdomains`/`All Endpoints`, or as a top-level item), `href="{% url 'assets' current_project.slug %}"`.

## Testing

- **API list/filter:** seed Assets of several kinds/tiers/states in a project; assert `listDatatableAsset?project=slug` returns only that project's rows; each facet param (`kind`,`scope_tier`,`state`,`tag`) narrows correctly; `?no_page` returns all; the serializer emits `parent_value` and `vuln_count` without per-row extra queries (assert query count bounded via `assertNumQueries`).
- **Confirm/Reject:** a `candidate` → confirm sets `owned_host`+`added_by`+reason+`state=active` and calls `invalidate`; reject sets `rejected`. Permission denied without `PERM_MODIFY_TARGETS`.
- **Manual add:** accepts a domain/host/ip/cidr; **rejects** `10.0.0.1`, `127.0.0.1`, `192.168.0.0/16`, `169.254.x`, and `*.x.com` (wildcard) with warnings; punycode-normalizes an IDN (e.g. `bücher.example` → `xn--bcher-kva.example`); warns when a hostname's registrable domain isn't an owned root; de-dupes on re-add. `added_by`/`decision_reason` recorded.
- **Rescan:** a `root_domain` asset with a matching `Domain` triggers `initiate_scan` with `scan_mode='asm'` (assert the task is enqueued / `create_scan_object` called); a `hostname`/`ip` asset or a root with no `Domain` returns `{'status': False}` with the not-supported message.
- **Page:** the `assets` view renders for a valid project slug and 404s/ redirects for an unknown slug (mirror existing views); the nav item appears.
- `makemigrations --check` clean (A2 adds NO model/migration); `make test` green; no new Celery task (TASK_PLAN/no-join invariants untouched).

## Review focus

1. **Project isolation:** every Asset endpoint must filter `project__slug`; a missing/wrong `project` must never leak another project's assets (the platform has no per-user ACL, so the query filter is the only guard). → list + action tests.
2. **Manual-add trust boundary:** private/reserved/loopback/link-local IPs, wildcards, and malformed input must be rejected, not stored — this is user-supplied data that later drives scans. → add tests.
3. **Rescan scope gate:** only `root_domain` (owned) assets can trigger a scan; a `candidate`/`rejected`/`co_brand`-unauthorized or non-root asset must not start active work. → rescan test + reuse `is_active_scan_allowed`.
4. **Serializer performance:** the list must not regress into N+1 (the Subdomain serializer's trap) — assets list is the hot path. → `assertNumQueries` test.
5. **Confirm/reject/add must refresh dashboard counts:** each mutation calls `invalidate(project_id)`, else the (unchanged) dashboard shows stale numbers. → assert `invalidate` called.

## Risks

- The platform's hand-rolled datatables filter idiom is verbose and column-index-coupled to the JS; A2 keeps its filter simpler (facet params + plain search) to avoid that fragility. Risk: column map drift between JS and view — mitigated by keeping the column set small and testing the facet params server-side.
- Rescan is domain-centric in the engine; A2 deliberately restricts rescan to root domains to avoid half-wiring a per-asset path that belongs to the Scanner module. Clear user-facing message for the unsupported case.
- No per-user project ACL exists platform-wide; A2 does not add one (out of scope) but documents that project isolation rests entirely on the query filter.
