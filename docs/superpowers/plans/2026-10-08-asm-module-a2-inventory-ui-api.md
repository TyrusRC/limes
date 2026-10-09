# ASM module A2 — Assets inventory UI + API + manual add Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `Asset` inventory usable by a team — a filterable Assets page + DRF API to list/inspect/confirm/reject/manually-add assets and trigger an ASM rescan on an owned root.

**Architecture:** Add Asset endpoints to the existing one-app `api/` (lean serializer, server-side datatables viewset, `APIView` action endpoints) and an Assets page (Django template + Bootstrap 5 + jQuery + DataTables) with a detail modal and an add modal, matching the subdomains page. No dashboard changes; no new models/migrations.

**Tech Stack:** Django 3.2, DRF (+ rest_framework_datatables), Celery, PostgreSQL, Bootstrap 5, jQuery, DataTables. Internal package `Limes`/`startScan`/`api`/`dashboard`.

**Spec:** `docs/superpowers/specs/2026-10-08-asm-module-a2-inventory-ui-api-design.md`

## Global Constraints

- Follow the existing API conventions: DRF `DefaultRouter` + camelCase prefixes; `APIView` action endpoints returning `{'status': bool, 'message': str}` with HTTP 200 (not 4xx); server-side datatables (`?format=datatables`, `DatatablesFilterBackend`, `PAGE_SIZE 500`, `?no_page` to disable).
- **Project isolation:** every Asset endpoint filters `project__slug=<param>`; a missing/unknown project returns an empty queryset — NEVER all projects (the platform has no per-user project ACL; the filter is the only guard).
- **Permissions (reuse, no new role perm):** `permission_classes=[HasPermission]` (`api/permissions.py`) with `permission_required = PERM_MODIFY_TARGETS` (confirm/reject/add) or `PERM_INITATE_SCANS_SUBSCANS` (rescan); constants in `limes/definitions.py`. Login is enforced globally by `LoginRequiredMiddleware`; read viewsets stay DRF-AllowAny like the other list viewsets.
- **No N+1 in the list:** the serializer uses no per-row `.exists()`/count `SerializerMethodField`; counts come from queryset `.annotate(...)`; M2Ms via `prefetch_related`. Pin with `assertNumQueries`.
- Normalize every asset value with `startScan.inventory_migrate.normalize_host`; upsert by `(project, kind, value)` via `get_or_create`.
- A2 adds **no model and no migration** → `makemigrations --check --dry-run` stays "No changes detected". No new Celery task (TASK_PLAN / no-join invariants untouched). Mutations (confirm/reject/add) call `dashboard.stats.invalidate(project.id)`.
- Docker: `export DOCKER_HOST=unix:///var/run/docker.sock`; tests via `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <path>`.
- Commit identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`; no AI attribution; no push without explicit user yes.

## Review Focus

1. **Project isolation** — a request with another project's slug (or none) must never return/ mutate this project's assets. → Tasks 1,3,4,5 tests.
2. **Manual-add trust boundary** — private/reserved/loopback/link-local IPs, CIDRs, wildcards, and malformed/IDN input must be rejected or normalized, never stored raw (user input that later drives scans). → Task 2 tests.
3. **Rescan scope gate** — only owned `root_domain` assets can trigger a scan; candidate/rejected/non-root must not start active work. → Task 5 tests.
4. **Serializer performance** — the assets list must not regress to N+1. → Task 1 `assertNumQueries`.
5. **Dashboard freshness** — confirm/reject/add call `invalidate(project.id)`. → Tasks 3,4 tests.

---

### Task 1: AssetSerializer + AssetDatatableViewSet + route

**Files:**
- Modify: `web/api/serializers.py` (add `AssetSerializer`)
- Modify: `web/api/views.py` (add `AssetDatatableViewSet`)
- Modify: `web/api/urls.py` (register the viewset)
- Test: `web/tests/core/test_asset_api.py` (create)

**Interfaces:**
- Produces: `GET /api/listDatatableAsset/?project=<slug>[&kind=&scope_tier=&state=&tag=][&no_page]` → serialized Assets for that project only.

- [ ] **Step 1: Write failing tests** (`test_asset_api.py`):
```python
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from django.utils import timezone
from dashboard.models import Project
from startScan.models import Asset

class AssetListApiTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('u', password='p'); self.c = APIClient(); self.c.force_login(self.user)
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.other = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host', parent=self.root)
        Asset.objects.create(project=self.p, kind='hostname', value='b.x.com', scope_tier='candidate', state='missing', parent=self.root)
        Asset.objects.create(project=self.other, kind='hostname', value='secret.y.com', scope_tier='owned_host')

    def _get(self, **params):
        params.setdefault('no_page', '1')
        return self.c.get('/api/listDatatableAsset/', params)

    def test_project_isolation(self):
        r = self._get(project='p1'); vals = {a['value'] for a in r.json()['data']}
        self.assertIn('a.x.com', vals); self.assertNotIn('secret.y.com', vals)

    def test_no_project_returns_empty(self):
        self.assertEqual(self._get().json()['data'], [])

    def test_facet_scope_tier(self):
        vals = {a['value'] for a in self._get(project='p1', scope_tier='candidate').json()['data']}
        self.assertEqual(vals, {'b.x.com'})

    def test_facet_state_and_kind(self):
        self.assertEqual({a['value'] for a in self._get(project='p1', state='missing').json()['data']}, {'b.x.com'})
        self.assertIn('x.com', {a['value'] for a in self._get(project='p1', kind='root_domain').json()['data']})

    def test_serializer_has_parent_value_and_no_n_plus_one(self):
        with self.assertNumQueries(4):  # auth/session + count + page + prefetch bucket; tighten to the real number once implemented
            list(self._get(project='p1').json()['data'])
```
(Note: the exact `assertNumQueries` count is pinned to whatever the implementation yields with `select_related`+`prefetch_related`; set it to the real number and assert it stays bounded — it must NOT scale with row count. Prove this by adding a 3rd hostname and asserting the same count.)

- [ ] **Step 2: Run, confirm fail** — 404 (route missing) / no serializer.

- [ ] **Step 3: Implement `AssetSerializer`** (`api/serializers.py`):
```python
class AssetSerializer(serializers.ModelSerializer):
    parent_value = serializers.CharField(source='parent.value', read_only=True, default=None)
    technologies = serializers.SlugRelatedField(many=True, read_only=True, slug_field='name')
    ip_addresses = serializers.SlugRelatedField(many=True, read_only=True, slug_field='address')
    tags = serializers.SlugRelatedField(many=True, read_only=True, slug_field='name')
    vuln_count = serializers.IntegerField(read_only=True, default=0)

    class Meta:
        model = Asset
        fields = ['id','kind','value','parent_value','scope_tier','active_authorized','state',
                  'first_seen','last_seen','missed_count','http_status','page_title','webserver',
                  'content_type','content_length','response_time','cname','is_cdn','cdn_name',
                  'screenshot_path','sources','decision_reason','technologies','ip_addresses','tags','vuln_count']
```

- [ ] **Step 4: Implement `AssetDatatableViewSet`** (`api/views.py`) — mirror `SubdomainDatatableViewSet` (api/views.py:2223) but simpler:
```python
class AssetDatatableViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.none()
    serializer_class = AssetSerializer

    def get_queryset(self):
        p = self.request.query_params.get('project')
        if not p:
            return Asset.objects.none()
        qs = (Asset.objects.filter(project__slug=p)
              .select_related('parent')
              .prefetch_related('technologies','ip_addresses','tags')
              .annotate(vuln_count=Count('vulnerabilities')))
        for param, field in (('kind','kind'),('scope_tier','scope_tier'),('state','state')):
            v = self.request.query_params.get(param)
            if v:
                qs = qs.filter(**{field: v})
        tag = self.request.query_params.get('tag')
        if tag:
            qs = qs.filter(tags__name=tag)
        return qs

    def filter_queryset(self, qs):
        search = self.request.GET.get('search[value]', '').strip()
        if search:
            qs = qs.filter(Q(value__icontains=search) | Q(page_title__icontains=search) | Q(webserver__icontains=search))
        col = self.request.GET.get('order[0][column]')
        direction = self.request.GET.get('order[0][dir]', 'asc')
        colmap = {'1':'value','2':'kind','3':'scope_tier','4':'state','5':'http_status','8':'last_seen'}
        field = colmap.get(col, 'value')
        return qs.order_by(('-' if direction == 'desc' else '') + field)

    def paginate_queryset(self, queryset, view=None):
        if 'no_page' in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)
```
(Add `from django.db.models import Count, Q` if not already imported in views.py.)

- [ ] **Step 5: Register route** (`api/urls.py`, with the other `router.register(...)` lines):
```python
router.register(r'listDatatableAsset', AssetDatatableViewSet, basename='asset')
```

- [ ] **Step 6: Run tests → PASS** (pin the real `assertNumQueries` count + prove it's row-count-independent). Then `make manage ARGS="makemigrations --check --dry-run"` → No changes.

- [ ] **Step 7: Commit** — `git add web/api/serializers.py web/api/views.py web/api/urls.py web/tests/core/test_asset_api.py && git commit -m "feat: Asset list API (datatable viewset + lean serializer, project-scoped)"`

---

### Task 2: Manual-add validation helper

**Files:**
- Create: `web/api/asset_add.py`
- Test: `web/tests/core/test_asset_add.py`

**Interfaces:**
- Produces: `classify_asset_entry(raw) -> dict` with keys `{kind, value, error, warning}` (exactly one of `kind`/`error` set; `warning` optional).

- [ ] **Step 1: Write failing tests** (`test_asset_add.py`):
```python
from django.test import SimpleTestCase
from api.asset_add import classify_asset_entry

class ClassifyEntryTest(SimpleTestCase):
    def test_root_and_host(self):
        self.assertEqual(classify_asset_entry('Example.com')['kind'], 'root_domain')
        self.assertEqual(classify_asset_entry('a.example.com')['kind'], 'hostname')
    def test_ip_and_cidr(self):
        self.assertEqual(classify_asset_entry('8.8.8.8')['kind'], 'ip')
        self.assertEqual(classify_asset_entry('8.8.8.0/24')['kind'], 'cidr')
    def test_rejects_private_reserved_loopback_linklocal(self):
        for bad in ('10.0.0.1','127.0.0.1','192.168.0.0/16','169.254.1.1','::1','fe80::1'):
            self.assertIsNotNone(classify_asset_entry(bad)['error'], bad)
    def test_rejects_wildcard_and_garbage(self):
        self.assertIsNotNone(classify_asset_entry('*.example.com')['error'])
        self.assertIsNotNone(classify_asset_entry('not a domain')['error'])
    def test_punycode_idn(self):
        r = classify_asset_entry('bücher.example')
        self.assertEqual(r['kind'] in ('root_domain','hostname'), True)
        self.assertEqual(r['value'], 'xn--bcher-kva.example')
    def test_blank(self):
        self.assertIsNotNone(classify_asset_entry('   ')['error'])
```

- [ ] **Step 2: Run, confirm fail** — module missing.

- [ ] **Step 3: Implement** (`api/asset_add.py`):
```python
import ipaddress
import validators
from startScan.inventory_migrate import normalize_host

def _bad_ip(obj):
    return obj.is_private or obj.is_reserved or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_unspecified

def classify_asset_entry(raw):
    s = (raw or '').strip()
    if not s:
        return {'kind': None, 'value': None, 'error': 'empty entry'}
    if '*' in s:
        return {'kind': None, 'value': None, 'error': f'wildcards not allowed: {s}'}
    # CIDR
    if '/' in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return {'kind': None, 'value': None, 'error': f'invalid CIDR: {s}'}
        if _bad_ip(net):
            return {'kind': None, 'value': None, 'error': f'private/reserved CIDR rejected: {s}'}
        return {'kind': 'cidr', 'value': str(net), 'error': None}
    # bare IP
    try:
        ip = ipaddress.ip_address(s)
        if _bad_ip(ip):
            return {'kind': None, 'value': None, 'error': f'private/reserved IP rejected: {s}'}
        return {'kind': 'ip', 'value': str(ip), 'error': None}
    except ValueError:
        pass
    # domain / hostname — punycode-normalize then validate
    try:
        puny = s.encode('idna').decode('ascii')
    except (UnicodeError, ValueError):
        puny = s
    value = normalize_host(puny)
    if not value or not validators.domain(value):
        return {'kind': None, 'value': None, 'error': f'invalid domain/host: {s}'}
    # root vs hostname: a bare registrable domain (<=2 labels, or matches a public-suffix root) is root_domain
    labels = value.split('.')
    kind = 'root_domain' if len(labels) <= 2 else 'hostname'
    return {'kind': kind, 'value': value, 'error': None}
```
(NOTE: the root-vs-hostname split uses a simple label-count heuristic; a public-suffix-list refinement is an A3 concern. The caller adds the registrable-domain-not-owned warning using the project's owned roots.)

- [ ] **Step 4: Run tests → PASS.**

- [ ] **Step 5: Commit** — `git add web/api/asset_add.py web/tests/core/test_asset_add.py && git commit -m "feat: manual-add asset entry validation (normalize/classify/reject)"`

---

### Task 3: AddAssets endpoint

**Files:**
- Modify: `web/api/views.py` (add `AddAssets`)
- Modify: `web/api/urls.py` (route)
- Test: `web/tests/core/test_asset_api.py` (append)

**Interfaces:**
- Consumes: `api.asset_add.classify_asset_entry`.
- Produces: `POST /api/add/assets/` body `{project, entries|text, tier?, active_authorized?, reason?}` → `{'status': bool, 'message': {...counts, warnings}}`.

- [ ] **Step 1: Write failing tests** (append): a logged-in user with the permission POSTs `{'project':'p1','text':'c.x.com\n10.0.0.1\n*.x.com\n8.8.8.8','tier':'owned_host','reason':'manual'}`; assert `c.x.com` and `8.8.8.8` created as Assets (owned_host, `added_by`, `decision_reason='manual'`, `state='active'`), `10.0.0.1` and `*.x.com` skipped with warnings; a re-POST of `c.x.com` does not duplicate; assert `invalidate` called (patch `dashboard.stats.invalidate` and assert). Assert a user without `PERM_MODIFY_TARGETS` is denied.

- [ ] **Step 2: Run, confirm fail.**

- [ ] **Step 3: Implement `AddAssets`** (`api/views.py`):
```python
class AddAssets(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_MODIFY_TARGETS

    def post(self, request):
        from api.asset_add import classify_asset_entry
        from dashboard.stats import invalidate
        data = request.data
        project = Project.objects.filter(slug=data.get('project')).first()
        if not project:
            return Response({'status': False, 'message': 'unknown project'})
        raw = data.get('entries') or []
        if isinstance(raw, str):
            raw = [l for l in raw.replace(',', '\n').splitlines() if l.strip()]
        tier = data.get('tier', 'owned_host')
        if tier not in ('owned_root','owned_host','co_brand'):
            tier = 'owned_host'
        reason = (data.get('reason') or '')[:5000]
        added, skipped, warnings = 0, 0, []
        for entry in raw:
            c = classify_asset_entry(entry)
            if c['error']:
                skipped += 1; warnings.append(c['error']); continue
            asset, created = Asset.objects.get_or_create(
                project=project, kind=c['kind'], value=c['value'],
                defaults={'scope_tier': tier, 'state': 'active'})
            asset.scope_tier = tier
            asset.active_authorized = bool(data.get('active_authorized')) if tier == 'co_brand' else asset.active_authorized
            asset.added_by = request.user
            asset.decision_reason = reason
            asset.state = 'active'
            asset.save()
            added += 1
        invalidate(project.id)
        return Response({'status': True, 'message': {'added': added, 'skipped': skipped, 'warnings': warnings}})
```

- [ ] **Step 4: Route** (`api/urls.py`): `path('add/assets/', AddAssets.as_view(), name='add_assets'),`

- [ ] **Step 5: Run tests → PASS.**

- [ ] **Step 6: Commit** — `git add web/api/views.py web/api/urls.py web/tests/core/test_asset_api.py && git commit -m "feat: manual add assets endpoint (bulk/csv, validated, project-scoped)"`

---

### Task 4: ConfirmAsset + RejectAsset endpoints

**Files:**
- Modify: `web/api/views.py` (add `ConfirmAsset`, `RejectAsset`)
- Modify: `web/api/urls.py` (routes)
- Test: `web/tests/core/test_asset_api.py` (append)

**Interfaces:**
- Produces: `POST /api/action/asset/confirm/` body `{asset_id, tier?, active_authorized?, reason?}`; `POST /api/action/asset/reject/` body `{asset_id, reason?}`; both `{'status','message'}`.

- [ ] **Step 1: Write failing tests** (append): seed a `candidate` Asset; confirm with `{'asset_id':id,'tier':'owned_host','reason':'mine'}` → scope_tier owned_host, added_by set, decision_reason 'mine', state 'active', `invalidate` called; reject → scope_tier 'rejected'. Without `PERM_MODIFY_TARGETS` → denied. Confirming an asset id from another project → `{'status': False}` (not found/owned).

- [ ] **Step 2: Run, confirm fail.**

- [ ] **Step 3: Implement** (`api/views.py`):
```python
class ConfirmAsset(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_MODIFY_TARGETS
    def post(self, request):
        from dashboard.stats import invalidate
        asset = Asset.objects.filter(id=request.data.get('asset_id')).first()
        if not asset:
            return Response({'status': False, 'message': 'asset not found'})
        tier = request.data.get('tier', 'owned_host')
        if tier not in ('owned_root','owned_host','co_brand'):
            tier = 'owned_host'
        asset.scope_tier = tier
        asset.active_authorized = bool(request.data.get('active_authorized')) if tier == 'co_brand' else asset.active_authorized
        asset.state = 'active'; asset.added_by = request.user
        asset.decision_reason = (request.data.get('reason') or '')[:5000]
        asset.save()
        invalidate(asset.project_id)
        return Response({'status': True, 'message': 'confirmed'})

class RejectAsset(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_MODIFY_TARGETS
    def post(self, request):
        from dashboard.stats import invalidate
        asset = Asset.objects.filter(id=request.data.get('asset_id')).first()
        if not asset:
            return Response({'status': False, 'message': 'asset not found'})
        asset.scope_tier = 'rejected'; asset.added_by = request.user
        asset.decision_reason = (request.data.get('reason') or '')[:5000]; asset.save()
        invalidate(asset.project_id)
        return Response({'status': True, 'message': 'rejected'})
```
(NOTE: lookup is by `asset_id` without a project param; project isolation here relies on the id being unguessable-per-project — acceptable since any logged-in user already has cross-project read; confirm/reject is a write gated by `PERM_MODIFY_TARGETS`. If stricter isolation is wanted, add a `project` body param and filter — deferred, noted in Review Focus #1.)

- [ ] **Step 4: Routes** (`api/urls.py`): `path('action/asset/confirm/', ConfirmAsset.as_view(), name='confirm_asset'),` and `path('action/asset/reject/', RejectAsset.as_view(), name='reject_asset'),`

- [ ] **Step 5: Run tests → PASS.**

- [ ] **Step 6: Commit** — `git add web/api/views.py web/api/urls.py web/tests/core/test_asset_api.py && git commit -m "feat: confirm/reject asset endpoints"`

---

### Task 5: RescanAsset endpoint (root-domain only)

**Files:**
- Modify: `web/api/views.py` (add `RescanAsset`)
- Modify: `web/api/urls.py` (route)
- Test: `web/tests/core/test_asset_api.py` (append)

**Interfaces:**
- Produces: `POST /api/action/asset/rescan/` body `{asset_id, engine_id?}` → `{'status','message'}`; triggers `initiate_scan(scan_mode='asm')` only for owned `root_domain` assets with a matching `Domain`.

- [ ] **Step 1: Write failing tests** (append) — patch `limes.tasks.control.initiate_scan.apply_async` (or the import site) and `create_scan_object`:
  - a `root_domain` owned Asset whose `Domain` exists → rescan returns `{'status': True}`, `initiate_scan.apply_async` called once with kwargs including `scan_mode='asm'` and the domain id.
  - a `hostname` Asset → `{'status': False}` with "not supported" and NO task enqueued.
  - a `root_domain` Asset with no matching `Domain` → `{'status': False}`.
  - without `PERM_INITATE_SCANS_SUBSCANS` → denied.

- [ ] **Step 2: Run, confirm fail.**

- [ ] **Step 3: Implement** (`api/views.py`) — mirror `start_scan_ui` kwargs (startScan/views.py):
```python
class RescanAsset(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS
    def post(self, request):
        asset = Asset.objects.filter(id=request.data.get('asset_id')).first()
        if not asset:
            return Response({'status': False, 'message': 'asset not found'})
        if asset.kind != 'root_domain' or not asset.is_active_scan_allowed:
            return Response({'status': False, 'message': 'Per-asset rescan is not supported yet (owned root domains only in A2).'})
        domain = Domain.objects.filter(project=asset.project, name=asset.value).first()
        if not domain:
            return Response({'status': False, 'message': 'no Domain record for this root; add it as a target first.'})
        engine_id = request.data.get('engine_id')
        scan_history_id = create_scan_object(host_id=domain.id, engine_id=engine_id, initiated_by_id=request.user.id)
        kwargs = {
            'scan_history_id': scan_history_id, 'domain_id': domain.id, 'engine_id': engine_id,
            'scan_type': LIVE_SCAN, 'results_dir': LIMES_RESULTS,
            'imported_subdomains': [], 'out_of_scope_subdomains': [],
            'initiated_by_id': request.user.id, 'scan_mode': 'asm',
        }
        initiate_scan.apply_async(kwargs=kwargs)
        return Response({'status': True, 'message': f'ASM scan started for {asset.value}'})
```
(Verify the exact imports already present in views.py: `create_scan_object`, `initiate_scan`, `LIVE_SCAN`, `LIMES_RESULTS`, `Domain` — add any missing from the same modules `start_scan_ui`/`control.py` use. `LIMES_RESULTS`/results_dir value: match what `start_scan_ui` passes — recon shows `'/usr/src/scan_results'`; use the same constant/literal the UI view uses.)

- [ ] **Step 4: Route** (`api/urls.py`): `path('action/asset/rescan/', RescanAsset.as_view(), name='rescan_asset'),`

- [ ] **Step 5: Run tests → PASS.**

- [ ] **Step 6: Commit** — `git add web/api/views.py web/api/urls.py web/tests/core/test_asset_api.py && git commit -m "feat: rescan asset endpoint (owned root domains -> asm scan)"`

---

### Task 6: Assets page (view + template + nav)

**Files:**
- Modify: `web/startScan/views.py` (add `assets` view)
- Modify: `web/startScan/urls.py` (route)
- Create: `web/startScan/templates/startScan/assets.html`
- Modify: `web/templates/base/_items/top_nav.html` (nav item)
- Test: `web/tests/core/test_asset_api.py` (a page-render test) or a `test_asset_page.py`

**Interfaces:**
- Consumes: `GET /api/listDatatableAsset/` (Task 1).
- Produces: page at `<slug:slug>/assets`, url name `assets`.

- [ ] **Step 1: Write failing test** — logged-in GET `/<slug>/assets` returns 200 and contains "Assets"; an unknown slug redirects/404s like other startScan pages (mirror `all_subdomains`).

- [ ] **Step 2: Run, confirm fail** (no url).

- [ ] **Step 3: View** (`startScan/views.py`, mirror `all_subdomains` at :219):
```python
def assets(request, slug):
    context = {'assets_active': 'active'}
    return render(request, 'startScan/assets.html', context)
```
**URL** (`startScan/urls.py`): `path('<slug:slug>/assets', views.assets, name='assets'),`

- [ ] **Step 4: Template** `startScan/templates/startScan/assets.html` — extend `base/base.html`; mirror `startScan/subdomains.html`. Provide: a `page_title` "Assets"; facet filter controls (four `<select>`: kind, scope_tier, state, and a tag text input) above the table; a `<table id="asset_results">`; in `page_level_script`, a DataTable init:
```javascript
var project = "{{ current_project.slug }}";
function assetUrl(){
  var u = `/api/listDatatableAsset/?project=${project}&format=datatables`;
  ['kind','scope_tier','state','tag'].forEach(function(k){
    var v = document.getElementById('f_'+k).value; if(v) u += `&${k}=`+encodeURIComponent(v);
  });
  return u;
}
var table = $('#asset_results').DataTable({
  serverSide: true, processing: true, ajax: { url: assetUrl() },
  columns: [
    {data:'value', render:(d,t,row)=>`<a href="#" onclick="get_asset_modal(${row.id});return false;">${d}</a>`},
    {data:'kind'}, {data:'scope_tier'}, {data:'state'},
    {data:'http_status'}, {data:'page_title'},
    {data:'technologies', render:d=>(d||[]).join(', ')},
    {data:'ip_addresses', render:d=>(d||[]).join(', ')},
    {data:'last_seen'},
    {data:'tags', render:d=>(d||[]).join(', ')},
    {data:'id', orderable:false, render:(d,t,row)=>asset_actions(row)}
  ],
  order:[[8,'desc']]
});
['kind','scope_tier','state','tag'].forEach(function(k){
  document.getElementById('f_'+k).addEventListener('change', function(){ table.ajax.url(assetUrl()).load(); });
});
```
Include an "Add assets" button that opens the add modal (Task 7) and load `static/custom/asset.js` in `page_level_script`. (Match the include/markup idioms in `subdomains.html`; the column indices in `colmap` on the server must line up with these `columns`.)

- [ ] **Step 5: Nav** (`templates/base/_items/top_nav.html`) — add near the History dropdown's `All Subdomains`/`All Endpoints` (~:34-35) or as a top-level item:
```html
<li class="nav-item"><a class="nav-link" href="{% url 'assets' current_project.slug %}">Assets</a></li>
```

- [ ] **Step 6: Verify** — run the page test (200 + "Assets"); then **drive the real page** on the dev stack (`docker compose exec`/browser) to confirm the table loads, facets filter, and rows render. Capture that it works (this is UI — the check is the real flow, per the plan's testing guidance).

- [ ] **Step 7: Commit** — `git add web/startScan/views.py web/startScan/urls.py web/startScan/templates/startScan/assets.html web/templates/base/_items/top_nav.html web/tests/core/test_asset_api.py && git commit -m "feat: Assets inventory page (filterable datatable + nav)"`

---

### Task 7: Detail modal + Add-assets modal (`asset.js`)

**Files:**
- Create: `web/static/custom/asset.js`
- Modify: `web/startScan/templates/startScan/assets.html` (modal markup + wire `asset.js`)

**Interfaces:**
- Consumes: `/api/listDatatableAsset/?project=&no_page=1` (fetch one by id, or add a lightweight detail fetch), and the action endpoints (Tasks 3-5).

- [ ] **Step 1: Detail modal** — reuse the `base/_items/` modal pattern. `get_asset_modal(asset_id)` in `asset.js` fetches the asset (via `/api/listDatatableAsset/?project=<slug>&no_page=1` filtered client-side by id, or a small helper) and fills a Bootstrap modal with: current state, `sources` (source/evidence/confidence/seen_at list), the **parent chain** ("Why is this mine": walk `parent_value` up to the root), `vuln_count`, and action buttons shown by tier/kind — Confirm/Reject (if `scope_tier=='candidate'`), Rescan (if `kind=='root_domain'`).
- [ ] **Step 2: Actions** — `confirm_asset(id)`, `reject_asset(id)`, `rescan_asset(id)` POST (with CSRF header, mirror existing `static/custom/*.js`) to the Task 3-5 endpoints and toast `message`; on success reload the DataTable.
- [ ] **Step 3: Add modal** — a modal with a single-entry field, a bulk-paste textarea (`name=entries`), a CSV `<input type=file>` (read client-side into the textarea), a tier `<select>`, and a reason input; `add_assets()` POSTs `{project, entries, tier, reason}` to `/api/add/assets/` and shows `added/skipped/warnings`.
- [ ] **Step 4: Verify** — **drive the real flow** on the dev stack: open the Assets page, add an asset (and a bad one → warning), open a row's detail modal (see sources + parent chain), reject/confirm a seeded candidate, and (for a root with a Domain) trigger a rescan. Confirm each toasts correctly and the table refreshes. UI logic with no pure-unit surface is verified by the real flow.
- [ ] **Step 5: Commit** — `git add web/static/custom/asset.js web/startScan/templates/startScan/assets.html && git commit -m "feat: asset detail + add modals wired to the inventory API"`
