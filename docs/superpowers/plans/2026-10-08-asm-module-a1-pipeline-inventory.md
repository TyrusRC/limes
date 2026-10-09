# ASM module A1 — ASM pipeline → inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An ASM-mode scan run writes the canonical `Asset` inventory as source of truth, running only the passive discovery+probe stages (Scanner stages gated off), with `ScanRun`/`ScanJob` bookkeeping, the scope gate, and the active↔missing lifecycle.

**Architecture:** Add a `mode` field to `ScanRun` and branch `initiate_scan` so `asm` runs build `chain(subdomain_discovery, screenshot)` + `report`. A new `limes/tasks/inventory.py` write layer upserts `Asset`/`ScanRun`/`ScanJob`; the existing passive writers (`save_subdomain`, `save_ip_address`, the in-process httpx probe inline writes) **dual-write** the inventory alongside the legacy rows, which stay as read-only history. `report` finalizes the run and runs the lifecycle.

**Tech Stack:** Django 3.2, Celery 5.4, PostgreSQL. Internal package `Limes`/`startScan`.

**Spec:** `docs/superpowers/specs/2026-10-08-asm-module-a1-pipeline-inventory-design.md`

## Global Constraints

- Preserve the no-join invariant: no `allow_join_result`, no in-task `.get()`/`.ready()`; `blocking_tasks()==[]` (`tests/core/test_no_joins.py`) must stay green. A1 adds **no new Celery task**, so `celery_routing.TASK_PLAN` / `test_every_task_is_planned` is untouched.
- Preserve secret redaction: the httpx probe keeps using `limes/identity.py` + `commands.redact_*`; add no new secret surface, log no secrets.
- Dual-write only: do NOT remove or alter the existing `Subdomain`/`EndPoint`/`IpAddress`/`Vulnerability` writes; ADD Asset writes beside them.
- Asset upserts are keyed by `(project, kind, value)` via `get_or_create`; `value` normalized with `startScan.inventory_migrate.normalize_host`; provenance appended to `sources` (deduped).
- `ScanRun.mode` default is `'full'` — existing (non-ASM) runs behave exactly as today.
- `makemigrations --check --dry-run` clean; `make test` green. Docker: `export DOCKER_HOST=unix:///var/run/docker.sock`; tests run via `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <path>`.
- Commit identity: `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`. No AI attribution in commit messages. No pushing without the user's explicit yes.

## Review Focus

1. A host present in a prior run but absent this run → active→missing after 3 consecutive misses (not deleted, not stuck active). → Task 7.
2. The same hostname discovered twice in one run (amass + httpx) → one Asset, sources appended not duplicated. → Task 3.
3. A `co_brand`/`candidate` asset seen passively → keeps its tier (never auto-promoted to `owned_host`). → Task 3.
4. A domain with no `project`, or a probe line with no resolvable host → skip cleanly, no crash, no mis-attributed Asset. → Task 2 (helpers null-safe) + Task 3.
5. A `full`/`scanner` run → behaves exactly as today (Scanner stages still run). → Task 6 (mode branch).

---

### Task 1: `ScanRun.mode` field + migration

**Files:**
- Modify: `web/startScan/asset_models.py` (the `ScanRun` model, ~`:94`)
- Create: `web/startScan/migrations/0008_scanrun_mode.py` (auto-generated)
- Test: `web/tests/core/test_asset_models.py`

**Interfaces:**
- Produces: `ScanRun.mode` CharField, choices `asm|scanner|full`, default `'full'`; module constant `SCAN_MODES`.

- [ ] **Step 1: Write the failing test** (append to `test_asset_models.py`):
```python
def test_scanrun_mode_defaults_to_full(self):
    from startScan.asset_models import Asset, ScanRun
    from dashboard.models import Project
    from django.utils import timezone
    p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
    root = Asset.objects.create(project=p, kind='root_domain', value='x.com', scope_tier='owned_root')
    run = ScanRun.objects.create(project=p, root_asset=root)
    self.assertEqual(run.mode, 'full')
    run2 = ScanRun.objects.create(project=p, root_asset=root, mode='asm')
    self.assertEqual(run2.mode, 'asm')
```

- [ ] **Step 2: Run it, confirm it fails** — `... test tests.core.test_asset_models` → FAIL (`ScanRun` has no field `mode`).

- [ ] **Step 3: Add the field.** In `asset_models.py` near the other constants add:
```python
SCAN_MODES = [(m, m) for m in ('asm', 'scanner', 'full')]
```
In the `ScanRun` model add (after `profile`):
```python
    mode = models.CharField(max_length=10, choices=SCAN_MODES, default='full')
```

- [ ] **Step 4: Generate the migration** — `make manage ARGS="makemigrations startScan"` → creates `0008_scanrun_mode.py` (dep `0007_migrate_to_assets`). Verify it only adds the field.

- [ ] **Step 5: Run the test + migration check** → test PASS; `makemigrations --check --dry-run` → "No changes detected".

- [ ] **Step 6: Commit** — `git add web/startScan/asset_models.py web/startScan/migrations/0008_scanrun_mode.py web/tests/core/test_asset_models.py && git commit -m "feat: add ScanRun.mode (asm/scanner/full) for the module split"`

---

### Task 2: `inventory.py` write layer

**Files:**
- Create: `web/limes/tasks/inventory.py`
- Test: `web/tests/core/test_inventory_writes.py`

**Interfaces:**
- Consumes: `startScan.models` (`Asset`, `ScanRun`, `ScanJob`, `Technology`, `IpAddress`), `startScan.inventory_migrate.normalize_host`.
- Produces:
  - `upsert_root_asset(project, name, request_headers=None) -> Asset`
  - `upsert_hostname_asset(project, name, parent=None, source='discovery', evidence='', scope_tier='owned_host') -> Asset|None`
  - `upsert_ip_asset(project, address, source='probe', evidence='') -> Asset|None`
  - `update_host_state(asset, **fields) -> None`
  - `is_active_scan_allowed_for(project, kind, value) -> bool`
  - `finalize_lifecycle(run) -> int` (count marked missing)
  - `STAGE_BY_TASK: dict[str,str]`

- [ ] **Step 1: Write failing tests** (`test_inventory_writes.py`):
```python
from django.test import TestCase
from django.utils import timezone
from dashboard.models import Project
from startScan.models import Asset
from limes.tasks import inventory as inv

class InventoryHelpersTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = inv.upsert_root_asset(self.p, 'Example.com.')

    def test_root_normalized_and_scoped(self):
        self.assertEqual(self.root.kind, 'root_domain')
        self.assertEqual(self.root.value, 'example.com')
        self.assertEqual(self.root.scope_tier, 'owned_root')

    def test_hostname_upsert_dedup_and_sources(self):
        a1 = inv.upsert_hostname_asset(self.p, 'A.example.com', parent=self.root, source='amass', evidence='e1')
        a2 = inv.upsert_hostname_asset(self.p, 'a.example.com', parent=self.root, source='amass', evidence='e1')
        a3 = inv.upsert_hostname_asset(self.p, 'a.example.com', parent=self.root, source='httpx', evidence='e2')
        self.assertEqual(a1.id, a2.id); self.assertEqual(a1.id, a3.id)
        self.assertEqual(a3.parent_id, self.root.id)
        self.assertEqual(len(a3.sources), 2)  # amass/e1 once + httpx/e2

    def test_hostname_empty_name_returns_none(self):
        self.assertIsNone(inv.upsert_hostname_asset(self.p, '', parent=self.root))

    def test_update_host_state_skips_none(self):
        a = inv.upsert_hostname_asset(self.p, 'h.example.com', parent=self.root)
        inv.update_host_state(a, http_status=200, page_title='T', webserver=None)
        a.refresh_from_db()
        self.assertEqual(a.http_status, 200); self.assertEqual(a.page_title, 'T')

    def test_is_active_scan_allowed_for(self):
        inv.upsert_hostname_asset(self.p, 'own.example.com', parent=self.root)  # owned_host
        cb = Asset.objects.create(project=self.p, kind='hostname', value='cb.example.com', scope_tier='co_brand')
        self.assertTrue(inv.is_active_scan_allowed_for(self.p, 'hostname', 'own.example.com'))
        self.assertFalse(inv.is_active_scan_allowed_for(self.p, 'hostname', 'cb.example.com'))
        self.assertFalse(inv.is_active_scan_allowed_for(self.p, 'hostname', 'missing.example.com'))

    def test_finalize_lifecycle_marks_unseen_missing(self):
        from startScan.asset_models import ScanRun
        a = inv.upsert_hostname_asset(self.p, 'stale.example.com', parent=self.root)
        run = ScanRun.objects.create(project=self.p, root_asset=self.root,
                                     start_scan_date=timezone.now())
        # asset last_seen is before run start (seeded earlier)
        Asset.objects.filter(id=a.id).update(last_seen=run.start_scan_date - timezone.timedelta(minutes=1))
        for _ in range(3):
            inv.finalize_lifecycle(run)
        a.refresh_from_db()
        self.assertEqual(a.state, 'missing'); self.assertEqual(a.missed_count, 3)
```

- [ ] **Step 2: Run, confirm fails** — ImportError / missing functions.

- [ ] **Step 3: Implement `inventory.py`:**
```python
"""ASM inventory write layer. Live-ORM upserts of Asset/ScanRun/ScanJob.
NOT the migration back-fill (that is startScan/inventory_migrate.py, apps.get_model).
Keyed by (project, kind, value); value normalized via normalize_host so live and
migrated rows share identity."""
from django.utils import timezone
from startScan.models import Asset
from startScan.inventory_migrate import normalize_host

STATE_FIELDS = ('http_status', 'page_title', 'webserver', 'content_type',
                'content_length', 'response_time', 'cname', 'is_cdn',
                'cdn_name', 'screenshot_path')

STAGE_BY_TASK = {
    'subdomain_discovery': 'discovery', 'http_crawl': 'probe', 'screenshot': 'probe',
    'port_scan': 'ports', 'fetch_url': 'crawl',
    'vulnerability_scan': 'dast', 'code_audit': 'code',
}


def _append_source(asset, source, evidence, confidence=0.5):
    srcs = asset.sources or []
    if not any(s.get('source') == source and s.get('evidence') == evidence for s in srcs):
        srcs.append({'source': source, 'evidence': evidence,
                     'confidence': confidence, 'seen_at': timezone.now().isoformat()})
        asset.sources = srcs
    return asset


def upsert_root_asset(project, name, request_headers=None):
    value = normalize_host(name)
    asset, _ = Asset.objects.get_or_create(
        project=project, kind='root_domain', value=value,
        defaults={'scope_tier': 'owned_root'})
    if request_headers and not asset.request_headers:
        asset.request_headers = request_headers
    asset.mark_missing_or_seen(True)
    return asset


def upsert_hostname_asset(project, name, parent=None, source='discovery',
                          evidence='', scope_tier='owned_host'):
    value = normalize_host(name)
    if not value:
        return None
    asset, _ = Asset.objects.get_or_create(
        project=project, kind='hostname', value=value,
        defaults={'scope_tier': scope_tier, 'parent': parent})
    if parent is not None and asset.parent_id is None:
        asset.parent = parent
    _append_source(asset, source, evidence)
    asset.save()
    asset.mark_missing_or_seen(True)   # never changes scope_tier -> no promotion
    return asset


def upsert_ip_asset(project, address, source='probe', evidence=''):
    if not address:
        return None
    asset, _ = Asset.objects.get_or_create(
        project=project, kind='ip', value=address,
        defaults={'scope_tier': 'owned_host'})
    _append_source(asset, source, evidence)
    asset.save()
    asset.mark_missing_or_seen(True)
    return asset


def update_host_state(asset, **fields):
    changed = []
    for k in STATE_FIELDS:
        if k in fields and fields[k] is not None:
            setattr(asset, k, fields[k]); changed.append(k)
    if changed:
        asset.save(update_fields=changed)


def is_active_scan_allowed_for(project, kind, value):
    asset = Asset.objects.filter(project=project, kind=kind, value=normalize_host(value)).first()
    return bool(asset and asset.is_active_scan_allowed)


def finalize_lifecycle(run):
    # NOTE: scans active hostname Assets under one root (.iterator, bounded per root);
    # upgrade path if a root grows very large: a single conditional bulk update.
    n = 0
    qs = Asset.objects.filter(project=run.project, kind='hostname', parent=run.root_asset,
                              state='active', last_seen__lt=run.start_scan_date)
    for asset in qs.iterator(chunk_size=2000):
        asset.mark_missing_or_seen(False); n += 1
    return n
```

- [ ] **Step 4: Run tests → PASS.**

- [ ] **Step 5: Commit** — `git add web/limes/tasks/inventory.py web/tests/core/test_inventory_writes.py && git commit -m "feat: ASM inventory write layer (upsert assets, scope gate, lifecycle)"`

---

### Task 3: `save_subdomain` dual-writes the hostname Asset

**Files:**
- Modify: `web/limes/tasks/persistence.py` (`save_subdomain`, `:510`)
- Test: `web/tests/core/test_inventory_writes.py`

**Interfaces:**
- Consumes: `inventory.upsert_root_asset`, `inventory.upsert_hostname_asset`.
- Produces: `save_subdomain` additionally upserts a `hostname` Asset (parent = the root Asset for `scan.domain`) when `scan.domain` has a project, returning the same `(Subdomain, created)` tuple as before.

- [ ] **Step 1: Write the failing test** (append): create a `Project` + `Domain` + `ScanHistory`, call `save_subdomain('a.x.com', ctx={'scan_history_id': scan.id, 'domain_id': domain.id})`, assert a `hostname` Asset `a.x.com` exists with `parent` = the root asset `x.com` and `scope_tier='owned_host'`; call again for `a.x.com` → still one Asset (dedup); seed a `co_brand` Asset `cb.x.com` then `save_subdomain('cb.x.com', ...)` → its `scope_tier` stays `co_brand` (no promotion).

- [ ] **Step 2: Run, confirm fails** — no Asset created.

- [ ] **Step 3: Implement.** In `save_subdomain`, after the existing `get_or_create` of the `Subdomain` and before returning, add (guarding on project):
```python
    project = getattr(domain, 'project', None)
    if project and subdomain.name:
        from limes.tasks import inventory as inv
        root = inv.upsert_root_asset(project, domain.name, getattr(domain, 'request_headers', None))
        inv.upsert_hostname_asset(project, subdomain.name, parent=root,
                                  source='discovery', evidence=f'scan:{scan.id}')
```
(The lazy import avoids a circular import with `persistence` ↔ `inventory` at module load.)

- [ ] **Step 4: Run tests → PASS** (hostname Asset created, dedup holds, co_brand not promoted).

- [ ] **Step 5: Commit** — `git add web/limes/tasks/persistence.py web/tests/core/test_inventory_writes.py && git commit -m "feat: save_subdomain dual-writes the hostname Asset"`

---

### Task 4: `save_ip_address` dual-writes the ip Asset + fixes the `cdn`→`is_cdn` bug

**Files:**
- Modify: `web/limes/tasks/persistence.py` (`save_ip_address`, `:590`)
- Test: `web/tests/core/test_inventory_writes.py`

**Interfaces:**
- Consumes: `inventory.upsert_ip_asset`, `inventory.update_host_state`.
- Produces: `save_ip_address` persists the CDN flag on `IpAddress.is_cdn` (callers pass `cdn=`), upserts an `ip` Asset for the subdomain's project, and links it to the host Asset's `ip_addresses` M2M. Same return tuple.

- [ ] **Step 1: Write the failing test:** call `save_ip_address('1.2.3.4', subdomain=sub, cdn=True)` where `sub` belongs to a project with a `hostname` Asset; assert the `IpAddress.is_cdn` is `True` (today it is lost), an `ip` Asset `1.2.3.4` exists for the project, and it is in the host Asset's `ip_addresses`.

- [ ] **Step 2: Run, confirm fails** — `is_cdn` False / no ip Asset.

- [ ] **Step 3: Implement.** In `save_ip_address`, map the legacy `cdn` kwarg to the real field, then dual-write:
```python
    if 'cdn' in kwargs:               # bug fix: model field is is_cdn, not cdn
        kwargs['is_cdn'] = kwargs.pop('cdn')
    # ... existing get_or_create/setattr/save, now using is_cdn ...
    if subdomain is not None:
        project = getattr(getattr(subdomain, 'target_domain', None), 'project', None)
        if project:
            from limes.tasks import inventory as inv
            ip_asset = inv.upsert_ip_asset(project, ip_address, evidence=f'host:{subdomain.name}')
            host = Asset.objects.filter(project=project, kind='hostname',
                                        value=subdomain.name.lower().rstrip('.')).first()
            if host and ip_asset:
                host.ip_addresses.add(ip)          # reuse the legacy IpAddress row
```
(Import `Asset` lazily or at top as the file already imports models.)

- [ ] **Step 4: Run tests → PASS.**

- [ ] **Step 5: Commit** — `git add ... && git commit -m "fix: persist IpAddress.is_cdn; save_ip_address dual-writes the ip Asset"`

---

### Task 5: probe inline writes update the host Asset current-state

**Files:**
- Modify: `web/limes/tasks/inventory.py` (add `mirror_subdomain_state`)
- Modify: `web/limes/tasks/stages.py` (`http_crawl` probe writes `:941-947`, technologies `:963-974`, Subdomain CNAME/CDN `:1002-1015`; screenshot `:279-280`)
- Test: `web/tests/core/test_inventory_writes.py`

**Interfaces:**
- Consumes: `inventory.update_host_state`, `inventory.upsert_hostname_asset`.
- Produces: after the probe updates a `Subdomain`'s current state, the matching `hostname` Asset gets the same `http_status/page_title/webserver/content_type/content_length/response_time/cname/is_cdn/cdn_name` and `technologies`; `screenshot` sets `screenshot_path` on the Asset too.

- [ ] **Step 1: Write the failing test:** drive the probe-state mirror via a small unit — after a `Subdomain` row gets probe fields + a `Technology`, call the new helper the stage will call (`mirror_subdomain_state(subdomain, project)`), assert the host Asset's state fields + `technologies` M2M match.

- [ ] **Step 2: Run, confirm fails.**

- [ ] **Step 3: Implement.** Add to `inventory.py` a convenience:
```python
def mirror_subdomain_state(subdomain, project):
    if not project:
        return None
    asset = upsert_hostname_asset(project, subdomain.name, source='probe',
                                  evidence='httpx')
    if not asset:
        return None
    update_host_state(asset, http_status=subdomain.http_status, page_title=subdomain.page_title,
                      webserver=subdomain.webserver, content_type=subdomain.content_type,
                      content_length=subdomain.content_length, response_time=subdomain.response_time,
                      cname=subdomain.cname, is_cdn=subdomain.is_cdn, cdn_name=subdomain.cdn_name,
                      screenshot_path=subdomain.screenshot_path)
    for tech in subdomain.technologies.all():
        asset.technologies.add(tech)
    return asset
```
Call `inventory.mirror_subdomain_state(subdomain, getattr(self.domain, 'project', None))` at the end of the `http_crawl` subdomain-state block (`stages.py:~1015`) and after the screenshot save (`:280`). Lazy-import `inventory`.

- [ ] **Step 4: Run tests → PASS.**

- [ ] **Step 5: Commit** — `git add ... && git commit -m "feat: mirror probe/tech/screenshot state onto the host Asset"`

---

### Task 6: ScanRun/ScanJob bookkeeping + `report` status

**Files:**
- Modify: `web/limes/tasks/control.py` (`initiate_scan` `:11`, `report` `:299`)
- Modify: `web/limes/celery_custom_task.py` (`LimesTask.__call__`, `:52`/activity creation `:109`)
- Test: `web/tests/core/test_scan_mode.py`

**Interfaces:**
- Consumes: `inventory.upsert_root_asset`, `inventory.STAGE_BY_TASK`, `inventory.finalize_lifecycle` (used in Task 7).
- Produces: a `ScanRun` is created in `initiate_scan` (`ctx['scan_run_id']` threaded); each executed stage whose name is in `STAGE_BY_TASK` creates/finishes a `ScanJob`; `report` sets `ScanRun.status`/`stop_scan_date`.

- [ ] **Step 1: Write the failing test:** run `initiate_scan` wiring in a unit harness (or call the helper that builds the run) and assert one `ScanRun(project, root_asset, mode)` exists with `ctx['scan_run_id']` set; simulate a stage via `LimesTask` and assert a `ScanJob(run, stage='discovery')` is created; call `report` and assert `ScanRun.status` is set.

- [ ] **Step 2: Run, confirm fails.**

- [ ] **Step 3: Implement.** In `initiate_scan`, after the `ScanHistory` is updated and before building the workflow:
```python
    from limes.tasks import inventory as inv
    project = domain.project
    scan_mode = (locals().get('scan_mode') or 'full')
    run = None
    if project:
        root = inv.upsert_root_asset(project, domain.name, getattr(domain, 'request_headers', None))
        from startScan.asset_models import ScanRun
        run = ScanRun.objects.create(project=project, root_asset=root, mode=scan_mode,
                                     results_dir=scan.results_dir, start_scan_date=timezone.now())
        ctx['scan_run_id'] = run.id
```
Add a `scan_mode='full'` kwarg to `initiate_scan`'s signature (default preserves behavior). In `LimesTask.__call__`, after the `ScanActivity` is created:
```python
    run_id = ctx.get('scan_run_id'); stage = inventory.STAGE_BY_TASK.get(self.name)
    self._scan_job = None
    if run_id and stage:
        from startScan.asset_models import ScanRun, ScanJob
        run = ScanRun.objects.filter(id=run_id).first()
        if run:
            self._scan_job = ScanJob.objects.create(run=run, asset=run.root_asset, stage=stage,
                                                    started=timezone.now(), celery_id=self.request.id)
```
and on completion set `self._scan_job.finished = now()`, `status`, `output_path` and save. In `report`, set `ScanRun.status` from the failed-activity count (mirror the existing `ScanHistory` logic) and `stop_scan_date`.

- [ ] **Step 4: Run tests → PASS.**

- [ ] **Step 5: Commit** — `git add ... && git commit -m "feat: ScanRun/ScanJob bookkeeping across the pipeline"`

---

### Task 7: scan-mode split (ASM chain) + finalize lifecycle

**Files:**
- Modify: `web/limes/tasks/control.py` (workflow build `:141-163`, `report` `:299`)
- Test: `web/tests/core/test_scan_mode.py`

**Interfaces:**
- Consumes: `inventory.finalize_lifecycle`.
- Produces: `mode=='asm'` builds `chain(subdomain_discovery, screenshot)` + report; `report` calls `finalize_lifecycle(run)`.

- [ ] **Step 1: Write the failing tests:** (a) a helper `build_workflow(ctx, mode)` returns a signature whose task-name set is exactly `{subdomain_discovery, screenshot}` for `'asm'` and includes `port_scan`/`fetch_url`/`vulnerability_scan`/`code_audit` for `'full'`; (b) after `report` runs with a `ScanRun`, an active hostname Asset under the root with `last_seen < run.start` is `missing` after 3 report runs, and one seen this run stays `active`.

- [ ] **Step 2: Run, confirm fails.**

- [ ] **Step 3: Implement.** Extract the chain construction into `build_workflow(ctx, mode)`:
```python
def build_workflow(ctx, mode):
    if mode == 'asm':
        return chain(subdomain_discovery.si(ctx=ctx, description='Subdomain discovery'),
                     screenshot.si(ctx=ctx, description='Screenshot'))
    return chain(subdomain_discovery.si(ctx=ctx, description='Subdomain discovery'),
                 port_scan.si(ctx=ctx, description='Port scan'),
                 fetch_url.si(ctx=ctx, description='Fetch URL'),
                 group(vulnerability_scan.si(ctx=ctx, description='Vulnerability scan'),
                       screenshot.si(ctx=ctx, description='Screenshot'),
                       code_audit.si(ctx=ctx, description='Code audit')))
```
`initiate_scan` calls `build_workflow(ctx, scan_mode)`. In `report`, after setting `ScanRun.status`, add:
```python
    run_id = ctx.get('scan_run_id')
    if run_id:
        from startScan.asset_models import ScanRun
        run = ScanRun.objects.filter(id=run_id).first()
        if run:
            from limes.tasks import inventory as inv
            inv.finalize_lifecycle(run)
```

- [ ] **Step 4: Run tests → PASS.**

- [ ] **Step 5: Commit** — `git add ... && git commit -m "feat: ASM-mode workflow split + active/missing lifecycle on finalize"`

---

### Task 8: E2E + invariants + benchmark

**Files:**
- Create: `docs/benchmarks/2026-10-asm-a1-pipeline.md`
- Test: run the full suite + invariants.

- [ ] **Step 1: Invariants green** — run `tests/core/test_no_joins.py`, `test_celery_config.py`, and the new `test_inventory_writes.py` + `test_scan_mode.py`; `make test` green; `makemigrations --check --dry-run` → "No changes detected". Paste real output.

- [ ] **Step 2: E2E on a seeded stack** — bring up the stack (`docker compose down -v; make up`), seed a small benchmark (`make bench-seed`), trigger one `initiate_scan(..., scan_mode='asm')` via the management shell (or `bench_scans` with mode), and assert: `ScanRun(mode='asm')` created; `hostname`/`ip` Assets populated for the root; the run's task set excluded `port_scan`/`fetch_url`/`vulnerability_scan`/`code_audit` (check `ScanActivity`/`ScanJob` rows); `blocking_tasks()==[]`. Use `docker compose exec web python3 manage.py ...` (NOT `make manage`, which targets the test DB).

- [ ] **Step 3: Record** `docs/benchmarks/2026-10-asm-a1-pipeline.md` with the commit hash, the asserted counts (assets created, ScanJobs per stage, excluded stages), and confirmation of the invariants.

- [ ] **Step 4: Commit** — `git add docs/benchmarks/2026-10-asm-a1-pipeline.md && git commit -m "docs: record ASM A1 pipeline validation"`
