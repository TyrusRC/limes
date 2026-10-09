# ASM 2a — Stage 1: Asset models + migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce the canonical deduplicated `Asset` inventory plus `ScanRun`/`ScanJob`/`Tag` models and a batched, reversible data migration from the existing scan-centric `Domain`/`Subdomain`/`IpAddress`/`Vulnerability` data — without yet changing the running pipeline or UI.

**Architecture:** New models live in a focused `web/startScan/asset_models.py` imported by `startScan/models.py` (so they're in the `startScan` app for migrations, reusing `Technology`/`IpAddress`/`Project`). One schema migration creates the tables + the `Vulnerability.asset` column; one `atomic=False`, chunked, reversible `RunPython` back-fills the inventory from existing rows. The live 0B pipeline is untouched this stage (it keeps writing `Subdomain`/`EndPoint`); Stage 2 rewires it.

**Tech Stack:** Django 3.2, PostgreSQL, Celery (models only here), the 0A containerized test harness (`make test`).

**Spec:** `docs/superpowers/specs/2026-10-07-asm-2a-asset-inventory-design.md`

## Global Constraints

- Internal package is `limes`. New models go in `web/startScan/asset_models.py`, imported into `web/startScan/models.py` so Django sees them in the `startScan` app.
- Asset kinds: exactly `root_domain`, `hostname`, `ip`, `cidr` (no `url`). Scope tiers: `owned_root`, `owned_host`, `co_brand`, `candidate`, `rejected`. States: `active`, `missing`, `stale`, `retired`.
- `Asset` uniqueness: `unique_together = ('project', 'kind', 'value')`.
- `is_active_scan_allowed` = `scope_tier in {owned_root, owned_host}` OR (`scope_tier == co_brand` AND `active_authorized`). Never true for `candidate`/`rejected`.
- The data migration must be **chunked** (`.iterator()` + `bulk_create`/`bulk_update`, chunk size 2000), **reversible** (reverse drops the new rows + column), and **idempotent** (a second forward run creates no duplicates — use get_or_create semantics or guard on existing).
- `make test` green after every task; `make manage ARGS="makemigrations --check --dry-run"` → "No changes detected" at the end of each schema-changing task. Docker via `DOCKER_HOST=unix:///var/run/docker.sock`. Never run `web/tests/test_scan.py`.
- TABS are NOT used in new files (4 spaces); `startScan/models.py` edits follow its existing style (it uses tabs).
- Commit identity TyrusRC (configured). No AI attribution in commits. Never bypass hooks; never commit `.env`.

## Review Focus

1. **A `Subdomain` name with mixed case / trailing dot / whitespace**: dedup must key on `normalize_host` so one host isn't split into two Assets — Task 4 tests case/dot normalization (`NormalizeTest`, `test_hostname_dedup_latest_state_and_dates`).
2. **A `Subdomain` whose `discovered_date` is NULL** (older rows): `first_seen`/`last_seen` aggregation must not crash or produce NULL `last_seen` — Task 4 `test_hostname_null_date_does_not_crash` (falls back to `now()`).
3. **A `Vulnerability` whose `subdomain` is NULL but `endpoint`/`target_domain` is set**: `asset` back-fill must use the fallback chain, not drop the row — Task 6 tests each fallback.
4. **Re-running the data migration** (idempotency): a second forward run must not double the Asset rows — Task 5 tests running the migration function twice.
5. **An `IpAddress.address` that is NULL/blank or a duplicate across subdomains**: ip-Asset creation must skip blanks and dedupe — Task 4 tests blank + duplicate addresses.

---

## File Structure

| File | Responsibility |
|---|---|
| `web/startScan/asset_models.py` (create) | `Tag`, `Asset`, `ScanRun`, `ScanJob` model definitions |
| `web/startScan/models.py` (modify) | `from startScan.asset_models import *`; add `asset` FK to `Vulnerability` |
| `web/startScan/migrations/0004_asset_models.py` (create) | schema: create Tag/Asset/ScanRun/ScanJob + `Vulnerability.asset` |
| `web/startScan/migrations/0005_migrate_to_assets.py` (create) | data: back-fill inventory from Domain/Subdomain/IpAddress + Vulnerability.asset |
| `web/startScan/inventory_migrate.py` (create) | the chunked, idempotent back-fill functions (imported by 0005 and unit-tested directly) |
| `web/tests/core/test_asset_models.py` (create) | model constraints, `is_active_scan_allowed`, lifecycle helper |
| `web/tests/core/test_inventory_migrate.py` (create) | dedup/normalization/idempotency/fallback of the back-fill functions |

---

### Task 1: Tag + Asset models

**Files:**
- Create: `web/startScan/asset_models.py`
- Modify: `web/startScan/models.py` (add `from startScan.asset_models import *` after the existing model imports/definitions it depends on — place it AFTER `Technology`, `IpAddress`, `Project` import usage; since asset_models imports those from startScan.models, import asset_models at the BOTTOM of models.py to avoid a circular import)
- Test: `web/tests/core/test_asset_models.py`

**Interfaces:**
- Produces: `Tag(name)`, `Asset` with fields/choices below and methods `is_active_scan_allowed` (property) and `mark_missing_or_seen(seen: bool)`. Later stages consume `Asset`, `Tag`.

- [ ] **Step 1: Write failing tests**

`web/tests/core/test_asset_models.py`:
```python
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from startScan.asset_models import Asset, Tag


def mk_project(slug='p'):
    return Project.objects.create(name=slug, slug=slug, insert_date=timezone.now())


class AssetModelTest(TestCase):
    def setUp(self):
        self.project = mk_project()

    def test_unique_per_project_kind_value(self):
        Asset.objects.create(project=self.project, kind='hostname', value='a.x.com')
        with self.assertRaises(IntegrityError):
            Asset.objects.create(project=self.project, kind='hostname', value='a.x.com')

    def test_same_value_different_kind_ok(self):
        Asset.objects.create(project=self.project, kind='hostname', value='x.com')
        Asset.objects.create(project=self.project, kind='root_domain', value='x.com')  # no raise

    def test_active_scan_allowed_by_tier(self):
        owned = Asset(project=self.project, kind='hostname', value='h', scope_tier='owned_host')
        root = Asset(project=self.project, kind='root_domain', value='r', scope_tier='owned_root')
        cand = Asset(project=self.project, kind='hostname', value='c', scope_tier='candidate')
        rej = Asset(project=self.project, kind='hostname', value='j', scope_tier='rejected')
        cob = Asset(project=self.project, kind='hostname', value='b', scope_tier='co_brand', active_authorized=False)
        cob_ok = Asset(project=self.project, kind='hostname', value='b2', scope_tier='co_brand', active_authorized=True)
        self.assertTrue(owned.is_active_scan_allowed)
        self.assertTrue(root.is_active_scan_allowed)
        self.assertFalse(cand.is_active_scan_allowed)
        self.assertFalse(rej.is_active_scan_allowed)
        self.assertFalse(cob.is_active_scan_allowed)
        self.assertTrue(cob_ok.is_active_scan_allowed)

    def test_lifecycle_missed_then_seen(self):
        a = Asset.objects.create(project=self.project, kind='hostname', value='h', state='active')
        for _ in range(3):
            a.mark_missing_or_seen(seen=False)
        self.assertEqual(a.state, 'missing')
        self.assertEqual(a.missed_count, 3)
        a.mark_missing_or_seen(seen=True)
        self.assertEqual(a.state, 'active')
        self.assertEqual(a.missed_count, 0)

    def test_missed_below_threshold_stays_active(self):
        a = Asset.objects.create(project=self.project, kind='hostname', value='h', state='active')
        a.mark_missing_or_seen(seen=False)
        a.mark_missing_or_seen(seen=False)
        self.assertEqual(a.state, 'active')
```

- [ ] **Step 2: Run to see it fail** — `make test` → ImportError for `startScan.asset_models`.

- [ ] **Step 3: Implement** `web/startScan/asset_models.py` (4-space):
```python
from django.contrib.postgres.fields import JSONField
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

from dashboard.models import Project
from startScan.models import IpAddress, Technology

ASSET_KINDS = [('root_domain', 'root_domain'), ('hostname', 'hostname'), ('ip', 'ip'), ('cidr', 'cidr')]
SCOPE_TIERS = [('owned_root', 'owned_root'), ('owned_host', 'owned_host'),
               ('co_brand', 'co_brand'), ('candidate', 'candidate'), ('rejected', 'rejected')]
ASSET_STATES = [('active', 'active'), ('missing', 'missing'), ('stale', 'stale'), ('retired', 'retired')]
MISSING_THRESHOLD = 3


class Tag(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name


class Asset(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    kind = models.CharField(max_length=20, choices=ASSET_KINDS)
    value = models.CharField(max_length=1000)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='children')

    scope_tier = models.CharField(max_length=20, choices=SCOPE_TIERS, default='candidate')
    active_authorized = models.BooleanField(default=False)
    state = models.CharField(max_length=20, choices=ASSET_STATES, default='active')
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    missed_count = models.IntegerField(default=0)

    sources = JSONField(default=list, blank=True)
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    decision_reason = models.TextField(blank=True, default='')

    # current observed state (hostname kind; nullable)
    http_status = models.IntegerField(null=True, blank=True)
    page_title = models.CharField(max_length=1000, null=True, blank=True)
    webserver = models.CharField(max_length=1000, null=True, blank=True)
    content_type = models.CharField(max_length=100, null=True, blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True)
    cname = models.CharField(max_length=5000, null=True, blank=True)
    is_cdn = models.BooleanField(default=False)
    cdn_name = models.CharField(max_length=200, null=True, blank=True)
    screenshot_path = models.CharField(max_length=1000, null=True, blank=True)
    technologies = models.ManyToManyField(Technology, blank=True, related_name='assets')
    ip_addresses = models.ManyToManyField(IpAddress, blank=True, related_name='assets')

    tags = models.ManyToManyField(Tag, blank=True, related_name='assets')
    cadence_tier = models.CharField(max_length=20, default='standard')
    request_headers = JSONField(null=True, blank=True)

    class Meta:
        unique_together = ('project', 'kind', 'value')
        indexes = [
            models.Index(fields=['project', 'kind'], name='asset_proj_kind_idx'),
            models.Index(fields=['project', 'scope_tier'], name='asset_proj_scope_idx'),
            models.Index(fields=['project', 'state'], name='asset_proj_state_idx'),
        ]

    def __str__(self):
        return f'{self.kind}:{self.value}'

    @property
    def is_active_scan_allowed(self):
        if self.scope_tier in ('owned_root', 'owned_host'):
            return True
        if self.scope_tier == 'co_brand' and self.active_authorized:
            return True
        return False

    def mark_missing_or_seen(self, seen):
        if seen:
            self.missed_count = 0
            self.last_seen = timezone.now()
            if self.state == 'missing':
                self.state = 'active'
        else:
            self.missed_count += 1
            if self.missed_count >= MISSING_THRESHOLD and self.state == 'active':
                self.state = 'missing'
        self.save(update_fields=['missed_count', 'last_seen', 'state'])
```
NOTE: Django 3.2 ships `django.contrib.postgres.fields.JSONField` (deprecated alias of `models.JSONField`); the repo already uses `JSONField` on `Domain.request_headers` — match whichever import that model uses (check `targetApp/models.py`; if it uses `models.JSONField`, use that instead to avoid the deprecation).
At the BOTTOM of `web/startScan/models.py` add: `from startScan.asset_models import *  # noqa: E402,F401,F403`

- [ ] **Step 4: Run tests** — `make test`; then `make manage ARGS="makemigrations --check --dry-run"` will now report changes (the new models) — that's expected; the migration is Task 3. For THIS task's green bar, the model tests pass.

- [ ] **Step 5: Commit**
```bash
git add web/startScan/asset_models.py web/startScan/models.py web/tests/core/test_asset_models.py
git commit -m "feat: add Asset and Tag models for the inventory"
```

---

### Task 2: ScanRun + ScanJob models

**Files:**
- Modify: `web/startScan/asset_models.py` (append)
- Test: `web/tests/core/test_asset_models.py` (append)

**Interfaces:**
- Consumes: `Asset`.
- Produces: `ScanRun(project, root_asset, profile, status, initiated_by, results_dir, start_scan_date, stop_scan_date, error_message)`; `ScanJob(run, asset, stage, status, started, finished, celery_id, output_path, error_message)`. Stage 2 consumes both.

- [ ] **Step 1: Write failing test** (append to test_asset_models.py):
```python
class ScanRunJobTest(TestCase):
    def setUp(self):
        from startScan.asset_models import ScanRun, ScanJob
        self.ScanRun, self.ScanJob = ScanRun, ScanJob
        self.project = mk_project('r')
        self.root = Asset.objects.create(project=self.project, kind='root_domain', value='x.com', scope_tier='owned_root')

    def test_run_and_job(self):
        run = self.ScanRun.objects.create(project=self.project, root_asset=self.root, profile='normal',
                                          start_scan_date=timezone.now())
        job = self.ScanJob.objects.create(run=run, asset=self.root, stage='discovery')
        self.assertEqual(job.run_id, run.id)
        self.assertEqual(run.jobs.count(), 1)
        self.assertEqual(job.stage, 'discovery')
```

- [ ] **Step 2: Run to fail** — ImportError for ScanRun.

- [ ] **Step 3: Implement** (append to asset_models.py):
```python
from limes.definitions import CELERY_TASK_STATUSES  # (-1..3 status ints, reused)

SCAN_STAGES = [(s, s) for s in ('discovery', 'resolve', 'ports', 'probe', 'crawl', 'dast', 'code')]


class ScanRun(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    root_asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='scan_runs')
    profile = models.CharField(max_length=20, default='normal')
    status = models.IntegerField(choices=CELERY_TASK_STATUSES, default=-1)
    initiated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    results_dir = models.CharField(max_length=200, blank=True, default='')
    start_scan_date = models.DateTimeField()
    stop_scan_date = models.DateTimeField(null=True, blank=True)
    error_message = models.CharField(max_length=300, null=True, blank=True)


class ScanJob(models.Model):
    run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name='jobs')
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='scan_jobs')
    stage = models.CharField(max_length=20, choices=SCAN_STAGES)
    status = models.IntegerField(choices=CELERY_TASK_STATUSES, default=-1)
    started = models.DateTimeField(null=True, blank=True)
    finished = models.DateTimeField(null=True, blank=True)
    celery_id = models.CharField(max_length=100, null=True, blank=True)
    output_path = models.CharField(max_length=300, null=True, blank=True)
    error_message = models.CharField(max_length=300, null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=['run', 'stage'], name='scanjob_run_stage_idx'),
                   models.Index(fields=['asset', 'stage'], name='scanjob_asset_stage_idx')]
```
Confirm `CELERY_TASK_STATUSES` exists in `limes/definitions.py` (it's used by `ScanHistory`); if the import name differs, match the existing `ScanHistory.scan_status` choices import.

- [ ] **Step 4: Run tests** — `make test` green.

- [ ] **Step 5: Commit**
```bash
git add web/startScan/asset_models.py web/tests/core/test_asset_models.py
git commit -m "feat: add ScanRun and ScanJob models"
```

---

### Task 3: Schema migration + Vulnerability.asset

**Files:**
- Modify: `web/startScan/models.py` (`Vulnerability`: add `asset` FK)
- Create: `web/startScan/migrations/0004_asset_models.py` (generated)

**Interfaces:**
- Produces: DB tables for Tag/Asset/ScanRun/ScanJob + `Vulnerability.asset` (nullable FK).

- [ ] **Step 1: Add the FK** — in `web/startScan/models.py` `Vulnerability` (TABS), add:
```python
	asset = models.ForeignKey('Asset', on_delete=models.SET_NULL, null=True, blank=True, related_name='vulnerabilities')
```

- [ ] **Step 2: Generate the migration**

Run: `make manage ARGS="makemigrations startScan --name asset_models"`
Expected: creates `0004_asset_models.py` with CreateModel for Tag/Asset/ScanRun/ScanJob + AddField Vulnerability.asset. Review it: dependency on `0003_phase0_indexes`, the unique_together + indexes present.

- [ ] **Step 3: Verify clean**

Run: `make manage ARGS="makemigrations --check --dry-run"`
Expected: `No changes detected`.

- [ ] **Step 4: Apply + model smoke test**

Run: `make test` (the harness applies migrations to the test DB; all model tests from Tasks 1-2 pass against the real schema).

- [ ] **Step 5: Commit**
```bash
git add web/startScan/models.py web/startScan/migrations/0004_asset_models.py
git commit -m "feat: schema migration for Asset/ScanRun/ScanJob + Vulnerability.asset"
```

---

### Task 4: Back-fill functions — domains, IPs, hostnames (dedup)

**Files:**
- Create: `web/startScan/inventory_migrate.py`
- Create: `web/tests/core/test_inventory_migrate.py`

**Interfaces:**
- Produces: `normalize_host(value: str) -> str`; `backfill_root_domains(apps) -> int`; `backfill_ip_assets(apps) -> int`; `backfill_hostname_assets(apps) -> int`. Each takes the migration `apps` registry (historical models) and returns the count created; each is idempotent. Task 5 consumes them; Task 6 adds vuln back-fill; the migration (Task 7? no — Task 5 wires them) calls them.

- [ ] **Step 1: Write failing tests**

`web/tests/core/test_inventory_migrate.py`:
```python
from django.apps import apps as django_apps
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from startScan import inventory_migrate as im
from startScan.asset_models import Asset
from startScan.models import IpAddress, ScanHistory, Subdomain
from scanEngine.models import EngineType
from targetApp.models import Domain


def seed(project, domain_name='x.com'):
    domain = Domain.objects.create(name=domain_name, project=project, insert_date=timezone.now())
    engine = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
    scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now())
    return domain, scan


class NormalizeTest(TestCase):
    def test_normalize(self):
        self.assertEqual(im.normalize_host('A.X.COM.'), 'a.x.com')
        self.assertEqual(im.normalize_host('  b.x.com '), 'b.x.com')


class BackfillTest(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain, self.scan = seed(self.project)

    def test_root_domain_backfill_idempotent(self):
        n1 = im.backfill_root_domains(django_apps)
        n2 = im.backfill_root_domains(django_apps)
        self.assertEqual(n1, 1)
        self.assertEqual(n2, 0)  # idempotent
        a = Asset.objects.get(kind='root_domain', value='x.com')
        self.assertEqual(a.scope_tier, 'owned_root')
        self.assertEqual(a.project_id, self.project.id)

    def test_hostname_dedup_latest_state_and_dates(self):
        early = timezone.now() - timezone.timedelta(days=5)
        late = timezone.now()
        Subdomain.objects.create(name='a.x.com', scan_history=self.scan, target_domain=self.domain,
                                 http_status=301, page_title='old', discovered_date=early)
        Subdomain.objects.create(name='A.X.COM', scan_history=self.scan, target_domain=self.domain,
                                 http_status=200, page_title='new', discovered_date=late)
        im.backfill_root_domains(django_apps)
        n = im.backfill_hostname_assets(django_apps)
        self.assertEqual(n, 1)  # deduped to one
        a = Asset.objects.get(kind='hostname', value='a.x.com')
        self.assertEqual(a.http_status, 200)  # latest wins
        self.assertEqual(a.page_title, 'new')
        self.assertEqual(a.scope_tier, 'owned_host')
        self.assertEqual(a.parent.value, 'x.com')
        self.assertEqual(a.first_seen, early)
        self.assertEqual(a.last_seen, late)

    def test_hostname_null_date_does_not_crash(self):
        Subdomain.objects.create(name='n.x.com', scan_history=self.scan, target_domain=self.domain,
                                 http_status=200, discovered_date=None)
        im.backfill_root_domains(django_apps)
        im.backfill_hostname_assets(django_apps)
        a = Asset.objects.get(kind='hostname', value='n.x.com')
        self.assertIsNotNone(a.last_seen)  # fell back, not NULL

    def test_ip_backfill_skips_blank_and_dedupes(self):
        IpAddress.objects.create(address='192.0.2.1')
        IpAddress.objects.create(address='192.0.2.1')  # dup
        IpAddress.objects.create(address='')  # blank
        IpAddress.objects.create(address=None)
        n = im.backfill_ip_assets(django_apps)
        self.assertEqual(n, 1)  # one unique non-blank
        self.assertTrue(Asset.objects.filter(kind='ip', value='192.0.2.1').exists())
```
NOTE: these tests call the backfill functions with the live `django_apps` registry (not the historical migration-state apps). The functions must therefore use `apps.get_model('startScan', 'Asset')` etc. so they work with BOTH the live registry (tests) and a migration's historical registry (Task 5). `Project`/`Domain` live in `dashboard`/`targetApp` apps — fetch them with the right app label.

- [ ] **Step 2: Run to fail** — ImportError for `inventory_migrate`.

- [ ] **Step 3: Implement** `web/startScan/inventory_migrate.py`:
```python
"""Back-fill the Asset inventory from the legacy scan-centric tables.
Functions take an `apps` registry (live or migration-historical) and are idempotent + chunked."""
from django.db.models import Max, Min
from django.utils import timezone

CHUNK = 2000


def normalize_host(value):
    return (value or '').strip().rstrip('.').lower()


def _models(apps):
    return {
        'Asset': apps.get_model('startScan', 'Asset'),
        'Subdomain': apps.get_model('startScan', 'Subdomain'),
        'IpAddress': apps.get_model('startScan', 'IpAddress'),
        'Domain': apps.get_model('targetApp', 'Domain'),
    }


def backfill_root_domains(apps):
    m = _models(apps)
    Asset, Domain = m['Asset'], m['Domain']
    created = 0
    for d in Domain.objects.all().iterator(chunk_size=CHUNK):
        value = normalize_host(d.name)
        if not value or d.project_id is None:
            continue
        _, was_created = Asset.objects.get_or_create(
            project_id=d.project_id, kind='root_domain', value=value,
            defaults={'scope_tier': 'owned_root', 'state': 'active',
                      'first_seen': d.insert_date or timezone.now(),
                      'last_seen': d.insert_date or timezone.now(),
                      'request_headers': getattr(d, 'request_headers', None)})
        created += int(was_created)
        cidr = getattr(d, 'ip_address_cidr', None)
        if cidr:
            Asset.objects.get_or_create(project_id=d.project_id, kind='cidr', value=cidr.strip(),
                                        defaults={'scope_tier': 'owned_root', 'state': 'active'})
    return created


def backfill_ip_assets(apps):
    m = _models(apps)
    Asset, IpAddress, Domain = m['Asset'], m['IpAddress'], m['Domain']
    # IPs have no project FK; attribute to the single project if unambiguous, else the first project.
    project_id = None
    first_domain = Domain.objects.exclude(project_id=None).first()
    if first_domain:
        project_id = first_domain.project_id
    if project_id is None:
        return 0
    seen, created = set(), 0
    for ip in IpAddress.objects.all().iterator(chunk_size=CHUNK):
        value = (ip.address or '').strip()
        if not value or value in seen:
            continue
        seen.add(value)
        _, was_created = Asset.objects.get_or_create(project_id=project_id, kind='ip', value=value,
                                                     defaults={'scope_tier': 'owned_host', 'state': 'active'})
        created += int(was_created)
    return created


def backfill_hostname_assets(apps):
    m = _models(apps)
    Asset, Subdomain = m['Asset'], m['Subdomain']
    # group subdomains by (project, normalized name); aggregate dates; latest row for state.
    groups = {}  # (project_id, value) -> {first, last, latest_row_id, latest_date}
    STATE_FIELDS = ['http_status', 'page_title', 'webserver', 'content_type', 'content_length',
                    'response_time', 'cname', 'is_cdn', 'cdn_name', 'screenshot_path']
    for s in Subdomain.objects.all().select_related('target_domain').iterator(chunk_size=CHUNK):
        if s.target_domain_id is None or s.target_domain.project_id is None:
            continue
        value = normalize_host(s.name)
        if not value:
            continue
        key = (s.target_domain.project_id, value)
        d = s.discovered_date
        g = groups.get(key)
        if g is None:
            groups[key] = {'first': d, 'last': d, 'row': s, 'date': d,
                           'root': normalize_host(s.target_domain.name)}
        else:
            if d is not None:
                g['first'] = d if g['first'] is None else min(g['first'], d)
                g['last'] = d if g['last'] is None else max(g['last'], d)
                if g['date'] is None or d >= g['date']:
                    g['date'], g['row'] = d, s
    created = 0
    for (project_id, value), g in groups.items():
        fallback = timezone.now()
        root = Asset.objects.filter(project_id=project_id, kind='root_domain', value=g['root']).first()
        defaults = {'scope_tier': 'owned_host', 'state': 'active',
                    'parent_id': root.id if root else None,
                    'first_seen': g['first'] or fallback, 'last_seen': g['last'] or fallback}
        for f in STATE_FIELDS:
            defaults[f] = getattr(g['row'], f, None)
        _, was_created = Asset.objects.get_or_create(
            project_id=project_id, kind='hostname', value=value, defaults=defaults)
        created += int(was_created)
    return created
```

- [ ] **Step 4: Run tests** — `make test` → the backfill tests pass.

- [ ] **Step 5: Commit**
```bash
git add web/startScan/inventory_migrate.py web/tests/core/test_inventory_migrate.py
git commit -m "feat: idempotent back-fill functions for root/ip/hostname assets"
```

---

### Task 5: Vulnerability.asset back-fill + wire the data migration

**Files:**
- Modify: `web/startScan/inventory_migrate.py` (add `backfill_vuln_assets`, `run_all`, `reverse_all`)
- Create: `web/startScan/migrations/0005_migrate_to_assets.py`
- Modify: `web/tests/core/test_inventory_migrate.py` (append vuln + idempotency tests)

**Interfaces:**
- Consumes: Task 4 functions.
- Produces: `backfill_vuln_assets(apps) -> int`; `run_all(apps)`; `reverse_all(apps)`.

- [ ] **Step 1: Write failing tests** (append):
```python
class VulnBackfillTest(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain, self.scan = seed(self.project)

    def test_vuln_asset_backfill_fallbacks(self):
        from startScan.models import EndPoint, Vulnerability
        sub = Subdomain.objects.create(name='a.x.com', scan_history=self.scan, target_domain=self.domain,
                                       http_status=200, discovered_date=timezone.now())
        v_sub = Vulnerability.objects.create(name='v1', severity=3, scan_history=self.scan,
                                             target_domain=self.domain, subdomain=sub, discovered_date=timezone.now())
        v_dom = Vulnerability.objects.create(name='v2', severity=1, scan_history=self.scan,
                                             target_domain=self.domain, discovered_date=timezone.now())
        im.run_all(django_apps)
        v_sub.refresh_from_db(); v_dom.refresh_from_db()
        self.assertEqual(v_sub.asset.kind, 'hostname')
        self.assertEqual(v_sub.asset.value, 'a.x.com')
        self.assertEqual(v_dom.asset.kind, 'root_domain')  # fallback to root

    def test_run_all_idempotent(self):
        Subdomain.objects.create(name='a.x.com', scan_history=self.scan, target_domain=self.domain,
                                 http_status=200, discovered_date=timezone.now())
        im.run_all(django_apps)
        count1 = Asset.objects.count()
        im.run_all(django_apps)
        self.assertEqual(Asset.objects.count(), count1)  # second run adds nothing
```

- [ ] **Step 2: Run to fail** — AttributeError `backfill_vuln_assets`/`run_all`.

- [ ] **Step 3: Implement** (append to inventory_migrate.py):
```python
def backfill_vuln_assets(apps):
    Asset = apps.get_model('startScan', 'Asset')
    Vulnerability = apps.get_model('startScan', 'Vulnerability')
    Subdomain = apps.get_model('startScan', 'Subdomain')
    updated = 0
    for v in Vulnerability.objects.filter(asset__isnull=True).select_related(
            'subdomain', 'endpoint', 'target_domain').iterator(chunk_size=CHUNK):
        project_id = v.target_domain.project_id if v.target_domain_id and v.target_domain.project_id else None
        value = kind = None
        if v.subdomain_id:
            value, kind = normalize_host(v.subdomain.name), 'hostname'
        elif v.endpoint_id and v.endpoint.subdomain_id:
            sub = Subdomain.objects.filter(id=v.endpoint.subdomain_id).first()
            if sub:
                value, kind = normalize_host(sub.name), 'hostname'
        if value is None and v.target_domain_id:
            value, kind = normalize_host(v.target_domain.name), 'root_domain'
        if value is None or project_id is None:
            continue
        asset = Asset.objects.filter(project_id=project_id, kind=kind, value=value).first()
        if asset:
            v.asset_id = asset.id
            v.save(update_fields=['asset'])
            updated += 1
    return updated


def run_all(apps):
    backfill_root_domains(apps)
    backfill_ip_assets(apps)
    backfill_hostname_assets(apps)
    backfill_vuln_assets(apps)


def reverse_all(apps):
    Asset = apps.get_model('startScan', 'Asset')
    Vulnerability = apps.get_model('startScan', 'Vulnerability')
    Vulnerability.objects.update(asset=None)
    Asset.objects.all().delete()
```

- [ ] **Step 4: Create the data migration** `web/startScan/migrations/0005_migrate_to_assets.py`:
```python
from django.db import migrations


def forward(apps, schema_editor):
    from startScan.inventory_migrate import run_all
    run_all(apps)


def backward(apps, schema_editor):
    from startScan.inventory_migrate import reverse_all
    reverse_all(apps)


class Migration(migrations.Migration):
    atomic = False
    dependencies = [('startScan', '0004_asset_models')]
    operations = [migrations.RunPython(forward, backward)]
```

- [ ] **Step 5: Run tests + migration check**

Run: `make test` then `make manage ARGS="makemigrations --check --dry-run"`
Expected: tests pass; `No changes detected`.

- [ ] **Step 6: Commit**
```bash
git add web/startScan/inventory_migrate.py web/startScan/migrations/0005_migrate_to_assets.py web/tests/core/test_inventory_migrate.py
git commit -m "feat: back-fill Vulnerability.asset and wire the reversible inventory data migration"
```

---

### Task 6: Migration validation on the benchmark seed

**Files:**
- Create: `docs/benchmarks/2026-10-asm2a-migration.md`

- [ ] **Step 1: Seed + migrate on the running stack**

```bash
export DOCKER_HOST=unix:///var/run/docker.sock
make up
make bench-seed            # 0A's seeder: ~50 domains / 200k subdomains / 1M endpoints / 50k vulns
```
Then run the data migration against the seeded DB (it ran at container start on an empty DB; re-run the back-fill explicitly to measure it on the seed):
```bash
make manage ARGS="shell -c \"import time; from django.apps import apps; from startScan.inventory_migrate import run_all; t=time.time(); run_all(apps); print('ran_all in', round(time.time()-t,1),'s')\""
```

- [ ] **Step 2: Assert correctness**
```bash
make manage ARGS="shell -c \"from startScan.asset_models import Asset; from startScan.models import Subdomain, Vulnerability; from django.db.models import Count; \
print('hostname assets', Asset.objects.filter(kind='hostname').count()); \
print('distinct subdomain names', Subdomain.objects.values('target_domain__project_id','name').distinct().count()); \
print('vulns total', Vulnerability.objects.count(), 'with asset', Vulnerability.objects.filter(asset__isnull=False).count()); \
print('root assets', Asset.objects.filter(kind='root_domain').count())\""
```
Expected: `hostname assets` ≈ `distinct subdomain names` (normalization may reduce slightly); most vulns have an asset; root assets == domain count.

- [ ] **Step 3: Idempotency + reverse on the seed**
```bash
make manage ARGS="shell -c \"from django.apps import apps; from startScan.inventory_migrate import run_all; from startScan.asset_models import Asset; n=Asset.objects.count(); run_all(apps); print('idempotent' if Asset.objects.count()==n else 'DUPLICATED')\""
make manage ARGS="migrate startScan 0004"   # reverse the data migration
make manage ARGS="shell -c \"from startScan.asset_models import Asset; print('after reverse assets', Asset.objects.count())\""   # expect 0
make manage ARGS="migrate startScan 0005"   # re-apply
```

- [ ] **Step 4: Record** `docs/benchmarks/2026-10-asm2a-migration.md` with commit hash, the counts, the `run_all` runtime on the seed, and the idempotency/reverse results. Stage 1 is done when the counts reconcile, the migration is idempotent + reversible on the seed, `make test` is green, and `makemigrations --check` is clean.

- [ ] **Step 5: Commit**
```bash
git add docs/benchmarks/2026-10-asm2a-migration.md
git commit -m "docs: record asm 2a stage-1 migration validation on the benchmark seed"
```
