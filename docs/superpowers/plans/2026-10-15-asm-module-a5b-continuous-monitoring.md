# ASM module A5b — Continuous monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rediscover every owned root on its cadence without anyone pressing Rescan, and age assets that disappear from `missing` to `stale` to `retired`.

**Architecture:** A new module, `web/limes/continuous.py`, holds three pieces:
- `start_asm_scan`: the Rescan action's logic, moved here and shared by Rescan and the dispatcher.
- `dispatch_due_scans`: a beat task every 60s. It starts at most one overdue owned root per tick, and nothing while 2 or more scans run.
- `age_assets`: a beat task, hourly.

A cadence API action and a modal dropdown let a user set `crown_jewel`, `standard`, `inactive` or `off` per root.

**Tech Stack:** Django 3.2, Celery 5.4 with django-celery-beat, PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-10-15-asm-module-a5b-continuous-monitoring-design.md`

## Global Constraints

- **Intervals:** `crown_jewel` 24h, `standard` 7 days, `inactive` 30 days. `off` is never automatic, and manual Rescan always works.
- **Dispatcher limits:** `MAX_IN_FLIGHT = 2` scans of any kind (`ScanHistory.scan_status` INITIATED or RUNNING), `MAX_DISPATCH_PER_TICK = 1`, `MAX_ATTEMPTS_PER_TICK = 5`.
- **Due-ness:** measured from the latest `ScanHistory.start_scan_date` for the root's `Domain`, regardless of outcome. A root with a scan in progress is never due.
- **Dispatched scans:** `scan_type=SCHEDULED_SCAN`, `initiated_by_id=None`, `scan_mode='asm'`. Kill switch: `CONTINUOUS_SCANS = env.bool('LIMES_CONTINUOUS_SCANS', default=True)`.
- **Aging:** `missing` → `stale` when `last_seen` is older than 30 days; `stale` → `retired` when older than 90 days. A sighting returns `missing`, `stale` or `retired` to `active`.
- **Beat:** `dispatch_due_scans` every 60s and `age_assets` every 3600s, both routed `(ORCHESTRATE, 15 * MIN)`.
- **Style:**
  - tabs in `api/views.py` and `asset.js`;
  - 4 spaces in `limes/continuous.py`, `startScan/*`, `settings.py`, `celery_routing.py`, `api/serializers.py` and tests;
  - `api/urls.py` has CRLF line endings: preserve them (edit with a tool that keeps `\r\n`, e.g. Python with `newline=''`).
- **Tests:** `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <dotted.path>`; the controller may use an equivalent local runner. No test touches the network or starts a real scan (mock `initiate_scan.apply_async` and `create_scan_object` in `limes.continuous`).
- **Migrations:** generate with `makemigrations`; the final `makemigrations --check` must be clean.
- **Commits:** identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`, no AI attribution, no push without an explicit user yes.

## Review Focus

1. **Double dispatch across ticks.** The in-progress check must see the `ScanHistory` that `create_scan_object` writes synchronously. Test: Task 2 `test_next_tick_never_redispatches_the_same_root`.
2. **First deploy with many due roots** must stagger: one dispatch per tick, none while 2 scans run. Tests: Task 2 `test_dispatches_one_per_tick_as_scheduled_system_scan` and `test_waits_while_two_scans_run`.
3. **A failing root must not hot-loop:** due-ness counts from the last start. Test: Task 2 `test_failed_scan_counts_from_its_start`.
4. **A retired asset seen again returns to `active`**, and aging never touches `active`. Tests: Task 3 `test_sighting_revives_stale_and_retired` and `test_active_never_ages`.
5. **A malformed cadence value must be rejected without a server error.** Examples: a list, a missing value, an unknown string. Test: Task 4 `test_rejects_unknown_tier_and_non_roots`.

## Rulings made while planning

- **Interval location:** `CADENCE_INTERVALS` lives in `limes/continuous.py`, next to the behaviour. `startScan/asset_models.py` holds only the `CADENCE_TIERS` choices.
- **Rescan test patch targets:** `RescanAssetApiTest` changes from `api.views.*` to `limes.continuous.*`, because the code moved. Every assertion is unchanged.
- **Null `last_seen`:** the spec's "a null `last_seen` never ages" is moot. `Asset.last_seen` is NOT NULL, so there is no such test.
- **Roots without a `Domain`:** they are filtered out in `due_roots`, not attempted and skipped. Otherwise more than 5 of them would use up every tick's attempts and starve the roots that can be scanned.
- **Non-string cadence values:** these are rejected with an `isinstance(tier, str)` guard. A list value crashed the prototype with `unhashable type`.
- **Dry run:** the plan's code was dry-run in a throwaway worktree before review. The full core suite passed (427 tests), `makemigrations --check` was clean, and `node --check asset.js` passed.

---

### Task 1: Shared ASM scan start

**Files:**
- Create: `web/limes/continuous.py`
- Create: `web/tests/core/test_continuous.py`
- Modify: `web/api/views.py` (`RescanAsset`, imports)
- Modify: `web/tests/core/test_asset_api.py` (`RescanAssetApiTest` patch targets only)

**Interfaces:**
- Produces: `limes.continuous.start_asm_scan(asset, engine_id=None, initiated_by_id=None, scan_type=LIVE_SCAN) -> tuple[bool, str]`. The messages are exactly today's `RescanAsset` messages.

- [ ] **Step 1: Write the failing tests**

Create `web/tests/core/test_continuous.py`:

```python
from datetime import timedelta
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import continuous
from limes.definitions import FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SCHEDULED_SCAN, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import Asset, ScanHistory
from targetApp.models import Domain


class Base(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.engine = EngineType.objects.create(engine_name='default', yaml_configuration='{}', default_engine=True)
        for target in ('limes.continuous.initiate_scan.apply_async', 'limes.continuous.create_scan_object'):
            p = mock.patch(target)
            setattr(self, 'apply_async' if 'apply' in target else 'create', p.start())
            self.addCleanup(p.stop)
        self.create.side_effect = self.fake_create
        self.now = timezone.now()

    def fake_create(self, host_id, engine_id, initiated_by_id=None):
        # what create_scan_object writes synchronously: an INITIATED ScanHistory
        return ScanHistory.objects.create(domain_id=host_id, scan_type_id=engine_id, scan_status=INITIATED_TASK,
                                          start_scan_date=timezone.now()).id

    def root(self, value, tier='standard', scope='owned_root', domain=True):
        if domain:
            Domain.objects.create(project=self.p, name=value, insert_date=timezone.now())
        return Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier=scope, cadence_tier=tier)

    def scanned(self, value, ago, status=SUCCESS_TASK):
        ScanHistory.objects.create(domain=Domain.objects.get(name=value), scan_type=self.engine, scan_status=status,
                                   start_scan_date=self.now - ago)

    def due(self):
        return [a.value for a in continuous.due_roots(self.now)]

class StartAsmScanTest(Base):
    def test_scheduled_system_start(self):
        a = self.root('x.com')
        self.assertEqual(continuous.start_asm_scan(a, scan_type=SCHEDULED_SCAN), (True, 'ASM scan started for x.com'))
        kw = self.apply_async.call_args.kwargs['kwargs']
        self.assertEqual((kw['scan_type'], kw['initiated_by_id'], kw['scan_mode']), (SCHEDULED_SCAN, None, 'asm'))
```

In `web/tests/core/test_asset_api.py` (`RescanAssetApiTest.setUp`), change the two lines

```python
        # patch where the names are looked up (star-imported into api.views); nothing really runs
        for target in ('api.views.initiate_scan.apply_async', 'api.views.create_scan_object'):
```

to

```python
        # patch where the names are looked up (limes.continuous.start_asm_scan); nothing really runs
        for target in ('limes.continuous.initiate_scan.apply_async', 'limes.continuous.create_scan_object'):
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_continuous tests.core.test_asset_api`
Expected:
- `test_continuous` errors with `ImportError: cannot import name 'continuous' from 'limes'`;
- `RescanAssetApiTest` errors with `ModuleNotFoundError: No module named 'limes.continuous'`.

- [ ] **Step 3: Implement**

Create `web/limes/continuous.py`:

```python
"""Continuous monitoring (A5b): cadence-driven rediscovery of owned roots and asset aging."""
from limes.common_func import create_scan_object
from limes.definitions import LIVE_SCAN
from limes.tasks.control import initiate_scan
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain

def start_asm_scan(asset, engine_id=None, initiated_by_id=None, scan_type=LIVE_SCAN):
    """Start the per-root ASM run (discovery, passive intel, screenshots). Returns (ok, message)."""
    if asset.kind != 'root_domain' or not asset.is_active_scan_allowed:
        return False, 'Per-asset rescan is not supported yet (owned root domains only in A2).'
    domain = Domain.objects.filter(project=asset.project, name=asset.value).first()
    if not domain:
        return False, 'no Domain record for this root; add it as a target first.'
    # No engine given: reuse the target's last engine, else the first built-in one.
    if engine_id in (None, ''):
        last = ScanHistory.objects.filter(domain=domain, scan_type__isnull=False).order_by('-start_scan_date').first()
        engine = last.scan_type if last else EngineType.objects.filter(default_engine=True).order_by('id').first()
    else:
        try:
            engine = EngineType.objects.filter(id=int(engine_id)).first()
        except (TypeError, ValueError, OverflowError):
            engine = None
    if not engine:
        return False, 'unknown scan engine; pick an engine or set a default one.'
    scan_history_id = create_scan_object(host_id=domain.id, engine_id=engine.id, initiated_by_id=initiated_by_id)
    # Mirrors startScan.views.start_scan_ui, plus scan_mode='asm'.
    initiate_scan.apply_async(kwargs={
        'scan_history_id': scan_history_id,
        'domain_id': domain.id,
        'engine_id': engine.id,
        'scan_type': scan_type,
        'results_dir': '/usr/src/scan_results',
        'imported_subdomains': [],
        'out_of_scope_subdomains': [],
        'initiated_by_id': initiated_by_id,
        'scan_mode': 'asm',
    })
    return True, f'ASM scan started for {asset.value}'
```

In `web/api/views.py`, add after `from startScan.models import EndPoint`:

```python
from limes.continuous import start_asm_scan
```

Then replace the whole `RescanAsset` class with:

```python
class RescanAsset(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		asset = _load_asset(request)
		if not asset:
			return Response({'status': False, 'message': 'asset not found'})
		ok, message = start_asm_scan(asset, engine_id=request.data.get('engine_id'), initiated_by_id=request.user.id)
		return Response({'status': ok, 'message': message})
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_continuous tests.core.test_asset_api`
Expected: all OK. Every existing `RescanAssetApiTest` passes with unchanged assertions.

- [ ] **Step 5: Commit**

```bash
git add web/limes/continuous.py web/tests/core/test_continuous.py web/api/views.py web/tests/core/test_asset_api.py
git commit -m "Move the per-root ASM scan start out of the Rescan view

The continuous dispatcher needs to start the same run without a
request; Rescan keeps its behaviour and messages."
```

### Task 2: Cadence tiers and the dispatcher

**Files:**
- Modify: `web/limes/continuous.py`
- Modify: `web/startScan/asset_models.py` (`CADENCE_TIERS`, `cadence_tier` choices). Generate `makemigrations startScan -n asset_cadence_tier_choices`, which should be `0017`.
- Modify: `web/limes/settings.py` (`CONTINUOUS_SCANS`, `CELERY_IMPORTS`, `CELERY_BEAT_SCHEDULE`)
- Modify: `web/limes/celery_routing.py` (`TASK_PLAN`)
- Test: `web/tests/core/test_continuous.py`

**Interfaces:**
- Consumes: `start_asm_scan` from Task 1.
- Produces:
  - `limes.continuous.due_roots(now) -> list[Asset]`;
  - the `dispatch_due_scans` Celery task, returning `{'dispatched', 'skipped'}`, or `{'dispatched': 0, 'reason': 'disabled'}`;
  - `CADENCE_INTERVALS`;
  - `startScan.asset_models.CADENCE_TIERS`.

- [ ] **Step 1: Write the failing tests**

Append to `web/tests/core/test_continuous.py`:

```python
class DueRootsTest(Base):
    def test_never_scanned_root_is_due(self):
        self.root('new.com')
        self.assertEqual(self.due(), ['new.com'])

    def test_each_tier_waits_its_interval(self):
        for tier, interval in (('crown_jewel', timedelta(hours=24)), ('standard', timedelta(days=7)),
                               ('inactive', timedelta(days=30))):
            self.root(f'{tier}-fresh.com', tier)
            self.scanned(f'{tier}-fresh.com', interval - timedelta(minutes=5))
            self.root(f'{tier}-old.com', tier)
            self.scanned(f'{tier}-old.com', interval + timedelta(minutes=5))
        self.assertEqual(sorted(self.due()), ['crown_jewel-old.com', 'inactive-old.com', 'standard-old.com'])

    def test_off_is_never_due(self):
        self.root('off.com', 'off')
        self.assertEqual(self.due(), [])

    def test_scan_in_progress_blocks_root(self):
        for status, value in ((INITIATED_TASK, 'queued.com'), (RUNNING_TASK, 'running.com')):
            self.root(value)
            self.scanned(value, timedelta(days=60), status=status)
        self.assertEqual(self.due(), [])

    def test_failed_scan_counts_from_its_start(self):
        self.root('recent-fail.com')
        self.scanned('recent-fail.com', timedelta(hours=1), status=FAILED_TASK)
        self.root('old-fail.com')
        self.scanned('old-fail.com', timedelta(days=8), status=FAILED_TASK)
        self.assertEqual(self.due(), ['old-fail.com'])

    def test_only_owned_roots_with_a_domain(self):
        for scope in ('candidate', 'co_brand', 'rejected', 'dependency'):
            self.root(f'{scope}.com', scope=scope)
        self.root('nodomain.com', domain=False)
        self.assertEqual(self.due(), [])

    def test_never_scanned_first_then_most_overdue(self):
        self.root('a-old.com')
        self.scanned('a-old.com', timedelta(days=20))
        self.root('b-older.com')
        self.scanned('b-older.com', timedelta(days=40))
        self.root('c-never.com')
        self.assertEqual(self.due(), ['c-never.com', 'b-older.com', 'a-old.com'])

class DispatchTest(Base):
    def test_dispatches_one_per_tick_as_scheduled_system_scan(self):
        self.root('a.com')
        self.root('b.com')
        self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 1, 'skipped': 0})
        kw = self.apply_async.call_args.kwargs['kwargs']
        self.assertEqual((kw['scan_type'], kw['initiated_by_id'], kw['scan_mode']), (SCHEDULED_SCAN, None, 'asm'))

    def test_next_tick_never_redispatches_the_same_root(self):
        self.root('a.com')
        self.root('b.com')
        continuous.dispatch_due_scans()
        continuous.dispatch_due_scans()
        domains = [c.kwargs['kwargs']['domain_id'] for c in self.apply_async.call_args_list]
        self.assertEqual(len(domains), len(set(domains)))
        self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 0, 'skipped': 0})  # 2 in flight now

    def test_waits_while_two_scans_run(self):
        self.root('busy1.com')
        self.root('busy2.com')
        self.scanned('busy1.com', timedelta(minutes=1), status=RUNNING_TASK)
        self.scanned('busy2.com', timedelta(minutes=1), status=INITIATED_TASK)
        self.root('due.com')
        self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 0, 'skipped': 0})
        self.apply_async.assert_not_called()

    def test_unstartable_root_is_skipped_and_next_tried(self):
        self.root('a-bad.com')
        self.root('b-good.com')
        with mock.patch.object(continuous, 'start_asm_scan', side_effect=[(False, 'no engine'), (True, 'ok')]) as start:
            self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 1, 'skipped': 1})
        self.assertEqual([c.args[0].value for c in start.call_args_list], ['a-bad.com', 'b-good.com'])

    @override_settings(CONTINUOUS_SCANS=False)
    def test_kill_switch(self):
        self.root('a.com')
        self.assertEqual(continuous.dispatch_due_scans(), {'dispatched': 0, 'reason': 'disabled'})
        self.apply_async.assert_not_called()

    def test_off_tier_still_allows_manual_start(self):
        a = self.root('off.com', 'off')
        self.assertEqual(continuous.start_asm_scan(a, initiated_by_id=None, scan_type=SCHEDULED_SCAN),
                         (True, 'ASM scan started for off.com'))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_continuous`
Expected: `DueRootsTest` and `DispatchTest` error with `AttributeError: module 'limes.continuous' has no attribute 'due_roots'` (or `'dispatch_due_scans'`). `test_kill_switch` may error the same way.

- [ ] **Step 3: Implement**

In `web/limes/continuous.py`, replace everything above `def start_asm_scan` with:

```python
"""Continuous monitoring (A5b): cadence-driven rediscovery of owned roots and asset aging."""
import logging
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from limes.celery import app
from limes.common_func import create_scan_object
from limes.definitions import INITIATED_TASK, LIVE_SCAN, RUNNING_TASK, SCHEDULED_SCAN
from limes.tasks.control import initiate_scan
from scanEngine.models import EngineType
from startScan.models import Asset, ScanHistory
from targetApp.models import Domain

logger = logging.getLogger(__name__)

CADENCE_INTERVALS = {'crown_jewel': timedelta(hours=24), 'standard': timedelta(days=7),
                     'inactive': timedelta(days=30)}  # 'off' is never automatic
MAX_IN_FLIGHT = 2  # NOTE: global ceiling: automation waits while this many scans run; upgrade: capacity-aware budget
MAX_DISPATCH_PER_TICK = 1
MAX_ATTEMPTS_PER_TICK = 5
IN_PROGRESS = (INITIATED_TASK, RUNNING_TASK)
```

Then append to the end of the file:

```python
def due_roots(now):
    """Owned roots whose cadence has elapsed and that have no scan in progress, most overdue first
    (never-scanned first). Due-ness counts from the last scan's start, whatever its outcome, so a
    failing root is retried once per interval, never every tick.
    NOTE: loads every candidate root each call; fine for hundreds. Upgrade: one annotated query."""
    due = []
    for asset in Asset.objects.filter(kind='root_domain', scope_tier='owned_root',
                                      cadence_tier__in=list(CADENCE_INTERVALS)).order_by('id'):
        domain = Domain.objects.filter(project_id=asset.project_id, name=asset.value).first()
        if not domain:
            continue  # no scan target for this root: nothing to start
        scans = ScanHistory.objects.filter(domain=domain)
        if scans.filter(scan_status__in=IN_PROGRESS).exists():
            continue
        last = scans.order_by('-start_scan_date').values_list('start_scan_date', flat=True).first()
        if last is None or last <= now - CADENCE_INTERVALS[asset.cadence_tier]:
            due.append((last is not None, last, asset.id, asset))
    due.sort(key=lambda d: d[:3])
    return [d[3] for d in due]


@app.task(name='dispatch_due_scans', bind=False)
def dispatch_due_scans():
    if not settings.CONTINUOUS_SCANS:
        return {'dispatched': 0, 'reason': 'disabled'}
    if ScanHistory.objects.filter(scan_status__in=IN_PROGRESS).count() >= MAX_IN_FLIGHT:
        return {'dispatched': 0, 'skipped': 0}
    dispatched = skipped = 0
    for asset in due_roots(timezone.now())[:MAX_ATTEMPTS_PER_TICK]:
        ok, message = start_asm_scan(asset, initiated_by_id=None, scan_type=SCHEDULED_SCAN)
        if ok:
            dispatched += 1
            if dispatched >= MAX_DISPATCH_PER_TICK:
                break
        else:
            logger.info(f'Continuous scan skipped for {asset.value}: {message}')
            skipped += 1
    return {'dispatched': dispatched, 'skipped': skipped}
```

In `web/startScan/asset_models.py`, add after `MISSING_THRESHOLD = 3`:

```python
CADENCE_TIERS = [(t, t) for t in ('crown_jewel', 'standard', 'inactive', 'off')]  # intervals: limes.continuous
```

Then change the field to:

```python
    cadence_tier = models.CharField(max_length=20, choices=CADENCE_TIERS, default='standard')
```

Run `python3 manage.py makemigrations startScan -n asset_cadence_tier_choices`.

In `web/limes/settings.py`:
- After the `ATTRIBUTION_AUTO_CONFIRM = ...` line, add:

```python
# Rediscover owned roots on their cadence_tier (limes.continuous); false stops all automatic scans
CONTINUOUS_SCANS = env.bool('LIMES_CONTINUOUS_SCANS', default=True)
```

- Change `CELERY_IMPORTS` to `('limes.tasks', 'limes.reaper', 'limes.continuous')`.
- Add these to `CELERY_BEAT_SCHEDULE`, after `reap-stuck-scans`:

```python
    'dispatch-due-scans': {'task': 'dispatch_due_scans', 'schedule': 60.0},
    'age-assets': {'task': 'age_assets', 'schedule': 3600.0},
```

In `web/limes/celery_routing.py`, add this line to `TASK_PLAN`, after the `'report': ..., 'reap_stuck_scans': ...` line:

```python
    'dispatch_due_scans': (ORCHESTRATE, 15 * MIN), 'age_assets': (ORCHESTRATE, 15 * MIN),
```

The `age_assets` route and beat entry go in now. The task itself arrives in Task 3: beat simply finds no such task until then, and the routing table is static.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_continuous tests.core.test_asset_api`, then `python3 manage.py makemigrations --check --dry-run`.
Expected: all OK, then `No changes detected`.

- [ ] **Step 5: Commit**

```bash
git add web/limes/continuous.py web/startScan/asset_models.py web/startScan/migrations/0017_asset_cadence_tier_choices.py web/limes/settings.py web/limes/celery_routing.py web/tests/core/test_continuous.py
git commit -m "Rediscover owned roots on their cadence

A beat task starts the most overdue owned root once a minute, never
while two scans run or while that root is still scanning, so roots
are rescanned without anyone pressing Rescan."
```

### Task 3: Aging missing assets

**Files:**
- Modify: `web/limes/continuous.py` (append)
- Modify: `web/startScan/asset_models.py` (`mark_missing_or_seen`)
- Test: `web/tests/core/test_continuous.py`

**Interfaces:**
- Produces: the `age_assets` Celery task, returning `{'stale': int, 'retired': int}`.

- [ ] **Step 1: Write the failing tests**

Append to `web/tests/core/test_continuous.py`:

```python
class AgingTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.now = timezone.now()

    def asset(self, value, state, days):
        return Asset.objects.create(project=self.p, kind='hostname', value=value, scope_tier='owned_host', state=state,
                                    last_seen=self.now - timedelta(days=days))

    def state(self, a):
        a.refresh_from_db()
        return a.state

    def test_thresholds(self):
        m29, m31 = self.asset('m29', 'missing', 29), self.asset('m31', 'missing', 31)
        s89, s91 = self.asset('s89', 'stale', 89), self.asset('s91', 'stale', 91)
        self.assertEqual(continuous.age_assets(), {'stale': 1, 'retired': 1})
        self.assertEqual([self.state(a) for a in (m29, m31, s89, s91)], ['missing', 'stale', 'stale', 'retired'])

    def test_active_never_ages(self):
        active = self.asset('a', 'active', 400)
        continuous.age_assets()
        self.assertEqual(self.state(active), 'active')

    def test_sighting_revives_stale_and_retired(self):
        for state in ('missing', 'stale', 'retired'):
            a = self.asset(state, state, 200)
            a.mark_missing_or_seen(True)
            self.assertEqual(self.state(a), 'active', state)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_continuous.AgingTest`
Expected:
- `test_thresholds` and `test_active_never_ages` error with `AttributeError: ... no attribute 'age_assets'`;
- `test_sighting_revives_stale_and_retired` FAILs on `stale`.

- [ ] **Step 3: Implement**

Append to `web/limes/continuous.py`:

```python
STALE_AFTER = timedelta(days=30)
RETIRE_AFTER = timedelta(days=90)


@app.task(name='age_assets', bind=False)
def age_assets():
    """missing -> stale after STALE_AFTER unseen; stale -> retired after RETIRE_AFTER.
    A sighting brings an asset back to active (Asset.mark_missing_or_seen)."""
    now = timezone.now()
    stale = Asset.objects.filter(state='missing', last_seen__lt=now - STALE_AFTER).update(state='stale')
    retired = Asset.objects.filter(state='stale', last_seen__lt=now - RETIRE_AFTER).update(state='retired')
    return {'stale': stale, 'retired': retired}
```

In `web/startScan/asset_models.py` (`mark_missing_or_seen`), change `if self.state == 'missing':` to:

```python
            if self.state in ('missing', 'stale', 'retired'):
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_continuous tests.core.test_inventory_writes`
Expected: all OK.

- [ ] **Step 5: Commit**

```bash
git add web/limes/continuous.py web/startScan/asset_models.py web/tests/core/test_continuous.py
git commit -m "Age missing assets to stale and retired

Assets that stopped appearing stayed missing forever. After 30 days
unseen they become stale and after 90 retired; a sighting brings them
back to active."
```

### Task 4: Cadence API and modal control

**Files:**
- Modify: `web/api/views.py` (`SetAssetCadence`, import of `CADENCE_TIERS`)
- Modify: `web/api/urls.py` (route; **CRLF line endings**)
- Modify: `web/api/serializers.py` (`AssetSerializer.Meta.fields` gains `'cadence_tier'`)
- Modify: `web/static/custom/asset.js`
- Test: `web/tests/core/test_asset_api.py`

**Interfaces:**
- Consumes: `CADENCE_TIERS` from Task 2.
- Produces: `POST /api/action/asset/cadence/`, taking `{asset_id, project, cadence_tier}` and returning `{status, message}`.

- [ ] **Step 1: Write the failing tests**

Append to `web/tests/core/test_asset_api.py`:

```python
class AssetCadenceApiTest(TestCase):
    def setUp(self):
        from rolepermissions.roles import assign_role
        self.admin = User.objects.create_user('adm4', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud4', password='p')
        assign_role(self.auditor, 'auditor')
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.host = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')

    def _post(self, user, **body):
        body.setdefault('project', 'p1')
        c = APIClient()
        c.force_login(user)
        return c.post('/api/action/asset/cadence/', body, format='json')

    def tier(self, a):
        a.refresh_from_db()
        return a.cadence_tier

    def test_sets_a_known_tier(self):
        for tier in ('crown_jewel', 'inactive', 'off', 'standard'):
            r = self._post(self.admin, asset_id=self.root.id, cadence_tier=tier).json()
            self.assertEqual(r, {'status': True, 'message': f'cadence set to {tier}'})
            self.assertEqual(self.tier(self.root), tier)

    def test_rejects_unknown_tier_and_non_roots(self):
        for body in ({'asset_id': self.root.id, 'cadence_tier': 'hourly'}, {'asset_id': self.root.id},
                     {'asset_id': self.root.id, 'cadence_tier': ['off']}, {'asset_id': self.host.id, 'cadence_tier': 'off'}):
            self.assertFalse(self._post(self.admin, **body).json()['status'], body)
        self.assertEqual((self.tier(self.root), self.tier(self.host)), ('standard', 'standard'))

    def test_needs_scan_permission(self):
        r = self._post(self.auditor, asset_id=self.root.id, cadence_tier='off')
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.tier(self.root), 'standard')

    def test_list_exposes_cadence(self):
        c = APIClient()
        c.force_login(self.admin)
        r = c.get(f'/api/listDatatableAsset/{self.root.id}/', {'project': 'p1'})
        self.assertEqual(r.json()['cadence_tier'], 'standard')
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_asset_api.AssetCadenceApiTest`
Expected:
- the POST tests FAIL: the route does not exist, so the response is a 404, and `.json()` fails or the status is wrong;
- `test_list_exposes_cadence` errors with `KeyError: 'cadence_tier'`.

- [ ] **Step 3: Implement**

In `web/api/views.py`, add after `from startScan.models import EndPoint`:

```python
from startScan.asset_models import CADENCE_TIERS
```

Then add this class directly after `RescanAsset`:

```python
class SetAssetCadence(APIView):
	"""How often continuous monitoring rediscovers an owned root (limes.continuous)."""
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		asset = _load_asset(request)
		if not asset:
			return Response({'status': False, 'message': 'asset not found'})
		if asset.kind != 'root_domain':
			return Response({'status': False, 'message': 'cadence applies to root domains only'})
		tier = request.data.get('cadence_tier')
		if not isinstance(tier, str) or tier not in dict(CADENCE_TIERS):
			return Response({'status': False, 'message': 'unknown cadence tier'})
		Asset.objects.filter(pk=asset.pk).update(cadence_tier=tier)
		return Response({'status': True, 'message': f'cadence set to {tier}'})
```

In `web/api/urls.py`, add after the `action/asset/rescan/` line, keeping the file's `\r\n` line endings:

```python
    path('action/asset/cadence/', SetAssetCadence.as_view(), name='set_asset_cadence'),
```

In `web/api/serializers.py`, append `'cadence_tier'` to `AssetSerializer.Meta.fields`, after `'confidence_detail'`.

In `web/static/custom/asset.js`, add after the `rescan_asset` function:

```javascript
var ASSET_CADENCES = [['crown_jewel', 'Crown jewel (daily)'], ['standard', 'Standard (weekly)'],
	['inactive', 'Inactive (monthly)'], ['off', 'Off (manual only)']];

// How often continuous monitoring rediscovers an owned root.
function asset_cadence_html(a) {
	if (a.kind !== 'root_domain') return '';
	var opts = ASSET_CADENCES.map(function(c) {
		return '<option value="' + c[0] + '"' + (a.cadence_tier === c[0] ? ' selected' : '') + '>' + c[1] + '</option>';
	}).join('');
	return '<div class="d-flex align-items-center mb-2"><label class="form-label mb-0 me-2" for="asset_cadence"><b>Cadence</b></label>' +
		'<select id="asset_cadence" class="form-select form-select-sm w-auto me-2">' + opts + '</select>' +
		'<button class="btn btn-xs btn-soft-primary" onclick="set_asset_cadence(' + Number(a.id) + ')">Save</button></div>';
}

function set_asset_cadence(id) {
	var body = {asset_id: Number(id), project: asset_project(), cadence_tier: document.getElementById('asset_cadence').value};
	asset_post('/api/action/asset/cadence/', body).then(function(data) {
		asset_toast(data.message);
	}).catch(function() {
		asset_toast('Request failed.');
	});
}
```

Then, in `get_asset_modal`, add `asset_cadence_html(a) +` on its own line directly after the `(a.decision_reason ? ... : '') +` line.

- [ ] **Step 4: Run the tests to verify they pass, then verify in the real UI**

Run: `... python3 manage.py test tests.core.test_asset_api tests.core.test_continuous` and `node --check web/static/custom/asset.js`.
Expected: all OK, and the syntax check passes.

UI check:
1. Start the dev server and open a root domain's modal on the Assets page.
2. Choose "Off (manual only)", then Save.
3. Expected: the toast says "cadence set to off".
4. Close the modal and reopen it. Expected: "Off (manual only)" is selected.
5. A hostname's modal has no Cadence control, and the console has no errors.

- [ ] **Step 5: Commit**

```bash
git add web/api/views.py web/api/urls.py web/api/serializers.py web/static/custom/asset.js web/tests/core/test_asset_api.py
git commit -m "Let users set a root's cadence from the asset modal"
```
