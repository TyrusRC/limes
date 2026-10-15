# ASM module — Slice A5b: Continuous monitoring

Status: design approved in brainstorming 2026-10-15; awaits user review of this file before planning.
Parent: Limes ASM platform. Builds on A5a (registry-verified auto-confirm, default on), `main` at `f36039c`.
Spec basis: `docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md` § "Inventory and cadence":
- "scan continuously without manual triggers";
- "A one-minute dispatcher picks due work from Postgres";
- cadence tiers crown jewel / standard / inactive;
- "Asset lifecycle: active → missing (3 consecutive successful-run misses) → stale → retired";
- "'Rescan now' exists on assets".

Platform: Django 3.2 + Celery 5.4 (django-celery-beat `DatabaseScheduler`) + PostgreSQL, internal package `limes`.

## Module context

ASM slices: A0–A3c ✓ · A5a ✓ · **A5b this slice** · A4 risk scoring.

Change alerts, digests and event notifications are roadmap sub-project 3 and are out of scope here.

## Goal

Owned roots are rediscovered on a schedule, with no one pressing Rescan. Assets that disappear age from `missing` to `stale` to `retired` instead of staying `missing` forever.

## Decisions taken in brainstorming

- **What gets scheduled.** Cadence is per owned root, and the scheduled unit is the existing per-root `asm` run: discovery, then passive intel (including A5a verification), then screenshots.
  - The roadmap's hourly or daily *probe* cadence needs per-host probe jobs, which don't exist. It is a later slice.
  - DAST and full scans stay manual, or on the existing scheduled-scan feature.
- **Tiers** (`Asset.cadence_tier` on the root asset):

  | Tier | Interval |
  |---|---|
  | `crown_jewel` | 24h |
  | `standard` (default) | 7 days |
  | `inactive` | 30 days |
  | `off` | never automatic; manual Rescan still works |

- **Aging:**
  - `missing` → `stale` when `last_seen` is older than 30 days;
  - `stale` → `retired` when older than 90 days;
  - any sighting brings the asset back to `active`.
- **No change alerts or event log** (that is sub-project 3).

## Scope

**In:**
- a shared "start an ASM scan for a root" function, which `RescanAsset` now uses;
- the dispatcher beat task;
- the aging beat task;
- the `cadence_tier` choices;
- a cadence API action;
- the cadence dropdown in the asset modal;
- the kill-switch setting.

**Out (later):**
- per-host probe and DAST cadence;
- fingerprint-change re-tests;
- aging roots, IPs or CIDRs (today only hostnames are counted as missed);
- change alerts and digests (sub-project 3);
- per-project scan windows or quiet hours.

## Design

### 1. Shared scan start (`limes/continuous.py`, new)

The body of `RescanAsset.post` after asset loading moves into:

`start_asm_scan(asset, engine_id=None, initiated_by_id=None, scan_type=LIVE_SCAN) -> (ok: bool, message: str)`

It keeps the current checks and messages unchanged:
- the asset must be a `root_domain` with `is_active_scan_allowed`;
- a `Domain` record must exist;
- engine resolution: the requested engine, else the domain's last engine, else the first default engine;
- `create_scan_object`, then `initiate_scan.apply_async` with `scan_mode='asm'`.

`RescanAsset.post` calls it with the request's engine and user. Its responses and messages are unchanged, so the existing rescan tests keep passing untouched.

### 2. Cadence (`startScan/asset_models.py`)

- `CADENCE_TIERS = ['crown_jewel', 'standard', 'inactive', 'off']`.
- `cadence_tier` gets `choices`, which needs a choices-only migration.
- `CADENCE_INTERVALS = {'crown_jewel': 24h, 'standard': 7d, 'inactive': 30d}`. `off` has no entry.

### 3. Dispatcher (`limes/continuous.py`, beat task `dispatch_due_scans`, every 60s)

1. If `settings.CONTINUOUS_SCANS` is false, return `{'dispatched': 0, 'reason': 'disabled'}`.
2. Count scans in progress: `ScanHistory.scan_status in (INITIATED_TASK, RUNNING_TASK)`. If there are `MAX_IN_FLIGHT = 2` or more, return without dispatching. Continuous scanning yields to whatever else is running, manual scans included.
   - `NOTE:` this is a global ceiling of 2 concurrent scans before automation waits. The upgrade path is a per-project or worker-capacity-aware budget.
3. Candidates are `Asset` rows with `kind='root_domain'`, `scope_tier='owned_root'`, and `cadence_tier` in `CADENCE_INTERVALS`. For each one:
   - Find the `Domain` (same project, `name=asset.value`).
   - Find the latest `ScanHistory` for that domain by `start_scan_date`, regardless of type, mode or outcome.
   - It is **due** when there is no such scan, or the latest start is older than the tier's interval, and no scan for that domain is `INITIATED` or `RUNNING`.

   `ScanHistory` is used rather than `ScanRun` because `create_scan_object` writes it synchronously, while `ScanRun` is only created once the Celery task starts. Checking `ScanRun` could double-dispatch on the next tick.

   Due-ness is measured from when the last run *started*, whatever its outcome, so a root whose scans keep failing is retried once per interval, never every minute. A manual full scan also counts as fresh: it includes discovery.
4. Dispatch at most `MAX_DISPATCH_PER_TICK = 1` due root. Pick the one never scanned first, else the oldest latest-start, tie-broken by asset `id`. Call `start_asm_scan(asset, scan_type=SCHEDULED_SCAN)` with `initiated_by_id=None`.
   - A `(False, message)` result is logged at info and counted as `skipped`. It never raises. The next due root is tried in the same tick, up to 5 attempts.
5. Return `{'dispatched': n, 'skipped': m}`.

All database work is plain queries. `NOTE:` the due scan loads every candidate root each minute, which is fine for hundreds of roots. The upgrade path is a single annotated query.

Setting: `CONTINUOUS_SCANS = env.bool('LIMES_CONTINUOUS_SCANS', default=True)`.

### 4. Aging (`limes/continuous.py`, beat task `age_assets`, hourly)

These are two bulk updates. They do not touch `missed_count`.

- `state='missing'` and `last_seen < now - 30d` → `stale`.
- `state='stale'` and `last_seen < now - 90d` → `retired`.

A null `last_seen` never ages. It returns `{'stale': n, 'retired': m}`.

`Asset.mark_missing_or_seen(seen=True)` now returns any of `missing`, `stale` or `retired` to `active`. Today only `missing` comes back.

### 5. Beat schedule (`limes/settings.py`)

- Add `'dispatch-due-scans': {'task': 'dispatch_due_scans', 'schedule': 60.0}` and `'age-assets': {'task': 'age_assets', 'schedule': 3600.0}`.
- Add `'limes.continuous'` to `CELERY_IMPORTS`.
- Add both tasks to `TASK_PLAN` in `limes/celery_routing.py` as `(ORCHESTRATE, 15 * MIN)`, matching `reap_stuck_scans`, so the dispatcher never waits behind scan work.

### 6. API and UI

- `AssetSerializer` exposes `cadence_tier` read-only.
- New `POST /api/action/asset/cadence/` (`SetAssetCadence`) with body `{asset_id, project, cadence_tier}`:
  - same permission as Rescan (`PERM_INITATE_SCANS_SUBSCANS`);
  - only for `kind='root_domain'`;
  - the tier must be in `CADENCE_TIERS`;
  - any other value returns `{'status': False, 'message': 'unknown cadence tier'}`.
- In the asset modal, root domains get a "Cadence" `<select>` whose four options use fixed labels, plus a Save button. All values go through `asset_esc`.

## Data flow

1. Beat, every minute, runs `dispatch_due_scans`.
2. It picks the most overdue owned root that has no scan in progress, provided fewer than 2 scans are running.
3. `start_asm_scan` creates the scan record and starts the existing `asm` run.
4. That run's discovery and passive intel upsert assets and mark them seen, and `finalize_lifecycle` counts misses.
5. Beat, every hour, runs `age_assets`: missing to stale, stale to retired.

## Testing

**Dispatcher:**
- a never-scanned root is due;
- a root scanned within its interval is not due, for each tier;
- `off` is never due;
- a scan in progress blocks that root;
- 2 scans in flight block all dispatching;
- one dispatch per tick, oldest first;
- a root whose last scan failed long ago is due, and one whose failed scan started recently is not;
- `candidate`, `co_brand` and `rejected` roots are never dispatched;
- a root with no `Domain` is skipped and the next one is tried;
- the kill switch returns `disabled`;
- dispatch passes `scan_type=SCHEDULED_SCAN` and `initiated_by_id=None`.

`initiate_scan.apply_async` is mocked.

**`start_asm_scan`:** the existing `RescanAsset` tests stay green unchanged. Add one test of the direct call with `SCHEDULED_SCAN`.

**Aging:**
- the thresholds at 29d versus 31d, and 89d versus 91d;
- `active` is never aged by time;
- a null `last_seen` never ages;
- a sighting returns `stale` and `retired` to `active`.

**API:**
- a valid tier saves;
- an unknown tier is rejected;
- a non-root asset is rejected;
- no permission → 403;
- the serializer exposes the field.

**UI:** drive the real modal. Change the cadence, reload, and confirm it persisted. Check that there are no console errors.

## Review focus

1. **Double dispatch.** Two beat ticks, or two beat processes, must not start the same root twice. The in-progress check uses the synchronously created `ScanHistory`. A second beat process is a deployment error, but the in-progress check still covers it once the first dispatch is written.
2. **First deploy with many roots.** Dispatches must stagger to one per minute while 2 or more scans run, never a burst.
3. **A failing root must not hot-loop.** Due-ness is measured from the last start, not the last success.
4. **A retired asset seen again must come back to `active`**, and aging must never touch `active` assets.
5. **The `off` tier and the kill switch must stop all automatic dispatch**, while manual Rescan still works.

## Risks

- **Load on upgrade.** Every existing owned root becomes due at once. The per-tick and in-flight caps spread the work out, but a large estate takes a while to cycle. That is accepted, and it is visible because the scans appear in scan history.
- **Third-party rate limits.** crt.sh and InternetDB see more traffic. Weekly is the default, and A3b's providers already back off and cache.
- **The global cap of 2 starves automation on a busy instance.** That is intentional: people come first. The upgrade path is a capacity-aware budget.
