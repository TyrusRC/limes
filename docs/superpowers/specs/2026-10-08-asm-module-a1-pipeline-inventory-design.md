# ASM module — Slice A1: ASM pipeline → inventory (scan-mode split)

Status: design drafted 2026-10-08; awaits user review before planning.
Parent: the Limes ASM platform. Builds on Stage 1 (asset inventory + models, merged `b81363f2`).
Spec basis: `docs/superpowers/specs/2026-10-07-asm-2a-asset-inventory-design.md` (orchestration + lifecycle sections), research report `reports/UpGuard replacement ASM design.md`.
Platform: Django 3.2 + Celery 5.4 + PostgreSQL, branded Limes (internal package `limes`/`startScan`).

## Module context (why this slice exists)

Limes splits into two independently-runnable modules whose results combine on the shared `Asset` inventory:

- **ASM module** (passive, low-noise, UpGuard-style, standalone): discovery → resolve → light HTTP probe → inventory + attack-surface mapping + risk score + continuous monitoring. No active exploitation.
- **Scanner module** (active, opt-in per asset, triggered separately): port scan (naabu+nmap) · crawl (katana/gau) · DAST (assay) · SAST (mantis, opengrep engine). Writes findings back onto assets. **Deferred — built after the ASM module.**

ASM slices in dependency order: **A0** inventory+models (done, Stage 1) · **A1** this slice · **A2** inventory UI/API + manual add · **A3** discovery depth (dnsx resolve, CT logs, passive DNS, FOFA/Shodan) + attack-surface graph · **A4** risk scoring · **A5** continuous monitoring. After A1+A2 the ASM inventory is populated by live scans and team-usable.

## Goal

A scan run in **ASM mode** executes only the passive ASM stages and writes the canonical `Asset` inventory as the source of truth, cleanly separated from the active Scanner stages, which are gated off. The run is recorded as a `ScanRun` + per-stage `ScanJob`s; the scope gate governs treatment of non-owned assets; the active↔missing lifecycle runs at finalize.

## Key fact from the current pipeline

`subdomain_discovery` (`web/limes/tasks/stages.py`) already runs the httpx probe **in-process** (`http_crawl(..., is_ran_from_subdomain_scan=True)`), producing `Subdomain` probe fields, `EndPoint`, `Technology` and `IpAddress` rows. So the ASM pipeline (discovery **+** probe) already exists inside one stage. A1 does **not** add new heavy stages; it (1) rewires those writes to also upsert the inventory, (2) adds a scan-mode split so ASM runs exclude the Scanner stages, (3) adds ScanRun/ScanJob bookkeeping, the scope gate, and the finalize lifecycle.

The current full chain (`web/limes/tasks/control.py`): `chain(subdomain_discovery, port_scan, fetch_url, group(vulnerability_scan, screenshot, code_audit))` + `report` callback. In ASM mode A1 runs `chain(subdomain_discovery, screenshot)` + `report`. `port_scan`/`fetch_url`/`vulnerability_scan`/`code_audit` are **Scanner** stages, excluded in ASM mode.

## Scope

**In:**
- A `mode` field on `ScanRun` (`asm` | `scanner` | `full`) and a scan-mode branch in `initiate_scan` that builds the ASM chain for `asm`.
- A focused write module `web/limes/tasks/inventory.py` holding the Asset/ScanRun/ScanJob upsert + scope-gate + lifecycle helpers (keeps `persistence.py` from growing).
- Rewire the passive writers to **dual-write** the inventory (old `Subdomain`/`EndPoint`/`IpAddress` rows stay as read-only history): `save_subdomain` → upsert `hostname` Asset (parent=root, scope `owned_host`, source+evidence, mark seen); `save_ip_address` → upsert `ip` Asset (project-scoped) + fix the `cdn`→`is_cdn` bug; the in-process probe inline writes (http_status/title/webserver/content_type/content_length/response_time/cname/is_cdn/cdn_name/technologies) → update the host Asset current-state + `technologies` M2M; screenshot_path → host Asset.
- `ScanRun` created per ASM run (root = upsert `root_domain` Asset from the domain, carrying `request_headers`); `ScanJob` per executed stage (via the `LimesTask` base, mapping task name → `ScanJob.stage`).
- Scope gate helper (`is_active_scan_allowed_for` + a filter) — in ASM mode all stages are passive so every tier is probed, but co_brand/candidate assets are created/kept at their tier and never promoted to owned by a passive sighting.
- Finalize (`report`): set `ScanRun.status`/`stop_scan_date`; for `hostname` Assets under the run's root not seen this run (`last_seen < run.start`), `mark_missing_or_seen(False)` (active→missing at 3 misses); runs even on partial failure (link_error), like today.

**Out (later slices):** a dedicated dnsx **resolve** stage and non-HTTP host inventory (A3); CT/passive-DNS/providers + attack-surface graph (A3); UI/API/manual-add (A2); scoring (A4); continuous cadence (A5); the Scanner module (ports/crawl/DAST/SAST) as a separate runnable module. In A1 the Scanner stages remain in the codebase and still run for `full`/`scanner` modes — A1 only adds the `asm` mode that omits them.

## Data model change

`ScanRun.mode = CharField(choices=[('asm','asm'),('scanner','scanner'),('full','full')], default='full')` + migration. `default='full'` preserves today's behavior; ASM runs set `mode='asm'`. No other model changes (Stage 1's `Asset`/`ScanRun`/`ScanJob` + `Vulnerability.asset` already exist).

## The write layer — `web/limes/tasks/inventory.py`

Live-ORM helpers (not `apps.get_model`; these run in app context, unlike the migration back-fill). Reuse `startScan.inventory_migrate.normalize_host` for value normalization so live and migrated keys match.

- `upsert_root_asset(project, name, request_headers=None) -> Asset` — get_or_create `(project,'root_domain',normalize_host(name))`, scope `owned_root`, carry `request_headers`, mark seen.
- `upsert_hostname_asset(project, name, parent=None, source='discovery', evidence='', scope_tier='owned_host') -> Asset|None` — get_or_create `(project,'hostname',normalize_host(name))`; set `parent` if unset; append provenance via `_append_source`; `mark_missing_or_seen(True)`. Returns None on empty/invalid name.
- `upsert_ip_asset(project, address, source='probe', evidence='') -> Asset|None` — get_or_create `(project,'ip',address)`, scope `owned_host`, append source, mark seen.
- `update_host_state(asset, **fields)` — overwrite the allowed current-state fields only (`http_status,page_title,webserver,content_type,content_length,response_time,cname,is_cdn,cdn_name,screenshot_path`), skipping None; `save(update_fields=...)`.
- `_append_source(asset, source, evidence, confidence=0.5)` — append `{source,evidence,confidence,seen_at}` to `asset.sources`, deduped by `(source,evidence)`.
- `is_active_scan_allowed_for(project, kind, value) -> bool` — look up the Asset and return its `is_active_scan_allowed`; missing asset → False (used by the Scanner module later; in A1 it backs the scope-gate test).
- `STAGE_BY_TASK = {'subdomain_discovery':'discovery','http_crawl':'probe','screenshot':'probe','port_scan':'ports','fetch_url':'crawl','vulnerability_scan':'dast','code_audit':'code'}` — task name → `ScanJob.stage`; tasks absent from the map create no ScanJob.
- `finalize_lifecycle(run)` — for `Asset.objects.filter(project=run.project, kind='hostname', parent=run.root_asset, state='active', last_seen__lt=run.start_scan_date).iterator()` call `mark_missing_or_seen(False)`. `# NOTE:` names the per-root scan ceiling; upgrade path is a bulk conditional update if roots grow very large.

The pipeline's `save_subdomain`/`save_ip_address` and the probe inline writes call these so the inventory is written alongside the existing rows. `project` is reached via `scan.domain.project` (ctx → `scan_history_id` → domain).

## Orchestration (A1)

`initiate_scan` resolves `mode` (from the engine config / a new `scan_mode` kwarg, default `full`), upserts the root Asset, creates `ScanRun(project, root_asset, mode, profile, initiated_by, results_dir, start_scan_date)`, and threads `ctx['scan_run_id']`. It then builds:
- `mode=='asm'`: `chain(subdomain_discovery.si(ctx), screenshot.si(ctx))` + `report` callback (same link_error/on_error wiring as today).
- else: the existing full chain, unchanged.

The `LimesTask` base (`web/limes/celery_custom_task.py`) already creates a `ScanActivity`; alongside it, when `ctx['scan_run_id']` is set and the task name is in `STAGE_BY_TASK`, create/finish a `ScanJob(run, asset=run.root_asset, stage, status, started/finished, celery_id, output_path)`. `report` sets `ScanRun.status` + `stop_scan_date` and calls `finalize_lifecycle(run)`.

**Invariants preserved:** the ASM chain is still `.si()` with no in-task `.get()`/`.ready()` — `blocking_tasks()==[]` / `test_no_joins` stays green. No new Celery task is added, so `TASK_PLAN`/`test_every_task_is_planned` is untouched. The probe keeps using the httpx `ScanIdentity` path and the existing secret-redaction; A1 adds no new secret surface.

## Testing

- **Mode split:** an `asm`-mode `initiate_scan` builds a workflow whose task set is exactly `{subdomain_discovery, screenshot, report}` — asserts `port_scan`/`fetch_url`/`vulnerability_scan`/`code_audit` are absent; a `full`-mode run is unchanged.
- **Discovery upsert:** two sightings of the same host (amass + httpx) in one run → one `hostname` Asset, `sources` appended not duplicated, `parent`=root, `last_seen` refreshed, `missed_count`=0.
- **Probe state:** a probed host → `update_host_state` sets http_status/title/webserver/cname/is_cdn/cdn_name/technologies on the Asset; `ip` Assets created and linked; the `cdn`→`is_cdn` fix persists the CDN flag.
- **Lifecycle:** a host present last run but not this run → `missing` after 3 consecutive misses; seen again → `active`, `missed_count` reset.
- **Scope gate:** a `co_brand` asset without `active_authorized` and a `candidate` asset → `is_active_scan_allowed_for` is False; a passive ASM run still records them at their tier and never promotes them to `owned_host`.
- **ScanRun/ScanJob:** an asm run creates one `ScanRun(mode='asm')` and `ScanJob`s for discovery+probe (not for the excluded stages); `report` sets `ScanRun.status` to success/failed.
- **Invariants:** `blocking_tasks()==[]`; `makemigrations --check` clean; existing `test_no_joins`/`test_celery_config` green; secret-redaction tests unaffected.

## Review focus (inputs the spec implies but a naive implementation breaks)

1. A host seen in a prior run but absent this run must transition active→missing (not be deleted, not stay active) — lifecycle at finalize.
2. The same hostname discovered twice in one run must dedupe to one Asset with appended (not duplicated) sources — idempotent upsert.
3. A `co_brand`/`candidate` asset must keep its tier under a passive sighting (never auto-promoted to `owned_host`) — scope gate.
4. A domain with no `project`, or a probe line with no resolvable host, must skip cleanly (no crash, no mis-attributed Asset) — null safety.
5. A `full`/`scanner` run must behave exactly as today (the Scanner stages still run) — the mode branch must not regress the existing pipeline.

## Risks

- Dual-write doubles write volume on discovery (one Asset upsert per subdomain alongside the existing row). Bounded by the same scan size as today; the upsert is a single get_or_create + at most one save. Measured against the 0A benchmark seed in the plan's final task.
- `finalize_lifecycle` scans active hostname Assets under the root; `.iterator()` + the NOTE'd ceiling keep it bounded; a bulk update is the upgrade path.
- Two sources of truth during transition (Asset vs read-only Subdomain/EndPoint). Mitigation: ASM runs write both; old tables are history; a later slice retires them.
