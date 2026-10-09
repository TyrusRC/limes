# Sub-project 2a: Asset inventory + inventory-first data model

Status: design approved in brainstorming 2026-10-07; this spec awaits user review before planning.
Parent roadmap: `docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md` (sub-project 2, first slice).
Research basis: `reports/UpGuard replacement ASM design.md`.
Builds on: phase 0A (stability) + 0B (fixed pipeline), already merged. Platform: Django 3.2 + Celery 5.4 + PostgreSQL, branded Limes (internal package `limes`).

## Goal

Make assets first-class. Today `Subdomain`/`EndPoint` rows are created per scan (duplicated every run) and scans own the data. This slice introduces one canonical, deduplicated `Asset` inventory as the source of truth, restructures scanning into per-asset jobs (`ScanRun` + `ScanJob`), migrates the existing scan-centric data, and lets users manually add any asset kind. Later slices (2b/2c) add the attack-surface graph, intelligence providers, CT/cloud continuous monitoring, and scoring — **out of scope here**.

## Scope

In: the `Asset`, `ScanRun`, `ScanJob` models; the scope tiers + lifecycle; the migration from `Domain`/`Subdomain`/`EndPoint`/`IpAddress`/`Vulnerability`; manual asset add with validation; restructuring the 0B pipeline into run-level + per-asset jobs that write the inventory; the scope gate at job creation; a minimal inventory UI/API to list/add/confirm/reject assets.

Out (later slices): the node/edge graph and pivoting; FOFA/Shodan/Censys and other providers; certificate-transparency streaming and cloud DNS connectors; the continuous one-minute dispatcher + cadence-driven auto-scanning (2a keeps manual/triggered runs); the A–F score; typosquatting; vendor risk.

## Data model

### Asset (new, canonical, one row per unique asset per project)
- **Identity:** `kind` ∈ {root_domain, hostname, ip, cidr}; `value` (normalized; unique together with `project` and `kind`); `project` FK; `parent` FK (self, nullable — hostname→its root_domain, ip→nothing or a cidr). URLs are NOT assets — they remain `EndPoint` rows linked to a host Asset.
- **Scope & lifecycle:** `scope_tier` ∈ {owned_root, owned_host, co_brand, candidate, rejected}; `state` ∈ {active, missing, stale, retired}; `first_seen`, `last_seen` (DateTimeField); `missed_count` (int, for the 3-consecutive-miss active→missing rule).
- **Attribution/audit:** `sources` (JSONField: list of {source, evidence, confidence, seen_at}); `added_by` FK(User, null) + `decision_reason` (text) for manual add / confirm / reject.
- **Current observed state** (nullable; for hostname kind; overwritten each scan = last known, NOT per-scan history): `http_status`, `page_title`, `webserver`, `content_type`, `content_length`, `response_time`, `cname`, `is_cdn`, `cdn_name`, `screenshot_path`; M2M `technologies`, `ip_addresses` (reuse existing `Technology`/`IpAddress` models).
- **Management:** `tags` (M2M to a simple Tag model, incl. a crown-jewel tag); `cadence_tier` (CharField, default 'standard' — consumed by 2b's scheduler, stored now); `request_headers` (JSON, the per-asset scan identity, migrated from `Domain.request_headers` / override).
- **Scope guarantee:** a property `is_active_scan_allowed` = `scope_tier in {owned_root, owned_host}` or (`co_brand` and an explicit `active_authorized` bool). Co-brand's registrable domain is never enumerated; candidate/rejected are never actively scanned.

### ScanRun (new; generalizes ScanHistory as the invocation record)
`project` FK, `root_asset` FK (the asset the run targets; for a single-asset rescan it's that asset), `profile` (CharField: quick/normal/thorough/passive), `status` (reuse CELERY_TASK_STATUSES), `initiated_by` FK, `results_dir`, `start/stop` dates, `error_message`.

### ScanJob (new; generalizes the existing SubScan to any asset + stage)
`run` FK, `asset` FK, `stage` (CharField: discovery/resolve/ports/probe/crawl/dast/code), `status`, `started/finished`, `celery_id`, `output_path`, `error_message`. For run-level batched stages the `asset` is the run's root; for per-asset stages it's the specific host.

### Changes to existing models
- `Vulnerability`: add `asset` FK (null during transition); keep `subdomain`/`endpoint`/`target_domain` FKs for now.
- `Subdomain`, `EndPoint`, `ScanHistory`, `SubScan`: unchanged, kept **read-only** (the existing history UI keeps reading them). Not written by new scans. Retired in a later slice.

## Orchestration (per-asset, hybrid)

A `ScanRun` over a root Asset fans out, reusing 0B's blocking-free structure (Celery `chain`/`group`/`chord` with callbacks; NEVER in-task `.get()`/`.ready()` polling — the `test_no_joins` invariant must stay green):

1. **discovery** (run-level ScanJob on the root): amass v5 + subfinder → upsert `hostname` Assets (parent=root, scope=owned_host, source+evidence recorded). New candidates below the auto-confirm bar are created as `candidate` (manual confirm in 2a; auto-attribution graph is 2b).
2. **Scope gate:** for each host Asset, decide allowed stages from `scope_tier` (+ `active_authorized` for co-brand). Co-brand/candidate → passive only.
3. **Batched run-level stages** (take lists, efficient, one ScanJob each): resolve (dnsx) → ports (naabu + nmap on open ports) → probe (httpx) → each upserts the host Assets' current state.
4. **Per-asset stages** (one ScanJob per in-scope host Asset, so 2b can reschedule a single host): crawl+code-audit (katana+gau → mantis) and DAST (assay). Findings → `Vulnerability` with `asset` set.
5. **finalize** (run-level callback): set `ScanRun` status; for every in-scope asset, update `last_seen`=now, reset `missed_count`; for assets expected but not seen this run, `missed_count += 1` and transition active→missing at 3 consecutive misses. **2a implements only active↔missing**; the missing→stale→retired thresholds are time/cadence-based and belong to 2b's scheduler (the `state` field already has those values, unused until then). Finalize runs even on partial failure (link_error), like 0B's `report`.

The pipeline's `save_subdomain`/`save_endpoint`/`save_ip_address`/`save_vulnerability` helpers (now in `limes/tasks/persistence.py`) are rewired to **upsert the Asset inventory** (get-or-create by project+kind+value, update current-state fields, append to `sources`) instead of creating per-scan `Subdomain`/`EndPoint` rows. `EndPoint` rows for crawled URLs are still created but linked to the host Asset.

## Migration

One batched, reversible `RunPython` data migration (runs in the one-shot `migrate` service, which bypasses pgbouncer per 0A), processing large tables with `.iterator()` + `bulk_create`/`bulk_update` in chunks:
- `Domain` → `Asset(root_domain, scope=owned_root)`, carrying `request_headers`; `Domain.ip_address_cidr` (if set) → `Asset(cidr)`.
- `Subdomain` deduped by `(project, name)` → one `Asset(hostname)`; current-state fields taken from the row with the latest `discovered_date`; `first_seen`=min, `last_seen`=max; `parent`=root Asset; `scope=owned_host`; carry `technologies`/`ip_addresses` M2M.
- `IpAddress` deduped → `Asset(ip)`.
- `Vulnerability.asset` back-filled from `vuln.subdomain`→its host Asset (fallback `endpoint`→host, else `target_domain`→root).
- `ScanHistory`/`SubScan` NOT migrated (kept as history); new scans create `ScanRun`/`ScanJob`.
Reverse migration drops the new tables + the `Vulnerability.asset` column.

## Manual add

A form/API accepting one asset or a bulk paste/CSV. Per entry: punycode-normalize; validate kind (root_domain/hostname/ip/cidr); **reject private/reserved/loopback IP ranges and wildcards**; a manual add is `scope`=owned_* (or co_brand if the user marks it) and auto-confirmed with `added_by`+reason (audit). If a hostname falls under a registrable domain not in the owned-root set, warn and suggest the `co_brand` tier.

## UI/API (minimal for 2a)

- An **Assets** inventory page: filterable table (kind, scope_tier, state, tags), a side drawer showing an asset's current state + its `sources`/evidence + "why is this mine" (the parent chain) + Confirm/Reject for candidates + Rescan. Follows 0B-era patterns (Django templates). Full UpGuard-style polish is a later UI slice.
- DRF endpoints: list/filter assets, add asset(s), confirm/reject a candidate, trigger a `ScanRun` on an asset, read run/job status.
- The dashboard asset counts switch to the Asset inventory (replacing the per-scan Subdomain counts from 0A's `dashboard/stats.py`).

## Testing

- **Dedup:** two same-name `Subdomain` rows from different scans → one `Asset`, current state from the most recent, correct first/last_seen.
- **Scope gate:** a `co_brand` asset without `active_authorized` yields only passive `ScanJob`s; `candidate`/`rejected` yield none; `owned_host` yields the full set. A property test asserts `is_active_scan_allowed`.
- **Orchestration:** a `ScanRun` on a seeded root produces the expected `ScanJob` set; `blocking_tasks()` stays empty (no in-task join reintroduced); the finalize callback runs on partial failure.
- **Lifecycle:** an asset missed 3 consecutive runs → `missing`; seen again → `active`, `missed_count` reset.
- **Migration:** on the 0A benchmark seed (50 domains / ~200k subdomains / ~1M endpoints / 50k vulns): migrate → assert `Asset(hostname)` count == distinct subdomain names, every `Vulnerability.asset` set, no data loss, idempotent (second run no-ops), reverse drops cleanly. Measure runtime (must complete within the migrate one-shot's budget).
- **Manual add:** rejects `10.0.0.1`/`127.0.0.1`/`192.168.*`/wildcards; punycode-normalizes an IDN; warns on a host under an unowned registrable domain.
- `makemigrations --check` clean; full `make test` green.

## Risks

- Large data migration (hundreds of thousands of subdomains, millions of endpoints). Mitigation: chunked `.iterator()`/`bulk_*`, benchmark-seed test with a runtime budget, reversible.
- Rewiring the 0B `save_*` helpers to upsert Assets is the behavioral core — must not regress the fixed pipeline or the no-join/secret-redaction invariants. Covered by reusing the 0B test suite + new inventory tests.
- Per-asset DAST/code jobs multiply Celery job count vs 0B's batched stages; the 0A sized worker pool + acks_late handle it, but very large roots create many jobs. Batched cheap stages (resolve/ports/probe) keep this bounded; the 2b scheduler will pace it.
- Two sources of truth during transition (Asset vs read-only Subdomain/EndPoint). Mitigation: new scans write only Assets; old tables are read-only history; a later slice retires them.
