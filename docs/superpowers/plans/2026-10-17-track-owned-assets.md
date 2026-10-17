# Track owned assets, ranges and ASNs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every asset a user adds or confirms keeps being watched. That covers root domains, hostnames, IPs, start–end ranges, CIDRs and ASNs. Ranges and ASNs are enumerated into child assets, safely and on a budget, and the Assets page shows what is monitored, when it was last checked and who found it.

**Architecture:**
- `api/asset_add.py` classifies entries using the PSL and parses start–end ranges and `AS<n>`.
- `limes/scan_target.py` (`ensure_scan_target`) gives every owned root a `Domain`, so the existing `dispatch_due_scans` scans it.
- `limes/owned_ranges.py` (`enumerate_ranges` beat task) refreshes ASN prefixes from RIPEstat and walks owned ranges per IP with PTR and InternetDB. The IP walk is behind an operator opt-in.
- `limes/monitor.py` (`monitor_assets` beat task) checks owned hostnames, IPs and owned_host roots that no scan covers: it resolves them, refreshes InternetDB, runs the risk checks and updates the lifecycle.
- All target contact goes through `limes/safe_fetch.py`. It resolves once, vets every answer and connects to the vetted IP.
- A new change kind `asset_new` announces hosts that appear.

**Tech Stack:** Django 3.2, DRF, Celery beat, PostgreSQL, django-redis cache, dnspython 2.6, requests/urllib3, jQuery and DataTables.

**Spec:** `docs/superpowers/specs/2026-10-17-track-owned-assets-design.md`

## Pre-flight rulings (coordinator, binding; they override the spec where they differ)

| # | Topic | Ruling | Owner |
|---|---|---|---|
| 1 | SSRF on a schedule / DNS rebinding | **Resolve and vet once:** each target host is resolved once (A+AAAA), and if **any** answer is reserved (`scope.is_reserved_ip`) the host is refused. **Pin the vetted IP:** the connection goes to the first vetted IP, with Host header and SNI set to the hostname. **Redirects:** only same-host redirects are followed, on the pinned IP, at most `collect.MAX_REDIRECTS` = 3; any other host is refused. **Refusals:** a refused host is recorded as skipped and never contacted. The existing fetchers re-resolve (`requests.get(url)` and `socket.create_connection((host, 443))` in `checks/collect.py`), so a new shared `limes/safe_fetch.py` is required. | Task 5 |
| 2 | InternetDB volume and terms | **Opt-in:** IP enumeration of ranges and ASNs is gated by `LIMES_RANGE_ENUMERATION`, default **off**. **Refresh:** ranges and ASNs refresh weekly (`standard`) by default. **Caps:** per-entry cap of 4,096 addresses, applied to the total after a start–end range is summarised; per-project cap `LIMES_RANGE_ADDRESS_CAP`, default 4,096, hard max 65,536. **Daily budgets** per instance, spread over 60 s ticks: `LIMES_INTERNETDB_DAILY_BUDGET` 5,000 and `LIMES_PTR_DAILY_BUDGET` 10,000. RIPEstat is limited to 1 ASN refresh per tick. **Passes:** an unfinished pass resumes from its cursor and never restarts. **Published terms:** the InternetDB terms are only partly published (see Global Constraints), so the opt-in note says so. | Tasks 1, 3, 4 |
| 3 | `Domain.name` is globally unique (`targetApp/models.py:149`) | If the `Domain` is in the same project, link it. If it is in another project (or has a null project), create nothing and return a **generic** warning. Limes has no per-project membership, so naming the other project could leak once an ACL exists. The root is then light-monitored as a host. | Task 2 |
| 4 | `asset_new` | Add the kind to `events.KINDS`, its label `'New asset'` in `dashboard/stats.py` `CHANGE_LABELS` (pinned by `test_every_change_kind_has_a_label`), an icon branch in `dashboard/index.html`, and the immediacy rule. The digest only uses titles, so it needs no change. | Task 3 |
| 5 | Scan burst after linking existing roots | Keep `MAX_IN_FLIGHT = 2` and `MAX_DISPATCH_PER_TICK = 1`. Say in the migration comment and the deploy notes that the first ticks scan every root that was previously unlinked. | Tasks 2, 6 |
| 6 | Existing PSL misclassifications | A management command reclassifies `hostname` rows whose value is registrable (`example.co.uk`). It is idempotent, logs each change and is tested. | Task 2 |

## Global Constraints

- **Django and style:**
  - Django 3.2; no new dependencies.
  - 4 spaces in `limes/*.py`, `startScan/*`, `api/asset_add.py`, `api/serializers.py` and tests.
  - Tabs in `api/views.py`, `asset.js`, `targetApp/*` and template script blocks.
  - `api/urls.py` is CRLF.
- **Tests:**
  - Run with `LIMES_DB=<name> LIMES_SRC=/home/kali/project/trc/limes-ui /tmp/claude-1000/-home-kali-project-trc-limes/1272ac93-25ff-41d2-a96c-5b1ecc4bf767/scratchpad/dj.sh test <dotted.path>`.
  - No network: every outbound function takes an injectable `get=`, `resolve=`, `session_factory=` or `create_connection=`, like the `Fake` in `tests/core/test_intel_run.py`.
- **Commits:**
  - Identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`.
  - No AI attribution of any kind, no `--no-verify`, no push.
- **Escaping:** asset values, PTR and InternetDB names, source evidence, reasons and refusal messages are untrusted. Render them through `asset_esc` or `textContent`, never `innerHTML` with unescaped data.
- **NOTE comments:** every deliberate ceiling gets a `NOTE:` naming the ceiling and the upgrade path. That covers caps, budgets, per-tick limits, overlap double counting and the limiter's clock assumption.
- **Kinds and values:**
  - `ASSET_KINDS` gains `('asn', 'asn')`, stored as `AS<number>`.
  - Ranges are `cidr` rows, one per covering CIDR (`ipaddress.summarize_address_range`).
- **Sources** use the existing dict shape via `inventory._append_source(asset, source, evidence)`:
  - manual adds: `source='manual'`, evidence = reason or `'added by <username>'`;
  - ASN prefixes: `source='asn'`, evidence `'AS12345'`;
  - range children: `source='cidr'`, evidence `'<range>'` (PTR names: `'ptr:<ip> in <range>'`).

  The spec's `'asn:AS12345'` strings map onto this shape.
- **Limits:**
  - `owned_ranges.MAX_ENTRY_ADDRESSES = 4096`;
  - `settings.RANGE_ADDRESS_CAP = min(env int LIMES_RANGE_ADDRESS_CAP default 4096, 65536)`;
  - an ASN is refused when its public prefixes total more than the project cap still free.

  Refusal messages give the reason and what to add instead, e.g. "AS64500 announces 131072 addresses, over this project's 4096-address cap: add the specific ranges you own instead".
- **Settings** (`limes/settings.py`, next to `CONTINUOUS_SCANS`):
  - `RANGE_ENUMERATION = env.bool('LIMES_RANGE_ENUMERATION', default=False)`;
  - `RANGE_ADDRESS_CAP`;
  - `INTERNETDB_DAILY_BUDGET = env.int(..., default=5000)`;
  - `PTR_DAILY_BUDGET = env.int(..., default=10000)`.
- **InternetDB terms (cite in the opt-in NOTE):**
  - internetdb.shodan.io says "It's free for non-commercial use!" and "If you're using the InternetDB API to make money then you need an enterprise license."
  - blog.shodan.io/introducing-the-internetdb-api says "you can use it at a company but you can't use it to build commercial products that you charge money for", and "Much higher rate limit" with no number.
  - book.shodan.io/developer-apis/internetdb says "a rate limit that allows bursts of up to 10,000 requests per second" and "updated weekly at midnight UTC".
  - No full ToS page for InternetDB was found. The 1 req/s figure is Limes's own throttle (`intel/http.py` `MIN_INTERVAL`), not a published limit.
  - The note says that commercial redistribution needs an enterprise license, and that the upgrade path is a paid key or Limes's own scanner.
- **Celery:**
  - `enumerate_ranges` and `monitor_assets` are routed `(ORCHESTRATE, 15 * MIN)` in `celery_routing.TASK_PLAN`.
  - Beat runs each every 60.0 s with `'options': {'expires': 55}`, next to `dispatch-due-scans`.
  - Both modules go in `CELERY_IMPORTS`.
  - Each holds its own advisory lock: `RANGE_LOCK = 0x4C494D46` and `MONITOR_LOCK = 0x4C494D47`.
  - Both honor `settings.CONTINUOUS_SCANS`.
- **Monitoring scope:** only `scope_tier in ('owned_root', 'owned_host')`, `state != 'retired'` and `cadence_tier != 'off'`. Tier and cadence are re-read immediately before acting on each asset.

## Review Focus

1. **Too large is refused.** That covers a /19, a start–end range of 4,097 addresses, a v6 /116+1 range, an existing oversized `cidr` row at enumeration time, and an ASN over the project cap. Each gives a reason and never partially enumerates. Tasks 1 and 4: `test_size_refusals`, `test_existing_oversized_range_refused`, `test_asn_over_cap_refused`.
2. **Reserved space inside public input is never touched.** That covers a range straddling 192.0.2.0/24, a reserved ASN prefix, and a host whose second A record is 10.0.0.1. Tasks 1, 4 and 5: `test_range_touching_reserved_refused`, `test_reserved_prefix_dropped`, `test_any_private_answer_refused`.
3. **A PTR or InternetDB name outside an owned root** becomes a `candidate` root and is never owned. That includes CDN and shared-hosting names. Task 4: `test_outside_names_stay_candidates`.
4. **A stopped or rejected asset is untouched**, even when it is stopped mid-tick, and a concurrent tick does nothing. Tasks 4 and 5: `test_stopped_or_rejected_untouched`, `test_concurrent_tick_is_locked`.
5. **Every typed entry is counted** as added, existing or skipped with a reason. A range splitting into 4 CIDRs counts each CIDR, and `<script>` in a source or reason renders as text. Task 1 `test_every_entry_accounted`; Task 6 real-UI check.

---

### Task 1: Entry parsing: PSL roots, start–end ranges, ASNs, size caps, `asn` kind

**Files:**
- Modify: `web/startScan/asset_models.py:9` (`ASSET_KINDS` + `asn`), then `makemigrations startScan -n asset_kind_asn`
- Modify: `web/api/asset_add.py`
- Create: `web/limes/owned_ranges.py` (constants and `range_addresses` only; Task 4 extends it)
- Modify: `web/limes/settings.py` (the four settings above)
- Modify: `web/api/views.py` `AddAssets` (multi-value results, the project cap, the `manual` source)
- Test: `web/tests/core/test_asset_add.py`, `web/tests/core/test_asset_api.py` (`AddAssetsApiTest`)

**Interfaces:**
- Produces:
  - `classify_asset_entry(raw) -> {'kind', 'value', 'values': list[str], 'error', 'warning'}`. `values` is `[value]`, except for a start–end range, where it lists the covering CIDRs and `value` is the first one. All current keys and behaviour are kept.
  - `owned_ranges.MAX_ENTRY_ADDRESSES = 4096`.
  - `owned_ranges.addresses(value: str) -> int`.
  - `owned_ranges.range_addresses(project, exclude_parent=None) -> int` sums the owned non-retired `cidr` rows. `exclude_parent` leaves out one ASN's children. `NOTE:` overlapping ranges are counted twice (conservative); the upgrade is to collapse with `ipaddress.collapse_addresses`.
  - `AddAssets` appends `'manual'` to `sources`.

- [ ] **Step 1: Write the failing tests:**
  - `test_psl_roots`:
    - `example.co.uk` → `root_domain`;
    - `www.example.co.uk` → `hostname`;
    - `www.example.com` → `hostname`;
    - `foo.github.io` → `root_domain` (private suffix);
    - `co.uk` is still an error.
  - `test_start_end_range`:
    - `8.8.8.0-8.8.8.255` → kind `cidr`, `values == ['8.8.8.0/24']`;
    - `8.8.8.1-8.8.8.6` gives exactly `['8.8.8.1/32', '8.8.8.2/31', '8.8.8.4/31', '8.8.8.6/32']`;
    - reversed bounds, mixed v4/v6, and `a-b.example.com` (a host, not a range) behave as expected.
  - `test_asn_entry`:
    - `AS12345`, `as12345` and `AS 12345` → (`asn`, `AS12345`);
    - bare `12345` → error mentioning `AS12345`;
    - `AS0`, `AS23456`, `AS64512`, `AS4200000000` and `AS4294967296` are errors (reserved or private).
  - `test_size_refusals`:
    - `8.8.0.0/19` is an error naming 8192 > 4096;
    - `8.8.0.0-8.8.16.0` (4,097 addresses) is an error;
    - `8.8.0.0/20` is ok;
    - a v6 range of 4,097 addresses is an error.
  - `test_range_touching_reserved_refused`: `192.0.1.0-192.0.2.255` is an error; nothing is partially accepted.
  - `AddAssetsApiTest.test_every_entry_accounted`:
    - the text `8.8.8.1-8.8.8.6\nexample.co.uk\nAS12345\n12345\n8.8.8.2/31` gives `added == 6` (4 CIDRs + root + ASN), `skipped == 1` and `existing == 1`;
    - `added + existing + skipped` equals the number of values;
    - each skipped entry has a warning.
  - `test_project_range_cap`: with `RANGE_ADDRESS_CAP=4096` and an existing owned /21, adding a /20 is skipped with a warning naming the cap and the current use. The cap counts across entries in the same request.
  - `test_manual_source_recorded`: a new asset has `sources[0]['source'] == 'manual'`.
- [ ] **Step 2: Run them.** `... test tests.core.test_asset_add tests.core.test_asset_api` fails.
- [ ] **Step 3: Implement:**
  - root = `domains.registrable(value) == value`; drop the label-count heuristic and its NOTE;
  - a range is exactly two `scope.parse_ip` values around one `-`;
  - an ASN matches `^AS\s?(\d{1,10})$` (case-insensitive) and must be in 1..4294967294, excluding 23456, 64496–131071 and 4200000000+;
  - `AddAssets` loops over `c['values']`, checks the project cap with a running total, and keeps its existing per-value logic.
- [ ] **Step 4: Run** the two modules plus `makemigrations --check --dry-run`. Expected: OK, then `No changes detected`.
- [ ] **Step 5: Commit** "Classify roots by public suffix and accept start-end ranges and ASNs".

### Task 2: Owned roots get a scan target

**Files:**
- Create: `web/limes/scan_target.py`
- Modify:
  - `web/api/views.py`: `AddAssets` calls it after its `transaction.atomic()` block for each new or promoted owned root and adds the warnings; `ConfirmAsset` calls it after `save()` and returns the warning in `message`.
  - `web/limes/tasks/attribution.py` `apply_decisions`: when `done` and the kind is `root_domain`, call it.
- Create:
  - `web/startScan/migrations/0025_link_owned_roots.py`: RunPython with `apps.get_model`, depending on 0024 and the latest `targetApp` migration;
  - `web/startScan/management/commands/reclassify_roots.py`.
- Test: `web/tests/core/test_scan_target.py`; update `test_asset_api.py:360 test_no_domain_record` setup if it adds via the API.

**Interfaces:**
- Produces:
  - `ensure_scan_target(asset) -> tuple[Domain | None, str | None]`. It returns `(None, None)` unless `kind == 'root_domain' and scope_tier == 'owned_root'`, and links a same-project `Domain`.
  - It creates `Domain(name=asset.value, project=asset.project, insert_date=now)`, catches `IntegrityError` and re-reads.
  - When the name belongs to another project or to none, it returns `(None, OTHER_PROJECT_MSG)`.
  - `OTHER_PROJECT_MSG = '{value} is already a scan target in another project; add it there or remove it there first. It is monitored as a host here meanwhile.'`
  - `scan_target.has_scan_target(asset) -> bool`, used by Task 5.
  - `manage.py reclassify_roots` converts `hostname` → `root_domain` when `registrable(value) == value`, no `root_domain` row with the same (project, value) exists, and (`added_by_id` is set or `parent_id` is null).
  - The command logs one line per change or skip, and calls `ensure_scan_target` for `owned_root` rows. Re-running it changes nothing.

- [ ] **Step 1: Write the failing tests** (`ScanTargetTest`, `ReclassifyTest`):
  - `test_creates_and_is_idempotent`: two calls give the same `Domain`, `Domain.objects.count() == 1`, and `continuous.due_roots(now)` now contains the root.
  - `test_links_existing_same_project`.
  - `test_other_project_not_created`:
    - the `Domain` exists in project B;
    - adding from A gives `(None, msg)`;
    - the message does not contain B's name or slug;
    - nothing is created.
  - `test_non_roots_ignored`: a hostname, or a root at `owned_host`, gives `(None, None)`.
  - `test_wired_paths`:
    - `POST /api/add/assets/` with tier `owned_root` creates a `Domain`, and the other-project warning appears in `warnings`;
    - `ConfirmAsset` to `owned_root` creates one;
    - `apply_decisions` auto-confirming a root creates one, while a lost race (`done == 0`) creates none.
  - `test_link_migration_function`: call the migration's function with `django.apps.apps` and check that an unlinked owned root gains a `Domain`, while a name owned elsewhere is skipped.
  - `test_reclassify_roots`:
    - `example.co.uk` (a hostname with `added_by`) becomes a root;
    - `www.example.com` stays;
    - a hostname with a conflicting existing root row stays and is logged;
    - a second run changes 0;
    - an `owned_root` row gets a `Domain`.
- [ ] **Step 2: Run them.** `... test tests.core.test_scan_target` fails with an ImportError.
- [ ] **Step 3: Implement.** The migration comment says: "First dispatcher ticks after deploy scan every previously unlinked owned root, throttled by MAX_IN_FLIGHT=2 / MAX_DISPATCH_PER_TICK=1."
- [ ] **Step 4: Run** `tests.core.test_scan_target tests.core.test_asset_api tests.core.test_continuous tests.core.test_attribution_decisions tests.core.test_alerts`. Expected: OK.
- [ ] **Step 5: Commit** "Give every owned root a scan target so continuous monitoring picks it up".

### Task 3: Shared rate limiter, daily budgets and the `asset_new` event

**Files:**
- Create: `web/limes/intel/ratelimit.py`
- Modify:
  - `web/limes/intel/http.py`: `get_json` waits on `ratelimit.reserve` instead of the per-process `_last`, and keeps the `clock`/`sleep` injection; replace the module NOTE.
  - `web/limes/alerts/events.py`, `web/limes/checks/network.py`, `web/dashboard/stats.py` (`CHANGE_LABELS`), `web/dashboard/templates/dashboard/index.html:140-150` (`fe-plus-circle`, `ov-fi-warn`).
- Test: `web/tests/core/test_intel_http.py` (replace `http._last.clear()` with `cache.clear()`), `test_alerts.py`, `test_dashboard_stats.py`

**Interfaces:**
- Produces:
  - `ratelimit.reserve(provider: str, interval: float, now: float, cache=default_cache) -> float`, the seconds to wait.
    - It claims the first free slot `floor(now / interval) + k` with `cache.add('limes:rl:<provider>:<slot>', 1, timeout)` for k in 0..119; when all are full it returns the wait to the last one.
    - On a cache error it falls back to process-local spacing and logs once.
    - `NOTE:` it assumes worker clocks agree to within an interval. The upgrade path is a Redis Lua token bucket on Redis `TIME`.
  - `ratelimit.take_daily(provider: str, limit: int, today: date | None = None, cache=...) -> bool` is a per-UTC-day counter (`add` then `incr`). It is False once the counter is over `limit`.
  - `ratelimit.per_tick(limit: int, tick_seconds: int = 60) -> int` is `max(1, ceil(limit * tick_seconds / 86400))`.
  - `network.risky_check(ports: Iterable[int]) -> str | None` returns the `net.exposed_<svc>` of the worst risky port, ties broken by the lowest port.
  - `events.KINDS` gains `'asset_new'`. `is_immediate('asset_new', key, sev)` is True iff `key` starts with `net.exposed_`.
  - `events.record_asset_new(project, asset, ports=()) -> ChangeEvent | None` uses `safe_record`. Its title is `f'New {asset.kind} {asset.value}'`, plus `f' exposes {svc}'` when risky, and its detail is `{'ports': [...], 'parent': parent value}`.

- [ ] **Step 1: Write the failing tests:**
  - `test_reserve_spaces_calls_across_processes`: two `reserve('internetdb', 1.0, now=100.2)` calls on one cache return 0 and ≈0.8 (the second takes slot 101).
  - `test_take_daily_and_per_tick`:
    - `take_daily` is True 5000 times and then False;
    - a new day resets it;
    - `per_tick(5000) == 4` and `per_tick(10000) == 7`.
  - The existing `test_min_interval_per_provider` still passes against the cache.
  - `test_rules` gains:
    - `is_immediate('asset_new', 'net.exposed_rdp', None)` is True;
    - `is_immediate('asset_new', None, None)` is False;
    - `risky_check([80, 3389, 21]) == 'net.exposed_rdp'`;
    - `risky_check([80]) is None`.
  - `test_every_change_kind_has_a_label` keeps passing with `'asset_new': 'New asset'`.
- [ ] **Step 2: Run them.** Expected: failures.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests.core.test_intel_http tests.core.test_intel_run tests.core.test_alerts tests.core.test_dashboard_stats`. Expected: OK.
- [ ] **Step 5: Commit** "Share provider rate limits across workers and add the asset_new change event".

### Task 4: ASN prefixes and range enumeration

**Files:**
- Modify:
  - `web/limes/owned_ranges.py`: enumeration and the `enumerate_ranges` task;
  - `web/limes/intel/ripestat.py`: `announced_prefixes_url`, `parse_announced_prefixes`;
  - `web/limes/alerts/issues.py`: `_bucket` and the silent first pass;
  - `web/limes/celery_routing.py` and `web/limes/settings.py` (beat, `CELERY_IMPORTS`).
- Test: `web/tests/core/test_owned_ranges.py`, `web/tests/core/test_celery_config.py`, plus a fixture `tests/core/fixtures/ripestat_announced_prefixes.json`

**Interfaces:**
- Consumes:
  - `ratelimit.take_daily` and `per_tick` (Task 3);
  - `events.record_asset_new` and `network.risky_check` (Task 3);
  - `intel._store` and `intel._fresh`;
  - `inventory.upsert_hostname_asset`, `upsert_candidate` and `owned_root_values`;
  - `range_addresses` (Task 1).
- Produces:
  - `ripestat.announced_prefixes_url(asn: str) -> str`, which hits `.../announced-prefixes/data.json?resource=AS<n>&sourceapp=limes`.
  - `ripestat.parse_announced_prefixes(obj) -> list[str]`: canonical, deduplicated network strings, with junk dropped.
  - `refresh_asn(asset, get=http.get_json, now=None) -> dict`:
    - drops reserved prefixes (`scope.is_reserved_network`);
    - refuses when the total is over `RANGE_ADDRESS_CAP - range_addresses(project, exclude_parent=asset)`, storing `enrichment['asn'] = {'status': 'refused', 'reason': ..., 'checked_at'}` and leaving the children unchanged;
    - otherwise upserts each prefix as a `cidr` child (`owned_host`, `parent=asset`, source `asn`) and calls `mark_missing_or_seen(False)` on children that are no longer announced (missing after 3 refreshes, via the existing `MISSING_THRESHOLD`);
    - stores `{'status': 'ok', 'prefixes': [...], 'refreshed_at'}`;
    - on a provider failure it changes nothing.
  - `resolve_ptr(ip: str, resolve=collect._resolve) -> list[str]` uses `dns.reversename`. Names are kept only when `normalize_host` and `validators.domain` accept them. NXDOMAIN gives `[]`; a DNS error gives `None` (retried later).
  - `place_names(project, names, ip_value, evidence) -> list[Asset]`:
    - a name under an owned root becomes `upsert_hostname_asset(parent=root, source='cidr', evidence=...)`;
    - other names become `upsert_candidate(project, 'root_domain', registrable(name), 'cidr', evidence)`;
    - it returns the newly created owned hostnames. Task 5 reuses it for InternetDB hostnames.
  - `enumerate_step(asset, idb_budget: int, ptr_budget: int, get=..., resolve=..., now=None) -> {'internetdb': n, 'ptr': n, 'new': n}`:
    - The cursor lives in `enrichment['enum'] = {'cursor': int, 'pass': int, 'status': 'running'|'done'|'refused', 'last_pass_at', 'reason'}`.
    - A range over `MAX_ENTRY_ADDRESSES` that is not an ASN child is refused, with the reason stored.
    - It walks addresses from the cursor and skips reserved IPs without spending budget.
    - An IP is live if InternetDB reports ports or hostnames, or PTR returns names.
    - A live IP becomes an `ip` child (`owned_host`, `parent=asset`, source `cidr`; an existing `dependency` row is promoted, `candidate`/`rejected` rows are untouched) with its InternetDB data stored.
    - Names go through `place_names`.
    - An existing child that is not live is marked a miss.
    - `record_asset_new` fires only when `pass >= 1`.
    - At the end of the range, `pass += 1`, `status = 'done'` and `cursor = 0`.
  - `due_ranges(now) -> list[Asset]` picks owned `asn`/`cidr` rows that are not off and whose own and parent tier and cadence allow it. A range is due when it is `running`, or when it is `done` and `last_pass_at` is older than `CADENCE_INTERVALS[cadence_tier]`. ASNs are due by `enrichment['asn']['refreshed_at']`. The list is ordered oldest first.
  - The `enumerate_ranges()` task:
    - holds `RANGE_LOCK` and checks `CONTINUOUS_SCANS`;
    - does at most 1 `refresh_asn` per tick, run whatever `RANGE_ENUMERATION` says (RIPEstat only);
    - runs `enumerate_step` calls only if `settings.RANGE_ENUMERATION`, sharing `per_tick(INTERNETDB_DAILY_BUDGET)` / `per_tick(PTR_DAILY_BUDGET)`, each call gated by `take_daily`;
    - calls `deliver_immediate(project)` for projects with new events;
    - returns the counts.
  - `issues._bucket`: an IP whose parent is a `cidr` maps to `f'cidr:{parent.value}'`. `sync_issues` never adds such a bucket to `state.roots` while that range's `enum.pass == 0`, so a first sweep is silent.

- [ ] **Step 1: Write the failing tests** (a fake `get` per provider and a fake `resolve`, no network):
  - `test_parse_announced_prefixes` against the fixture, plus junk input.
  - `test_asn_refresh_children_and_withdrawal`: the children are created with `parent=asn` and source `asn`, and a prefix withdrawn for 3 refreshes is `missing`.
  - `test_reserved_prefix_dropped`.
  - `test_asn_over_cap_refused`: the reason names the total and the cap, and no children are created.
  - `test_existing_oversized_range_refused`: a /16 row added before this change is refused, with no InternetDB call.
  - `test_enumeration_opt_in`: with `RANGE_ENUMERATION=False`, `enumerate_ranges()` makes no InternetDB or PTR call, but an ASN refresh still runs.
  - `test_budget_and_cursor_resume`:
    - a /28 with `idb_budget=4` takes 4 calls per step, the cursor advances by 4, and nothing restarts;
    - after 4 steps it is `done`, with `pass == 1`;
    - it is not due again until 7 days later;
    - `take_daily` exhaustion stops the calls.
  - `test_reserved_ips_in_range_skipped`.
  - `test_live_ip_becomes_child_and_names_placed`.
  - `test_outside_names_stay_candidates`: a PTR name `x.cdn-provider.net` and an InternetDB hostname outside the owned roots become `candidate` roots, and nothing is owned.
  - `test_asset_new_only_after_first_pass`:
    - no event in pass 0;
    - in pass 1, a new IP with port 3389 gives an immediate `asset_new`, and one with port 80 gives a non-immediate event;
    - issue sync of the range's IPs during pass 0 creates rows silently.
  - `test_stopped_or_rejected_untouched`: a range set `off` or `rejected` between `due_ranges` and the step, or whose parent ASN is rejected, gets no call.
  - `test_concurrent_tick_is_locked`: holding the lock gives `{'reason': 'locked'}`.
  - `test_beat_and_routing` in `test_celery_config.py`: 60.0 s, `expires` 55, `(ORCHESTRATE, 15 * MIN)`, and the module is in `CELERY_IMPORTS`.
- [ ] **Step 2: Run them.** `... test tests.core.test_owned_ranges` fails.
- [ ] **Step 3: Implement.** The opt-in NOTE cites the InternetDB terms from Global Constraints.
- [ ] **Step 4: Run** `tests.core.test_owned_ranges tests.core.test_alerts tests.core.test_celery_config tests.core.test_intel_run`. Expected: OK.
- [ ] **Step 5: Commit** "Enumerate owned ranges and ASN prefixes on a budget, behind an operator opt-in".

### Task 5: Safe fetch and the light monitor

**Files:**
- Create: `web/limes/safe_fetch.py`, `web/limes/monitor.py`
- Modify:
  - `web/limes/checks/run.py`: `_defaults()` uses the pinned observers via a per-host `safe_fetch.resolve_vetted`, and `run_asset_checks` is added. This fixes the scan path's re-resolution too.
  - `web/api/asset_add.py`: replace the "reject private resolved IPs" NOTE with a pointer to `safe_fetch`.
  - `web/api/views.py` `SetAssetCadence`: allow `root_domain`, `hostname`, `ip`, `cidr` and `asn`, and set `enrichment['cadence_explicit'] = True` under `select_for_update`.
  - `celery_routing.py` and `settings.py` (beat, imports).
- Test: `web/tests/core/test_safe_fetch.py`, `web/tests/core/test_monitor.py`; update `test_asset_api.py:403 test_rejects_unknown_tier_and_non_roots` (hostnames are now accepted, unknown tiers and candidates still rejected); `test_risk_checks.py` must still pass.

**Interfaces:**
- Consumes:
  - `place_names` (Task 4);
  - `record_asset_new` and `take_daily` (Task 3);
  - `has_scan_target` (Task 2);
  - `inventory.record_resolution`, `intel._store` and `_fresh`;
  - `continuous.CADENCE_INTERVALS`;
  - `issues.sync_issues` and `deliver.deliver_immediate`.
- Produces:
  - `safe_fetch.resolve_vetted(host: str, resolve=collect._resolve) -> tuple[str | None, str | None]` returns `(ip, None)` or `(None, reason)`.
    - It resolves A and AAAA once each; the resolver follows CNAMEs.
    - Any reserved answer refuses the host outright, as do no answers, an internal TLD and a resolver error.
    - An IP literal is vetted directly.
  - `safe_fetch.pinned_get(host: str, ip: str, session_factory=requests.Session)` returns a callable with the `requests.get(url, **kw)` signature, so it can be passed as `get=` to `collect.observe_http`.
    - It accepts only URLs whose host is `host`; anything else raises `requests.exceptions.InvalidURL`.
    - It connects to `ip` (bracketed for v6) with `Host: host`, and an HTTPAdapter whose pool manager gets `server_hostname=host` and `assert_hostname=host`. TLS verification stays on.
  - `safe_fetch.pinned_tls_connect(ip: str, create_connection=socket.create_connection)` returns `connect(host, legacy=None)` for `collect.observe_tls`. It dials `(ip, 443)` with `server_hostname=host`.
  - `checks.run.run_asset_checks(asset, now=None, observers=None, resolve=collect._resolve) -> {'checked', 'failed', 'http_live': bool, 'refused': str | None}`:
    - hostname and root kinds get web+tls through the pinned observers (headers holder: the asset, else its owned root via `_root_of`, else none);
    - `root_domain` also gets email+dns;
    - `ip` gets network (DB only, no contact);
    - a refusal writes no check rows and contacts nothing.
  - `monitor.ACTIVE_INTERVAL = timedelta(hours=24)`, `INACTIVE_INTERVAL = timedelta(days=30)`, `MAX_PER_TICK = 20`, `TICK_BUDGET = timedelta(seconds=50)`.
  - `monitor.effective_interval(asset) -> timedelta | None`:
    - `off` gives None;
    - with `cadence_explicit`, `CADENCE_INTERVALS[tier]`;
    - otherwise ACTIVE if `enrichment['monitor']['active']`, else INACTIVE.
  - `monitor.monitored(project=None) -> QuerySet`: owned tiers; kinds `hostname`, `ip` and `root_domain`; not retired; not off; excluding roots where `has_scan_target`.
  - `monitor.due_assets(now, limit=MAX_PER_TICK) -> list[Asset]`:
    - due when `last_resolved_at` is null or older than `effective_interval`;
    - never-checked first, then oldest;
    - skips hostnames whose owned root has a `ScanHistory` in progress;
    - root scans already stamp `last_resolved_at` on their hostnames, so covered hosts are not due.
  - `monitor.check_asset(asset, now=None, resolve=..., get=http.get_json, observers=None) -> dict`:
    - re-reads the row (tier and cadence) first;
    - names: resolves A/AAAA/CNAME, writes answers with `record_resolution`, then `mark_missing_or_seen(answered)`; new owned IPs found this way, and new owned hostnames from `place_names`, get `record_asset_new`;
    - refreshes InternetDB for each owned IP when it is not `_fresh` and `take_daily` allows; owned IPs' InternetDB hostnames go through `place_names`;
    - runs `run_asset_checks`, and treats MX as present when `observe_mail_dns`/`resolve(value, 'MX')` returns records;
    - stamps `last_resolved_at = now` for every kind (IPs included; it is the "Last checked" field);
    - stores `enrichment['monitor'] = {'checked_at', 'active': ports or http_live or mx, 'status': 'ok'|'refused'|'unresolved', 'reason'}`.
  - The `monitor_assets()` task holds `MONITOR_LOCK`, respects `CONTINUOUS_SCANS`, works through `due_assets` within `TICK_BUDGET`, then runs `sync_issues`, `deliver_immediate` and `invalidate` for each touched project.

- [ ] **Step 1: Write the failing tests:**
  - `test_any_private_answer_refused`:
    - a stub returning `10.0.0.1` gives `(None, reason)`;
    - A `['93.184.216.34', '10.0.0.1']` is refused;
    - `localhost`-style and internal TLDs are refused.
  - `test_rebinding_uses_vetted_ip`:
    - the resolver stub returns a public IP on its 1st call and `10.0.0.1` on its 2nd;
    - `resolve_vetted` is called once;
    - the fake session and fake `create_connection` saw only the public IP;
    - Host and SNI equal the hostname.
  - `test_pinned_get_refuses_other_hosts_and_caps_redirects`:
    - a redirect to another host is not followed;
    - 5 same-host redirects stop after 3.
  - `test_refused_host_never_contacted`: `check_asset` on a host resolving to 10.0.0.1 never calls the http/tls observers, stores `monitor.status == 'refused'` and writes no `RiskCheck` rows.
  - `test_activity_rule_and_explicit_cadence`:
    - an asset with InternetDB ports is due again after 24 h, and one without after 30 d;
    - an explicit `standard` gives 7 d;
    - `off` is never due.
  - `test_covered_by_root_scan_not_due`: a hostname with a recent `last_resolved_at` is skipped, as is one whose root has a scan in progress.
  - `test_monitor_records_lifecycle_and_issues`:
    - an unresolvable host goes to `missing` after 3 checks;
    - a failing TLS check creates a `TrackedIssue` via `sync_issues`;
    - `project_score` counts the host (owned, outside any root).
  - `test_new_ip_from_resolution_emits_asset_new`, only for owned-tier IPs and never for dependency IPs.
  - `test_root_without_scan_target_is_monitored`: an `owned_host` root and an other-project root are monitored with email/dns.
  - `test_stopped_or_rejected_untouched`: a cadence set `off` after `due_assets` is skipped, and a rejected asset is skipped.
  - `test_concurrent_tick_is_locked`.
  - `test_beat_and_routing`.
  - `AssetCadenceApiTest`: a hostname accepts `off` and sets `cadence_explicit`, and a candidate is refused.
- [ ] **Step 2: Run them.** Expected: ImportError and failures.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests.core.test_safe_fetch tests.core.test_monitor tests.core.test_risk_checks tests.core.test_asset_api tests.core.test_scoring tests.core.test_alerts tests.core.test_celery_config`, then the full `tests.core`. Expected: OK.
- [ ] **Step 5: Commit** "Monitor added hosts and IPs on the activity rule, contacting only vetted, pinned addresses".

### Task 6: Assets page tracking UI and deploy notes

**Files:**
- Modify:
  - `web/api/serializers.py` `AssetSerializer`: `monitor` and `found_by` method fields, plus `last_resolved_at`;
  - `web/api/views.py` `AssetDatatableViewSet`: the `source` filter and `colmap['12'] = 'last_resolved_at'`;
  - `web/limes/monitor.py`: the pure helpers below;
  - `web/startScan/templates/startScan/assets.html`: the `asn` kind option, a Source select, and 3 new `<th>` cells before Actions;
  - `web/static/custom/asset.js`.
- Test: `web/tests/core/test_asset_api.py` (`AssetListApiTest`)

**Interfaces:**
- Consumes: `effective_interval` (Task 5), `enrichment['enum'|'asn'|'monitor']` (Tasks 4 and 5).
- Produces:
  - `monitor.FOUND_BY = {'manual': 'manual', 'discovery': 'scan', 'probe': 'scan', 'dns': 'scan', 'crtsh': 'CT', 'internetdb': 'InternetDB', 'cidr': 'CIDR', 'asn': 'ASN', 'attribution': 'attribution'}`;
  - `monitor.found_by(asset) -> list[str]`: unique labels in source order. An unknown source gives `'other'`. Empty sources give `'manual'` if `added_by_id`, else `'target'`.
  - `monitor.monitor_state(asset) -> {'interval': str | None, 'next_due': iso | None, 'last_checked': iso | None, 'status': str | None, 'reason': str | None}`:
    - no queries;
    - `next_due = last_resolved_at + interval`;
    - roots with a scan target use `CADENCE_INTERVALS`;
    - cidr/asn rows read `enum`/`asn` status and reason.
  - The list endpoint accepts `?source=<label>`, an OR of `sources__contains=[{'source': raw}]` over the raw names for that label. An unknown label returns an empty result.

- [ ] **Step 1: Write the failing tests:**
  - `test_found_by_and_source_filter`: `?source=CT` returns only crt.sh rows, and `?source=manual` returns the manual rows.
  - `test_monitor_state_shape`: an owned host checked 2 h ago with ports has `interval == '24h'` and `next_due` 22 h ahead, and a refused ASN carries its reason.
  - `test_no_n_plus_one` still passes, with the query count unchanged.
- [ ] **Step 2: Run them.** Expected: failures.
- [ ] **Step 3: Implement the API and the page:**
  - Columns are appended after Confidence:
    - "Monitored": interval and next due, "off" or "Refused: <reason>";
    - "Last checked";
    - "Found by".
  - `order: [[8, 'desc']]` stays, and the colmap NOTE is updated.
  - `asset_actions` shows "Stop monitoring" for owned assets whose cadence is not off; it posts `cadence_tier: 'off'` to `/api/action/asset/cadence/`.
  - `asset_cadence_html` covers all monitorable kinds.
  - The existing `asset_parent_chain` shows ASN → range → IP.
  - The add modal's label reads "Domains, hosts, IPs, CIDRs, start–end ranges (1.2.3.0-1.2.3.255) or ASNs (AS12345)".
  - Every new field goes through `asset_esc`.
- [ ] **Step 4: Verify in the real UI** (puppeteer-core, `/usr/bin/chromium`):
  - **Data:** seed a project with:
    - an ASN `AS64500` (refused, reason set) and an owned CIDR child with an IP child;
    - a manual host whose source evidence and `decision_reason` are `<script>alert(1)</script>`;
    - a crt.sh host.
  - **List:**
    - the columns render;
    - Source=CT filters the list;
    - the script text shows as text, with no script element and no dialog.
  - **Modal:** the IP's modal shows the chain AS64500 → range → IP.
  - **Actions:**
    - Stop monitoring makes the row show "off";
    - adding `8.8.8.1-8.8.8.6` reports added 4;
    - `AS 1` is reported with a reason.
  - **Console:** no console errors.
  - **Checks:** run `node --check static/custom/asset.js` and the full `tests.core`.
- [ ] **Step 5: Write the deploy notes in the commit body** (operator-facing, no secrets):
  - **Scan burst:** the first dispatcher ticks scan every owned root that was previously unlinked, two at a time.
  - **Reclassify:** run `manage.py reclassify_roots` once.
  - **Enumeration opt-in:** range enumeration is off until `LIMES_RANGE_ENUMERATION=true`. Read the InternetDB terms quoted in `limes/owned_ranges.py` first.
  - **Caps and budgets:** `LIMES_RANGE_ADDRESS_CAP` (max 65,536), `LIMES_INTERNETDB_DAILY_BUDGET` and `LIMES_PTR_DAILY_BUDGET`.
- [ ] **Step 6: Commit** "Show monitoring, last check and discovery source on the Assets page".
