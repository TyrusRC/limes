# Near-real-time Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Limes notices new certificates, subdomains and DNS changes on owned names within minutes, not on the next cadence tick. It degrades to cadence and says so, never to silence.

**Architecture:**
- **Event queue.** `limes/event_queue.py` is a bounded Redis sorted set (`limes:evq`). It has per-asset cooldowns, per-project burst caps and drop counters. The existing `monitor_assets` tick drains it, so it shares the tick's lock, budget, `_ours` re-read and `safe_fetch`. A 15 s `drain-events` beat entry runs the same task with `events_only=True`.
- **Certificate watch** (opt-in, `make up REALTIME=1` and `LIMES_CT_WATCH=true`):
  - A `ct-watch` compose service runs `manage.py ct_watch`.
  - `ct_watch` writes the watchlist from the database and supervises a pinned certspotter.
  - certspotter's `-script` hook (`limes/ct/hook.py`, stdlib only) copies each match into a spool directory.
  - The supervisor ingests the spool through `limes/ct/match.py` (pure) and `limes/ct/ingest.py`, which stores `CertSighting` rows and records `cert_new` events.
- **Fallbacks:**
  - `poll_ct_api` (60 s beat) polls the Cert Spotter API when a key is set.
  - The same task evaluates watch health and records `monitoring_degraded` / `monitoring_restored` once per transition.
  - The cadence crt.sh query stays as it is.
- **DNS deltas.** `limes/dns_delta.py` compares each new answer with `enrichment['dns']`. The tick re-resolves crown jewels every 15 minutes, DNS only.
- **Overview.** `GET /<slug>/dashboard/live` returns the events since an id plus the Real-time card. `overview.js` polls it every 30 s while the tab is visible.

**Tech Stack:** Django 3.2, Celery 5.4 beat, PostgreSQL behind pgbouncer (transaction pooling), Redis 7.2 (`noeviction`, AOF) through `django_redis.get_redis_connection('default')`, certspotter v0.25.0 (Go, MPL-2.0), Django templates, vanilla JS, puppeteer-core with `/usr/bin/chromium` for the UI check.

**Spec:** `docs/superpowers/specs/2026-10-23-near-real-time-design.md` (approved). The user accepted every recommended default:
- the watch is off by default, behind `make up REALTIME=1`;
- the Cert Spotter API key is an optional fallback;
- a certificate from a CA not seen for that root in 365 days alerts immediately.

Sibling spec: `limes-p3` `docs/superpowers/specs/2026-10-23-discovery-reputation-design.md`. Its lookalikes are only an optional hook here, never a dependency.

### External facts this plan relies on (checked 2026-10-23)

- **certspotter's hook interface** (https://github.com/SSLMate/certspotter/blob/master/man/certspotter-script.md):
  - `EVENT` is `discovered_cert`, `malformed_cert` or `error`, and "more may be added".
  - For `discovered_cert` the hook receives `WATCH_ITEM`, `LOG_URI`, `ENTRY_INDEX`, `TBS_SHA256`, `CERT_SHA256`, `JSON_FILENAME`, `CERT_FILENAME`, `TEXT_FILENAME`, `NOT_BEFORE_RFC3339`, `NOT_AFTER_RFC3339`, `ISSUER_DN` and `SUMMARY`.
  - The JSON file holds `tbs_sha256`, `pubkey_sha256`, `dns_names` (SANs and CN, IDNs in Punycode), `ip_addresses`, `not_before` and `not_after`.
  - There is **no precertificate flag**. A certificate and its precertificate share `TBS_SHA256`.
  - Under `-no_save` the files are temporary and deleted after the script finishes.
  - The page says nothing on concurrent hook runs or exit-code handling.
- **certspotter's command line** (https://github.com/SSLMate/certspotter/blob/master/man/certspotter.md):
  - flags: `-watchlist`, `-state_dir`, `-script`, `-no_save` ("causes duplicate notifications"), `-start_at_end`, `-healthcheck` (default 24h), `-logs`, `-verbose`;
  - the watchlist has one name per line, and a leading dot covers the subtree. It is read only at startup, so a change needs a restart;
  - `state_dir/logs` holds the per-log positions;
  - it exits 0 on SIGTERM and SIGINT, and non-zero on serious errors, including a failure to run the script;
  - `HTTPS_PROXY` is honoured.
- **Building certspotter** (https://github.com/SSLMate/certspotter, https://raw.githubusercontent.com/SSLMate/certspotter/master/go.mod, https://raw.githubusercontent.com/SSLMate/certspotter/master/CHANGELOG.md):
  - it installs with `go install software.sslmate.com/src/certspotter/cmd/certspotter@…`;
  - `go.mod` says `go 1.25.0`, and the image's Go stage is 1.27.1;
  - the licence is MPL-2.0. No official Docker image is published;
  - v0.25.0 (2026-09-13) is the latest. v0.24.0 added precertificate/certificate dedupe;
  - v0.19.0, the release that brought static-ct-api, was RETRACTED, and v0.19.1 came out the same day. Pinning v0.25.0 avoids it.
- **The Cert Spotter API** (https://sslmate.com/help/reference/ct_search_api_v1):
  - `GET https://api.certspotter.com/v1/issuances?domain=&include_subdomains=true&match_wildcards=true&after=<id>&expand=dns_names&expand=issuer`, with `Authorization: Bearer <key>`;
  - each issuance has `id`, `tbs_sha256`, `cert_sha256`, `not_before`, `not_after`, and `issuer.name` (an RFC 2253 DN);
  - without `after`, the oldest issuances come first;
  - an empty page carries `Retry-After`, and throttling returns the `rate_limited` error code (status 4xx).

## Global Constraints

- **Django and style:**
  - Django 3.2; **no new Python dependencies**. certspotter is the only new binary, built in the existing `gotools` stage.
  - 4 spaces in `limes/*`, `dashboard/*`, `startScan/*` and tests.
  - Tabs in `api/views.py`.
  - 2 spaces in `overview.js` and the template script blocks.
  - `api/urls.py` (CRLF) is not touched.
- **Tests:**
  - Run with `LIMES_DB=<unique name> LIMES_SRC=/home/kali/project/trc/limes-p4 /tmp/claude-1000/-home-kali-project-trc-limes/1272ac93-25ff-41d2-a96c-5b1ecc4bf767/scratchpad/dj.sh test <dotted.path> --noinput`. Below this is written `... test <path>`.
  - Each agent uses its **own** `LIMES_DB`.
  - Implementers and reviewers quote the real `Ran N tests` and `OK` lines from their own `dj.sh test tests.core --noinput` run. Never trust counts from a shared file.
  - No network. Redis in tests is the scratch fakeredis server behind `CACHE_URL`, and `cache.clear()` in `setUp` flushes it, the `limes:evq*` and `limes:ct:*` keys included.
- **Commits:**
  - identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`;
  - **no AI attribution of any kind** (no `Co-Authored-By`, no tool trailer);
  - never `--no-verify`;
  - no push without an explicit user yes.
- **Hostile data:**
  - certificate names, DNs, log URIs and certspotter summaries are attacker-controlled;
  - they render only through Django autoescape or `textContent`. No `innerHTML`, `.html()`, `insertAdjacentHTML` or `|safe` with them;
  - they are logged only with `%r`, never in an f-string;
  - they never reach a shell. The subprocess gets an argument list with no `shell=True`;
  - they never form a path. Spool filenames come only from a validated 64-hex `tbs_sha256` or an integer.
- **Target contact:**
  - every automatic contact with a target goes through `monitor.check_asset`, which means `limes/safe_fetch.py`;
  - lookalike, co-tenant and candidate names are never contacted;
  - the DNS watch sends DNS queries only (`collect._resolve`);
  - Limes never fetches URLs found in certificates (AIA, CRL, OCSP).
- **Privacy:**
  - only certificates with a matching name are stored, and only their matched names plus an `other_names` count;
  - nothing is stored per foreign domain, except through the existing co-tenant candidate rule;
  - the Cert Spotter key is read from the environment, sent only as the `Authorization` header, and never logged. Errors log the exception type only.
- **Bounded:**
  - every Redis key is capped or has a TTL. Redis runs `noeviction`, so an unbounded key would eventually stop the broker;
  - the queue is capped at `EVENT_QUEUE_MAX`, the watchlist at `CT_WATCHLIST_MAX` and spool ingestion at `CT_INGEST_PER_MIN`;
  - latency lists keep 1,000 entries and live 2 days;
  - every drop is counted and shown on the card.
- **No alert storms:**
  - `cert_new` coalesces to one row per `(project, asset, immediate)` per `CT_EVENT_WINDOW`;
  - `deliver.ALERT_HOURLY_CAP` (10 per project) and the digest still apply;
  - `monitoring_degraded` is sent once per transition.
- **Locks:** Redis only, through `continuous.tick_lock` or `SET NX`. No Postgres advisory locks (pgbouncer transaction pooling). `ct_watch` calls `django.db.close_old_connections()` every loop and keeps no long transactions.
- **Kill switches:** `settings.CONTINUOUS_SCANS = False` stops the drain, the DNS watch, the API poller, the watcher's certspotter child and live polling's queue figures. `EVENT_CHECKS = False` makes `enqueue` a no-op.
- **Headline model unchanged:** `scoring.py` is not touched. `PENALTY`, `CEILING`, `GRADES`, `MAX_SCORE` and `VERSION = 'limes-score-v3'` stay as they are.
- **Return shapes kept:** `monitor_assets()` still returns `{'checked': n}`, or `{'checked': 0, 'reason': ...}`. `age_assets()` still returns `{'stale', 'retired'}`. Existing assertions stay unchanged.
- **NOTE comments:** every deliberate ceiling gets a `NOTE:` naming the ceiling and the upgrade path, in the codebase's style. That covers the queue cap, cooldown, burst, the per-tick share, the watchlist cap, the spool backlog, the /24 and /48 heuristic, the issuer-history cap and the API slot.
- **Clock:** latencies are computed from epoch seconds (`time.time()`, `timezone.now().timestamp()`, file `st_mtime`). A negative difference is clamped to 0 and counted as `skew`. Every stored timestamp is an aware UTC ISO string.

## Review Focus

1. **A wildcard or SAN-heavy certificate burst** must cost at most one immediate alert per root and hour, with no unbounded rows or queue items. Picture 500 certificates for `*.x.com` and `a1..a999.x.com` within a minute:
   - one `cert_new` row per root per window (plus at most one immediate new-issuer row);
   - a 1,000-SAN certificate stores at most 100 names;
   - enqueues stop at the burst cap and are counted.

   Task 2 `test_cert_burst_coalesces`; Task 1 `test_burst_cap_per_project`.
2. **Hostile spool and hook input.** The cases:
   - a symlink or `../` name in the spool;
   - a 10 MB file;
   - a non-hex `TBS_SHA256`;
   - JSON whose `dns_names` holds `<img src=x onerror=alert(1)>.x.com`, `a\nb.x.com` and a 300-character label;
   - an `ISSUER_DN` with a newline and `%s`.

   Each must be dropped or escaped, never followed, interpolated or rendered as HTML. Task 4 `test_spool_refuses_links_and_oversize`, `test_hook_refuses_bad_hash`; Task 2 `test_hostile_names_rejected`; Task 6 the UI check.
3. **Duplicates after a restart or redelivery** must change nothing: no second sighting, event, enqueue or alert. That covers the same `tbs` from a second log, from `-no_save` redelivery, from the API after the watcher, and from a spool file re-read after a crash between commit and delete. Task 2 `test_duplicate_tbs_is_noop`; Task 4 `test_crash_between_commit_and_delete`.
4. **A dead watcher hidden by a working fallback.** The watch is on, but the heartbeat is stale or certspotter keeps exiting, while the API poller still finds certificates. The card must say `degraded` with the reason, one `monitoring_degraded` event must reach every project, and API finds must count as `api_only`. Task 5 `test_degraded_once_even_with_api`, `test_api_only_counts_watch_misses`.
5. **Lookalike names become owned or contacted.** A certificate naming an owned host and a watched lookalike must never turn the lookalike into a candidate `Asset` through the co-tenant rule, and must never enqueue it. Task 2 `test_lookalike_never_candidate_or_contacted`.

---

### Task 1: Event queue library and settings

**Files:**
- Create: `web/limes/event_queue.py`
- Modify:
  - `web/limes/settings.py`, next to `CONTINUOUS_SCANS`:
    - `EVENT_CHECKS = env.bool('LIMES_EVENT_CHECKS', default=True)`;
    - `EVENT_QUEUE_MAX = max(1, env.int(..., default=1000))`;
    - `EVENT_COOLDOWN = env.int('LIMES_EVENT_COOLDOWN', default=900)`;
    - `EVENT_BURST = env.int('LIMES_EVENT_BURST', default=200)`;
    - `EVENT_SHARE = min(0.9, max(0.1, env.float('LIMES_EVENT_SHARE', default=0.5)))`.
- Test: `web/tests/core/test_event_queue.py`

**Interfaces:**
- Produces:
  - `REASONS = ('ct_new', 'ct_cert', 'ct_recheck_1h', 'ct_recheck_24h', 'asset_new', 'manual', 'exposed', 'dns_change')`. Any other reason raises `ValueError`, a programming error.
  - Keys:
    - `QUEUE = 'limes:evq'` (zset, member `str(asset_id)`, score = due unix time);
    - `WHY = 'limes:evq:why'` (hash `asset_id → 'reason|enqueued_unix'`);
    - `cool_key(asset_id) = f'limes:evq:cool:{asset_id}'`;
    - `burst_key(project_id, hour) = f'limes:evq:burst:{project_id}:{hour:%Y%m%d%H}'` (TTL 3600);
    - `stats_key(day) = f'limes:evq:stats:{day:%Y%m%d}'` (hash, TTL 2 days);
    - `lat_key(day) = f'limes:evq:lat:{day:%Y%m%d}'` (list, `LTRIM` to 1,000, TTL 2 days).
  - `enqueue(asset, reason, delay=0, now=None) -> str`. It returns one of `'off' | 'skipped' | 'cooled' | 'burst' | 'overflow' | 'dup' | 'queued' | 'error'`, and the outcome is also counted in today's stats hash. In order:
    1. `'off'` when `not settings.CONTINUOUS_SCANS or not settings.EVENT_CHECKS`.
    2. `'skipped'` unless `monitor._ours(asset)` (lazy import, no cycle).
    3. Cooldown `SET cool NX EX EVENT_COOLDOWN`, except for the `ct_recheck_*` reasons.
    4. Burst `INCR` with `EXPIRE` against `EVENT_BURST`.
    5. One Lua script, `ENQUEUE_LUA`:
       - when `ZSCORE` exists: `ZADD LT` gives `'dup'`, and `HSET` runs only when the score was lowered;
       - else when `ZCARD >= EVENT_QUEUE_MAX`: `'overflow'`;
       - else `ZADD`, then `HSET`, giving `'queued'`.

       It is atomic, so concurrent enqueuers cannot overshoot the cap.

    When step 4 or 5 drops the request, the cooldown key set in step 3 is deleted, so a later request is not wrongly `cooled`. On a `RedisError` it logs `type(e).__name__` only and returns `'error'`.
  - `due_count(now) -> int`: `ZCOUNT -inf now`; 0 on a `RedisError`.
  - `claim_due(now, limit) -> list[tuple[int, str, float]]`, as `(asset_id, reason, enqueued_unix)`:
    - `ZRANGEBYSCORE -inf now LIMIT 0 limit`, then `ZREM` per member;
    - only members whose `ZREM` returned 1 are returned, and their `WHY` field is deleted;
    - unclaimed members keep their score;
    - `[]` on a `RedisError`.
  - `count(outcome, n=1, now=None) -> None`: `HINCRBY` today's stats hash.
  - `record_latency(seconds, now=None) -> None`: clamps a negative value to 0 and counts it as `skew`, then `LPUSH`, `LTRIM 0 999` and `EXPIRE`.
  - `snapshot(now) -> {'depth': int, 'due': int, 'oldest_age': int | None, 'counts': {outcome: int}, 'latency': [float]}`. Counts are summed over today and yesterday (UTC); `latency` covers both days. It reads Redis only.
  - `percentile(values: list[float], q: float) -> float | None`: nearest rank; None for empty input.

- [ ] **Step 1: Write the failing tests.** `Base(TestCase)` with `cache.clear()`; owned host `h` (`owned_host`, cadence `standard`) in project `p`. The tests:
  - `test_double_enqueue_is_one_entry`:
    - `enqueue(h, 'manual')` is `'queued'`;
    - with `EVENT_COOLDOWN=0`, a second `enqueue(h, 'manual')` is `'dup'`;
    - `ZCARD == 1`;
    - `claim_due` returns `[(h.id, 'manual', ~now)]` once, then `[]`.
  - `test_cooldown`:
    - a second enqueue within 900 s is `'cooled'`, and counts `cooled == 1`;
    - `ct_recheck_1h` bypasses the cooldown.
  - `test_overflow_counted_and_cooldown_released`:
    - with `EVENT_QUEUE_MAX=2`, three hosts give `queued`, `queued`, `overflow`;
    - the third host's cooldown key does not exist;
    - `snapshot()['counts']['overflow'] == 1`.
  - `test_burst_cap_per_project`:
    - with `EVENT_BURST=3`, five hosts in `p` give 3 `queued` and 2 `burst`;
    - a host in project `o` is still `queued`.
  - `test_delayed_item_not_claimed_early`:
    - `enqueue(h, 'ct_recheck_1h', delay=3600)`;
    - `claim_due(now)` is `[]`, and `due_count(now) == 0`;
    - `claim_due(now + 3601s)` returns it;
    - `snapshot()['depth'] == 1` before the claim.
  - `test_earlier_request_moves_delayed_item_forward`: a delayed recheck followed by `enqueue(h, 'ct_cert')` with the cooldown off gives `'dup'`, and `claim_due(now)` returns `(h.id, 'ct_cert', …)`.
  - `test_stopped_rejected_or_covered_skipped`:
    - cadence `off`, `rejected` and `candidate` hosts each give `'skipped'`;
    - so does an owned root with a `Domain`;
    - with `CONTINUOUS_SCANS=False` or `EVENT_CHECKS=False`, the result is `'off'` and no key exists.
  - `test_redis_down_fails_soft`: with `get_redis_connection` patched to raise `redis.exceptions.ConnectionError`:
    - `enqueue` is `'error'`;
    - `claim_due` is `[]`;
    - `due_count` is 0;
    - the log line holds `ConnectionError` and not the host value.
  - `test_unknown_reason_raises` (`ValueError`), and `test_percentile` (`[1..100]` gives p50 50 and p95 95; `[]` gives None).
  - `test_every_key_is_bounded`: after one enqueue, claim and stats write, every key matching `limes:evq*` either has a TTL (`> 0`) or is `QUEUE` / `WHY`, whose sizes are capped.
- [ ] **Step 2: Run** `... test tests.core.test_event_queue`. Expected: ImportError.
- [ ] **Step 3: Implement.**
  - `# NOTE: the queue is capped at EVENT_QUEUE_MAX, with a per-asset cooldown and a per-project hourly burst. A dropped request falls back to the cadence, where a never-checked asset already sorts first. Upgrade path: a per-project share of the cap.`
- [ ] **Step 4: Run** `... test tests.core.test_event_queue tests.core.test_monitor`. Expected: OK.
- [ ] **Step 5: Commit** "Add a bounded event queue for event-driven checks".

### Task 2: Certificate model, matching and ingestion

**Files:**
- Create:
  - `web/limes/ct/__init__.py` (empty);
  - `web/limes/ct/match.py`, pure: no ORM and no I/O;
  - `web/limes/ct/ingest.py`;
  - `web/limes/ct/lookalikes.py`, the optional project-3 hook.
- Modify:
  - `web/startScan/asset_models.py`: add `CertSighting` (below), then run `makemigrations startScan -n cert_sighting`, which creates `0028_cert_sighting.py`.
  - `web/limes/alerts/events.py`:
    - `KINDS += ('cert_new', 'dns_changed', 'monitoring_degraded', 'monitoring_restored')`;
    - `ALWAYS_IMMEDIATE += ('monitoring_degraded',)`;
    - `NEW_ISSUER_KEY = 'cert.new_issuer'`;
    - in `is_immediate`, `cert_new` is immediate iff `key == NEW_ISSUER_KEY`, and `dns_changed` and `monitoring_restored` are False;
    - `record_asset_new(project, asset, ports=(), enqueue=True)`: after `safe_record`, when `enqueue`, it calls `event_queue.enqueue(asset, 'asset_new')`.
  - `web/dashboard/stats.py`: `CHANGE_LABELS` gains `'cert_new': 'New certificate'`, `'dns_changed': 'DNS changed'`, `'monitoring_degraded': 'Monitoring degraded'` and `'monitoring_restored': 'Monitoring restored'`. `test_every_change_kind_has_a_label` pins this.
  - `web/limes/monitor.py`: `FOUND_BY['ct'] = 'CT'`, and `FOUND_BY['certspotter_api'] = 'CT'`.
  - `web/limes/tasks/intel.py`:
    - factor the co-tenant block of `run_crtsh` into `cotenant_candidates(...)` (below), which `run_crtsh` then calls with a run-local counter;
    - after parsing, `run_crtsh` calls `ingest.seed_issuers(root, crtsh.issuers(rows), now)`.
  - `web/limes/intel/crtsh.py`: add `issuers(rows) -> set[str]`, the `match.issuer_org(row['issuer_name'])` of valid rows. `parse` is unchanged, so `test_intel_parsers` stays as it is.
  - `web/limes/continuous.py` `age_assets`: also delete `CertSighting` rows with `first_seen_at < now − 400 days`. Its return dict is unchanged.
  - `web/limes/settings.py`: `CT_EVENT_WINDOW = env.int('LIMES_CT_EVENT_WINDOW', default=3600)`.
- Test: `web/tests/core/test_ct_match.py` (`SimpleTestCase`), `web/tests/core/test_ct_ingest.py`, plus `test_alerts.py` `ImmediacyTest.test_rules` (new asserts added; existing ones unchanged).

**Model** `CertSighting`:
- `project` FK CASCADE;
- `asset` FK `Asset` null `SET_NULL`;
- `tbs_sha256` CharField(64);
- `cert_sha256` CharField(64) null;
- `names` JSONField(default=list), at most 100;
- `other_names` int;
- `wildcard` bool;
- `issuer` CharField(500), blank;
- `not_before` / `not_after` DateTimeField null;
- `log_uri` CharField(500), blank;
- `entry_index` BigIntegerField null;
- `source` CharField(20), one of `certspotter`, `certspotter_api` or `crtsh`;
- `first_seen_at` DateTimeField(default=timezone.now);
- `watch_seen_at` DateTimeField null: set when the watcher delivers this `tbs`;
- `api_while_watch_ok` bool, default False.

`Meta`: `UniqueConstraint(fields=['project', 'tbs_sha256'], name='certsighting_proj_tbs')`, and `Index(fields=['project', 'first_seen_at'])`.

**Interfaces:**
- Consumes:
  - Task 1 `event_queue.enqueue`;
  - `inventory.upsert_hostname_asset`, `record_fact`, `upsert_candidate` and `owned_root_values`;
  - `domains.registrable`;
  - `intel.SHARED_CERT_LIMIT` and `MAX_CANDIDATES_PER_ROOT`;
  - `events.safe_record`.
- Produces (`match.py`):
  - `MAX_NAMES = 1000`, `STORED_NAMES = 100` and `SAMPLE_NAMES = 20`.
  - `normalise(raw) -> tuple[str, bool] | None`, giving `(name, wildcard)`:
    - strip, lowercase, drop one trailing dot;
    - a leading `*.` sets `wildcard`;
    - IDNA-encode;
    - None unless the name is ≤ 253 characters, matches `^[a-z0-9.-]+$`, and passes `validators.domain(n) is True`.

    It extends `crtsh._clean`'s rules without changing `_clean`.
  - `Index = NamedTuple(roots: dict[str, list[tuple[int, int]]], hosts: dict[str, list[tuple[int, int]]], lookalikes: dict[str, list[int]])`:
    - `roots` maps a root value to `[(project_id, root_asset_id)]`;
    - `hosts` maps an exact owned name to `[(project_id, asset_id)]`;
    - `lookalikes` maps a lookalike domain to `[project_id]`.
  - `ProjectMatch = NamedTuple(owned: list[tuple[str, bool, int]], hosts: list[tuple[str, int]], lookalikes: list[str], others: list[str])`. An `owned` entry is `(name, wildcard, root_asset_id)`.
  - `classify(raw_names: list, index: Index) -> tuple[dict[int, ProjectMatch], int]`. It returns the per-project matches and the count of names dropped as invalid or truncated.
    - It handles the first `MAX_NAMES` entries.
    - Per project, the order is: the longest owned root equal to or a dot-suffix of the name, then an exact owned host, then a name equal to or under a lookalike, else `others`.
    - A project with no owned, host or lookalike match is absent from the result.
  - `issuer_org(dn: str) -> str`:
    - the `O=` value of an RFC 2253 or OpenSSL-style DN, handling `\,` escapes and `, ` or `/` separators;
    - else the `CN=` value; else `''`;
    - stripped, collapsed whitespace, at most 200 characters.

    The comparison key is `issuer_org(dn).casefold()`.
- Produces (`lookalikes.py`, the optional hook):
  - `WATCH_STATUSES = ('registered', 'watching', 'reported')`.
  - `model() -> type | None`: the first `django.apps.apps.get_models()` model named `Lookalike` whose concrete fields include `project`, `domain`, `status` and `ct`, else None. It is cached with `functools.lru_cache(None)`.
  - `watched() -> list[tuple[int, str]]`, as `(project_id, ascii domain)` for rows in `WATCH_STATUSES`; `[]` when `model()` is None.
  - `record_sighting(project_id, domain, now) -> bool`:
    - under `select_for_update`, it sets `ct = {'count': n + 1, 'first_seen': kept or now, 'last_seen': now}` (ISO strings);
    - it returns False when there is no model or no row;
    - it never creates rows, records events or enqueues. Project 3's `lookalike_tick` owns `lookalike_active`.
- Produces (`ingest.py`):
  - `load_index() -> match.Index`, in a fixed number of queries:
    - roots: `root_domain`, `owned_root`, cadence not `off`, not retired, and `registrable(value) == value`;
    - hosts: owned `hostname`, and `owned_host` `root_domain`, not retired, cadence not off, and under no indexed root;
    - lookalikes: `lookalikes.watched()`.
  - `parse_record(raw: bytes) -> dict | None`. It checks the schema and returns `{'tbs_sha256', 'cert_sha256', 'dns_names', 'names_total', 'issuer_dn', 'not_before', 'not_after', 'log_uri', 'entry_index'}`, or None:
    - None when `len(raw) > SPOOL_MAX_BYTES` (512 KiB), the input is not a JSON object, `tbs_sha256` is not `^[0-9a-f]{64}$`, or `dns_names` is not a list of str;
    - `cert_sha256` becomes None unless it is 64 hex;
    - DN and URI are truncated to 500;
    - times go through `parse_datetime`, giving None when invalid;
    - `entry_index` is an int ≥ 0, else None.
  - `ingest(record: dict, source: str, index: match.Index, now, seen_at: float | None = None, silent=False) -> set[int]`. It returns the ids of the touched projects (those where a sighting was created). Per matched project, in one `transaction.atomic()`:
    1. `CertSighting` `get_or_create` on `(project, tbs)`. An existing row gets only `watch_seen_at = now`, and only when `source == 'certspotter'` and it is null. Then return: the duplicate is a no-op.
    2. Owned non-wildcard names that are not the root and not yet assets go through `upsert_hostname_asset(project, name, parent=root, source='ct' if source == 'certspotter' else source, evidence=f'cert:{tbs[:16]}')`. Each new one is enqueued as `ct_new` with `transaction.on_commit`; an existing owned host is enqueued as `ct_cert`. Wildcard names and the root create no asset.
    3. `asset` is the first new or existing matched hostname, else the root, else the exact host.
    4. Lookalike names get `lookalikes.record_sighting` and nothing else.
    5. Co-tenants: when the project matched an owned root, `others` go to `intel.cotenant_candidates`.
       - They first exclude every registrable domain that is a watched lookalike of the project.
       - The hourly allowance is a Redis counter `limes:ct:cand:{root_id}:{hour}` (TTL 3600) against `MAX_CANDIDATES_PER_ROOT`.
    6. The issuer history update and `cert_new` event, unless `silent`.
    7. `seen_at` (spool `st_mtime`) gives `record_t1(now.timestamp() − seen_at)`, an `LPUSH` to `limes:ct:lat:{day}`, capped at 1,000 with a 2-day TTL, clamped and counted as skew. `now − not_before` goes to `limes:ct:age:{day}` the same way.
  - `ISSUER_HISTORY = timedelta(days=365)`, `ISSUER_BASELINE = timedelta(days=30)` and `ISSUER_MAX = 50`.
  - `note_issuer(root, org_key, now) -> bool`. It returns "new issuer, immediate". The history is stored in `root.enrichment['ct_issuers'] = {'orgs': {key: iso}, 'since': iso, 'seeded': bool}`, under `select_for_update`.
    - It returns True iff the root is baselined (`seeded`, or `since <= now − ISSUER_BASELINE`), and the key is non-empty and absent or last seen before `now − ISSUER_HISTORY`.
    - It always records `key → now`, and keeps the `ISSUER_MAX` most recent entries.
  - `seed_issuers(root, orgs: set[str], now) -> None`: records each org and sets `seeded = True`. crt.sh's `exclude=expired` returns every certificate still valid, which is about a year of history.
  - `record_cert_event(project, asset, names: list[str], immediate: bool, issuer: str, now) -> ChangeEvent`:
    - it looks for a `ChangeEvent(kind='cert_new', project, asset, immediate=immediate, created_at >= now − CT_EVENT_WINDOW)` under `select_for_update`;
    - when one exists, it sets `detail.count += 1` and merges names into `detail.names`, sorted, at most `SAMPLE_NAMES`, and records no new row;
    - otherwise it records through `events.record`, with key `NEW_ISSUER_KEY` when immediate, title `f'New certificate for {asset.value}'` + (`f' from a new issuer ({issuer[:80]})'` when immediate), and `detail={'count': 1, 'names': […], 'issuer': issuer[:200]}`.
- Produces (`tasks/intel.py`): `cotenant_candidates(project, root, cert_ref: str, names: list[str], owned: set[str], known: set[str], allow: Callable[[], bool], source: str, exclude: set[str] = frozenset()) -> tuple[int, int]`, giving `(new, capped)`. It keeps the existing `SHARED_CERT_LIMIT` refusal, the evidence wording and the `record_fact` calls; `exclude` holds registrable domains never to suggest.

- [ ] **Step 1: Write the failing tests.**
  - `test_ct_match.py`:
    - `test_normalise`:
      - `'*.X.com.'` gives `('x.com', True)`;
      - `'bücher.example'` gives its `xn--` form;
      - `''`, `'a..b'`, `'-a.com'`, `'a b.com'`, `'a\nb.x.com'`, `'<img src=x>.x.com'`, `'x' * 254` and `'1.2.3.4'` each give None.
    - `test_longest_root_wins`: with roots `x.com` (p1, r1) and `a.x.com` (p1, r2), `b.a.x.com` maps to r2, and `c.x.com` to r1.
    - `test_name_equal_to_root_and_wildcard`: `x.com` and `*.x.com` are owned with root r1, with wildcards False and True.
    - `test_host_and_lookalike_and_other`:
      - `app.vendor.com` is a host match;
      - `login.examp1e.com` is a lookalike match for `examp1e.com`;
      - `z.org` goes to `others`;
      - a project with only `others` is absent.
    - `test_projects_classified_separately`: the same root in p1 and p2 gives two entries.
    - `test_truncation_counted`: 1,005 names give `dropped >= 5`, and at most 1,000 are classified.
    - `test_issuer_org`:
      - `"C=US, O=Let's Encrypt, CN=R11"` gives `"Let's Encrypt"`;
      - `'CN=Foo CA,O=Acme\\, Inc.,C=US'` gives `'Acme, Inc.'`;
      - `'/C=US/O=DigiCert Inc/CN=x'` gives `'DigiCert Inc'`;
      - `'CN=Only'` gives `'Only'`;
      - `''` gives `''`;
      - a 1,000-character O value gives 200 characters.
    - `test_hostile_names_rejected`: none of the hostile names in Review Focus 2 reaches any `ProjectMatch` list.
  - `test_ct_ingest.py` (`Base` with owned root `x.com` (`r`) that has a `Domain`, an owned host `www.x.com`, and a `rec(names, tbs='a' * 64, issuer="C=US, O=Let's Encrypt, CN=R11")` helper):
    - `test_new_hostname_upserted_and_enqueued`:
      - `ingest(rec(['new.x.com']), 'certspotter', load_index(), now, seen_at=now.timestamp() - 3)` under `captureOnCommitCallbacks(execute=True)`;
      - the hostname asset `new.x.com` has `parent == r` and `sources[0]['source'] == 'ct'`, and `found_by` gives `['CT']`;
      - `event_queue` holds it with reason `ct_new`;
      - a `CertSighting` row has `names == ['new.x.com']`, `asset` is the new host, and `source == 'certspotter'`;
      - `limes:ct:lat:<day>` holds about 3.0.
    - `test_wildcard_creates_no_asset`: `['*.x.com']` creates no hostname, the sighting's `asset == r` and `wildcard` is True, and nothing is enqueued.
    - `test_existing_host_enqueued_as_ct_cert`.
    - `test_duplicate_tbs_is_noop`:
      - a second `ingest` of the same `tbs` from `certspotter_api`, and then from `certspotter`, adds no row, no `ChangeEvent` and no queue entry;
      - the second sets `watch_seen_at`.
    - `test_cert_burst_coalesces`:
      - with `rec` issued for 30 distinct `tbs` values within the window, there is exactly 1 `cert_new` row for `r`, with `detail.count == 30` and `len(detail.names) <= 20`;
      - a 1,000-SAN certificate stores `len(names) == 100` and `other_names` equal to the rest;
      - after `CT_EVENT_WINDOW`, a new row starts.
    - `test_new_issuer_is_immediate_after_baseline`:
      - with no baseline, `cert_new` is not immediate;
      - after `seed_issuers(r, {"let's encrypt"}, now)`, a Let's Encrypt certificate is not immediate;
      - a `C=US, O=Evil CA, CN=E` certificate makes a second row with `immediate=True` and the new-issuer title, while the digest row keeps coalescing;
      - an issuer last seen 366 days ago counts as new.
    - `test_hostile_dn_truncated_and_logged_safely`:
      - an issuer of `'O=' + 'A' * 600 + '\n%s'` gives `issuer` length ≤ 500;
      - the event title is ≤ 300 characters;
      - `assertLogs` output never contains a raw newline from the DN.
    - `test_lookalike_never_candidate_or_contacted`:
      - with `lookalikes.model` patched to a fake whose `watched()` gives `[(p.id, 'examp1e.com')]`, a certificate for `['www.x.com', 'login.examp1e.com', 'shop.other.net']`;
      - `other.net` becomes a candidate;
      - `examp1e.com` is no `Asset` in any tier;
      - `record_sighting` is called once;
      - the queue holds only `www.x.com`.
    - `test_lookalike_hook_absent_is_inert`: with the real `model()` returning None in this tree, `watched() == []`, and `record_sighting` returns False.
    - `test_parse_record_schema`: oversize, non-object, `tbs` `'../../etc'`, `dns_names` as a str, and a non-int `entry_index` each give None, or the field is coerced to None as specified.
    - `test_crtsh_still_uses_shared_cotenant_rule`: the existing `test_intel_run` `run_crtsh` expectations pass unchanged, and the root's `ct_issuers.seeded` is True after a run with `issuer_name` rows.
    - `test_old_sightings_pruned`: `age_assets()` deletes a 401-day-old sighting, keeps a 399-day-old one, and returns its usual keys only.
  - `test_alerts.ImmediacyTest.test_rules` gains:
    - `is_immediate('cert_new', 'cert.new_issuer', None)` is True;
    - `is_immediate('cert_new', None, None)` is False;
    - `is_immediate('monitoring_degraded', None, None)` is True;
    - `is_immediate('dns_changed', None, None)` and `is_immediate('monitoring_restored', None, None)` are False.
- [ ] **Step 2: Run** `... test tests.core.test_ct_match tests.core.test_ct_ingest tests.core.test_alerts`. Expected: ImportError, and the label test fails.
- [ ] **Step 3: Implement**, then add the migration.
  - `# NOTE: the issuer history keeps ISSUER_MAX organisations per root. Upgrade path: a per-root issuer table if CA churn ever exceeds it.`
- [ ] **Step 4: Run** `... test tests.core.test_ct_match tests.core.test_ct_ingest tests.core.test_alerts tests.core.test_intel_run tests.core.test_intel_parsers tests.core.test_dashboard_stats tests.core.test_continuous`, then `makemigrations --check --dry-run`. Expected: OK, then `No changes detected`.
- [ ] **Step 5: Commit** "Match certificates to owned names and record coalesced certificate events".

### Task 3: Drain in the monitor tick, triggers and DNS change detection

**Files:**
- Create: `web/limes/dns_delta.py`
- Modify:
  - `web/limes/monitor.py`:
    - `monitor_assets(events_only=False)`;
    - `_tick(events_only=False)`;
    - factor `_scanning_roots() -> dict[int, list[str]]` out of `due_assets`;
    - `check_asset(..., reason=None)`;
    - `_names` calls `dns_delta.observe` on a definite NXDOMAIN, but not on `'error'`.
  - `web/limes/tasks/inventory.py` `record_resolution`: call `dns_delta.observe(asset, record)` before replacing the links. It uses a lazy import, so there is no cycle.
  - `web/limes/alerts/issues.py` `sync_issues`: for each `issue_new` whose key starts with `net.exposed_` on an `ip` asset, `transaction.on_commit` enqueues the owned hostnames linked to that IP (`ip_addresses__address=ip.value`, at most `EXPOSED_HOSTS = 20`) with reason `exposed`.
  - `web/api/views.py`:
    - `AddAssets`: after the transaction, every *added* asset of kind `hostname`, `ip` or `root_domain` gets `enqueue(asset, 'manual')`, through the same loop as `ensure_scan_target`;
    - `ConfirmAsset`: after `save()`, `enqueue(asset, 'manual')`.
  - `web/limes/settings.py`:
    - `DNS_WATCH_INTERVAL = env.int('LIMES_DNS_WATCH_INTERVAL', default=900)`, where 0 means off;
    - `DNS_WATCH_PER_TICK = env.int(..., default=30)`.
  - `web/limes/settings.py` `CELERY_BEAT_SCHEDULE`: add `'drain-events': {'task': 'monitor_assets', 'schedule': 15.0, 'kwargs': {'events_only': True}, 'options': {'expires': 14}}`.
- Test: `web/tests/core/test_event_drain.py`, `web/tests/core/test_dns_delta.py`, plus one assertion added to `test_monitor.BeatTest`.

**Interfaces:**
- Consumes:
  - Task 1: `enqueue`, `claim_due`, `due_count`, `count`, `record_latency`;
  - Task 2: `events.record_asset_new(..., enqueue=False)` and the `dns_changed` kind;
  - `collect._lookup`, `collect._resolve`, `intel._store` (lazy import).
- Produces:
  - `dns_delta.significant(before: dict, after: dict) -> str | None`, where each dict is `{'a': list, 'aaaa': list, 'cname': list}`. It returns `'cname'`, `'unresolved'`, `'resolved'`, `'moved'` or None:
    - `'cname'` when the sorted, lowercased CNAME targets differ;
    - `'unresolved'` when A and AAAA go from non-empty to empty, and `'resolved'` for the reverse;
    - `'moved'` when both sides resolve and no new IPv4 shares a /24 with an old one **and** no new IPv6 shares a /48 with an old one. A family empty on both sides is ignored.
    - `# NOTE: /24 and /48 proximity keeps CDN rotation quiet; it misses a move within one provider's /24 and flags a CDN that rotates across blocks. Upgrade path: compare origin ASNs from RIPEstat enrichment.`
  - `dns_delta.observe(asset, record: dict, now=None, watched=False) -> ChangeEvent | None`:
    - it acts only on owned (`OWNED`) `hostname` and `root_domain` assets;
    - under the `_store` lock it reads the previous `enrichment['dns']` and writes `{'a', 'aaaa', 'cname'}` (each capped at 20, sorted), `changed_at` (when significant), and `watched_at` (when `watched`). `_store` adds `fetched_at`;
    - with no previous answer, it only stores (silent baseline);
    - when significant: `events.safe_record(asset.project, 'dns_changed', f'DNS changed for {asset.value}: {LABELS[reason]}', asset=asset, detail={'reason': reason, 'before': prev, 'after': new})`, holding addresses and names only.
  - `dns_delta.LABELS = {'cname': 'CNAME target changed', 'unresolved': 'stopped resolving', 'resolved': 'started resolving', 'moved': 'moved to new addresses'}`.
  - `monitor.dns_watch(now, deadline: float, resolve=collect._resolve) -> int`:
    - it covers owned, not retired, `cadence_tier='crown_jewel'` `hostname` and `root_domain` assets whose `enrichment.dns.watched_at` is missing or older than `DNS_WATCH_INTERVAL`, oldest first, at most `DNS_WATCH_PER_TICK`;
    - it stops at `deadline`;
    - each asset is resolved for A, AAAA and CNAME through `collect._lookup`, and skipped when any lookup is `'error'`;
    - then `observe(..., watched=True)`; a returned event gives `enqueue(asset, 'dns_change')`;
    - it returns how many assets were watched.
  - `_tick(events_only)`:
    - `share = TICK_BUDGET.total_seconds() * settings.EVENT_SHARE`;
    - it claims one item at a time (`claim_due(now, 1)`), at most `ceil(MAX_PER_TICK * EVENT_SHARE)` (10) items and only until `start + share`. Items it never reached were never removed, so they keep their score and their place;
    - a hostname whose root `_scanning_roots()` lists is counted as `covered`, not checked;
    - each check is `check_asset(asset, reason=reason)`. Then `record_latency(now − enqueued)`, counts `checked` or `skipped`, and adds the project to `touched`;
    - unless `events_only`: `dns_watch(now, start + share)`, then the cadence loop as today, until `start + TICK_BUDGET`;
    - `checked` counts event and cadence checks alike;
    - `monitor_assets(events_only=True)` returns `{'checked': 0, 'reason': 'idle'}` without taking the lock when `due_count(now) == 0`.
  - `check_asset(..., reason=None)`:
    - with `reason == 'ct_new'`, after the checks it calls `events.record_asset_new(a.project, a, ports=ports, enqueue=False)`, whatever the baseline. The new host's own event is never silent; its children keep the first-check-silent rule;
    - when `reason in ('ct_new', 'ct_recheck_1h')` and the status is `'unresolved'`, it calls `enqueue(a, 'ct_recheck_1h', delay=3600)` or `enqueue(a, 'ct_recheck_24h', delay=23 * 3600)` respectively, so the rechecks land 1 h and 24 h after discovery;
    - it stores `monitor['enqueued_reason'] = reason` when a reason is given.

- [ ] **Step 1: Write the failing tests.**
  - `test_dns_delta.py`:
    - `test_cdn_rotation_is_silent`: `a ['1.2.3.4']` to `['1.2.3.9']`, and v6 `2001:db8:1::1` to `2001:db8:1:5::1`, give None.
    - `test_moves_and_cname_and_resolution`:
      - `1.2.3.4` to `5.6.7.8` gives `'moved'`;
      - CNAME `a.cdn.net` to `b.other.net` gives `'cname'`;
      - `['1.2.3.4']` to `[]` gives `'unresolved'`, and the reverse gives `'resolved'`;
      - a v4-only host gaining v6 in the same v4 /24 gives None.
    - `test_observe_emits_once`:
      - the first `observe` stores silently;
      - the same answer again records no event;
      - a moved answer records exactly one `dns_changed`, whose `detail.before.a == ['1.2.3.4']` and title contains `moved to new addresses`;
      - a candidate host records nothing.
    - `test_record_resolution_and_nxdomain_paths`:
      - `record_resolution` with a new CNAME emits `'cname'`;
      - `monitor.check_asset` on a host whose A and AAAA become NXDOMAIN emits `'unresolved'`;
      - a lookup `'error'` (SERVFAIL stub) emits nothing.
  - `test_event_drain.py` (the `Get`, `observers`, `public` and `stub` helpers from `test_monitor`, and `cache.clear()`):
    - `test_queued_asset_checked_first_and_latency_recorded`:
      - an owned host checked 1 h ago (not due) is `enqueue`d `manual`;
      - `monitor_assets()` with `check_asset` patched to `{'status': 'ok', 'project_id': p.id}` checks it with `reason='manual'`;
      - `snapshot()['counts']['checked'] == 1`, and `len(latency) == 1`.
    - `test_cadence_still_gets_half_the_tick`:
      - 12 queued hosts and 5 due hosts, with each check taking 10 fake seconds (`limes.monitor.time.monotonic`);
      - event checks stop once 25 s are spent (3 checks);
      - the cadence loop still checks at least 2 due hosts;
      - the unreached queued items are still in `limes:evq` with their original scores.
    - `test_events_only_idle_and_locked`:
      - with an empty queue, `monitor_assets(events_only=True) == {'checked': 0, 'reason': 'idle'}`, and `tick_lock` was never taken (`get_redis_connection().exists('limes:tick:monitor_assets') == 0` during the call, via a patched `tick_lock` spy);
      - with a queued item while another holder has the lock, the result is `{'checked': 0, 'reason': 'locked'}` and the item is still queued.
    - `test_covered_by_scan_in_progress`: a queued host under a root with an `IN_PROGRESS` `ScanHistory` is not checked, `counts['covered'] == 1`, and it is not re-queued.
    - `test_stopped_mid_queue_untouched`: a host queued, then set to cadence `off` before the tick, is not contacted (`self.calls == []`) and counts as `skipped`.
    - `test_precert_rechecks_twice_then_stops`, through the real `check_asset` and an NXDOMAIN stub:
      - `ct_new` gives an `asset_new` event (not immediate, `detail.ports == []`) and a queue score of about now + 3600;
      - after the claim at +3601 s, `ct_recheck_1h` gives a score of about +24 h from discovery;
      - after `ct_recheck_24h`, nothing is queued;
      - when a recheck resolves, no further recheck is queued.
    - `test_ct_new_with_exposed_service_is_immediate`: InternetDB ports `[3389]` on the new host's IP give an `asset_new` event with `immediate=True`.
    - `test_triggers`:
      - `record_asset_new` enqueues `asset_new`, and `enqueue=False` does not;
      - `AddAssets` with `a.x.com` and `9.9.9.9` queues both as `manual` (`captureOnCommitCallbacks(execute=True)`);
      - `ConfirmAsset` queues the confirmed host;
      - a second sync that creates `issue_new net.exposed_rdp` on owned IP `I`, linked to 25 owned hostnames, queues exactly 20 with reason `exposed`.
    - `test_dns_watch_crown_jewels_only`:
      - a crown-jewel host with `enrichment.dns` watched 16 minutes ago is re-resolved with DNS-only stub calls (`('h', 'A')`, `('h', 'AAAA')`, `('h', 'CNAME')`), with no `pinned_get` and no TLS connect;
      - a standard host is not resolved;
      - a moved answer records `dns_changed` and enqueues `dns_change`;
      - with `DNS_WATCH_PER_TICK=1`, only the oldest of two is watched;
      - with `DNS_WATCH_INTERVAL=0`, none is watched.
  - In `test_monitor.BeatTest.test_beat_and_routing`, add:
    - the entry `'drain-events'` is `('monitor_assets', 15.0, {'events_only': True}, {'expires': 14})`.
- [ ] **Step 2: Run** `... test tests.core.test_dns_delta tests.core.test_event_drain`. Expected: ImportError or FAIL.
- [ ] **Step 3: Implement.** Keep the existing `test_monitor` assertions unchanged. `test_tick_budget_stops_between_assets` must still give `(1, 1)` with an empty queue.
  - `# NOTE: event checks and the DNS watch share LIMES_EVENT_SHARE of the tick (25 s by default), so the cadence keeps the rest. Upgrade path: a dedicated event worker once queues routinely stay full.`
- [ ] **Step 4: Run** `... test tests.core.test_dns_delta tests.core.test_event_drain tests.core.test_monitor tests.core.test_alerts tests.core.test_asset_api tests.core.test_resolution tests.core.test_event_queue`. Expected: OK.
- [ ] **Step 5: Commit** "Drain event-driven checks in the monitor tick and detect DNS changes".

### Task 4: Certificate watcher: hook, spool, supervisor, compose service

**Files:**
- Create:
  - `web/limes/ct/hook.py`: stdlib only, with the first line `#!/usr/bin/python3 -I`. Commit it executable with `git update-index --chmod=+x`.
  - `web/limes/ct/watch.py`.
  - `web/startScan/management/commands/ct_watch.py`, a thin wrapper: `ct_watch` runs `watch.run()`, and `ct_watch --health` exits `watch.health_exit_code()`.
- Modify:
  - `web/Dockerfile`, `gotools` stage: after the amass line, add `CGO_ENABLED=0 go install -ldflags="-s -w" software.sslmate.com/src/certspotter/cmd/certspotter@v0.25.0`. It lands in `/go/bin`, which the runtime stage already copies. There is no new stage and no `@latest`.
  - `docker-compose.yml`:
    - service `ct-watch` (`<<: *app`, `profiles: [realtime]`, `entrypoint: ["python3", "manage.py", "ct_watch"]`, `mem_limit: ${CT_WATCH_MEM:-512m}`, `volumes: [ct_state:/var/lib/ct-watch]`, no `ports`);
    - healthcheck `["CMD", "python3", "manage.py", "ct_watch", "--health"]` with interval 60s, timeout 30s, retries 3 and start_period 120s;
    - volume `ct_state`.
  - `Makefile`: below the `LLM` block, add `ifeq ($(REALTIME), 1)` / `SERVICES += ct-watch` / `COMPOSE_ALL_FILES += --profile realtime` / `endif`, with the comment `# The certificate watch is opt-in (about 157 GB/day inbound, inferred): make up REALTIME=1 with LIMES_CT_WATCH=true`.
  - `web/limes/settings.py`:
    - `CT_WATCH = env.bool('LIMES_CT_WATCH', default=False)`;
    - `CT_WATCH_RESTART_MIN = env.int(..., default=300)`;
    - `CT_WATCHLIST_MAX = env.int(..., default=5000)`;
    - `CT_INGEST_PER_MIN = env.int(..., default=600)`;
    - `CT_STATE_DIR = env('LIMES_CT_STATE_DIR', default='/var/lib/ct-watch')`;
    - `CT_WATCH_STALE = env.int('LIMES_CT_WATCH_STALE', default=180)`.
- Test: `web/tests/core/test_ct_watch.py`, using temp directories (`tempfile.TemporaryDirectory`) and a fake `Popen`.

**Interfaces:**
- Consumes: Task 2 `ingest.load_index`, `parse_record` and `ingest`; `deliver_immediate`; `dashboard.stats.invalidate`.
- Produces (`hook.py`):
  - `main(env: Mapping[str, str], spool: str) -> int`. It always returns 0, and the module's `__main__` calls `sys.exit(main(os.environ, os.environ.get('LIMES_CT_SPOOL', '/var/lib/ct-watch/spool')))`.
  - `discovered_cert`:
    - refuses unless `TBS_SHA256` matches `^[0-9a-f]{64}$`;
    - refuses unless `JSON_FILENAME` is a regular file ≤ 256 KiB, opened with `O_NOFOLLOW`;
    - keeps the first 1,000 `dns_names` that are str ≤ 253 characters, and records `names_total`;
    - writes `{'v': 1, 'tbs_sha256', 'cert_sha256', 'dns_names', 'names_total', 'issuer_dn'[:500], 'not_before', 'not_after', 'log_uri'[:500], 'entry_index'}`. The times come from `NOT_BEFORE_RFC3339` / `NOT_AFTER_RFC3339`, else from the JSON;
    - writes through `tempfile.mkstemp(dir=spool + '/.tmp')`, then `os.replace` to `spool/<tbs>.json`.
  - `error` and `malformed_cert` write `spool/_health/<time.time_ns()>.json` = `{'event', 'summary'[:2048], 'at'}`.
  - Any other `EVENT` is ignored. Nothing is printed except a fixed one-line reason to stderr.
- Produces (`watch.py`):
  - `HEARTBEAT = 'limes:ct:watch'` (JSON, `EX 600`); `LOOP_SECONDS = 5`; `HEALTH_KEEP = 100`; `SPOOL_FAIL_LIMIT = 3`.
  - `paths(state_dir=None) -> {'state', 'spool', 'tmp', 'health', 'watchlist'}`, under `settings.CT_STATE_DIR`.
  - `watchlist(max_entries=None) -> tuple[list[str], int, str]`, giving `(lines, dropped, sha256 hex)`:
    - lines are `'.' + root` for each indexed root, then exact hosts, then `'.' + lookalike`, deduplicated and sorted within each group;
    - over the cap, lookalikes are dropped first, then hosts, never before roots;
    - `# NOTE: capped at LIMES_CT_WATCHLIST_MAX; owned names win and lookalikes are dropped first. Upgrade path: a measured cap once certspotter's per-entry cost is known.`
  - `command(p: dict, watchlist_file: str) -> list[str]`: `['certspotter', '-watchlist', f, '-state_dir', p['state'], '-script', HOOK_PATH, '-no_save', '-start_at_end', '-healthcheck', '1h']`. `HOOK_PATH` is the absolute path of `hook.py`.
  - `class Supervisor(popen=subprocess.Popen, clock=time.monotonic, wall=time.time)`, with:
    - `step(now: datetime) -> dict` (one loop; it returns the heartbeat dict);
    - `stop()`.

    Each `step`:
    1. If `CT_WATCH` and `CONTINUOUS_SCANS` are not both on, or the watchlist is empty, the child is stopped and the heartbeat reads `state: 'off' | 'idle'`.
    2. Every 60 s it recomputes the watchlist. When the hash changed and the last start is ≥ `CT_WATCH_RESTART_MIN` ago, it writes the file atomically, sends SIGTERM, waits up to 30 s, then SIGKILL, and starts again.
    3. A child that exited is restarted. Restarts within 10 minutes are kept in a `deque(maxlen=50)`.
    4. `drain_spool(...)`.
    5. `read_health(...)`.
    6. `close_old_connections()`.
    7. It writes the heartbeat `{'pid_alive', 'started_at', 'restarts_10m', 'watchlist_size', 'watchlist_dropped', 'watchlist_hash', 'last_ingest_at', 'last_match_at', 'spool_depth', 'health': 'ok' | 'error', 'last_error_at', 'last_error_summary', 'state', 'at'}`, with times as ISO and `'at'` set to wall now.
  - `drain_spool(spool: str, limit: int, now, index_loader=ingest.load_index) -> dict`, giving `{'ingested', 'invalid', 'failed', 'depth', 'projects': set[int]}`:
    - it lists the spool with `os.scandir`;
    - it accepts only `entry.is_file(follow_symlinks=False)` with a name matching `^[0-9a-f]{64}\.json$`, whose `lstat` size is ≤ `SPOOL_MAX_BYTES`. Others are deleted (a symlink is unlinked, never followed); `.tmp` files older than 1 h are removed;
    - files are taken oldest `st_mtime` first, at most `limit` per call (`ceil(CT_INGEST_PER_MIN * LOOP_SECONDS / 60)` = 50);
    - each file is opened with `O_NOFOLLOW`, run through `parse_record`, then `ingest(..., seen_at=st_mtime)`, then unlinked;
    - an invalid file is unlinked and counted;
    - a DB error keeps the file. After `SPOOL_FAIL_LIMIT` failures in this process it is unlinked and logged with the hash only;
    - the index is loaded once per call, and only when files exist;
    - then `deliver_immediate(project)` and `invalidate(pid)` run for each touched project;
    - `# NOTE: the backlog waits on disk, bounded by the volume; only matches are written, so it stays small. Upgrade path: a size alarm feeding the degraded state (Task 5's spool rule).`
  - `read_health(health_dir) -> dict | None`. It reads the newest `_health/*.json` (integer names only) into `{'last_error_at', 'last_error_summary'}`, and deletes all but the newest `HEALTH_KEEP`.
  - `run() -> None`: SIGTERM and SIGINT stop the child and exit 0.
  - `health_exit_code(now=None) -> int`: 0 when the heartbeat exists and `at` is within `CT_WATCH_STALE`, else 1.

- [ ] **Step 1: Write the failing tests:**
  - `test_hook_writes_atomically`:
    - `main({'EVENT': 'discovered_cert', 'TBS_SHA256': 'ab' * 32, 'JSON_FILENAME': f, 'ISSUER_DN': 'O=X\n%s', 'NOT_BEFORE_RFC3339': …}, spool)` returns 0;
    - exactly `spool/abab….json` exists and `.tmp` is empty;
    - the content parses with `ingest.parse_record`, and `issuer_dn` is ≤ 500;
    - 1,500 names give `len(dns_names) == 1000` and `names_total == 1500`.
  - `test_hook_refuses_bad_hash`: `TBS_SHA256` values of `'../../x'`, `'AB' * 32` (uppercase) and `''` write nothing and return 0.
  - `test_hook_exits_zero_on_garbage`:
    - a missing `JSON_FILENAME`, a 300 KiB file, a symlinked JSON file, invalid JSON and an unknown `EVENT` each give 0 and no spool file;
    - `error` with a 5 KB `SUMMARY` writes one `_health/<int>.json` with a 2,048-character summary.
  - `test_hook_is_executable_with_isolated_shebang`: `os.access(HOOK_PATH, os.X_OK)` and the first line is `#!/usr/bin/python3 -I`. Run it as a subprocess with an env (no shell) and check the spool result and exit 0.
  - `test_watchlist_cap_and_order`:
    - roots `x.com` and `co.uk` (a public suffix is refused), a cadence-`off` root, an owned host `app.vendor.com`, a host under `x.com` (not listed), and two fake lookalikes;
    - the lines are `['.x.com', 'app.vendor.com', '.l1.com', '.l2.com']`;
    - with `max_entries=2`, `dropped == 2` and both lookalikes are gone;
    - the hash is stable across calls and changes when a root is added.
  - `test_supervisor_restarts_on_change_rate_limited`. With a fake `Popen` recording argv and `terminate`:
    - the first step starts it with the exact `command(...)` list (argv is a list and `shell` is not passed);
    - a changed watchlist at +100 s causes no restart;
    - at +301 s there is one `terminate` and a new start;
    - a child that exits is restarted, and `restarts_10m` counts it;
    - with `CT_WATCH=False`, it is stopped and the heartbeat `state == 'off'`.
  - `test_spool_refuses_links_and_oversize`:
    - a symlink named `<hex>.json` pointing to `/etc/passwd`, a file `../evil.json`-style name, `notes.txt`, a 1 MiB `<hex>.json` and a valid file are present;
    - only the valid one is ingested;
    - the symlink is unlinked and its target is untouched;
    - `invalid` is 2 or more.
  - `test_spool_rate_and_order`: 120 valid files give exactly 50 ingested per call, oldest mtime first, with `depth == 70` afterwards.
  - `test_crash_between_commit_and_delete`: after ingesting a file and restoring the same file (as though the unlink never happened), a second `drain_spool` creates no new sighting, event or queue entry, and the file is gone.
  - `test_db_error_keeps_file_then_gives_up`: with `ingest` raising `OperationalError`, the file stays for 2 calls and is unlinked after 3.
  - `test_heartbeat_and_health_exit`:
    - after `step`, `HEARTBEAT` has a TTL ≤ 600, and `health_exit_code() == 0`;
    - a heartbeat whose `at` is 200 s old gives 1;
    - a missing heartbeat gives 1.
- [ ] **Step 2: Run** `... test tests.core.test_ct_watch`. Expected: ImportError.
- [ ] **Step 3: Implement**; then edit the Dockerfile, compose file and Makefile.
- [ ] **Step 4: Verify:**
  - `... test tests.core.test_ct_watch tests.core.test_ct_ingest`. Expected: OK.
  - `docker compose -f docker-compose.yml --profile realtime config --services` lists `ct-watch`, and the plain `config --services` does not.
  - `make -n up REALTIME=1 | grep -c ct-watch` prints 1, and `make -n up` prints 0.
  - Docker build: build only the gotools stage, with `docker build --target gotools -t limes-gotools-check web/` (local; it pushes nothing), then `docker run --rm limes-gotools-check /go/bin/certspotter -version`. Quote the version line. Stop and ask before any `make up`.
- [ ] **Step 5: Commit** "Run a pinned certspotter behind an opt-in realtime profile and ingest its matches".

### Task 5: Watch health, degraded alert and Cert Spotter API fallback

**Files:**
- Create:
  - `web/limes/ct/health.py`;
  - `web/limes/ct/api.py`.
- Modify:
  - `web/limes/celery_routing.py`: `'poll_ct_api': (IO, 15 * MIN)`.
  - `web/limes/settings.py`:
    - add `'limes.ct.api'` to `CELERY_IMPORTS`;
    - beat entry `'poll-ct-api': {'task': 'poll_ct_api', 'schedule': 60.0, 'options': {'expires': 55}}`;
    - `CERTSPOTTER_API_KEY = env('LIMES_CERTSPOTTER_API_KEY', default='')`;
    - `CERTSPOTTER_HOURLY_BUDGET = max(1, min(env.int(..., default=7), 10))`.
- Test: `web/tests/core/test_ct_health.py`, `web/tests/core/test_ct_api.py`

**Interfaces:**
- Consumes:
  - Task 4's `HEARTBEAT` contents;
  - Task 2's `ingest` and `CertSighting`;
  - Task 1's `snapshot` and `percentile`;
  - `events.record` and `deliver_immediate`.
- Produces (`health.py`):
  - `STATE_KEY = 'limes:ct:state'`: a single JSON value `{'state', 'since', 'reasons'}`, with no TTL (one bounded key).
  - `REASONS = {'no_heartbeat': 'The watcher has not reported', 'stale_heartbeat': 'The watcher stopped reporting', 'process_down': 'certspotter is not running', 'restart_storm': 'certspotter keeps restarting', 'watcher_error': 'certspotter reported an error', 'spool_backlog': 'Certificate backlog is growing'}`.
  - `mode() -> 'real-time' | 'api' | 'cadence'`:
    - `'real-time'` when `CT_WATCH`;
    - `'api'` when the key is set;
    - else `'cadence'`;
    - `'cadence'` whenever `CONTINUOUS_SCANS` is off.
  - `evaluate(now) -> {'state': 'off' | 'idle' | 'healthy' | 'degraded', 'reasons': [code], 'heartbeat': dict | None}`. Only when `CT_WATCH` and `CONTINUOUS_SCANS`:
    - degraded when the heartbeat is missing or older than `CT_WATCH_STALE`, `pid_alive` is False while `state` is not idle, `restarts_10m > 3`, `last_error_at` is within 1 h, or `spool_depth > 1000`;
    - `idle` (an empty watchlist) is never degraded.
  - `transition(now) -> str | None`:
    - it compares `evaluate` with `STATE_KEY`;
    - on `healthy`/`idle` → `degraded` it records `monitoring_degraded` once per project (fan-out rows: `ChangeEvent.project` stays non-null, so every existing project-scoped query keeps working). The title is `'Certificate watch degraded: ' + '; '.join(REASONS[c] for c in reasons)`, built from fixed text only. Then `deliver_immediate(project)` runs;
    - on `degraded` → `healthy` it records `monitoring_restored` (digest);
    - any other move, including the first evaluation and `off`, only stores the state;
    - it returns the kind recorded or None.
  - `card(project, now) -> dict`, read by Task 6:
    - `mode`, `state`, `reasons: [{'code', 'label'}]`;
    - `watch: {'heartbeat_age', 'last_match_age', 'watchlist_size', 'watchlist_dropped', 'restarts_10m', 'spool_depth', 'last_error_summary'[:300] | None, 'api_only_7d'}`;
    - `queue: {'depth', 'oldest_age', 'counts'}` from `event_queue.snapshot`;
    - `latency: {'t1_p50', 't1_p95', 't1_upper_p50', 't2_p50', 't2_p95', 't3_p50', 't3_p95'}`, rounded seconds or None:
      - T1 from `limes:ct:lat:*`;
      - `t1_upper` from `limes:ct:age:*`;
      - T2 from `snapshot.latency`;
      - T3 from the project's `ChangeEvent` rows with `notified_at` in 24 h (`values_list`, `[:1000]`);
    - `dns: {'watched', 'oldest_age'}` over the project's crown jewels;
    - `api: {'used_this_hour', 'budget', 'oldest_poll_age'} | None`.

    It uses a fixed number of queries, all project-scoped. Ages are integer seconds, clamped to ≥ 0.
- Produces (`api.py`):
  - `URL = 'https://api.certspotter.com/v1/issuances'`;
  - `SLOT_KEY = 'limes:ct:api:slot'`;
  - `count_key(hour) = f'limes:ct:api:count:{hour:%Y%m%d%H}'` (TTL 7200).
  - `@app.task(name='poll_ct_api') poll_ct_api() -> dict`:
    - under `tick_lock('poll_ct_api')`, it always runs `health.transition(timezone.now())` first;
    - then, only with a key and `CONTINUOUS_SCANS`, it runs `poll_once`;
    - it returns `{'transition': kind | None, 'polled': str | None}`.
  - `poll_once(now, session=requests) -> dict | None`:
    - `SET SLOT_KEY NX EX ceil(3600 / CERTSPOTTER_HOURLY_BUDGET)`. When the slot is taken, it returns None. That is one request per slot, never a sleep;
    - it picks the distinct indexed root value whose `enrichment['certspotter']` has the oldest `polled_at` and `retry_at` ≤ now;
    - `GET` with `params=[('domain', root), ('include_subdomains', 'true'), ('match_wildcards', 'true'), ('expand', 'dns_names'), ('expand', 'issuer')] + after`, `headers={'Authorization': f'Bearer {key}', 'User-Agent': http.HEADERS['User-Agent']}`, `timeout=http.TIMEOUT` and `allow_redirects=False`;
    - each issuance is mapped to `ingest`'s record (`issuer_dn = issuer.name`) and ingested with `source='certspotter_api'`, `silent=not baseline_done`. `api_while_watch_ok` is set when `health.evaluate(now)['state'] == 'healthy'`;
    - the cursor `{'after', 'polled_at', 'retry_at', 'baseline_done'}` goes on every project's root asset with that value;
    - an empty page sets `baseline_done = True` and `retry_at = now + Retry-After` (an int, clamped to 60..86400);
    - a 4xx or `rate_limited` sets `retry_at = now + 1 h`;
    - a `RequestException` logs `type(e).__name__` only;
    - the key, the headers and the response body are never logged.
  - `# NOTE: one request per 3600/budget seconds (about 514 s at 7), shared by all roots, so each root is polled about every ceil(roots/7) hours; a large root's silent baseline takes several slots. Upgrade path: a paid plan's budget.`

- [ ] **Step 1: Write the failing tests:**
  - `test_ct_health.py`:
    - `test_modes`: `CT_WATCH` gives `'real-time'`, a key alone gives `'api'`, neither gives `'cadence'`, and `CONTINUOUS_SCANS=False` gives `'cadence'` whatever else is set.
    - `test_degraded_rules`: each degraded case gives the matching reason; a fresh heartbeat with `health: 'ok'` gives `healthy`; `state: 'idle'` with `pid_alive` False gives `idle`.
    - `test_degraded_once_even_with_api`:
      - two projects, a key set and a stale heartbeat;
      - the first `transition` only stores the state (no event);
      - with a fresh heartbeat, the next is `healthy` with no event;
      - stale again gives `'monitoring_degraded'`: one immediate row per project, whose title has no heartbeat text and `deliver_immediate` called per project;
      - a repeat gives None;
      - fresh again gives `'monitoring_restored'`, one non-immediate row per project.
    - `test_restart_storm_and_recovery_emit_once`: `restarts_10m` going 5, 5, 0 gives degraded, None, restored.
    - `test_card_project_scoped_and_escaped`:
      - a `last_error_summary` of `'<img src=x onerror=alert(1)>' * 50` is ≤ 300 characters in the card (escaping is Task 6's job);
      - `api_only_7d` counts only `p`'s `certspotter_api` rows that have `api_while_watch_ok`, no `watch_seen_at`, and are older than 1 h and younger than 7 days;
      - T3 percentiles come only from `p`'s events;
      - a negative T1 sample is clamped to 0.
    - `test_api_only_counts_watch_misses`:
      - an API-ingested `tbs` with the watch healthy at ingest, 2 h old, gives `api_only_7d == 1`;
      - the watcher later delivering it sets `watch_seen_at`, and the count becomes 0.
  - `test_ct_api.py` (a `Session` fake recording calls; the responses are a list of issuances, an empty list with `Retry-After: 300`, and a 429 `{'code': 'rate_limited'}`):
    - `test_no_key_no_request`: with `CERTSPOTTER_API_KEY=''`, `poll_ct_api()` makes no session call and still runs `transition`.
    - `test_one_request_per_slot`: two `poll_once` calls in a row give one request, and the second returns None.
    - `test_baseline_silent_then_events`:
      - the first page (no `after`) stores sightings and records no `ChangeEvent`;
      - the empty page sets `baseline_done` and `retry_at = now + 300`;
      - the next page with a new `tbs` records `cert_new`;
      - the request params carry `after=<last id>` and both `expand` values.
    - `test_rate_limited_and_errors_logged_without_key`: with the key `sk-test-SECRET`, the 429 sets `retry_at` 1 h ahead, a `ConnectionError` is logged as its type, and `'SECRET'` appears in no log record.
    - `test_shared_root_polled_once_ingested_per_project`: `x.com` owned in `p` and `o` gives one request, a sighting in each project, and both roots' cursors updated.
    - `test_beat_routing`: the `'poll-ct-api'` entry, `TASK_PLAN['poll_ct_api'] == (IO, 15 * MIN)`, and `'limes.ct.api' in CELERY_IMPORTS`.
- [ ] **Step 2: Run** `... test tests.core.test_ct_health tests.core.test_ct_api`. Expected: ImportError.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `... test tests.core.test_ct_health tests.core.test_ct_api tests.core.test_ct_ingest tests.core.test_celery_config`. Expected: OK.
- [ ] **Step 5: Commit** "Detect a degraded certificate watch and poll the Cert Spotter API as a fallback".

### Task 6: Live Overview: polling endpoint, Real-time card, live recent changes

**Files:**
- Create: `web/dashboard/live.py`, holding the view and its payload builder.
- Modify:
  - `web/dashboard/urls.py`: `path('<slug:slug>/dashboard/live', live.live, name='dashboardLive')`.
  - `web/dashboard/views.py` `index`: add `'realtime': ct.health.card(project, now)` (outside the cached stats), `'live_poll_seconds': settings.LIVE_POLL_SECONDS` and `'live_since'` (the newest event id, else 0) to the context.
  - `web/dashboard/stats.py` `_recent_changes`: each row gains `'id'`.
  - `web/dashboard/templates/dashboard/index.html`:
    - icon branches for the four new kinds: `fe-shield` warn for `cert_new`, `fe-shuffle` warn for `dns_changed`, `fe-wifi-off` bad for `monitoring_degraded` and `fe-wifi` ok for `monitoring_restored`;
    - `aria-live="polite"` and `id="dash_changes_feed"` on the `ov-feed` list;
    - a hidden `#live_stale` button reading "Updated — refresh";
    - a new `<section class="card ov-realtime" id="dash_realtime" aria-labelledby="h-realtime">` after `dash_monitoring` in `ov-side`. Every value element carries `data-rt="<dotted path>"`;
    - a root `<div id="ov_live" data-url="{% url 'dashboardLive' project.slug %}" data-since="{{ live_since }}" data-poll="{{ live_poll_seconds }}" hidden>`.
  - `web/static/limes/overview.js`: a third IIFE (polling).
  - `web/static/limes/limes.css`: `ov-realtime` and the state pill (`ov-rt-healthy`, `ov-rt-degraded`, `ov-rt-off`), with `@media (prefers-reduced-motion: reduce)` disabling the new-row highlight.
  - `web/limes/settings.py`: `LIVE_POLL_SECONDS = max(0, env.int('LIMES_LIVE_POLL_SECONDS', default=30))`.
- Test: `web/tests/core/test_overview_live.py`, plus `test_overview_page.py`, where `OVERVIEW_QUERIES` is updated to the measured value with a one-line justification in the commit message. UI script: `/tmp/claude-1000/-home-kali-project-trc-limes/1272ac93-25ff-41d2-a96c-5b1ecc4bf767/scratchpad/tools/realtime_ui.js`, following the `overview_ui.js` pattern.

**Interfaces:**
- Consumes: Task 5 `health.card`; `CHANGE_LABELS`.
- Produces:
  - `live.LIVE_LIMIT = 20`.
  - `live.live(request, slug) -> JsonResponse`, `GET` only (`require_GET`). Login comes from the global `LoginRequiredMiddleware`, as for `index`.
    - An unknown slug gives 404 `{'error': 'not found'}`.
    - `since` must match `^\d{1,18}$`, else 400 `{'error': 'bad since'}`.
    - The body is `{'events': [{'id', 'kind', 'label', 'title', 'severity', 'asset', 'created_at': iso}], 'realtime': card, 'poll': LIVE_POLL_SECONDS}`. Events have `id > since` for this project only, ordered by id ascending, at most `LIVE_LIMIT`.
    - It sends `Cache-Control: no-store`.
    - It never calls `project_stats` or `asm_stats`.
  - `overview.js` polling:
    - it does nothing when `#ov_live` is absent or `data-poll` is 0;
    - `setTimeout` chain: it polls only while `document.visibilityState === 'visible'`, polls at once when the page becomes visible after more than `poll` seconds, and backs off ×2 per error up to 300 s, resetting on success;
    - with `fetch(url + '?since=' + since, {credentials: 'same-origin', headers: {'Accept': 'application/json'}})`, it builds each new `<li>` with `createElement` and `textContent` only. The icon class comes from a fixed `kind → class` map in the script, never from the payload;
    - it prepends new rows and keeps at most 6;
    - it un-hides `#live_stale`, which reloads the page;
    - it sets every `[data-rt]` element's `textContent` from the card by dotted path. Ages are formatted by `fmtAge(seconds)`, and None shows as `—`;
    - it swaps the state pill class from a fixed map.

- [ ] **Step 1: Write the failing tests** (`test_overview_live.py`, with the login pattern of `OverviewPageTest`):
  - `test_live_returns_new_events_only_for_project`:
    - events e1 and e2 in `p`, and e3 in `o`;
    - `?since=<e1.id>` gives `[e2]`;
    - `?since=0` gives `[e1, e2]`;
    - `o`'s event never appears;
    - 25 events give 20;
    - the labels come from `CHANGE_LABELS`.
  - `test_since_validated`:
    - `-1`, `abc`, `1e3`, `''` (absent is treated as 0), `9` × 19 and `1 OR 1=1` each give 400, except the absent case;
    - an unknown slug gives 404;
    - a logged-out request redirects to login and returns no JSON.
  - `test_live_does_not_touch_stats`: with `mock.patch('dashboard.stats.asm_stats')`, it is not called, and `CaptureQueriesContext` count `== LIVE_QUERIES`. That is a module constant measured on the finished branch, `# a rise must be justified in review`, and the same with 3 and 30 events.
  - `test_realtime_card_rendered_and_escaped`:
    - the heartbeat summary is `<img src=x onerror=alert(1)>`, and an event title is `New certificate for <img src=x onerror=alert(1)>`, written directly as a hostile row;
    - the page HTML contains `&lt;img src=x onerror=alert(1)&gt;` inside `dash_realtime` and `dash_changes`, and never the raw string;
    - the JSON response carries the raw title as data only (`application/json`);
    - `dash_realtime` shows `Cadence only` with the watch off, and `Degraded` plus the reason label with a stale heartbeat while `CT_WATCH=True`.
  - `test_new_kinds_have_icons`: one event of each new kind renders its icon class.
  - `test_poll_off`: `LIVE_POLL_SECONDS=0` renders `data-poll="0"`.
- [ ] **Step 2: Run** `... test tests.core.test_overview_live`. Expected: FAIL (no URL).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify.**
  - Run `... test tests.core.test_overview_live tests.core.test_overview_page tests.core.test_dashboard_stats`, `node --check web/static/limes/overview.js`, and `tpl.sh`.
  - Then the real UI, with `runserver` on 8765, user `uitest`, and a seed with a fresh heartbeat in Redis plus one event. Run `realtime_ui.js`, with `LIVE_POLL_SECONDS=2` for the run, and confirm each item prints `PASS`:
    - after load, inserting a `ChangeEvent` titled `<img src=x onerror=alert(1)>` makes it appear in `#dash_changes_feed` within 5 s as text. There is no `dialog` event and no `img[src="x"]`;
    - `#live_stale` becomes visible;
    - while hidden (`Page.setWebLifecycleState` frozen, or `document.visibilityState` overridden), no request is made for 6 s;
    - a 500 from the endpoint (route interception) doubles the interval;
    - `[data-rt="queue.depth"]` updates after a Redis change;
    - there are no console errors in light or dark;
    - at a 390 px viewport `scrollWidth <= 390`;
    - screenshots go to `scratchpad/shots-realtime/`. Look at them before continuing.
- [ ] **Step 5: Commit** "Refresh the Overview live and show the Real-time card".

### Task 7: Operator docs, env example, README, final sweep

**Files:**
- Create: `docs/realtime.md`
- Modify:
  - `.env.example`: a commented "Near-real-time" block with every setting from the spec's settings table, plus `LIMES_CT_STATE_DIR`, at its default. Each gets one line of explanation, and the bandwidth and terms lines are copied from the doc.
  - `README.md`:
    - "Status" gains "near-real-time monitoring (opt-in certificate watch, event-driven checks, DNS change detection, live Overview)" under "Built and merged";
    - the deploy notes add `make up REALTIME=1`, `poll_ct_api` on `io` and the `drain-events` tick.
- Test: none new; this is the final sweep.

- [ ] **Step 1: Write `docs/realtime.md`** following the spec's "Operator docs" outline:
  1. What "real time" means: the targets table T1–T6 and what is not real time.
  2. Turning it on: `LIMES_CT_WATCH=true` plus `make up REALTIME=1`; the bandwidth estimate (**about 157 GB/day inbound, inferred**, to be replaced by the measured figure); `HTTPS_PROXY`; the `ct_state` volume; a restart resumes from saved log positions.
  3. The optional Cert Spotter key: the free plan has 10 full-domain queries per hour, and Limes uses 7. Unauthenticated use is "personal or evaluation" only. Cite the URLs.
  4. Reading the Real-time card and each degraded reason, with what to do.
  5. Tuning the queue, cooldown, burst, share and DNS watch.
  6. Privacy: only matches are stored. Name what goes to whom: CT logs see that someone downloads them, not what Limes watches, and SSLMate sees the owned roots only when the API key is used.
- [ ] **Step 2: Run the final sweep:**
  - `verify.sh` (compile, `tests.core`, `check`, `makemigrations --check`, `tpl.sh`);
  - `node --check` on `overview.js`;
  - the Task 6 UI script again;
  - `git ls-files -s web/limes/ct/hook.py` shows mode `100755`.

  Quote your own `Ran N tests` and `OK` lines. `git diff main --stat` shows no file outside this plan's lists.
- [ ] **Step 3: Measure (user-gated).** Ask the user before any of it; only they can provide the test root and approve contacting every CT log.
  - Run `make up REALTIME=1` in the `limes-run` deployment for 24 h.
  - Record certspotter's RX bytes (`docker stats` or `/sys/class/net`), CPU and RSS.
  - Put the numbers in `docs/realtime.md` in place of the inferred figure.
  - Issue a staging-ACME certificate for a root the operator controls, then note the T1 watcher leg from the card.
- [ ] **Step 4: Commit** "Document near-real-time monitoring and update the README status".

---

## Self-review

- **Spec coverage:**

  | Spec requirement | Task |
  |---|---|
  | Event queue: zset, cooldown, cap, idempotency, reason hash, Redis-error fallback, burst cap, counters | 1 |
  | Drain in `monitor._tick`: share, cadence never starved, covered, kept order, 15 s `drain-events`, one drainer | 3 |
  | Precertificate re-check at 1 h and 24 h; `asset_new` after the check, immediate only when exposed | 3 |
  | Triggers: CT new or existing, `asset_new`, manual and Confirm, exposed risky service (≤ 20 hosts), DNS change | 2 (CT), 3 (rest) |
  | DNS delta with the /24 and /48 heuristic; 15-minute crown-jewel watch, DNS only | 3 |
  | certspotter: pinned build, supervisor, argv list, restart rate limit, `-start_at_end`, `-no_save`, state volume | 4 |
  | Hook: stdlib, `-I`, exit 0, 256 KB, 1,000 names, hex filename, tmp then rename, health files | 4 |
  | Spool ingest: schema, rate cap, one transaction per file, `deliver_immediate`, `close_old_connections` | 4 |
  | Heartbeat key and Docker healthcheck | 4 |
  | Watchlist: roots, hosts, lookalikes, PSL guard, cap with owned winning | 4 (uses the Task 2 index) |
  | Match logic 1–8: normalise, classify, upsert, wildcard, existing, lookalike, co-tenant, dedupe | 2 |
  | Hostile data, privacy, no AIA/OCSP fetch | 2, 4, 6 |
  | `CertSighting` model, retention 400 days | 2 |
  | `cert_new` coalescing and new-issuer immediacy (365 days) | 2 |
  | New kinds, labels, digest | 2 |
  | Cert Spotter API fallback: budget, cursor, `Retry-After`, silent baseline, cross-check `api_only` | 5 |
  | Degraded rule, one-time alert, restored to digest | 5 |
  | Live endpoint, polling, visibility, back-off, `aria-live`, reduced motion | 6 |
  | Real-time card contents | 5 (data), 6 (render) |
  | Compose profile, `make up REALTIME=1`, `mem_limit`, no ports | 4 |
  | Settings table and `.env.example` | 1–6 (each its own), 7 |
  | Operator docs and measurement | 7 |

  The non-goals get no task: port scanning, keyword lookalikes, takeover, SSE, a paid feed and backfill.
- **Spec ambiguities resolved:**
  1. **Lookalike hook.** Project 3 made `Lookalike` its own model, not a candidate `Asset`. So the hook detects that model by name and fields, watches the `registered`, `watching` and `reported` rows, and updates only `Lookalike.ct`, instead of `record_fact(candidate)`. Lookalike domains are also kept out of the co-tenant candidate rule.
  2. **Degraded alert.** It is recorded as fan-out rows, one per project, with no nullable project.
  3. **Where health is evaluated.** In `poll_ct_api`, which runs every 60 s with or without a key, because a dead watcher cannot report itself.
  4. **Issuer baseline.** History is seeded from crt.sh's `issuer_name` (valid certificates only) or after 30 days of sightings. The first certificates after turning the watch on therefore cannot all alert.
  5. **API baseline seeding.** The API documents no way to seed `after`, so the baseline pages silently until an empty page, and that also builds the issuer history.
  6. **`cert_new` coalescing key.** It is `(project, asset, immediate)`, so a new-issuer alert is never folded into a digest row.
  7. **Unreached queue items.** They are never removed: they keep their score.
  8. **Two `CertSighting` fields** were added for the `api_only` cross-check: `watch_seen_at` and `api_while_watch_ok`.
- **Decisions beyond the spec:**
  - `ct_watch` lives in `startScan/management/commands`, because `limes` is not an installed app.
  - certspotter is built in the existing `gotools` stage. Go 1.27.1 satisfies `go 1.25.0`.
  - The `ct-watch` service reuses `limes:local`.
  - `monitor_assets` and `age_assets` keep their return shapes.
- **Type consistency:**
  - `enqueue` → `claim_due` gives `(asset_id, reason, enqueued_unix)`, which Task 3 consumes;
  - `ingest(record, source, index, now, seen_at, silent)` is called identically by Tasks 4 and 5;
  - `health.card` is used by Task 6 as defined in Task 5.
