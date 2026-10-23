# Lookalikes, IP Reputation, Exploitability and New Exposure Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Limes finds registered lookalikes of owned roots, checks owned IPs, ranges and ASNs against free blocklists, marks findings with CISA KEV and FIRST EPSS, fingerprints exposed AI services and flags Supabase secret keys in crawled JavaScript. Every new check is *provisional*: it shows up as an issue and can alert, but costs no points, so `limes-score-v3` stays numerically unchanged.

**Architecture:**
- `catalogue.Check` gains `provisional`. `scoring.points(key, severity)` is the one place a penalty is looked up, and `assessed_assets` ignores provisional checks, so the headline and the six scored categories stay bit-identical. Two provisional categories, `reputation` and `data_leakage`, show "Provisional, not scored".
- A small feeds framework (`limes/feeds/`) downloads each feed politely (conditional GET, size cap, strict parse) into `LIMES_RESULTS/feeds/<name>` and tracks it in `FeedState`. `limes/reputation.py` matches owned assets against it (no network), `limes/exploit.py` fills `CveIntel` for CVE ids Limes already holds.
- Exposed-AI probes reuse `safe_fetch.resolve_vetted` + `pinned_get` on ports already known open. The Supabase scan is a pure pass over `code_artifacts/`. HIBP runs only with the operator's key.
- Lookalikes live in their own `Lookalike` table, never `Asset`, so no scan or monitor selector can reach them. `dnstwist.Fuzzer` generates candidates; Limes does its own DNS, RDAP (IANA bootstrap, https only) and crt.sh lookups under daily budgets and a Redis tick lock.

**Tech Stack:** Django 3.2, DRF, Celery beat (IO queue), PostgreSQL behind pgbouncer (transaction pooling), django-redis, dnspython 2.6, requests, tldextract 3.5 (bundled PSL), `dnstwist==20250130` (new, generator only), jQuery/DataTables, puppeteer-core + `/usr/bin/chromium` for the UI check.

**Spec:** `docs/superpowers/specs/2026-10-23-discovery-reputation-design.md` (approved with every recommended default: provisional scoring, keyed and unclear-licence feeds off, no HTTP to lookalikes, blocklist.de and CINS opt-in only).

## Facts verified while planning (2026-10-23)

| Fact | Consequence |
|---|---|
| Spamhaus `drop_v4.json`, `drop_v6.json`, `asndrop.json`: NDJSON, one object per line (`{"cidr","sblid","rir"}` / `{"asn","rir","domain","cc","asname"}`), last line `{"type":"metadata","timestamp","size","records","copyright","terms"}`. `Last-Modified`, no ETag. | Parser keeps the metadata line's timestamp and copyright; the raw file is stored as received, trailer included. |
| SSLBL `sslipblacklist.csv` now holds only a header: "This list has been deprecated on 2025-01-03". | SSLBL is dropped. `rep.listed_c2` uses Feodo Tracker only. |
| abuse.ch Feodo `ipblocklist_recommended.json` answers 200 without an `Auth-Key`; JSON array of `{ip_address, port, status, first_seen, last_online, malware, ...}`; currently 1 entry. | Feodo is on by default; `Auth-Key` is sent only when `LIMES_ABUSECH_AUTH_KEY` is set; an empty Feodo list is valid (`allow_empty`). |
| CISA KEV JSON: `{catalogVersion, dateReleased, count, vulnerabilities:[{cveID, dateAdded, dueDate, knownRansomwareCampaignUse:'Known'|'Unknown', ...}]}`, ETag + Last-Modified, 1.8 MB. CVE numbers can have 6+ digits. | CVE regex is `^CVE-\d{4}-\d{4,7}$`. |
| EPSS `epss_scores-current.csv.gz` answers **302** to a relative `epss_scores-<date>.csv.gz` on the same host; 2.8 MB gzip, 12 MB CSV, ~394k rows; first line `#model_version:…,score_date:…`, then `cve,epss,percentile`. | The feed fetcher follows at most 3 same-host https redirects; the 50 MB cap is on decompressed bytes. |
| IANA `https://data.iana.org/rdap/dns.json`: `services: [[tlds], [urls]]`; 2 services list only `http://` URLs; `.de` is absent. RDAP for `example.com` (Verisign): `events[eventAction=registration].eventDate`, entity with role `registrar` (`vcardArray` `fn`), nested entity with role `abuse` (`email`). | RDAP is https-only; a TLD without an https server gets no RDAP (DNS decides). |
| CINS serves `https://cinsscore.com/list/ci-badguys.txt`. | The opt-in CINS feed uses https (the spec's integrity worry goes away; the terms worry keeps it opt-in). |
| `dnstwist` 20250130 wheel (sha256 `41dbe883…ce2ce34`): single module, no required deps; `pip install --dry-run dnstwist==20250130` in the web image: "Would install dnstwist-20250130". At import it runs `socket.setdefaulttimeout(12.0)` and prints import errors to stderr when `DEBUG` is in the environment. Without the `tld` package its `domain_tld()` split is a heuristic (`foo.github.io` → label `github`). | Import it lazily and restore the socket default; override the Fuzzer's split with tldextract (`intel.domains._EXTRACT`). |
| mantis has no Supabase rule; its `secret-jwt-with-signature` flags every JWT, anon keys included. | The `service_role` decode is Limes's own pass. |

## Global Constraints

- **Django and style:** Django 3.2. 4 spaces in `limes/*`, `dashboard/*.py`, `startScan/*.py`, `api/lookalikes.py` and tests; tabs in `api/views.py`, `api/serializers.py`, `limes/tasks/stages.py`, `dashboard/models.py`, `issues.js`, `asset.js`, `lookalikes.js` and template script blocks; `api/urls.py` is CRLF (edit with `crlf_patch.py` or keep `\r\n`).
- **One new dependency:** `dnstwist==20250130` in `web/requirements.txt` (exact pin). Only `dnstwist.Fuzzer` is used; never `dnstwist.run()`, `Scanner`, `UrlOpener`, `--lsh` or `--phash`.
- **Score model unchanged:** `VERSION = 'limes-score-v3'`, `PENALTY`, `CEILING`, `GRADES`, `MAX_SCORE` stay. For every input, `project_score(p)` with provisional rows equals `project_score(p)` without them, and the six existing category scores are bit-identical. KEV and EPSS never change points.
- **Provisional ids (exactly these 13):** `rep.listed_drop` (3), `rep.listed_asndrop` (3), `rep.listed_c2` (4), `rep.listed_attacker` (2), `rep.dnsbl_listed` (2), `net.exposed_ollama` (3), `net.exposed_openai_api` (3), `net.exposed_triton` (2), `net.exposed_gradio` (2), `net.exposed_jupyter` (4), `net.exposed_ray` (4), `leak.supabase_secret_key` (4), `leak.hibp_breach` (2). Groups: `reputation`, `network`, `data_leakage`.
- **Categories:** `CATEGORIES = ('web', 'tls', 'email', 'dns', 'network', 'vulnerabilities', 'reputation', 'data_leakage')`; labels add `'reputation': 'IP Reputation'`, `'data_leakage': 'Data Leakage'`. No `brand` category (spec Out); Brand is an Overview card.
- **Contact rules:**
  - every automatic contact with an owned target goes through `limes/safe_fetch.py` (`resolve_vetted` then `pinned_get`); no redirects followed;
  - feed and provider fetches never touch targets: `User-Agent: Limes-ASM`, 30 s timeout, at most one download per feed per cadence (Spamhaus DROP/ASN-DROP, KEV, EPSS, blocklist.de, CINS: 24 h; Feodo: 6 h; IANA bootstrap: 7 d);
  - third-party lookalikes get DNS (configured recursive resolver), RDAP and crt.sh only; HTTP only with `LIMES_LOOKALIKE_HTTP=true`;
  - no lookalike ever becomes an `Asset` row or reaches `scope.may_attack`, a scan tool or the monitor.
- **Budgets and locks:** `ratelimit.take_daily` (fails closed), `ratelimit.per_tick`, `ratelimit.reserve`; every beat task holds `continuous.tick_lock(name)` (Redis, never a Postgres advisory lock: pgbouncer runs `POOL_MODE=transaction`); each task is in `celery_routing.TASK_PLAN` on `IO` with `15 * MIN`; 60 s beat entries carry `'options': {'expires': 55}`.
- **Feed terms:** raw feed files stay in `LIMES_RESULTS/feeds/` and are never served by a view, the API, exports or reports; only matches against the project's own assets are shown, each with its credit line: "Contains data from The Spamhaus Project (<date>)", "abuse.ch Feodo Tracker (CC0)", "CISA KEV (CC0)", "EPSS by FIRST.org / Empirical Security", "Have I Been Pwned (CC BY 4.0)" with a link.
- **Hostile data:** feed text, RDAP/vCard strings, certificate names, lookalike domains (IDN included), HTTP titles, JS-extracted URLs and model names are attacker-controlled. Cap strings on write (200 chars unless stated), render only through template autoescape, `asset_esc`/`issue_esc` or `textContent`/`.value`; no `innerHTML`/`.html()`/`|safe` with them. Lookalike domains are text, never links, and are defanged (`example[.]com`) in event titles and chat/webhook text.
- **Secrets:** HIBP, DQS and abuse.ch keys come only from the environment; never logged, never in evidence, events or errors; a DQS key inside a DNS name is redacted from every log line. A found Supabase key is stored only as its shape (`sb_secret_…4f2a`). HTTP errors log the status, never request headers.
- **First runs are silent:** a provisional check's first fresh evaluation in a project, and a root's first lookalike sweep, record rows without events.
- **NOTE comments** name every ceiling (caps, budgets, in-memory matching, per-process caches) and its upgrade path.
- **Settings** go in `limes/settings.py` next to `PTR_DAILY_BUDGET`, and each name (no values for keys) in `.env.example` with a one-line comment.
- **Tests:** `LIMES_DB=<unique name> LIMES_SRC=/home/kali/project/trc/limes-p3 /tmp/claude-1000/-home-kali-project-trc-limes/1272ac93-25ff-41d2-a96c-5b1ecc4bf767/scratchpad/dj.sh test <dotted.path> --noinput`.
  - Each agent uses its own `LIMES_DB`. Before reporting a task done, implementer and reviewer each quote the real `Ran N tests` and `OK` lines from their own `dj.sh test tests.core --noinput` run.
  - No network: every outbound call takes an injectable `get=`, `session=`, `resolve=` or observer (the `Fake` in `test_intel_run.py`, `Get` in `test_monitor.py`). Redis is the scratch fakeredis behind `CACHE_URL`.
- **Commits:** identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`; no AI attribution of any kind; never `--no-verify`; no push.

## Review Focus

1. **A provisional check that scores anyway.** An IP whose only fresh rows are `rep.*` passes must stay unassessed; a host whose worst issue is the critical `leak.supabase_secret_key` must not be capped at 599; `top_penalties`, `waived_count` and `check_coverage` must not move. Task 1 `test_provisional_fail_leaves_headline_identical`, `test_provisional_worst_severity_has_no_ceiling`, `test_ip_with_only_reputation_rows_stays_unassessed`.
2. **A lookalike that becomes scannable or owned.** A user clicks "This is ours", a permutation equals another owned root, or the same name already exists as a candidate `Asset`. No `Asset` row is created, `scope.may_attack` refuses it, no selector returns it. Task 7 `test_lookalike_never_selected_by_pipelines`, `test_owned_roots_never_generated`; Task 8 `test_ours_never_creates_asset`.
3. **Hostile or broken feed data.** A `{"cidr":"0.0.0.0/0"}` line, garbage lines, a 60 MB body, a gzip bomb, an HTML error page with 200, a zero-entry DROP. Limes keeps the last good copy, flags absurd prefixes out, and never marks every IP listed. Task 2 `test_hostile_feed_lines_ignored`, `test_size_cap_and_gzip_bomb`, `test_zero_entry_fetch_rejected_keeps_last_good`.
4. **Double-counted or flooding alerts.** A listed /22 with range enumeration on (1,024 owned IPs under it), the same evaluation run twice, a feed's first evaluation, a root's first sweep of 700 candidates. One issue per listing, no repeat events, silent baselines. Task 3 `test_range_listing_not_repeated_per_ip`, `test_first_evaluation_is_silent_then_alerts`; Task 7 `test_first_sweep_silent`.
5. **Permutation explosion or DNS flood.** A 63-character label, 100 brand keywords, a cache outage (budgets fail closed), a budget spent mid-tick. Candidates stay ≤ 1000 per root and no DNS query runs past the budget. Task 7 `test_long_label_and_many_keywords_capped`, `test_budget_exhaustion_stops_tick`, `test_cache_down_no_dns`.
6. **A Supabase key or a feed/HIBP/DQS key leaking.** The full token or key never appears in `RiskCheck.evidence`, `ChangeEvent`, `Asset.enrichment`, log output or API JSON. Task 6 `test_service_role_jwt_detected_key_never_stored`, `test_scan_artifacts_writes_on_owned_host_only`; Task 3 `test_dqs_key_redacted_in_logs`.
7. **Licence credit missing.** Every feed has a credit and terms URL, and every surface that shows feed-derived data shows the credit. Task 2 `test_every_feed_has_credit_and_terms`; Task 8 `test_attribution_shown_where_data_shown`.

---

### Task 1: Provisional checks, the two new categories, and their "not scored" state

**Files:**
- Modify:
  - `web/limes/checks/catalogue.py`: `Check` gains a defaulted `provisional` field; a `_PROVISIONAL` table with the 13 ids, titles and fixes; `PROVISIONAL`.
  - `web/limes/scoring.py`: `points`, `issue_assets`, `_fresh_checks(…, assets=None)`, `PROVISIONAL_CATEGORIES`, the changes listed under Step 3.
  - `web/limes/alerts/issues.py` `sync_issues`: `passed` uses `scoring._fresh_checks(project, now, assets=scoring.issue_assets(project))`; `assets` loads `id__in=set(issues) | assessed | {a for a, _ in passed}` (a passing cidr/asn row must still close its issue).
  - `web/dashboard/posture.py` `category_cards`: each card gains `'provisional': bool`; `delta_30` is None for provisional cards.
  - `web/dashboard/activity.py` `top_risks`: `'points': scoring.points(key, sev)`, `'provisional': key in PROVISIONAL`.
  - `web/dashboard/templates/dashboard/index.html`: category card branch for provisional; top-risks row shows a `Provisional` tag instead of `−0`.
  - `web/static/limes/limes.css`: `.ov-cat-grid` goes 4 columns (base), 2 (≤1399.98px), 1 (≤575.98px); fix the `nth-child` border rules for 8 cards; `.ov-cat-prov` (dashed outline like `.ov-cat-na`).
  - `web/api/views.py` `IssueList`: each row gains `'provisional': i.key in PROVISIONAL`.
  - `web/startScan/templates/startScan/issues.html`: `f_category` gains `reputation` / `IP Reputation` and `data_leakage` / `Data Leakage`.
  - `web/static/custom/issues.js`: a `Provisional` badge (static text) after the title cell and in the issue detail.
  - `web/static/custom/asset.js` `asset_penalty_rows`: a provisional row shows `Provisional` in place of points.
- Test: new `web/tests/core/test_provisional.py` (reuse `CategoryBase` from `test_category_scores.py`); update `test_risk_checks.py` `CatalogueTest` (SPEC gains the 13), `test_category_scores.py` and `test_overview_page.py` expected dicts (add the two provisional categories; the six existing values do not change).

**Interfaces:**
- Produces:
  - `catalogue.Check = namedtuple('Check', 'id group severity title fix provisional', defaults=(False,))`; `catalogue.PROVISIONAL: frozenset[str]`.
  - `scoring.points(key: str, severity: int) -> int`: 0 when `key in PROVISIONAL`, else `PENALTY.get(severity, 0)`.
  - `scoring._score(categories)`: sums `points(k, s)`; the `CEILING` term uses the worst severity over non-provisional keys only.
  - `scoring._rows(...)`: `'points': points(c, s)`, plus `'provisional': c in PROVISIONAL`.
  - `scoring.issue_assets(project) -> QuerySet[Asset]`: owned (`owned_root`/`owned_host`), non-retired, kind in `('root_domain', 'hostname', 'ip', 'cidr', 'asn')`.
  - `scoring._fresh_checks(project, now=None, assets=None)`: `assets` defaults to `scored_assets(project)`. `_check_penalties` passes `assets=issue_assets(project)`; every other caller keeps the default.
  - `scoring.assessed_assets`: the `checked` set excludes `check_id__in=PROVISIONAL`.
  - `scoring.project_score`: `check_coverage`'s fresh count excludes provisional ids; `top_penalties` and `waived_count` skip provisional keys.
  - `scoring.PROVISIONAL_CATEGORIES = frozenset({'reputation', 'data_leakage'})`, derived: groups whose every check is provisional.
  - `scoring.category_scores(project, now=None)`: every value gains `'provisional': bool`. A provisional category is `{'label', 'score': None, 'grade': 'N/A', 'raw_score': None, 'raw_grade': 'N/A', 'assessed': 0, 'provisional': True}`. Scored categories ignore provisional keys in both `checked` and `split`.
  - `snapshot_scores` stores `None` for the two provisional categories (falls out of `category_scores`).
- Consumed by: Tasks 3–7 (the check ids), Task 8 (cards).

- [ ] **Step 1: Write the failing tests** (`test_provisional.py`):
  - `test_points_and_ids`: `PROVISIONAL` equals the 13 ids of Global Constraints; `points('rep.listed_c2', 4) == 0`; `points('net.exposed_rdp', 3) == 80`; `points('CVE-2021-44228', 3) == 80`; every provisional id's `CHECKS[id].group` is as listed and `category_of` maps it there.
  - `test_provisional_fail_leaves_headline_identical`: `reconcile_project()`; `before = project_score(p)`, `cats = category_scores(p)`, `assessed = assessed_assets(p)`. Add fresh `fail` rows: `rep.listed_c2` on a new owned IP `45.10.1.5` (no other rows), `net.exposed_jupyter` on `a`, `leak.supabase_secret_key` on `b`, `rep.listed_drop` on a new owned `cidr` `45.10.0.0/22`. Then `project_score(p) == before` (whole dict), `assessed_assets(p) == assessed`, `category_scores(p)[c] == cats[c]` for the six original keys, and `category_scores(p)['reputation']` / `['data_leakage']` have `score is None`, `grade == 'N/A'`, `provisional is True`.
  - `test_provisional_worst_severity_has_no_ceiling`: `_score({'leak.supabase_secret_key': 4, 'web.hsts_missing': 2}) == 925`.
  - `test_ip_with_only_reputation_rows_stays_unassessed`: an owned IP with fresh `rep.listed_drop` and `rep.listed_c2` **passes** only: absent from `assessed_assets(p)`; `project_score(p)['unassessed']` and `check_coverage` unchanged.
  - `test_provisional_issues_are_tracked`: after `sync_issues(p)`, `TrackedIssue` rows exist for all four, including the cidr asset; `category_issue_counts(p)['reputation']['open'] == 2`, `['data_leakage']['open'] == 1`, `['network']['open']` includes the jupyter row; then the cidr's row turns `pass` (fresh) and the next `sync_issues` fixes that issue.
  - `test_top_risks_provisional_rows`: a provisional critical and a high finding: `top_risks` lists the high first, the provisional row last with `points == 0` and `provisional is True`.
  - `test_issue_list_flags_provisional`: `GET /api/issues/?project=p` row for the leak issue has `provisional: true`; `?category=data_leakage` returns only it; `?category=reputation` returns both rep rows.
  - `test_overview_provisional_cards` (in `test_overview_page.py`): `cat_reputation` and `cat_data_leakage` contain `Provisional, not scored`, link `?category=reputation` / `?category=data_leakage`, have no `ov-grade-` class; a hostile issue key on them does not reach the HTML unescaped.
- [ ] **Step 2: Run** `… test tests.core.test_provisional --noinput`. Expected: ImportError (`points`) and failures.
- [ ] **Step 3: Implement** with the interfaces above. The 13 catalogue titles end with a period and have one-line fixes (CatalogueTest checks both). The provisional card markup: `<span class="ov-cat-na ov-cat-prov">Provisional, not scored</span>` and the open/waived counts; no trend span.
- [ ] **Step 4: Run** `tests.core.test_provisional tests.core.test_scoring tests.core.test_category_scores tests.core.test_risk_checks tests.core.test_alerts tests.core.test_issue_api tests.core.test_overview_page tests.core.test_overview_activity tests.core.test_waivers`, then `node --check web/static/custom/issues.js web/static/custom/asset.js`, `tpl.sh`. Expected: OK.
- [ ] **Step 5: Commit** "Add provisional checks that show as issues but cost no points".

### Task 2: Data model and the feeds framework

**Files:**
- Create:
  - `web/startScan/intel_models.py`: `FeedState`, `CveIntel`, `Lookalike`, `DomainBreach` (all new models of this project, so one migration). `web/startScan/models.py` ends with `from startScan.intel_models import *  # noqa: E402,F401,F403` after the `asset_models` import. Then `makemigrations startScan -n feeds_lookalikes` → `0028_feeds_lookalikes.py`.
  - `web/limes/feeds/__init__.py` (empty), `sources.py`, `parse.py`, `store.py`, `tasks.py`.
  - `web/tests/core/fixtures/feeds/`: `drop_v4.json` (3 entries + metadata line), `drop_v6.json`, `asndrop.json`, `feodo.json`, `kev.json` (3 entries), `epss.csv.gz` (5 rows + `#model_version` line), `iana_dns.json` (com https, `kg` http-only), `blocklist.txt`. Values are invented; shapes match the facts table.
- Modify: `web/limes/settings.py` (`FEEDS_OPTIN = env.list('LIMES_FEEDS_OPTIN', default=[])`, `ABUSECH_AUTH_KEY = env('LIMES_ABUSECH_AUTH_KEY', default='')`; `CELERY_IMPORTS` += `'limes.feeds.tasks'`; beat `'refresh-feeds': {'task': 'refresh_feeds', 'schedule': 3600.0, 'options': {'expires': 3300}}`), `web/limes/celery_routing.py` (`'refresh_feeds': (IO, 15 * MIN)`), `.env.example`.
- Test: `web/tests/core/test_feeds.py`

**Interfaces:**
- Produces (models; strings capped as stated):
  - `FeedState(name CharField(64, unique), url CharField(500), fetched_at DateTimeField(null), last_good_at DateTimeField(null), source_date DateTimeField(null), etag CharField(200, blank), last_modified CharField(100, blank), sha256 CharField(64, blank), entries IntegerField(default=0), status CharField(16, default='never'), error CharField(300, blank))`. `status` ∈ `never|ok|not_modified|error|rejected`. `source_date` (the feed's own timestamp) is an addition to the spec's field list: `rep.*` evidence needs it.
  - `CveIntel(cve CharField(20, unique), epss FloatField(null), percentile FloatField(null), epss_date DateField(null), kev BooleanField(default=False), kev_added DateField(null), kev_due DateField(null), kev_ransomware BooleanField(null), updated_at DateTimeField(default=now))`.
  - `Lookalike(project FK Project CASCADE, root FK Asset CASCADE related_name='lookalikes', domain CharField(253) ascii/punycode, unicode CharField(253), fuzzers JSONField(list), source CharField(12) 'permutation'|'ct', status CharField(12, default='unchecked'), registered BooleanField(null), dns JSONField(dict) {ns,a,aaaa,mx}, has_mx BooleanField(default=False), rdap JSONField(dict) {registrar, created, abuse_email, statuses}, ct JSONField(dict) {count, first_seen, last_seen, ids}, http JSONField(null), first_seen, last_checked(null), next_check DateTimeField(default=now, db_index=True), rdap_checked_at(null), ct_checked_at(null), decided_by FK User SET_NULL null, decided_at(null), reported_at(null), note TextField(blank))`, `unique_together = ('project', 'domain')`. Statuses: `unchecked`, `unregistered`, `registered`, `gone` (automatic); `watching`, `ignored`, `ours`, `reported` (decisions). `rdap_checked_at`, `ct_checked_at` and `reported_at` add the timestamps the spec's cadences and "reported, with its date" need.
  - `DomainBreach(project FK, root FK Asset CASCADE, breach_name CharField(100), addresses IntegerField, breach_date DateField(null), published DateTimeField(null), first_seen DateTimeField(default=now))`, `unique_together = ('root', 'breach_name')`.
  - `sources.Feed = namedtuple('Feed', 'name url cadence parser credit terms optin allow_empty')`; `sources.FEEDS: dict[str, Feed]` with `drop_v4`, `drop_v6`, `asndrop` (24 h), `feodo` (6 h, `allow_empty=True`), `kev`, `epss` (24 h), `iana_rdap` (7 d), `blocklist_de`, `cins` (24 h, `optin=True`, `allow_empty=True`), URLs from the spec and the facts table; `sources.enabled(feed) -> bool` (`not feed.optin or feed.name in settings.FEEDS_OPTIN`); `sources.REPUTATION = ('drop_v4', 'drop_v6', 'asndrop', 'feodo', 'blocklist_de', 'cins')`.
  - `parse.PARSERS: dict[str, Callable[[bytes], tuple[data, meta]]]`; every `meta` has `'rows': int` (valid entries) and `'dropped': int`; `source_date` where the feed has one.
    - `spamhaus_drop(blob) -> ([(network: str, sblid: str)], meta + {'source_date', 'copyright'})`: drops non-JSON lines, invalid CIDRs, sblid not matching `^SBL\d{1,10}$`, and prefixes shorter than `/8` (v4) or `/16` (v6) (`# NOTE: a whole-internet entry would list every owned IP; real DROP entries are far narrower`).
    - `spamhaus_asndrop(blob) -> ([(asn: int, asname: str[:100])], meta)`: `1 <= asn < 2**32`.
    - `feodo(blob) -> ([ip: str], meta)`; `plain_ips(blob) -> ([ip: str], meta)` (blocklist.de, CINS: skip `#` lines; one public IP per line).
    - `kev(blob) -> ({cve: {'added': date|None, 'due': date|None, 'ransomware': bool}}, meta + {'source_date'})`.
    - `epss(blob, wanted: set | None = None) -> ({cve: (epss: float, percentile: float)}, meta + {'source_date', 'model_version'})`: streams the gzip; `rows` counts every valid row; `data` holds only `wanted` ids (empty dict when `wanted` is None); values outside `[0, 1]` are dropped.
    - `rdap_bootstrap(blob) -> ({tld: https_base_url}, meta)`: only `https://` URLs; tld lowercased ASCII.
    - `CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')`; `norm_cve(value) -> str | None` (strip, upper, match).
  - `store.MAX_BYTES = 50 * 1024 * 1024`; `store.feed_path(name) -> str` (`os.path.join(settings.LIMES_RESULTS, 'feeds', name)`).
  - `store.fetch(feed, now, session=requests) -> str`: one conditional GET (`If-None-Match`, `If-Modified-Since` from `FeedState`), `Auth-Key` only for `abuse.ch` hosts when `ABUSECH_AUTH_KEY` is set, at most 3 same-host https redirects, `stream=True`, bytes capped at `MAX_BYTES` (gzip checked after decompression, read in chunks), parse, then: 304 → `not_modified`; non-200 or a parser exception → `error` (`error = f'HTTP {status}'` or the exception class name; never headers); `rows == 0 and not feed.allow_empty` → `rejected`; else write atomically (`<path>.tmp` + `os.replace`), store `sha256`, `entries`, `etag`, `last_modified`, `source_date`, `last_good_at = now`, `ok`. Always sets `fetched_at = now`. Returns the status.
  - `store.read(name) -> bytes | None`; `store.load(name) -> tuple[data, meta] | None` memoized per process by `(name, sha256)` (`# NOTE: one parsed copy per feed per worker process; EPSS is never loaded this way (read + parse(wanted)). Upgrade path: a shared cache`).
  - `store.is_stale(feed, state, now) -> bool`: no `last_good_at`, or older than `3 * feed.cadence`.
  - `store.due(feed, state, now) -> bool`: never fetched, or `fetched_at <= now - feed.cadence`.
  - `tasks.refresh_feeds()` (Celery `refresh_feeds`): skips when `not settings.CONTINUOUS_SCANS`; inside `tick_lock('refresh_feeds')` fetches each enabled, due feed; returns `{'fetched': [...], 'changed': [names with status ok]}`. Tasks 3 and 4 add their follow-ups.

- [ ] **Step 1: Write the failing tests** (`test_feeds.py`, `FakeSession` returning `(status, headers, body)` per URL and recording request headers):
  - `test_parsers_on_fixtures`: DROP v4 gives 3 `(network, sblid)` pairs, `source_date` from the metadata timestamp, `copyright` text; ASN-DROP ints; Feodo IPs; KEV `ransomware` True for `Known`; EPSS with `wanted={'CVE-2021-44228'}` returns one id and `rows == 5`; IANA keeps `com`, drops `kg`.
  - `test_hostile_feed_lines_ignored`: DROP lines `{"cidr":"0.0.0.0/0","sblid":"SBL1"}`, `{"cidr":"::/0"}`, `not json`, `{"cidr":"999.1.1.1/24"}`, `{"cidr":"1.2.3.0/24","sblid":"<script>"}`, a 1 MB line → none kept, `dropped == 6`; KEV `cveID` `"CVE-2021-1"` and `"cve-2021-44228 "` → only the normalized second.
  - `test_conditional_get_and_not_modified`: second fetch sends `If-None-Match` / `If-Modified-Since` from the first response; a 304 leaves the file and `last_good_at` unchanged and returns `not_modified`.
  - `test_zero_entry_fetch_rejected_keeps_last_good`: good DROP, then a 200 with only the metadata line → `rejected`, file bytes and `entries` unchanged; Feodo `[]` → `ok` with `entries == 0`.
  - `test_size_cap_and_gzip_bomb`: a 51 MB body → `error`; a gzip that inflates past `MAX_BYTES` → `error` without reading it all (count chunks read); old file intact.
  - `test_epss_redirect_same_host_only`: 302 to `epss_scores-2026-10-22.csv.gz` is followed; 302 to `https://evil.example/x` → `error`, no request to it.
  - `test_error_never_logs_headers`: with `ABUSECH_AUTH_KEY='k-secret'`, a 500 from Feodo logs `HTTP 500`; `k-secret` appears in no log record and not in `FeedState.error`; the key is sent only to abuse.ch URLs.
  - `test_due_and_stale`: DROP fetched 23 h ago is not due, 24 h is; `is_stale` false at 71 h, true at 73 h, true when never good.
  - `test_refresh_respects_optin_and_lock`: default settings fetch the seven default feeds once and never `blocklist_de`/`cins`; `FEEDS_OPTIN=['cins']` adds CINS; a second call in the same hour fetches nothing; holding `tick_lock('refresh_feeds')` → `{'reason': 'locked'}`.
  - `test_every_feed_has_credit_and_terms`: every `Feed` has a non-empty `credit` and an `https://` `terms` URL; `drop_*` credit contains `The Spamhaus Project`.
  - `test_beat_and_routing` (`SimpleTestCase`): beat entry, `TASK_PLAN['refresh_feeds'] == (IO, 15 * MIN)`, `'limes.feeds.tasks' in CELERY_IMPORTS`.
  - `test_models_constraints`: `Lookalike` unique on `(project, domain)`; `DomainBreach` unique on `(root, breach_name)`.
- [ ] **Step 2: Run** `tests.core.test_feeds`. Expected: ImportError.
- [ ] **Step 3: Implement.** The feed fetch uses `requests` directly (it needs headers, streaming and redirects that `intel.http.get_json` does not do), with `HEADERS = {'User-Agent': 'Limes-ASM'}`. `.env.example` gains a "Reputation feeds" block naming `LIMES_FEEDS_OPTIN` (comment: "blocklist_de,cins: terms unclear, off by default") and `LIMES_ABUSECH_AUTH_KEY` (empty).
- [ ] **Step 4: Run** `tests.core.test_feeds`, then `makemigrations --check --dry-run`. Expected: OK, `No changes detected`.
- [ ] **Step 5: Commit** "Add the feed store and the models for lookalikes, CVE intel and breaches".

### Task 3: IP reputation checks

**Files:**
- Create: `web/limes/reputation.py`
- Modify:
  - `web/limes/checks/run.py`: the IP branch of `run_checks` and `run_asset_checks` appends `reputation.evaluate_asset(asset, now)` (no DQS; no network).
  - `web/limes/feeds/tasks.py`: after fetching, call `reputation.evaluate_reputation(now)` when a `REPUTATION` feed changed or `cache.get('limes:reputation:evaluated')` is unset (set it for 24 h after a run; `# NOTE: a cache flush only causes one extra evaluation`).
  - `web/limes/alerts/events.py` `is_immediate`: `issue_new` / `issue_regressed` with a `rep.` key are immediate at any severity.
  - `web/limes/alerts/issues.py` `sync_issues`: a new `TrackedIssue` whose key is a provisional check id is silent while `f'check:{key}'` is not in `state.roots`; after the loop, add `check:<id>` for every provisional id with a fresh `pass`/`fail` row in the project (from the `passed` set and `issues`).
  - `web/limes/settings.py`: `SPAMHAUS_DQS_KEY = env('LIMES_SPAMHAUS_DQS_KEY', default='')`; `.env.example`.
  - `web/static/custom/asset.js`: `asset_reputation_html(checks)`: a "Reputation" section listing failing `rep.*` rows (feed, entry, listed since, credit), placed before Risk checks.
- Test: `web/tests/core/test_reputation.py`; `test_alerts.py` `ImmediacyTest` gains the `rep.` cases.

**Interfaces:**
- Consumes: `store.load`, `store.is_stale`, `sources.FEEDS/enabled` (Task 2); `run._write`; `CHECKS`; `sync_issues`, `deliver_immediate`, `dashboard.stats.invalidate`.
- Produces:
  - `reputation.Index`: built by `reputation.index(now) -> Index` once per run: sorted `(first_int, last_int, network, sblid, feed)` per IP version for DROP, `{asn: asname}`, `{ip: feed}` for C2 and for attacker lists, `stale: {check_id: bool}`, `meta: {feed: {'source_date', 'fetched_at', 'credit'}}`. `# NOTE: the whole index lives in memory per run (DROP ~2k networks, ASN-DROP ~500); IP lookups bisect, cidr overlap scans the DROP list. Upgrade path: PostgreSQL inet/cidr columns and GiST.`
  - `reputation.evaluate_asset(asset, now, idx=None, dqs=None) -> list[Result]`:
    - ip: `rep.listed_drop`, `rep.listed_c2`; `rep.listed_attacker` only when `blocklist_de` or `cins` is enabled; `rep.dnsbl_listed` only when `dqs` is given.
    - cidr: `rep.listed_drop` (any overlap). asn (`AS<n>`): `rep.listed_asndrop`.
    - An IP covered by an owned, non-retired `cidr` asset of its project that is listed by the same DROP entry gets `not_applicable` with `{'covered_by': '<cidr>'}`: one issue per listing.
    - A stale or never-fetched source → `error` `{'reason': 'feed data older than 3 x its cadence'}`, never `pass`.
    - Fail evidence: `{'feed': name, 'entry': '<cidr> SBL…' | 'AS<n> <asname>' | ip, 'listed_at': source_date iso | None, 'fetched_at': iso, 'credit': feed.credit}`.
  - `reputation.dqs_lookup(ip: str, key: str, resolve=collect._resolve) -> tuple[str, str | None]`: queries `A` for `<reversed-octets>.<key>.zen.dq.spamhaus.net`; `('listed', code)` for `127.0.0.0/24` except `127.255.255.x`; `('clean', None)` on NXDOMAIN; `('error', code_or_class)` for `127.255.255.254/255`, timeouts and anything else. IPv6 → `('error', 'ipv6 not supported')` (`# NOTE: ZEN over DQS for IPv6 uses nibble format; upgrade path`). Every message passes through `reputation.redact(text, key)`.
  - `reputation.evaluate_reputation(now=None) -> {'checked': int, 'projects': int}`: one `index(now)`; every owned non-retired ip/cidr/asn asset of every project; DQS for an IP only when `SPAMHAUS_DQS_KEY` is set, its last `rep.dnsbl_listed` row is older than 24 h, and `ratelimit.take_daily('dqs', DQS_DAILY_BUDGET)` allows it (`DQS_DAILY_BUDGET = 5000`, NOTE). Writes via `run._write`, then `sync_issues`, `deliver_immediate` and `invalidate` per touched project (each guarded like `owned_ranges._tick`).

- [ ] **Step 1: Write the failing tests** (`test_reputation.py`; feed files written into a temp `LIMES_RESULTS` with `override_settings`, `FeedState` rows set by hand):
  - `test_drop_overlap_ip_and_cidr`: DROP `45.10.0.0/22 SBL1` and v6 `2a0d:1000::/32 SBL2`: IP `45.10.1.5` fails with `entry` containing `SBL1`; IP `45.11.0.1` passes; cidr `45.10.2.0/24` (inside) and `45.8.0.0/14` (contains) fail; cidr `46.0.0.0/24` passes; IP `2a0d:1000::5` fails.
  - `test_asndrop_matches_asn_assets`: ASN-DROP 12345 → `AS12345` fails with the asname; `AS1` passes.
  - `test_c2_listing`: Feodo lists `45.12.0.9` → `rep.listed_c2` fail, severity 4; credit `abuse.ch`.
  - `test_stale_feed_gives_error`: DROP `last_good_at = now - 73h` → `rep.listed_drop` `error`; never fetched → `error`; Feodo fresh still decides `rep.listed_c2`.
  - `test_optin_feed_off_writes_no_row`: no `rep.listed_attacker` row by default; with `FEEDS_OPTIN=['blocklist_de']` and a listing → fail, severity 2.
  - `test_range_listing_not_repeated_per_ip`: owned cidr `45.10.0.0/24` listed, 3 owned child IPs under it → one `fail` (the cidr), IPs `not_applicable` with `covered_by`; after `sync_issues`, one open `rep.listed_drop` issue.
  - `test_first_evaluation_is_silent_then_alerts`: a synced project (`IssueSyncState` with `#ips`), a listed IP: first `evaluate_reputation()` creates the issue and no `ChangeEvent`; a second run creates nothing new; then a new owned listed IP → one `issue_new` event with `immediate=True`; a third run → still one.
  - `test_dqs_codes`: fake `resolve` returning `['127.0.0.2']` → listed; NXDOMAIN → clean; `['127.255.255.254']` and `['127.255.255.255']` → error; `dns.exception.Timeout` → error; IPv6 → error; the queried name ends with `.zen.dq.spamhaus.net`.
  - `test_dqs_key_redacted_in_logs`: key `dqs-secret-123`; `resolve` raises `dns.exception.DNSException(f'no answer for 4.3.2.1.dqs-secret-123.zen.dq.spamhaus.net')`; under `assertLogs('limes.reputation')`, no record and no stored evidence contains `dqs-secret-123`.
  - `test_dqs_daily_and_budget`: a row checked 2 h ago is not re-queried; `take_daily` False → no query, row unchanged.
  - `test_monitor_ip_check_writes_rep_rows`: `run.run_asset_checks(ip)` (observers as in `test_monitor.py`) writes `rep.listed_drop`, no DNS query.
  - `ImmediacyTest`: `is_immediate('issue_new', 'rep.listed_attacker', 2)` and `('issue_regressed', 'rep.listed_drop', 3)` are True; `('issue_fixed', 'rep.listed_drop', 3)` is False.
- [ ] **Step 2: Run** `tests.core.test_reputation tests.core.test_alerts`. Expected: ImportError, immediacy False.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests.core.test_reputation tests.core.test_alerts tests.core.test_monitor tests.core.test_risk_checks tests.core.test_provisional tests.core.test_feeds`, `node --check web/static/custom/asset.js`. Expected: OK.
- [ ] **Step 5: Commit** "Check owned IPs, ranges and ASNs against Spamhaus DROP and Feodo".

### Task 4: Exploitability markers (KEV and EPSS)

**Files:**
- Create: `web/limes/exploit.py`
- Modify:
  - `web/limes/feeds/tasks.py`: call `exploit.refresh_cve_intel(now)` when `kev` or `epss` changed or the `limes:cve_intel:refreshed` cache stamp (24 h) is unset.
  - `web/dashboard/activity.py` `top_risks`: rows gain `'cves': [str]`, `'kev': bool`, `'epss': float | None`, `'percentile': float | None`; sort key `(-points, not kev, -(epss if epss is not None else -1), detected is None, detected or now, asset, key)`.
  - `web/dashboard/templates/dashboard/index.html`: top-risks row shows `<span class="ov-tag ov-kev">KEV</span>` and EPSS `{{ r.epss|floatformat… }}%`; meta line "Ties: known exploited, then EPSS".
  - `web/api/views.py` `IssueList`: rows gain `cves: [{cve, kev, epss, percentile}]`, `kev`, `epss`; `?kev=true` keeps rows with `kev` (filtered in Python after the two extra queries); `AssetDatatableViewSet.retrieve` adds `unverified_cves` for `kind == 'ip'`.
  - `web/api/serializers.py` `VulnerabilitySerializer`: `cve_intel = SerializerMethodField()` → `{name: {kev, epss, percentile}}`, filled for the whole page in one query on first call (memo on `self.root`).
  - `web/startScan/templates/startScan/issues.html`, `web/static/custom/issues.js`: a `f_kev` select ("Any" / "Known exploited") added to both key lists; KEV and EPSS columns; issue detail lists CVE ids with both markers; footnote "CISA KEV (CC0) · EPSS by FIRST.org / Empirical Security".
  - `web/startScan/templates/startScan/vulnerabilities.html`: a `KEV` badge and `EPSS n%` badge beside each CVE badge (`htmlEncode`).
  - `web/static/custom/asset.js`: `asset_unverified_cves_html(rows)`: section "Unverified CVEs (InternetDB banner)" with the note "Banner match, not verified, not scored".
  - `web/tests/core/test_overview_page.py`: re-measure `OVERVIEW_QUERIES` (+2: CVE join and `CveIntel`); say so in the commit body.
- Test: `web/tests/core/test_exploit.py`

**Interfaces:**
- Consumes: `parse.kev`, `parse.epss(blob, wanted)`, `parse.norm_cve`, `store.read`, `store.load` (Task 2); `CveIntel`.
- Produces:
  - `exploit.held_cves() -> set[str]`: normalized `CveId.name` values ∪ `enrichment.internetdb.vulns` of owned, non-retired ip assets.
  - `exploit.refresh_cve_intel(now=None) -> {'updated': int, 'created': int}`: KEV and EPSS for held ids only; existing rows `bulk_update`, new rows `bulk_create` in batches of 1000 (`# NOTE: Django 3.2 has no upsert; two passes`). An id that leaves KEV gets `kev=False`.
  - `exploit.markers(names: Iterable[str]) -> dict[str, {'kev': bool, 'epss': float | None, 'percentile': float | None, 'kev_ransomware': bool | None}]` (one query; unknown ids absent).
  - `exploit.issue_cves(project, pairs: Iterable[tuple[int, str]]) -> dict[tuple[int, str], list[str]]`: for finding keys only, one query over open `Vulnerability` rows of those assets (`template_id or name` → `scoring.issue_key`) joined to `cve_ids__name`, normalized, sorted.
  - `exploit.summary(cves, marks) -> {'kev': bool, 'epss': float | None, 'percentile': float | None}` (max EPSS, its percentile).
  - `exploit.unverified(asset) -> list[{cve, kev, epss, percentile}]`: valid ids from `enrichment.internetdb.vulns`, at most 200, KEV first then EPSS desc.

- [ ] **Step 1: Write the failing tests** (`test_exploit.py`):
  - `test_refresh_only_held_ids`: `CveId(name='cve-2021-44228')` on a vuln, InternetDB `vulns: ['CVE-2023-48022']` on an owned IP; KEV fixture holds 44228 (`Known`) and `CVE-1999-0001`; EPSS has all three. After refresh: exactly two `CveIntel` rows; 44228 `kev True`, `kev_ransomware True`; 48022 `kev False` with its EPSS; 1999-0001 absent. A second refresh after 44228 leaves KEV sets `kev False`.
  - `test_hostile_cve_strings_ignored`: `CveId` names `<script>`, `CVE-2021-1`, `CVE-2021-44228<b>` store nothing.
  - `test_top_risks_kev_epss_tiebreak`: a critical with no CVE; three highs A (no CVE), B (EPSS 0.5), C (KEV, EPSS 0.1) → order critical, C, B, A; `points == [200, 80, 80, 80]`; `project_score(p)` identical before and after the `CveIntel` rows exist.
  - `test_issue_list_markers_and_kev_filter`: the C row has `kev true`, `cves[0].cve == 'CVE-…'`; `?kev=true` returns only C; `?kev=bogus` returns all.
  - `test_unverified_cves_on_ip_detail`: InternetDB `vulns: ['CVE-2021-44228', 'junk<b>']` → `unverified_cves == [{'cve': 'CVE-2021-44228', 'kev': True, …}]`; the asset's `risk` is unchanged.
  - `test_vulnerability_api_carries_markers`: the vulnerabilities list JSON has `cve_intel['CVE-2021-44228']['kev'] is True`, with a constant query count for 2 versus 20 vulns.
- [ ] **Step 2: Run** `tests.core.test_exploit`. Expected: ImportError.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests.core.test_exploit tests.core.test_issue_api tests.core.test_overview_activity tests.core.test_overview_page tests.core.test_feeds`, `node --check` on `issues.js` and `asset.js`, `tpl.sh`. Expected: OK.
- [ ] **Step 5: Commit** "Mark findings with CISA KEV and EPSS and break Top-risk ties with them".

### Task 5: Exposed AI services

**Files:**
- Create: `web/limes/checks/ai.py` (pure evaluator)
- Modify:
  - `web/limes/checks/catalogue.py`: `AI_PORTS` and `MAX_AI_PORTS = 6`.
  - `web/limes/checks/collect.py`: `observe_ai`, `BODY_CAP = 256 * 1024`.
  - `web/limes/checks/run.py`: `_ip_checks(asset, now, obs, observers) -> list[Result]` used by both IP branches: network + reputation (Task 3) + AI.
  - `web/dashboard/posture.py` `exposure`: rows on an `AI_PORTS` port gain `'ai': True` and the service name; the template adds an `AI` tag.
- Test: `web/tests/core/test_ai_checks.py`

**Interfaces:**
- Produces:
  - `catalogue.AI_PORTS = {11434: ('ollama',), 8000: ('openai_api', 'triton'), 7860: ('gradio',), 8888: ('jupyter',), 8265: ('ray',), 4000: ('openai_api',), 1234: ('openai_api',)}` (4000 LiteLLM, 1234 LM Studio: both documented OpenAI-compatible defaults).
  - `ai.FINGERPRINTS = {'ollama': '/api/tags', 'openai_api': '/v1/models', 'triton': '/v2', 'gradio': '/config', 'jupyter': '/api', 'ray': '/api/version'}`. Triton uses the KServe v2 server-metadata path `/v2` (`{"name": "triton", …}`) rather than `/v2/health/ready`, whose empty 200 cannot be told from a catch-all server.
  - `collect.observe_ai(ip: str, ports: Iterable[int], get, ua: str) -> {port: {service: {'status': int | 'error' | None, 'json': object | None, 'second': {...} | None}}}`: the lowest `MAX_AI_PORTS` open ports in `AI_PORTS`; one `GET http://<ip>:<port><path>` per (port, service) with `headers={'User-Agent': ua}`, `allow_redirects=False`, `stream=True`, `timeout=TIMEOUT`; body read through `iter_content` up to `BODY_CAP`, JSON-decoded or None; Jupyter adds `GET /api/kernels` only when `/api` returned JSON with `version`. Connection refused → None; timeout/other request error → `'error'`.
  - `ai.evaluate(obs, complete: bool) -> list[Result]` for the six ids, in catalogue order:
    - `fail` when a probe matched unauthenticated: Ollama `models` list; OpenAI-compatible 200 with `data` list; Triton JSON `name == 'triton'`; Gradio JSON with `version` and `components`; Jupyter `/api/kernels` 200; Ray JSON with `ray_version` or `version`.
    - `pass` when the service answered with 401/403 on its path (Jupyter: on `/api/kernels`).
    - `error` when a relevant probe returned `'error'`, or no relevant port was seen and `complete` is False.
    - `not_applicable` otherwise.
    - Evidence `{'port', 'path', 'status', 'version': str[:50] | None, 'models': int | None}`; never model names or bodies.
  - `run._ip_checks`: when an AI port is open, `ip, reason = safe_fetch.resolve_vetted(asset.value)` (IP literal; no DNS); refused → the six AI ids get `error` `{'reason': reason}`; else `get = safe_fetch.pinned_get(ip, ip, deadline=safe_fetch.Deadline())`, UA `identity.DEFAULT_UA`. Observers may inject `'ai'`. Never `scope.may_attack`, never a scan tool.

- [ ] **Step 1: Write the failing tests** (`test_ai_checks.py`, a `Get` recording URLs and kwargs, responses with `iter_content`):
  - `test_only_known_open_ai_ports_probed`: ports `{22, 11434, 8888, 9999}` → calls only `http://45.1.1.1:11434/api/tags` and `:8888/api` (+ `/api/kernels` when `/api` has `version`); every call had `allow_redirects=False` and only a `User-Agent` header. No AI port open → zero calls; results `not_applicable` when complete, `error` when not.
  - `test_ollama_unauthenticated_fails_with_count_only`: `{'models': [{'name': 'llama3:<script>'}] * 3}` → fail, evidence `{'port': 11434, 'path': '/api/tags', 'status': 200, 'version': None, 'models': 3}`; `llama3` not in `json.dumps(evidence)`.
  - `test_openai_api_auth`: 401 → pass; 200 `{'object': 'list', 'data': [{}, {}]}` → fail with `models == 2`; 200 HTML → not_applicable.
  - `test_jupyter_needs_second_get`: `/api` `{'version': '2.14.0'}` + `/api/kernels` 403 → pass; + 200 `[]` → fail; `/api` HTML → not_applicable and no second call.
  - `test_triton_gradio_ray_fingerprints`: one fail case and one look-alike non-match each (`/v2` `{"name": "other"}`, `/config` without `components`, `/api/version` HTML).
  - `test_body_cap`: a 10 MB streamed body stops reading at `BODY_CAP` (count bytes yielded) → not_applicable, no exception.
  - `test_at_most_six_ports`: all 7 AI ports open → the 6 lowest probed.
  - `test_probe_goes_through_safe_fetch`: owned IP `10.0.0.5` with port 11434 → `resolve_vetted` refuses, no `pinned_get`, the six rows `error`; a public IP → `pinned_get` built with `(ip, ip)`.
  - `test_ai_issue_is_immediate`: `is_immediate('issue_new', 'net.exposed_ollama', 3)` True (existing prefix rule, no code change).
  - `test_exposure_marks_ai_ports`: InternetDB `ports: [11434]` → exposure row `ai True`, service `ollama`.
- [ ] **Step 2: Run** `tests.core.test_ai_checks`. Expected: ImportError.
- [ ] **Step 3: Implement.** `# NOTE: plain HTTP only: an IP has no hostname to verify a certificate against. Upgrade path: probe https with the IP's PTR or CT name once safe_fetch can pin a verified name.`
- [ ] **Step 4: Run** `tests.core.test_ai_checks tests.core.test_risk_checks tests.core.test_monitor tests.core.test_safe_fetch tests.core.test_overview_posture tests.core.test_reputation`. Expected: OK; `test_risk_checks` passes with unchanged assertions apart from `CatalogueTest`.
- [ ] **Step 5: Commit** "Fingerprint exposed AI services on known-open ports of owned IPs".

### Task 6: Data leakage: Supabase secret keys in crawled JavaScript, optional HIBP

**Files:**
- Create: `web/limes/checks/leak.py`, `web/limes/hibp.py`
- Modify:
  - `web/limes/tasks/stages.py` `code_audit`: after reading `mapping`, before the mantis `try`, call `leak.scan_artifacts(f'{self.results_dir}/code_artifacts', mapping, self.domain.project, timezone.now())` inside its own `try/except Exception` (logged, never raised; tabs).
  - `web/limes/alerts/events.py`: `KINDS` += `'breach_new'` (digest only); `web/dashboard/stats.py` `CHANGE_LABELS['breach_new'] = 'New breach'`; an icon branch in `index.html`.
  - `web/limes/intel/http.py` `get_json`: add `headers=None` (merged over `HEADERS`) and `max_wait=None` (a reserved slot further away than `max_wait` returns `(None, None)` without sleeping).
  - `web/limes/settings.py`: `HIBP_API_KEY = env('LIMES_HIBP_API_KEY', default='')`; `CELERY_IMPORTS` += `'limes.hibp'`; beat `'hibp-sync': {'task': 'hibp_sync', 'schedule': 86400.0}`; `celery_routing`: `'hibp_sync': (IO, 15 * MIN)`; `.env.example`.
  - `web/static/custom/asset.js`: the asset detail shows `enrichment.backends` ("Backends referenced by client code, informational") and, for roots, breach rows with "Breach data: Have I Been Pwned (CC BY 4.0)" linking `https://haveibeenpwned.com/`.
  - `web/api/views.py` `AssetDatatableViewSet.retrieve`: `breaches` (`DomainBreach` rows of that root: name, addresses, breach_date, published) for `root_domain` assets.
- Test: `web/tests/core/test_leak.py`; `test_intel_http.py` gains the two `get_json` kwargs.

**Interfaces:**
- Produces:
  - `leak.SB_SECRET_RE = re.compile(r'\bsb_secret_[A-Za-z0-9_-]{16,}')`; `leak.JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')`.
  - `leak.shape(token: str, kind: str) -> str`: `'sb_secret_…' + token[-4:]` or `'JWT(service_role)…' + token[-4:]`.
  - `leak.scan_text(text: str) -> {'secrets': [{'kind': 'sb_secret' | 'jwt_service_role', 'shape': str}], 'backends': [{'kind': 'supabase' | 'firebase' | 's3', 'ref': str[:200]}]}`: a JWT counts only when its base64url-decoded payload is a JSON object with `role == 'service_role'`; decode errors are skipped; at most 20 backends.
  - `leak.scan_artifacts(art_dir, mapping, project, now) -> {'hosts': int, 'secrets': int}`: for each mapped `.js`/`.map` file (read at most 5 MB), `host = scope.target_host(source_url)`; only an owned, non-retired `hostname`/`root_domain` asset of the project with that exact value is used (`# NOTE: a key in JS served from a third-party CDN host is not attributed. Upgrade path: attribute by the page that loaded it`). Per asset: `leak.supabase_secret_key` `fail` `{'artifact_url': url[:500], 'key_shape': shape, 'kind': kind}` when any secret, else `pass`; backends merged into `enrichment['backends']` through `limes.tasks.intel._store(asset, 'backends', {'items': [...]}, now)`. Logs counts only.
  - `hibp.hibp_sync()` (Celery `hibp_sync`): returns `{'reason': 'no key'}` without any call when `HIBP_API_KEY` is empty; skips when `not CONTINUOUS_SCANS`; holds `tick_lock('hibp_sync')`; each request first takes `ratelimit.take_daily('hibp', HIBP_DAILY_BUDGET)` (`HIBP_DAILY_BUDGET = 50`) and goes through `http.get_json(url, provider='hibp', headers={'hibp-api-key': key})`. Calls `GET https://haveibeenpwned.com/api/v3/latestbreach`; per owned root (`root_domain`, `owned_root`, not retired) calls `breachedDomain/{root}` only when the latest breach name changed since `enrichment['hibp']['latest']` or 7 days passed; counts addresses per breach name (aliases are never stored or logged); fetches `GET /api/v3/breach/{name}` once per new name for `BreachDate`/`AddedDate`; upserts `DomainBreach`; writes `leak.hibp_breach` on the root: `fail` when any breach `published >= now - 365 days`, `pass` otherwise, `error` `{'reason': 'domain not verified with HIBP'}` on 403. A new breach name records `breach_new` (title `New breach <name> affects <n> addresses at <root>`), except on the root's first sync (`enrichment['hibp']['baselined']`). Then `sync_issues`/`deliver_immediate` per touched project.
  - `hibp.HIBP_DAILY_BUDGET = 50`.

- [ ] **Step 1: Write the failing tests** (`test_leak.py`):
  - `test_service_role_jwt_detected_key_never_stored`: a JWT built from header `{"alg":"HS256"}` and payload `{"role":"service_role","iss":"supabase"}` → one secret, shape ends with the token's last 4 and contains no other part of it; payload role `anon` → none; broken base64 → none; `sb_secret_` + 30 chars → one; `sb_publishable_…` → none.
  - `test_scan_artifacts_writes_on_owned_host_only`: temp dir with `a.js` (mapped to `https://app.x.com/a.js`, owned) and `b.js` (`https://cdn.other.net/b.js`, not owned) both holding the key; `c.js` on owned `www.x.com` clean → `app.x.com` fail, `www.x.com` pass, nothing for `cdn.other.net`; the full token is in no `RiskCheck.evidence`, `Asset.enrichment` or `assertLogs` record; `app.x.com`'s `enrichment['backends']['items']` holds the `supabase` ref.
  - `test_code_audit_runs_leak_scan_even_if_mantis_fails`: `mantis.audit_dir` raising `MantisError` → `scan_artifacts` still called once; `scan_artifacts` raising → `code_audit` still returns normally.
  - `test_hibp_off_without_key`: no `get` call, `{'reason': 'no key'}`.
  - `test_hibp_counts_only_no_aliases`: `breachedDomain` `{'alice': ['Adobe'], 'bob': ['Adobe', 'Canva']}` → `DomainBreach` Adobe 2, Canva 1; `alice` appears in no model field, event or log; the request carried `hibp-api-key` and the key is in no log record.
  - `test_hibp_first_sync_silent_then_breach_new_digest`: first sync → rows, no event; a new name next run → one `breach_new` with `immediate False`; `leak.hibp_breach` fails for a breach added 30 days ago, passes when all are older than 365 days.
  - `test_hibp_403_error_not_pass` and `test_hibp_budget_exhausted_stops` (take_daily False → no call, no row change).
  - `test_get_json_headers_and_max_wait` (`test_intel_http.py`): extra headers are sent alongside `User-Agent`; a reserved slot 30 s away with `max_wait=5` returns `(None, None)` with no sleep.
- [ ] **Step 2: Run** `tests.core.test_leak tests.core.test_intel_http`. Expected: ImportError, kwargs unknown.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests.core.test_leak tests.core.test_intel_http tests.core.test_crawl_artifacts tests.core.test_stage_scope tests.core.test_alerts tests.core.test_dashboard_stats tests.core.test_provisional`, `node --check web/static/custom/asset.js`. Expected: OK.
- [ ] **Step 5: Commit** "Flag Supabase secret keys in client JavaScript and add opt-in HIBP domain breaches".

### Task 7: Lookalike generation, checks, events and the abuse report

**Files:**
- Create: `web/limes/lookalike/__init__.py` (empty), `generate.py`, `rdap.py`, `check.py`, `report.py`, `tasks.py`
- Modify:
  - `web/requirements.txt`: `dnstwist==20250130`; install it into the scratch venv (`…/scratchpad/venv/bin/pip install dnstwist==20250130`) before running tests.
  - `web/limes/intel/crtsh.py`: `exact_url(name) -> str` (`?q=<name>&output=json&exclude=expired`) and `keyword_url(label) -> str` (`?q=%25<label>%25&output=json&exclude=expired`), both `quote`d.
  - `web/limes/intel/http.py`: `MIN_INTERVAL` lookup uses the provider's prefix before `:` (so `rdap:<host>` gets `'rdap': 2.0`).
  - `web/limes/alerts/events.py`: `KINDS` += `'lookalike_new', 'lookalike_active'`; `is_immediate`: `lookalike_active` always; `lookalike_new` when `key == 'phishing_ready'`. `dashboard/stats.py` `CHANGE_LABELS`: `'New lookalike'`, `'Lookalike active'`; icons in `index.html`.
  - `web/limes/settings.py`: `LOOKALIKE_ENABLED = env.bool('LIMES_LOOKALIKE_ENABLED', default=True)`, `LOOKALIKE_DNS_DAILY_BUDGET = env.int(…, default=5000)`, `RDAP_DAILY_BUDGET = env.int(…, default=500)`, `LOOKALIKE_HTTP = env.bool('LIMES_LOOKALIKE_HTTP', default=False)`; `CELERY_IMPORTS` += `'limes.lookalike.tasks'`; beat `'generate-lookalikes': {'task': 'generate_lookalikes', 'schedule': 86400.0}`, `'lookalike-tick': {'task': 'lookalike_tick', 'schedule': 60.0, 'options': {'expires': 55}}`; `celery_routing`: both `(IO, 15 * MIN)`; `.env.example`.
- Test: `web/tests/core/test_lookalikes.py`; fixture `web/tests/core/fixtures/rdap_domain.json` (RFC 9083 shape from the facts table, invented values, a 5,000-character `<script>` registrar name).

**Interfaces:**
- Consumes: `Lookalike` (Task 2), `store.load('iana_rdap')`, `intel.domains._EXTRACT`, `collect._resolve`/`_lookup`, `http.get_json(…, max_wait=…)` (Task 6), `ratelimit`, `tick_lock`, `events.safe_record`, `deliver_immediate`, `invalidate`, `limes.tasks.intel._store`.
- Produces:
  - `generate.MAX_CANDIDATES_PER_ROOT = 1000` (NOTE: ceiling; upgrade path a per-root setting); `generate.TLDS = ('com', 'net', 'org', 'co', 'io', 'info', 'xyz', 'app')`; `generate.WORDS = ('login', 'secure', 'account', 'support', 'mail', 'portal', 'online', 'app')`; `generate.MAX_KEYWORDS = 20`.
  - `generate._fuzzer_class()`: imports `dnstwist` once, saving and restoring `socket.getdefaulttimeout()` around the import; returns `dnstwist.Fuzzer`.
  - `generate.distance(a: str, b: str, limit: int = 2) -> int`: Levenshtein, returns `limit + 1` early once over.
  - `generate.candidates(root: str, keywords=(), exclude=frozenset()) -> list[{'domain': str, 'unicode': str, 'fuzzers': list[str]}]`: only for a registrable `root` (`_EXTRACT(root).registered_domain == root`, else `[]`); builds the Fuzzer, then overrides `subdomain, domain, tld = '', <idna-decoded label>, <suffix>` from tldextract before `generate()`; `dictionary` = first `MAX_KEYWORDS` valid keywords + `WORDS`; drops `*original`, the root, and `exclude`; keeps `homoglyph` results only at `distance(unicode_label, label) == 1`; merges fuzzer names per domain; orders by (first fuzzer's rank in `RANKS`, domain) and cuts at `MAX_CANDIDATES_PER_ROOT`. `RANKS = ('omission', 'transposition', 'replacement', 'insertion', 'repetition', 'addition', 'vowel-swap', 'hyphenation', 'plural', 'bitsquatting', 'homoglyph', 'cyrillic', 'tld-swap', 'dictionary', 'various', 'subdomain')`.
  - `generate.ct_matches(names: Iterable[str], label: str, exclude) -> list[str]`: registrable domains (`intel.domains.registrable`) of CT names with a token (split on `.` and `-`) equal to `label` or at `distance <= 2`, never substring matches; owned values excluded; at most 100.
  - `rdap.server_for(domain, bootstrap: dict) -> str | None` (https only); `rdap.parse(obj) -> {'registrar', 'created', 'abuse_email', 'statuses'}` (strings ≤ 200, statuses ≤ 10); `rdap.lookup(domain, bootstrap, get) -> tuple['registered' | 'unregistered' | 'unknown', dict]` (404 → unregistered; 200 → registered; anything else → unknown), `get_json(url, provider=f'rdap:{host}', max_wait=10)`.
  - `check.NEXT = {'unregistered': 7 d, 'registered': 1 d, 'watching': 1 d, 'reported': 1 d, 'ignored': 30 d, 'gone': 30 d, 'unchecked': 0}`; RDAP re-check 30 d; CT re-check 1 d for `watching`, 30 d otherwise; DNS error → retry in 1 h.
  - `check.check_row(row, now, resolve, get, bootstrap, spend) -> list[tuple[kind, title, key]]`: `spend(kind) -> bool` wraps `take_daily` + the tick share (`'dns'`, `'rdap'`); one `NS` query; NS present → `A`, `AAAA`, `MX` (lists ≤ 10, strings ≤ 253) and `registered=True`; no NS and never registered → `unregistered`, no RDAP; no NS but previously registered → RDAP decides (`200` keeps `registered` with empty DNS, `404` → `gone`); RDAP for registered rows when due; CT exact query for registered rows when due (a timeout leaves `ct` unchanged); decision statuses (`watching`, `ignored`, `ours`, `reported`) are kept, only `gone` overrides them; `ours` rows are never checked again. Events: `lookalike_new` when a row first becomes registered (key `phishing_ready` when RDAP `created` is within 30 days and it has MX or a certificate); `lookalike_active` when a `watching` row gains MX, an A record or a certificate. Returns events; the caller records them unless the root is not yet baselined.
  - `check.due_rows(now, limit) -> list[Lookalike]` (`next_check <= now`, not `ours`, oldest first; only rows whose project root is still an owned, non-retired root).
  - `check.check_http(row, now, get_factory=safe_fetch.pinned_get, resolve=collect._resolve) -> dict | None`: only with `LOOKALIKE_HTTP`, a registered row with an A record, at most once per 7 days, `take_daily('lookalike_http', 50)`; `resolve_vetted` + `pinned_get`, `GET https://<domain>/`, `allow_redirects=False`, body ≤ 256 KB; stores `{'status', 'title': str[:200], 'brand_in_page': bool, 'password_field': bool, 'location_host': str | None, 'checked_at'}`. Never `scope.may_attack`.
  - `report.defang(domain) -> str` (`.` → `[.]`); `report.abuse_report(row, user) -> {'to': str, 'subject': str, 'body': str}`: plain text with the owned root, punycode + unicode, fuzzers, RDAP registrar and creation date, DNS and MX, CT ids and dates, HTTP evidence when present, and the reporter (`user.get_full_name() or user.username`, `user.email`, project name: the project has no reporter fields). `to` is the RDAP abuse email, else the registrar name.
  - `tasks.generate_lookalikes()`: skips unless `LOOKALIKE_ENABLED and CONTINUOUS_SCANS`; `tick_lock('generate_lookalikes')`; per owned root: `candidates(root.value, project.brand_keywords, exclude=<all owned root and hostname values of the project>)` → `bulk_create(ignore_conflicts=True)` of `unchecked` rows; once per root per day one CT keyword query (`get_json(crtsh.keyword_url(label), provider='crtsh', max_wait=10)`) → `ct_matches` → rows with `source='ct'`; never deletes rows.
  - `tasks.lookalike_tick()`: same gates; `tick_lock('lookalike_tick')`; `TICK_BUDGET = 45 s`; per-tick shares `per_tick(LOOKALIKE_DNS_DAILY_BUDGET)` and `per_tick(RDAP_DAILY_BUDGET)`; stops at the first refused `spend`; records events with titles using `defang`; a root is baselined (`enrichment['lookalike']['baselined_at']` via `_store`) once all its rows have `last_checked`; then `deliver_immediate` and `invalidate` per touched project. The baseline lives on the root asset, not `IssueSyncState.roots` as the spec suggests: creating `IssueSyncState` outside `sync_issues` would make the project's first issue sync loud.

- [ ] **Step 1: Write the failing tests** (`test_lookalikes.py`):
  - `test_candidates_homoglyph_filter_and_cap`: `candidates('example.com')`: every `homoglyph` entry's unicode label is at distance 1 from `example`; `example.com` absent; every `domain` is ASCII and valid; `len <= 1000`; equal on a second call; with `MAX_CANDIDATES_PER_ROOT` patched to 50 → exactly the first 50 by rank.
  - `test_registrable_split_uses_psl`: `mybrand.co.uk` → non-tld-swap entries end with `.co.uk`; `foo.github.io` → every non-tld-swap entry ends with `.github.io` (the label permuted is `foo`, never `github`); `www.example.com` → `[]`.
  - `test_import_keeps_socket_default_timeout`: `socket.getdefaulttimeout()` before equals after `_fuzzer_class()`.
  - `test_long_label_and_many_keywords_capped`: a 63-character label root with 100 keywords → `len <= 1000`, only the first 20 keywords used.
  - `test_owned_roots_never_generated`: project owns `example.com` and `example.net` → `example.net` is not a candidate of `example.com`.
  - `test_ns_registration_and_rdap_override`: fake `resolve`: NS `[]` → `unregistered`, no RDAP call, next in 7 d; NS `['ns1.x.net.']` → `registered`, DNS stored, RDAP fixture parsed (`registrar` ≤ 200 chars, `abuse_email`, `created`); a registered row with NS `[]` and RDAP 200 stays registered; RDAP 404 → `gone`.
  - `test_rdap_https_only_and_spacing`: a TLD whose bootstrap entry is http-only → no RDAP call; a `.com` call used `provider='rdap:rdap.verisign.com'` and `max_wait=10`.
  - `test_budget_exhaustion_stops_tick`: `take_daily` allows 3 DNS queries → the tick stops; rows not reached keep their `next_check`.
  - `test_cache_down_no_dns`: the cache raising on `add` → `take_daily` False → zero `resolve` calls.
  - `test_first_sweep_silent`: 3 rows registered on the first sweep → no `ChangeEvent`; the root's `baselined_at` set; a later new registration → one `lookalike_new` with a defanged title (`examp1e[.]com`, no bare `examp1e.com`); RDAP created 5 days ago with MX → `immediate True`; created 2 years ago without MX → `immediate False`.
  - `test_watched_gains_mx_active_event`: a `watching` row gains MX → `lookalike_active`, immediate.
  - `test_decisions_sticky`: an `ignored` row stays `ignored` after a check and is due again in 30 days; `ours` rows are never selected by `due_rows`.
  - `test_lookalike_never_selected_by_pipelines`: after `generate_lookalikes()` and a `lookalike_tick()`: `Asset.objects.count()` unchanged; no lookalike value in `scoring.scored_assets(p)`, `monitor.monitored(p)`, `monitor.due_assets(now)`, `continuous.due_roots(now, project=p)`; `scope.may_attack(p, [domain])` refuses it.
  - `test_idn_stored_with_punycode`: a Cyrillic candidate has `domain` starting `xn--` and `unicode` the decoded form.
  - `test_ct_keyword_whole_label_match`: names `examp1e-login.com`, `myexamplestore.com`, `example.evil.net`, `examples.org`, `example.com` (owned) → `['evil.net', 'examp1e-login.com', 'examples.org']` (sorted), `myexamplestore.com` absent.
  - `test_http_optin`: default settings → no `pinned_get`; with `LOOKALIKE_HTTP=True` → `resolve_vetted` then one GET with `allow_redirects=False`; a 302 records `location_host` only; a page title `<script>` is stored capped and as text.
  - `test_abuse_report_text`: `to` is the abuse email (registrar when absent); body holds punycode, unicode, registrar, creation date, MX and the reporter's username.
  - `test_beat_and_routing`: both beat entries and `TASK_PLAN` rows; `'limes.lookalike.tasks' in CELERY_IMPORTS`; `LOOKALIKE_ENABLED=False` → both tasks return `{'reason': 'disabled'}` with no DNS.
- [ ] **Step 2: Run** `tests.core.test_lookalikes`. Expected: ImportError.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests.core.test_lookalikes tests.core.test_alerts tests.core.test_dashboard_stats tests.core.test_intel_http tests.core.test_intel_run tests.core.test_monitor tests.core.test_continuous tests.core.test_scope`. Expected: OK.
- [ ] **Step 5: Commit** "Find registered lookalikes of owned roots with DNS, RDAP and CT only".

### Task 8: Lookalikes page, Brand card, data sources, docs and final sweep

**Files:**
- Create:
  - `web/api/lookalikes.py`: `LookalikeList`, `DecideLookalike`, `LookalikeReport` (APIView, 4 spaces).
  - `web/startScan/templates/startScan/lookalikes.html`, `web/static/custom/lookalikes.js` (tabs).
  - `web/tests/core/test_lookalike_page.py`
- Modify:
  - `web/api/urls.py` (CRLF): `path('lookalikes/', LookalikeList.as_view(), name='lookalikes')`, `path('action/lookalike/decide/', DecideLookalike.as_view(), name='decide_lookalike')`, `path('action/lookalike/report/', LookalikeReport.as_view(), name='lookalike_report')`, importing from `.lookalikes`.
  - `web/startScan/urls.py` + `views.py`: `path('<slug:slug>/lookalikes', views.lookalikes, name='lookalikes')`.
  - `web/templates/base/_items/sidebar.html`: "Lookalikes" (`fe-copy`) after Assets.
  - `web/startScan/templates/startScan/assets.html` / `asset.js`: `?add=<value>` opens `show_add_asset_modal` with the textarea's `.value` set to it (text, never HTML).
  - `web/dashboard/posture.py`: `brand`, `data_sources`; `dashboard/stats.py` `asm_stats` adds `'brand'` and `'data_sources'`; `index.html` adds `dash_brand` after `dash_categories` and a sources footnote in `dash_categories`; `limes.css`.
  - `web/tests/core/test_overview_page.py`: `test_page_order` gains `dash_brand`; re-measure `OVERVIEW_QUERIES` (+2) with a justification in the commit body.
  - `README.md`: Configuration rows for every new setting; "Passive providers" gains Spamhaus DROP/ASN-DROP, abuse.ch Feodo, CISA KEV, EPSS, IANA RDAP + registry RDAP, and optional HIBP/DQS, each with its terms line; "Scope and safety" gains "Lookalikes: DNS, RDAP and CT only; HTTP only with `LIMES_LOOKALIKE_HTTP`, which tells the lookalike's operator someone is watching"; "Upgrading" notes the new `io` beat tasks, silent first runs and provisional checks; "Status" moves this project to built.
- Test: `web/tests/core/test_lookalike_page.py`, `test_overview_page.py`

**Interfaces:**
- Consumes: `Lookalike`, `report.abuse_report`, `report.defang` (Task 7), `FeedState`, `sources.FEEDS`, `store.is_stale` (Task 2), `HasPermission`/`PERM_MODIFY_TARGETS`, `dashboard.stats.invalidate`.
- Produces:
  - `GET /api/lookalikes/?project=<slug>[&status=&registered=true|false&mx=true&young=true]` → rows `{id, domain, unicode, idn: bool, fuzzers, source, registered, created, age_days, registrar, has_mx, cert: bool, has_a: bool, status, first_seen, last_checked, root}`; unknown filter values ignored; project-scoped; plus `meta: {enabled, budgets, credit: 'Certificate data: crt.sh · Registration data: RDAP'}`.
  - `POST /api/action/lookalike/decide/ {project, id, decision: 'watch'|'ignore'|'ours', note}` → sets `status` (`watching`/`ignored`/`ours`), `decided_by`, `decided_at`, `note[:1000]`; `ours` returns `{'add_url': '<assets url>?add=<domain>'}` and creates nothing. `PERM_MODIFY_TARGETS`.
  - `POST /api/action/lookalike/report/ {project, id}` → `{'to', 'subject', 'body'}`; sets `status='reported'`, `reported_at`, `decided_by`. `PERM_MODIFY_TARGETS`.
  - `posture.brand(project, now) -> {'enabled': bool, 'registered': int, 'new_30': int, 'phishing_ready': int, 'awaiting': int, 'tracked': int}` in one aggregate query: registered = `registered=True` and status not in `ignored/ours/gone`; `new_30` = RDAP `created` (else `first_seen`) within 30 days; phishing_ready = `has_mx` or `ct.count > 0`; awaiting = status `registered`.
  - `posture.data_sources(now) -> list[{'name', 'credit', 'terms', 'last_good_at', 'stale': bool}]` for enabled feeds (one query).
  - Page ids: `lk_table`, `lk_f_status`, `lk_f_registered`, `lk_f_mx`, `lk_f_young`, `lk_report` (read-only `<textarea>`), `lk_copy`.

- [ ] **Step 1: Write the failing tests:**
  - `test_list_scoped_and_filtered`: rows of project `p` only; `?registered=true`, `?mx=true`, `?young=true`, `?status=watching` each narrow as expected; `?status=<script>` is ignored.
  - `test_decisions_audited`: `watch` sets `decided_by == user`, `decided_at`, status; a user without `PERM_MODIFY_TARGETS` gets 403 and nothing changes; an id from another project → not found.
  - `test_ours_never_creates_asset`: `ours` returns `add_url` ending `?add=xn--…`; `Asset.objects.count()` unchanged; the row is never due again.
  - `test_report_sets_reported`: body matches `report.abuse_report`; `status == 'reported'`, `reported_at` set.
  - `test_page_renders_no_domain_server_side`: the Lookalikes page HTML contains none of the seeded domain strings (rows arrive as JSON); `lookalikes.js` contains no `innerHTML`, `.html(` or `insertAdjacentHTML`, and no `href` built from a row value (grep test, the `test_output_escaping.py` pattern).
  - `test_brand_card_counts`: seeded rows give `registered 3`, `new_30 1`, `phishing_ready 2`, `awaiting 1`; ignored and gone rows excluded; the `dash_brand` section links the Lookalikes page and shows the numbers; with `LOOKALIKE_ENABLED=False` it says lookalike monitoring is off.
  - `test_attribution_shown_where_data_shown`: the Overview `dash_categories` footnote lists each enabled feed's credit with its date and marks a stale one "stale"; the asset JSON for a listed IP carries the Spamhaus credit; the Issues page has the KEV/EPSS footnote; a root with breaches carries the HIBP credit.
  - `test_page_order` and `test_page_queries_bounded` updated as above.
- [ ] **Step 2: Run** `tests.core.test_lookalike_page tests.core.test_overview_page`. Expected: FAIL (404s, missing ids).
- [ ] **Step 3: Implement.** The page follows `issues.html`'s restyle list pattern. Domain cells are `textContent` (punycode, then unicode in `.l-muted` and an `IDN` badge when they differ); never a link. Actions: Watch, Ignore, This is ours (navigates to `add_url`), Abuse report (fills `#lk_report.value`; Copy uses `navigator.clipboard.writeText`).
- [ ] **Step 4: Verify.**
  - `tests.core.test_lookalike_page tests.core.test_overview_page tests.core.test_dashboard_stats`, `node --check web/static/custom/lookalikes.js`, `tpl.sh`.
  - Real UI with `runserver` on 8765, user `uitest`, seeded with: a lookalike `xn--exmple-cua.com` (unicode `exämple.com`) whose RDAP registrar is `<img src=x onerror=alert(1)>`, a listed IP, a provisional data-leak issue and a KEV finding. A puppeteer script `…/scratchpad/tools/p3_ui.js` (the `overview_ui.js` pattern) prints `PASS` for: no `dialog` event and no `img[src="x"]`; the Lookalikes table shows the registrar as text and no `<a>` inside `#lk_table tbody`; Watch updates the row; Abuse report fills `#lk_report`; "This is ours" lands on the Assets page with the add modal's textarea holding the domain; the Overview shows `Provisional, not scored` on two cards and the Brand card; the Issues page shows the KEV badge and the `Known exploited` filter works; light and dark have no console errors; at 390 × 844 `scrollWidth <= 390`. Screenshots in `scratchpad/shots-p3/`; look at them.
- [ ] **Step 5: Final sweep.** `verify.sh` (compile, `tests.core`, `check`, `makemigrations --check`, `tpl.sh`); `node --check` on every changed JS file; quote your own `Ran N tests` / `OK` lines; `git diff main --stat` shows no file outside this plan.
- [ ] **Step 6: Commit** "Add the Lookalikes page, the Brand card and feed credits; document the new settings".

---

## Self-review

- **Spec coverage:**

  | Spec requirement | Task |
  |---|---|
  | `Check.provisional`, `points()`, `CEILING` without provisional, `assessed_assets` ignores them, headline/assessed test | 1 |
  | `reputation` / `data_leakage` categories, "Provisional, not scored", snapshot `None`, AI checks in `network` | 1 |
  | Provisional issues tracked, Issues category filter and badge, waivers work on them | 1 (waivers need no change: `waived_keys` is key-based) |
  | `FeedState`, feed cadences, conditional GET, 50 MB cap, strict parse, zero-entry rejection, never served | 2 |
  | Spamhaus DROP v4/v6 and ASN-DROP, Feodo, opt-in blocklist.de/CINS, DQS key-only | 2 + 3 |
  | Stale rule (3 × cadence → `error`), evidence with feed timestamp and `fetched_at` | 3 |
  | `rep.*` immediate, first feed evaluation silent, 10/hour cap unchanged | 3 |
  | `CveIntel` for held ids, KEV/EPSS markers, Top-risks tie-break, filter, issue detail, unverified InternetDB CVEs | 4 |
  | AI fingerprints on known-open ports through `safe_fetch`, Jupyter second GET, count-only evidence | 5 |
  | Supabase secret / `service_role` scan in `code_audit`, backend refs informational, key never stored | 6 |
  | HIBP opt-in, counts only, `breach_new` digest, attribution | 6 |
  | `Lookalike` model (never `Asset`), dnstwist `Fuzzer` only, homoglyph filter, 1000 cap, tldextract split | 2 + 7 |
  | DNS NS-first, RDAP via IANA bootstrap with per-server spacing and budget, monthly RDAP, CT exact + daily keyword | 7 |
  | `lookalike_new` / `lookalike_active` immediacy, silent first sweep, abuse-report text, opt-in HTTP | 7 |
  | Lookalikes page, actions audited, "This is ours" opens the manual add flow | 8 |
  | Overview Brand card, new category cards, attribution wherever data is shown, env-only settings, README | 1 + 8 |

  Out of scope with no task: proving Supabase/Firebase/S3 exposure, screenshots/LSH, sending reports, score changes, a Brand score, paid feeds, SSLBL certificate match, certstream.

- **Decisions beyond or against the spec's letter** (each forced by code or a verified fact):
  - SSLBL is dropped (deprecated upstream on 2025-01-03); `rep.listed_c2` is Feodo only, and Feodo may be empty (`allow_empty`).
  - abuse.ch downloads work without a key today, so Feodo is on; the key is still sent when set.
  - CINS uses its https URL.
  - URLhaus and Spamhaus DBL get no code and no `LIMES_URLHAUS_AUTH_KEY` setting: the spec's catalogue has no domain-reputation check id to write.
  - cidr and asn assets reach the Issues page through `scoring.issue_assets` (they are not `scored_assets`), without touching the headline.
  - An IP inside an owned, listed range gets `not_applicable` (`covered_by`) so one listing is one issue.
  - Triton is fingerprinted on `/v2` server metadata, not `/v2/health/ready`.
  - The lookalike baseline is stored on the root asset, not `IssueSyncState.roots`; the feed baseline is a `check:<id>` marker inside `IssueSyncState.roots`, written only by `sync_issues`.
  - `FeedState.source_date`, `Lookalike.rdap_checked_at` / `ct_checked_at` / `reported_at` are added for evidence and cadences the spec requires.
  - All four models ship in one migration (Task 2), matching "one migration per app".
  - The abuse report's reporter comes from the requesting user, because `Project` has no reporter fields.
  - dnstwist is imported lazily and the process socket timeout restored (its import sets it to 12 s).
