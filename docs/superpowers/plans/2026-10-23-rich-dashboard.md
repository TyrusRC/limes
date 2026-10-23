# Richer Overview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Overview explains the headline score by category and shows exposure, certificates, technologies, remediation, discovery, coverage, top risks and what changed, all from data Limes already stores.

**Architecture:**
- `limes/scoring.py` gains the category model: `category_of`, `category_q`, `category_scores` and `category_issue_counts`. They reuse `baselines`, `assessed_assets`, `_penalties`, `_live`, `_score` and `p10`, so there is no second scoring model. `snapshot_scores` also stores the category scores.
- The card builders live in two new modules next to `dashboard/stats.py`, which is already 154 lines:
  - `dashboard/posture.py`: categories, exposure, certificates, technologies;
  - `dashboard/activity.py`: remediation, top risks, what changed, discovery, coverage.
- `asm_stats` assembles the cards, and the existing 60-second cache wraps the whole result.
- The template, `limes.css` (`ov-*`) and `overview.js` render the cards. Untrusted text goes only through template autoescaping.

**Tech Stack:** Django 3.2, DRF, PostgreSQL, Django templates, jQuery and DataTables (Issues and Assets pages), ApexCharts (existing trend), puppeteer-core with `/usr/bin/chromium` for the UI check.

**Spec:** `docs/superpowers/specs/2026-10-23-rich-dashboard-design.md`. Research notes: `docs/superpowers/specs/UPGUARD-HELP-DOCS-NOTES.md`. These are for information architecture only. Never copy UpGuard's assets, wording or branding.

## Global Constraints

- **Categories:**
  - The keys, in this order, are `('web', 'tls', 'email', 'dns', 'network', 'vulnerabilities')`. These are the `catalogue.py` group names, plus `vulnerabilities` for scanner findings.
  - The labels are `Website`, `Encryption`, `Email`, `DNS`, `Network`, `Vulnerabilities`.
  - Any other `category` value is ignored, never an error.
- **Score model unchanged:** `PENALTY`, `CEILING`, `GRADES`, `MAX_SCORE = 950` and `VERSION = 'limes-score-v3'` stay as they are. `project_score` output does not change. Categories explain the headline; they are never weighted into it.
- **Category score:** this is `p10` over that category's assessed assets of `_score(that asset's issues in the category)`.
  - Waived issues (`waived_keys`) are left out of the adjusted score. `raw_score` keeps them.
  - When a category has no assessed asset, `score` is None, the grade is `'N/A'`, and the UI shows "Not assessed", never 950.
  - A check category's assessed assets are the scored assets with a fresh (`CHECK_FRESH`) `pass` or `fail` `RiskCheck` in that group. The vulnerabilities category's assessed assets are the assessed assets under an owned root with a baseline (`_root_of(value, baselines)`).
- **Issue counts** come from open `TrackedIssue` rows, the same rows `/api/issues/` lists, waived ones included. That way a category card's number equals what its Issues link shows.
- **First detected** means `reopened_at or first_seen`, so it resets when a fixed issue comes back.
- **Windows:**
  - certificates: 30 days ahead;
  - remediation: 7 and 30 days;
  - what changed: 30 and 90 days;
  - category change: against the latest snapshot dated at or before today − 30 days that has `categories`.
- **List limits:** exposure 15 rows, certificates 10, technologies 10, top risks 10, oldest open issues 5, what-changed samples 5.
- **Escaping:** asset values, technology names, issue keys and titles, and event titles are scanner or user text. They render only through template autoescaping or `textContent`. No `innerHTML`, `.html()` or `|safe` with them. No `json_script` is needed beyond the existing trend.
- **Scoping:** every new query is filtered to the current project. No query runs per asset; the page's query count is pinned by a test.
- **Corner cuts** with a known ceiling get a `NOTE:` comment naming the ceiling and the upgrade path, in the codebase's existing style.
- **Style:**
  - 4 spaces in `limes/*.py`, `dashboard/*.py`, `startScan/*` and the tests;
  - tabs in `api/views.py` and `issues.js`;
  - 2 spaces in `overview.js` and in the template script blocks;
  - `api/urls.py` (CRLF) is not touched.
- **Tests:** `LIMES_DB=<unique name> LIMES_SRC=/home/kali/project/trc/limes /tmp/claude-1000/-home-kali-project-trc-limes/1272ac93-25ff-41d2-a96c-5b1ecc4bf767/scratchpad/dj.sh test <dotted.path> --noinput`.
  - Each agent uses its own `LIMES_DB` name.
  - Before reporting a task done, quote the real `Ran N tests` and `OK` lines from your own `dj.sh test tests.core --noinput` run. `verify.sh` writes per-run files, but never trust counts from a shared file.
  - No network.
- **No new dependencies.** **Commits:**
  - identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`;
  - no AI attribution of any kind;
  - never `--no-verify`;
  - no push without an explicit user yes.

## Review Focus

1. **A project whose owned assets were never scanned or checked.** Every category reads "Not assessed", and none shows 950 or grade A. Task 1 `test_nothing_assessed_is_not_assessed`; Task 5 `test_empty_and_unassessed_states`.
2. **A project whose only issues are waived.** The adjusted category scores are 950 and the raw ones are lower. The cards still count the waived issues, as the Issues page does, and say how many are waived. Task 3 `test_waived_only_project`.
3. **Open issues on retired or missing assets.** These assets leave the score but stay open on the Issues page. Category counts must still add up to the Issues list, and the scores must ignore them. Task 1 `test_issue_counts_add_up_to_issues_page`; Task 2 `test_category_filter_matches_counts`.
4. **Snapshot rows written before this change** (`categories` is null), or with a category missing or null. The change shows as none ("no trend"), never as a crash or a fake delta. Task 3 `test_category_change_needs_a_30_day_snapshot`.
5. **A hostile name in every card:**
   - an asset, technology or finding named `<img src=x onerror=alert(1)>`;
   - each card that prints a name shows it escaped;
   - the raw string appears nowhere on the page.

   Task 5 `test_hostile_names_escaped_in_every_card` and the real-UI check.

---

### Task 1: Category scores, issue counts and snapshots

**Files:**
- Modify:
  - `web/limes/scoring.py`: add the constants and functions below. `snapshot_scores` writes `categories` in its `update_or_create` defaults.
  - `web/startScan/asset_models.py`: add `ScoreSnapshot.categories = models.JSONField(null=True, blank=True)`. It holds `{category: adjusted score | None}` and is null on older rows.

  Then run `makemigrations startScan -n score_categories`, which creates `0026_score_categories.py`.
- Test: `web/tests/core/test_category_scores.py` (copy the `Base` helpers from `test_scoring.py`)

**Interfaces:**
- Produces:
  - `scoring.CATEGORIES = ('web', 'tls', 'email', 'dns', 'network', 'vulnerabilities')`;
  - `scoring.CATEGORY_LABELS = {'web': 'Website', 'tls': 'Encryption', 'email': 'Email', 'dns': 'DNS', 'network': 'Network', 'vulnerabilities': 'Vulnerabilities'}`;
  - `scoring.category_of(key: str) -> str`: `CHECKS[key].group` when `key in CHECKS`, else `'vulnerabilities'`. Hashed long keys and unknown keys go to vulnerabilities.
  - `scoring.category_q(category: str) -> Q | None`, a `TrackedIssue` filter:
    - `Q(source='finding')` for vulnerabilities;
    - `Q(source='check', key__in=[ids of that group])` for the other categories;
    - None for an unknown value.
  - `scoring.category_scores(project, now=None) -> dict[str, dict]`, in `CATEGORIES` order. Each value is `{'label': str, 'score': int | None, 'grade': str, 'raw_score': int | None, 'raw_grade': str, 'assessed': int}`, where `assessed` is the number of assets assessed in that category.
  - `scoring.category_issue_counts(project, now=None) -> dict[str, {'open': int, 'waived': int}]`, from open `TrackedIssue` rows of the project, in one aggregate query (`Count('id', filter=category_q(c) [& active-waiver Exists])`).
- Note: the existing local names `categories` in `scoring.py` mean issue keys. Leave them alone; the new concept is always spelled `category` or `CATEGORIES`.

- [ ] **Step 1: Write the failing tests.** The shared fixture `reconcile_project()` builds:
  - owned root `x.com` with a baseline scan (`scan()` with the vulnerability stage succeeded);
  - hosts `a.x.com`, `b.x.com`, `c.x.com`, and a retired `d.x.com`;
  - findings: `a` has template `cve-1` at severity 3, and `b` has `cve-2` at severity 2;
  - fresh `RiskCheck` rows (`last_checked=now`, `severity=CHECKS[id].severity`):
    - `a`: `web.hsts_missing` fail and `tls.cert_expired` fail;
    - `b`: `web.hsts_missing` pass;
    - `x.com`: `email.dmarc_missing` fail and `dns.caa_missing` pass;
  - `sync_issues(project)` (the first sync is silent), then an extra open `TrackedIssue(asset=d, key='cve-9', source='finding', severity=3)`.

  The tests:
  - `test_category_of`:
    - `'web.hsts_missing'` gives `'web'`;
    - `'tls.cert_expired'` gives `'tls'`;
    - `'email.spf_missing'` gives `'email'`;
    - `'dns.caa_missing'` gives `'dns'`;
    - `'net.exposed_rdp'` gives `'network'`;
    - `'CVE-2021-44228'`, `issue_key('x' * 400)` and `'web.not_a_check'` give `'vulnerabilities'`;
    - for every id in `CHECKS`, `TrackedIssue.objects.filter(category_q(category_of(id)))` matches a check row with that key;
    - `category_q('bogus')` is None.
  - `test_category_scores_match_scoring_by_hand`: `category_scores(p)` gives
    - `{'web': (925, 'A', 2), 'tls': (799, 'B', 1), 'email': (925, 'A', 1), 'dns': (950, 'A', 1), 'network': (None, 'N/A', 0), 'vulnerabilities': (799, 'B', 4)}`, as `(score, grade, assessed)`.

    These follow from `p10` (minimum with four or fewer assets) of `950 − PENALTY` with the `CEILING`:
    - vulnerabilities: `a` is 870, capped to 799;
    - tls: `a` is 870, capped to 799;
    - web: `a` is 925.

    `project_score(p)['score']` is still 765 (`a`: 950 − 80 − 25 − 80), unchanged by this task.
  - `test_waived_issue_moves_adjusted_only`:
    - `create_waiver` on `a`'s `tls.cert_expired` issue (`accepted_risk`);
    - tls gives `score == 950` and `raw_score == 799`, with `raw_grade == 'B'`;
    - the other categories are unchanged;
    - `project_score(p)['score'] == 799`.
  - `test_nothing_assessed_is_not_assessed`: a project with an owned root and hosts, but no scan and no checks. Every category has `score` None, `grade == 'N/A'` and `assessed == 0`. A check fail whose `last_checked` is now − 31 days keeps `web` unassessed.
  - `test_checks_without_baseline`: with no scan, but a fresh web pass on a host, `web` is 950 with `assessed == 1` and `vulnerabilities` is None.
  - `test_issue_counts_add_up_to_issues_page`:
    - `category_issue_counts(p)` gives `{'web': 1, 'tls': 1, 'email': 1, 'dns': 0, 'network': 0, 'vulnerabilities': 3}` for `open`;
    - the sum of `open` (6) equals `TrackedIssue.objects.filter(project=p, status='open').count()`, the base query of `IssueList`;
    - a fixed issue is not counted;
    - another project's issues are not counted;
    - after waiving one, that category's `waived == 1`.
  - `test_snapshot_writes_categories`:
    - `snapshot_scores()` writes `categories == {'web': 925, 'tls': 799, 'email': 925, 'dns': 950, 'network': None, 'vulnerabilities': 799}`;
    - `version == 'limes-score-v3'`;
    - a `ScoreSnapshot` created without the field has `categories` None.
- [ ] **Step 2: Run** `... test tests.core.test_category_scores --noinput`. Expected: ImportError or AttributeError.
- [ ] **Step 3: Implement.**
  - `category_scores` builds its inputs once:
    - `base = baselines(project)`;
    - `assets = assessed_assets(project, base, now)`;
    - `_penalties(project, base=base, now=now)` restricted to `assets`;
    - `waived_keys(project, now)`;
    - one `_fresh_checks(project, now).filter(status__in=('pass', 'fail')).values_list('asset_id', 'check_id').distinct()` for the per-group assessed sets.
  - It then splits each asset's issues by `category_of`, and gets adjusted and raw values from `_score` via `_live`, then `p10`.
  - `# NOTE: recomputes baselines (a few queries per owned root) that project_score also builds; cached for STATS_TTL by the Overview. Upgrade path: one shared inputs object.`
- [ ] **Step 4: Run** `tests.core.test_category_scores tests.core.test_scoring tests.core.test_waivers`, then `makemigrations --check --dry-run`. Expected: OK, then `No changes detected`.
- [ ] **Step 5: Commit** "Score each category with the headline's model and snapshot it".

### Task 2: `category` filter on the Issues API and page

**Files:**
- Modify:
  - `web/api/views.py` `IssueList.get`: when `scoring.category_q(q.get('category') or '')` is not None, filter by it.
  - `web/startScan/templates/startScan/issues.html`: a fourth `l-field` in the filter bar, `<select id="f_category">` with an "All categories" empty option, then one option per category in `CATEGORIES` order. Its values are the keys and its text the labels; the options are written in the template.
  - `web/static/custom/issues.js`: add `'category'` to both `['severity', 'source', 'waived']` lists (`issue_url` and the change listeners). On load, preselect each of these four selects from `URLSearchParams(location.search)` when the value is one of its options. This is the `assets.html` `qTier` pattern, so the Overview links `?category=web` and `?severity=4` work.
- Test: `web/tests/core/test_issue_api.py`

**Interfaces:**
- Consumes: `scoring.category_q`, `scoring.CATEGORIES` and `scoring.category_issue_counts` (Task 1).
- Produces: `GET /api/issues/?project=<slug>&category=<key>`. The Issues page also accepts `?category=`, `?severity=`, `?source=` and `?waived=` in its URL.

- [ ] **Step 1: Write the failing tests** (`IssueApiTest`, existing fixtures `i1` web check, `i2` finding `<script>x`, `i3` fixed, and `other`):
  - `test_category_filter`:
    - `category=web` gives ids `[i1]`;
    - `category=vulnerabilities` gives `[i2]`;
    - `category=tls` gives `[]`;
    - `category=bogus`, `category=WEB` and `category=` each give the unfiltered list `[i2, i1]`;
    - `other` never appears.
  - `test_category_filter_matches_counts`:
    - add a retired asset with an open finding issue;
    - for every key in `CATEGORIES`, `len(list(category=key)) == category_issue_counts(p)[key]['open']`;
    - the sum equals the length of the unfiltered list.
  - In `IssuePageTest`: `test_category_select_rendered`. The page contains `id="f_category"` and `<option value="vulnerabilities">Vulnerabilities</option>`.
- [ ] **Step 2: Run** `tests.core.test_issue_api`. Expected: the category tests FAIL, because the filter is ignored and the select is missing.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests.core.test_issue_api`, then `node --check web/static/custom/issues.js` and `tpl.sh`. Expected: OK. In the browser, `/scan/<slug>/issues?category=web` opens with Website selected and only web rows.
- [ ] **Step 5: Commit** "Filter issues by score category".

### Task 3: Posture cards: categories, exposure, certificates, technologies

**Files:**
- Create: `web/dashboard/posture.py`
- Modify:
  - `web/dashboard/stats.py`: `asm_stats` adds the keys `categories`, `exposure`, `certificates` and `technologies`.
  - `web/limes/checks/tls.py`: in `evaluate`, both `tls.cert_expired` and `tls.cert_expiring` carry `ev` (`{'not_after': iso}`) whenever `not_after` is known, passing results included. Today only failing rows store it, so certificates 15–30 days out are invisible. This is not new collection: the observation already has the value.
  - `web/api/views.py` `AssetDatatableViewSet.get_queryset`: a `technology` param filters `qs.filter(id__in=Asset.objects.filter(project__slug=project, technologies__name=tech).values('id'))`. A subquery, so the annotated counts don't fan out.
  - `web/startScan/templates/startScan/assets.html`:
    - add `<input type="text" id="f_technology" class="form-control" placeholder="Any technology">` beside Tag;
    - add `'technology'` to both key lists;
    - generalize the `qTier` preselect: for each key, a select takes the URL value only when it is one of its options, and a text input takes it as typed.
- Test: `web/tests/core/test_overview_posture.py`, plus updates in `web/tests/core/test_risk_checks.py` where a pass row asserted empty evidence.

**Interfaces:**
- Consumes: Task 1's `category_scores` and `category_issue_counts`; `collect._fresh_internetdb(asset, now)`; `catalogue.RISKY_PORTS` and `CHECKS`; `scoring.scored_assets`, `_fresh_checks` and `SEVERITY_NAMES`.
- Produces (each returns plain data; the template only formats it):
  - `posture.category_cards(project, now) -> list[{'key', 'label', 'score', 'grade', 'raw_score', 'assessed': bool, 'open': int, 'waived': int, 'delta_30': int | None}]`.
  - `posture.exposure(project, now) -> {'rows': [{'port': int, 'service': str, 'hosts': int, 'risky': bool, 'severity': str | None, 'check': str | None}], 'ports': int, 'hosts': int}`.
    - The source is fresh InternetDB `ports` on `scored_assets(project).filter(kind='ip')`.
    - The service is the `RISKY_PORTS` name, else `socket.getservbyport(port, 'tcp')`, else `''` on `OSError`.
    - Rows are ordered risky first (severity desc), then hosts desc, then port; at most `EXPOSURE_LIMIT = 15`. `ports` and `hosts` are the full totals.
  - `posture.certificates(project, now) -> {'rows': [{'host', 'not_after': datetime, 'days_left': int, 'expired': bool, 'severity': str | None}], 'total': int}`.
    - The source is `_fresh_checks(project, now).filter(check_id__in=('tls.cert_expired', 'tls.cert_expiring'))` rows with `evidence.not_after`, one per asset (the earliest).
    - It keeps those with `not_after <= now + CERT_WINDOW` (`timedelta(days=30)`).
    - `days_left = (not_after − now).days` and `expired = not_after <= now`.
    - `severity` is `SEVERITY_NAMES` of the failing check's severity: high when expired, medium within 14 days, None otherwise.
    - Rows are sorted by `not_after`; at most `CERT_LIMIT = 10`.
  - `posture.technologies(project) -> list[{'name': str, 'count': int}]`.
    - The source is owned (`OWNED`), non-retired assets: `.values('technologies__name').annotate(count=Count('id', distinct=True))`, without null names, ordered `-count`, then name; at most `TECH_LIMIT = 10`.
  - `GET /api/listDatatableAsset/?project=&technology=<name>`; the Assets page accepts `?technology=` and `?source=` in its URL.

- [ ] **Step 1: Write the failing tests** (`test_overview_posture.py`, using the `Base` pattern of `test_dashboard_stats.py`, with `cache.clear()`):
  - `test_category_cards_carry_counts_and_links`: on Task 1's reconciliation fixture, the `web` card is `score=925, grade='A', open=1, waived=0, assessed=True`, and the `network` card has `assessed=False` and `score` None.
  - `test_category_change_needs_a_30_day_snapshot`:
    - with no snapshot, `delta_30` is None everywhere;
    - a snapshot dated today − 31 with `categories=None` is skipped in favour of one dated today − 40 with `categories={'web': 900, 'tls': None}`, which gives web `delta_30 == 25`, and tls and vulnerabilities None;
    - a snapshot dated today − 10 is never used.
  - `test_waived_only_project`:
    - waive every open issue of a host with a high finding and a web fail;
    - the vulnerabilities and web cards show `score == 950`, `raw_score < 950` and `open == waived == 1`;
    - `project_score` is 950.
  - `test_exposure_from_fresh_internetdb`:
    - IP `1.2.3.4` has `enrichment={'internetdb': {'ports': [443, 3389], 'fetched_at': now.isoformat()}}`;
    - IP `1.2.3.5` has `[443]`;
    - IP `1.2.3.6` has `[23]`, but fetched 31 days ago;
    - a retired IP has `[22]`;
    - a candidate IP has `[21]`;
    - the result: rows `[(3389, 'rdp', 1, True, 'high', 'net.exposed_rdp'), (443, <any>, 2, False, None, None)]`, with `ports == 2` and `hosts == 2`.
  - `test_certificates_window_and_order`: fresh rows give
    - not_after now + 10d + 1h: `days_left` 10, medium;
    - now + 25d: 25, None;
    - now − 2d: expired, high;
    - now + 40d: absent;
    - a stale (31-day-old) row: absent;
    - a row on another project's asset: absent.

    The rows are ordered expired first, then 10, then 25.
  - `test_tls_pass_keeps_not_after`: `tls.evaluate` with not_after now + 25 days gives `tls.cert_expiring` as `pass` with `evidence == {'not_after': iso}`.
  - `test_technologies_top_ten`:
    - 12 technology names over owned assets give 10 rows, sorted by count;
    - two `Technology` rows with the same name merge into one row;
    - candidate and retired assets don't count;
    - `GET /api/listDatatableAsset/?project=p&technology=nginx&format=datatables` returns exactly the assets with nginx, `recordsTotal` included.
- [ ] **Step 2: Run** `tests.core.test_overview_posture`. Expected: ImportError.
- [ ] **Step 3: Implement.** Each builder makes a fixed number of queries.
  - `exposure` loads `id`, `value` and `enrichment` of owned IPs in one query. `# NOTE: reads every owned IP's enrichment JSON into Python; fine for tens of thousands. Upgrade path: jsonb_array_elements in SQL.`
- [ ] **Step 4: Run** `tests.core.test_overview_posture tests.core.test_risk_checks tests.core.test_asset_api tests.core.test_dashboard_stats`. Expected: OK. The `test_asset_api` query-count tests still pass (6).
- [ ] **Step 5: Commit** "Add category, exposure, certificate and technology cards' data".

### Task 4: Activity cards: remediation, top risks, what changed, discovery, coverage

**Files:**
- Create: `web/dashboard/activity.py`
- Modify:
  - `web/startScan/asset_models.py`: add `TrackedIssue.reopened_at = models.DateTimeField(null=True, blank=True)`. Then run `makemigrations startScan -n issue_reopened_at`. Its `RunPython` backfills open rows with `reopened > 0` from the newest `ChangeEvent(kind='issue_regressed', asset_id=row.asset_id, detail__key=row.key)`; the reverse is a noop.
  - `web/limes/alerts/issues.py` `sync_issues`: on regression, also set `row.reopened_at = now`.
  - `web/dashboard/stats.py`: `asm_stats` adds `remediation`, `top_risks`, `what_changed`, `discovery` and `coverage`. `top_risks` gets the existing `live`, and `what_changed` gets `risk['score']`.
- Test: `web/tests/core/test_overview_activity.py`, plus `test_alerts.py` `test_new_fixed_regressed` (assert `reopened_at == now` of the regressing sync)

**Interfaces:**
- Consumes: `stats._live_issues` output (`{Asset: {key: severity}}`), `scoring.issue_key`, `PENALTY`, `SEVERITY_NAMES`, `category_of` (Task 1), `CHECKS` titles, `monitor.monitor_state`, `monitor.found_by` and `monitor.FOUND_BY`.
- Produces:
  - `activity.detected_at(issue) -> datetime`: `issue.reopened_at or issue.first_seen`. In SQL: `Coalesce('reopened_at', 'first_seen')`.
  - `activity.remediation(project, now) -> {'fixed_7', 'fixed_30', 'opened_7', 'opened_30': int, 'oldest': [{'id', 'asset', 'title', 'category', 'severity': str, 'detected_at', 'age_days': int, 'reopened': bool}]}`.
    - Fixed means `status='fixed'` and `fixed_at >= now − N days`. Opened means detected at or after `now − N` days, whatever the status now. Both are counted in one aggregate query.
    - `oldest` holds open issues with severity ≥ 3 and no active waiver, oldest detection first; at most `OLDEST_LIMIT = 5`.
  - `activity.top_risks(project, live, now) -> list[{'id': int | None, 'asset', 'title', 'key', 'category', 'severity': str, 'points': int, 'detected_at': datetime | None, 'age_days': int | None}]`.
    - The source is the live (waiver-excluded) scoring inputs, joined to open `TrackedIssue` rows on `(asset_id, issue_key(key))` in one query.
    - Sorted by `-points`, then oldest detection (None last), then asset, then key; at most `TOP_RISKS = 10`.
    - `title` is `CHECKS[key].title` for checks, else the key.
  - `activity.what_changed(project, now, score) -> list[{'days': 30 | 90, 'new_assets': int, 'new_sample': [str], 'removed_assets': int, 'removed_sample': [str], 'introduced': int, 'resolved': int, 'score_from': int | None, 'score_to': int | None, 'score_delta': int | None}]`:
    - new: owned, `first_seen >= since`;
    - removed: owned, `state in ('missing', 'stale', 'retired')` with `last_seen >= since`;
    - introduced: detected at or after `since`;
    - resolved: `fixed_at >= since`;
    - `score_from` is the latest snapshot with `date <= since.date()`, and `score_to = score`;
    - samples are values ordered by value, at most 5.
  - `activity.discovery(project) -> {'rows': [{'label': str, 'name': str, 'count': int, 'filter': str | None}], 'total': int}`.
    - It covers owned, non-retired assets, with labels from `monitor.found_by`; an asset counts once per label.
    - `name` comes from `DISCOVERY_NAMES = {'manual': 'Added by hand', 'CT': 'Certificate transparency', 'scan': 'Scan', 'InternetDB': 'Passive intel (InternetDB)', 'ASN': 'ASN', 'CIDR': 'IP range', 'attribution': 'Attribution', 'target': 'Scan target', 'other': 'Other'}`.
    - `filter` is the label when the Assets page's `f_source` has that option (`manual`, `scan`, `CT`, `InternetDB`, `CIDR`, `ASN`, `attribution`), else None.
    - Rows are ordered by count desc.
  - `activity.coverage(project, now) -> {'total', 'on_time', 'overdue', 'never', 'stopped', 'range_swept': int, 'oldest': {'value', 'last_checked': datetime | None, 'why': 'never' | 'overdue'} | None}`.
    - The source is owned, non-retired `hostname`, `ip` and `root_domain` assets, in one query with `select_related('parent', 'parent__parent')` and the `has_target` annotation used by `AssetDatatableViewSet`. Each row is classified from `monitor_state(a)`:
      - `status == 'range_sweep'` gives range_swept;
      - `interval` None gives stopped;
      - `last_checked` None gives never;
      - `next_due < now` gives overdue;
      - anything else is on_time.
    - `oldest` is the never-checked asset with the earliest `first_seen`, else the overdue asset with the earliest `last_checked`.

- [ ] **Step 1: Write the failing tests:**
  - `test_remediation_windows`:
    - issues fixed 3 days ago (counts in 7 and 30), fixed 20 days ago (30 only) and fixed 40 days ago (neither);
    - an issue opened 2 days ago, and one first seen 60 days ago but reopened 5 days ago, which counts as opened in 7;
    - `oldest` lists an open critical first seen 50 days ago (`age_days == 50`), then the reopened high, with `reopened` True and `age_days == 5`;
    - medium issues, waived critical issues and fixed issues are absent.
  - `test_top_risks_cost_order`:
    - a critical (200 points) and two highs (80), one first detected earlier;
    - the order is critical, then the older high, then the newer high, with `points` `[200, 80, 80]`;
    - a waived issue is absent;
    - 12 issues give 10 rows;
    - a check row's `title` is the catalogue title and its `category` the group.
  - `test_what_changed_windows`:
    - assets first seen 10 and 60 days ago: `new_assets` is 1 at 30 days and 2 at 90;
    - a missing asset last seen 20 days ago counts as removed in both windows;
    - an active asset doesn't count;
    - snapshots 31 and 91 days ago with scores 700 and 600, and a live score of 765: `score_delta` is 65 at 30 days and 165 at 90;
    - with no snapshot, the score fields are None.
  - `test_discovery_by_source`:
    - in a project with no other owned assets: sources `crtsh`, `dns`, `crtsh`+`internetdb`, `cidr`, an asset with none but `added_by`, and one with none and no `added_by`;
    - result: `CT` 2, `scan` 1, `InternetDB` 1, `CIDR` 1, `manual` 1, `target` 1 (with `filter` None), and `total == 6`;
    - a candidate doesn't count.
  - `test_coverage_states` (`override_settings(RANGE_ENUMERATION=True)`, in a project with no other owned assets):
    - an on-time host (`last_resolved_at = now − 1h`, active, daily);
    - an overdue host (`now − 3 days`, `enrichment={'monitor': {'active': True}}`);
    - a never-checked host;
    - a host with `cadence_tier='off'`;
    - an IP under an owned, swept `cidr`;
    - the counts are 1 each, and `oldest` is the never-checked host.
  - `test_activity_queries_do_not_scale`: `CaptureQueriesContext` around the five builders, with 3 versus 30 hosts (each with a tracked issue, sources and a monitor state), gives equal counts.
- [ ] **Step 2: Run** `tests.core.test_overview_activity tests.core.test_alerts`. Expected: ImportError, and the `reopened_at` assertion fails.
- [ ] **Step 3: Implement**, then add the field and migration.
  - `coverage` and `discovery` iterate rows in Python. `# NOTE: one row per owned asset in memory (monitor_state is Python-only); fine for tens of thousands. Upgrade path: store monitor status in a column.`
- [ ] **Step 4: Run** `tests.core.test_overview_activity tests.core.test_alerts tests.core.test_dashboard_stats tests.core.test_monitor`, then `makemigrations --check --dry-run`. Expected: OK, then `No changes detected`.
- [ ] **Step 5: Commit** "Add remediation, top risk, change, discovery and coverage cards' data".

### Task 5: Overview template, styles and toggle

**Files:**
- Modify:
  - `web/dashboard/templates/dashboard/index.html`;
  - `web/static/limes/limes.css` (the `ov-*` section and its three media blocks);
  - `web/static/limes/overview.js`: a second IIFE before the trend one, for the toggle only.
- Test: `web/tests/core/test_overview_page.py` (the `OverviewPageTest` login pattern from `test_dashboard_stats.py`). UI script: `/tmp/claude-1000/-home-kali-project-trc-limes/1272ac93-25ff-41d2-a96c-5b1ecc4bf767/scratchpad/tools/overview_ui.js` (the `a5b_ui.js` pattern).

**Interfaces:**
- Consumes: the `asm_stats` keys from Tasks 3 and 4, plus `issues_url` and `assets_url`.
- Produces: these section ids, which the tests and the UI script rely on:
  - `dash_what_changed`, `dash_categories`, `dash_exposure`, `dash_certs`, `dash_tech`, `dash_remediation`, `dash_discovery`, `dash_coverage`, `dash_top_risks`;
  - the existing `dash_risk`, `dash_inventory`, `dash_findings`, `dash_risky`, `dash_changes` and `dash_monitoring` stay.

  The toggle buttons are `#wc_30` and `#wc_90` (`aria-pressed`), and the panels `#wc_panel_30` and `#wc_panel_90` (`hidden`).

- [ ] **Step 1: Write the failing tests:**
  - `test_page_order`: the section ids appear in this order:
    - `dash_risk`, then the trend (`score_trend`), then `dash_what_changed`, `dash_categories`, `dash_inventory`, `dash_findings`;
    - then `dash_exposure`, `dash_certs`, `dash_tech`, `dash_remediation`, `dash_discovery`, `dash_coverage`, `dash_top_risks`;
    - then `dash_risky`, `dash_changes`, `dash_monitoring`.
  - `test_category_cards_link_and_states`:
    - each assessed card links `{issues_url}?category=<key>` and shows `ov-grade-<grade|lower>`;
    - a not-assessed card shows the text `Not assessed` and no `ov-grade-` class;
    - a card with `delta_30` None shows `No trend yet`.
  - `test_hostile_names_escaped_in_every_card`. With `X = '<img src=x onerror=alert(1)>'`, seed:
    - a host `X + '.x.com'` with a high finding named and templated `X`, a fresh failed `tls.cert_expiring` with near `not_after`, the technology `X`, and `sources=[{'source': 'crtsh'}]`;
    - an owned IP with InternetDB ports;
    - a never-checked host `X + '.y.x.com'`;
    - `sync_issues`.

    Then:
    - `X` is nowhere in the HTML;
    - `&lt;img src=x onerror=alert(1)&gt;` is inside each of the sections `dash_certs` (host), `dash_tech` (name), `dash_remediation` (asset and title), `dash_coverage` (oldest), `dash_top_risks` (asset and title) and `dash_what_changed` (new sample);
    - the sections with no free text (`dash_categories`, `dash_exposure`, `dash_discovery`) render.

    Slice each section with `html.index('id="dash_x"')` up to the next `</section>`.
  - `test_empty_and_unassessed_states`:
    - a new empty project renders every new section id with its empty text: `No open ports seen`, `No certificates expire in the next 30 days`, `No technologies detected`, `Nothing fixed or opened yet`, `No owned assets yet`;
    - all six category cards say `Not assessed`;
    - no `ov-gauge-value` appears.
  - `test_risky_ports_link_to_network_issues`: the risky row's link is `{issues_url}?category=network`.
- [ ] **Step 2: Run** `tests.core.test_overview_page`. Expected: FAIL, because the ids are missing.
- [ ] **Step 3: Implement** in the page order above.
  - The grid, at 1400px and wider:
    - score 3 | trend 6 | what changed 3;
    - categories 12, laid out as an inner grid of 6, 3 or 1 columns;
    - surface 12, always the 4-column stats variant (move the `max-width: 1399.98px` `.ov-stats` rules into the base rule);
    - severity 12;
    - exposure 6 | certificates 6;
    - technologies 4 | remediation 4 | discovery 4;
    - coverage 4 | top risks 8;
    - risky 8 | side 4.
  - Below 1400px, the 6- and 4-column cards span 6 and the 8-column cards span 12. Below 992px everything spans 12. Below 576px the category grid is one column.
  - Use the existing tokens, the `ov-grade-*` classes, the `sev-*` pills, `ov-tag`, `ov-flush` tables (copy the `.ov-risky .table` rules to a shared `.ov-table`), `ov-note ov-empty-note ov-pad`, and `overflow-wrap: anywhere` on name cells.
  - Severities and grades come from the data, never hardcoded.
  - Dates go in `<time datetime="{{ d|date:'c' }}">`, with `naturaltime` or `date:'Y-m-d'`.
  - The toggle JS only flips `hidden` and `aria-pressed`. It touches no strings.
- [ ] **Step 4: Verify.**
  - Run `tests.core.test_overview_page tests.core.test_dashboard_stats`, `node --check web/static/limes/overview.js`, and `tpl.sh`.
  - Then the real UI, with `runserver` on 8765 and a seed like the hostile test (plus snapshots 31 and 91 days old with categories) for user `uitest`. Run `overview_ui.js` and confirm each item prints `PASS`:
    - no `dialog` event, and no `img[src="x"]` in the DOM;
    - all 9 new section ids are present;
    - clicking `#wc_90` shows `#wc_panel_90`, hides `#wc_panel_30`, and sets `aria-pressed`;
    - a category card link navigates to the Issues page with the matching select value;
    - a technology link navigates to the Assets page with `#f_technology` filled and filtered rows;
    - in light and dark (`localStorage['limes-theme']`) there are no console errors;
    - at a 390 × 844 viewport, `document.documentElement.scrollWidth <= 390`, and the category cards share one `offsetLeft` (they stack);
    - screenshots of both themes at 1440 and 390 are saved to `scratchpad/shots-overview/`.

    Look at the screenshots yourself before continuing.
- [ ] **Step 5: Commit** "Show the richer Overview".

### Task 6: Query budget, project scoping, docs and final sweep

**Files:**
- Test: `web/tests/core/test_overview_page.py` (`OverviewBudgetTest`, `OverviewScopeTest`)
- Modify: `README.md` "Status" section

- [ ] **Step 1: Write the tests:**
  - `test_page_queries_bounded`:
    - with `cache.clear()`, use `CaptureQueriesContext` around the second `GET /p/dashboard/` (the first is the prefs warm-up), seeded with 1 owned root and a baseline, then N hosts, each with a finding, a fresh check, a technology, a tracked issue and sources, plus N owned IPs with InternetDB ports;
    - the counts for N = 3 and N = 40 are equal;
    - assert `assertEqual(count, OVERVIEW_QUERIES)`, where `OVERVIEW_QUERIES` is a module constant measured on the finished branch, with the comment `# a rise must be justified in review`.
  - `test_second_load_is_cached`: a second GET within `STATS_TTL` doesn't call `dashboard.stats.asm_stats` (`mock.patch(..., wraps=asm_stats)`), and `invalidate(p.id)` makes the next GET call it.
  - `test_no_cross_project_data`:
    - `before = asm_stats(p)`;
    - then seed project `o` with everything: issues and waivers, IPs with ports, certificates, technologies named `ONLY-IN-O`, events, snapshots with categories, sources, and monitor states;
    - `asm_stats(p) == before`;
    - the `p` page doesn't contain `ONLY-IN-O`.
- [ ] **Step 2: Run them.** They pass, unless a builder leaks or scales. A failure here is a bug in Tasks 3–5: fix it there, not in the test.
- [ ] **Step 3: Update `README.md`.**
  - Under "Status", add "a richer Overview (score by category, exposure, certificates, technologies, remediation, discovery, coverage and what changed)" to "Built and merged".
  - Remove its bullet from "Designed, not built yet".
  - Extend the Portal row's text only if it names Overview contents.
- [ ] **Step 4: Run the final sweep.**
  - `verify.sh` (compile, `tests.core`, `check`, `makemigrations --check`, `tpl.sh`);
  - `node --check` on `overview.js`, `issues.js`, and the inline script of `assets.html` (extracted);
  - the Task 5 UI script again.

  Quote your own `Ran N tests` and `OK` lines. `git diff main --stat` shows no file outside this plan's lists.
- [ ] **Step 5: Commit** "Pin the Overview's query budget and project scoping; update the README status".

---

## Self-review

- **Spec coverage:**

  | Spec requirement | Task |
  |---|---|
  | Six categories, per-category score and grade, waived excluded, raw available, "Not assessed" | 1 |
  | Snapshot `categories` field and its migration | 1 |
  | Category cards with count, 30-day change and Issues link | 3 + 5 |
  | `category` filter (API and page, unknown ignored) | 2 |
  | Exposure with risky ports linked | 3 + 5 |
  | Certificates (30 days, expired) | 3 |
  | Technologies, top 10, linked to Assets | 3 |
  | Remediation (7 and 30 days, oldest critical/high, age, reopened reset) | 4 |
  | Discovery | 4 |
  | Coverage | 4 |
  | Top risks | 4 |
  | What changed, 30 and 90 days | 4 + 5 |
  | Page order, 390 px stacking, light and dark | 5 |
  | Hostile-name check | 5 |
  | Query count, cache | 6 |
  | Project scoping | 6, plus per-builder negatives in 1, 3 and 4 |
  | Reconciliation anti-goal | 1 + 2 |

  Non-goals (IP Reputation, Brand, Data Leakage, per-category charts, drag and drop) get no task.
- **Decisions beyond the spec:**
  - Category keys reuse the catalogue group names (`tls`, `network`), with display labels on top.
  - Card counts include waived issues, so they equal the Issues filter; the waived number is shown beside them.
  - `TrackedIssue.reopened_at` is added (Task 4), because `reopened` is only a counter and cannot reset "first detected".
  - TLS pass rows keep `not_after`, because fail-only evidence cannot show the 15–30-day window.
  - The card builders go in `posture.py` and `activity.py` rather than growing `stats.py`.
  - The existing Riskiest assets and Monitoring cards stay, after Top risks.
