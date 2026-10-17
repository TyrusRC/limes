# Risk checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run about 25 UpGuard-style configuration checks on every owned host, root and IP in every scan, store one current result per (asset, check), and feed failed checks into a published `limes-score-v2`.

**Architecture:**
- **`web/limes/checks/` holds pure code:**
  - `catalogue.py` lists the checks;
  - `web.py`, `tls.py`, `email.py`, `dns.py` and `network.py` hold evaluators that turn observation dicts into results.
- **I/O lives elsewhere:**
  - `collect.py` does the network work: one HTTPS and one HTTP GET, TLS handshakes, DNS lookups, and reading stored ports. All of it uses injectable functions.
  - `run.py` picks targets, enforces scope, calls the collectors and evaluators, and upserts `RiskCheck` rows.
- A `risk_checks` Celery stage runs it in every scan mode.
- `limes/scoring.py` becomes v2 and adds fresh failed checks as penalties.
- The asset modal, score card and dashboard trend show the results.

**Tech Stack:** Django 3.2, Celery 5.4, PostgreSQL, Python stdlib `ssl`/`socket`, `requests==2.31.0`, `dnspython==2.6.1`.

**Spec:** `docs/superpowers/specs/2026-10-17-risk-checks-design.md`

## Global Constraints

- **Contact:** at most one HTTPS GET of `/` (following up to 3 same-host redirects), one HTTP GET of `/`, one TLS handshake on 443, and one handshake attempt each for TLS 1.0 and TLS 1.1.
  - Every contacted host must pass `scope.may_contact(project, [host])` first.
  - A host that is refused gets no results.
  - DNS lookups use the system resolver. Ports are read from the database only, never probed.
- **Timeouts and limits:** 5 seconds per network operation. `MAX_HOSTS = 200` hosts per run, oldest-checked first (never-checked first), carrying a `NOTE:` naming the ceiling.
- **Statuses:** `pass`, `fail`, `error` and `not_applicable`. Only `fail` ever scores. A refused legacy-TLS context or handshake capability is `error`, never `pass`.
- **Freshness:** a failed check scores only if its `last_checked` is within `CHECK_FRESH = 30 days`. Ports count only from InternetDB `fetched_at` within 30 days, or from naabu `IpAddress.ports`.
- **No inheritance:** root-level email and DNS results belong to the root asset only. IP network results belong to the IP asset only.
- **TLS verification is never disabled.** That means no `verify=False` and no `CERT_NONE`.
  - Certificate problems are classified from `ssl.SSLCertVerificationError.verify_code` on a verified handshake: 10 means expired; 18, 19, 20 and 21 mean untrusted or self-signed; 62 means hostname mismatch.
  - A legacy handshake that reaches certificate verification and fails there has accepted the protocol.
- **HTTP requests:** use `ScanIdentity.for_domain(domain)`: `ua()` plus non-secret and secret header values. Header values never appear in evidence.
- **Severity ints** follow the findings scale: high 3, medium 2, low 1. The penalty table `{3: 80, 2: 25, 1: 5}` and the ceilings are unchanged from v1.
- **Style:**
  - tabs in `stages.py`, `control.py`, `api/views.py` and `asset.js`;
  - 4 spaces everywhere else;
  - no `shell=True`;
  - no network in tests: every collector takes injected callables.
- **Tests:** `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <dotted.path>`; the controller may use an equivalent local runner.
- **Commits:** identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`, no AI attribution, no push without an explicit user yes.

## Check catalogue (exact ids and severities)

| id | group | severity | applies to |
|---|---|---|---|
| `web.https_missing` | web | high | hosts where HTTP answers and HTTPS does not |
| `web.http_no_redirect` | web | medium | HTTP answers without redirecting to `https://` on the same host |
| `web.hsts_missing` | web | medium | HTTPS answers without `Strict-Transport-Security` |
| `web.csp_missing` | web | low | HTTPS response without `Content-Security-Policy` |
| `web.frame_options_missing` | web | low | no `X-Frame-Options` and no `frame-ancestors` in CSP |
| `web.content_type_options_missing` | web | low | `X-Content-Type-Options` is not `nosniff` |
| `web.cookie_flags_missing` | web | low | any `Set-Cookie` lacking Secure, HttpOnly or SameSite |
| `web.version_disclosure` | web | low | `Server` or `X-Powered-By` contains a digit |
| `tls.cert_expired` | tls | high | `not_after` is before now |
| `tls.cert_expiring` | tls | medium | `not_after` is within 14 days |
| `tls.cert_hostname_mismatch` | tls | high | the certificate doesn't match the host |
| `tls.cert_untrusted` | tls | high | self-signed or not verifiable against system trust |
| `tls.legacy_protocol` | tls | medium | TLS 1.0 or 1.1 handshake succeeded |
| `email.spf_missing` | email | medium | root has no `v=spf1` TXT record |
| `email.spf_permissive` | email | medium | SPF ends with `+all` or `?all` |
| `email.dmarc_missing` | email | medium | no `v=DMARC1` TXT at `_dmarc.<root>` |
| `email.dmarc_none` | email | low | DMARC `p=none` |
| `email.mx_unprotected` | email | low | MX present but SPF or DMARC missing |
| `dns.dnssec_missing` | dns | low | no DS record for the root |
| `dns.caa_missing` | dns | low | no CAA record at the root |
| `net.exposed_<svc>` | network | high, except `ftp` medium | owned IP with the port open |

The `<svc>` ports are: `ftp` 21, `telnet` 23, `smb` 445, `rdp` 3389, `mssql` 1433, `oracle` 1521, `mysql` 3306, `postgres` 5432, `redis` 6379, `elasticsearch` 9200, `memcached` 11211, `mongodb` 27017, `docker` 2375, `vnc` 5900.

Each catalogue entry carries a one-sentence `title` and `fix`. The wording is left to the implementer.

## Verified on real hosts while planning (2026-10-17)

These results come from badssl.com and www.google.com, with default verification on and OpenSSL 3.5.7:
- `expired.badssl.com`: verify_code 10.
- `self-signed.badssl.com`: 18.
- `untrusted-root.badssl.com`: 19.
- `wrong.host.badssl.com`: 62.
- `badssl.com`: verifies, and `notAfter` is readable.
- **Legacy probes:**
  - `tls-v1-0.badssl.com:1010` accepts TLS 1.0 and rejects 1.1 with `UNSUPPORTED_PROTOCOL`;
  - `tls-v1-2.badssl.com:1012` rejects both by **resetting the connection**;
  - `www.google.com` really does accept TLS 1.0 and 1.1, so the check flags large sites too, as UpGuard does.

## Review Focus

1. **A timeout, DNS failure or refused legacy-TLS handshake must never read as `pass`.**
   - Task 2 `test_legacy_context_refused_is_error`;
   - Task 4 `test_timeouts_become_error_not_pass`.
2. **An out-of-scope or reserved-address host must never be contacted.** Task 4 `test_refused_host_is_never_contacted`.
3. **A root-level failure must not repeat across subdomains, and IP failures must not be copied to hostnames.** Task 5 `test_root_and_ip_results_are_not_inherited`.
4. **Stale failed checks must stop scoring, and `error` / `not_applicable` must never score.** Task 5 `test_stale_error_and_na_never_score`.
5. **Header and cookie values from the target are attacker text.** They must render escaped, and secret request headers must never appear in evidence.
   - Task 4 `test_evidence_never_contains_request_secrets`;
   - Task 6's real-UI check with a `<script>` cookie name.

---

### Task 1: Catalogue and `RiskCheck` model

**Files:**
- Create: `web/limes/checks/__init__.py`, `web/limes/checks/catalogue.py`
- Modify: `web/startScan/asset_models.py` (`RiskCheck`, `__all__`), then generate `makemigrations startScan -n riskcheck` (`0019`)
- Test: `web/tests/core/test_risk_checks.py`

**Interfaces:**
- Produces:
  - `catalogue.CHECKS: dict[str, Check]`, where `Check = namedtuple('Check', 'id group severity title fix')` and `severity` is the int 3, 2 or 1;
  - `catalogue.RISKY_PORTS: dict[int, tuple[str, int]]`, mapping a port to (`svc`, severity);
  - `catalogue.Result = namedtuple('Result', 'check status evidence')`;
  - `catalogue.STATUSES = ('pass', 'fail', 'error', 'not_applicable')`;
  - the `RiskCheck(asset FK related_name='risk_checks', check_id CharField(60), status CharField(16), severity IntegerField, evidence JSONField(default=dict), first_seen, last_checked)` model, with `unique_together = ('asset', 'check_id')`.

- [ ] **Step 1: Write the failing tests** in `web/tests/core/test_risk_checks.py`, class `CatalogueTest(SimpleTestCase)`:
  - `test_ids_and_severities_match_the_spec`: assert that the full id → severity map equals the catalogue table above (all 20 non-network ids, plus `net.exposed_<svc>` for each of the 14 ports), that `CHECKS['net.exposed_ftp'].severity == 2`, and that every other `net.exposed_*` has severity 3;
  - `test_every_check_has_title_and_fix`: assert both strings are non-empty and contain no newline.
  
  Then class `RiskCheckModelTest(TestCase)`:
  - `test_one_row_per_asset_and_check`: creating a second `RiskCheck` with the same `(asset, check_id)` raises `IntegrityError`.
- [ ] **Step 2: Run the tests.** `... manage.py test tests.core.test_risk_checks`. Expected: ImportError for `limes.checks`.
- [ ] **Step 3: Implement** `catalogue.py` and the model, then generate the migration.
- [ ] **Step 4: Run the tests.** The same command, then `makemigrations --check --dry-run`. Expected: OK, then `No changes detected`.
- [ ] **Step 5: Commit** "Add the risk-check catalogue and the RiskCheck model".

### Task 2: Web and TLS evaluators

**Files:**
- Create: `web/limes/checks/web.py`, `web/limes/checks/tls.py`
- Test: `web/tests/core/test_risk_checks.py` (classes `WebEvalTest`, `TlsEvalTest`, both `SimpleTestCase`)

**Interfaces:**
- Consumes: `CHECKS`, `Result` (Task 1).
- Produces:
  - `web.evaluate(obs: dict) -> list[Result]` takes `obs = {'https': {'status': int, 'headers': {lowercased name: value}, 'cookies': [raw Set-Cookie str], 'url': str} | None | 'error', 'http': {'status': int, 'location': str | None} | None | 'error'}`. `None` means no answer; `'error'` means a timeout or other failure.
  - `tls.evaluate(obs: dict, now: datetime) -> list[Result]` takes `obs = {'cert': {'not_after': datetime | None, 'expired': bool, 'hostname_ok': bool, 'trusted': bool} | None | 'error', 'legacy': {'TLSv1': bool | None, 'TLSv1_1': bool | None}}`. `not_after` is known only after a verified handshake; `expired` comes from verify code 10. `None` in `legacy` means the context or handshake capability was refused (error); `False` means rejected; `True` means accepted.
  - Both return exactly one `Result` per check in their group.

- [ ] **Step 1: Write the failing tests:**
  - `test_good_https_site_passes`: HTTPS 200 with HSTS, CSP containing `frame-ancestors 'self'`, `nosniff` and a cookie `a=1; Secure; HttpOnly; SameSite=Lax`, and HTTP 301 to `https://h/`. Every web result is `pass`.
  - `test_no_web_server_is_not_applicable`: `https` and `http` both `None`, so all 8 results are `not_applicable`.
  - `test_http_only_host`: `https=None` and HTTP 200, so `web.https_missing` is `fail` and `web.http_no_redirect` is `fail`. The header checks are `not_applicable`, because there is no HTTPS response.
  - `test_header_failures_carry_evidence`: HTTPS with `server: nginx/1.18.0`, no CSP, `x-frame-options` absent and a cookie `sid=x`. `web.version_disclosure` fails with `evidence == {'server': 'nginx/1.18.0'}`; `web.cookie_flags_missing` fails with `evidence['cookies'] == ['sid']` (the name only, never the value).
  - `test_https_error_is_error`: `https='error'`, so every HTTPS-dependent check is `error`.
  - `TlsEvalTest.test_expiry_windows`: `not_after` at now+10d gives `cert_expiring` fail and `cert_expired` pass; now+30d gives both pass. `{'expired': True, 'not_after': None}` gives `cert_expired` fail and `cert_expiring` `not_applicable`.
  - `test_mismatch_untrusted_legacy`: `hostname_ok=False` and `trusted=False` make those two checks fail. `legacy={'TLSv1': True, 'TLSv1_1': False}` makes `tls.legacy_protocol` fail with `evidence == {'accepted': ['TLSv1']}`.
  - `test_legacy_context_refused_is_error`: `legacy={'TLSv1': None, 'TLSv1_1': False}` gives `tls.legacy_protocol` status `error`.
  - `test_no_tls_is_not_applicable`: `cert=None` gives every TLS result `not_applicable`.
- [ ] **Step 2: Run them.** Expected: ImportError.
- [ ] **Step 3: Implement** the two pure modules. Header names are matched case-insensitively. "Contains a digit" means a version leak.
- [ ] **Step 4: Run them.** Expected: OK.
- [ ] **Step 5: Commit** "Evaluate website and TLS risk checks".

### Task 3: Email, DNS and network evaluators

**Files:**
- Create: `web/limes/checks/email.py`, `web/limes/checks/dns.py`, `web/limes/checks/network.py`
- Test: `web/tests/core/test_risk_checks.py` (`MailDnsEvalTest`, `NetworkEvalTest`)

**Interfaces:**
- Produces:
  - `email.evaluate(obs) -> list[Result]` with `obs = {'txt': [str] | 'error', 'dmarc': [str] | 'error', 'mx': [str] | 'error'}`;
  - `dns.evaluate(obs) -> list[Result]` with `obs = {'ds': bool | 'error', 'caa': bool | 'error'}`;
  - `network.evaluate(ports: dict[int, list[str]]) -> list[Result]`, which takes a port → sources map (e.g. `{3389: ['internetdb 2026-10-10']}`) and returns one `Result` per `RISKY_PORTS` entry, `fail` with `evidence={'port': p, 'seen_by': sources}` when present, otherwise `pass`. `network.evaluate(None)` (no fresh data) returns every result as `error`.

- [ ] **Step 1: Write the failing tests:**
  - `test_spf_and_dmarc_good`: `txt=['v=spf1 include:_spf.x -all']`, `dmarc=['v=DMARC1; p=reject']`, `mx=['mx.x']`. All email checks pass.
  - `test_spf_permissive_and_dmarc_none`: `~all` passes. `+all` and `?all` each make `email.spf_permissive` fail. `p=none` makes `email.dmarc_none` fail.
  - `test_missing_records`: `txt=[]`, `dmarc=[]`, `mx=['mx.x']` make `spf_missing`, `dmarc_missing` and `mx_unprotected` fail. With `mx=[]`, `mx_unprotected` passes.
  - `test_lookup_error_is_error`: `txt='error'` gives `spf_missing` and `spf_permissive` status `error`.
  - `test_dnssec_and_caa`: `{'ds': False, 'caa': True}` gives `dnssec_missing` fail and `caa_missing` pass. `'error'` gives `error`.
  - `NetworkEvalTest.test_risky_ports`: `{3389: ['naabu'], 443: ['internetdb 2026-10-10']}` gives `net.exposed_rdp` fail with `seen_by == ['naabu']`, and every other `net.exposed_*` pass. Port 443 creates no result.
  - `test_no_fresh_port_data_is_error`: `evaluate(None)` gives all 14 results `error`.
- [ ] **Step 2: Run them.** Expected: ImportError.
- [ ] **Step 3: Implement** the three modules.
- [ ] **Step 4: Run them.** Expected: OK.
- [ ] **Step 5: Commit** "Evaluate email, DNS and exposed-service risk checks".

### Task 4: Collectors and the run

**Files:**
- Create: `web/limes/checks/collect.py`, `web/limes/checks/run.py`
- Test: `web/tests/core/test_risk_checks.py` (`CollectTest(SimpleTestCase)`, `RunTest(TestCase)`)

**Interfaces:**
- Consumes: the evaluators from Tasks 2 and 3, `RiskCheck` (Task 1), `scope.may_contact`, `identity.ScanIdentity`, and `scoring._root_of`.
- Produces:
  - `collect.observe_http(host, ident, get=requests.get) -> dict` returns the web `obs` shape. It calls `get(url, headers=..., timeout=5, allow_redirects=False)`, with default verification. It follows at most 3 same-host redirects. `requests.exceptions.SSLError` means `'error'`: the TLS checks report the certificate, and the header checks become `error`, never `pass`. Any other `ConnectionError` means `None`, and other `requests` exceptions mean `'error'`.
  - `collect.observe_tls(host, connect=_tls_connect) -> dict` returns the TLS `obs` shape.
  - `collect.observe_mail_dns(root, resolve=_resolve) -> (mail_obs, dns_obs)`.
  - `collect.ports_for_ip(asset, now) -> dict[int, list[str]] | None`.
  - `run.run_checks(project, root, now=None, observers=None) -> {'checked': int, 'failed': int}`. `observers` is a dict with keys `http`, `tls`, `mail_dns` and `ports`, defaulting to the collect functions; tests pass fakes.
  - `run.MAX_HOSTS = 200`.

- [ ] **Step 1: Write the failing tests:**
  - `CollectTest.test_redirect_is_followed_within_host_only`: a fake `get` returns `301 Location: https://h/a`, then 200. The result `https.status == 200`. A redirect to another host stops, and that 3xx response is evaluated.
  - `test_tls_verify_codes_are_classified`: a fake `connect` raises `SSLCertVerificationError` with `verify_code` 10, 18 and 62 in turn, giving `expired`, `trusted=False` and `hostname_ok=False` respectively. A legacy probe that raises `SSLCertVerificationError` gives `True`. A legacy probe whose fake handshake raises `ConnectionResetError` gives `False`. One whose fake connect raises `TimeoutError` gives `None`.
  - `test_timeouts_become_error_not_pass`: a fake `get` raises `requests.exceptions.ReadTimeout`, so `https == 'error'`. An `SSLError` also gives `'error'`. Feeding the result to `web.evaluate` yields no `pass` for HTTPS checks.
  - `test_evidence_never_contains_request_secrets`: an ident with a secret header value `s3cr3t` gives an `obs` whose repr does not contain `s3cr3t`.
  - `test_ports_union_and_freshness`: an IP asset with `enrichment['internetdb'] = {'ports': [3389], 'fetched_at': now-5d}` and an `IpAddress` with naabu port 6379 gives `{3389: ['internetdb ...'], 6379: ['naabu']}`. InternetDB `fetched_at` at now−40d with no naabu data gives `None`.
  - `RunTest.test_writes_one_row_per_check_and_updates_in_place`:
    - an owned root `x.com` and host `a.x.com`, with fake observers: the web and TLS checks are written on both hosts, mail and DNS on the root only;
    - running again with HSTS added flips `web.hsts_missing` to `pass` on the same row, keeping `first_seen` and updating `last_checked`.
  - `test_refused_host_is_never_contacted`: `scope.may_contact` is patched to refuse `a.x.com`. The fake `http` observer records calls and never sees `a.x.com`, and no web or TLS rows are written for it.
  - `test_cap_checks_oldest_first`: with `MAX_HOSTS` patched to 1, a never-checked host is chosen before one checked yesterday.
  - `test_only_owned_assets_under_this_root`: candidate, co_brand and another root's hosts get no rows.
- [ ] **Step 2: Run them.** Expected: ImportError.
- [ ] **Step 3: Implement** `collect.py` and `run.py`.
  - `_tls_connect` uses `ssl.create_default_context()`.
    - Success: `not_after` from `getpeercert()`, `trusted` and `hostname_ok` True.
    - `SSLCertVerificationError`: classify by `verify_code`.
  - Legacy probes use a default (verifying) context pinned to TLS 1.0 or 1.1 with `@SECLEVEL=0` ciphers.
    - Success, or an `SSLCertVerificationError`, means `True` (the protocol was negotiated).
    - Any other `SSLError`, or a `ConnectionResetError`, during the handshake means `False`. Real TLS-1.2-only servers reset instead of sending an alert.
    - Failing to open the TCP connection, or a timeout, means `None` (error).
    - An `SSLError` or `ValueError` while creating or configuring the context means `None`.
  - The run upserts with `update_or_create(asset, check_id, defaults={status, severity, evidence, last_checked})`.
- [ ] **Step 4: Run them.** Expected: OK.
- [ ] **Step 5: Commit** "Collect observations and run risk checks within scope".

### Task 5: Stage, workflow and `limes-score-v2`

**Files:**
- Modify: `web/limes/tasks/stages.py` (new `risk_checks` task), `web/limes/tasks/control.py` (`build_workflow`), `web/limes/celery_routing.py` (`'risk_checks': (SCAN, 1 * HOUR)`), `web/limes/scoring.py`
- Test: `web/tests/core/test_risk_checks.py` (`StageTest`, `ScoreV2Test`), `web/tests/core/test_scoring.py`, `web/tests/core/test_asset_api.py`, `web/tests/core/test_scan_mode.py` (or wherever `build_workflow` is tested)

**Interfaces:**
- Consumes: `run.run_checks` (Task 4).
- Produces:
  - the `risk_checks(ctx)` Celery stage, skipped unless the domain's root is `owned_root` (same guard as `passive_intel`);
  - `scoring.VERSION = 'limes-score-v2'`;
  - `scoring.CHECK_FRESH = timedelta(days=30)`;
  - `scored_assets` now includes owned `kind='ip'`;
  - `project_score(...)['check_coverage']` (0–1, or `None`);
  - penalty rows gain `'kind': 'check' | 'finding'`.

- [ ] **Step 1: Write the failing tests:**
  - **Workflow:** `asm` is `subdomain_discovery → passive_intel → risk_checks → screenshot`. In `full`, `risk_checks` comes directly after `port_scan`.
  - `ScoreV2Test.test_failed_check_costs_points`: an owned host with a fresh `fail` `web.hsts_missing` (medium) and no vulnerability baseline scores 925, and `assessed` is True.
  - `test_ceiling_applies_to_checks`: a fresh `tls.cert_expired` (high) caps the score at 799.
  - `test_root_and_ip_results_are_not_inherited`: an `email.dmarc_missing` fail on the root costs only the root (subdomain `a.x.com` stays 950). An IP's `net.exposed_redis` costs only the IP.
  - `test_stale_error_and_na_never_score`: a fail checked 31 days ago, plus `error` and `not_applicable` rows, leaves the score at 950. Only the stale fail's asset counts as unassessed if it has nothing fresh.
  - `test_checks_and_findings_add_up`: one high finding in the baseline plus one low check gives `min(950−80−5, 799)`, with two rows of different `kind`.
  - `test_check_coverage`: 2 scored assets, 1 with a fresh non-error result, gives `check_coverage == 0.5`.
  - Update the existing assertions that expect `'limes-score-v1'` to `'limes-score-v2'` in `test_scoring.py` and `test_asset_api.py`.
- [ ] **Step 2: Run them.** Expected: the workflow assertions and `ScoreV2Test` fail.
- [ ] **Step 3: Implement.**
  - Add the stage (tabs) and its workflow placement.
  - Add the routing entry.
  - In scoring: `_check_penalties(project, now) -> {asset_id: {check_id: severity}}` reads fresh `fail` rows on scored assets.
  - `assessed_assets` becomes the baseline-assessed set ∪ assets with a fresh `pass`/`fail` row.
  - Merge the check penalties into `_penalties` per asset (the category is the `check_id`, which never collides with finding templates because of its `group.` prefix).
  - Bump `VERSION`.
- [ ] **Step 4: Run them.** `tests.core.test_risk_checks tests.core.test_scoring tests.core.test_asset_api tests.core.test_dashboard_stats`, plus the workflow test module. Expected: OK.
- [ ] **Step 5: Commit** "Run risk checks in every scan and score them as limes-score-v2".

### Task 6: UI: asset risks, coverage and trend marker

**Files:**
- Modify: `web/api/views.py` (`AssetDatatableViewSet.retrieve` adds `risk_checks`), `web/static/custom/asset.js` (modal "Risk checks" table; a score-card line for check coverage), `web/dashboard/stats.py` (trend points gain `version`), `web/dashboard/templates/dashboard/index.html` (an annotation where `version` changes)
- Test: `web/tests/core/test_asset_api.py`, `web/tests/core/test_dashboard_stats.py`

**Interfaces:**
- Produces:
  - retrieve JSON `risk_checks: [{check, title, fix, status, severity, evidence, last_checked}]`, failed first, then by severity descending;
  - trend points `{date, score, version}`.

- [ ] **Step 1: Write the failing tests:**
  - `test_retrieve_lists_risk_checks_failed_first`: three rows (pass low, fail low, fail high) come back in the order fail-high, fail-low, pass, with `title` and `fix` from the catalogue.
  - `test_trend_carries_version`: two snapshots with versions v1 and v2 produce trend items with `version`.
- [ ] **Step 2: Run them.** Expected: `KeyError` on `risk_checks` and `version`.
- [ ] **Step 3: Implement.**
  - The modal renders the table with `asset_esc` on every field, including evidence values.
  - The score card adds "N% of owned assets checked in 30 days".
  - The trend chart adds an x-axis annotation labelled `model <version>` at the first point whose version differs from the previous point.
- [ ] **Step 4: Verify.** Run the tests above, `node --check`, and the template check. Then the real UI:
  - seed an owned host with a fail `web.cookie_flags_missing` whose evidence cookie name is `<script>alert(1)</script>`, and v1/v2 snapshots;
  - the modal shows the check, its fix and the cookie name as text, with no `<script>` element and no dialog;
  - the score card shows the check-coverage line;
  - the dashboard trend shows the model annotation;
  - there are no console errors.
- [ ] **Step 5: Commit** "Show risk checks, check coverage and the score-model change".
