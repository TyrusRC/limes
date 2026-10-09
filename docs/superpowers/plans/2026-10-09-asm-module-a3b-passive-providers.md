# ASM module A3b — Passive providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add crt.sh certificate co-tenancy, Shodan InternetDB and RIPEstat as passive sources: new hostnames under owned roots, candidate roots for the review queue, and per-IP enrichment — without contacting any target.

**Architecture:** Pure provider modules in `web/limes/intel/` (URL builders + parsers) share one polite HTTP helper (`intel/http.py`) and an offline registrable-domain helper (`intel/domains.py`). `web/limes/tasks/intel.py` orchestrates providers against the inventory through `inventory.upsert_candidate` / `upsert_hostname_asset`; a thin `passive_intel` Celery stage runs it after discovery in `asm` and `full` workflows. `Asset.enrichment` stores per-provider snapshots shown in the asset modal.

**Tech Stack:** Django 3.2, Celery 5.4, PostgreSQL, `requests`, `tldextract` (offline snapshot), `validators`.

**Spec:** `docs/superpowers/specs/2026-10-09-asm-module-a3b-passive-providers-design.md`

## Global Constraints

- Contact only `crt.sh`, `internetdb.shodan.io`, `stat.ripe.net` — never a target.
- Every provider request: `timeout=30`, header `User-Agent: Limes-ASM`, up to 2 retries with exponential backoff on 429/5xx/connection errors, per-provider minimum interval (crt.sh 5 s, InternetDB 1 s, RIPEstat 0.25 s). `get_json` never raises; failures return `(None, None)`.
- Registrable-domain decisions use `tldextract.TLDExtract(suffix_list_urls=())` — no network.
- Existing assets never change `scope_tier` through this slice; `rejected` is never re-suggested.
- Only an `owned_root` root is expanded. Certificates with more than 20 distinct registrable domains are skipped for candidates. At most 10 000 names per root. IPs enriched within 24 h are skipped.
- Hostnames found on dependency IPs never become candidates.
- Migrations generated with `makemigrations`; final `makemigrations --check` clean.
- Style: tabs in `web/limes/tasks/stages.py`, `control.py`, `asset.js`; 4 spaces in `web/limes/intel/*`, `web/limes/tasks/intel.py`, `inventory.py`, `resolution.py`, `startScan/*`, `api/serializers.py` (AssetSerializer block), tests.
- Tests: `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <dotted.path>`; no test touches the network.
- Commit identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`; no AI attribution; no push without an explicit user yes.

## Review Focus

1. **A provider returns junk** (HTML error page with 200, a list where an object is expected, huge SAN lists) — parsers and `get_json` must return empty/None, never raise into the scan → Task 1 invalid-JSON test, Task 2 malformed-row fixtures.
2. **Candidate equals an owned root under a different spelling** (`Example.COM.`, IDN) — must not become a candidate → Task 3 `test_candidate_under_owned_root_is_not_created`, Task 1 IDN test.
3. **One provider down for the whole run** (crt.sh timeouts) — the others still enrich and the stage completes → Task 5 `test_one_failing_provider_does_not_stop_others`.
4. **A transient failure is cached as "no data"** — a `None` status must not write `fetched_at`, so the next run retries → Task 4 `test_provider_failure_is_not_cached`.
5. **Workflow order** — `passive_intel` must run after discovery and before the first guarded stage, or crt.sh hostnames are never resolved this run → Task 5 `test_passive_intel_runs_right_after_discovery`.

---

### Task 1: Offline domains helper + polite HTTP helper

**Files:**
- Create: `web/limes/intel/__init__.py` (empty), `web/limes/intel/domains.py`, `web/limes/intel/http.py`
- Test: `web/tests/core/test_intel_http.py` (create)

**Interfaces:**
- Produces: `domains.registrable(name: str) -> str | None` (punycode, lower-case); `http.get_json(url, *, provider, session=requests, clock=time.monotonic, sleep=time.sleep) -> tuple[int | None, object | None]`; `http.MIN_INTERVAL`, `http.TIMEOUT = 30`, `http.RETRIES = 2`; module state `http._last: dict`.

- [ ] **Step 1: Failing tests** (`test_intel_http.py`):
```python
from unittest import mock

import requests
from django.test import SimpleTestCase

from limes.intel import domains, http


class RegistrableTest(SimpleTestCase):
    def test_offline_and_normalized(self):
        with mock.patch('requests.sessions.Session.request', side_effect=AssertionError('network used')):
            self.assertEqual(domains.registrable('a.b.Example.CO.UK.'), 'example.co.uk')
            self.assertEqual(domains.registrable('shop.Bücher.de'), 'xn--bcher-kva.de')
        for bad in ('', None, 'localhost', 'com'):
            self.assertIsNone(domains.registrable(bad), bad)


class Resp:
    def __init__(self, status, body=None, bad_json=False):
        self.status_code, self.body, self.bad_json = status, body, bad_json

    def json(self):
        if self.bad_json:
            raise ValueError('not json')
        return self.body


class Session:
    def __init__(self, *items):
        self.items, self.calls = list(items), []

    def get(self, url, timeout=None, headers=None):
        self.calls.append((url, timeout, headers))
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class GetJsonTest(SimpleTestCase):
    def setUp(self):
        http._last.clear()
        self.now, self.sleeps = [0.0], []

    def clock(self):
        return self.now[0]

    def sleep(self, s):
        self.sleeps.append(s)
        self.now[0] += s

    def get(self, session, provider='internetdb'):
        return http.get_json('https://x/', provider=provider, session=session, clock=self.clock, sleep=self.sleep)

    def test_success_uses_timeout_and_user_agent(self):
        s = Session(Resp(200, {'a': 1}))
        self.assertEqual(self.get(s), (200, {'a': 1}))
        self.assertEqual(s.calls[0][1], 30)
        self.assertEqual(s.calls[0][2]['User-Agent'], 'Limes-ASM')

    def test_retries_on_429_then_succeeds(self):
        s = Session(Resp(429), Resp(200, [1]))
        self.assertEqual(self.get(s), (200, [1]))
        self.assertEqual(len(s.calls), 2)
        self.assertIn(1, self.sleeps)  # backoff 2**0

    def test_gives_up_after_retries(self):
        s = Session(Resp(503), Resp(503), Resp(503))
        self.assertEqual(self.get(s), (None, None))
        self.assertEqual(len(s.calls), 3)

    def test_connection_errors_never_raise(self):
        err = requests.ConnectionError('down')
        self.assertEqual(self.get(Session(err, err, err)), (None, None))

    def test_404_is_returned_not_retried(self):
        s = Session(Resp(404, {'detail': 'No information available'}))
        self.assertEqual(self.get(s), (404, {'detail': 'No information available'}))
        self.assertEqual(len(s.calls), 1)

    def test_bad_json_returns_none_body(self):
        self.assertEqual(self.get(Session(Resp(200, bad_json=True))), (200, None))

    def test_min_interval_per_provider(self):
        s = Session(Resp(200, {}), Resp(200, {}))
        self.get(s, provider='crtsh')
        self.get(s, provider='crtsh')
        self.assertIn(5.0, self.sleeps)
```

- [ ] **Step 2: Run, confirm fail** — `ImportError: cannot import name 'domains'`.

- [ ] **Step 3: `web/limes/intel/domains.py`:**
```python
"""Registrable-domain decisions from the bundled public-suffix snapshot (never fetched)."""
import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def registrable(name):
    n = (name or '').strip().rstrip('.').lower()
    if not n:
        return None
    try:
        n = n.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    return _EXTRACT(n).registered_domain or None
```

- [ ] **Step 4: `web/limes/intel/http.py`:**
```python
"""Polite JSON fetches from passive third-party providers. Never contacts a target.

NOTE: rate state is per process (prefork workers each keep their own); crt.sh is often
slow or down. Upgrade path: a shared rate limiter in Redis and a local CT mirror/certstream.
"""
import logging
import time

import requests

logger = logging.getLogger(__name__)

TIMEOUT = 30
RETRIES = 2
MIN_INTERVAL = {'crtsh': 5.0, 'internetdb': 1.0, 'ripestat': 0.25}
HEADERS = {'User-Agent': 'Limes-ASM'}
_last = {}


def get_json(url, *, provider, session=requests, clock=time.monotonic, sleep=time.sleep):
    """(status, parsed JSON | None); (None, None) after retries. Never raises."""
    for attempt in range(RETRIES + 1):
        wait = MIN_INTERVAL.get(provider, 1.0) - (clock() - _last.get(provider, float('-inf')))
        if wait > 0:
            sleep(wait)
        _last[provider] = clock()
        try:
            resp = session.get(url, timeout=TIMEOUT, headers=HEADERS)
        except requests.RequestException as e:
            logger.warning(f'{provider}: request failed: {e}')
        else:
            if resp.status_code != 429 and resp.status_code < 500:
                try:
                    return resp.status_code, resp.json()
                except ValueError:
                    logger.warning(f'{provider}: non-JSON response ({resp.status_code})')
                    return resp.status_code, None
            logger.warning(f'{provider}: HTTP {resp.status_code}')
        if attempt < RETRIES:
            sleep(2 ** attempt)
    return None, None
```

- [ ] **Step 5: Run** `tests.core.test_intel_http` → PASS. **Step 6: Commit** — `git commit -m "Add offline domain helper and polite provider HTTP client"`.

---

### Task 2: Provider parsers (crt.sh, InternetDB, RIPEstat)

**Files:**
- Create: `web/limes/intel/crtsh.py`, `web/limes/intel/internetdb.py`, `web/limes/intel/ripestat.py`
- Create fixtures: `web/tests/core/fixtures/crtsh_sample.json`, `internetdb_sample.json`, `internetdb_404.json`, `ripestat_network_info.json`, `ripestat_as_overview.json`
- Test: `web/tests/core/test_intel_parsers.py` (create)

**Interfaces:**
- Produces: `crtsh.build_url(root) -> str`, `crtsh.parse(rows) -> list[{'id': int, 'names': list[str]}]`; `internetdb.build_url(ip) -> str`, `internetdb.parse(obj) -> dict | None` with keys `ports, cpes, vulns, tags, hostnames`; `ripestat.network_info_url(ip)`, `ripestat.as_overview_url(asn)`, `ripestat.parse_network_info(obj) -> {'asn': str|None, 'prefix': str|None}`, `ripestat.parse_as_overview(obj) -> {'holder': str|None}`.

- [ ] **Step 1: Fixtures.**
`crtsh_sample.json`:
```json
[
  {"id": 101, "common_name": "example.com", "name_value": "example.com\nwww.example.com\n*.example.com"},
  {"id": 102, "common_name": "api.example.com", "name_value": "api.example.com\nshop.example-brand.net\n*.example-brand.net\nexample.org"},
  {"id": "bad", "name_value": "x.example.com"},
  "not a dict",
  {"id": 103, "name_value": "not a domain\nWWW.Example.COM."}
]
```
`internetdb_sample.json`:
```json
{"cpes": ["cpe:/a:nginx:nginx:1.18.0"], "hostnames": ["Mail.Partner-Co.com.", "www.example.com", 7], "ip": "203.0.114.7", "ports": [443, 80, 80, "x"], "tags": ["cloud"], "vulns": ["CVE-2021-23017"]}
```
`internetdb_404.json`: `{"detail": "No information available"}`
`ripestat_network_info.json`: `{"data": {"asns": ["13335"], "prefix": "104.16.0.0/13"}, "status": "ok"}`
`ripestat_as_overview.json`: `{"data": {"holder": "CLOUDFLARENET - Cloudflare, Inc., US", "resource": "13335"}, "status": "ok"}`

- [ ] **Step 2: Failing tests** (`test_intel_parsers.py`):
```python
import json
import os

from django.test import SimpleTestCase

from limes.intel import crtsh, internetdb, ripestat

FX = os.path.join(os.path.dirname(__file__), 'fixtures')


def load(name):
    with open(os.path.join(FX, name)) as f:
        return json.load(f)


class CrtshTest(SimpleTestCase):
    def test_url(self):
        self.assertEqual(crtsh.build_url('example.com'),
                         'https://crt.sh/?q=%25.example.com&output=json&exclude=expired')

    def test_parse(self):
        self.assertEqual(crtsh.parse(load('crtsh_sample.json')), [
            {'id': 101, 'names': ['example.com', 'www.example.com']},
            {'id': 102, 'names': ['api.example.com', 'shop.example-brand.net', 'example-brand.net', 'example.org']},
            {'id': 103, 'names': ['www.example.com']},
        ])

    def test_parse_junk(self):
        for junk in (None, {}, 'html', [None, 1]):
            self.assertEqual(crtsh.parse(junk), [])


class InternetDbTest(SimpleTestCase):
    def test_url(self):
        self.assertEqual(internetdb.build_url('203.0.114.7'), 'https://internetdb.shodan.io/203.0.114.7')

    def test_parse(self):
        self.assertEqual(internetdb.parse(load('internetdb_sample.json')), {
            'ports': [80, 443], 'cpes': ['cpe:/a:nginx:nginx:1.18.0'], 'vulns': ['CVE-2021-23017'],
            'tags': ['cloud'], 'hostnames': ['mail.partner-co.com', 'www.example.com']})

    def test_parse_404_and_junk(self):
        self.assertIsNone(internetdb.parse(load('internetdb_404.json')))
        for junk in (None, [], 'x'):
            self.assertIsNone(internetdb.parse(junk))


class RipestatTest(SimpleTestCase):
    def test_urls(self):
        self.assertEqual(ripestat.network_info_url('104.16.1.1'),
                         'https://stat.ripe.net/data/network-info/data.json?resource=104.16.1.1&sourceapp=limes')
        self.assertEqual(ripestat.as_overview_url('13335'),
                         'https://stat.ripe.net/data/as-overview/data.json?resource=AS13335&sourceapp=limes')

    def test_parse(self):
        self.assertEqual(ripestat.parse_network_info(load('ripestat_network_info.json')),
                         {'asn': '13335', 'prefix': '104.16.0.0/13'})
        self.assertEqual(ripestat.parse_as_overview(load('ripestat_as_overview.json')),
                         {'holder': 'CLOUDFLARENET - Cloudflare, Inc., US'})

    def test_parse_junk(self):
        for junk in (None, {}, {'data': None}, {'data': {'asns': 'x', 'prefix': 5}}):
            self.assertEqual(ripestat.parse_network_info(junk), {'asn': None, 'prefix': None})
            self.assertEqual(ripestat.parse_as_overview(junk), {'holder': None})
```

- [ ] **Step 3: Run, confirm fail** — `ImportError`.

- [ ] **Step 4: Implement.** `crtsh.py`:
```python
"""crt.sh certificate transparency search (passive; third-party only)."""
from urllib.parse import quote

import validators


def build_url(root):
    return f'https://crt.sh/?q=%25.{quote(root)}&output=json&exclude=expired'


def _clean(raw):
    n = raw.strip().lower().rstrip('.')
    if n.startswith('*.'):
        n = n[2:]
    return n if n and validators.domain(n) is True else None


def parse(rows):
    certs = []
    if not isinstance(rows, list):
        return certs
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), int):
            continue
        names = []
        for raw in str(row.get('name_value') or '').split('\n'):
            n = _clean(raw)
            if n and n not in names:
                names.append(n)
        if names:
            certs.append({'id': row['id'], 'names': names})
    return certs
```
`internetdb.py`:
```python
"""Shodan InternetDB per-IP lookup (passive, keyless; non-commercial terms)."""
from urllib.parse import quote


def build_url(ip):
    return f'https://internetdb.shodan.io/{quote(ip)}'


def _strs(value):
    return [v for v in (value if isinstance(value, list) else []) if isinstance(v, str)]


def parse(obj):
    """None when InternetDB has no data (404 body) or the body is not an IP record."""
    if not isinstance(obj, dict) or 'ip' not in obj:
        return None
    ports = sorted({p for p in (obj.get('ports') if isinstance(obj.get('ports'), list) else [])
                    if isinstance(p, int) and not isinstance(p, bool)})
    hostnames = []
    for h in _strs(obj.get('hostnames')):
        h = h.strip().lower().rstrip('.')
        if h and h not in hostnames:
            hostnames.append(h)
    return {'ports': ports, 'cpes': _strs(obj.get('cpes')), 'vulns': _strs(obj.get('vulns')),
            'tags': _strs(obj.get('tags')), 'hostnames': hostnames}
```
`ripestat.py`:
```python
"""RIPEstat network/AS lookups (passive, keyless)."""
from urllib.parse import quote

BASE = 'https://stat.ripe.net/data'


def network_info_url(ip):
    return f'{BASE}/network-info/data.json?resource={quote(ip)}&sourceapp=limes'


def as_overview_url(asn):
    return f'{BASE}/as-overview/data.json?resource=AS{quote(str(asn))}&sourceapp=limes'


def _data(obj):
    data = obj.get('data') if isinstance(obj, dict) else None
    return data if isinstance(data, dict) else {}


def parse_network_info(obj):
    data = _data(obj)
    asns = data.get('asns') if isinstance(data.get('asns'), list) else []
    asn = str(asns[0]) if asns and isinstance(asns[0], (str, int)) and not isinstance(asns[0], bool) else None
    prefix = data.get('prefix') if isinstance(data.get('prefix'), str) else None
    return {'asn': asn, 'prefix': prefix}


def parse_as_overview(obj):
    holder = _data(obj).get('holder')
    return {'holder': holder if isinstance(holder, str) else None}
```

- [ ] **Step 5: Run** `tests.core.test_intel_parsers` → PASS. **Step 6: Commit** — `git commit -m "Add crt.sh, InternetDB and RIPEstat parsers"`.

---

### Task 3: Inventory — enrichment field, candidates, root lookup

**Files:**
- Modify: `web/startScan/asset_models.py` (`enrichment`), generate `web/startScan/migrations/0014_asset_enrichment.py`
- Modify: `web/limes/tasks/inventory.py` (`owned_root_values`, `upsert_candidate`)
- Modify: `web/limes/tasks/resolution.py` (extract `root_for_domain`; `resolve_domain` uses it)
- Test: `web/tests/core/test_candidates.py` (create)

**Interfaces:**
- Consumes: `inventory._append_source`, `normalize_host`.
- Produces: `Asset.enrichment: dict`; `inventory.owned_root_values(project) -> set[str]`; `inventory.upsert_candidate(project, kind, value, source, evidence) -> Asset | None`; `resolution.root_for_domain(domain) -> tuple[Project | None, Asset | None]`.

- [ ] **Step 1: Failing tests** (`test_candidates.py`):
```python
from types import SimpleNamespace

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import inventory, resolution
from startScan.models import Asset


class CandidateTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())

    def test_new_value_is_candidate_with_evidence(self):
        a = inventory.upsert_candidate(self.p, 'root_domain', 'Partner-Co.com.', 'crtsh', 'cert:1')
        self.assertEqual((a.value, a.scope_tier), ('partner-co.com', 'candidate'))
        self.assertEqual(a.sources[0]['evidence'], 'cert:1')

    def test_existing_tiers_never_change(self):
        for value, tier in (('own.com', 'owned_root'), ('nope.com', 'rejected')):
            Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier=tier)
            a = inventory.upsert_candidate(self.p, 'root_domain', value, 'crtsh', 'cert:2')
            self.assertEqual(a.scope_tier, tier)
            self.assertEqual(a.sources[-1]['source'], 'crtsh')

    def test_owned_root_values(self):
        Asset.objects.create(project=self.p, kind='root_domain', value='own.com', scope_tier='owned_root')
        Asset.objects.create(project=self.p, kind='root_domain', value='cand.com', scope_tier='candidate')
        self.assertEqual(inventory.owned_root_values(self.p), {'own.com'})

    def test_enrichment_defaults_to_dict(self):
        a = Asset.objects.create(project=self.p, kind='ip', value='8.8.8.8', scope_tier='dependency')
        a.refresh_from_db()
        self.assertEqual(a.enrichment, {})


class RootForDomainTest(TestCase):
    def test_lookup(self):
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        root = Asset.objects.create(project=p, kind='root_domain', value='example.com', scope_tier='owned_root')
        self.assertEqual(resolution.root_for_domain(SimpleNamespace(project=p, name='Example.com.')), (p, root))
        self.assertEqual(resolution.root_for_domain(SimpleNamespace(project=None, name='example.com')), (None, None))
        self.assertEqual(resolution.root_for_domain(SimpleNamespace(project=p, name='other.com')), (p, None))
```

- [ ] **Step 2: Run, confirm fail.**

- [ ] **Step 3: Field.** In `Asset` (next to `sources`): `enrichment = models.JSONField(default=dict, blank=True)`. `makemigrations startScan -n asset_enrichment` → `0014_asset_enrichment.py`.

- [ ] **Step 4: Inventory** (append to `inventory.py`):
```python
def owned_root_values(project):
    return set(Asset.objects.filter(project=project, kind='root_domain', scope_tier='owned_root')
               .values_list('value', flat=True))


def upsert_candidate(project, kind, value, source, evidence):
    """New assets start as candidates; an existing asset keeps its tier (rejected is never re-suggested)."""
    value = normalize_host(value)
    if not value:
        return None
    asset, _ = Asset.objects.get_or_create(project=project, kind=kind, value=value,
                                           defaults={'scope_tier': 'candidate'})
    _append_source(asset, source, evidence)
    asset.save()
    return asset
```

- [ ] **Step 5: `resolution.py`** — replace the lookup inside `resolve_domain` with:
```python
def root_for_domain(domain):
    """(project, root asset) for a scan's Domain; either may be None."""
    project = getattr(domain, 'project', None)
    if not project:
        return None, None
    root = Asset.objects.filter(project=project, kind='root_domain', value=normalize_host(domain.name)).first()
    return project, root


def resolve_domain(domain, results_dir):
    """Resolve a scan's root domain inventory; 0 when the domain has no project or root asset."""
    project, root = root_for_domain(domain)
    if not project or not root:
        logger.warning('Resolve: no project/root asset for this scan, skipping')
        return 0
    return resolve_root(project, root, results_dir)
```

- [ ] **Step 6: Run** `tests.core.test_candidates tests.core.test_resolution` → PASS; `makemigrations --check` clean. **Step 7: Commit** — `git commit -m "Add asset enrichment, candidate upsert and shared root lookup"`.

---

### Task 4: Provider orchestration (`limes/tasks/intel.py`)

**Files:**
- Create: `web/limes/tasks/intel.py`
- Test: `web/tests/core/test_intel_run.py` (create)

**Interfaces:**
- Consumes: Tasks 1-3 (`http.get_json`, `domains.registrable`, parsers, `inventory.upsert_hostname_asset(project, name, parent=None, source='discovery', evidence='', scope_tier='owned_host')`, `inventory.upsert_candidate`, `inventory.owned_root_values`).
- Produces: `run_crtsh(project, root, get=http.get_json) -> dict` (`{'hostnames': int, 'candidates': int}`); `run_internetdb(project, root, get=http.get_json, now=None) -> dict` (`{'internetdb_enriched': int, 'candidates': int}`); `run_ripestat(project, root, get=http.get_json, now=None) -> dict` (`{'ripestat_enriched': int}`); constants `SHARED_CERT_LIMIT = 20`, `MAX_NAMES_PER_ROOT = 10000`, `FRESH_FOR = timedelta(hours=24)`.

- [ ] **Step 1: Failing tests** (`test_intel_run.py`):
```python
import json
import os
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import intel
from startScan.models import Asset, IpAddress

FX = os.path.join(os.path.dirname(__file__), 'fixtures')


def load(name):
    with open(os.path.join(FX, name)) as f:
        return json.load(f)


class Fake:
    """get_json stand-in: provider -> (status, body) or callable(url) -> (status, body)."""
    def __init__(self, **by_provider):
        self.by_provider, self.calls = by_provider, []

    def __call__(self, url, *, provider):
        self.calls.append((provider, url))
        r = self.by_provider[provider]
        return r(url) if callable(r) else r


class IntelRunTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        self.www = Asset.objects.create(project=self.p, kind='hostname', value='www.example.com',
                                        scope_tier='owned_host', parent=self.root)
        self.cdn_host = Asset.objects.create(project=self.p, kind='hostname', value='cdn.example.com',
                                             scope_tier='owned_host', parent=self.root)
        self.own_ip = Asset.objects.create(project=self.p, kind='ip', value='203.0.114.7', scope_tier='owned_host')
        self.dep_ip = Asset.objects.create(project=self.p, kind='ip', value='104.16.1.1', scope_tier='dependency')
        self.www.ip_addresses.add(IpAddress.objects.create(address='203.0.114.7'))
        self.cdn_host.ip_addresses.add(IpAddress.objects.create(address='104.16.1.1'))

    def tier(self, value):
        return Asset.objects.get(project=self.p, value=value).scope_tier

    # crt.sh
    def test_crtsh_hostnames_and_co_tenancy_candidates(self):
        out = intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, load('crtsh_sample.json'))))
        self.assertEqual(self.tier('api.example.com'), 'owned_host')
        self.assertEqual(Asset.objects.get(value='api.example.com').parent, self.root)
        self.assertEqual(self.tier('example-brand.net'), 'candidate')
        self.assertEqual(self.tier('example.org'), 'candidate')
        self.assertIn('cert:102 shared with example.com', Asset.objects.get(value='example.org').sources[0]['evidence'])
        self.assertFalse(Asset.objects.filter(kind='hostname', value='example.com').exists())
        self.assertEqual(out['candidates'], 2)

    def test_crtsh_never_resuggests_or_downgrades(self):
        Asset.objects.create(project=self.p, kind='root_domain', value='example.org', scope_tier='rejected')
        Asset.objects.create(project=self.p, kind='root_domain', value='example-brand.net', scope_tier='owned_root')
        intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, load('crtsh_sample.json'))))
        self.assertEqual(self.tier('example.org'), 'rejected')
        self.assertEqual(self.tier('example-brand.net'), 'owned_root')

    def test_candidate_under_owned_root_is_not_created(self):
        rows = [{'id': 7, 'name_value': 'Example.COM.\nmail.EXAMPLE.com'}]
        intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, rows)))
        self.assertFalse(Asset.objects.filter(scope_tier='candidate').exists())

    def test_mass_shared_certificate_is_skipped(self):
        names = '\n'.join(['example.com'] + [f'site{i}.com' for i in range(21)])
        intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, [{'id': 9, 'name_value': names}])))
        self.assertFalse(Asset.objects.filter(scope_tier='candidate').exists())

    def test_crtsh_failure_is_harmless(self):
        self.assertEqual(intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(None, None))),
                         {'hostnames': 0, 'candidates': 0})

    # InternetDB
    def test_internetdb_enriches_and_suggests_only_from_owned_ips(self):
        body = load('internetdb_sample.json')
        out = intel.run_internetdb(self.p, self.root, get=Fake(internetdb=lambda url: (200, dict(body, ip=url.rsplit('/', 1)[1]))))
        self.own_ip.refresh_from_db(); self.dep_ip.refresh_from_db()
        self.assertEqual(self.own_ip.enrichment['internetdb']['ports'], [80, 443])
        self.assertIn('fetched_at', self.dep_ip.enrichment['internetdb'])
        self.assertEqual(self.tier('partner-co.com'), 'candidate')
        ev = [s['evidence'] for s in Asset.objects.get(value='partner-co.com').sources]
        self.assertEqual(ev, ['ip:203.0.114.7'])  # not from the dependency IP
        self.assertEqual(out['internetdb_enriched'], 2)

    def test_internetdb_404_cached_as_no_data_and_fresh_skipped(self):
        fake = Fake(internetdb=(404, load('internetdb_404.json')))
        intel.run_internetdb(self.p, self.root, get=fake)
        self.own_ip.refresh_from_db()
        self.assertTrue(self.own_ip.enrichment['internetdb']['no_data'])
        intel.run_internetdb(self.p, self.root, get=fake)
        self.assertEqual(len(fake.calls), 2)  # second run: both IPs fresh, no calls

    def test_stale_entries_are_refetched(self):
        old = (timezone.now() - timedelta(hours=25)).isoformat()
        for ip in (self.own_ip, self.dep_ip):
            ip.enrichment = {'internetdb': {'no_data': True, 'fetched_at': old}}
            ip.save()
        fake = Fake(internetdb=(404, load('internetdb_404.json')))
        intel.run_internetdb(self.p, self.root, get=fake)
        self.assertEqual(len(fake.calls), 2)

    def test_provider_failure_is_not_cached(self):
        intel.run_internetdb(self.p, self.root, get=Fake(internetdb=(None, None)))
        self.own_ip.refresh_from_db()
        self.assertNotIn('internetdb', self.own_ip.enrichment)

    # RIPEstat
    def test_ripestat_enrichment_and_holder_cached_per_asn(self):
        def ripe(url):
            if 'network-info' in url:
                return 200, load('ripestat_network_info.json')
            return 200, load('ripestat_as_overview.json')
        fake = Fake(ripestat=ripe)
        out = intel.run_ripestat(self.p, self.root, get=fake)
        self.dep_ip.refresh_from_db()
        r = self.dep_ip.enrichment['ripestat']
        self.assertEqual((r['asn'], r['prefix'], r['holder']), ('13335', '104.16.0.0/13', 'CLOUDFLARENET - Cloudflare, Inc., US'))
        self.assertEqual(sum(1 for p, u in fake.calls if 'as-overview' in u), 1)  # one holder lookup for one ASN
        self.assertEqual(out['ripestat_enriched'], 2)
```

- [ ] **Step 2: Run, confirm fail** — `ImportError: cannot import name 'intel'`.

- [ ] **Step 3: Implement `web/limes/tasks/intel.py`:**
```python
"""Passive providers against one owned root. Contacts only crt.sh, InternetDB and RIPEstat."""
import logging
from datetime import datetime, timedelta

from django.db.models import Q
from django.utils import timezone

from limes.intel import crtsh, domains, http, internetdb, ripestat
from limes.tasks import inventory
from startScan.models import Asset, IpAddress

logger = logging.getLogger(__name__)

SHARED_CERT_LIMIT = 20      # certificates listing more registrable domains are not ownership evidence
MAX_NAMES_PER_ROOT = 10000  # NOTE: ceiling per root per run; upgrade path: paginate/stream crt.sh
FRESH_FOR = timedelta(hours=24)


def _owned_registrables(project):
    return {domains.registrable(v) or v for v in inventory.owned_root_values(project)}


def _root_ips(project, root):
    addrs = (IpAddress.objects.filter(Q(assets=root) | Q(assets__parent=root, assets__kind='hostname'))
             .values_list('address', flat=True).distinct())
    return list(Asset.objects.filter(project=project, kind='ip', value__in=list(addrs)))


def _fresh(asset, key, now):
    ts = ((asset.enrichment or {}).get(key) or {}).get('fetched_at')
    try:
        return bool(ts) and now - datetime.fromisoformat(ts) < FRESH_FOR
    except (TypeError, ValueError):
        return False


def _store(asset, key, data, now):
    asset.enrichment = {**(asset.enrichment or {}), key: {**data, 'fetched_at': now.isoformat()}}
    asset.save(update_fields=['enrichment'])


def run_crtsh(project, root, get=http.get_json):
    status, rows = get(crtsh.build_url(root.value), provider='crtsh')
    certs = crtsh.parse(rows) if status == 200 else []
    owned = _owned_registrables(project)
    hostnames = candidates = seen = 0
    for cert in certs:
        for name in cert['names']:
            if seen >= MAX_NAMES_PER_ROOT:
                break
            if name.endswith('.' + root.value):
                inventory.upsert_hostname_asset(project, name, parent=root, source='crtsh',
                                                evidence=f'cert:{cert["id"]}')
                hostnames += 1
                seen += 1
        regs = {r for r in (domains.registrable(n) for n in cert['names']) if r}
        if len(regs) > SHARED_CERT_LIMIT:
            continue
        for reg in sorted(regs - owned):
            inventory.upsert_candidate(project, 'root_domain', reg, 'crtsh',
                                       f'cert:{cert["id"]} shared with {root.value}')
            candidates += 1
    return {'hostnames': hostnames, 'candidates': candidates}


def run_internetdb(project, root, get=http.get_json, now=None):
    now = now or timezone.now()
    owned = _owned_registrables(project)
    enriched = candidates = 0
    for ip in _root_ips(project, root):
        if _fresh(ip, 'internetdb', now):
            continue
        status, body = get(internetdb.build_url(ip.value), provider='internetdb')
        if status == 404:
            data = None
        elif status == 200:
            data = internetdb.parse(body)
        else:
            continue  # provider failure: not cached, retried next run
        _store(ip, 'internetdb', data or {'no_data': True}, now)
        enriched += 1
        if data and ip.scope_tier in ('owned_root', 'owned_host'):
            for host in data['hostnames']:
                reg = domains.registrable(host)
                if reg and reg not in owned:
                    inventory.upsert_candidate(project, 'root_domain', reg, 'internetdb', f'ip:{ip.value}')
                    candidates += 1
    return {'internetdb_enriched': enriched, 'candidates': candidates}


def run_ripestat(project, root, get=http.get_json, now=None):
    now = now or timezone.now()
    holders, enriched = {}, 0
    for ip in _root_ips(project, root):
        if _fresh(ip, 'ripestat', now):
            continue
        status, body = get(ripestat.network_info_url(ip.value), provider='ripestat')
        if status != 200:
            continue
        info = ripestat.parse_network_info(body)
        if info['asn'] and info['asn'] not in holders:
            s, b = get(ripestat.as_overview_url(info['asn']), provider='ripestat')
            holders[info['asn']] = ripestat.parse_as_overview(b)['holder'] if s == 200 else None
        _store(ip, 'ripestat', {**info, 'holder': holders.get(info['asn'])}, now)
        enriched += 1
    return {'ripestat_enriched': enriched}
```

- [ ] **Step 4: Run** `tests.core.test_intel_run` → PASS. **Step 5: Commit** — `git commit -m "Run passive providers against an owned root"`.

---

### Task 5: `passive_intel` stage + workflow

**Files:**
- Modify: `web/limes/tasks/stages.py` (new task), `web/limes/tasks/control.py` (`build_workflow`, import), `web/limes/celery_routing.py` (`TASK_PLAN`), `web/limes/tasks/inventory.py` (`STAGE_BY_TASK`)
- Modify: `web/tests/core/test_scan_mode.py` (`WorkflowSplitTest` expected sets)
- Test: `web/tests/core/test_passive_intel_stage.py` (create)

**Interfaces:**
- Consumes: `resolution.root_for_domain`, `resolution.resolve_root(project, root, results_dir)`, `intel.run_crtsh/run_internetdb/run_ripestat`.
- Produces: Celery task `passive_intel(ctx)` returning a counts dict.

- [ ] **Step 1: Failing tests** (`test_passive_intel_stage.py`, stage run through `LimesTask.__call__` like `test_stage_scope.py`):
```python
import tempfile
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.celery_custom_task import LimesTask
from limes.tasks import control, stages
from scanEngine.models import EngineType
from startScan.models import Asset, ScanHistory
from targetApp.models import Domain


def _names(sig):
    tasks = getattr(sig, 'tasks', None)
    if tasks is None:
        return [sig.task.rsplit('.', 1)[-1]]
    out = []
    for t in tasks:
        out += _names(t)
    return out


class PassiveIntelStageTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='example.com', project=self.p, insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(scan_type=eng, domain=self.domain, start_scan_date=timezone.now(),
                                               results_dir=tempfile.mkdtemp())
        self.ctx = {'scan_history_id': self.scan.id, 'results_dir': self.scan.results_dir, 'track': False}
        p = mock.patch.object(LimesTask, 'notify')
        p.start()
        self.addCleanup(p.stop)

    def patched(self, **overrides):
        mocks = {
            'run_crtsh': mock.patch('limes.tasks.intel.run_crtsh', return_value={'hostnames': 1, 'candidates': 1}),
            'resolve_root': mock.patch('limes.tasks.resolution.resolve_root', return_value=3),
            'run_internetdb': mock.patch('limes.tasks.intel.run_internetdb', return_value={'internetdb_enriched': 2, 'candidates': 0}),
            'run_ripestat': mock.patch('limes.tasks.intel.run_ripestat', return_value={'ripestat_enriched': 2}),
        }
        mocks.update(overrides)
        return {k: p.start() for k, p in mocks.items()}

    def tearDown(self):
        mock.patch.stopall()

    def test_runs_providers_and_resolves_between(self):
        m = self.patched()
        stages.passive_intel(ctx=dict(self.ctx))
        for name in ('run_crtsh', 'resolve_root', 'run_internetdb', 'run_ripestat'):
            m[name].assert_called_once()

    def test_one_failing_provider_does_not_stop_others(self):
        m = self.patched(run_crtsh=mock.patch('limes.tasks.intel.run_crtsh', side_effect=RuntimeError('crt.sh down')))
        stages.passive_intel(ctx=dict(self.ctx))
        m['run_internetdb'].assert_called_once()
        m['run_ripestat'].assert_called_once()

    def test_non_owned_root_is_never_expanded(self):
        self.root.scope_tier = 'candidate'
        self.root.save()
        m = self.patched()
        stages.passive_intel(ctx=dict(self.ctx))
        for name in ('run_crtsh', 'run_internetdb', 'run_ripestat'):
            m[name].assert_not_called()

    def test_passive_intel_runs_right_after_discovery(self):
        for mode in ('asm', 'full'):
            names = _names(control.build_workflow({}, mode))
            self.assertEqual(names[:2], ['subdomain_discovery', 'passive_intel'], mode)
```
Update `tests/core/test_scan_mode.py` `WorkflowSplitTest` expected sets to include `'passive_intel'` in both.

- [ ] **Step 2: Run, confirm fail.**

- [ ] **Step 3: Stage** (`stages.py`, after `subdomain_discovery`; add `from limes.tasks import intel` to the imports):
```python
@app.task(name='passive_intel', base=LimesTask, bind=True)
def passive_intel(self, ctx={}, description=None):
	"""Passive providers (crt.sh, Shodan InternetDB, RIPEstat) for the scan's owned root.

	Contacts only those third-party APIs, never a target, so it needs no scope guard.
	"""
	project, root = resolution.root_for_domain(self.domain) if self.domain else (None, None)
	if not project or not root or root.scope_tier != 'owned_root':
		logger.warning('Passive intel: no owned root for this scan, skipping')
		return {}
	steps = (
		('crtsh', lambda: intel.run_crtsh(project, root)),
		# hostnames crt.sh added are resolved so the scope guard and per-IP enrichment see them
		('resolve', lambda: {'resolved': resolution.resolve_root(project, root, self.results_dir)}),
		('internetdb', lambda: intel.run_internetdb(project, root)),
		('ripestat', lambda: intel.run_ripestat(project, root)),
	)
	counts, failed = {}, []
	for name, step in steps:
		try:
			for k, v in step().items():
				counts[k] = counts.get(k, 0) + v
		except Exception:
			logger.exception(f'Passive intel: {name} failed')
			failed.append(name)
	if failed:
		counts['failed'] = ', '.join(failed)
	self.notify(fields={k.replace('_', ' ').capitalize(): v for k, v in counts.items()})
	return counts
```

- [ ] **Step 4: Workflow** (`control.py`): import `passive_intel` from stages; in `build_workflow` insert `passive_intel.si(ctx=ctx, description='Passive intel'),` right after `subdomain_discovery.si(...)` in both the `asm` chain and the full chain. `celery_routing.TASK_PLAN['passive_intel'] = (SCAN, 1 * HOUR)` (add it to the dict next to `subdomain_discovery`). `inventory.STAGE_BY_TASK['passive_intel'] = 'discovery'`.

- [ ] **Step 5: Run** `tests.core.test_passive_intel_stage tests.core.test_scan_mode tests.core.test_celery_config` and the full suite → PASS. **Step 6: Commit** — `git commit -m "Run passive providers as a stage after discovery"`.

---

### Task 6: Enrichment in the API and asset modal; README

**Files:**
- Modify: `web/api/serializers.py` (`AssetSerializer.Meta.fields` += `'enrichment'`)
- Modify: `web/static/custom/asset.js` (Intel section in `get_asset_modal`)
- Modify: `README.md` (providers section)
- Test: `web/tests/core/test_asset_api.py` (one retrieve assertion)

**Interfaces:**
- Consumes: `Asset.enrichment` (`{'internetdb': {ports, cpes, vulns, tags, hostnames, fetched_at} | {'no_data': True, 'fetched_at'}, 'ripestat': {asn, prefix, holder, fetched_at}}`).

- [ ] **Step 1: Failing test** (in `AssetListApiTest`):
```python
    def test_retrieve_includes_enrichment(self):
        self.root.enrichment = {'ripestat': {'asn': '13335', 'prefix': None, 'holder': 'X', 'fetched_at': 't'}}
        self.root.save()
        r = self.c.get(f'/api/listDatatableAsset/{self.root.id}/', {'project': 'p1'})
        self.assertEqual(r.json()['enrichment']['ripestat']['asn'], '13335')
```
- [ ] **Step 2: Run, confirm fail** (`KeyError: 'enrichment'`). **Step 3:** add `'enrichment'` to the serializer field list; re-run `tests.core.test_asset_api` (the N+1 test's count must not change — same row).

- [ ] **Step 4: Modal** (`asset.js`): add a helper and render it after the Sources table:
```javascript
function asset_intel_html(e) {
	e = e || {};
	var rows = [], idb = e.internetdb, ripe = e.ripestat;
	if (idb) {
		if (idb.no_data) {
			rows.push('<tr><td>InternetDB</td><td class="text-muted">No data</td><td>' + asset_esc(idb.fetched_at) + '</td></tr>');
		} else {
			rows.push('<tr><td>Open ports</td><td>' + asset_esc((idb.ports || []).join(', ')) + '</td><td>' + asset_esc(idb.fetched_at) + '</td></tr>');
			rows.push('<tr><td>CPEs</td><td>' + asset_esc((idb.cpes || []).join(', ')) + '</td><td></td></tr>');
			rows.push('<tr><td>Vulnerabilities</td><td>' + asset_esc((idb.vulns || []).join(', ')) + '</td><td></td></tr>');
			rows.push('<tr><td>Tags</td><td>' + asset_esc((idb.tags || []).join(', ')) + '</td><td></td></tr>');
		}
	}
	if (ripe) {
		rows.push('<tr><td>ASN / prefix</td><td>' + asset_esc((ripe.asn ? 'AS' + ripe.asn : '') + (ripe.prefix ? ' ' + ripe.prefix : '')) +
			'</td><td>' + asset_esc(ripe.fetched_at) + '</td></tr>');
		rows.push('<tr><td>Holder</td><td>' + asset_esc(ripe.holder) + '</td><td></td></tr>');
	}
	if (!rows.length) return '';
	return '<h5>Intel</h5><table class="table table-sm"><thead><tr><th></th><th>Value</th><th>Fetched</th></tr></thead><tbody>' +
		rows.join('') + '</tbody></table>';
}
```
In `get_asset_modal`, append `+ asset_intel_html(a.enrichment)` after `sources + '</tbody></table>'`. `node --check web/static/custom/asset.js`.

- [ ] **Step 5: README** — insert before `## Security`:
```markdown
## Passive providers

Scans query three free, keyless sources; none of them contacts your targets:

| Provider | Used for |
|---|---|
| crt.sh | Hostnames under owned roots; other domains sharing your certificates become review candidates |
| Shodan InternetDB | Open ports, CPEs, vulnerability IDs and tags per IP; hostnames on owned IPs become candidates |
| RIPEstat | ASN, prefix and holder per IP |

Shodan InternetDB is free for non-commercial use; check Shodan's terms before commercial deployment.
```

- [ ] **Step 6: Run** the full suite; **Step 7: Commit** — `git commit -m "Show passive intel on assets and document providers"`.
