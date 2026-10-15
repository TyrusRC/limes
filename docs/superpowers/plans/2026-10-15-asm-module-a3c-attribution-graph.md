# ASM module A3c — Attribution graph + ownership confidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every candidate an explainable ownership confidence from typed evidence, rank and filter the review queue by it, and auto-confirm only candidates with a working NS delegation to owned hosts plus a certificate/InternetDB corroboration.

**Architecture:** A new `AssetFact` table holds typed evidence (`cert`, `ip`, `ns`, `mx`) recorded by the A3b providers and a new NS/MX lookup. `web/limes/tasks/attribution.py` collects NS/MX, scores candidates set-based (published weights, noisy-OR, hop-2 at half weight) into `Asset.confidence` / `confidence_detail`, and applies decisions with a conditional update. It runs as two steps at the end of the `passive_intel` stage and via `manage.py rescore_assets`. The Assets API/UI show, sort and filter by confidence.

**Tech Stack:** Django 3.2, Celery 5.4, PostgreSQL, ProjectDiscovery dnsx.

**Spec:** `docs/superpowers/specs/2026-10-15-asm-module-a3c-attribution-graph-design.md`

## Global Constraints

- Weights (module constants, version `attribution-v1`): `ns_control` 0.95, `mx` 0.60, `ip` 0.60, `cert` 0.50, `brand` 0.30; `HOP2_FACTOR` 0.5; `AUTO_CONFIRM` 0.90; `REVIEW` 0.40; brand keywords shorter than 4 characters ignored.
- `ns` is control only when **every** NS host of the candidate equals or is under an owned root **and** the candidate resolved (A) in the same lookup. MX is never control.
- Auto-confirm requires: score ≥ 0.90 **and** a hop-1 `ns` control contribution **and** a hop-1 corroboration. **Corroboration = a `cert` fact, or an `ip` fact whose source is `internetdb`.** (Plan refinement of the spec's "cert or ip": an `ip` fact from the candidate's own A record is attacker-controlled, so it adds score but never corroborates.)
- Only `candidate` assets are scored or changed; owned, co-brand, dependency, rejected are never touched. Auto-confirm uses a conditional update (`filter(pk=..., scope_tier='candidate').update(...)`) so a concurrent human decision always wins.
- Hidden = candidate with confidence < 0.40; never deleted; only the **list** endpoint hides them (retrieve still works); unscored candidates (`confidence` null) are shown.
- NS/MX lookup: at most 2 000 candidate root domains per run (NOTE), 10-minute dnsx timeout, contained errors, re-raises `SoftTimeLimitExceeded`; argv list only, never a shell.
- Migrations generated with `makemigrations`; final `makemigrations --check` clean.
- Style: tabs in `stages.py`, `api/views.py` (AssetDatatableViewSet), `dashboard/models.py`, `asset.js`; 4 spaces in `attribution.py`, `intel.py`, `inventory.py`, `startScan/*`, `limes/pipeline/*`, `api/serializers.py` AssetSerializer, tests, the management command.
- Tests: `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <dotted.path>`; no test touches the network.
- Commit identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`; no AI attribution; no push without an explicit user yes.

## Review Focus

1. **A third party names our hosts in their DNS** (MX → our mail host; NS → our vanity NS without a working zone; A → our IP) — must never reach auto-confirm → Task 5 `test_spoofed_dns_evidence_never_auto_confirms`.
2. **Rounding/combination pushes a no-control candidate over 0.9** (MX 0.6 + cert 0.5 + brand 0.3 ≈ 0.86; MX + ip(internetdb) + cert ≈ 0.92) — stays a candidate → Task 5 `test_high_score_without_control_stays_candidate`.
3. **A human rejects while scoring runs** — the conditional update must not overwrite the rejection → Task 5 `test_concurrent_rejection_wins`.
4. **Stale NS delegation** — a candidate whose NS moved away (or now fails to resolve) must lose its NS facts → Task 3 `test_ns_facts_replaced_by_latest_lookup`.
5. **Hidden candidate opened from a link** — retrieve of a hidden (< 0.4) candidate still returns it; only the list hides → Task 6 `test_hidden_candidate_still_retrievable`.

---

### Task 1: Evidence model, confidence fields, brand keywords

**Files:**
- Modify: `web/startScan/asset_models.py` (`AssetFact`, `__all__`, `Asset.confidence`, `Asset.confidence_detail`); generate `web/startScan/migrations/0015_assetfact_asset_confidence.py`
- Modify: `web/dashboard/models.py` (`Project.brand_keywords`); generate `web/dashboard/migrations/0004_project_brand_keywords.py`
- Modify: `web/limes/tasks/inventory.py` (`record_fact`)
- Test: `web/tests/core/test_asset_facts.py` (create)

**Interfaces:**
- Produces: `AssetFact(asset, kind, value, source, first_seen, last_seen)` importable from `startScan.models`; `Asset.confidence: float|None`; `Asset.confidence_detail: dict|None`; `Project.brand_keywords: list`; `inventory.record_fact(asset, kind, value, source) -> AssetFact | None`.

- [ ] **Step 1: Failing tests** (`test_asset_facts.py`):
```python
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import inventory
from startScan.models import Asset, AssetFact


class AssetFactTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.a = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='candidate')

    def test_record_is_unique_and_refreshes_last_seen(self):
        f1 = inventory.record_fact(self.a, 'cert', '101', 'crtsh')
        first = f1.last_seen
        f2 = inventory.record_fact(self.a, 'cert', '101', 'crtsh')
        self.assertEqual(AssetFact.objects.filter(asset=self.a).count(), 1)
        self.assertGreaterEqual(f2.last_seen, first)

    def test_value_normalized_and_empty_ignored(self):
        f = inventory.record_fact(self.a, 'ns', ' NS1.X.COM ', 'dns')
        self.assertEqual(f.value, 'ns1.x.com')
        self.assertIsNone(inventory.record_fact(self.a, 'ns', '  ', 'dns'))

    def test_defaults(self):
        self.a.refresh_from_db()
        self.assertIsNone(self.a.confidence)
        self.assertIsNone(self.a.confidence_detail)
        self.assertEqual(Project.objects.get(pk=self.p.pk).brand_keywords, [])
```
- [ ] **Step 2: Run, confirm fail** (ImportError for `AssetFact`).
- [ ] **Step 3: Models.** In `startScan/asset_models.py` add `'AssetFact'` to `__all__`; on `Asset` (next to `enrichment`): `confidence = models.FloatField(null=True, blank=True)` and `confidence_detail = models.JSONField(null=True, blank=True)`; after `Asset`:
```python
class AssetFact(models.Model):
    """Typed ownership evidence attached to an asset (A3c attribution graph)."""
    KINDS = [(k, k) for k in ('cert', 'ip', 'ns', 'mx')]

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='facts')
    kind = models.CharField(max_length=10, choices=KINDS)
    value = models.CharField(max_length=500)
    source = models.CharField(max_length=50)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('asset', 'kind', 'value')
        indexes = [models.Index(fields=['kind', 'value'], name='assetfact_kind_value_idx')]
```
In `dashboard/models.py` `Project` (tabs): `brand_keywords = models.JSONField(default=list, blank=True)`. Generate: `makemigrations startScan -n assetfact_asset_confidence` and `makemigrations dashboard -n project_brand_keywords`.
- [ ] **Step 4: `inventory.record_fact`:**
```python
def record_fact(asset, kind, value, source):
    """Upsert one typed evidence fact on an asset; refreshes last_seen when it already exists."""
    from startScan.models import AssetFact
    value = (value or '').strip().lower()
    if not value:
        return None
    fact, created = AssetFact.objects.get_or_create(asset=asset, kind=kind, value=value,
                                                    defaults={'source': source})
    if not created:
        fact.last_seen = timezone.now()
        fact.save(update_fields=['last_seen'])
    return fact
```
- [ ] **Step 5: Run** the test + full suite; `makemigrations --check` clean. **Step 6: Commit** — `git commit -m "Add asset evidence facts, confidence fields and brand keywords"`.

---

### Task 2: Record facts from crt.sh and InternetDB

**Files:**
- Modify: `web/limes/tasks/intel.py` (`run_crtsh`, `run_internetdb`)
- Test: `web/tests/core/test_intel_run.py` (add two tests)

**Interfaces:**
- Consumes: `inventory.record_fact(asset, kind, value, source)`; `inventory.upsert_candidate(...)` returns the asset (existing or new).

- [ ] **Step 1: Failing tests** (add to `IntelRunTest`):
```python
    def test_crtsh_records_cert_facts_on_root_and_co_tenant(self):
        from startScan.models import AssetFact
        intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, load('crtsh_sample.json'))))
        self.assertTrue(AssetFact.objects.filter(asset=self.root, kind='cert', value='102').exists())
        org = Asset.objects.get(value='example.org')
        self.assertTrue(AssetFact.objects.filter(asset=org, kind='cert', value='102', source='crtsh').exists())

    def test_internetdb_records_ip_fact_on_candidate(self):
        from startScan.models import AssetFact
        body = load('internetdb_sample.json')
        intel.run_internetdb(self.p, self.root, get=Fake(internetdb=lambda url: (200, dict(body, ip=url.rsplit('/', 1)[1]))))
        cand = Asset.objects.get(value='partner-co.com')
        self.assertTrue(AssetFact.objects.filter(asset=cand, kind='ip', value='203.0.114.7', source='internetdb').exists())
```
- [ ] **Step 2: Run, confirm fail.**
- [ ] **Step 3: Implement.** In `run_crtsh`, right after the `if not in_root: continue` line add `inventory.record_fact(root, 'cert', str(cert['id']), 'crtsh')`; replace the `inventory.upsert_candidate(...)` call with:
```python
            cand = inventory.upsert_candidate(project, 'root_domain', reg, 'crtsh',
                                              f'cert:{cert["id"]} ({in_root}) shared with {root.value}')
            if cand:
                inventory.record_fact(cand, 'cert', str(cert['id']), 'crtsh')
```
In `run_internetdb`, replace the `upsert_candidate` call with:
```python
                    cand = inventory.upsert_candidate(project, 'root_domain', reg, 'internetdb', f'ip:{ip.value}')
                    if cand:
                        inventory.record_fact(cand, 'ip', ip.value, 'internetdb')
```
- [ ] **Step 4: Run** `tests.core.test_intel_run` → PASS. **Step 5: Commit** — `git commit -m "Record certificate and IP evidence facts from passive providers"`.

---

### Task 3: NS/MX collection for candidates

**Files:**
- Modify: `web/limes/pipeline/dnsx.py` (`build_ns_mx_argv`, `parse_ns_mx`)
- Create: `web/limes/tasks/attribution.py` (`collect_dns` + constants)
- Create fixture: `web/tests/core/fixtures/dnsx_ns_mx_sample.jsonl`
- Test: `web/tests/core/test_attribution_dns.py` (create)

**Interfaces:**
- Consumes: `inventory.record_fact`, `commands.run(argv, timeout=...)` (returns object with `return_code`).
- Produces: `dnsx.build_ns_mx_argv(hosts_file, output_file) -> list[str]`; `dnsx.parse_ns_mx(lines) -> {host: {'a': [str], 'ns': [str], 'mx': [str]}}`; `attribution.collect_dns(project, results_dir, run=commands.run) -> {'dns_checked': int}`; constants `MAX_DNS_CANDIDATES = 2000`, `NS_MX_TIMEOUT = 600`.

- [ ] **Step 1: Fixture** `dnsx_ns_mx_sample.jsonl`:
```
{"host":"Partner-Co.com","a":["198.51.99.10"],"ns":["NS1.Example.com.","ns2.example.com"],"mx":["10 mail.example.com."]}
{"host":"lame.net","ns":["ns1.example.com"]}
{"host":"thirdparty.org","a":["198.51.99.11"],"ns":["ns1.provider.net"],"mx":["mx.provider.net"]}
not json
{"host":"weird.com","a":"x","ns":5,"mx":[7]}
```
- [ ] **Step 2: Failing tests** (`test_attribution_dns.py`):
```python
import os
import shutil
import tempfile
from types import SimpleNamespace

from celery.exceptions import SoftTimeLimitExceeded
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.pipeline import dnsx
from limes.tasks import attribution
from startScan.models import Asset, AssetFact

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'dnsx_ns_mx_sample.jsonl')


class NsMxParseTest(SimpleTestCase):
    def test_argv(self):
        argv = dnsx.build_ns_mx_argv('/r/h.txt', '/r/o.jsonl')
        for flag in ('-a', '-ns', '-mx', '-resp', '-json', '-silent'):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index('-l') + 1], '/r/h.txt')
        self.assertEqual(argv[argv.index('-o') + 1], '/r/o.jsonl')

    def test_parse(self):
        with open(FIXTURE) as f:
            out = dnsx.parse_ns_mx(f)
        self.assertEqual(out['partner-co.com'], {'a': ['198.51.99.10'], 'ns': ['ns1.example.com', 'ns2.example.com'],
                                                 'mx': ['mail.example.com']})
        self.assertEqual(out['lame.net'], {'a': [], 'ns': ['ns1.example.com'], 'mx': []})
        self.assertEqual(out['weird.com'], {'a': [], 'ns': [], 'mx': []})


class CollectDnsTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        for v in ('partner-co.com', 'lame.net', 'thirdparty.org'):
            Asset.objects.create(project=self.p, kind='root_domain', value=v, scope_tier='candidate')
        Asset.objects.create(project=self.p, kind='root_domain', value='decided.com', scope_tier='rejected')
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def run_with(self, fixture=FIXTURE, rc=0):
        def run(argv, **kw):
            self.kw = kw
            with open(argv[argv.index('-l') + 1]) as f:
                self.hosts = f.read().split()
            shutil.copy(fixture, argv[argv.index('-o') + 1])
            return SimpleNamespace(return_code=rc)
        return run

    def facts(self, value, kind):
        return sorted(AssetFact.objects.filter(asset__value=value, kind=kind).values_list('value', flat=True))

    def test_records_ns_mx_and_a_only_for_resolving_candidates(self):
        out = attribution.collect_dns(self.p, self.dir, run=self.run_with())
        self.assertEqual(sorted(self.hosts), ['lame.net', 'partner-co.com', 'thirdparty.org'])  # candidates only
        self.assertEqual(self.kw.get('timeout'), 600)
        self.assertEqual(self.facts('partner-co.com', 'ns'), ['ns1.example.com', 'ns2.example.com'])
        self.assertEqual(self.facts('partner-co.com', 'mx'), ['mail.example.com'])
        self.assertEqual(self.facts('partner-co.com', 'ip'), ['198.51.99.10'])
        self.assertEqual(self.facts('lame.net', 'ns'), [])  # did not resolve: delegation unproven
        self.assertEqual(out['dns_checked'], 3)

    def test_ns_facts_replaced_by_latest_lookup(self):
        attribution.collect_dns(self.p, self.dir, run=self.run_with())
        moved = os.path.join(self.dir, 'moved.jsonl')
        with open(moved, 'w') as f:
            f.write('{"host":"partner-co.com","a":["198.51.99.10"],"ns":["ns9.elsewhere.net"]}\n')
        attribution.collect_dns(self.p, self.dir, run=self.run_with(fixture=moved))
        self.assertEqual(self.facts('partner-co.com', 'ns'), ['ns9.elsewhere.net'])
        self.assertEqual(self.facts('partner-co.com', 'mx'), [])

    def test_failures_contained_but_time_limit_propagates(self):
        def boom(argv, **kw):
            raise OSError('dnsx missing')
        with self.assertLogs('limes.tasks.attribution', level='ERROR'):
            self.assertEqual(attribution.collect_dns(self.p, self.dir, run=boom), {'dns_checked': 0})

        def slow(argv, **kw):
            raise SoftTimeLimitExceeded()
        with self.assertRaises(SoftTimeLimitExceeded):
            attribution.collect_dns(self.p, self.dir, run=slow)
```
- [ ] **Step 3: Run, confirm fail.**
- [ ] **Step 4: `dnsx.py`** (append):
```python
def build_ns_mx_argv(hosts_file, output_file):
    """A is requested too: an NS delegation only proves control when the zone actually resolves."""
    return ['dnsx', '-l', hosts_file, '-a', '-ns', '-mx', '-resp', '-json', '-silent', '-o', output_file]


def _hostnames(values):
    out = []
    for v in _as_list(values):
        if not isinstance(v, str):
            continue
        h = normalize_host(v.split()[-1]) if v.split() else ''  # MX may carry a priority prefix
        if h and h not in out:
            out.append(h)
    return out


def parse_ns_mx(lines):
    out = {}
    for line in lines:
        try:
            rec = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        host = normalize_host(rec.get('host') if isinstance(rec.get('host'), str) else '')
        if not host:
            continue
        entry = out.setdefault(host, {'a': [], 'ns': [], 'mx': []})
        for v in _as_list(rec.get('a')):
            ip = _canonical_ip(v, 4)
            if ip and ip not in entry['a']:
                entry['a'].append(ip)
        for key in ('ns', 'mx'):
            for h in _hostnames(rec.get(key)):
                if h not in entry[key]:
                    entry[key].append(h)
    return out
```
- [ ] **Step 5: `web/limes/tasks/attribution.py`** (new; scoring and decisions are added in Tasks 4-5):
```python
"""Ownership attribution (A3c): evidence collection, scoring and decisions for candidates.

DNS lookups go to resolvers only, never to a target.
"""
import logging
import os

from celery.exceptions import SoftTimeLimitExceeded

from limes import commands
from limes.pipeline import dnsx
from limes.tasks import inventory
from startScan.models import Asset, AssetFact

logger = logging.getLogger(__name__)

MAX_DNS_CANDIDATES = 2000  # NOTE: ceiling per run; oldest candidates first; upgrade path: rotate by last check
NS_MX_TIMEOUT = 10 * 60


def collect_dns(project, results_dir, run=commands.run):
    """NS/MX/A for candidate root domains. NS facts are kept only when the zone resolved (a working
    delegation); each answered host's NS/MX facts are replaced by the latest answer."""
    cands = dict(Asset.objects.filter(project=project, kind='root_domain', scope_tier='candidate')
                 .order_by('id').values_list('value', 'id')[:MAX_DNS_CANDIDATES])
    if not cands:
        return {'dns_checked': 0}
    hosts_file = os.path.join(results_dir, 'attribution_hosts.txt')
    out_file = os.path.join(results_dir, 'attribution_dnsx.jsonl')
    try:
        if os.path.exists(out_file):
            os.remove(out_file)
        with open(hosts_file, 'w') as f:
            f.write('\n'.join(cands) + '\n')
        res = run(dnsx.build_ns_mx_argv(hosts_file, out_file), timeout=NS_MX_TIMEOUT)
        if res is None or res.return_code != 0:
            logger.warning(f'dnsx (ns/mx) exited with {getattr(res, "return_code", None)}')
        if not os.path.isfile(out_file):
            return {'dns_checked': 0}
        with open(out_file) as f:
            records = dnsx.parse_ns_mx(f)
        checked = 0
        for name, rec in records.items():
            asset_id = cands.get(name)
            if asset_id is None:
                continue
            asset = Asset.objects.get(pk=asset_id)
            ns = rec['ns'] if rec['a'] else []  # lame delegation proves nothing
            AssetFact.objects.filter(asset=asset, kind='ns').exclude(value__in=ns).delete()
            AssetFact.objects.filter(asset=asset, kind='mx').exclude(value__in=rec['mx']).delete()
            for h in ns:
                inventory.record_fact(asset, 'ns', h, 'dns')
            for h in rec['mx']:
                inventory.record_fact(asset, 'mx', h, 'dns')
            for ip in rec['a']:
                inventory.record_fact(asset, 'ip', ip, 'dns')
            checked += 1
        return {'dns_checked': checked}
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        logger.exception('Attribution DNS collection failed')
        return {'dns_checked': 0}
```
- [ ] **Step 6: Run** `tests.core.test_attribution_dns tests.core.test_dnsx` → PASS. **Step 7: Commit** — `git commit -m "Collect NS/MX evidence for candidates"`.

---

### Task 4: Scoring (`attribution-v1`)

**Files:**
- Modify: `web/limes/tasks/attribution.py` (constants, `brand_tokens`, `score_project`)
- Test: `web/tests/core/test_attribution_score.py` (create)

**Interfaces:**
- Consumes: `AssetFact`, `inventory.owned_root_values(project)`, `domains.registrable(name)`, `Project.brand_keywords`.
- Produces: `VERSION = 'attribution-v1'`, `WEIGHTS`, `HOP2_FACTOR`, `AUTO_CONFIRM`, `REVIEW`, `MIN_BRAND_LEN`; `brand_tokens(value) -> set[str]`; `score_project(project) -> {'scored': int}` writing `Asset.confidence` and `confidence_detail = {'version', 'score', 'contributions': [{'kind', 'value', 'via', 'weight', 'hop', 'control', 'corroborates'}]}`.

- [ ] **Step 1: Failing tests** (`test_attribution_score.py`):
```python
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import attribution, inventory
from startScan.models import Asset


class BrandTokensTest(SimpleTestCase):
    def test_whole_label_tokens(self):
        self.assertIn('acme', attribution.brand_tokens('acme-shop.com'))
        self.assertNotIn('acme', attribution.brand_tokens('acmesoft.com'))
        self.assertEqual(attribution.brand_tokens('shop.acme.co.uk'), {'shop', 'acme'})


class ScoreTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now(), brand_keywords=['acme', 'ab'])
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        self.own_ip = Asset.objects.create(project=self.p, kind='ip', value='203.0.114.7', scope_tier='owned_host')
        inventory.record_fact(self.root, 'cert', '102', 'crtsh')

    def cand(self, value, *facts):
        a = Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier='candidate')
        for kind, val, src in facts:
            inventory.record_fact(a, kind, val, src)
        return a

    def score(self, a):
        attribution.score_project(self.p)
        a.refresh_from_db()
        return a.confidence, {c['kind']: c for c in a.confidence_detail['contributions']}

    def test_each_weight_alone(self):
        cases = [
            (('ns', 'ns1.example.com', 'dns'), 0.95), (('mx', 'mail.example.com', 'dns'), 0.60),
            (('ip', '203.0.114.7', 'internetdb'), 0.60), (('cert', '102', 'crtsh'), 0.50),
        ]
        for i, (fact, expected) in enumerate(cases):
            a = self.cand(f'c{i}.net', fact)
            self.assertAlmostEqual(self.score(a)[0], expected, places=4, msg=fact)

    def test_noisy_or_and_flags(self):
        a = self.cand('both.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        score, by = self.score(a)
        self.assertAlmostEqual(score, 1 - (1 - 0.95) * (1 - 0.5), places=4)
        self.assertTrue(by['ns']['control'])
        self.assertTrue(by['cert']['corroborates'])
        self.assertEqual(by['ns']['via'], 'example.com')

    def test_ns_control_needs_every_ns_under_owned_root(self):
        a = self.cand('mixed.net', ('ns', 'ns1.example.com', 'dns'), ('ns', 'ns1.provider.net', 'dns'))
        self.assertIsNone(self.score(a)[1].get('ns'))

    def test_dns_sourced_ip_scores_but_never_corroborates(self):
        a = self.cand('pointed.net', ('ip', '203.0.114.7', 'dns'))
        score, by = self.score(a)
        self.assertAlmostEqual(score, 0.60, places=4)
        self.assertFalse(by['ip']['corroborates'])

    def test_brand_whole_label_and_short_keywords_ignored(self):
        self.assertAlmostEqual(self.score(self.cand('acme-store.net'))[0], 0.30, places=4)
        self.assertAlmostEqual(self.score(self.cand('acmesoft.net'))[0] or 0.0, 0.0, places=4)
        self.assertAlmostEqual(self.score(self.cand('ab-shop.net'))[0] or 0.0, 0.0, places=4)  # 'ab' < 4 chars

    def test_hop2_half_weight_only_through_reviewable_candidate(self):
        strong = self.cand('strong.net', ('cert', '102', 'crtsh'), ('mx', 'mail.example.com', 'dns'))  # 0.8 hop-1
        linked = self.cand('linked.net', ('cert', '555', 'crtsh'))
        inventory.record_fact(strong, 'cert', '555', 'crtsh')
        weak = self.cand('weak.net', ('cert', '777', 'crtsh'))
        unlinked = self.cand('unlinked.net', ('cert', '777', 'crtsh'))
        attribution.score_project(self.p)
        linked.refresh_from_db(); unlinked.refresh_from_db()
        self.assertAlmostEqual(linked.confidence, 0.25, places=4)
        self.assertEqual(linked.confidence_detail['contributions'][0]['hop'], 2)
        self.assertEqual(linked.confidence_detail['contributions'][0]['via'], 'strong.net')
        self.assertAlmostEqual(unlinked.confidence or 0.0, 0.0, places=4)  # weak.net scores 0 at hop 1

    def test_decided_assets_never_scored(self):
        rej = Asset.objects.create(project=self.p, kind='root_domain', value='nope.net', scope_tier='rejected')
        inventory.record_fact(rej, 'cert', '102', 'crtsh')
        attribution.score_project(self.p)
        rej.refresh_from_db(); self.root.refresh_from_db()
        self.assertIsNone(rej.confidence)
        self.assertIsNone(self.root.confidence)
```
- [ ] **Step 2: Run, confirm fail.**
- [ ] **Step 3: Implement** (append to `attribution.py`; add imports `import re`, `from collections import defaultdict`, `from limes.intel import domains`):
```python
VERSION = 'attribution-v1'
WEIGHTS = {'ns_control': 0.95, 'mx': 0.60, 'ip': 0.60, 'cert': 0.50, 'brand': 0.30}
HOP2_FACTOR = 0.5
AUTO_CONFIRM = 0.90
REVIEW = 0.40
MIN_BRAND_LEN = 4  # NOTE: shorter keywords would match everything
OWNED = ('owned_root', 'owned_host')


def _under_root(host, roots):
    return next((r for r in roots if host == r or host.endswith('.' + r)), None)


def brand_tokens(value):
    """Whole label tokens of a name, excluding its public suffix (labels split on '.' and '-')."""
    reg = domains.registrable(value)
    head = value
    if reg and '.' in reg:
        suffix = reg.split('.', 1)[1]
        if value.endswith('.' + suffix):
            head = value[:-(len(suffix) + 1)]
    return {t for t in re.split(r'[.\-]', head) if t}


def _combine(contribs):
    p = 1.0
    for c in contribs:
        p *= 1 - c['weight']
    return 1 - p


def _hop1(asset, facts, roots, owned_ips, owned_certs, keywords):
    out, seen = [], set()

    def add(kind, value, via, weight, control=False, corroborates=False):
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append({'kind': kind, 'value': value, 'via': via, 'weight': weight, 'hop': 1,
                        'control': control, 'corroborates': corroborates})

    ns = sorted(v for k, v, _ in facts if k == 'ns')
    if ns and all(_under_root(h, roots) for h in ns):
        add('ns', ', '.join(ns), _under_root(ns[0], roots), WEIGHTS['ns_control'], control=True)
    for kind, value, source in facts:
        if kind == 'mx' and _under_root(value, roots):
            add('mx', value, _under_root(value, roots), WEIGHTS['mx'])
        elif kind == 'ip' and value in owned_ips:
            add('ip', value, value, WEIGHTS['ip'], corroborates=source == 'internetdb')
        elif kind == 'cert' and value in owned_certs:
            add('cert', value, owned_certs[value], WEIGHTS['cert'], corroborates=True)
    tokens = brand_tokens(asset.value)
    for kw in keywords:
        if kw in tokens:
            add('brand', kw, 'brand keyword', WEIGHTS['brand'])
            break
    return out


def score_project(project):
    """Score every candidate of the project (set-based: a fixed number of queries per project)."""
    cands = list(Asset.objects.filter(project=project, scope_tier='candidate'))
    if not cands:
        return {'scored': 0}
    roots = inventory.owned_root_values(project)
    owned_ips = set(Asset.objects.filter(project=project, kind='ip', scope_tier__in=OWNED)
                    .values_list('value', flat=True))
    owned_certs = dict(AssetFact.objects.filter(asset__project=project, asset__scope_tier__in=OWNED, kind='cert')
                       .values_list('value', 'asset__value'))
    keywords = [k.lower() for k in (project.brand_keywords or []) if isinstance(k, str) and len(k) >= MIN_BRAND_LEN]
    facts = defaultdict(list)
    for aid, kind, value, source in (AssetFact.objects.filter(asset__in=cands)
                                     .values_list('asset_id', 'kind', 'value', 'source')):
        facts[aid].append((kind, value, source))
    hop1 = {c.id: _hop1(c, facts[c.id], roots, owned_ips, owned_certs, keywords) for c in cands}
    value_of = {c.id: c.value for c in cands}
    sharing = defaultdict(set)  # (kind, value) -> candidate ids, for hop 2
    for aid, fl in facts.items():
        for kind, value, _ in fl:
            if kind in ('cert', 'ip'):
                sharing[(kind, value)].add(aid)
    for c in cands:
        contribs = list(hop1[c.id])
        seen = {(x['kind'], x['value']) for x in contribs}
        for kind, value, _ in facts[c.id]:
            if kind not in ('cert', 'ip') or (kind, value) in seen:
                continue
            via = sorted(o for o in sharing[(kind, value)] if o != c.id and _combine(hop1[o]) >= REVIEW)
            if via:
                seen.add((kind, value))
                contribs.append({'kind': kind, 'value': value, 'via': value_of[via[0]],
                                 'weight': WEIGHTS[kind] * HOP2_FACTOR, 'hop': 2,
                                 'control': False, 'corroborates': False})
        score = round(_combine(contribs), 4)
        c.confidence = score
        c.confidence_detail = {'version': VERSION, 'score': score, 'contributions': contribs}
    Asset.objects.bulk_update(cands, ['confidence', 'confidence_detail'], batch_size=500)
    return {'scored': len(cands)}
```
- [ ] **Step 4: Run** `tests.core.test_attribution_score` → PASS. **Step 5: Commit** — `git commit -m "Score candidates with published attribution weights"`.

---

### Task 5: Decisions, stage steps, rescore command

**Files:**
- Modify: `web/limes/tasks/attribution.py` (`apply_decisions`)
- Modify: `web/limes/tasks/stages.py` (two steps at the end of `passive_intel`; import `attribution`)
- Create: `web/startScan/management/commands/rescore_assets.py`
- Test: `web/tests/core/test_attribution_decisions.py` (create); `web/tests/core/test_passive_intel_stage.py` (extend the `patched()` helper and add one order test)

**Interfaces:**
- Consumes: Task 4 outputs; `dashboard.stats.invalidate(project_id)`; `inventory._append_source(asset, source, evidence)`.
- Produces: `attribution.apply_decisions(project) -> {'auto_confirmed': int}`; command `manage.py rescore_assets <project_slug>`.

- [ ] **Step 1: Failing tests** (`test_attribution_decisions.py`):
```python
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import attribution, inventory
from startScan.models import Asset


class DecisionTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        Asset.objects.create(project=self.p, kind='ip', value='203.0.114.7', scope_tier='owned_host')
        inventory.record_fact(self.root, 'cert', '102', 'crtsh')
        p = mock.patch('dashboard.stats.invalidate')
        self.inv = p.start()
        self.addCleanup(p.stop)

    def cand(self, value, *facts):
        a = Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier='candidate')
        for kind, val, src in facts:
            inventory.record_fact(a, kind, val, src)
        return a

    def run_all(self):
        attribution.score_project(self.p)
        return attribution.apply_decisions(self.p)

    def tier(self, a):
        a.refresh_from_db()
        return a.scope_tier

    def test_working_ns_control_plus_cert_auto_confirms(self):
        a = self.cand('ours.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.assertEqual(self.run_all(), {'auto_confirmed': 1})
        self.assertEqual(self.tier(a), 'owned_root')
        self.assertIn('auto-confirmed (attribution-v1)', a.decision_reason)
        self.assertIn('ns1.example.com', a.decision_reason)
        self.assertIsNone(a.added_by)
        self.assertEqual(a.sources[-1]['source'], 'attribution')
        self.inv.assert_called_once_with(self.p.id)

    def test_ns_control_without_corroboration_stays_candidate(self):
        a = self.cand('nsonly.net', ('ns', 'ns1.example.com', 'dns'))
        self.run_all()
        self.assertEqual(self.tier(a), 'candidate')

    def test_spoofed_dns_evidence_never_auto_confirms(self):
        # MX at our mail host + A at our IP + cert co-tenancy: high score, no NS control
        a = self.cand('spoof.net', ('mx', 'mail.example.com', 'dns'), ('ip', '203.0.114.7', 'dns'), ('cert', '102', 'crtsh'))
        # NS at our host but only alongside a DNS-sourced ip (attacker-controlled A record)
        b = self.cand('spoof2.net', ('ns', 'ns1.example.com', 'dns'), ('ip', '203.0.114.7', 'dns'))
        self.run_all()
        self.assertEqual((self.tier(a), self.tier(b)), ('candidate', 'candidate'))

    def test_high_score_without_control_stays_candidate(self):
        a = self.cand('rich.net', ('mx', 'mail.example.com', 'dns'), ('ip', '203.0.114.7', 'internetdb'),
                      ('cert', '102', 'crtsh'))
        self.run_all()
        a.refresh_from_db()
        self.assertGreaterEqual(a.confidence, 0.9)
        self.assertEqual(a.scope_tier, 'candidate')

    def test_concurrent_rejection_wins(self):
        a = self.cand('race.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        attribution.score_project(self.p)
        Asset.objects.filter(pk=a.pk).update(scope_tier='rejected')  # human decision lands first
        self.assertEqual(attribution.apply_decisions(self.p), {'auto_confirmed': 0})
        self.assertEqual(self.tier(a), 'rejected')

    def test_rescore_command(self):
        a = self.cand('cmd.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        out = StringIO()
        call_command('rescore_assets', 'p', stdout=out)
        self.assertEqual(self.tier(a), 'owned_root')
        self.assertIn('scored', out.getvalue())
```
In `test_passive_intel_stage.py`: add to `patched()`'s dict `'collect_dns': mock.patch('limes.tasks.attribution.collect_dns', return_value={'dns_checked': 1})`, `'score_project': mock.patch('limes.tasks.attribution.score_project', return_value={'scored': 1})`, `'apply_decisions': mock.patch('limes.tasks.attribution.apply_decisions', return_value={'auto_confirmed': 0})`, and add:
```python
    def test_attribution_runs_after_providers_even_if_dns_fails(self):
        m = self.patched(collect_dns=mock.patch('limes.tasks.attribution.collect_dns', side_effect=RuntimeError('x')))
        stages.passive_intel(ctx=dict(self.ctx))
        m['score_project'].assert_called_once()
        m['apply_decisions'].assert_called_once()
```
- [ ] **Step 2: Run, confirm fail.**
- [ ] **Step 3: `apply_decisions`** (append to `attribution.py`):
```python
def apply_decisions(project):
    """Auto-confirm only score >= AUTO_CONFIRM with hop-1 NS control AND hop-1 corroboration.
    The conditional update means a concurrent human decision always wins."""
    from dashboard.stats import invalidate
    auto = 0
    for a in Asset.objects.filter(project=project, scope_tier='candidate', kind__in=('root_domain', 'hostname'),
                                  confidence__gte=AUTO_CONFIRM):
        contribs = (a.confidence_detail or {}).get('contributions') or []
        control = next((c for c in contribs if c.get('hop') == 1 and c.get('control')), None)
        if not control or not any(c.get('hop') == 1 and c.get('corroborates') for c in contribs):
            continue
        reason = (f'auto-confirmed ({VERSION}) {a.confidence:.2f}: NS {control["value"]} '
                  f'under owned root {control["via"]}')
        inventory._append_source(a, 'attribution', reason)
        tier = 'owned_root' if a.kind == 'root_domain' else 'owned_host'
        auto += Asset.objects.filter(pk=a.pk, scope_tier='candidate').update(
            scope_tier=tier, decision_reason=reason, sources=a.sources, added_by=None)
    if auto:
        invalidate(project.id)
    return {'auto_confirmed': auto}
```
- [ ] **Step 4: Stage** — in `passive_intel` add `from limes.tasks import attribution` to `stages.py` imports and two steps after `('ripestat', ...)`:
```python
		('attribution_dns', lambda: attribution.collect_dns(project, self.results_dir)),
		('attribution', lambda: {**attribution.score_project(project), **attribution.apply_decisions(project)}),
```
- [ ] **Step 5: Command** `web/startScan/management/commands/rescore_assets.py`:
```python
from django.core.management.base import BaseCommand, CommandError

from dashboard.models import Project
from limes.tasks import attribution


class Command(BaseCommand):
    help = 'Re-score candidate ownership with the current attribution weights and apply decisions.'

    def add_arguments(self, parser):
        parser.add_argument('project_slug')

    def handle(self, *args, **options):
        project = Project.objects.filter(slug=options['project_slug']).first()
        if not project:
            raise CommandError(f'unknown project {options["project_slug"]}')
        counts = {**attribution.score_project(project), **attribution.apply_decisions(project)}
        self.stdout.write(', '.join(f'{k}={v}' for k, v in counts.items()))
```
- [ ] **Step 6: Run** the new tests, `tests.core.test_passive_intel_stage`, full suite → PASS. **Step 7: Commit** — `git commit -m "Auto-confirm only verified NS control with corroboration; rescore command"`.

---

### Task 6: Confidence in the API and Assets UI

**Files:**
- Modify: `web/api/serializers.py` (`AssetSerializer` fields += `'confidence', 'confidence_detail'`)
- Modify: `web/api/views.py` (`AssetDatatableViewSet`: hide low-confidence candidates on list; order by confidence)
- Modify: `web/startScan/templates/startScan/assets.html` (Confidence column, show-low toggle)
- Modify: `web/static/custom/asset.js` (confidence section in the modal)
- Test: `web/tests/core/test_asset_api.py` (add tests to `AssetListApiTest`)

**Interfaces:**
- Consumes: `attribution.REVIEW`.

- [ ] **Step 1: Failing tests** (add to `AssetListApiTest`):
```python
    def _scored(self, value, confidence):
        return Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier='candidate',
                                    confidence=confidence,
                                    confidence_detail={'version': 'attribution-v1', 'score': confidence, 'contributions': []})

    def test_low_confidence_candidates_hidden_by_default(self):
        self._scored('low.net', 0.2)
        self._scored('mid.net', 0.6)
        self.assertNotIn('low.net', self._vals(project='p1'))
        self.assertIn('mid.net', self._vals(project='p1'))
        self.assertIn('b.x.com', self._vals(project='p1'))  # unscored candidates still shown
        self.assertIn('low.net', self._vals(project='p1', show_low='1'))

    def test_hidden_candidate_still_retrievable(self):
        low = self._scored('low.net', 0.2)
        r = self.c.get(f'/api/listDatatableAsset/{low.id}/', {'project': 'p1'})
        self.assertEqual((r.status_code, r.json()['confidence']), (200, 0.2))

    def test_order_by_confidence_nulls_last(self):
        self._scored('mid.net', 0.6)
        self._scored('hi.net', 0.85)
        r = self.c.get('/api/listDatatableAsset/', {'project': 'p1', 'no_page': '1',
                                                    'order[0][column]': '10', 'order[0][dir]': 'desc'})
        vals = [a['value'] for a in r.json()]
        self.assertEqual(vals[:2], ['hi.net', 'mid.net'])
```
- [ ] **Step 2: Run, confirm fail.**
- [ ] **Step 3: Serializer** — add `'confidence', 'confidence_detail'` to `AssetSerializer.Meta.fields`.
- [ ] **Step 4: Viewset** (`api/views.py`, tabs). In `get_queryset`, before `return qs`:
```python
		if self.action == 'list' and not params.get('show_low'):
			from limes.tasks.attribution import REVIEW
			qs = qs.exclude(scope_tier='candidate', confidence__lt=REVIEW)  # unscored (null) stay visible
```
In `filter_queryset`, extend the colmap with `'10': 'confidence'` and replace the final `return` with:
```python
		field = colmap.get(col, 'value')
		if field == 'confidence':
			f = F('confidence')
			return qs.order_by(f.desc(nulls_last=True) if direction == 'desc' else f.asc(nulls_last=True), 'id')
		return qs.order_by(('-' if direction == 'desc' else '') + field, 'id')
```
(`F` is already imported in `api/views.py`; verify.) Re-run the existing no-N+1 test — the count must not change.
- [ ] **Step 5: Template** — header: insert `<th>Confidence</th>` before the final `<th></th>`; columns: insert before the `{data: 'id', ...}` entry:
```javascript
      {data: 'confidence', render: function(d) { return d === null || d === undefined ? '' : esc(Number(d).toFixed(2)); }},
```
Filter row: add a checkbox column after the tag input:
```html
          <div class="col-md-12">
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="f_show_low">
              <label class="form-check-label" for="f_show_low">Show low-confidence candidates</label>
            </div>
          </div>
```
In `assetUrl()` add `if (document.getElementById('f_show_low').checked) u += '&show_low=1';` and register `document.getElementById('f_show_low').addEventListener('change', function() { table.ajax.url(assetUrl()).load(); });`. Update the colmap NOTE comment to `(0..4, 8, 10)`.
- [ ] **Step 6: Modal** (`asset.js`, tabs) — add:
```javascript
function asset_confidence_html(a) {
	var d = a.confidence_detail;
	if (!d || !Array.isArray(d.contributions)) return '';
	var rows = d.contributions.map(function(c) {
		return '<tr><td>' + asset_esc(c.kind) + '</td><td>' + asset_esc(c.value) + '</td><td>' + asset_esc(c.via) +
			'</td><td>' + asset_esc(c.weight) + '</td><td>' + asset_esc(c.hop) + '</td></tr>';
	}).join('') || '<tr><td colspan="5" class="text-muted">No evidence yet.</td></tr>';
	return '<h5>Confidence ' + asset_esc(Number(d.score).toFixed(2)) + ' <small class="text-muted">(' +
		asset_esc(d.version) + ')</small></h5><table class="table table-sm"><thead><tr><th>Evidence</th><th>Value</th>' +
		'<th>Via</th><th>Weight</th><th>Hop</th></tr></thead><tbody>' + rows + '</tbody></table>';
}
```
and in `get_asset_modal` append `+ asset_confidence_html(a)` right after the `'<h5>Why is this mine</h5><p>' + path + '</p>'` fragment. `node --check web/static/custom/asset.js`.
- [ ] **Step 7: Run** `tests.core.test_asset_api` and the full suite → PASS. **Step 8: Commit** — `git commit -m "Show, sort and filter asset ownership confidence"`.
