# ASM module A-dash — Inventory-first dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the project dashboard's legacy per-scan charts with an inventory-first page covering risk, inventory and the review queue, this week's changes, findings, monitoring and recent activity.

**Architecture:**
- `web/dashboard/stats.py` keeps `project_stats(project)` (same cache key, 60s TTL and `invalidate`), but it now returns `asm_stats(project)`. That function is built from the `Asset` inventory, `limes.scoring` (A4), `ScoreSnapshot`, `limes.continuous.due_roots` (A5b) and `ScanActivity`.
- `dashboard/templates/dashboard/index.html` is rewritten to render those sections, with an ApexCharts score trend fed through `json_script`.
- The Assets page honours `?scope_tier=`, so the review-queue tile can link straight to candidates.

**Tech Stack:** Django 3.2 templates, jQuery, ApexCharts 3.29.0 (cdnjs, SRI), PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-10-15-asm-module-a-dash-dashboard-design.md`

## Global Constraints

- **Cache:** `project_stats` keeps the key `dashboard:stats:<project_id>`, `STATS_TTL = 60` and `invalidate(project_id)`, which existing callers use.
- **Windows and limits:** `WEEK = 7 days`, `LIST_LIMIT = 10`, trend = last 30 snapshots oldest first, next due = 5, activity = 15.
- **Owned** means `scope_tier` in (`owned_root`, `owned_host`). The review queue is candidates with `confidence` null or ≥ `attribution.REVIEW`.
- **Findings** are counted only from `scoring.baselines()` scans, on `scoring.assessed_assets()`, with `open_status` true and `severity >= 1`.
- **Project scope:** every section is limited to the project, including `next_due` (`due_roots` is global; filter by `project_id`).
- **Escaping:** Django auto-escaping for every value. The trend goes through `json_script`, never interpolated into JS. No `|safe`.
- **No legacy chart scripts:** the template loads no jvectormap and no `apexcharts.com/samples` scripts.
- **Style:** 4 spaces in `stats.py` and tests; 2 spaces in templates (as in the existing files).
- **Tests:** `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <dotted.path>`; the controller may use an equivalent local runner.
- **Commits:** identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`, no AI attribution, no push without an explicit user yes.

## Review Focus

1. **Cross-project leakage**, especially `next_due` and `last_auto`. Tests: Task 1 `test_due_roots_scoped_and_last_auto_ignores_users`, `test_other_project_findings_never_counted`, `test_counts_are_per_project_and_owned` and `test_review_queue`.
2. **Findings count disagreeing with the score's baselines.** Test: Task 1 `test_counts_only_baseline_findings_on_assessed_assets`.
3. **The trend breaking out of `json_script`.** Task 2's real-UI check renders the trend chart, and every value goes through `json_script`.
4. **An empty project** (no scans, assets or snapshots) rendering without errors. Tests: Task 1 `test_empty_project_renders_defaults`, and Task 2's UI check on an empty project.
5. **The new template referencing a missing context key.** Task 2's template compile check, plus the UI check that every section renders.

## Rulings made while planning

- **View unchanged:** `dashboard/views.py::index` still spreads `project_stats` into the context, so the template reads `risk`, `inventory`, `review`, `changes`, `findings`, `monitoring` and `activity` directly.
- **Owned-host count:** it counts hostname and root-domain assets, while `owned_host` IP assets are counted under `ip`. A host is never counted twice.
- **"Last 7 days" for auto-confirms:** taken from the `seen_at` of the asset's `attribution` source entry. `Asset` stores no decision timestamp.
- **Supply-chain cleanup:** the legacy template's `apexcharts.com/samples/*.js` scripts are dropped. They were loaded from a demo site without integrity checks.
- **Dry run:** the plan's code was dry-run in a throwaway worktree before review. The full core suite passed (466 tests), the template compile check passed, and a real Chromium run of every section passed, including an XSS asset value and the review-link prefill.

---

### Task 1: Dashboard data from the inventory

**Files:**
- Modify (rewrite): `web/dashboard/stats.py`
- Modify (rewrite): `web/tests/core/test_dashboard_stats.py`

**Interfaces:**
- Consumes:
  - `limes.scoring.project_score`, `baselines` and `assessed_assets` (A4);
  - `limes.continuous.due_roots(now)` and `IN_PROGRESS` (A5b);
  - `limes.tasks.attribution.REVIEW`;
  - `startScan.models.ScoreSnapshot`.
- Produces: `dashboard.stats.asm_stats(project) -> dict` with keys `risk` (`project_score` plus `trend`), `inventory`, `review`, `changes`, `findings`, `monitoring` and `activity`. `project_stats(project)` returns it, cached.

- [ ] **Step 1: Write the failing tests**

Replace `web/tests/core/test_dashboard_stats.py` with:

```python
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from dashboard.stats import asm_stats, invalidate, project_stats
from limes.definitions import RUNNING_TASK, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import Asset, ScanActivity, ScanHistory, ScoreSnapshot, Vulnerability
from targetApp.models import Domain


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.now = timezone.now()
        self.eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.p = Project.objects.create(name='p', slug='p', insert_date=self.now)
        self.other = Project.objects.create(name='o', slug='o', insert_date=self.now)
        self.root = self.owned_root(self.p, 'x.com')
        self.owned_root(self.other, 'y.com')

    def owned_root(self, project, value):
        Domain.objects.create(project=project, name=value, insert_date=self.now)
        return Asset.objects.create(project=project, kind='root_domain', value=value, scope_tier='owned_root')

    def asset(self, value, tier='owned_host', kind='hostname', project=None, **kw):
        return Asset.objects.create(project=project or self.p, kind=kind, value=value, scope_tier=tier, **kw)

    def scan(self, domain='x.com', ago=timedelta(hours=1), vuln=True, user=None, status=SUCCESS_TASK):
        s = ScanHistory.objects.create(domain=Domain.objects.get(name=domain), scan_type=self.eng, scan_status=status,
                                       start_scan_date=self.now - ago, initiated_by=user)
        if vuln:
            ScanActivity.objects.create(scan_of=s, name='vulnerability_scan', title='v', time=self.now, status=SUCCESS_TASK)
        return s


class InventoryTest(Base):
    def test_counts_are_per_project_and_owned(self):
        self.asset('a.x.com')
        self.asset('b.x.com', state='missing')
        self.asset('203.0.113.9', kind='ip')
        self.asset('cdn.net', tier='dependency', kind='root_domain')
        self.asset('cand.x.com', tier='candidate', state='missing')
        self.asset('o.y.com', project=self.other)
        inv = asm_stats(self.p)['inventory']
        self.assertEqual((inv['owned_root'], inv['owned_host'], inv['ip'], inv['dependency']), (1, 2, 1, 1))
        self.assertEqual(inv['states'], {'active': 3, 'missing': 1, 'stale': 0, 'retired': 0})

    def test_review_queue(self):
        self.asset('low.net', tier='candidate', kind='root_domain', confidence=0.2)
        self.asset('mid.net', tier='candidate', kind='root_domain', confidence=0.6)
        self.asset('new.net', tier='candidate', kind='root_domain')
        self.asset('would.net', tier='candidate', kind='root_domain', confidence=0.95,
                   confidence_detail={'would_auto_confirm': True})
        self.asset('o.net', tier='candidate', kind='root_domain', project=self.other)
        self.assertEqual(asm_stats(self.p)['review'], {'candidates': 3, 'would_auto_confirm': 1})


class ChangesTest(Base):
    def test_seven_day_windows_and_order(self):
        recent, old = self.asset('recent.x.com'), self.asset('old.x.com')
        Asset.objects.filter(pk=recent.pk).update(first_seen=self.now - timedelta(days=6))
        Asset.objects.filter(pk=old.pk).update(first_seen=self.now - timedelta(days=8))
        Asset.objects.filter(pk=self.root.pk).update(first_seen=self.now - timedelta(days=30))
        m1 = self.asset('m1.x.com', state='missing')
        m2 = self.asset('m2.x.com', state='missing')
        Asset.objects.filter(pk=m1.pk).update(last_seen=self.now - timedelta(days=5), first_seen=self.now - timedelta(days=30))
        Asset.objects.filter(pk=m2.pk).update(last_seen=self.now - timedelta(days=2), first_seen=self.now - timedelta(days=30))
        ch = asm_stats(self.p)['changes']
        self.assertEqual([r['value'] for r in ch['new_owned']], ['recent.x.com'])
        self.assertEqual([r['value'] for r in ch['missing']], ['m2.x.com', 'm1.x.com'])

    def test_auto_confirmed_this_week(self):
        for value, days in (('fresh.net', 2), ('stale.net', 8)):
            self.asset(value, tier='owned_root', kind='root_domain',
                       decision_reason='auto-confirmed (attribution-v1) 0.97: NS ...',
                       sources=[{'source': 'attribution', 'evidence': 'e',
                                 'seen_at': (self.now - timedelta(days=days)).isoformat()}])
        self.asset('manual.net', tier='owned_root', kind='root_domain', decision_reason='confirmed by hand',
                   sources=[{'source': 'manual', 'evidence': 'e', 'seen_at': self.now.isoformat()}])
        self.assertEqual([r['value'] for r in asm_stats(self.p)['changes']['auto_confirmed']], ['fresh.net'])


class FindingsTest(Base):
    def test_counts_only_baseline_findings_on_assessed_assets(self):
        a = self.asset('a.x.com')
        old = self.scan(ago=timedelta(days=3))
        Vulnerability.objects.create(scan_history=old, asset=a, name='gone', severity=4, open_status=True)
        new = self.scan()
        for sev in (4, 3, 3, 1, 0):
            Vulnerability.objects.create(scan_history=new, asset=a, name=f'v{sev}', severity=sev, open_status=True)
        Vulnerability.objects.create(scan_history=new, asset=a, name='closed', severity=4, open_status=False)
        self.assertEqual(asm_stats(self.p)['findings'], {'critical': 1, 'high': 2, 'medium': 0, 'low': 1})

    def test_other_project_findings_never_counted(self):
        o = self.asset('o.y.com', project=self.other)
        Vulnerability.objects.create(scan_history=self.scan('y.com'), asset=o, name='v', severity=4, open_status=True)
        self.assertEqual(asm_stats(self.p)['findings']['critical'], 0)


class RiskTest(Base):
    def test_trend_oldest_first_capped_and_scoped(self):
        for i in range(35):
            ScoreSnapshot.objects.create(project=self.p, date=(self.now - timedelta(days=i)).date(), version='v',
                                         score=900 - i, grade='A')
        ScoreSnapshot.objects.create(project=self.other, date=(self.now + timedelta(days=1)).date(), version='v',
                                     score=1, grade='F')
        trend = asm_stats(self.p)['risk']['trend']
        self.assertEqual(len(trend), 30)
        self.assertEqual((trend[0]['score'], trend[-1]['score']), (871, 900))
        self.assertTrue(trend[0]['date'] < trend[-1]['date'])


class MonitoringTest(Base):
    def test_due_roots_scoped_and_last_auto_ignores_users(self):
        from django.contrib.auth.models import User
        user = User.objects.create_user('u', password='p')
        self.scan(ago=timedelta(days=1), vuln=False)  # automatic (no user)
        self.scan(ago=timedelta(hours=1), vuln=False, user=user)  # manual, newer
        self.scan('y.com', ago=timedelta(minutes=1), vuln=False)  # other project's automatic scan
        mon = asm_stats(self.p)['monitoring']
        self.assertEqual(mon['last_auto'], self.now - timedelta(days=1))
        self.assertEqual(mon['next_due'], [])  # x.com was scanned within its 7-day cadence
        Asset.objects.filter(pk=self.root.pk).update(cadence_tier='crown_jewel')
        Asset.objects.filter(project=self.other).update(cadence_tier='crown_jewel')
        ScanHistory.objects.all().update(start_scan_date=self.now - timedelta(days=2))
        self.assertEqual(asm_stats(self.p)['monitoring']['next_due'], [{'value': 'x.com', 'cadence_tier': 'crown_jewel'}])

    @override_settings(CONTINUOUS_SCANS=False)
    def test_running_and_disabled(self):
        self.scan(vuln=False, status=RUNNING_TASK)
        self.scan('y.com', vuln=False, status=RUNNING_TASK)
        mon = asm_stats(self.p)['monitoring']
        self.assertEqual((mon['enabled'], mon['running']), (False, 1))


class EmptyAndCacheTest(Base):
    def test_empty_project_renders_defaults(self):
        empty = Project.objects.create(name='e', slug='e', insert_date=self.now)
        s = asm_stats(empty)
        self.assertEqual((s['risk']['score'], s['risk']['grade'], s['risk']['trend']), (None, 'N/A', []))
        self.assertEqual(s['inventory']['owned_root'], 0)
        self.assertEqual(s['changes'], {'new_owned': [], 'missing': [], 'auto_confirmed': []})
        self.assertEqual(s['activity'], [])

    def test_cached_until_invalidated(self):
        with mock.patch('dashboard.stats.asm_stats', wraps=asm_stats) as compute:
            project_stats(self.p)
            project_stats(self.p)
            self.assertEqual(compute.call_count, 1)
            invalidate(self.p.id)
            project_stats(self.p)
            self.assertEqual(compute.call_count, 2)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_dashboard_stats`
Expected: ERROR, `ImportError: cannot import name 'asm_stats' from 'dashboard.stats'`.

- [ ] **Step 3: Implement**

Replace `web/dashboard/stats.py` with:

```python
"""Project dashboard data (A-dash): inventory-first, read from the Asset inventory and the A4 score.
Cached per project for STATS_TTL; asset decisions and finished scans call invalidate()."""
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db.models import Count, Q
from django.utils import timezone

STATS_TTL = 60
WEEK = timedelta(days=7)
LIST_LIMIT = 10
OWNED = ('owned_root', 'owned_host')
SEVERITY_FIELDS = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}


def _key(project_id):
    return f'dashboard:stats:{project_id}'


def invalidate(project_id):
    cache.delete(_key(project_id))


def _risk(project):
    from limes import scoring
    from startScan.models import ScoreSnapshot
    risk = scoring.project_score(project)
    snaps = ScoreSnapshot.objects.filter(project=project).order_by('-date').values('date', 'score')[:30]
    risk['trend'] = [{'date': s['date'].isoformat(), 'score': s['score']} for s in reversed(list(snaps))]
    return risk


def _inventory(project):
    from startScan.models import Asset
    assets = Asset.objects.filter(project=project)
    counts = assets.aggregate(
        owned_root=Count('id', filter=Q(scope_tier='owned_root')),
        owned_host=Count('id', filter=Q(scope_tier='owned_host', kind__in=('hostname', 'root_domain'))),
        ip=Count('id', filter=Q(scope_tier__in=OWNED, kind='ip')),
        dependency=Count('id', filter=Q(scope_tier='dependency')))
    states = dict(assets.filter(scope_tier__in=OWNED).values_list('state').annotate(n=Count('id')))
    counts['states'] = {s: states.get(s, 0) for s in ('active', 'missing', 'stale', 'retired')}
    return counts


def _review(project):
    from limes.tasks.attribution import REVIEW
    from startScan.models import Asset
    cands = Asset.objects.filter(project=project, scope_tier='candidate')
    return {'candidates': cands.filter(Q(confidence__isnull=True) | Q(confidence__gte=REVIEW)).count(),
            'would_auto_confirm': cands.filter(confidence_detail__would_auto_confirm=True).count()}


def _changes(project, now):
    from startScan.models import Asset
    owned = Asset.objects.filter(project=project, scope_tier__in=OWNED)
    new = owned.filter(first_seen__gte=now - WEEK).order_by('-first_seen', 'id')[:LIST_LIMIT]
    missing = owned.filter(state='missing').order_by('-last_seen', 'id')[:LIST_LIMIT]
    auto = []
    for a in owned.filter(decision_reason__startswith='auto-confirmed', sources__contains=[{'source': 'attribution'}]):
        seen = max((s.get('seen_at') or '' for s in a.sources or [] if s.get('source') == 'attribution'), default='')
        if seen >= (now - WEEK).isoformat():
            auto.append({'value': a.value, 'kind': a.kind, 'seen_at': seen})
    auto.sort(key=lambda r: r['seen_at'], reverse=True)
    return {'new_owned': _rows(new, 'first_seen'), 'missing': _rows(missing, 'last_seen'),
            'auto_confirmed': auto[:LIST_LIMIT]}


def _rows(assets, field):
    return [{'value': a.value, 'kind': a.kind, field: getattr(a, field)} for a in assets]


def _findings(project):
    from limes import scoring
    from startScan.models import Vulnerability
    base = scoring.baselines(project)
    assets = scoring.assessed_assets(project, base)
    counts = (Vulnerability.objects.filter(scan_history__in=[s.id for s in base.values()], open_status=True,
                                           asset_id__in=list(assets), severity__gte=1)
              .values_list('severity').annotate(n=Count('id')))
    by_sev = dict(counts)
    return {name: by_sev.get(sev, 0) for sev, name in SEVERITY_FIELDS.items()}


def _monitoring(project, now):
    from limes import continuous
    from startScan.models import ScanHistory
    scans = ScanHistory.objects.filter(domain__project=project)
    # NOTE: due_roots spans every project; fine for hundreds of roots, cached for STATS_TTL
    due = [a for a in continuous.due_roots(now) if a.project_id == project.id][:5]
    last_auto = scans.filter(initiated_by__isnull=True).order_by('-start_scan_date').values_list('start_scan_date', flat=True).first()
    return {'enabled': settings.CONTINUOUS_SCANS,
            'running': scans.filter(scan_status__in=continuous.IN_PROGRESS).count(),
            'next_due': [{'value': a.value, 'cadence_tier': a.cadence_tier} for a in due],
            'last_auto': last_auto}


def asm_stats(project):
    from startScan.models import ScanActivity
    now = timezone.now()
    return {
        'risk': _risk(project),
        'inventory': _inventory(project),
        'review': _review(project),
        'changes': _changes(project, now),
        'findings': _findings(project),
        'monitoring': _monitoring(project, now),
        'activity': list(ScanActivity.objects.filter(scan_of__domain__project=project).order_by('-time')[:15]),
    }


def project_stats(project):
    stats = cache.get(_key(project.id))
    if stats is None:
        stats = asm_stats(project)
        cache.set(_key(project.id), stats, STATS_TTL)
    return stats
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_dashboard_stats tests.core.test_scoring tests.core.test_continuous`
Expected: all OK.

- [ ] **Step 5: Commit**

```bash
git add web/dashboard/stats.py web/tests/core/test_dashboard_stats.py
git commit -m "Build dashboard data from the asset inventory and risk score

The dashboard counted the per-scan tables, so every rescan inflated
its totals, and it ignored scope, lifecycle, the score and monitoring."
```

### Task 2: Dashboard page and review-queue link

**Files:**
- Modify (rewrite): `web/dashboard/templates/dashboard/index.html`
- Modify: `web/startScan/templates/startScan/assets.html` (`?scope_tier=` prefill)

**Interfaces:**
- Consumes: the `asm_stats` context keys from Task 1, and the `assets` URL name (`startScan/urls.py`).

- [ ] **Step 1: Implement**

Replace `web/dashboard/templates/dashboard/index.html` with:

```html
{% extends 'base/base.html' %}
{% load humanize %}
{% load static %}
{% block title %}
Dashboard
{% endblock title %}

{% block page_title %}
Dashboard
{% endblock page_title %}

{% block custom_js_css_link %}
<link rel="stylesheet" type="text/css" href="{% static 'custom/custom.css' %}">
{% endblock custom_js_css_link %}

{% block breadcrumb_title %}
<span class="badge badge-soft-info">Limes {{ LIMES_CURRENT_VERSION }}</span>
{% endblock breadcrumb_title %}

{% block main_content %}
{% url 'assets' slug=project.slug as assets_url %}
<div class="row">
  <div class="col-xl-5">
    <div class="card" id="dash_risk">
      <div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <h4 class="header-title mb-0">Risk</h4>
          <a href="{{ assets_url }}" class="btn btn-xs btn-soft-primary">Assets</a>
        </div>
        {% if risk.score is not None %}
          <div class="d-flex align-items-baseline">
            <span class="display-5 me-2">{{ risk.score }}</span>
            <span class="badge bg-soft-primary text-primary font-16">{{ risk.grade }}</span>
          </div>
          <p class="text-muted mb-2">
            {% if risk.coverage is not None %}{% widthratio risk.coverage 1 100 %}%{% else %}n/a{% endif %} of owned roots scanned for vulnerabilities in 30 days
            {% if risk.unassessed %}&middot; {{ risk.unassessed }} assets not yet scanned{% endif %}
            &middot; {{ risk.version }}
          </p>
        {% elif risk.unassessed %}
          <p class="text-muted">Not yet vulnerability-scanned: {{ risk.unassessed }} owned assets have no score.</p>
        {% else %}
          <p class="text-muted">No owned assets yet.</p>
        {% endif %}
        <div id="score_trend"></div>
        {% if risk.top_penalties %}
        <table class="table table-sm mb-0 mt-2">
          <thead><tr><th>Asset</th><th>Issue</th><th>Severity</th><th>Points</th></tr></thead>
          <tbody>
          {% for p in risk.top_penalties %}
            <tr><td>{{ p.asset }}</td><td>{{ p.issue }}</td><td>{{ p.severity }}</td><td>-{{ p.points }}</td></tr>
          {% endfor %}
          </tbody>
        </table>
        {% endif %}
      </div>
    </div>
  </div>
  <div class="col-xl-7">
    <div class="card" id="dash_inventory">
      <div class="card-body">
        <h4 class="header-title mb-3">Inventory</h4>
        <div class="row text-center">
          <div class="col-3"><h3 class="mb-0">{{ inventory.owned_root|intcomma }}</h3><small class="text-muted">Owned roots</small></div>
          <div class="col-3"><h3 class="mb-0">{{ inventory.owned_host|intcomma }}</h3><small class="text-muted">Owned hosts</small></div>
          <div class="col-3"><h3 class="mb-0">{{ inventory.ip|intcomma }}</h3><small class="text-muted">IPs</small></div>
          <div class="col-3"><h3 class="mb-0">{{ inventory.dependency|intcomma }}</h3><small class="text-muted">Dependencies</small></div>
        </div>
        <p class="text-muted mt-3 mb-2">
          Active {{ inventory.states.active }} &middot; Missing {{ inventory.states.missing }} &middot;
          Stale {{ inventory.states.stale }} &middot; Retired {{ inventory.states.retired }}
        </p>
        <a href="{{ assets_url }}?scope_tier=candidate" id="dash_review" class="d-block border rounded p-2">
          <b>Review queue:</b> {{ review.candidates }} candidates
          {% if review.would_auto_confirm %}&middot; {{ review.would_auto_confirm }} would auto-confirm{% endif %}
        </a>
      </div>
    </div>
    <div class="card" id="dash_findings">
      <div class="card-body">
        <h4 class="header-title mb-2">Findings on owned assets</h4>
        <span class="badge bg-danger me-1">Critical {{ findings.critical }}</span>
        <span class="badge bg-warning me-1">High {{ findings.high }}</span>
        <span class="badge bg-info me-1">Medium {{ findings.medium }}</span>
        <span class="badge bg-secondary">Low {{ findings.low }}</span>
        <p class="text-muted mb-0 mt-2"><small>Open findings from each owned root's latest vulnerability scan.</small></p>
      </div>
    </div>
  </div>
</div>
<div class="row">
  <div class="col-xl-7">
    <div class="card" id="dash_changes">
      <div class="card-body">
        <h4 class="header-title mb-3">This week</h4>
        <div class="row">
          <div class="col-md-4">
            <h5>New owned assets</h5>
            {% for a in changes.new_owned %}<div>{{ a.value }} <small class="text-muted">{{ a.first_seen|naturaltime }}</small></div>
            {% empty %}<p class="text-muted">None.</p>{% endfor %}
          </div>
          <div class="col-md-4">
            <h5>Missing</h5>
            {% for a in changes.missing %}<div>{{ a.value }} <small class="text-muted">seen {{ a.last_seen|naturaltime }}</small></div>
            {% empty %}<p class="text-muted">None.</p>{% endfor %}
          </div>
          <div class="col-md-4">
            <h5>Auto-confirmed</h5>
            {% for a in changes.auto_confirmed %}<div>{{ a.value }}</div>
            {% empty %}<p class="text-muted">None.</p>{% endfor %}
          </div>
        </div>
      </div>
    </div>
  </div>
  <div class="col-xl-5">
    <div class="card" id="dash_monitoring">
      <div class="card-body">
        <h4 class="header-title mb-2">Monitoring</h4>
        <p class="mb-1">Continuous scanning <b>{% if monitoring.enabled %}on{% else %}off{% endif %}</b> &middot; {{ monitoring.running }} running</p>
        <p class="text-muted mb-2">Last automatic scan: {% if monitoring.last_auto %}{{ monitoring.last_auto|naturaltime }}{% else %}never{% endif %}</p>
        {% if monitoring.next_due %}
        <table class="table table-sm mb-0">
          <thead><tr><th>Next due</th><th>Cadence</th></tr></thead>
          <tbody>{% for r in monitoring.next_due %}<tr><td>{{ r.value }}</td><td>{{ r.cadence_tier }}</td></tr>{% endfor %}</tbody>
        </table>
        {% else %}<p class="text-muted mb-0">Nothing due.</p>{% endif %}
      </div>
    </div>
  </div>
</div>
<div class="row">
  <div class="col-12">
    <div class="card" id="dash_activity">
      <div class="card-body">
        <h4 class="header-title mb-2">Recent scan activity</h4>
        {% for a in activity %}
          <div><small class="text-muted">{{ a.time|naturaltime }}</small> {{ a.title }}</div>
        {% empty %}<p class="text-muted mb-0">No scan activity yet.</p>{% endfor %}
      </div>
    </div>
  </div>
</div>
{{ risk.trend|json_script:"score_trend_data" }}
{% endblock main_content %}

{% block page_level_script %}
<script src="https://cdnjs.cloudflare.com/ajax/libs/apexcharts/3.29.0/apexcharts.min.js" integrity="sha512-fe6OklXva8AWoqdwgkE7Ni4uWgHGWxFQWZx4lYehzY2Qrst5YfogjAbnLd6egsoTrnjGI9/LYt1Ont2cKNbP2A==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script type="text/javascript">
$(document).ready(function() {
  var trend = JSON.parse(document.getElementById('score_trend_data').textContent);
  if (trend.length < 2) return;
  new ApexCharts(document.getElementById('score_trend'), {
    chart: {type: 'line', height: 140, toolbar: {show: false}, sparkline: {enabled: false}},
    series: [{name: 'Score', data: trend.map(function(p) { return {x: p.date, y: p.score}; })}],
    xaxis: {type: 'category', labels: {show: false}},
    yaxis: {min: 0, max: 950},
    stroke: {width: 2}
  }).render();
});
</script>
{% endblock page_level_script %}
```

In `web/startScan/templates/startScan/assets.html`, add directly after the line `  load_asset_score();`:

```javascript
  // ?scope_tier= (e.g. the dashboard's review-queue link) preselects a known filter value
  var qTier = new URLSearchParams(location.search).get('scope_tier');
  var tierSel = document.getElementById('f_scope_tier');
  if (qTier && Array.prototype.some.call(tierSel.options, function(o) { return o.value === qTier; })) tierSel.value = qTier;
```

- [ ] **Step 2: Verify templates and the real UI**

Run the template compile check (every template under `web/` compiles), then the full core suite.
Expected: `bad=0`, and all tests OK.

Restart the dev server. Seed:
- an owned host whose value is `"><script>alert(9)</script>.example.com`;
- a candidate with `would_auto_confirm`;
- two `ScoreSnapshot` rows.

Open `/<slug>/dashboard/`. Expected:
- all six sections render (`#dash_risk`, `#dash_inventory`, `#dash_findings`, `#dash_changes`, `#dash_monitoring`, `#dash_activity`);
- the trend chart renders;
- the script-tag asset value shows as text, with no `<script>` element inside the section and no dialog;
- the review tile mentions "would auto-confirm", and clicking it opens Assets with the scope filter set to `candidate`;
- an empty project shows "No owned assets yet.";
- there are no console errors.

- [ ] **Step 3: Commit**

```bash
git add web/dashboard/templates/dashboard/index.html web/startScan/templates/startScan/assets.html
git commit -m "Show risk, inventory, changes and monitoring on the dashboard

Legacy per-scan charts, the world map and demo-site chart scripts go;
the review-queue tile links to the Assets page filtered to candidates."
```
