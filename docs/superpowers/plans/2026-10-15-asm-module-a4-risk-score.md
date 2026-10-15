# ASM module A4 — Explainable risk score Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every project a published 0–950 risk score and grade built from findings on its owned assets, show which findings cost points, and keep a daily snapshot.

**Architecture:**
- `save_vulnerability` links each finding to its inventory asset (`resolve_vuln_asset`), and a command backfills older rows.
- `web/limes/scoring.py` (model `limes-score-v1`) computes asset and project scores on demand. It reads each owned root's latest scan whose `vulnerability_scan` activity succeeded.
- A daily beat task stores a `ScoreSnapshot`.
- A score API feeds a card on the Assets page. The asset retrieve API adds a `risk` breakdown for the modal.

**Tech Stack:** Django 3.2, Celery 5.4 with django-celery-beat, PostgreSQL, jQuery and DataTables.

**Spec:** `docs/superpowers/specs/2026-10-15-asm-module-a4-risk-score-design.md`

## Global Constraints

- **Model constants:**
  - `VERSION = 'limes-score-v1'`, `MAX_SCORE = 950`;
  - `PENALTY = {4: 200, 3: 80, 2: 25, 1: 5}` (info 0 and unknown -1 cost nothing);
  - `CEILING = {4: 599, 3: 799}`;
  - grades A ≥800, B ≥600, C ≥400, D ≥200, F otherwise;
  - `COVERAGE_WINDOW = 30 days`, `TOP_PENALTIES = 5`.
- **Scored assets:** `scope_tier` in (`owned_root`, `owned_host`), `kind` in (`root_domain`, `hostname`), and `state != 'retired'`.
- **Baseline:** per owned root's `Domain`, the latest `ScanHistory` with a `ScanActivity(name='vulnerability_scan', status=SUCCESS_TASK)`.
- **Counted findings:** in a baseline scan, `open_status` true, `severity >= 1`, on a scored asset. Category is `template_id or name`, counted once per asset at its worst severity.
- **Project score:** the nearest-rank P10, index `max(0, ceil(0.10·n) − 1)`. No scored assets gives `None` / `'N/A'`.
- **Linking never crosses projects:** the asset must be in `scan_history.domain.project`.
- **Escaping:** finding names, template ids and URLs are scanner output and go through `asset_esc` everywhere they render.
- **Style:**
  - tabs in `persistence.py`, `api/views.py`, `asset.js` and `assets.html`'s script;
  - 4 spaces in `scoring.py`, `startScan/*`, the management command and tests;
  - `api/urls.py` is **CRLF**: keep `\r\n` (Python `newline=''`).
- **Tests:** `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <dotted.path>`; the controller may use an equivalent local runner. No network.
- **Migrations:** generate with `makemigrations`. The final `makemigrations --check` must be clean.
- **Commits:** identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`, no AI attribution, no push without an explicit user yes.

## Review Focus

1. **Double counting across rescans and URLs.** Tests: Task 2 `test_refound_finding_counts_once` and `test_same_issue_counts_once_at_its_worst`.
2. **A scan without a successful vulnerability stage** must never become the baseline, or everything would read as "fixed". Test: Task 2 `test_scan_without_a_successful_vuln_stage_is_never_baseline`.
3. **Linking must never cross projects.** Test: Task 1 `test_never_crosses_projects_or_invents`. Scoring must never include another project's findings. Test: Task 2 `test_other_projects_never_leak_in`.
4. **P10 at small n** (1, 2, 9, 10, 11), and no assets giving N/A. Tests: Task 2 `test_p10_nearest_rank` and `test_no_assets_is_not_applicable`.
5. **An XSS payload in a finding name** renders as text in the card and the modal. Test: Task 3 `test_project_score` returns it raw, and Task 4's real-UI check confirms it is escaped.

## Rulings made while planning

- **Where the backfill resolver lives:** `resolve_vuln_asset(scan_history, subdomain=None, http_url=None)` lives in `limes/tasks/persistence.py`, next to `save_vulnerability`. Every finding writer and the backfill command share it.
- **Retrieve API:** `AssetDatatableViewSet.retrieve` is overridden to add `risk`. The list endpoint stays unscored, to avoid N+1 scoring per page.
- **Score endpoint permissions:** `AssetScore` has no extra permission class, the same as the asset list. Login is enforced by the site's login-required middleware.
- **Duplicate-row test artifact:** the test helper gives every saved finding a distinct name. Calling `get_or_create` with the same partial fields twice raised `MultipleObjectsReturned`, which is the existing `save_vulnerability` contract and not part of this slice.
- **Dry run:** the plan's code was dry-run in a throwaway worktree before review. The full core suite passed (454 tests), `makemigrations --check` was clean, and `node --check` passed.

---

### Task 1: Link findings to assets

**Files:**
- Modify: `web/limes/tasks/persistence.py` (`resolve_vuln_asset`, and `save_vulnerability` sets `asset`)
- Create: `web/startScan/management/commands/link_vulnerabilities.py`
- Create: `web/tests/core/test_vuln_link.py`

**Interfaces:**
- Produces: `limes.tasks.persistence.resolve_vuln_asset(scan_history, subdomain=None, http_url=None) -> Asset | None`, and the command `manage.py link_vulnerabilities [project_slug]`, which prints `linked=<n>`.

- [ ] **Step 1: Write the failing tests**

Create `web/tests/core/test_vuln_link.py`:

```python
from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks.persistence import save_vulnerability
from scanEngine.models import EngineType
from startScan.models import Asset, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class LinkTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.other = Project.objects.create(name='o', slug='o', insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.domain = Domain.objects.create(project=self.p, name='x.com', insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=eng, start_scan_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.host = Asset.objects.create(project=self.p, kind='hostname', value='app.x.com', scope_tier='owned_host')
        Asset.objects.create(project=self.other, kind='hostname', value='api.x.com', scope_tier='owned_host')

    def save(self, **kw):
        save_vulnerability(scan_history=self.scan, name=f'n{Vulnerability.objects.count()}', severity=3, **kw)
        return Vulnerability.objects.latest('id')

    def test_links_by_subdomain_then_url(self):
        sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='app.x.com')
        self.assertEqual(self.save(subdomain=sub, http_url='https://other.x.com/').asset, self.host)
        self.assertEqual(self.save(http_url='https://APP.x.com.:8443/login').asset, self.host)
        self.assertEqual(self.save(http_url='x.com/path').asset, self.root)

    def test_never_crosses_projects_or_invents(self):
        self.assertIsNone(self.save(http_url='https://api.x.com/').asset)  # only the other project has it
        self.assertIsNone(self.save(http_url='https://unknown.x.com/').asset)
        self.assertIsNone(self.save().asset)

    def test_backfill_is_idempotent(self):
        v = Vulnerability.objects.create(scan_history=self.scan, name='old', severity=2, http_url='https://app.x.com/')
        out = StringIO()
        call_command('link_vulnerabilities', 'p', stdout=out)
        call_command('link_vulnerabilities', stdout=out)
        v.refresh_from_db()
        self.assertEqual(v.asset, self.host)
        self.assertEqual(out.getvalue().split(), ['linked=1', 'linked=0'])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_vuln_link`
Expected:
- `test_links_by_subdomain_then_url` FAILs with `None != <Asset ...>`;
- `test_backfill_is_idempotent` errors with `Unknown command: 'link_vulnerabilities'`;
- `test_never_crosses_projects_or_invents` already passes, because nothing links today. It pins the boundary for Step 3.

- [ ] **Step 3: Implement**

In `web/limes/tasks/persistence.py`, add directly above `def save_vulnerability(**vuln_data):`:

```python
def resolve_vuln_asset(scan_history, subdomain=None, http_url=None):
	"""The scan's project Asset (hostname or root domain) a finding is on, else None.
	Never crosses projects: the asset must belong to the scan's own project."""
	from urllib.parse import urlsplit
	from startScan.models import Asset
	if not scan_history:
		return None
	host = getattr(subdomain, 'name', None)
	if not host and http_url:
		try:
			host = urlsplit(http_url if '://' in http_url else '//' + http_url).hostname
		except ValueError:
			host = None
	host = (host or '').strip().rstrip('.').lower()
	if not host:
		return None
	return (Asset.objects
			.filter(project_id=scan_history.domain.project_id, kind__in=('hostname', 'root_domain'), value=host)
			.first())
```

In `save_vulnerability`, right after `vuln_data = replace_nulls(vuln_data)`, add:

```python
	if not vuln_data.get('asset'):
		vuln_data['asset'] = resolve_vuln_asset(
			vuln_data.get('scan_history'), vuln_data.get('subdomain'), vuln_data.get('http_url'))
```

Create `web/startScan/management/commands/link_vulnerabilities.py`:

```python
from django.core.management.base import BaseCommand, CommandError

from dashboard.models import Project
from limes.tasks.persistence import resolve_vuln_asset
from startScan.models import Vulnerability


class Command(BaseCommand):
    help = 'Link findings saved before A4 to their inventory asset (idempotent).'

    def add_arguments(self, parser):
        parser.add_argument('project_slug', nargs='?')

    def handle(self, *args, **options):
        vulns = Vulnerability.objects.filter(asset__isnull=True).select_related('scan_history__domain', 'subdomain')
        if options['project_slug']:
            project = Project.objects.filter(slug=options['project_slug']).first()
            if not project:
                raise CommandError(f'unknown project {options["project_slug"]}')
            vulns = vulns.filter(scan_history__domain__project=project)
        linked = 0
        for v in vulns.iterator():
            asset = resolve_vuln_asset(v.scan_history, v.subdomain, v.http_url)
            if asset:
                linked += Vulnerability.objects.filter(pk=v.pk, asset__isnull=True).update(asset=asset)
        self.stdout.write(f'linked={linked}')
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_vuln_link tests.core.test_asset_api`
Expected: all OK.

- [ ] **Step 5: Commit**

```bash
git add web/limes/tasks/persistence.py web/startScan/management/commands/link_vulnerabilities.py web/tests/core/test_vuln_link.py
git commit -m "Link findings to their inventory asset

Vulnerability.asset was never set, so every asset reported zero
findings and nothing could be scored per asset. Every finding writer
now links through save_vulnerability, and link_vulnerabilities
backfills older rows."
```

### Task 2: Score model and daily snapshot

**Files:**
- Create: `web/limes/scoring.py`
- Modify: `web/startScan/asset_models.py` (`ScoreSnapshot`, `__all__`). Generate `makemigrations startScan -n scoresnapshot`, which should be `0018`.
- Modify: `web/limes/settings.py` (`CELERY_IMPORTS` gains `'limes.scoring'`; beat `'snapshot-scores': {'task': 'snapshot_scores', 'schedule': 86400.0}`)
- Modify: `web/limes/celery_routing.py` (`'snapshot_scores': (ORCHESTRATE, 15 * MIN),`)
- Create: `web/tests/core/test_scoring.py`

**Interfaces:**
- Consumes: linked `Vulnerability.asset` from Task 1.
- Produces:
  - `scoring.asset_breakdown(asset) -> {'score': int, 'grade': str, 'penalties': [{'asset', 'issue', 'severity', 'points'}]}`;
  - `scoring.project_score(project) -> {'version', 'score', 'grade', 'coverage', 'asset_count', 'top_penalties'}`;
  - `scoring.scored_assets(project) -> QuerySet[Asset]`;
  - `scoring.grade(score)`, `scoring.p10(scores)`, `scoring.coverage(project, now=None)`;
  - the `snapshot_scores` task;
  - `ScoreSnapshot` with `related_name='score_snapshots'`.

- [ ] **Step 1: Write the failing tests**

Create `web/tests/core/test_scoring.py`:

```python
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes import scoring
from limes.definitions import FAILED_TASK, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import Asset, ScanActivity, ScanHistory, ScoreSnapshot, Vulnerability
from targetApp.models import Domain


class Base(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.root = self.owned_root('x.com')
        self.now = timezone.now()

    def owned_root(self, value, project=None):
        project = project or self.p
        Domain.objects.create(project=project, name=value, insert_date=timezone.now())
        return Asset.objects.create(project=project, kind='root_domain', value=value, scope_tier='owned_root')

    def host(self, value, tier='owned_host', state='active', project=None):
        return Asset.objects.create(project=project or self.p, kind='hostname', value=value, scope_tier=tier, state=state)

    def scan(self, domain='x.com', ago=timedelta(hours=1), vuln_stage=SUCCESS_TASK):
        s = ScanHistory.objects.create(domain=Domain.objects.get(name=domain), scan_type=self.eng,
                                       start_scan_date=self.now - ago)
        if vuln_stage is not None:
            ScanActivity.objects.create(scan_of=s, name='vulnerability_scan', title='v', time=self.now, status=vuln_stage)
        return s

    def vuln(self, scan, asset, severity, template='t1', url='https://h/', open_status=True):
        return Vulnerability.objects.create(scan_history=scan, asset=asset, name=f'{template} name', template_id=template,
                                            severity=severity, http_url=url, open_status=open_status)

    def score(self, asset):
        return scoring.asset_breakdown(asset)['score']


class AssetScoreTest(Base):
    def test_clean_asset_scores_max(self):
        self.scan()
        self.assertEqual(scoring.asset_breakdown(self.host('a.x.com')), {'score': 950, 'grade': 'A', 'penalties': []})

    def test_penalties_and_ceilings(self):
        s = self.scan()
        med, high, crit = self.host('m.x.com'), self.host('h.x.com'), self.host('c.x.com')
        self.vuln(s, med, 2)
        self.vuln(s, high, 3)
        self.vuln(s, crit, 4)
        self.assertEqual((self.score(med), self.score(high), self.score(crit)), (925, 799, 599))
        self.assertEqual((scoring.grade(925), scoring.grade(799), scoring.grade(599)), ('A', 'B', 'C'))

    def test_same_issue_counts_once_at_its_worst(self):
        s = self.scan()
        a = self.host('a.x.com')
        for url in ('https://a/1', 'https://a/2', 'https://a/3'):
            self.vuln(s, a, 2, url=url)
        self.vuln(s, a, 3, url='https://a/4')  # same template, worse severity
        self.vuln(s, a, 1, template='t2')
        b = scoring.asset_breakdown(a)
        self.assertEqual(b['score'], min(950 - 80 - 5, 799))
        self.assertEqual([(r['issue'], r['severity'], r['points']) for r in b['penalties']],
                         [('t1', 'high', 80), ('t2', 'low', 5)])

    def test_floor_at_zero(self):
        s = self.scan()
        a = self.host('a.x.com')
        for i in range(6):
            self.vuln(s, a, 4, template=f't{i}')
        self.assertEqual(self.score(a), 0)

    def test_excluded_findings(self):
        s = self.scan()
        a = self.host('a.x.com')
        self.vuln(s, a, 0, template='info')
        self.vuln(s, a, -1, template='unknown')
        self.vuln(s, a, 4, template='closed', open_status=False)
        self.assertEqual(self.score(a), 950)

    def test_monotonic(self):
        s = self.scan()
        a = self.host('a.x.com')
        before = self.score(a), scoring.project_score(self.p)['score']
        for sev, t in ((1, 'l'), (2, 'm'), (3, 'h'), (4, 'c')):
            self.vuln(s, a, sev, template=t)
            after = self.score(a), scoring.project_score(self.p)['score']
            self.assertLessEqual(after[0], before[0])
            self.assertLessEqual(after[1], before[1])
            before = after


class BaselineTest(Base):
    def test_newer_scan_without_the_finding_recovers(self):
        a = self.host('a.x.com')
        old = self.scan(ago=timedelta(days=2))
        self.vuln(old, a, 4)
        self.assertEqual(self.score(a), 599)
        self.scan(ago=timedelta(hours=1))  # verified fix: the stage ran and found nothing
        self.assertEqual(self.score(a), 950)

    def test_scan_without_a_successful_vuln_stage_is_never_baseline(self):
        a = self.host('a.x.com')
        self.vuln(self.scan(ago=timedelta(days=2)), a, 4)
        self.scan(ago=timedelta(hours=2), vuln_stage=None)  # asm-only run
        self.scan(ago=timedelta(hours=1), vuln_stage=FAILED_TASK)
        self.assertEqual(self.score(a), 599)

    def test_refound_finding_counts_once(self):
        a = self.host('a.x.com')
        self.vuln(self.scan(ago=timedelta(days=2)), a, 3)
        self.vuln(self.scan(ago=timedelta(hours=1)), a, 3)
        self.assertEqual(scoring.asset_breakdown(a)['penalties'], [{'asset': 'a.x.com', 'issue': 't1', 'severity': 'high', 'points': 80}])

    def test_only_owned_unretired_assets_count(self):
        s = self.scan()
        for tier, state in (('candidate', 'active'), ('co_brand', 'active'), ('owned_host', 'retired')):
            a = self.host(f'{tier}-{state}.x.com', tier=tier, state=state)
            self.vuln(s, a, 4)
        self.assertEqual(scoring.project_score(self.p)['score'], 950)
        self.assertEqual(scoring.project_score(self.p)['top_penalties'], [])


class ProjectScoreTest(Base):
    def test_p10_nearest_rank(self):
        cases = {1: [5], 2: [5, 9], 9: list(range(9)), 10: list(range(10)), 11: list(range(11))}
        expected = {1: 5, 2: 5, 9: 0, 10: 0, 11: 1}
        for n, scores in cases.items():
            self.assertEqual(scoring.p10(list(reversed(scores))), expected[n], n)
        self.assertIsNone(scoring.p10([]))

    def test_merger_invariance(self):
        scores = [950, 925, 799, 599, 0, 870, 950, 950, 940, 600, 300, 950]
        self.assertEqual(scoring.p10(scores), scoring.p10(scores + scores))

    def test_no_assets_is_not_applicable(self):
        empty = Project.objects.create(name='e', slug='e', insert_date=timezone.now())
        s = scoring.project_score(empty)
        self.assertEqual((s['score'], s['grade'], s['coverage'], s['asset_count']), (None, 'N/A', None, 0))

    def test_project_score_and_top_penalties(self):
        s = self.scan()
        a, b = self.host('a.x.com'), self.host('b.x.com')
        self.vuln(s, a, 3)
        self.vuln(s, b, 2, template='t2')
        out = scoring.project_score(self.p)
        self.assertEqual((out['version'], out['asset_count'], out['score'], out['grade']), ('limes-score-v1', 3, 799, 'B'))
        self.assertEqual([r['asset'] for r in out['top_penalties']], ['a.x.com', 'b.x.com'])

    def test_coverage_window(self):
        self.owned_root('y.com')
        self.scan('x.com', ago=timedelta(days=29))
        self.scan('y.com', ago=timedelta(days=31))
        self.assertEqual(scoring.coverage(self.p, now=self.now), 0.5)

    def test_other_projects_never_leak_in(self):
        other = Project.objects.create(name='o', slug='o', insert_date=timezone.now())
        self.owned_root('z.com', project=other)
        a = self.host('a.z.com', project=other)
        self.vuln(self.scan('z.com'), a, 4)
        self.scan('x.com')
        self.assertEqual(scoring.project_score(self.p)['score'], 950)


class SnapshotTest(Base):
    def test_one_row_per_project_per_day(self):
        self.vuln(self.scan(), self.host('a.x.com'), 3)
        scoring.snapshot_scores()
        self.vuln(self.scan(ago=timedelta(minutes=5)), self.host('b.x.com'), 4)
        scoring.snapshot_scores()
        snaps = ScoreSnapshot.objects.filter(project=self.p)
        self.assertEqual(snaps.count(), 1)
        self.assertEqual((snaps[0].score, snaps[0].grade, snaps[0].version), (599, 'C', 'limes-score-v1'))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_scoring`
Expected: ERROR, `ImportError: cannot import name 'scoring' from 'limes'` (or `cannot import name 'ScoreSnapshot'`).

- [ ] **Step 3: Implement**

Append to `web/startScan/asset_models.py`:

```python
class ScoreSnapshot(models.Model):
    """Daily project risk score (A4, limes.scoring), kept with the model version that produced it."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='score_snapshots')
    date = models.DateField()
    version = models.CharField(max_length=30)
    score = models.IntegerField(null=True, blank=True)
    grade = models.CharField(max_length=3)
    coverage = models.FloatField(null=True, blank=True)
    asset_count = models.IntegerField(default=0)
    top_penalties = models.JSONField(default=list)

    class Meta:
        unique_together = ('project', 'date')
```

Add `'ScoreSnapshot'` to that file's `__all__`, then run `python3 manage.py makemigrations startScan -n scoresnapshot`.

Create `web/limes/scoring.py`:

```python
"""Published, explainable risk score (A4, model limes-score-v1).

Asset score: 950 minus one penalty per distinct issue (template, else name) at its worst severity,
floored at 0, then capped by the worst severity present. Project score: nearest-rank P10 of owned
asset scores (weakest-link). Findings count only from each root's latest scan whose vulnerability
stage succeeded, so a fix confirmed by a rescan recovers at once and old scans never double-count.
"""
import math
from datetime import timedelta

from django.db.models import Exists, OuterRef
from django.utils import timezone

from limes.celery import app
from limes.definitions import SUCCESS_TASK
from startScan.models import Asset, ScanActivity, ScanHistory, ScoreSnapshot, Vulnerability
from targetApp.models import Domain

VERSION = 'limes-score-v1'
MAX_SCORE = 950
PENALTY = {4: 200, 3: 80, 2: 25, 1: 5}  # critical, high, medium, low; info (0) and unknown (-1) cost nothing
CEILING = {4: 599, 3: 799}  # any critical caps at grade C, any high at grade B
GRADES = [(800, 'A'), (600, 'B'), (400, 'C'), (200, 'D'), (0, 'F')]
COVERAGE_WINDOW = timedelta(days=30)
TOP_PENALTIES = 5
SEVERITY_NAMES = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}


def grade(score):
    if score is None:
        return 'N/A'
    return next(g for floor, g in GRADES if score >= floor)


def scored_assets(project):
    return Asset.objects.filter(project=project, scope_tier__in=('owned_root', 'owned_host'),
                                kind__in=('root_domain', 'hostname')).exclude(state='retired')


def _owned_domains(project):
    roots = Asset.objects.filter(project=project, kind='root_domain', scope_tier='owned_root').values('value')
    return Domain.objects.filter(project=project, name__in=roots)


def baselines(project):
    """{domain_id: ScanHistory} - each owned root's latest scan whose vulnerability stage succeeded."""
    vuln_ok = ScanActivity.objects.filter(scan_of=OuterRef('pk'), name='vulnerability_scan', status=SUCCESS_TASK)
    out = {}
    for d in _owned_domains(project):
        scan = (ScanHistory.objects.filter(domain=d).filter(Exists(vuln_ok))
                .order_by('-start_scan_date', '-id').first())
        if scan:
            out[d.id] = scan
    return out


def _penalties(project, asset_ids=None):
    """{asset_id: {category: severity}} from the baseline scans, worst severity per category."""
    scans = [s.id for s in baselines(project).values()]
    vulns = Vulnerability.objects.filter(scan_history_id__in=scans, open_status=True, severity__gte=1,
                                         asset__in=scored_assets(project))
    if asset_ids is not None:
        vulns = vulns.filter(asset_id__in=asset_ids)
    out = {}
    for asset_id, template_id, name, severity in vulns.values_list('asset_id', 'template_id', 'name', 'severity'):
        category = template_id or name
        per_asset = out.setdefault(asset_id, {})
        per_asset[category] = max(severity, per_asset.get(category, severity))
    return out


def _score(categories):
    score = max(0, MAX_SCORE - sum(PENALTY.get(s, 0) for s in categories.values()))
    worst = max(categories.values(), default=0)
    return min(score, CEILING.get(worst, MAX_SCORE))


def _rows(value, categories):
    return [{'asset': value, 'issue': c, 'severity': SEVERITY_NAMES[s], 'points': PENALTY[s]}
            for c, s in sorted(categories.items(), key=lambda kv: (-kv[1], kv[0]))]


def asset_breakdown(asset):
    categories = _penalties(asset.project, [asset.id]).get(asset.id, {})
    score = _score(categories)
    return {'score': score, 'grade': grade(score), 'penalties': _rows(asset.value, categories)}


def p10(scores):
    """Nearest-rank 10th percentile: the weakest assets drive it, duplicating the estate does not."""
    if not scores:
        return None
    ordered = sorted(scores)
    return ordered[max(0, math.ceil(0.10 * len(ordered)) - 1)]


def coverage(project, now=None):
    now = now or timezone.now()
    domains = list(_owned_domains(project).values_list('id', flat=True))
    if not domains:
        return None
    fresh = sum(1 for s in baselines(project).values() if s.start_scan_date >= now - COVERAGE_WINDOW)
    return fresh / len(domains)


def project_score(project):
    assets = dict(scored_assets(project).values_list('id', 'value'))
    penalties = _penalties(project)
    scores = [_score(penalties.get(a, {})) for a in assets]
    rows = [r for a, cats in penalties.items() if a in assets for r in _rows(assets[a], cats)]
    rows.sort(key=lambda r: (-r['points'], r['asset'], r['issue']))
    score = p10(scores)
    return {'version': VERSION, 'score': score, 'grade': grade(score), 'coverage': coverage(project),
            'asset_count': len(assets), 'top_penalties': rows[:TOP_PENALTIES]}


@app.task(name='snapshot_scores', bind=False)
def snapshot_scores():
    from dashboard.models import Project
    today = timezone.localdate()
    for project in Project.objects.all():
        s = project_score(project)
        ScoreSnapshot.objects.update_or_create(project=project, date=today, defaults={
            'version': s['version'], 'score': s['score'], 'grade': s['grade'], 'coverage': s['coverage'],
            'asset_count': s['asset_count'], 'top_penalties': s['top_penalties']})
    return {'projects': Project.objects.count()}
```

In `web/limes/settings.py`:
- set `CELERY_IMPORTS = ('limes.tasks', 'limes.reaper', 'limes.continuous', 'limes.scoring')`;
- add `    'snapshot-scores': {'task': 'snapshot_scores', 'schedule': 86400.0},` to `CELERY_BEAT_SCHEDULE`, after `age-assets`.

In `web/limes/celery_routing.py`, add `    'snapshot_scores': (ORCHESTRATE, 15 * MIN),` after the `'dispatch_due_scans': ...` line.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_scoring tests.core.test_vuln_link`, then `python3 manage.py makemigrations --check --dry-run`.
Expected: all OK, then `No changes detected`.

- [ ] **Step 5: Commit**

```bash
git add web/limes/scoring.py web/startScan/asset_models.py web/startScan/migrations/0018_scoresnapshot.py web/limes/settings.py web/limes/celery_routing.py web/tests/core/test_scoring.py
git commit -m "Score owned assets with the published limes-score-v1 model

950 minus one penalty per distinct issue from each root's latest
successful vulnerability stage, capped by the worst severity; the
project takes the P10 of its assets. A daily snapshot keeps the trend."
```

### Task 3: Score API and asset risk breakdown

**Files:**
- Modify: `web/api/views.py` (`AssetDatatableViewSet.retrieve`, new `AssetScore`)
- Modify: `web/api/urls.py` (route; **CRLF**)
- Test: `web/tests/core/test_asset_api.py`

**Interfaces:**
- Consumes: `scoring.project_score`, `scoring.asset_breakdown` and `scoring.scored_assets` from Task 2.
- Produces:
  - `GET /api/asset_score/?project=<slug>` returns `project_score(...)` plus `history` (up to 30 snapshots of `date`, `score`, `grade` and `version`), or a 404;
  - asset retrieve JSON gains `risk`: an `asset_breakdown(...)` or `null`.

- [ ] **Step 1: Write the failing tests**

Append to `web/tests/core/test_asset_api.py`:

```python
class AssetScoreApiTest(TestCase):
    def setUp(self):
        from datetime import timedelta
        from limes.definitions import SUCCESS_TASK
        from scanEngine.models import EngineType
        from startScan.models import ScanActivity, ScanHistory, Vulnerability
        from targetApp.models import Domain
        self.user = User.objects.create_user('u5', password='p')
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.c = APIClient()
        self.c.force_login(self.user)
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        domain = Domain.objects.create(project=self.p, name='x.com', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.host = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.cand = Asset.objects.create(project=self.p, kind='root_domain', value='c.com', scope_tier='candidate')
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='e', yaml_configuration='{}'),
                                          start_scan_date=timezone.now() - timedelta(hours=1))
        ScanActivity.objects.create(scan_of=scan, name='vulnerability_scan', title='v', time=timezone.now(), status=SUCCESS_TASK)
        Vulnerability.objects.create(scan_history=scan, asset=self.host, name='<img src=x onerror=alert(1)>', severity=3,
                                     http_url='https://a.x.com/')

    def test_project_score(self):
        r = self.c.get('/api/asset_score/', {'project': 'p1'})
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual((d['score'], d['grade'], d['version'], d['coverage'], d['asset_count']), (799, 'B', 'limes-score-v1', 1.0, 2))
        self.assertEqual(d['top_penalties'][0]['issue'], '<img src=x onerror=alert(1)>')
        self.assertEqual(d['history'], [])

    def test_unknown_project_is_404(self):
        self.assertEqual(self.c.get('/api/asset_score/', {'project': 'nope'}).status_code, 404)
        self.assertEqual(self.c.get('/api/asset_score/').status_code, 404)

    def test_requires_login(self):
        self.assertNotEqual(APIClient().get('/api/asset_score/', {'project': 'p1'}).status_code, 200)

    def test_retrieve_carries_risk_list_does_not(self):
        one = self.c.get(f'/api/listDatatableAsset/{self.host.id}/', {'project': 'p1'}).json()
        self.assertEqual((one['risk']['score'], one['risk']['grade']), (799, 'B'))
        self.assertIsNone(self.c.get(f'/api/listDatatableAsset/{self.cand.id}/', {'project': 'p1'}).json()['risk'])
        rows = self.c.get('/api/listDatatableAsset/', {'project': 'p1', 'no_page': '1'}).json()
        self.assertTrue(all('risk' not in r for r in rows))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_asset_api.AssetScoreApiTest`
Expected:
- the score endpoint tests fail, because the route doesn't exist;
- `test_retrieve_carries_risk_list_does_not` errors with `KeyError: 'risk'`;
- `test_requires_login` may already pass, and should.

- [ ] **Step 3: Implement**

In `web/api/views.py`, inside `class AssetDatatableViewSet`, add directly above its `def paginate_queryset` (there are several `paginate_queryset` methods in this file; use the one in this class):

```python
	def retrieve(self, request, *args, **kwargs):
		# Risk is computed on retrieve only: scoring every row of a list page would be N+1.
		from limes import scoring
		asset = self.get_object()
		data = self.get_serializer(asset).data
		scored = scoring.scored_assets(asset.project).filter(pk=asset.pk).exists()
		data['risk'] = scoring.asset_breakdown(asset) if scored else None
		return Response(data)
```

Add this class directly above `class AddTarget(APIView):`:

```python
class AssetScore(APIView):
	"""Project risk score (limes.scoring) with its last 30 daily snapshots."""

	def get(self, request):
		from limes import scoring
		project = Project.objects.filter(slug=request.query_params.get('project') or '').first()
		if not project:
			return Response({'status': False, 'message': 'project not found'}, status=404)
		data = scoring.project_score(project)
		data['history'] = list(project.score_snapshots.order_by('-date')
							   .values('date', 'score', 'grade', 'version')[:30])
		return Response(data)
```

In `web/api/urls.py`, add after the `action/asset/cadence/` line, keeping `\r\n`:

```python
    path('asset_score/', AssetScore.as_view(), name='asset_score'),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_asset_api tests.core.test_scoring`
Expected: all OK.

- [ ] **Step 5: Commit**

```bash
git add web/api/views.py web/api/urls.py web/tests/core/test_asset_api.py
git commit -m "Expose the project score and each asset's risk breakdown"
```

### Task 4: Score card and modal risk section

**Files:**
- Modify: `web/static/custom/asset.js`
- Modify: `web/startScan/templates/startScan/assets.html`

**Interfaces:**
- Consumes: `GET /api/asset_score/` and the retrieve `risk` from Task 3.

- [ ] **Step 1: Implement**

In `web/static/custom/asset.js`, add directly above `function asset_confidence_html(a) {`:

```javascript
function asset_penalty_rows(rows, withAsset) {
	return (rows || []).map(function(r) {
		return '<tr>' + (withAsset ? '<td>' + asset_esc(r.asset) + '</td>' : '') + '<td>' + asset_esc(r.issue) +
			'</td><td>' + asset_esc(r.severity) + '</td><td>-' + asset_esc(r.points) + '</td></tr>';
	}).join('');
}

// Risk section of the asset modal (limes.scoring); null for assets that are not scored.
function asset_risk_html(risk) {
	if (!risk) return '';
	var rows = asset_penalty_rows(risk.penalties, false);
	return '<h5>Risk ' + asset_esc(risk.score) + ' <span class="badge bg-soft-primary text-primary">' + asset_esc(risk.grade) +
		'</span></h5>' + (rows ? '<table class="table table-sm"><thead><tr><th>Issue</th><th>Severity</th><th>Points</th></tr></thead><tbody>' +
		rows + '</tbody></table>' : '<p class="text-muted">No open findings in the latest vulnerability scan.</p>');
}

// Project score card above the Assets table.
function load_asset_score() {
	var box = document.getElementById('asset_score');
	fetch('/api/asset_score/?project=' + encodeURIComponent(asset_project()), {credentials: 'same-origin'})
		.then(function(r) { if (!r.ok) throw new Error('score'); return r.json(); })
		.then(function(s) {
			if (s.score === null) {
				box.innerHTML = '<p class="text-muted mb-0">No owned assets to score yet.</p>';
				return;
			}
			var cov = s.coverage === null ? 'n/a' : Math.round(Number(s.coverage) * 100) + '%';
			var rows = asset_penalty_rows(s.top_penalties, true);
			box.innerHTML = '<div class="d-flex align-items-baseline mb-1"><span class="h2 mb-0 me-2">' + asset_esc(s.score) +
				'</span><span class="badge bg-soft-primary text-primary me-3">' + asset_esc(s.grade) + '</span>' +
				'<small class="text-muted">' + asset_esc(cov) + ' of owned roots scanned for vulnerabilities in 30 days &middot; ' +
				asset_esc(s.version) + '</small></div>' + (rows ? '<table class="table table-sm mb-0"><thead><tr><th>Asset</th>' +
				'<th>Issue</th><th>Severity</th><th>Points</th></tr></thead><tbody>' + rows + '</tbody></table>' : '');
		}).catch(function() {
			box.innerHTML = '<p class="text-muted mb-0">Score unavailable.</p>';
		});
}
```

In `get_asset_modal`, change

```javascript
				'<h5>Why is this mine</h5><p>' + path + '</p>' + asset_confidence_html(a) +
```

so that it starts with `asset_risk_html(a.risk) + `:

```javascript
				asset_risk_html(a.risk) + '<h5>Why is this mine</h5><p>' + path + '</p>' + asset_confidence_html(a) +
```

The real line has 3 leading tabs; match on its text.

In `web/startScan/templates/startScan/assets.html`, add `<div id="asset_score" class="mb-3"></div>` directly after the header `</div>` that closes the "Assets / Add assets" row. Then add `load_asset_score();` as the first line inside `$(document).ready(function() {`.

- [ ] **Step 2: Verify in the real UI**

Run `node --check web/static/custom/asset.js`, then migrate the dev database and restart the dev server.

Seed a project with:
- an owned root that has a `Domain`;
- a scan with a successful `vulnerability_scan` activity;
- a high finding named `<img src=x onerror=alert(1)>` on an owned hostname.

Open the Assets page. Expected:
- the card shows `799`, `B`, the coverage percentage and the model version, with the finding's name as literal text: no image element, and no dialog;
- opening the hostname's modal shows "Risk 799 B" with that penalty row;
- a project with no owned assets shows "No owned assets to score yet.";
- there are no console errors.

- [ ] **Step 3: Commit**

```bash
git add web/static/custom/asset.js web/startScan/templates/startScan/assets.html
git commit -m "Show the project score card and each asset's risk"
```
