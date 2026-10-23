from datetime import timedelta

from django.contrib.auth.models import User
from django.db import connection
from django.test.utils import CaptureQueriesContext, override_settings

from dashboard import activity
from dashboard.stats import _live_issues
from limes import waivers
from startScan.models import Asset, IssueWaiver, ScoreSnapshot, TrackedIssue
from tests.core.test_scoring import Base

HOSTILE = '<img src=x onerror=alert(1)>'


def days(n):
    return timedelta(days=n)


class ActivityBase(Base):
    def issue(self, asset, key, severity, first=0, status='open', fixed=None, reopened=None, source=None):
        return TrackedIssue.objects.create(
            project=asset.project, asset=asset, key=key, severity=severity, status=status, source=source or 'finding',
            first_seen=self.now - days(first), fixed_at=self.now - days(fixed) if fixed is not None else None,
            reopened=1 if reopened is not None else 0, reopened_at=self.now - days(reopened) if reopened is not None else None)

    def waive(self, issue):
        IssueWaiver.objects.create(issue=issue, kind='accepted_risk', reason='r')

    def queries(self, fn):
        with CaptureQueriesContext(connection) as ctx:
            fn()
        return len(ctx)


class RemediationTest(ActivityBase):
    def test_remediation_windows(self):
        a = self.host('a.x.com')
        self.issue(a, 'f3', 2, first=90, status='fixed', fixed=3)
        self.issue(a, 'f20', 2, first=90, status='fixed', fixed=20)
        self.issue(a, 'f40', 2, first=90, status='fixed', fixed=40)
        self.issue(a, 'new2', 2, first=2)
        self.issue(a, 'back', 3, first=60, reopened=5)
        self.issue(a, 'crit', 4, first=50)
        self.issue(a, 'med', 2, first=80)
        self.waive(self.issue(a, 'waived', 4, first=70))
        r = activity.remediation(self.p, self.now)
        self.assertEqual((r['fixed_7'], r['fixed_30']), (1, 2))
        # opened: new2, back (reopened), crit (50d: not in 30), so 7 -> new2+back; 30 -> same
        self.assertEqual((r['opened_7'], r['opened_30']), (2, 2))
        self.assertEqual([(o['title'], o['age_days'], o['reopened'], o['severity']) for o in r['oldest']],
                         [('crit', 50, False, 'critical'), ('back', 5, True, 'high')])

    def test_oldest_limit_and_empty(self):
        self.assertEqual(activity.remediation(self.p, self.now),
                         {'fixed_7': 0, 'fixed_30': 0, 'opened_7': 0, 'opened_30': 0, 'oldest': []})
        a = self.host('a.x.com')
        for i in range(8):
            self.issue(a, f'k{i}', 3, first=i + 1)
        oldest = activity.remediation(self.p, self.now)['oldest']
        self.assertEqual([o['age_days'] for o in oldest], [8, 7, 6, 5, 4])

    def test_other_project_excluded_and_hostile_name_is_data(self):
        a = self.host(HOSTILE)
        self.issue(a, HOSTILE, 4, first=3)
        other = self.host('o.y.com', project=self._other())
        self.issue(other, 'zz', 4, first=3)
        r = activity.remediation(self.p, self.now)
        self.assertEqual([(o['asset'], o['title']) for o in r['oldest']], [(HOSTILE, HOSTILE)])

    def _other(self):
        from dashboard.models import Project
        from django.utils import timezone
        return Project.objects.create(name='q', slug='q', insert_date=timezone.now())


class TopRisksTest(ActivityBase):
    def live(self):
        return _live_issues(self.p)

    def test_top_risks_cost_order(self):
        a, b = self.host('a.x.com'), self.host('b.x.com')
        s = self.scan()
        self.vuln(s, a, 4, template='crit')
        self.vuln(s, a, 3, template='hi-old')
        self.vuln(s, b, 3, template='hi-new')
        self.vuln(s, b, 3, template='hi-waived')
        self.issue(a, 'crit', 4, first=1)
        self.issue(a, 'hi-old', 3, first=40)
        self.issue(b, 'hi-new', 3, first=2)
        self.waive(self.issue(b, 'hi-waived', 3, first=90))
        rows = activity.top_risks(self.p, self.live(), self.now)
        self.assertEqual([(r['key'], r['points'], r['severity']) for r in rows],
                         [('crit', 200, 'critical'), ('hi-old', 80, 'high'), ('hi-new', 80, 'high')])
        self.assertEqual(rows[1]['age_days'], 40)
        self.assertEqual(rows[0]['category'], 'vulnerabilities')

    def test_check_title_category_and_untracked(self):
        from limes.checks.catalogue import CHECKS
        from startScan.models import RiskCheck
        a = self.host('a.x.com')
        RiskCheck.objects.create(asset=a, check_id='web.hsts_missing', status='fail',
                                 severity=CHECKS['web.hsts_missing'].severity, last_checked=self.now)
        rows = activity.top_risks(self.p, self.live(), self.now)
        (r,) = rows
        self.assertEqual((r['title'], r['category'], r['id'], r['detected_at'], r['age_days']),
                         (CHECKS['web.hsts_missing'].title, 'web', None, None, None))

    def test_limit_ten_and_empty(self):
        self.assertEqual(activity.top_risks(self.p, {}, self.now), [])
        a = self.host('a.x.com')
        s = self.scan()
        for i in range(12):
            self.vuln(s, a, 2, template=f't{i:02d}')
        self.assertEqual(len(activity.top_risks(self.p, self.live(), self.now)), 10)

    def test_hostile_names_pass_through(self):
        a = self.host('a.x.com')
        self.vuln(self.scan(), a, 3, template=HOSTILE)
        (r,) = activity.top_risks(self.p, self.live(), self.now)
        self.assertEqual((r['asset'], r['key'], r['title']), ('a.x.com', HOSTILE, HOSTILE))


class WhatChangedTest(ActivityBase):
    def test_what_changed_windows(self):
        self.root.delete()
        Asset.objects.create(project=self.p, kind='hostname', value='n10.x.com', scope_tier='owned_host', first_seen=self.now - days(10))
        Asset.objects.create(project=self.p, kind='hostname', value='n60.x.com', scope_tier='owned_host', first_seen=self.now - days(60))
        Asset.objects.create(project=self.p, kind='hostname', value='gone.x.com', scope_tier='owned_host', state='missing',
                             first_seen=self.now - days(200), last_seen=self.now - days(20))
        Asset.objects.create(project=self.p, kind='hostname', value='old-gone.x.com', scope_tier='owned_host', state='retired',
                             first_seen=self.now - days(200), last_seen=self.now - days(60))
        Asset.objects.create(project=self.p, kind='hostname', value='cand.x.com', scope_tier='candidate', first_seen=self.now - days(1))
        a = Asset.objects.get(value='n10.x.com')
        self.issue(a, 'i5', 2, first=5)
        self.issue(a, 'i50', 2, first=50)
        self.issue(a, 'r', 2, first=100, status='fixed', fixed=15)
        today = self.now.date()
        ScoreSnapshot.objects.create(project=self.p, date=today - days(31), version='v', grade='B', score=700)
        ScoreSnapshot.objects.create(project=self.p, date=today - days(91), version='v', grade='B', score=600)
        w30, w90 = activity.what_changed(self.p, self.now, 765)
        self.assertEqual((w30['days'], w90['days']), (30, 90))
        self.assertEqual((w30['new_assets'], w90['new_assets']), (1, 2))
        self.assertEqual(w30['new_sample'], ['n10.x.com'])
        self.assertEqual((w30['removed_assets'], w90['removed_assets']), (1, 2))
        self.assertEqual(w30['removed_sample'], ['gone.x.com'])
        self.assertEqual((w30['introduced'], w90['introduced']), (1, 2))
        self.assertEqual((w30['resolved'], w90['resolved']), (1, 1))
        self.assertEqual((w30['score_from'], w30['score_to'], w30['score_delta']), (700, 765, 65))
        self.assertEqual((w90['score_from'], w90['score_delta']), (600, 165))

    def test_no_snapshot_or_score(self):
        self.root.delete()
        w30, _ = activity.what_changed(self.p, self.now, 765)
        self.assertEqual((w30['score_from'], w30['score_to'], w30['score_delta']), (None, 765, None))
        w30, _ = activity.what_changed(self.p, self.now, None)
        self.assertEqual((w30['score_to'], w30['score_delta']), (None, None))
        self.assertEqual((w30['new_sample'], w30['removed_sample']), ([], []))

    def test_samples_capped_and_hostile(self):
        self.root.delete()
        for i in range(7):
            self.host(f'h{i}.x.com')
        w30, _ = activity.what_changed(self.p, self.now, None)
        self.assertEqual((w30['new_assets'], w30['new_sample']), (7, [f'h{i}.x.com' for i in range(5)]))
        Asset.objects.exclude(value=HOSTILE).delete()
        self.host(HOSTILE)
        w30, _ = activity.what_changed(self.p, self.now, None)
        self.assertEqual(w30['new_sample'], [HOSTILE])  # passes through unmodified


class DiscoveryTest(ActivityBase):
    def src(self, value, *names, **kw):
        return Asset.objects.create(project=self.p, kind='hostname', value=value, scope_tier=kw.pop('tier', 'owned_host'),
                                    sources=[{'source': n} for n in names], **kw)

    def test_discovery_by_source(self):
        self.root.delete()
        user = User.objects.create(username='u')
        self.src('a.x.com', 'crtsh')
        self.src('b.x.com', 'dns')
        self.src('c.x.com', 'crtsh', 'internetdb')
        self.src('d.x.com', 'cidr')
        self.src('e.x.com', added_by=user)
        self.src('f.x.com')
        self.src('cand.x.com', 'crtsh', tier='candidate')
        self.src('ret.x.com', 'crtsh', state='retired')
        d = activity.discovery(self.p)
        got = {r['label']: (r['count'], r['filter'], r['name']) for r in d['rows']}
        self.assertEqual(got, {'CT': (2, 'CT', 'Certificate transparency'), 'scan': (1, 'scan', 'Scan'),
                               'InternetDB': (1, 'InternetDB', 'Passive intel (InternetDB)'), 'CIDR': (1, 'CIDR', 'IP range'),
                               'manual': (1, 'manual', 'Added by hand'), 'target': (1, None, 'Scan target')})
        self.assertEqual(d['total'], 6)
        self.assertEqual(d['rows'][0]['label'], 'CT')

    def test_empty(self):
        self.root.delete()
        self.assertEqual(activity.discovery(self.p), {'rows': [], 'total': 0})


@override_settings(RANGE_ENUMERATION=True)
class CoverageTest(ActivityBase):
    def mon(self, value, ago, active=False, **kw):
        return Asset.objects.create(project=self.p, kind='hostname', value=value, scope_tier='owned_host',
                                    last_resolved_at=self.now - ago if ago is not None else None,
                                    enrichment={'monitor': {'active': active}}, **kw)

    def test_coverage_states(self):
        self.root.delete()
        ok = self.mon('ok.x.com', timedelta(hours=1), active=True)
        late = self.mon('late.x.com', days(3), active=True)
        never = self.mon('never.x.com', None)
        self.mon('off.x.com', None, cadence_tier='off')
        rng = Asset.objects.create(project=self.p, kind='cidr', value='198.51.100.0/24', scope_tier='owned_root')
        Asset.objects.create(project=self.p, kind='ip', value='198.51.100.7', scope_tier='owned_host', parent=rng)
        c = activity.coverage(self.p, self.now)
        self.assertEqual({k: c[k] for k in ('on_time', 'overdue', 'never', 'stopped', 'range_swept')},
                         {'on_time': 1, 'overdue': 1, 'never': 1, 'stopped': 1, 'range_swept': 1})
        self.assertEqual(c['total'], 5)
        self.assertEqual(c['oldest'], {'value': 'never.x.com', 'last_checked': None, 'why': 'never'})
        never.delete()
        c = activity.coverage(self.p, self.now)
        self.assertEqual((c['oldest']['value'], c['oldest']['why']), ('late.x.com', 'overdue'))
        self.assertEqual(c['oldest']['last_checked'], late.last_resolved_at)
        ok.delete()
        late.delete()

    def test_empty(self):
        self.root.delete()
        self.assertEqual(activity.coverage(self.p, self.now),
                         {'total': 0, 'on_time': 0, 'overdue': 0, 'never': 0, 'stopped': 0, 'range_swept': 0, 'oldest': None})

    def test_hostile_name(self):
        self.root.delete()
        self.mon(HOSTILE, None)
        self.assertEqual(activity.coverage(self.p, self.now)['oldest']['value'], HOSTILE)


class QueryCountTest(ActivityBase):
    def populate(self, n):
        rng = Asset.objects.create(project=self.p, kind='cidr', value=f'198.51.{n}.0/24', scope_tier='owned_root')
        s = self.scan()
        for i in range(n):
            a = Asset.objects.create(project=self.p, kind='hostname', value=f'h{n}-{i}.x.com', scope_tier='owned_host',
                                     parent=rng if i % 3 == 0 else self.root, sources=[{'source': 'crtsh'}],
                                     last_resolved_at=self.now - days(i), enrichment={'monitor': {'active': True}})
            self.vuln(s, a, 3, template=f'v{n}-{i}')
            self.issue(a, f'v{n}-{i}', 3, first=i + 1)

    def run_all(self):
        live = _live_issues(self.p)
        activity.remediation(self.p, self.now)
        activity.top_risks(self.p, live, self.now)
        activity.what_changed(self.p, self.now, 700)
        activity.discovery(self.p)
        activity.coverage(self.p, self.now)

    @override_settings(RANGE_ENUMERATION=True)
    def test_activity_queries_do_not_scale(self):
        self.populate(3)
        small = self.queries(self.run_all)
        self.populate(30)
        self.assertEqual(self.queries(self.run_all), small)
