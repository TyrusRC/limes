from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.conf import settings
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard.models import Project
from limes import celery_routing, scoring, waivers
from limes.alerts import events, issues, waiver_tasks
from startScan.models import Asset, ChangeEvent, IssueWaiver, ScoreSnapshot, TrackedIssue, Vulnerability
from tests.core.test_scoring import Base as ScoringBase


class WaiverRulesTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.issue = TrackedIssue.objects.create(project=self.p, asset=a, key='k', source='finding', severity=3)
        self.u1 = User.objects.create(username='u1')
        self.u2 = User.objects.create(username='u2')
        self.now = timezone.now()

    def test_accepted_risk_defaults_to_90_days(self):
        w = waivers.create_waiver(self.issue, 'accepted_risk', 'ok', self.u1, now=self.now)
        self.assertEqual(w.expires_at, self.now + timedelta(days=90))
        self.assertEqual(w.created_by, self.u1)

    def test_validation(self):
        now = self.now
        cases = [
            ('nope', 'r', None),
            ('accepted_risk', '', None),
            ('accepted_risk', '   ', None),
            ('false_positive', 'x' * 5001, None),
            ('accepted_risk', 'r', now - timedelta(minutes=1)),
            ('accepted_risk', 'r', now + timedelta(days=366)),
            ('false_positive', 'r', now + timedelta(days=366)),
        ]
        for kind, reason, exp in cases:
            with self.subTest(kind=kind, reason=reason[:5], exp=exp):
                with self.assertRaises(waivers.WaiverError):
                    waivers.create_waiver(self.issue, kind, reason, self.u1, expires_at=exp, now=now)
        self.assertEqual(self.issue.waivers.count(), 0)
        w = waivers.create_waiver(self.issue, 'false_positive', 'fp', self.u1, now=now)
        self.assertIsNone(w.expires_at)

    def test_new_waiver_revokes_previous(self):
        w1 = waivers.create_waiver(self.issue, 'accepted_risk', 'a', self.u1, now=self.now)
        w2 = waivers.create_waiver(self.issue, 'false_positive', 'b', self.u2, now=self.now)
        w1.refresh_from_db()
        self.assertEqual(w1.revoked_at, self.now)
        self.assertEqual(w1.revoked_by, self.u2)
        self.assertEqual(waivers.active_waiver(self.issue, now=self.now), w2)
        self.assertEqual(self.issue.waivers.filter(revoked_at__isnull=True).count(), 1)

    def test_active_respects_expiry_and_revocation(self):
        exp = self.now + timedelta(days=5)
        waivers.create_waiver(self.issue, 'accepted_risk', 'a', self.u1, expires_at=exp, now=self.now)
        self.assertIsNotNone(waivers.active_waiver(self.issue, now=exp - timedelta(seconds=1)))
        self.assertIsNone(waivers.active_waiver(self.issue, now=exp))
        self.assertTrue(waivers.revoke_waiver(self.issue, self.u2, now=self.now))
        self.assertIsNone(waivers.active_waiver(self.issue, now=self.now))
        self.assertFalse(waivers.revoke_waiver(self.issue, self.u2, now=self.now))

    def test_notes(self):
        n = waivers.add_note(self.issue, self.u1, 'hello')
        self.assertEqual((n.author, n.text), (self.u1, 'hello'))
        for bad in ('', '  ', 'x' * 5001):
            with self.assertRaises(waivers.WaiverError):
                waivers.add_note(self.issue, self.u1, bad)


class ScoreV3Test(ScoringBase):
    def setUp(self):
        super().setUp()
        self.user = User.objects.create(username='u')
        self.scan_ = self.scan()
        self.host_ = self.host('a.x.com')

    def issue(self, key='t1', sev=3, asset=None):
        return TrackedIssue.objects.create(project=self.p, asset=asset or self.host_, key=key, source='finding', severity=sev)

    def test_waiver_excludes_penalty_from_adjusted_score_only(self):
        self.vuln(self.scan_, self.host_, 3)
        issue = self.issue()
        s = scoring.project_score(self.p)
        self.assertEqual((s['score'], s['raw_score']), (799, 799))
        waivers.create_waiver(issue, 'accepted_risk', 'ok', self.user)
        s = scoring.project_score(self.p)
        self.assertEqual((s['score'], s['raw_score'], s['waived_count'], s['version']), (950, 799, 1, 'limes-score-v3'))
        b = scoring.asset_breakdown(self.host_)
        self.assertEqual(b['score'], 950)
        self.assertTrue(b['penalties'][0]['waived'])

    def test_waiver_expiry_restores_penalty_at_expires_at(self):
        self.vuln(self.scan_, self.host_, 3)
        exp = self.now + timedelta(days=5)
        waivers.create_waiver(self.issue(), 'accepted_risk', 'ok', self.user, expires_at=exp, now=self.now)
        self.assertEqual(scoring.project_score(self.p, now=exp - timedelta(seconds=1))['score'], 950)
        self.assertEqual(scoring.project_score(self.p, now=exp)['score'], 799)

    def test_false_positive_without_expiry_stays_waived(self):
        self.vuln(self.scan_, self.host_, 3)
        waivers.create_waiver(self.issue(), 'false_positive', 'fp', self.user)
        self.assertEqual(scoring.project_score(self.p, now=self.now + timedelta(days=3000))['score'], 950)

    def test_long_key_waiver_matches(self):
        name = 'n' * 400
        Vulnerability.objects.create(scan_history=self.scan_, asset=self.host_, name=name, template_id='',
                                     severity=3, http_url='https://h/', open_status=True)
        self.assertEqual(scoring.project_score(self.p)['score'], 799)
        waivers.create_waiver(self.issue(key=scoring.issue_key(name)), 'accepted_risk', 'ok', self.user)
        self.assertEqual(scoring.project_score(self.p)['score'], 950)

    def test_forecast(self):
        self.vuln(self.scan_, self.host_, 3, template='t1')
        self.vuln(self.scan_, self.host_, 2, template='t2')
        high, med = self.issue('t1', 3), self.issue('t2', 2)
        cur = scoring.project_score(self.p)['score']
        self.assertEqual(cur, 799)
        f = scoring.forecast(self.p, [high.id])
        self.assertEqual((f['score'], f['delta'], f['grade']), (925, 925 - cur, 'A'))
        other = Project.objects.create(name='o', slug='o', insert_date=timezone.now())
        foreign = TrackedIssue.objects.create(project=other, asset=Asset.objects.create(
            project=other, kind='hostname', value='b.o.com', scope_tier='owned_host'), key='t1', source='finding', severity=3)
        self.assertEqual(scoring.forecast(self.p, [999999, foreign.id])['delta'], 0)
        waivers.create_waiver(high, 'accepted_risk', 'ok', self.user)
        cur = scoring.project_score(self.p)['score']
        self.assertEqual(scoring.forecast(self.p, [high.id])['delta'], 0)
        self.assertEqual(scoring.forecast(self.p, [med.id, high.id])['delta'], 950 - cur)

    def test_snapshot_stores_raw_score(self):
        self.vuln(self.scan_, self.host_, 3)
        waivers.create_waiver(self.issue(), 'accepted_risk', 'ok', self.user)
        scoring.snapshot_scores()
        snap = ScoreSnapshot.objects.get(project=self.p)
        self.assertEqual((snap.score, snap.raw_score), (950, 799))


class WaiverAlertsTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.u = User.objects.create(username='u')
        self.now = timezone.now()

    def sync(self, issues_):
        with mock.patch('limes.scoring.current_issues', return_value=(issues_, {self.a.id})):
            return issues.sync_issues(self.p)

    def issue(self, sev=3, status='open'):
        return TrackedIssue.objects.create(project=self.p, asset=self.a, key='k', source='finding', severity=sev, status=status)

    def expired(self, issue, **kw):
        w = waivers.create_waiver(issue, 'accepted_risk', 'r', self.u, now=self.now - timedelta(days=10),
                                  expires_at=self.now - timedelta(days=10) + timedelta(days=5))
        if kw:
            IssueWaiver.objects.filter(pk=w.pk).update(**kw)
        return w

    def test_rules(self):
        self.assertTrue(events.is_immediate('waiver_expired', 'k', 3))
        self.assertFalse(events.is_immediate('waiver_expired', 'k', 2))

    def test_waived_issue_does_not_alert(self):
        self.sync({self.a.id: {'k': 3}})
        issue = TrackedIssue.objects.get(key='k')
        waivers.create_waiver(issue, 'accepted_risk', 'ok', self.u)
        self.assertEqual(self.sync({self.a.id: {'k': 4}}), [])
        self.assertEqual([e.kind for e in self.sync({})], ['issue_fixed'])
        self.assertEqual(self.sync({self.a.id: {'k': 4}}), [])
        issue.refresh_from_db()
        self.assertEqual((issue.status, issue.reopened), ('open', 1))

    def test_expired_waiver_alerts_again(self):
        self.sync({self.a.id: {'k': 3}})
        self.expired(TrackedIssue.objects.get(key='k'))
        self.assertEqual([e.kind for e in self.sync({self.a.id: {'k': 4}})], ['issue_new'])

    def test_expire_waivers_announces_once(self):
        issue = self.issue()
        self.expired(issue)
        self.assertEqual(waiver_tasks.expire_waivers(now=self.now), {'expired': 1})
        e = ChangeEvent.objects.get(kind='waiver_expired')
        self.assertTrue(e.immediate)
        self.assertEqual(waiver_tasks.expire_waivers(now=self.now), {'expired': 0})
        self.assertEqual(ChangeEvent.objects.filter(kind='waiver_expired').count(), 1)

    def test_expire_waivers_skips_revoked_and_unexpired(self):
        self.expired(self.issue(), revoked_at=self.now)
        other = TrackedIssue.objects.create(project=self.p, asset=self.a, key='k2', source='finding', severity=3)
        waivers.create_waiver(other, 'accepted_risk', 'r', self.u, now=self.now)
        self.assertEqual(waiver_tasks.expire_waivers(now=self.now), {'expired': 0})
        self.assertFalse(ChangeEvent.objects.exists())

    def test_low_severity_expiry_is_digest_only(self):
        self.expired(self.issue(sev=2))
        waiver_tasks.expire_waivers(now=self.now)
        self.assertFalse(ChangeEvent.objects.get(kind='waiver_expired').immediate)

    def test_new_waiver_keeps_expired_one_announceable(self):
        issue = self.issue()
        old = self.expired(issue)
        waivers.create_waiver(issue, 'accepted_risk', 'again', self.u, now=self.now)
        old.refresh_from_db()
        self.assertIsNone(old.revoked_at)
        self.assertEqual(waiver_tasks.expire_waivers(now=self.now), {'expired': 1})
        self.assertEqual(waiver_tasks.expire_waivers(now=self.now), {'expired': 0})

    def test_beat_and_routing(self):
        self.assertEqual(settings.CELERY_BEAT_SCHEDULE['expire-waivers']['task'], 'expire_waivers')
        self.assertEqual(settings.CELERY_BEAT_SCHEDULE['expire-waivers']['schedule'], 86400.0)
        self.assertEqual(celery_routing.TASK_PLAN['expire_waivers'], (celery_routing.ORCHESTRATE, 15 * celery_routing.MIN))
        self.assertIn('limes.alerts.waiver_tasks', settings.CELERY_IMPORTS)
