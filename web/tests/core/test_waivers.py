from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes import waivers
from startScan.models import Asset, TrackedIssue


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
