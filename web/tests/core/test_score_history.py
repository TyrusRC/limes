from datetime import timedelta

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from dashboard import activity
from dashboard.models import Project
from dashboard.views import on_user_logged_in
from startScan.models import Asset, ScoreSnapshot, TrackedIssue


class ScoreHistoryApiTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.c = APIClient()
        self.c.force_login(User.objects.create_user('u', password='p'))
        self.now = timezone.now()
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=self.now)
        self.q = Project.objects.create(name='p2', slug='p2', insert_date=self.now)
        today = timezone.localdate()
        for days, score in ((400, 300), (200, 500), (80, 600), (20, 700), (1, 720)):
            ScoreSnapshot.objects.create(project=self.p, date=today - timedelta(days=days), version='limes-score-v3', score=score, grade='B')
        ScoreSnapshot.objects.create(project=self.q, date=today - timedelta(days=5), version='limes-score-v3', score=111, grade='F')
        old = Asset.objects.create(project=self.p, kind='hostname', value='old.x.com', scope_tier='owned_host')
        Asset.objects.filter(pk=old.pk).update(first_seen=self.now - timedelta(days=150))
        new = Asset.objects.create(project=self.p, kind='hostname', value='new.x.com', scope_tier='owned_host')
        TrackedIssue.objects.create(project=self.p, asset=new, key='web.hsts_missing', source='check', severity=2,
                                    first_seen=self.now - timedelta(days=10))
        TrackedIssue.objects.create(project=self.p, asset=old, key='web.csp_missing', source='check', severity=1, status='fixed',
                                    first_seen=self.now - timedelta(days=200), fixed_at=self.now - timedelta(days=100))

    def get(self, **q):
        q.setdefault('project', 'p1')
        return self.c.get('/api/score_history/', q)

    def test_ranges_select_the_snapshots_inside_them(self):
        scores = lambda d: [p['score'] for p in self.get(days=d).json()['series'] if p['score'] is not None]
        self.assertEqual(scores(30)[:2], [700, 720])
        self.assertEqual(scores(90)[:3], [600, 700, 720])
        self.assertEqual(scores(365)[:4], [500, 600, 700, 720])  # the 400-day-old snapshot is out of range

    def test_change_panel_follows_the_range(self):
        ch = lambda d: self.get(days=d).json()['change']
        self.assertEqual((ch(30)['new_assets'], ch(30)['introduced'], ch(30)['resolved']), (1, 1, 0))
        self.assertEqual((ch(90)['new_assets'], ch(90)['resolved']), (1, 0))
        self.assertEqual((ch(365)['new_assets'], ch(365)['introduced'], ch(365)['resolved']), (2, 2, 1))
        self.assertEqual(ch(365)['days'], 365)

    def test_default_is_30_days_and_bad_values_are_400(self):
        self.assertEqual(self.get().json()['days'], 30)
        for bad in ('7', 'abc', '', '-1', '365 '):
            self.assertEqual(self.get(days=bad).status_code, 400, bad)

    def test_project_scoping(self):
        self.assertEqual(self.get(project='nope').status_code, 404)
        self.assertEqual(self.c.get('/api/score_history/').status_code, 404)
        for p in self.get(days=30).json()['series']:
            self.assertNotEqual(p['score'], 111)

    def test_requires_login(self):
        self.assertNotEqual(APIClient().get('/api/score_history/', {'project': 'p1'}).status_code, 200)


class WindowRefactorTest(TestCase):
    def test_what_changed_still_returns_both_windows(self):
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        out = activity.what_changed(p, timezone.now(), None)
        self.assertEqual([w['days'] for w in out], [30, 90])
