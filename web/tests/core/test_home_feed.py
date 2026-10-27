from datetime import timedelta

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from dashboard import home
from dashboard.models import FeedDismissal, InAppNotification, Project
from dashboard.views import on_user_logged_in
from startScan.models import Asset, ChangeEvent, IssueWaiver, TrackedIssue

X = '<img src=x onerror=alert(1)>'
ESC = '&lt;img src=x onerror=alert(1)&gt;'


class HomeBase(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.now = timezone.now()
        self.u = User.objects.create_user('u', password='p')
        self.v = User.objects.create_user('v', password='p')
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=self.now)
        self.q = Project.objects.create(name='p2', slug='p2', insert_date=self.now)
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.o = Asset.objects.create(project=self.q, kind='hostname', value='o.y.com', scope_tier='owned_host')

    def event(self, project=None, title='New asset a.x.com', kind='asset_new', days=0, **kw):
        return ChangeEvent.objects.create(project=project or self.p, kind=kind, title=title,
                                          created_at=self.now - timedelta(days=days), **kw)

    def issue(self, asset=None, key='web.hsts_missing', sev=3, days=1, source='check', **kw):
        return TrackedIssue.objects.create(project=asset.project if asset else self.p, asset=asset or self.a, key=key,
                                           source=source, severity=sev, first_seen=self.now - timedelta(days=days), **kw)

    def api(self, user):
        c = APIClient()
        c.force_login(user)
        return c


class FeedBuildTest(HomeBase):
    def test_activity_is_project_scoped_newest_first_and_recent(self):
        old = self.event(title='old', days=40)
        new = self.event(title='new', days=1)
        mid = self.event(title='mid', days=3)
        self.event(project=self.q, title='other project')
        feed = home.build(self.p, self.u, self.now)
        self.assertEqual([c['title'] for c in feed['activity']], ['new', 'mid'])
        self.assertEqual(feed['activity'][0]['key'], f'event:{new.id}')
        self.assertNotIn(f'event:{old.id}', [c['key'] for c in feed['activity']])

    def test_dismissal_is_per_user(self):
        e = self.event()
        FeedDismissal.objects.create(user=self.u, project=self.p, item=f'event:{e.id}')
        self.assertEqual(home.build(self.p, self.u, self.now)['activity'], [])
        self.assertEqual(len(home.build(self.p, self.v, self.now)['activity']), 1)

    def test_notices_for_this_project_or_the_whole_system_with_safe_links(self):
        mk = lambda **kw: InAppNotification.objects.create(description='d', icon='x', **kw)
        mk(title='system', notification_type='system', redirect_link='/scan/p1/issues')
        mk(title='mine', project=self.p, notification_type='project', redirect_link='javascript:alert(1)')
        mk(title='theirs', project=self.q, notification_type='project')
        cards = {c['title']: c for c in home.build(self.p, self.u, self.now)['activity']}
        self.assertEqual(set(cards), {'system', 'mine'})
        self.assertEqual(cards['system']['url'], '/scan/p1/issues')
        self.assertIsNone(cards['mine']['url'])  # an unsafe link is dropped, the card stays

    def test_tasks_expiring_waivers_new_serious_issues_and_candidates(self):
        soon = self.issue(key='web.csp_missing', sev=1, days=30)
        IssueWaiver.objects.create(issue=soon, kind='accepted_risk', reason='r', created_by=self.u, expires_at=self.now + timedelta(days=3))
        later = self.issue(key='web.frame_options_missing', sev=1, days=30)
        IssueWaiver.objects.create(issue=later, kind='accepted_risk', reason='r', created_by=self.u, expires_at=self.now + timedelta(days=60))
        fresh = self.issue(key='tls.cert_expired', sev=3, days=1)
        self.issue(key='web.version_disclosure', sev=1, days=1)                       # low: not a task
        self.issue(key='net.exposed_ollama', sev=3, days=1)                           # provisional: not scored
        self.issue(key='web.cookie_flags_missing', sev=4, days=40)                    # old
        waived = self.issue(key='web.https_missing', sev=4, days=1)
        IssueWaiver.objects.create(issue=waived, kind='false_positive', reason='r', created_by=self.u)
        self.issue(asset=self.o, key='tls.cert_expired', sev=4, days=1)               # other project
        cand = Asset.objects.create(project=self.p, kind='hostname', value='c.x.com', scope_tier='candidate')
        Asset.objects.create(project=self.p, kind='hostname', value='low.x.com', scope_tier='candidate', confidence=0.1)
        tasks = home.build(self.p, self.u, self.now)['tasks']
        self.assertEqual([c['key'] for c in tasks], [f'task:waiver:{soon.waivers.get().id}', f'task:issue:{fresh.id}', f'task:candidate:{cand.id}'])
        self.assertIn('3 days', tasks[0]['title'])

    def test_dismissed_task_is_gone(self):
        fresh = self.issue(key='tls.cert_expired', sev=3, days=1)
        FeedDismissal.objects.create(user=self.u, project=self.p, item=f'task:issue:{fresh.id}')
        self.assertEqual(home.build(self.p, self.u, self.now)['tasks'], [])

    def test_a_fixed_issue_is_not_a_task(self):
        self.issue(key='tls.cert_expired', sev=3, days=1, status='fixed')
        self.assertEqual(home.build(self.p, self.u, self.now)['tasks'], [])


class DismissApiTest(HomeBase):
    def dismiss(self, user, **body):
        body.setdefault('project', 'p1')
        return self.api(user).post('/api/action/feed/dismiss/', body, format='json')

    def test_dismiss_event_then_idempotent(self):
        e = self.event()
        r = self.dismiss(self.u, keys=[f'event:{e.id}'])
        self.assertEqual((r.status_code, r.json()['status'], r.json()['dismissed']), (200, True, 1))
        self.assertTrue(self.dismiss(self.u, keys=[f'event:{e.id}']).json()['status'])
        self.assertEqual(FeedDismissal.objects.filter(user=self.u).count(), 1)

    def test_foreign_project_items_are_404(self):
        foreign = self.event(project=self.q)
        ti = self.issue(asset=self.o, key='tls.cert_expired')
        for key in (f'event:{foreign.id}', f'task:issue:{ti.id}', f'task:candidate:{self.o.id}', 'event:999999'):
            self.assertEqual(self.dismiss(self.u, keys=[key]).status_code, 404, key)
        self.assertEqual(self.dismiss(self.u, project='nope', keys=['event:1']).status_code, 404)
        self.assertEqual(FeedDismissal.objects.count(), 0)

    def test_a_foreign_item_in_a_batch_dismisses_nothing(self):
        mine, foreign = self.event(), self.event(project=self.q)
        self.assertEqual(self.dismiss(self.u, keys=[f'event:{mine.id}', f'event:{foreign.id}']).status_code, 404)
        self.assertEqual(FeedDismissal.objects.count(), 0)

    def test_bad_keys_are_400(self):
        for keys in ('event:1', [], [None], ['event:abc'], ['nope:1'], ['task:x:1'], ['event:1' * 40], [f'event:{i}' for i in range(1, 102)]):
            self.assertEqual(self.dismiss(self.u, keys=keys).status_code, 400, keys)

    def test_notice_and_task_keys(self):
        n = InAppNotification.objects.create(title='t', description='d', icon='x', notification_type='system')
        w = self.issue(key='web.csp_missing', sev=1)
        wv = IssueWaiver.objects.create(issue=w, kind='accepted_risk', reason='r', expires_at=self.now + timedelta(days=2))
        cand = Asset.objects.create(project=self.p, kind='hostname', value='c.x.com', scope_tier='candidate')
        keys = [f'notice:{n.id}', f'task:waiver:{wv.id}', f'task:issue:{w.id}', f'task:candidate:{cand.id}']
        self.assertEqual(self.dismiss(self.u, keys=keys).json()['dismissed'], 4)

    def test_requires_login(self):
        r = APIClient().post('/api/action/feed/dismiss/', {'project': 'p1', 'keys': ['event:1']}, format='json')
        self.assertIn(r.status_code, (302, 401, 403))


class HomePageTest(HomeBase):
    def page(self, user=None, slug='p1'):
        self.client.force_login(user or self.u)
        self.client.get(f'/{slug}/home/')  # warm-up (lazy prefs creation)
        return self.client.get(f'/{slug}/home/')

    def test_tabs_cards_and_actions(self):
        self.event(title='New asset a.x.com', asset=self.a)
        self.issue(key='tls.cert_expired', sev=3, days=1)
        r = self.page()
        self.assertEqual(r.status_code, 200)
        html = r.content.decode()
        for needle in ('All activity', 'My tasks', 'role="tablist"', 'New asset a.x.com', 'data-key="event:', 'data-key="task:issue:',
                       'Dismiss', 'limes/home.js'):
            self.assertIn(needle, html)

    def test_caught_up_when_nothing_is_left(self):
        html = self.page().content.decode()
        self.assertEqual(html.count("You&#x27;re all caught up") + html.count("You're all caught up"), 2)  # both tabs

    def test_hostile_text_is_escaped(self):
        self.event(title=X, asset=self.a)
        InAppNotification.objects.create(title=X, description=X, icon='x', notification_type='system')
        a = Asset.objects.create(project=self.p, kind='hostname', value=X + '.x.com', scope_tier='candidate')
        html = self.page().content.decode()
        self.assertNotIn(X, html)
        self.assertGreaterEqual(html.count(ESC), 3)

    def test_unknown_project_is_404(self):
        self.client.force_login(self.u)
        self.assertEqual(self.client.get('/nope/home/').status_code, 404)

    def test_other_projects_data_never_shows(self):
        self.event(project=self.q, title='SECRET-OTHER')
        self.assertNotIn('SECRET-OTHER', self.page().content.decode())

    def test_queries_do_not_grow_with_cards(self):
        self.page()
        with CaptureQueriesContext(connection) as small:
            self.client.get('/p1/home/')
        for i in range(25):
            self.event(title=f'e{i}', asset=self.a)
            self.issue(key=f'k{i}', sev=3, days=1, source='finding')
            Asset.objects.create(project=self.p, kind='hostname', value=f'c{i}.x.com', scope_tier='candidate')
        with CaptureQueriesContext(connection) as big:
            r = self.client.get('/p1/home/')
        self.assertEqual(len(small), len(big))
        self.assertLessEqual(len(big), 40)

    def test_sidebar_links_home_first_and_marks_it_current(self):
        html = self.page().content.decode()
        nav = html[html.index('id="nav-monitor"'):]
        self.assertLess(nav.index('href="/p1/home/"'), nav.index('href="/p1/dashboard/"'))
        self.assertRegex(html, r'href="/p1/home/" aria-current="page"')
        self.client.get('/p1/dashboard/')
        self.assertNotRegex(self.client.get('/p1/dashboard/').content.decode(), r'href="/p1/home/" aria-current="page"')
