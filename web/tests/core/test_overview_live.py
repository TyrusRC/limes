from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test.utils import CaptureQueriesContext, override_settings
from django.urls import reverse

from dashboard import live
from dashboard.stats import CHANGE_LABELS, invalidate
from startScan.models import Asset, ChangeEvent
from tests.core.test_ct_health import Base as HealthBase

X = '<img src=x onerror=alert(1)>'
ESCAPED = '&lt;img src=x onerror=alert(1)&gt;'
LIVE_QUERIES = 8  # session, user, the membership check, project, events and the card's three; measured on the finished branch; a rise must be justified in review
API_QUERIES = 1  # api.card reads the owned roots' poll times once; measured with a key set


def section(html, id_):
    start = html.index(f'id="{id_}"')
    return html[start:html.index('</section>', start)]


class LiveBase(HealthBase):
    def setUp(self):
        super().setUp()
        from django.contrib.auth.signals import user_logged_in
        from dashboard.views import on_user_logged_in
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.o = type(self.p).objects.create(name='o', slug='o', insert_date=self.now)
        self.client.force_login(User.objects.create_user('u', password='p'))

    def ev(self, title='t', project=None, kind='asset_new', **kw):
        return ChangeEvent.objects.create(project=project or self.p, kind=kind, title=title, **kw)

    def asset(self, value):
        return Asset.objects.create(project=self.p, kind='hostname', value=value, scope_tier='owned_host')

    def get(self, slug='p', since=None):
        return self.client.get(reverse('dashboardLive', kwargs={'slug': slug}), {} if since is None else {'since': since})


class LiveEndpointTest(LiveBase):
    def test_live_returns_new_events_only_for_project(self):
        e1, e2, e3 = self.ev('one'), self.ev('two', kind='cert_new'), self.ev('other', project=self.o)
        r = self.get(since=e1.id)
        body = r.json()
        self.assertEqual([e['id'] for e in body['events']], [e2.id])
        self.assertEqual(body['events'][0]['label'], CHANGE_LABELS['cert_new'])
        self.assertEqual(body['events'][0]['title'], 'two')
        self.assertEqual([e['id'] for e in self.get(since=0).json()['events']], [e1.id, e2.id])
        self.assertNotIn(e3.id, [e['id'] for e in self.get(since=0).json()['events']])
        self.assertEqual(r['Cache-Control'], 'no-store')
        self.assertEqual(r['Content-Type'], 'application/json')
        self.assertIn('realtime', body)
        self.assertEqual(body['poll'], 30)
        for i in range(25):
            self.ev(f'n{i}')
        evs = self.get(since=0).json()['events']
        self.assertEqual(len(evs), live.LIVE_LIMIT)
        self.assertEqual([e['id'] for e in evs], sorted(e['id'] for e in evs))

    def test_since_validated(self):
        for bad in ('-1', 'abc', '1e3', '9' * 19, '1 OR 1=1', '1.5', '１２'):
            r = self.get(since=bad)
            self.assertEqual((r.status_code, r.json()), (400, {'error': 'bad since'}), bad)
        self.assertEqual(self.get(since='').status_code, 400)
        self.assertEqual(self.get().status_code, 200)  # absent is 0
        self.assertEqual(self.get(slug='nope').status_code, 404)
        self.assertEqual(self.client.post(reverse('dashboardLive', kwargs={'slug': 'p'})).status_code, 405)
        self.client.cookies.clear()
        r = self.get()
        self.assertEqual(r.status_code, 302)
        self.assertIn('login', r['Location'])

    def test_every_response_is_uncacheable(self):
        for r in (self.get(), self.get(since='x'),
                  self.client.post(reverse('dashboardLive', kwargs={'slug': 'p'}))):
            self.assertEqual(r['Cache-Control'], 'no-store', r.status_code)
            self.assertIn('Cookie', r['Vary'], r.status_code)

    def test_payload_names_its_page_size(self):
        self.assertEqual(self.get().json()['limit'], live.LIVE_LIMIT)

    def test_live_does_not_touch_stats(self):
        with mock.patch('dashboard.stats.asm_stats') as a, mock.patch('dashboard.stats.project_stats') as s:
            self.get()
            self.assertEqual((a.call_count, s.call_count), (0, 0))
        counts = []
        for n in (3, 30):
            ChangeEvent.objects.all().delete()
            Asset.objects.all().delete()
            for i in range(n):
                self.ev(f'n{i}', asset=self.asset(f'h{i}.x.com'))  # an asset each: a lost select_related shows as N+1
            self.get()  # warm-up: session, prefs
            with CaptureQueriesContext(connection) as q:
                self.get()
            counts.append(len(q))
        self.assertEqual(counts[0], counts[1])
        self.assertEqual(counts[0], LIVE_QUERIES)

    @override_settings(CERTSPOTTER_API_KEY='k' * 8)
    def test_live_queries_with_an_api_key(self):
        self.get()  # warm-up: session, prefs
        with CaptureQueriesContext(connection) as q:
            self.get()
        self.assertEqual(len(q), LIVE_QUERIES + API_QUERIES)

    @override_settings(CT_WATCH=True, CONTINUOUS_SCANS=True)
    def test_card_is_honest_in_json(self):
        r = self.get().json()['realtime']
        self.assertEqual((r['state'], r['label']), ('degraded', 'Degraded'))
        self.beat()
        self.assertEqual(self.get().json()['realtime']['label'], 'Live')


@override_settings(CT_WATCH=False, CONTINUOUS_SCANS=True, CERTSPOTTER_API_KEY='')
class LivePageTest(LiveBase):
    def page(self):
        invalidate(self.p.id)  # the stats cache holds the feed for a minute (cache.clear() would wipe the heartbeat)
        self.client.get('/p/dashboard/')
        r = self.client.get('/p/dashboard/')
        self.assertEqual(r.status_code, 200)
        return r.content.decode()

    def test_realtime_card_rendered_and_escaped(self):
        self.ev('New certificate for ' + X, kind='cert_new')
        with override_settings(CT_WATCH=True):
            self.beat(last_error_summary=X, at=(self.now - timedelta(seconds=1000)).isoformat())
            html = self.page()
        for id_ in ('dash_realtime', 'dash_changes'):
            self.assertIn(ESCAPED, section(html, id_), id_)
        self.assertNotIn(X, html)
        self.assertIn('Degraded', section(html, 'dash_realtime'))
        self.assertIn('The watcher stopped reporting', section(html, 'dash_realtime'))
        self.assertNotIn('>Live<', section(html, 'dash_realtime'))
        data = self.get().json()
        self.assertEqual(data['events'][0]['title'], 'New certificate for ' + X)

    def test_watch_off_is_cadence_only(self):
        s = section(self.page(), 'dash_realtime')
        self.assertIn('Cadence only', s)
        self.assertIn('ov-rt-off', s)
        self.assertNotIn('>Live<', s)

    def test_healthy_says_live(self):
        with override_settings(CT_WATCH=True):
            self.beat()
            s = section(self.page(), 'dash_realtime')
        self.assertIn('>Live<', s)
        self.assertIn('ov-rt-healthy', s)

    def test_new_kinds_have_icons(self):
        for kind, icon in (('cert_new', 'fe-shield'), ('dns_changed', 'fe-shuffle'),
                           ('monitoring_degraded', 'fe-wifi-off'), ('monitoring_restored', 'fe-wifi')):
            ChangeEvent.objects.all().delete()
            self.ev('x', kind=kind)
            html = section(self.page(), 'dash_changes')
            self.assertIn(f'<i class="{icon}">', html, kind)
            self.assertNotIn('fe-activity', html, kind)

    def test_root_and_wiring(self):
        e = self.ev('x')
        html = self.page()
        self.assertIn(f'data-since="{e.id}"', html)
        self.assertIn('data-poll="30"', html)
        self.assertIn(reverse('dashboardLive', kwargs={'slug': 'p'}), html)
        self.assertIn('id="dash_changes_feed"', html)
        self.assertIn('id="live_stale"', html)
        self.assertIn(f'data-id="{e.id}"', html)
        with override_settings(LIVE_POLL_SECONDS=0):
            self.assertIn('data-poll="0"', self.page())
        ChangeEvent.objects.all().delete()
        self.assertIn('data-since="0"', self.page())

    def test_cache_without_ids_falls_back_to_a_real_cursor(self):
        e = self.ev('x')
        legacy = [{'kind': 'asset_new', 'label': 'l', 'title': 't', 'severity': None, 'created_at': self.now, 'asset': None}]
        self.assertEqual(live.newest_id(legacy, self.p), e.id)  # not 0: that would replay the oldest events as new
        self.assertEqual(live.newest_id([{'id': 5}, {'id': 9}], self.p), 9)
        self.assertEqual(live.newest_id([], self.p), 0)  # an empty cache means no events then: all are new

    def test_card_labels_scope_and_poll_off_snapshot(self):
        html = self.page()
        self.assertIn('Instance-wide', section(html, 'dash_realtime'))
        self.assertIn('id="rt_asof"', html)
        with override_settings(LIVE_POLL_SECONDS=0):
            self.assertIn('Snapshot from page load', section(self.page(), 'dash_realtime'))

    def test_empty_feed_still_has_a_list(self):
        self.assertIn('id="dash_changes_feed"', self.page())  # the first live row needs somewhere to land
