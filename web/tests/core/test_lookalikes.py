import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import timedelta
from unittest import mock

import dns.resolver
import idna
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import continuous, monitor, scope, scoring
from limes.celery_routing import TASK_PLAN
from limes.checks import collect
from limes.intel import crtsh, http, ratelimit
from limes.lookalike import check, generate, rdap, report, tasks
from startScan.models import Asset, ChangeEvent, Lookalike

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')
BOOTSTRAP = {'com': 'https://rdap.verisign.com/com/v1/', 'net': 'https://rdap.example-net.test/', 'kg': 'http://rdap.cctld.kg/'}
BIG_BUDGET = 10 ** 7


def rdap_fixture(created=None):
    with open(os.path.join(FIXTURES, 'rdap_domain.json')) as f:
        obj = json.load(f)
    if created:
        obj['events'][0]['eventDate'] = created.strftime('%Y-%m-%dT%H:%M:%SZ')
    return obj


class Resolver:
    """resolve(name, rdtype): the table's list, or NXDOMAIN when absent."""
    def __init__(self, table=None):
        self.table, self.calls = table or {}, []

    def __call__(self, name, rdtype):
        self.calls.append((name, rdtype))
        if (name, rdtype) not in self.table:
            raise dns.resolver.NXDOMAIN()
        got = self.table[name, rdtype]
        if isinstance(got, Exception):
            raise got
        return got


class FakeGet:
    """get_json stand-in: first route whose key is in the url wins; unrouted calls time out (None, None)."""
    def __init__(self, routes=None):
        self.routes, self.calls = routes or {}, []

    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        for key, resp in self.routes.items():
            if key in url:
                return resp
        return None, None


def allow(kind):
    return True


class GenerateTest(SimpleTestCase):
    def test_candidates_homoglyph_filter_and_cap(self):
        out = generate.candidates('example.com')
        self.assertTrue(0 < len(out) <= 1000)
        self.assertEqual(out, generate.candidates('example.com'))
        self.assertNotIn('example.com', [c['domain'] for c in out])
        homoglyphs = [c for c in out if 'homoglyph' in c['fuzzers']]
        self.assertTrue(homoglyphs)
        for c in out:
            self.assertTrue(c['domain'].isascii())
            self.assertEqual(c['domain'], c['domain'].lower())
        for c in homoglyphs:
            self.assertEqual(generate.distance(c['unicode'].rsplit('.', 1)[0], 'example'), 1)
        with mock.patch.object(generate, 'MAX_CANDIDATES_PER_ROOT', 50):
            small = generate.candidates('example.com')
        self.assertEqual(small, out[:50])
        ranks = [generate.RANKS.index(c['fuzzers'][0]) for c in small]
        self.assertEqual(ranks, sorted(ranks))

    def test_distance(self):
        self.assertEqual(generate.distance('example', 'examp1e'), 1)
        self.assertEqual(generate.distance('example', 'example'), 0)
        self.assertEqual(generate.distance('abc', 'xyzxyz', limit=2), 3)

    def test_registrable_split_uses_psl(self):
        co = generate.candidates('mybrand.co.uk')
        swaps = [c for c in co if 'tld-swap' not in c['fuzzers']]
        self.assertTrue(swaps)
        self.assertTrue(all(c['domain'].endswith('.co.uk') for c in swaps))
        gh = generate.candidates('foo.github.io')
        swaps = [c for c in gh if 'tld-swap' not in c['fuzzers']]
        self.assertTrue(swaps)
        self.assertTrue(all(c['domain'].endswith('.github.io') for c in swaps))
        self.assertTrue(any(c['domain'] == 'fo.github.io' for c in gh))
        self.assertEqual(generate.candidates('www.example.com'), [])
        self.assertEqual(generate.candidates('com'), [])
        self.assertEqual(generate.candidates(''), [])

    def test_import_keeps_socket_default_timeout(self):
        socket.setdefaulttimeout(3.5)
        try:
            with mock.patch.dict(sys.modules):
                sys.modules.pop('dnstwist', None)
                with mock.patch.object(generate, '_FUZZER', None):
                    generate._fuzzer_class()
                    self.assertIn('dnstwist', sys.modules)
            self.assertEqual(socket.getdefaulttimeout(), 3.5)
        finally:
            socket.setdefaulttimeout(None)

    def test_long_label_and_many_keywords_capped(self):
        import time
        start = time.monotonic()
        out = generate.candidates('a' * 63 + '.com', [f'kw{i:02d}' for i in range(100)])
        self.assertLess(time.monotonic() - start, 20)  # homoglyphs of a long label are skipped, not minutes of work
        self.assertLessEqual(len(out), 1000)
        for c in out:
            self.assertLessEqual(len(c['domain']), 253)
            self.assertTrue(all(len(label) <= 63 for label in c['domain'].split('.')))
        out = generate.candidates('brand.com', [f'kw{i:02d}' for i in range(100)])
        names = ' '.join(c['domain'] for c in out)
        self.assertIn('kw00', names)
        self.assertIn('kw19', names)
        self.assertNotIn('kw20', names)
        # unusable keywords are skipped, not used
        out = generate.candidates('brand.com', ['Bad Word', '-x', 'ünï', 5, 'ok1'])
        names = ' '.join(c['domain'] for c in out)
        self.assertIn('ok1', names)
        self.assertNotIn('bad', names)

    def test_owned_values_never_candidates(self):
        out = generate.candidates('example.com', exclude=frozenset({'example.net'}))
        self.assertNotIn('example.net', [c['domain'] for c in out])
        self.assertIn('example.org', [c['domain'] for c in generate.candidates('example.com')])

    def test_idn_stored_with_punycode(self):
        idn = [c for c in generate.candidates('example.com') if c['domain'].startswith('xn--')]
        self.assertTrue(idn)
        for c in idn:
            self.assertFalse(c['unicode'].isascii())
            self.assertEqual(idna.encode(c['unicode']).decode(), c['domain'])

    def test_ct_keyword_whole_label_match(self):
        names = ['examp1e-login.com', 'myexamplestore.com', 'example.evil.net', 'examples.org', 'example.com',
                 'EXAMPLE.evil.net', 5, 'x' * 300 + '.com', 'bad name.com']
        out = generate.ct_matches(names, 'example', frozenset({'example.com'}))
        self.assertEqual(out, ['evil.net', 'examp1e-login.com', 'examples.org'])
        many = [f'example{i}.org' for i in range(300)]
        self.assertEqual(len(generate.ct_matches(many, 'example', frozenset())), 100)


class RdapTest(SimpleTestCase):
    def test_server_for_https_only(self):
        self.assertEqual(rdap.server_for('a.com', BOOTSTRAP), 'https://rdap.verisign.com/com/v1/')
        self.assertIsNone(rdap.server_for('a.kg', BOOTSTRAP))
        self.assertIsNone(rdap.server_for('a.zz', BOOTSTRAP))
        self.assertIsNone(rdap.server_for('a.co.uk', {'uk': 'http://x.test/'}))
        self.assertEqual(rdap.server_for('a.co.uk', {'uk': 'https://x.test/'}), 'https://x.test/')

    def test_parse_caps_and_shapes(self):
        out = rdap.parse(rdap_fixture())
        self.assertEqual(out['abuse_email'], 'abuse@registrar.example')
        self.assertTrue(out['registrar'].startswith('<script>'))
        self.assertEqual(len(out['registrar']), 200)
        self.assertEqual(out['created'][:10], '2026-10-18')
        self.assertEqual(len(out['statuses']), 10)
        for junk in (None, [], 'x', {'entities': 'x', 'events': 5, 'status': 'x'},
                     {'entities': [{'roles': ['abuse'], 'vcardArray': ['vcard', [['email', {}, 'text', 'not an email']]]}]}):
            out = rdap.parse(junk)
            self.assertEqual(set(out), {'registrar', 'created', 'abuse_email', 'statuses'})
            self.assertEqual(out['abuse_email'], '')

    def test_lookup_outcomes(self):
        get = FakeGet({'/domain/a.com': (200, rdap_fixture())})
        state, info = rdap.lookup('a.com', BOOTSTRAP, get)
        self.assertEqual((state, info['abuse_email']), ('registered', 'abuse@registrar.example'))
        self.assertEqual(get.calls[0][1], {'provider': 'rdap:rdap.verisign.com', 'max_wait': 10, 'max_bytes': http.MAX_BODY})
        self.assertEqual(rdap.lookup('b.com', BOOTSTRAP, FakeGet({'/domain/b.com': (404, {})}))[0], 'unregistered')
        self.assertEqual(rdap.lookup('b.com', BOOTSTRAP, FakeGet({'/domain/b.com': (503, {})}))[0], 'unknown')
        self.assertEqual(rdap.lookup('b.com', BOOTSTRAP, FakeGet())[0], 'unknown')
        self.assertEqual(rdap.lookup('b.com', BOOTSTRAP, FakeGet({'/domain/b.com': (200, None)}))[0], 'unknown')


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.now = timezone.now()
        self.p = Project.objects.create(name='Acme', slug='acme', insert_date=self.now)
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')

    def row(self, domain='examp1e.com', **kw):
        kw.setdefault('unicode', domain)
        kw.setdefault('source', 'permutation')
        kw.setdefault('fuzzers', ['homoglyph'])
        return Lookalike.objects.create(project=self.p, root=self.root, domain=domain, **kw)

    def run_check(self, row, resolve=None, get=None, now=None, spend=allow):
        return check.check_row(row, now or self.now, resolve or Resolver(), get or FakeGet(), BOOTSTRAP, spend)

    def baseline(self):
        from limes.tasks import intel
        intel._store(self.root, 'lookalike', {'baselined_at': self.now.isoformat()}, self.now)


class CheckRowTest(Base):
    def test_ns_registration_and_rdap_override(self):
        none = self.row('examp1e.net')
        resolve, get = Resolver(), FakeGet()
        self.assertEqual(self.run_check(none, resolve, get), [])
        none.refresh_from_db()
        self.assertEqual((none.status, none.registered), ('unregistered', False))
        self.assertEqual(none.next_check, self.now + timedelta(days=7))
        self.assertEqual([c for c in get.calls if 'rdap' in c[0]], [])
        self.assertEqual(resolve.calls, [('examp1e.net', 'NS')])

        live = self.row('examp1e.com')
        resolve = Resolver({('examp1e.com', 'NS'): ['ns1.x.net.'], ('examp1e.com', 'A'): ['1.2.3.4'],
                            ('examp1e.com', 'MX'): ['10 mail.x.net.']})
        get = FakeGet({'/domain/examp1e.com': (200, rdap_fixture())})
        events = self.run_check(live, resolve, get)
        live.refresh_from_db()
        self.assertEqual((live.status, live.registered, live.has_mx), ('registered', True, True))
        self.assertEqual(live.dns, {'ns': ['ns1.x.net.'], 'a': ['1.2.3.4'], 'aaaa': [], 'mx': ['10 mail.x.net.']})
        self.assertEqual(len(live.rdap['registrar']), 200)
        self.assertEqual(live.rdap['abuse_email'], 'abuse@registrar.example')
        self.assertEqual(live.next_check, self.now + timedelta(days=1))
        self.assertEqual([e[0] for e in events], ['lookalike_new'])

        for code, want in ((200, 'registered'), (404, 'gone')):
            row = self.row(f'prev{code}.com', status='registered', registered=True, dns={'ns': ['ns.x.'], 'a': ['1.1.1.1']})
            self.run_check(row, Resolver(), FakeGet({'/domain/': (code, rdap_fixture() if code == 200 else {})}))
            row.refresh_from_db()
            self.assertEqual(row.status, want)
            if code == 200:
                self.assertEqual(row.registered, True)
                self.assertEqual(row.dns.get('ns', []), [])
            else:
                self.assertEqual(row.registered, False)
                self.assertEqual(row.next_check, self.now + timedelta(days=30))

    def test_dns_error_retries_in_an_hour(self):
        row = self.row()
        events = self.run_check(row, Resolver({('examp1e.com', 'NS'): dns.resolver.NoNameservers()}))
        row.refresh_from_db()
        self.assertEqual(events, [])
        self.assertEqual(row.next_check, self.now + timedelta(hours=1))
        self.assertEqual((row.status, row.registered), ('unchecked', None))
        self.assertIsNotNone(row.last_checked)

    def test_hostile_domain_not_resolved(self):
        for bad in ('a' * 70 + '.com', 'bad name.com', 'x.com\n', '-x.com'):
            row = self.row(bad, unicode=bad)
            resolve = Resolver()
            self.assertEqual(self.run_check(row, resolve), [])
            self.assertEqual(resolve.calls, [])

    def test_rdap_https_only_and_spacing(self):
        kg = self.row('examp1e.kg')
        resolve = Resolver({('examp1e.kg', 'NS'): ['ns.x.']})
        get = FakeGet()
        self.run_check(kg, resolve, get)
        self.assertEqual([c for c in get.calls if 'rdap' in c[0]], [])
        com = self.row('examp1e.com')
        get = FakeGet({'/domain/examp1e.com': (200, rdap_fixture())})
        self.run_check(com, Resolver({('examp1e.com', 'NS'): ['ns.x.']}), get)
        calls = [c for c in get.calls if 'rdap' in c[0]]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], {'provider': 'rdap:rdap.verisign.com', 'max_wait': 10, 'max_bytes': http.MAX_BODY})

    def test_rdap_provider_prefix_gets_its_own_spacing(self):
        self.assertEqual(http.MIN_INTERVAL['rdap'], 2.0)
        with mock.patch.object(ratelimit, 'reserve', return_value=0.0) as reserve:
            resp = mock.Mock(status_code=200, **{'json.return_value': {}})
            http.get_json('https://x.test/', provider='rdap:rdap.verisign.com', session=mock.Mock(get=mock.Mock(return_value=resp)))
        self.assertEqual(reserve.call_args[0][:2], ('rdap:rdap.verisign.com', 2.0))

    def test_live_sightings_from_the_certificate_watch_survive_the_crtsh_summary(self):
        from limes.ct import lookalikes as live
        row = self.row()
        self.assertTrue(live.record_sighting(self.p.id, 'examp1e.com', self.now))
        resolve = Resolver({('examp1e.com', 'NS'): ['ns.x.']})
        ct = [{'id': 7, 'name_value': 'examp1e.com', 'not_before': '2026-10-20T00:00:00'}]
        self.run_check(row, resolve, FakeGet({'/domain/': (404, {}), 'crt.sh': (200, ct)}))
        row.refresh_from_db()
        self.assertEqual(row.ct['count'], 1)  # the crt.sh summary is the check's
        self.assertEqual(row.ct['live']['count'], 1)  # and the watch's count is carried over, not wiped

    def test_ct_exact_query_and_timeout_leaves_value(self):
        row = self.row()
        resolve = Resolver({('examp1e.com', 'NS'): ['ns.x.']})
        ct = [{'id': 7, 'name_value': 'examp1e.com\nwww.examp1e.com', 'not_before': '2026-10-20T00:00:00'},
              {'id': 8, 'name_value': 'other.org', 'not_before': '2026-10-21T00:00:00'}]
        get = FakeGet({'/domain/': (404, {}), 'crt.sh': (200, ct)})
        self.run_check(row, resolve, get)
        row.refresh_from_db()
        url = [c[0] for c in get.calls if 'crt.sh' in c[0]][0]
        self.assertEqual(url, crtsh.exact_url('examp1e.com'))
        self.assertEqual(url, 'https://crt.sh/?q=examp1e.com&output=json&exclude=expired')
        self.assertEqual(row.ct['count'], 1)
        self.assertEqual(row.ct['certs'], [{'id': 7, 'date': '2026-10-20'}])
        self.assertIsNotNone(row.ct_checked_at)
        before = dict(row.ct)
        later = self.now + timedelta(days=2)
        self.run_check(row, resolve, FakeGet({'/domain/': (404, {})}), now=later)  # crt.sh times out
        row.refresh_from_db()
        self.assertEqual(row.ct, before)
        self.assertEqual(crtsh.keyword_url('brand'), 'https://crt.sh/?q=%25brand%25&output=json&exclude=expired')

    def test_decisions_sticky(self):
        ign = self.row('examp1e.org', status='ignored', registered=False)
        resolve = Resolver({('examp1e.org', 'NS'): ['ns.x.']})
        events = self.run_check(ign, resolve, FakeGet({'/domain/': (200, rdap_fixture())}))
        ign.refresh_from_db()
        self.assertEqual((ign.status, ign.registered), ('ignored', True))
        self.assertEqual(ign.next_check, self.now + timedelta(days=30))
        self.assertEqual(events, [])
        gone = self.row('gone1.net', status='ignored', registered=True)
        self.run_check(gone, Resolver(), FakeGet({'/domain/': (404, {})}))
        gone.refresh_from_db()
        self.assertEqual(gone.status, 'gone')

        ours = self.row('examp1e.co', status='ours', next_check=self.now - timedelta(days=1))
        resolve = Resolver()
        self.assertEqual(self.run_check(ours, resolve), [])
        self.assertEqual(resolve.calls, [])
        self.assertNotIn(ours.id, [r.id for r in check.due_rows(self.now, 100)])

    def test_due_rows_only_owned_live_roots(self):
        due = self.row('examp1e.xyz')
        other = Asset.objects.create(project=self.p, kind='root_domain', value='old.com', scope_tier='owned_root', state='retired')
        Lookalike.objects.create(project=self.p, root=other, domain='o1d.com', unicode='o1d.com', source='ct')
        cand = Asset.objects.create(project=self.p, kind='root_domain', value='cand.com', scope_tier='candidate')
        Lookalike.objects.create(project=self.p, root=cand, domain='cand1.com', unicode='cand1.com', source='ct')
        self.row('examp1e.app', next_check=self.now + timedelta(days=1))
        self.assertEqual([r.id for r in check.due_rows(self.now + timedelta(minutes=1), 10)], [due.id])

    def test_watched_gains_mx_active_event(self):
        self.baseline()
        row = self.row(status='watching', registered=True, dns={'ns': ['ns.x.'], 'a': ['1.1.1.1'], 'aaaa': [], 'mx': []},
                       rdap_checked_at=self.now, ct_checked_at=self.now, next_check=self.now - timedelta(minutes=1))
        resolve = Resolver({('examp1e.com', 'NS'): ['ns.x.'], ('examp1e.com', 'A'): ['1.1.1.1'],
                            ('examp1e.com', 'MX'): ['10 mail.x.net.']})
        with mock.patch.object(collect, '_resolve', resolve), mock.patch.object(http, 'get_json', FakeGet()), \
                mock.patch('limes.feeds.store.load', return_value=(BOOTSTRAP, {})), \
                override_settings(LOOKALIKE_ENABLED=True, CONTINUOUS_SCANS=True, LOOKALIKE_DNS_DAILY_BUDGET=BIG_BUDGET):
            out = tasks.lookalike_tick.run()
        self.assertEqual(out['events'], 1)
        ev = ChangeEvent.objects.get()
        self.assertEqual((ev.kind, ev.immediate), ('lookalike_active', True))
        self.assertIn('examp1e[.]com', ev.title)
        row.refresh_from_db()
        self.assertEqual(row.status, 'watching')
        self.assertTrue(row.has_mx)


@override_settings(LOOKALIKE_ENABLED=True, CONTINUOUS_SCANS=True, LOOKALIKE_DNS_DAILY_BUDGET=BIG_BUDGET, RDAP_DAILY_BUDGET=BIG_BUDGET)
class TickTest(Base):
    def tick(self, resolve=None, get=None):
        with mock.patch.object(collect, '_resolve', resolve or Resolver()), \
                mock.patch.object(http, 'get_json', get or FakeGet()), \
                mock.patch('limes.feeds.store.load', return_value=(BOOTSTRAP, {})):
            return tasks.lookalike_tick.run()

    def test_budget_exhaustion_stops_tick(self):
        rows = [self.row(f'examp{i}e.com', next_check=self.now - timedelta(hours=10 - i)) for i in range(5)]
        calls = []

        def three(provider, limit, **kw):
            calls.append(provider)
            return len(calls) <= 3
        resolve = Resolver()
        with mock.patch.object(ratelimit, 'take_daily', three):
            out = self.tick(resolve)
        self.assertEqual(len(resolve.calls), 3)
        self.assertTrue(out['stopped'])
        for r in rows:
            r.refresh_from_db()
        self.assertTrue(all(r.next_check > self.now for r in rows[:3]))
        self.assertTrue(all(r.next_check < self.now for r in rows[3:]))

    def test_cache_down_no_dns(self):
        self.row()
        resolve = Resolver()
        with mock.patch.object(cache, 'add', side_effect=ConnectionError), mock.patch.object(cache, 'incr', side_effect=ConnectionError):
            self.tick(resolve)
        self.assertEqual(resolve.calls, [])

    def test_first_sweep_silent(self):
        ns = lambda d: {(d, 'NS'): ['ns.x.net.']}  # noqa: E731
        table = {**ns('examp1e.com'), **ns('examp1e.net'), **ns('examp1e.org'), **ns('3xample.com'),
                 ('examp1e.com', 'MX'): ['10 mail.x.net.']}
        for d in ('examp1e.net', 'examp1e.org'):
            self.row(d)
        self.row('3xample.com')
        out = self.tick(Resolver(table), FakeGet({'/domain/': (200, rdap_fixture(self.now - timedelta(days=700)))}))
        self.assertEqual(out['events'], 0)
        self.assertEqual(ChangeEvent.objects.count(), 0)
        self.root.refresh_from_db()
        self.assertIn('baselined_at', self.root.enrichment['lookalike'])
        self.assertEqual(Lookalike.objects.filter(registered=True).count(), 3)

        self.row('examp1e.com')  # new registration, created 5 days ago, with MX
        self.row('examp1e.info')  # created two years ago, no MX
        table[('examp1e.info', 'NS')] = ['ns.x.net.']
        get = FakeGet({'/domain/examp1e.com': (200, rdap_fixture(self.now - timedelta(days=5))),
                       '/domain/examp1e.info': (200, rdap_fixture(self.now - timedelta(days=700)))})
        with mock.patch.dict(BOOTSTRAP, {'info': 'https://rdap.info.test/'}):
            out = self.tick(Resolver(table), get)
        self.assertEqual(out['events'], 2)
        evs = {e.title: e for e in ChangeEvent.objects.filter(kind='lookalike_new')}
        self.assertEqual(len(evs), 2)
        loud = next(e for t, e in evs.items() if 'examp1e[.]com' in t)
        self.assertTrue(loud.immediate)
        self.assertTrue(next(e for t, e in evs.items() if 'examp1e[.]info' in t).immediate is False)
        for e in evs.values():
            self.assertNotIn('examp1e.com', e.title)
            self.assertNotIn('examp1e.info', e.title)
        self.assertEqual(loud.asset_id, self.root.id)

    def test_generate_and_pipelines_blind_to_lookalikes(self):
        self.p.brand_keywords = ['acme']
        self.p.save()
        Asset.objects.create(project=self.p, kind='hostname', value='www.example.com', parent=self.root, scope_tier='owned_host')
        before = Asset.objects.count()
        with mock.patch.object(http, 'get_json', FakeGet({'crt.sh': (200, [{'id': 1, 'name_value': 'examp1e-login.net'}])})) as get:
            out = tasks.generate_lookalikes.run()
        self.assertGreater(Lookalike.objects.count(), 100)
        self.assertEqual(Lookalike.objects.filter(source='ct').count(), 1)
        self.assertEqual(len([c for c in get.calls if 'crt.sh' in c[0]]), 1)
        self.assertEqual([c[1].get('max_bytes') for c in get.calls if 'crt.sh' in c[0]], [http.MAX_BODY])  # the %label% query is capped
        self.assertFalse(Lookalike.objects.filter(domain='www.example.com').exists())
        self.tick(Resolver({}))
        self.assertEqual(Asset.objects.count(), before)
        domains = set(Lookalike.objects.values_list('domain', flat=True))
        seen = {a.value for a in scoring.scored_assets(self.p)} | {a.value for a in monitor.monitored(self.p)} \
            | {a.value for a in monitor.due_assets(self.now + timedelta(days=30))} \
            | {a.value for a in continuous.due_roots(self.now + timedelta(days=30), project=self.p)}
        self.assertFalse(seen & domains)
        some = sorted(domains)[0]
        allowed, refused = scope.may_attack(self.p, [some])
        self.assertEqual(allowed, [])
        self.assertTrue(refused)
        # a second run adds nothing and never deletes; the CT query is once a day
        total = Lookalike.objects.count()
        with mock.patch.object(http, 'get_json', FakeGet()) as get:
            tasks.generate_lookalikes.run()
        self.assertEqual(Lookalike.objects.count(), total)
        self.assertEqual(get.calls, [])

    def test_beat_and_routing(self):
        from django.conf import settings
        for name in ('generate_lookalikes', 'lookalike_tick'):
            self.assertEqual(TASK_PLAN[name], ('io', 900))
        self.assertIn('limes.lookalike.tasks', settings.CELERY_IMPORTS)
        beat = settings.CELERY_BEAT_SCHEDULE
        self.assertEqual(beat['generate-lookalikes'], {'task': 'generate_lookalikes', 'schedule': 86400.0})
        self.assertEqual(beat['lookalike-tick'], {'task': 'lookalike_tick', 'schedule': 60.0, 'options': {'expires': 55}})
        self.row()
        resolve = Resolver()
        with override_settings(LOOKALIKE_ENABLED=False):
            self.assertEqual(self.tick(resolve), {'reason': 'disabled'})
            self.assertEqual(tasks.generate_lookalikes.run(), {'reason': 'disabled'})
        with override_settings(CONTINUOUS_SCANS=False):
            self.assertEqual(self.tick(resolve), {'reason': 'disabled'})
        self.assertEqual(resolve.calls, [])


class HttpTest(Base):
    def setUp(self):
        super().setUp()
        self.row_ = self.row(registered=True, status='registered', dns={'ns': ['ns.x.'], 'a': ['9.9.9.9']})

    def resp(self, status=200, body=b'', headers=None):
        r = mock.Mock(status_code=status, headers=headers or {})
        r.iter_content.side_effect = lambda chunk_size=1: iter([body[i:i + 4096] for i in range(0, len(body), 4096)])
        return r

    def run_http(self, resp):
        get = mock.Mock(return_value=resp)
        factory = mock.Mock(return_value=get)
        resolve = Resolver({('examp1e.com', 'A'): ['9.9.9.9'], ('examp1e.com', 'AAAA'): []})
        out = check.check_http(self.row_, self.now, get_factory=factory, resolve=resolve)
        return out, get, factory

    def test_http_optin(self):
        with override_settings(LOOKALIKE_HTTP=False):
            out, get, factory = self.run_http(self.resp())
        self.assertIsNone(out)
        factory.assert_not_called()

        page = b'<html><title>Login to <script>alert(1)</script>' + b'z' * 500 + b'</title><input type="password"> example</html>'
        with override_settings(LOOKALIKE_HTTP=True):
            out, get, factory = self.run_http(self.resp(200, page))
            self.assertEqual(factory.call_args[0][:2], ('examp1e.com', '9.9.9.9'))
            get.assert_called_once()
            self.assertEqual(get.call_args[0][0], 'https://examp1e.com/')
            self.assertIs(get.call_args[1]['allow_redirects'], False)
            self.assertEqual(out['status'], 200)
            self.assertTrue(out['title'].startswith('Login to <script>'))
            self.assertEqual(len(out['title']), 200)
            self.assertTrue(out['password_field'])
            self.assertTrue(out['brand_in_page'])
            self.assertIsNone(out['location_host'])
            self.row_.refresh_from_db()
            self.assertEqual(self.row_.http, out)
            # once per 7 days
            self.assertIsNone(check.check_http(self.row_, self.now + timedelta(days=3), get_factory=factory, resolve=Resolver()))
            out, get, _ = self.run_http(self.resp(302, b'', {'Location': 'https://Elsewhere.test/login'}))
            self.assertIsNone(out)  # still inside the 7 days
            self.row_.http = None
            out, get, _ = self.run_http(self.resp(302, b'', {'Location': 'https://Elsewhere.test/login'}))
            self.assertEqual((out['status'], out['location_host'], out['title']), (302, 'elsewhere.test', ''))
            self.assertEqual(get.call_count, 1)

    def test_http_refused_address_is_not_contacted(self):
        resolve = Resolver({('examp1e.com', 'A'): ['10.0.0.5'], ('examp1e.com', 'AAAA'): []})
        factory = mock.Mock()
        with override_settings(LOOKALIKE_HTTP=True):
            out = check.check_http(self.row_, self.now, get_factory=factory, resolve=resolve)
        factory.assert_not_called()
        self.assertIsNone(out['status'])

    def test_http_only_registered_with_a_record(self):
        self.row_.dns = {'ns': ['ns.x.'], 'a': []}
        with override_settings(LOOKALIKE_HTTP=True):
            self.assertIsNone(check.check_http(self.row_, self.now, get_factory=mock.Mock(), resolve=Resolver()))


class ReportTest(Base):
    def test_abuse_report_text(self):
        user = User.objects.create(username='reporter1', email='rep@acme.test', first_name='Rita', last_name='Rep')
        row = self.row('xn--exmple-cua.com', unicode='exámple.com', fuzzers=['homoglyph', 'replacement'],
                       dns={'ns': ['ns.x.'], 'a': ['1.2.3.4'], 'mx': ['10 mail.x.net.']}, has_mx=True,
                       rdap={'registrar': 'Shady Registrar', 'created': '2026-10-18T09:30:00+00:00',
                             'abuse_email': 'abuse@shady.test', 'statuses': []},
                       ct={'count': 1, 'certs': [{'id': 7, 'date': '2026-10-20'}]},
                       http={'status': 200, 'title': 'Login', 'brand_in_page': True, 'password_field': True,
                             'location_host': None, 'checked_at': self.now.isoformat()})
        out = report.abuse_report(row, user)
        self.assertEqual(out['to'], 'abuse@shady.test')
        for needle in ('xn--exmple-cua.com', 'exámple.com', 'example.com', 'Shady Registrar', '2026-10-18', '10 mail.x.net.',
                       '1.2.3.4', 'homoglyph', 'Rita Rep', 'rep@acme.test', 'Acme', '7', 'Login'):
            self.assertIn(needle, out['body'])
        self.assertIn('xn--exmple-cua.com', out['subject'])
        row.rdap = {'registrar': 'Shady\nRegistrar', 'created': '', 'abuse_email': '', 'statuses': []}
        out = report.abuse_report(row, User(username='u2'))
        self.assertEqual(out['to'], 'Shady Registrar')
        self.assertIn('u2', out['body'])
        self.assertNotIn('\n', out['subject'])
        self.assertEqual(report.defang('a.b.com'), 'a[.]b[.]com')


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == '/ok':
            body = b'[1, 2]'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        total = 40 * 1024 * 1024 if self.path == '/huge' else 1000
        self.send_response(200)
        self.send_header('Content-Length', str(total))
        self.end_headers()
        try:
            if self.path == '/huge':
                chunk = b'1,' * 32768
                while self.server.sent < total:
                    self.wfile.write(chunk)
                    self.server.sent += len(chunk)
            else:
                for _ in range(100):
                    self.wfile.write(b'1')
                    self.wfile.flush()
                    time.sleep(0.2)
        except OSError:
            pass


class CappedFetchTest(TestCase):
    """http.get_json against a real local server: a huge body and a slow trickle are errors, never parsed."""
    def setUp(self):
        cache.clear()
        self.srv = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        self.srv.sent = 0
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def get(self, path, **kw):
        start = time.monotonic()
        out = http.get_json(f'http://127.0.0.1:{self.srv.server_port}{path}', provider='t' + path.strip('/'),
                            sleep=lambda s: None, **kw)
        return out, time.monotonic() - start

    def test_small_body_parses(self):
        self.assertEqual(self.get('/ok', max_bytes=1000)[0], (200, [1, 2]))

    def test_oversize_body_is_an_error_not_a_truncated_parse(self):
        out, took = self.get('/huge', max_bytes=1024 * 1024)
        self.assertEqual(out, (None, None))
        self.assertLess(took, 10)
        self.assertLess(self.srv.sent, 35 * 1024 * 1024)

    def test_slow_trickle_hits_the_overall_deadline_once(self):
        out, took = self.get('/slow', max_bytes=1024 * 1024, deadline=0.8)
        self.assertEqual(out, (None, None))
        self.assertLess(took, 2.5)  # not retried: three attempts would take longer

    def test_watchdog_shuts_down_through_socket_not_ssl_wrapper(self):
        # an SSLSocket's own shutdown() drops its SSL object under the reader; the watchdog must bypass it
        import socket
        wrong = []

        class Wrapped(socket.socket):
            def shutdown(self, how):
                wrong.append(how)

        a, b = socket.socketpair()
        sock = Wrapped(fileno=a.detach())
        self.addCleanup(sock.close)
        self.addCleanup(b.close)
        resp = mock.Mock()
        resp.raw._connection.sock = sock

        def slow(chunk_size):
            time.sleep(0.4)
            yield b'x'
        resp.iter_content = slow
        with self.assertRaises(http._Refused):
            http._read_capped(resp, 1024, 0.05)
        self.assertEqual(wrong, [])
        b.settimeout(2)
        self.assertEqual(b.recv(1), b'')  # the real shutdown reached the peer

    def test_callers_pass_the_cap(self):
        get = FakeGet({'/domain/': (404, {})})
        rdap.lookup('a.com', BOOTSTRAP, get)
        self.assertEqual(get.calls[0][1]['max_bytes'], http.MAX_BODY)


class HostileTextTest(SimpleTestCase):
    def test_page_regexes_are_linear(self):
        for page in ('<input ' * 40000, '<title ' * 40000, '<input type=' * 20000, '<title>' + 'x' * 250000):
            start = time.monotonic()
            check.analyse(page.encode().decode(), 'example')
            self.assertLess(time.monotonic() - start, 1)
        title, password, brand = check.analyse('<html><title> A  B </title><input type="password">example', 'example')
        self.assertEqual((title, password, brand), ('A B', True, True))
        self.assertEqual(check.analyse('x' * 20000 + '<title>late</title>', 'e')[0], '')  # only the head is searched

    def test_abuse_email_is_conservative(self):
        def mail(addr):
            obj = {'entities': [{'roles': ['abuse'], 'vcardArray': ['vcard', [['email', {}, 'text', addr]]]}]}
            return rdap.parse(obj)['abuse_email']
        self.assertEqual(mail('abuse@registrar.example'), 'abuse@registrar.example')
        self.assertEqual(mail('a.b+c@sub.registrar.co.uk'), 'a.b+c@sub.registrar.co.uk')
        for bad in ('x?bcc=attacker@evil.com', 'a&b@x.com', 'a#b@x.com', 'a%b@x.com', 'a..b@x.com', '.a@x.com', 'a@x', 'a@-x.com',
                    'a@x.com\nBcc: z@evil.com', 'a b@x.com'):
            self.assertEqual(mail(bad), '', bad)

    def test_invisible_and_control_characters_stripped(self):
        nasty = 'Bank\u202eEvil\u2066\u200b\u2028\x85\ufeff\u200fOK\x1b[31m'
        obj = {'entities': [{'roles': ['registrar'], 'vcardArray': ['vcard', [['fn', {}, 'text', nasty]]]}]}
        got = rdap.parse(obj)['registrar']
        for ch in ('\u202e', '\u2066', '\u200b', '\u2028', '\x85', '\ufeff', '\u200f', '\x1b'):
            self.assertNotIn(ch, got)
        self.assertTrue(got.startswith('Bank'))
        self.assertTrue(report.CTRL.search(nasty))
        self.assertIsNone(report.CTRL.search(report._t(nasty)))


class FixRoundTest(Base):
    def test_dns_errors_back_off_exponentially(self):
        row = self.row()
        err = Resolver({('examp1e.com', 'NS'): dns.resolver.NoNameservers()})
        seen = []
        now = self.now
        for _ in range(8):
            self.run_check(row, err, now=now)
            row.refresh_from_db()
            seen.append(row.next_check - now)
            now = row.next_check
        hours = [d.total_seconds() / 3600 for d in seen]
        self.assertEqual(hours, [1, 2, 4, 8, 16, 24, 24, 24])
        ok = Resolver({('examp1e.com', 'NS'): ['ns.x.']})
        self.run_check(row, ok, now=now)
        row.refresh_from_db()
        self.assertNotIn('fails', row.dns)

    def test_first_failed_check_then_registration_is_silent(self):
        row = self.row()
        self.run_check(row, Resolver({('examp1e.com', 'NS'): dns.resolver.NoNameservers()}))
        row.refresh_from_db()
        events = self.run_check(row, Resolver({('examp1e.com', 'NS'): ['ns.x.']}), now=self.now + timedelta(hours=2))
        self.assertEqual(events, [])
        row.refresh_from_db()
        self.assertEqual(row.status, 'registered')

    def test_http_skips_ignored_and_charges_dns_budget(self):
        row = self.row(registered=True, status='ignored', dns={'ns': ['ns.x.'], 'a': ['9.9.9.9']})
        factory = mock.Mock()
        with override_settings(LOOKALIKE_HTTP=True):
            self.assertIsNone(check.check_http(row, self.now, get_factory=factory, resolve=Resolver()))
            row.status = 'registered'
            spent = []
            resolve = Resolver({('examp1e.com', 'A'): ['9.9.9.9'], ('examp1e.com', 'AAAA'): []})
            factory.return_value.return_value = mock.Mock(status_code=200, headers={}, **{'iter_content.return_value': iter([b''])})
            check.check_http(row, self.now, get_factory=factory, resolve=resolve, spend=lambda k: spent.append(k) or True)
            self.assertEqual(spent, ['dns', 'dns'])
            row.http = None
            with self.assertRaises(check.Stop):
                check.check_http(row, self.now, get_factory=factory, resolve=resolve, spend=lambda k: False)


@override_settings(LOOKALIKE_ENABLED=True, CONTINUOUS_SCANS=True, LOOKALIKE_DNS_DAILY_BUDGET=BIG_BUDGET, RDAP_DAILY_BUDGET=BIG_BUDGET)
class FixTickTest(Base):
    def tick(self, resolve=None, get=None):
        with mock.patch.object(collect, '_resolve', resolve or Resolver()), \
                mock.patch.object(http, 'get_json', get or FakeGet()), \
                mock.patch('limes.feeds.store.load', return_value=(BOOTSTRAP, {})):
            return tasks.lookalike_tick.run()

    def generate(self, get, candidates=()):
        with mock.patch.object(http, 'get_json', get), mock.patch.object(generate, 'candidates', return_value=list(candidates)):
            return tasks.generate_lookalikes.run()

    def test_first_successful_ct_run_after_baseline_is_silent(self):
        self.baseline()
        ct = FakeGet({'crt.sh': (200, [{'id': 1, 'name_value': 'examp1e-login.net'}])})
        self.generate(ct)
        self.assertEqual(Lookalike.objects.filter(source='ct').count(), 1)
        table = {('examp1e-login.net', 'NS'): ['ns.x.'], ('examp1e-login.net', 'MX'): ['10 m.x.']}
        out = self.tick(Resolver(table), FakeGet({'/domain/': (200, rdap_fixture(self.now - timedelta(days=2)))}))
        self.assertEqual((out['checked'], out['events']), (1, 0))
        self.assertEqual(Lookalike.objects.get(source='ct').status, 'registered')
        # a later CT run finds a new name: that one is news
        from limes.tasks import intel
        self.root.refresh_from_db()
        old = (self.now - timedelta(days=2)).isoformat()
        tasks._state(self.root, ct_at=old)
        self.generate(FakeGet({'crt.sh': (200, [{'id': 2, 'name_value': 'examp1e-pay.net'}])}))
        table = {('examp1e-pay.net', 'NS'): ['ns.x.']}
        out = self.tick(Resolver(table), FakeGet({'/domain/': (200, rdap_fixture(self.now - timedelta(days=200)))}))
        self.assertEqual(out['events'], 1)

    def test_owned_now_is_ours_and_not_checked(self):
        self.baseline()
        a = self.row('examp1e.com')
        b = self.row('www.examp1e.net')
        Asset.objects.create(project=self.p, kind='hostname', value='examp1e.com', scope_tier='owned_host', parent=self.root)
        Asset.objects.create(project=self.p, kind='root_domain', value='examp1e.net', scope_tier='owned_root')
        resolve = Resolver({('examp1e.com', 'NS'): ['ns.x.'], ('www.examp1e.net', 'NS'): ['ns.x.']})
        out = self.tick(resolve)
        self.assertEqual(resolve.calls, [])
        self.assertEqual(out['events'], 0)
        for r in (a, b):
            r.refresh_from_db()
            self.assertEqual(r.status, 'ours')

    def test_generate_stops_cleanly_and_resumes_least_recent_first(self):
        roots = [self.root] + [Asset.objects.create(project=self.p, kind='root_domain', value=f'r{i}.com', scope_tier='owned_root')
                               for i in (1, 2)]
        clock = [0.0]
        order = []

        def slow(root, keywords=(), exclude=frozenset()):
            order.append(root)
            clock[0] += 400
            return []
        with mock.patch.object(tasks, '_clock', lambda: clock[0]), mock.patch.object(generate, 'candidates', slow), \
                mock.patch.object(http, 'get_json', FakeGet()):
            first = tasks.generate_lookalikes.run()
            ran_first = list(order)
            clock[0] = 0
            del order[:]
            second = tasks.generate_lookalikes.run()
        self.assertEqual((len(ran_first), first['deferred']), (2, 1))
        skipped = ({r.value for r in roots} - set(ran_first)).pop()
        self.assertEqual(order[0], skipped)  # the root that never got its turn goes first
        self.assertEqual(second['deferred'], 1)

    def test_soft_time_limit_still_propagates(self):
        from celery.exceptions import SoftTimeLimitExceeded
        with mock.patch.object(generate, 'candidates', side_effect=SoftTimeLimitExceeded), mock.patch.object(http, 'get_json', FakeGet()):
            with self.assertRaises(SoftTimeLimitExceeded):
                tasks.generate_lookalikes.run()
