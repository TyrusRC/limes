import base64
import json
import logging
import os
import shutil
import tempfile
import time
from datetime import timedelta
from unittest import mock

from celery.exceptions import SoftTimeLimitExceeded
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import hibp
from limes.checks import leak
from limes.tasks import stages
from startScan.models import Asset, ChangeEvent, DomainBreach, RiskCheck


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')


def jwt(role='service_role'):
    return '.'.join([_b64({'alg': 'HS256'}), _b64({'role': role, 'iss': 'supabase'}), 'SIGNATUREpartZZ1234'])


SB = 'sb_secret_' + 'Ab3dEf6hJk9mNp2qRs5tUv8xYz0123'


# a JWT whose payload is nested far past the JSON parser's recursion limit
HOSTILE = '.'.join([_b64({'alg': 'x'}), _b64('{"a":' + '[' * 3000 + ']' * 3000 + '}'), 'SIGNATUREpartZZ1234'])


class ScanTextTest(SimpleTestCase):
    def test_service_role_jwt_detected_key_never_stored(self):
        tok = jwt()
        out = leak.scan_text(f'var k="{tok}";')['secrets']
        self.assertEqual([s['kind'] for s in out], ['jwt_service_role'])
        shape = out[0]['shape']
        self.assertEqual(shape, 'JWT(service_role)…' + tok[-4:])
        for part in tok.split('.'):
            self.assertNotIn(part, shape)
        self.assertEqual(leak.scan_text(f'"{jwt("anon")}"')['secrets'], [])
        self.assertEqual(leak.scan_text('eyJ!!!!!!!!!!!!.eyJ??????????????.xxxxxxxxxxxx')['secrets'], [])
        broken = 'eyJhbGciOiJIUzI1NiJ9AAAA.eyJ0AAAAAAAAAAAA.SIGNATUREpartZZ1234'
        self.assertEqual(leak.scan_text(broken)['secrets'], [])

    def test_sb_secret_and_publishable(self):
        out = leak.scan_text(f'x="{SB}"')['secrets']
        self.assertEqual(out, [{'kind': 'sb_secret', 'shape': 'sb_secret_…' + SB[-4:]}])
        self.assertNotIn(SB[10:20], out[0]['shape'])
        self.assertEqual(leak.scan_text('sb_publishable_' + 'A' * 30)['secrets'], [])

    def test_placeholders_escapes_and_hostile_input(self):
        self.assertEqual(leak.scan_text('sb_secret_' + 'x' * 20)['secrets'], [])
        self.assertEqual(leak.scan_text('sb_secret_your_key_here_please')['secrets'], [])
        # sourcesContent: the key follows a JSON-escaped newline / tab
        for esc in ('\\n', '\\t'):
            self.assertEqual(len(leak.scan_text(f'a{esc}{SB}')['secrets']), 1, esc)
            self.assertEqual(len(leak.scan_text(f'a{esc}{jwt()}')['secrets']), 1, esc)
        self.assertEqual(leak.scan_text(f'"{HOSTILE}" "{SB}"')['secrets'][0]['kind'], 'sb_secret')

    def test_no_quadratic_blowup(self):
        for text in ('-eyJ' * 50000, 'https://' + 'a.s3' * 50000, 'https://' * 25000, 'eyJ' + 'a' * 200000,
                     ('eyJaaaaaaaaaaaa.' * 12500)):
            t = time.monotonic()
            leak.scan_text(text)
            self.assertLess(time.monotonic() - t, 1.0, text[:20])

    def test_backends(self):
        text = 'https://abcd.supabase.co/rest/v1 https://x-default-rtdb.firebaseio.com/ https://bkt.s3.amazonaws.com/a'
        kinds = {b['kind'] for b in leak.scan_text(text)['backends']}
        self.assertEqual(kinds, {'supabase', 'firebase', 's3'})
        many = ' '.join(f'https://p{i}.supabase.co' for i in range(50))
        self.assertEqual(len(leak.scan_text(many)['backends']), 20)


class ScanArtifactsTest(TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.now = timezone.now()
        self.p = Project.objects.create(name='p', slug='p', insert_date=self.now)
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.app = Asset.objects.create(project=self.p, kind='hostname', value='app.x.com', scope_tier='owned_host', parent=self.root)
        self.www = Asset.objects.create(project=self.p, kind='hostname', value='www.x.com', scope_tier='owned_host', parent=self.root)

    def put(self, name, text):
        with open(os.path.join(self.dir, name), 'w') as f:
            f.write(text)

    def test_scan_artifacts_writes_on_owned_host_only(self):
        tok = jwt()
        body = f'const a="{tok}"; const b="{SB}"; fetch("https://proj1.supabase.co/rest/v1/")'
        self.put('a.js', body)
        self.put('b.js', body)
        self.put('c.js', 'console.log(1)')
        mapping = {'a.js': 'https://app.x.com/a.js?v=1', 'b.js': 'https://cdn.other.net/b.js', 'c.js': 'https://www.x.com/c.js'}
        with self.assertLogs(level='DEBUG') as logs:
            logging.getLogger('limes.checks.leak').debug('start')
            out = leak.scan_artifacts(self.dir, mapping, self.p, self.now)
        self.assertEqual(out, {'hosts': 2, 'secrets': 2})
        rc = {r.asset.value: r for r in RiskCheck.objects.filter(check_id='leak.supabase_secret_key')}
        self.assertEqual(set(rc), {'app.x.com', 'www.x.com'})
        self.assertEqual(rc['app.x.com'].status, 'fail')
        self.assertEqual(rc['www.x.com'].status, 'pass')
        self.assertEqual(rc['app.x.com'].evidence['artifact_url'], 'https://app.x.com/a.js')
        self.assertEqual(Asset.objects.get(value='app.x.com').enrichment['backends']['items'],
                         [{'kind': 'supabase', 'ref': 'https://proj1.supabase.co'}])
        dump = json.dumps([list(RiskCheck.objects.values()), list(Asset.objects.values('enrichment')),
                           [r.getMessage() for r in logs.records]], default=str)
        for secret in (tok, SB, tok.split('.')[2], SB[10:]):
            self.assertNotIn(secret, dump)
        self.assertFalse(Asset.objects.filter(value='cdn.other.net').exists())

    def test_hostile_jwt_and_unowned_files_do_not_stop_others(self):
        self.put('h.js', f'"{HOSTILE}"')
        self.put('a.js', f'"{SB}"')
        self.put('m.mjs', f'"{SB}"')
        self.put('b.js', f'"{SB}"')
        mapping = {'h.js': 'https://www.x.com/h.js', 'a.js': 'https://user:pw@app.x.com/a.js', 'b.js': 'https://cdn.other.net/b.js'}
        real = leak._read
        with mock.patch.object(leak, '_read', side_effect=real) as rd:
            out = leak.scan_artifacts(self.dir, mapping, self.p, self.now)
        self.assertEqual([c.args[0].endswith('b.js') for c in rd.call_args_list].count(True), 0)  # unowned: never read
        self.assertEqual(out['hosts'], 2)
        self.assertEqual(RiskCheck.objects.get(asset=self.app, check_id='leak.supabase_secret_key').evidence['artifact_url'],
                         'https://app.x.com/a.js')
        self.assertEqual(RiskCheck.objects.get(asset=self.www, check_id='leak.supabase_secret_key').status, 'pass')
        # one file raising must not stop the next
        with mock.patch.object(leak, '_read', side_effect=lambda path: (_ for _ in ()).throw(RecursionError()) if path.endswith('h.js') else f'"{SB}"'):
            leak.scan_artifacts(self.dir, {'h.js': 'https://www.x.com/h.js', 'a.js': 'https://app.x.com/a.js'}, self.p, self.now)
        self.assertEqual(RiskCheck.objects.get(asset=self.app, check_id='leak.supabase_secret_key').status, 'fail')

    def test_mjs_scanned(self):
        self.put('m.mjs', f'"{SB}"')
        leak.scan_artifacts(self.dir, {'m.mjs': 'https://app.x.com/m.mjs'}, self.p, self.now)
        self.assertEqual(RiskCheck.objects.get(asset=self.app, check_id='leak.supabase_secret_key').status, 'fail')

    def test_fixed_key_flips_to_pass(self):
        self.put('a.js', f'"{SB}"')
        leak.scan_artifacts(self.dir, {'a.js': 'https://app.x.com/a.js'}, self.p, self.now)
        self.put('a.js', 'clean')
        leak.scan_artifacts(self.dir, {'a.js': 'https://app.x.com/a.js'}, self.p, self.now)
        self.assertEqual(RiskCheck.objects.get(asset=self.app, check_id='leak.supabase_secret_key').status, 'pass')

    def test_retired_or_unowned_asset_ignored(self):
        self.app.state = 'retired'
        self.app.save()
        self.put('a.js', f'"{SB}"')
        out = leak.scan_artifacts(self.dir, {'a.js': 'https://app.x.com/a.js'}, self.p, self.now)
        self.assertEqual(out, {'hosts': 0, 'secrets': 0})


class CodeAuditTest(TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        with open(f'{self.dir}/code_artifacts.json', 'w') as f:
            json.dump({'a.js': 'https://app.x.com/a.js'}, f)
        for attr, val in (('results_dir', self.dir), ('domain', mock.Mock(project=mock.sentinel.project))):
            p = mock.patch.object(stages.code_audit, attr, val, create=True)
            p.start()
            self.addCleanup(p.stop)

    def test_code_audit_runs_leak_scan_even_if_mantis_fails(self):
        with mock.patch.object(stages.mantis, 'audit_dir', side_effect=stages.mantis.MantisError('boom')), \
                mock.patch.object(stages.leak, 'scan_artifacts') as scan:
            self.assertEqual(stages.code_audit.run(), 0)
        scan.assert_called_once()
        self.assertEqual(scan.call_args[0][0], f'{self.dir}/code_artifacts')
        with mock.patch.object(stages.mantis, 'audit_dir', return_value=[]), \
                mock.patch.object(stages.leak, 'scan_artifacts', side_effect=RuntimeError('x')):
            self.assertEqual(stages.code_audit.run(), 0)

    def test_code_audit_reraises_soft_time_limit(self):
        with mock.patch.object(stages.mantis, 'audit_dir') as audit, \
                mock.patch.object(stages.leak, 'scan_artifacts', side_effect=SoftTimeLimitExceeded()):
            with self.assertRaises(SoftTimeLimitExceeded):
                stages.code_audit.run()
        audit.assert_not_called()


class FakeGet:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        for suffix, resp in self.routes.items():
            if url.endswith(suffix):
                return resp
        return None, None


KEY = 'HIBPKEYsecret0123456789abcdef'


@override_settings(HIBP_API_KEY=KEY, CONTINUOUS_SCANS=True)
class HibpTest(TestCase):
    def setUp(self):
        cache.clear()
        self.now = timezone.now()
        self.p = Project.objects.create(name='p', slug='p', insert_date=self.now)
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.recent = (self.now - timedelta(days=30)).date().isoformat()
        self.routes = {
            'latestbreach': (200, {'Name': 'Adobe'}),
            'breachedDomain/x.com': (200, {'alice': ['Adobe'], 'bob': ['Adobe', 'Canva']}),
            'breach/Adobe': (200, {'BreachDate': self.recent, 'AddedDate': self.now.isoformat()}),
            'breach/Canva': (200, {'BreachDate': '2019-05-24', 'AddedDate': '2019-08-01T00:00:00Z'}),
        }

    def run_sync(self, routes=None, now=None):
        get = FakeGet(routes or self.routes)
        self.last_calls = get.calls
        with mock.patch.object(hibp.http, 'get_json', get):
            return hibp.hibp_sync.run(), get

    @override_settings(HIBP_API_KEY='')
    def test_hibp_off_without_key(self):
        out, get = self.run_sync()
        self.assertEqual(out, {'reason': 'no key'})
        self.assertEqual(get.calls, [])

    def test_hibp_counts_only_no_aliases(self):
        with self.assertLogs(level='DEBUG') as logs:
            logging.getLogger('x').debug('start')
            _, get = self.run_sync()
        self.assertTrue(all(kw['headers'] == {'hibp-api-key': KEY} and kw['provider'] == 'hibp' for _, kw in get.calls))
        self.assertEqual({b.breach_name: b.addresses for b in DomainBreach.objects.all()}, {'Adobe': 2, 'Canva': 1})
        dump = json.dumps([list(DomainBreach.objects.values()), list(ChangeEvent.objects.values()),
                           list(RiskCheck.objects.values()), list(Asset.objects.values('enrichment')),
                           [r.getMessage() for r in logs.records]], default=str)
        for needle in ('alice', 'bob', KEY):
            self.assertNotIn(needle, dump)

    def test_hibp_first_sync_silent_then_breach_new_digest(self):
        self.run_sync()
        self.assertEqual(ChangeEvent.objects.filter(kind='breach_new').count(), 0)
        rc = RiskCheck.objects.get(asset=self.root, check_id='leak.hibp_breach')
        self.assertEqual(rc.status, 'fail')
        routes = {**self.routes, 'latestbreach': (200, {'Name': 'Zed'}),
                  'breachedDomain/x.com': (200, {'alice': ['Adobe', 'Zed']}),
                  'breach/Zed': (200, {'BreachDate': '2020-01-01', 'AddedDate': '2020-02-01T00:00:00Z'})}
        self.run_sync(routes)
        ev = ChangeEvent.objects.get(kind='breach_new')
        self.assertFalse(ev.immediate)
        self.assertEqual(ev.title, 'New breach Zed affects 1 addresses at x.com')
        # all older than a year: pass
        old = {**routes, 'breach/Adobe': (200, {'BreachDate': '2015-01-01', 'AddedDate': '2015-01-02T00:00:00Z'})}
        Asset.objects.filter(pk=self.root.pk).update(enrichment={})  # force a fresh run
        DomainBreach.objects.filter(breach_name='Adobe').update(published=None)
        self.run_sync({**old, 'breachedDomain/x.com': (200, {'alice': ['Zed']})})
        self.assertEqual(RiskCheck.objects.get(asset=self.root, check_id='leak.hibp_breach').status, 'pass')

    def test_hibp_403_error_not_pass(self):
        self.run_sync({**self.routes, 'breachedDomain/x.com': (403, None)})
        rc = RiskCheck.objects.get(asset=self.root, check_id='leak.hibp_breach')
        self.assertEqual((rc.status, rc.evidence), ('error', {'reason': 'domain not verified with HIBP'}))

    def test_budget_exhausted_mid_root_keeps_counts_and_does_not_starve_next_root(self):
        names = [f'B{i}' for i in range(60)]
        two = Asset.objects.create(project=self.p, kind='root_domain', value='y.com', scope_tier='owned_root')
        routes = {'latestbreach': (200, {'Name': 'B0'}),
                  'breachedDomain/x.com': (200, {'a': names}),
                  'breachedDomain/y.com': (200, {'a': ['Only']}),
                  'breach/Only': (200, {'BreachDate': '2021-01-01', 'AddedDate': '2021-01-02T00:00:00Z'})}
        for n in names:
            routes[f'breach/{n}'] = (200, {'BreachDate': '2021-01-01', 'AddedDate': '2021-01-02T00:00:00Z'})
        calls = {'n': 0}

        def take(provider, limit):
            calls['n'] += 1
            return calls['n'] <= 50
        with mock.patch.object(hibp.ratelimit, 'take_daily', side_effect=take):
            out, _ = self.run_sync(routes)
        self.assertEqual(out['stopped'], 'budget')
        self.assertEqual(DomainBreach.objects.filter(root=self.root).count(), 60)  # counts kept, dates pending
        self.assertEqual(RiskCheck.objects.get(asset=self.root, check_id='leak.hibp_breach').status, 'error')
        calls['n'] = 0  # next day: the dated root is no longer first in line, the pending dates fill in
        with mock.patch.object(hibp.ratelimit, 'take_daily', side_effect=take):
            self.run_sync(routes)
        self.assertTrue(DomainBreach.objects.filter(root=two).exists())
        calls['n'] = 0
        with mock.patch.object(hibp.ratelimit, 'take_daily', side_effect=take):
            self.run_sync(routes)
        self.assertFalse(DomainBreach.objects.filter(root=self.root, published__isnull=True).exists())

    def test_401_stops_run_and_logs_key_rejected_without_key(self):
        with self.assertLogs('limes.hibp', 'WARNING') as logs:
            out, get = self.run_sync({'latestbreach': (401, {'message': 'bad'})})
        self.assertEqual(out['stopped'], 'key rejected')
        self.assertEqual(len(get.calls), 1)
        self.assertEqual(sum('key rejected' in m for m in logs.output), 1)
        self.assertNotIn(KEY, ' '.join(logs.output))

    def test_unsafe_breach_names_ignored(self):
        routes = {**self.routes, 'breachedDomain/x.com': (200, {'a': ['..', '../x', '.hid', 'Ok_1', 'a..b']})}
        self.run_sync(routes)
        self.assertEqual(set(DomainBreach.objects.values_list('breach_name', flat=True)), {'Ok_1'})
        self.assertTrue(all('..' not in u for u, _ in self.last_calls))

    def test_unsafe_latest_name_ignored(self):
        out, get = self.run_sync({**self.routes, 'latestbreach': (200, {'Name': '../../etc'})})
        self.assertEqual(out['reason'], 'no latest breach')
        self.assertEqual(len(get.calls), 1)

    def test_hibp_budget_exhausted_stops(self):
        with mock.patch.object(hibp.ratelimit, 'take_daily', return_value=False):
            _, get = self.run_sync()
        self.assertEqual(get.calls, [])
        self.assertFalse(DomainBreach.objects.exists())
        self.assertFalse(RiskCheck.objects.exists())


class BreachApiTest(TestCase):
    def test_root_detail_lists_breaches(self):
        from rest_framework.test import APIClient
        now = timezone.now()
        p = Project.objects.create(name='p', slug='p', insert_date=now)
        root = Asset.objects.create(project=p, kind='root_domain', value='x.com', scope_tier='owned_root')
        DomainBreach.objects.create(project=p, root=root, breach_name='Adobe', addresses=3)
        from django.contrib.auth import get_user_model
        from django.contrib.auth.signals import user_logged_in
        from dashboard.views import on_user_logged_in
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        c = APIClient()
        c.force_login(get_user_model().objects.create_user('u', password='p'))
        r = c.get(f'/api/listDatatableAsset/{root.pk}/?project=p')
        self.assertEqual(r.status_code, 200, r.content[:200])
        self.assertEqual(r.json()['breaches'], [{'name': 'Adobe', 'addresses': 3, 'breach_date': None, 'published': None}])
