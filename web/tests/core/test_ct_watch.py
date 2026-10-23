import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone as dt_tz
from unittest import mock

from django.core.cache import cache
from django.db import OperationalError
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from django_redis import get_redis_connection

from dashboard.models import Project
from limes.ct import hook, ingest, match, watch
from startScan.models import Asset, CertSighting

TBS = 'ab' * 32


class HookTest(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spool = os.path.join(self.tmp.name, 'spool')
        self.src = os.path.join(self.tmp.name, 'cert.json')

    def cert(self, names=('a.x.com',), **kw):
        with open(self.src, 'w') as f:
            json.dump({'dns_names': list(names), **kw}, f)
        return {'EVENT': 'discovered_cert', 'TBS_SHA256': TBS, 'JSON_FILENAME': self.src}

    def files(self, sub=''):
        d = os.path.join(self.spool, sub)
        return sorted(n for n in os.listdir(d)) if os.path.isdir(d) else []

    def test_hook_writes_atomically(self):
        env = self.cert([f'h{i}.x.com' for i in range(1500)])
        env.update({'ISSUER_DN': 'O=X\n%s' % ('y' * 900), 'NOT_BEFORE_RFC3339': '2026-10-01T00:00:00Z',
                    'NOT_AFTER_RFC3339': '2027-01-01T00:00:00Z'})
        self.assertEqual(hook.main(env, self.spool), 0)
        self.assertEqual([n for n in self.files() if not n.startswith('_')], ['.tmp', TBS + '.json'])
        self.assertEqual(self.files('.tmp'), [])
        with open(os.path.join(self.spool, TBS + '.json'), 'rb') as f:
            raw = f.read()
        rec = ingest.parse_record(raw)
        self.assertIsNotNone(rec)
        self.assertLessEqual(len(rec['issuer_dn']), 500)
        data = json.loads(raw)
        self.assertEqual(len(data['dns_names']), 1000)
        self.assertEqual(data['names_total'], 1500)
        self.assertEqual(data['not_before'], '2026-10-01T00:00:00Z')

    def test_hook_refuses_bad_hash(self):
        for bad in ('../../x', 'AB' * 32, ''):
            env = self.cert()
            env['TBS_SHA256'] = bad
            self.assertEqual(hook.main(env, self.spool), 0)
        self.assertEqual([n for n in self.files() if n.endswith('.json')], [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, 'x')))

    def test_hook_exits_zero_on_garbage(self):
        cases = []
        env = self.cert()
        env['JSON_FILENAME'] = os.path.join(self.tmp.name, 'missing.json')
        cases.append(env)
        big = os.path.join(self.tmp.name, 'big.json')
        with open(big, 'w') as f:
            f.write(json.dumps({'dns_names': ['a.x.com'], 'pad': 'z' * 300 * 1024}))
        cases.append({**env, 'JSON_FILENAME': big})
        link = os.path.join(self.tmp.name, 'link.json')
        self.cert()
        os.symlink(self.src, link)
        cases.append({**env, 'JSON_FILENAME': link})
        bad = os.path.join(self.tmp.name, 'bad.json')
        with open(bad, 'w') as f:
            f.write('{nope')
        cases.append({**env, 'JSON_FILENAME': bad})
        cases.append({**self.cert(), 'EVENT': 'something_else'})
        for e in cases:
            self.assertEqual(hook.main(e, self.spool), 0)
        self.assertEqual([n for n in self.files() if n.endswith('.json')], [])
        self.assertEqual(hook.main({'EVENT': 'error', 'SUMMARY': 'e' * 5000}, self.spool), 0)
        (name,) = self.files('_health')
        self.assertTrue(name[:-5].isdigit())
        with open(os.path.join(self.spool, '_health', name)) as f:
            rec = json.load(f)
        self.assertEqual(len(rec['summary']), 2048)
        self.assertEqual(rec['event'], 'error')

    def test_hook_is_executable_with_isolated_shebang(self):
        self.assertTrue(os.access(watch.HOOK_PATH, os.X_OK))
        with open(watch.HOOK_PATH) as f:
            self.assertEqual(f.readline().rstrip('\n'), '#!/usr/bin/python3 -I')
        env = {**self.cert(), 'LIMES_CT_SPOOL': self.spool}
        r = subprocess.run([watch.HOOK_PATH], env=env, capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(TBS + '.json', self.files())


@override_settings(CONTINUOUS_SCANS=True)
class WatchlistTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())

    def asset(self, kind, value, tier, **kw):
        return Asset.objects.create(project=self.p, kind=kind, value=value, scope_tier=tier, **kw)

    def test_watchlist_cap_and_order(self):
        self.asset('root_domain', 'x.com', 'owned_root')
        self.asset('root_domain', 'co.uk', 'owned_root')
        self.asset('root_domain', 'off.com', 'owned_root', cadence_tier='off')
        self.asset('hostname', 'app.vendor.com', 'owned_host')
        self.asset('hostname', 'www.x.com', 'owned_host')
        look = [(self.p.id, 'l2.com'), (self.p.id, 'l1.com')]
        with mock.patch('limes.ct.lookalikes.watched', return_value=look):
            lines, dropped, h = watch.watchlist(max_entries=100)
            self.assertEqual(lines, ['.x.com', 'app.vendor.com', '.l1.com', '.l2.com'])
            self.assertEqual(dropped, 0)
            self.assertEqual(watch.watchlist(max_entries=100)[2], h)
            small, dropped, _ = watch.watchlist(max_entries=2)
            self.assertEqual(small, ['.x.com', 'app.vendor.com'])
            self.assertEqual(dropped, 2)
            self.asset('root_domain', 'y.com', 'owned_root')
            self.assertNotEqual(watch.watchlist(max_entries=100)[2], h)
            roots_only, dropped, _ = watch.watchlist(max_entries=1)  # roots are never dropped
            self.assertEqual(roots_only, ['.x.com', '.y.com'])
            self.assertEqual(dropped, 3)


class FakeProc:
    def __init__(self, argv, kw):
        self.argv, self.kw, self.rc, self.terminated, self.killed = argv, kw, None, 0, 0

    def poll(self):
        return self.rc

    def terminate(self):
        self.terminated += 1

    def kill(self):
        self.killed += 1

    def wait(self, timeout=None):
        self.rc = 0
        return 0


class FakePopen:
    def __init__(self):
        self.procs = []

    def __call__(self, argv, **kw):
        p = FakeProc(argv, kw)
        self.procs.append(p)
        return p


class SupervisorTest(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.r = get_redis_connection('default')
        self.r.delete(watch.HEARTBEAT)
        self.addCleanup(self.r.delete, watch.HEARTBEAT)
        self.t = [0.0]
        self.popen = FakePopen()
        self.wl = (['.x.com'], 0, 'h1')
        self.sup = watch.Supervisor(popen=self.popen, clock=lambda: self.t[0], wall=lambda: 1_800_000_000 + self.t[0])
        for target, ret in (('watchlist', None), ('drain_spool', {'ingested': 0, 'invalid': 0, 'failed': 0, 'depth': 0, 'projects': set()}),
                            ('read_health', None), ('close_old_connections', None)):
            p = mock.patch.object(watch, target, side_effect=(lambda *a, **k: self.wl) if target == 'watchlist' else None,
                                  return_value=ret)
            p.start()
            self.addCleanup(p.stop)
        o = override_settings(CT_STATE_DIR=self.tmp.name, CT_WATCH=True, CONTINUOUS_SCANS=True, CT_WATCH_RESTART_MIN=300)
        o.enable()
        self.addCleanup(o.disable)
        self.now = datetime(2026, 10, 23, tzinfo=dt_tz.utc)

    def test_supervisor_restarts_on_change_rate_limited(self):
        hb = self.sup.step(self.now)
        (proc,) = self.popen.procs
        self.assertEqual(proc.argv, watch.command(watch.paths(), watch.paths()['watchlist']))
        self.assertIsInstance(proc.argv, list)
        self.assertNotIn('shell', proc.kw)
        self.assertNotIn('LIMES_SECRET_KEY', proc.kw['env'])  # the child never inherits the app's secrets
        self.assertEqual(hb['state'], 'running')
        with open(watch.paths()['watchlist']) as f:
            self.assertEqual(f.read().split(), ['.x.com'])
        self.wl = (['.x.com', '.y.com'], 0, 'h2')
        self.t[0] = 100
        self.sup.step(self.now)
        self.assertEqual((len(self.popen.procs), proc.terminated), (1, 0))
        self.t[0] = 301
        hb = self.sup.step(self.now)
        self.assertEqual((len(self.popen.procs), proc.terminated), (2, 1))
        with open(watch.paths()['watchlist']) as f:
            self.assertEqual(f.read().split(), ['.x.com', '.y.com'])
        self.assertEqual(hb['watchlist_hash'], 'h2')
        self.popen.procs[1].rc = 1  # the child dies
        self.t[0] = 310
        hb = self.sup.step(self.now)
        self.assertEqual(len(self.popen.procs), 3)
        self.assertGreaterEqual(hb['restarts_10m'], 1)
        with override_settings(CT_WATCH=False):
            hb = self.sup.step(self.now)
        self.assertEqual(hb['state'], 'off')
        self.assertEqual(self.popen.procs[2].terminated, 1)

    def test_empty_watchlist_is_idle(self):
        self.wl = ([], 0, 'e')
        self.assertEqual(self.sup.step(self.now)['state'], 'idle')
        self.assertEqual(self.popen.procs, [])

    def test_heartbeat_and_health_exit(self):
        self.assertEqual(watch.health_exit_code(self.now), 1)  # missing
        hb = self.sup.step(timezone.now())
        self.assertLessEqual(self.r.ttl(watch.HEARTBEAT), 600)
        self.assertGreater(self.r.ttl(watch.HEARTBEAT), 0)
        self.assertEqual(hb['pid_alive'], True)
        at = datetime.fromtimestamp(1_800_000_000, dt_tz.utc)
        self.assertEqual(watch.health_exit_code(at + timedelta(seconds=10)), 0)
        self.assertEqual(watch.health_exit_code(at + timedelta(seconds=200)), 1)


class SpoolBase(TestCase):
    def setUp(self):
        cache.clear()
        self.r = get_redis_connection('default')
        self.wipe()
        self.addCleanup(self.wipe)
        watch._FAILS.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spool = os.path.join(self.tmp.name, 'spool')
        os.makedirs(os.path.join(self.spool, '.tmp'))
        self.now = timezone.now()
        self.p = Project.objects.create(name='p', slug='p', insert_date=self.now)
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')

    def wipe(self):
        for pat in ('limes:evq*', 'limes:ct:*'):
            for k in self.r.scan_iter(pat):
                self.r.delete(k)

    def put(self, i, names=None, mtime=None, name=None):
        tbs = f'{i:064x}'
        path = os.path.join(self.spool, name or tbs + '.json')
        with open(path, 'w') as f:
            json.dump({'v': 1, 'tbs_sha256': tbs, 'cert_sha256': None, 'dns_names': names or [f'h{i}.x.com'],
                       'issuer_dn': 'O=LE', 'entry_index': i}, f)
        if mtime:
            os.utime(path, (mtime, mtime))
        return path

    def drain(self, limit=50, **kw):
        with self.captureOnCommitCallbacks(execute=True):
            return watch.drain_spool(self.spool, limit, self.now, **kw)


class SpoolTest(SpoolBase):
    def test_spool_refuses_links_and_oversize(self):
        target = os.path.join(self.tmp.name, 'victim.txt')
        with open(target, 'w') as f:
            f.write('keep')
        os.symlink(target, os.path.join(self.spool, f'{1:064x}.json'))
        with open(os.path.join(self.spool, '..evil.json'), 'w') as f:
            f.write('{}')
        with open(os.path.join(self.spool, 'notes.txt'), 'w') as f:
            f.write('x')
        with open(os.path.join(self.spool, f'{2:064x}.json'), 'w') as f:
            f.write(' ' * (1024 * 1024))
        stale = os.path.join(self.spool, '.tmp', 'old')
        fresh = os.path.join(self.spool, '.tmp', 'new')
        for p in (stale, fresh):
            open(p, 'w').close()
        os.utime(stale, (1, 1))
        self.put(3)
        res = self.drain()
        self.assertEqual(res['ingested'], 1)
        self.assertGreaterEqual(res['invalid'], 2)
        self.assertEqual(os.listdir(self.spool).count('notes.txt'), 0)
        self.assertEqual(sorted(n for n in os.listdir(self.spool)), ['.tmp'])
        with open(target) as f:
            self.assertEqual(f.read(), 'keep')
        self.assertFalse(os.path.exists(stale))
        self.assertTrue(os.path.exists(fresh))
        self.assertEqual(CertSighting.objects.count(), 1)

    def test_spool_rate_and_order(self):
        for i in range(1, 121):
            self.put(i, mtime=1_000_000 + (121 - i))  # higher i = older
        res = self.drain()
        self.assertEqual((res['ingested'], res['depth']), (50, 70))
        left = sorted(n for n in os.listdir(self.spool) if n != '.tmp')
        self.assertEqual(len(left), 70)
        self.assertNotIn(f'{120:064x}.json', left)  # the oldest went first
        self.assertIn(f'{1:064x}.json', left)
        self.assertEqual(res['projects'], {self.p.id})

    def test_crash_between_commit_and_delete(self):
        path = self.put(7)
        with open(path, 'rb') as f:
            raw = f.read()
        self.drain()
        sightings = CertSighting.objects.count()
        queued = self.r.zcard('limes:evq')
        with open(path, 'wb') as f:  # the unlink never happened
            f.write(raw)
        res = self.drain()
        self.assertEqual(CertSighting.objects.count(), sightings)
        self.assertEqual(self.r.zcard('limes:evq'), queued)
        self.assertEqual(res['projects'], set())
        self.assertFalse(os.path.exists(path))

    def test_db_error_keeps_file_then_gives_up(self):
        path = self.put(9)
        with mock.patch.object(watch.ingest, 'ingest', side_effect=OperationalError('down')):
            for _ in range(2):
                res = self.drain()
                self.assertEqual(res['failed'], 1)
                self.assertTrue(os.path.exists(path))
            self.drain()
        self.assertFalse(os.path.exists(path))
