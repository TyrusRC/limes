import json
import os
from datetime import timedelta
from unittest import mock

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import owned_ranges as r
from limes.alerts import issues
from limes.intel import ratelimit, ripestat
from startScan.models import Asset, ChangeEvent, IssueSyncState

FX = os.path.join(os.path.dirname(__file__), 'fixtures')


def load(name):
    with open(os.path.join(FX, name)) as f:
        return json.load(f)


class Get:
    """get_json stand-in: prefixes for RIPEstat, InternetDB data by ip ({ip: body}; missing = 404)."""
    def __init__(self, prefixes=None, idb=None, ripe_status=200, idb_status=None):
        self.prefixes, self.idb, self.ripe_status, self.idb_status, self.calls = prefixes, idb or {}, ripe_status, idb_status, []

    def __call__(self, url, *, provider):
        self.calls.append((provider, url))
        if provider == 'ripestat':
            body = {'data': {'prefixes': [{'prefix': p} for p in (self.prefixes or [])]}}
            return (self.ripe_status, body if self.ripe_status == 200 else None)
        if self.idb_status is not None:
            return self.idb_status, None
        ip = url.rsplit('/', 1)[1]
        if ip in self.idb:
            return 200, {'ip': ip, **self.idb[ip]}
        return 404, {'detail': 'No information available'}

    def n(self, provider):
        return sum(1 for p, _ in self.calls if p == provider)


def resolver(ptrs=None):
    ptrs = ptrs or {}
    calls = []

    def resolve(name, rdtype):
        calls.append(name)
        for ip, names in ptrs.items():
            if name.startswith('.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'):
                return [n + '.' for n in names]
        import dns.resolver
        raise dns.resolver.NXDOMAIN()
    resolve.calls = calls
    return resolve


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.now = timezone.now()
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')

    def asn(self, value='AS64500', **kw):
        return Asset.objects.create(project=self.p, kind='asn', value=value, scope_tier='owned_root', **kw)

    def cidr(self, value='203.0.114.0/28', **kw):
        kw.setdefault('scope_tier', 'owned_host')
        return Asset.objects.create(project=self.p, kind='cidr', value=value, **kw)


class ParseTest(TestCase):
    def test_url(self):
        self.assertEqual(ripestat.announced_prefixes_url('AS64500'),
                         'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64500&sourceapp=limes')

    def test_parse_announced_prefixes(self):
        self.assertEqual(ripestat.parse_announced_prefixes(load('ripestat_announced_prefixes.json')),
                         ['198.18.0.0/24', '203.0.114.0/24', '2606:4700::/48'])
        for junk in (None, [], {}, {'data': 5}, {'data': {'prefixes': 'x'}}):
            self.assertEqual(ripestat.parse_announced_prefixes(junk), [])


class AsnTest(Base):
    def test_asn_refresh_children_and_withdrawal(self):
        a = self.asn()
        out = r.refresh_asn(a, get=Get(['203.0.114.0/28', '198.51.101.0/28']), now=self.now)
        self.assertEqual(out['status'], 'ok')
        kids = Asset.objects.filter(parent=a, kind='cidr')
        self.assertEqual(sorted(k.value for k in kids), ['198.51.101.0/28', '203.0.114.0/28'])
        k = kids.get(value='203.0.114.0/28')
        self.assertEqual((k.scope_tier, k.sources[0]['source'], k.sources[0]['evidence']), ('owned_host', 'asn', 'AS64500'))
        for _ in range(3):
            r.refresh_asn(a, get=Get(['203.0.114.0/28']), now=self.now)
        self.assertEqual(Asset.objects.get(value='198.51.101.0/28').state, 'missing')
        self.assertEqual(Asset.objects.get(value='203.0.114.0/28').state, 'active')

    def test_reserved_prefix_dropped(self):
        a = self.asn()
        r.refresh_asn(a, get=Get(['10.0.0.0/24', '198.18.0.0/24', '203.0.114.0/28']), now=self.now)
        self.assertEqual(list(Asset.objects.filter(kind='cidr').values_list('value', flat=True)), ['203.0.114.0/28'])

    def test_asn_over_cap_refused(self):
        a = self.asn()
        self.cidr('203.0.114.0/24')  # 256 owned elsewhere
        with override_settings(RANGE_ADDRESS_CAP=512):
            out = r.refresh_asn(a, get=Get(['8.8.0.0/23', '8.8.4.0/24']), now=self.now)  # 768 total
            self.assertEqual(out['status'], 'refused')
            self.assertIn('768', out['reason'])
            self.assertIn('512', out['reason'])
            self.assertEqual(Asset.objects.filter(parent=a).count(), 0)
            self.assertEqual(Asset.objects.get(pk=a.pk).enrichment['asn']['status'], 'refused')
            self.assertEqual(r.range_addresses(self.p), 256)  # free cap for others unchanged

    def test_provider_failure_changes_nothing(self):
        a = self.asn()
        r.refresh_asn(a, get=Get(['203.0.114.0/28']), now=self.now)
        before = Asset.objects.get(pk=a.pk).enrichment
        self.assertEqual(r.refresh_asn(a, get=Get(ripe_status=500), now=self.now), {})
        self.assertEqual(r.refresh_asn(a, get=lambda url, provider: (None, None), now=self.now), {})
        self.assertEqual(Asset.objects.get(pk=a.pk).enrichment, before)
        self.assertEqual(Asset.objects.get(value='203.0.114.0/28').missed_count, 0)

    def test_rejected_asn_untouched(self):
        a = self.asn()
        Asset.objects.filter(pk=a.pk).update(scope_tier='rejected')
        g = Get(['203.0.114.0/28'])
        r.refresh_asn(a, get=g, now=self.now)
        self.assertEqual(g.calls, [])


@override_settings(RANGE_ENUMERATION=True, INTERNETDB_DAILY_BUDGET=5000, PTR_DAILY_BUDGET=10000)
class EnumTest(Base):
    def step(self, c, idb=4, ptr=4, get=None, resolve=None):
        return r.enumerate_step(c, idb, ptr, get=get or Get(), resolve=resolve or resolver(), now=self.now)

    def test_existing_oversized_range_refused(self):
        c = self.cidr('8.8.0.0/16')
        g = Get()
        self.assertEqual(self.step(c, get=g), {'internetdb': 0, 'ptr': 0, 'new': 0})
        self.assertEqual(g.calls, [])
        e = Asset.objects.get(pk=c.pk).enrichment['enum']
        self.assertEqual(e['status'], 'refused')
        self.assertIn('4096', e['reason'])

    def test_budget_and_cursor_resume(self):
        c = self.cidr('203.0.114.0/28')
        g, res = Get(), resolver()
        for i in range(1, 5):
            out = self.step(c, get=g, resolve=res)
            self.assertEqual(out['internetdb'], 4)
            e = Asset.objects.get(pk=c.pk).enrichment['enum']
            self.assertEqual(e['cursor'], 4 * i % 16)
        self.assertEqual((e['status'], e['pass']), ('done', 1))
        self.assertEqual(g.n('internetdb'), 16)
        self.assertNotIn(c.pk, [a.pk for a in r.due_ranges(self.now + timedelta(days=6))])
        self.assertIn(c.pk, [a.pk for a in r.due_ranges(self.now + timedelta(days=8))])

    def test_unfinished_range_is_due_and_take_daily_exhaustion_stops(self):
        c = self.cidr('203.0.114.0/28')
        g = Get()
        with override_settings(INTERNETDB_DAILY_BUDGET=2):
            out = self.step(c, get=g)
        self.assertEqual(out['internetdb'], 2)
        self.assertEqual(g.n('internetdb'), 2)
        self.assertEqual(Asset.objects.get(pk=c.pk).enrichment['enum']['cursor'], 2)
        self.assertIn(c.pk, [a.pk for a in r.due_ranges(self.now)])
        with mock.patch.object(ratelimit, 'take_daily', return_value=False):
            self.assertEqual(self.step(c, get=g)['internetdb'], 0)
        self.assertEqual(g.n('internetdb'), 2)

    def test_reserved_ips_in_range_skipped(self):
        c = self.cidr('192.0.2.0/30')  # TEST-NET: reserved, refused as a whole
        g, res = Get(), resolver()
        self.assertEqual(self.step(c, get=g, resolve=res)['internetdb'], 0)
        self.assertEqual((g.calls, res.calls), ([], []))
    
        d = self.cidr('203.0.114.0/30')
        with mock.patch('limes.owned_ranges.scope.is_reserved_ip', side_effect=lambda ip: str(ip).endswith('.1')):
            g = Get()
            out = self.step(d, get=g)
        self.assertEqual(out['internetdb'], 3)  # .1 skipped without spending budget
        self.assertNotIn('203.0.114.1', [u.rsplit('/', 1)[1] for _, u in g.calls])

    def test_live_ip_becomes_child_and_names_placed(self):
        c = self.cidr('203.0.114.0/30')
        g = Get(idb={'203.0.114.2': {'ports': [80], 'hostnames': ['api.example.com']}})
        res = resolver({'203.0.114.1': ['www.example.com'], '203.0.114.3': ['example.com']})
        self.step(c, get=g, resolve=res)
        ips = {a.value: a for a in Asset.objects.filter(kind='ip')}
        self.assertEqual(sorted(ips), ['203.0.114.1', '203.0.114.2', '203.0.114.3'])  # .3: PTR only
        i = ips['203.0.114.2']
        self.assertEqual((i.parent, i.scope_tier, i.sources[0]['source']), (c, 'owned_host', 'cidr'))
        self.assertEqual(i.enrichment['internetdb']['ports'], [80])
        h = Asset.objects.get(kind='hostname', value='www.example.com')
        self.assertEqual((h.parent, h.scope_tier, h.sources[0]['evidence']), (self.root, 'owned_host', 'ptr:203.0.114.1 in 203.0.114.0/30'))
        self.assertTrue(Asset.objects.filter(kind='hostname', value='api.example.com').exists())
        self.assertFalse(Asset.objects.filter(kind='hostname', value='example.com').exists())

    def test_existing_ip_tiers(self):
        c = self.cidr('203.0.114.0/30')
        for v, t in (('203.0.114.0', 'dependency'), ('203.0.114.1', 'candidate'), ('203.0.114.2', 'rejected')):
            Asset.objects.create(project=self.p, kind='ip', value=v, scope_tier=t)
        g = Get(idb={f'203.0.114.{i}': {'ports': [80]} for i in range(3)})
        self.step(c, get=g)
        t = {a.value: (a.scope_tier, a.parent_id) for a in Asset.objects.filter(kind='ip')}
        self.assertEqual(t['203.0.114.0'], ('owned_host', c.pk))
        self.assertEqual(t['203.0.114.1'], ('candidate', None))
        self.assertEqual(t['203.0.114.2'], ('rejected', None))

    def test_not_live_child_counts_a_miss(self):
        c = self.cidr('203.0.114.0/30')
        Asset.objects.create(project=self.p, kind='ip', value='203.0.114.1', scope_tier='owned_host', parent=c)
        self.step(c)
        self.assertEqual(Asset.objects.get(value='203.0.114.1').missed_count, 1)
        self.step(c, get=Get(idb_status=500))  # provider down: no information, no miss
        self.assertEqual(Asset.objects.get(value='203.0.114.1').missed_count, 1)

    def test_outside_names_stay_candidates(self):
        c = self.cidr('203.0.114.0/30')
        g = Get(idb={'203.0.114.1': {'ports': [443], 'hostnames': ['shop.other-brand.org']}})
        res = resolver({'203.0.114.0': ['x.cdn-provider.net'], '203.0.114.2': ['bad name!.example.com', 'evil.com..']})
        self.step(c, get=g, resolve=res)
        for v in ('cdn-provider.net', 'other-brand.org'):
            a = Asset.objects.get(kind='root_domain', value=v)
            self.assertEqual(a.scope_tier, 'candidate')
        self.assertEqual(Asset.objects.filter(kind='hostname').count(), 0)
        self.assertEqual(Asset.objects.filter(scope_tier__in=('owned_root', 'owned_host'), kind__in=('root_domain', 'hostname')).count(), 1)

    def test_asset_new_only_after_first_pass(self):
        c = self.cidr('203.0.114.0/30')
        self.step(c, idb=4, ptr=4, get=Get(idb={'203.0.114.0': {'ports': [80]}}))
        self.assertEqual(ChangeEvent.objects.count(), 0)  # pass 0 silent
        self.assertEqual(Asset.objects.get(pk=c.pk).enrichment['enum']['pass'], 1)
        g = Get(idb={'203.0.114.1': {'ports': [3389]}, '203.0.114.2': {'ports': [80]}})
        self.step(c, get=g)
        ev = {e.asset.value: e for e in ChangeEvent.objects.filter(kind='asset_new')}
        self.assertEqual(sorted(ev), ['203.0.114.1', '203.0.114.2'])
        self.assertTrue(ev['203.0.114.1'].immediate)
        self.assertFalse(ev['203.0.114.2'].immediate)

    def test_first_pass_issue_sync_is_silent(self):
        c = self.cidr('203.0.114.0/30')
        Asset.objects.filter(pk=c.pk).update(enrichment={'enum': {'cursor': 2, 'pass': 0, 'status': 'running'}})
        mk = lambda v: Asset.objects.create(project=self.p, kind='ip', value=v, scope_tier='owned_host', parent=c)
        one, two = mk('203.0.114.0'), mk('203.0.114.1')

        def sync(found):
            with mock.patch('limes.scoring.current_issues', return_value=({a.id: {'net.exposed_rdp': 3} for a in found},
                                                                            {a.id for a in found})):
                return issues.sync_issues(self.p)
        sync([])  # the project's own first sync
        self.assertEqual(sync([one]), [])  # pass 0: rows created silently
        self.assertNotIn(f'cidr:{c.value}', IssueSyncState.objects.get(project=self.p).roots)
        self.assertEqual(issues._bucket(one, []), f'cidr:{c.value}')
        Asset.objects.filter(pk=c.pk).update(enrichment={'enum': {'cursor': 0, 'pass': 1, 'status': 'done'}})
        self.assertEqual(sync([one]), [])
        self.assertIn(f'cidr:{c.value}', IssueSyncState.objects.get(project=self.p).roots)
        self.assertEqual([e.kind for e in sync([one, two])], ['issue_new'])  # a pass-1 find is announced

    def test_stopped_or_rejected_untouched(self):
        c = self.cidr('203.0.114.0/30')
        due = r.due_ranges(self.now)
        self.assertIn(c.pk, [a.pk for a in due])
        g, res = Get(), resolver()
        Asset.objects.filter(pk=c.pk).update(cadence_tier='off')
        self.assertEqual(self.step(c, get=g, resolve=res)['internetdb'], 0)
        Asset.objects.filter(pk=c.pk).update(cadence_tier='standard', scope_tier='rejected')
        self.assertEqual(self.step(c, get=g, resolve=res)['internetdb'], 0)
        a = self.asn()
        Asset.objects.filter(pk=c.pk).update(scope_tier='owned_host', parent=a)
        Asset.objects.filter(pk=a.pk).update(scope_tier='rejected')
        self.assertEqual(self.step(c, get=g, resolve=res)['internetdb'], 0)
        self.assertEqual((g.calls, res.calls), ([], []))
        self.assertEqual(r.due_ranges(self.now), [])


@override_settings(RANGE_ENUMERATION=True, CONTINUOUS_SCANS=True)
class TaskTest(Base):
    def run_task(self, get=None, resolve=None):
        with mock.patch('limes.owned_ranges.http.get_json', get or Get()), \
                mock.patch('limes.owned_ranges.collect._resolve', resolve or resolver()), \
                mock.patch('limes.owned_ranges.deliver_immediate') as d:
            out = r.enumerate_ranges()
        return out, d

    def test_enumeration_opt_in(self):
        a = self.asn()
        c = self.cidr('203.0.114.0/30')
        g, res = Get(['198.51.101.0/30']), resolver()
        with override_settings(RANGE_ENUMERATION=False):
            self.run_task(get=g, resolve=res)
        self.assertEqual((g.n('internetdb'), res.calls), (0, []))
        self.assertEqual(g.n('ripestat'), 1)
        self.assertTrue(Asset.objects.filter(parent=a, value='198.51.101.0/30').exists())

    def test_one_asn_refresh_per_tick_and_budget_shared(self):
        self.asn('AS1'), self.asn('AS2')
        c = self.cidr('203.0.114.0/28')
        g = Get(['198.51.101.0/30'])
        out, _ = self.run_task(get=g)
        self.assertEqual(g.n('ripestat'), 1)
        self.assertEqual(out['internetdb'], ratelimit.per_tick(settings.INTERNETDB_DAILY_BUDGET))

    def test_new_event_triggers_delivery(self):
        c = self.cidr('203.0.114.0/30')
        Asset.objects.filter(pk=c.pk).update(enrichment={'enum': {'cursor': 0, 'pass': 1, 'status': 'running'}})
        _, d = self.run_task(get=Get(idb={'203.0.114.0': {'ports': [3389]}}))
        d.assert_called_once_with(self.p)

    def test_disabled(self):
        with override_settings(CONTINUOUS_SCANS=False):
            self.assertEqual(r.enumerate_ranges()['reason'], 'disabled')

    def test_concurrent_tick_is_locked(self):
        with mock.patch('limes.owned_ranges._lock', return_value=False):
            self.assertEqual(r.enumerate_ranges(), {'reason': 'locked'})
