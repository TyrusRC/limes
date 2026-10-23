import json
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from django_redis import get_redis_connection

from dashboard.models import Project
from limes import continuous, event_queue as eq
from limes.alerts import events
from limes.ct import ingest, lookalikes, match
from limes.monitor import found_by
from limes.tasks import intel
from startScan.models import Asset, CertSighting, ChangeEvent
from targetApp.models import Domain
from tests.core.test_intel_run import Fake

LE = "C=US, O=Let's Encrypt, CN=R11"


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.r = get_redis_connection('default')
        self.wipe()
        self.addCleanup(self.wipe)
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.now = timezone.now()
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        Domain.objects.create(name='x.com', project=self.p, insert_date=self.now)
        self.www = Asset.objects.create(project=self.p, kind='hostname', value='www.x.com', scope_tier='owned_host',
                                        parent=self.root)

    def wipe(self):
        for pat in ('limes:evq*', 'limes:ct:*'):
            for k in self.r.scan_iter(pat):
                self.r.delete(k)

    def rec(self, names, tbs='a' * 64, issuer=LE, **kw):
        return {'tbs_sha256': tbs, 'cert_sha256': None, 'dns_names': names, 'names_total': len(names),
                'issuer_dn': issuer, 'not_before': kw.get('not_before'), 'not_after': None, 'log_uri': '',
                'entry_index': None}

    def run_ingest(self, names, source='certspotter', tbs='a' * 64, now=None, **kw):
        with self.captureOnCommitCallbacks(execute=True):
            return ingest.ingest(self.rec(names, tbs=tbs, issuer=kw.pop('issuer', LE)), source, ingest.load_index(),
                                 now or self.now, **kw)

    def queued(self):
        return {(a, r) for a, r, _ in eq.claim_due(self.now + timedelta(days=1), 1000)}


class IngestTest(Base):
    def test_new_hostname_upserted_and_enqueued(self):
        self.run_ingest(['new.x.com'], seen_at=self.now.timestamp() - 3)
        a = Asset.objects.get(kind='hostname', value='new.x.com')
        self.assertEqual(a.parent, self.root)
        self.assertEqual(a.sources[0]['source'], 'ct')
        self.assertEqual(found_by(a), ['CT'])
        self.assertEqual(self.queued(), {(a.id, 'ct_new')})
        s = CertSighting.objects.get()
        self.assertEqual((s.names, s.asset, s.source), (['new.x.com'], a, 'certspotter'))
        lat = [float(x) for x in self.r.lrange(f'limes:ct:lat:{self.now:%Y%m%d}', 0, -1)]
        self.assertAlmostEqual(lat[0], 3.0, delta=0.01)

    def test_wildcard_creates_no_asset(self):
        self.run_ingest(['*.x.com'])
        self.assertFalse(Asset.objects.filter(kind='hostname').exclude(pk=self.www.pk).exists())
        s = CertSighting.objects.get()
        self.assertEqual((s.asset, s.wildcard, s.names), (self.root, True, ['*.x.com']))
        self.assertEqual(self.queued(), set())

    def test_root_name_creates_no_asset(self):
        self.run_ingest(['x.com'])
        self.assertEqual(Asset.objects.filter(kind='hostname').count(), 1)

    def test_existing_host_enqueued_as_ct_cert(self):
        self.run_ingest(['www.x.com'])
        self.assertEqual(self.queued(), {(self.www.id, 'ct_cert')})
        self.assertEqual(CertSighting.objects.get().asset, self.www)

    def test_duplicate_tbs_is_noop(self):
        self.assertEqual(self.run_ingest(['new.x.com'], source='certspotter_api'), {self.p.id})
        s = CertSighting.objects.get()
        self.assertIsNone(s.watch_seen_at)
        events_before = ChangeEvent.objects.count()
        self.queued()
        self.assertEqual(self.run_ingest(['new.x.com'], source='certspotter'), set())
        self.assertEqual((CertSighting.objects.count(), ChangeEvent.objects.count()), (1, events_before))
        self.assertEqual(self.queued(), set())
        s.refresh_from_db()
        self.assertEqual((s.watch_seen_at, s.source), (self.now, 'certspotter_api'))

    def test_api_source_keeps_its_label(self):
        self.run_ingest(['new.x.com'], source='certspotter_api')
        self.assertEqual(Asset.objects.get(value='new.x.com').sources[0]['source'], 'certspotter_api')

    def test_cert_burst_coalesces(self):
        for i in range(30):
            self.run_ingest([f'h{i}.x.com'], tbs=f'{i:064x}')
        ev = ChangeEvent.objects.get(kind='cert_new')
        self.assertEqual((ev.asset, ev.detail['count'], ev.immediate), (self.root, 30, False))
        self.assertLessEqual(len(ev.detail['names']), 20)
        self.run_ingest(['late.x.com'], tbs='f' * 64, now=self.now + timedelta(seconds=3601))
        self.assertEqual(ChangeEvent.objects.filter(kind='cert_new').count(), 2)

    def test_many_sans_are_capped_and_counted(self):
        self.run_ingest([f'h{i}.x.com' for i in range(1000)])
        s = CertSighting.objects.get()
        self.assertEqual((len(s.names), s.other_names), (100, 900))
        self.assertEqual(Asset.objects.filter(kind='hostname').count(), 1 + 100)

    def test_new_issuer_is_immediate_after_baseline(self):
        self.run_ingest(['a.x.com'], tbs='1' * 64, issuer='C=US, O=Evil CA, CN=E')
        self.assertEqual(list(ChangeEvent.objects.values_list('immediate', flat=True)), [False])  # no baseline yet
        ChangeEvent.objects.all().delete()
        ingest.seed_issuers(self.root, {"let's encrypt"}, self.now)
        self.run_ingest(['b.x.com'], tbs='2' * 64)
        self.assertEqual(list(ChangeEvent.objects.values_list('immediate', flat=True)), [False])
        self.run_ingest(['c.x.com'], tbs='3' * 64, issuer='C=US, O=Other CA, CN=E')
        digest, hot = ChangeEvent.objects.order_by('immediate')
        self.assertEqual((digest.detail['count'], digest.immediate), (2, False))
        self.assertEqual((hot.immediate, hot.title), (True, 'New certificate for x.com from a new issuer (Other CA)'))
        self.run_ingest(['d.x.com'], tbs='4' * 64, issuer='C=US, O=Other CA, CN=E')  # now known: digest only
        self.assertEqual(ChangeEvent.objects.filter(immediate=True).count(), 1)

    def test_issuer_unseen_for_a_year_is_new_again(self):
        ingest.seed_issuers(self.root, {"let's encrypt"}, self.now - timedelta(days=366))
        self.run_ingest(['b.x.com'])
        self.assertTrue(ChangeEvent.objects.get(immediate=True).title.endswith("(Let's Encrypt)"))

    def test_note_issuer_baseline_by_age_and_cap(self):
        self.assertFalse(ingest.note_issuer(self.root, 'a', self.now - timedelta(days=31)))
        self.assertTrue(ingest.note_issuer(self.root, 'b', self.now))   # first sight 31 days ago: baselined by age
        self.assertFalse(ingest.note_issuer(self.root, 'b', self.now))
        self.assertFalse(ingest.note_issuer(self.root, '', self.now))
        for i in range(60):
            ingest.note_issuer(self.root, f'o{i:02}', self.now + timedelta(seconds=i))
        self.root.refresh_from_db()
        orgs = self.root.enrichment['ct_issuers']['orgs']
        self.assertEqual(len(orgs), 50)
        self.assertIn('o59', orgs)
        self.assertNotIn('o00', orgs)

    def test_seed_from_empty_answer_does_not_baseline(self):
        ingest.seed_issuers(self.root, set(), self.now)
        self.root.refresh_from_db()
        self.assertNotIn('ct_issuers', self.root.enrichment)

    def test_silent_records_sighting_only(self):
        self.run_ingest(['new.x.com'], silent=True)
        self.assertEqual((CertSighting.objects.count(), ChangeEvent.objects.count()), (1, 0))
        self.root.refresh_from_db()
        self.assertNotIn('ct_issuers', self.root.enrichment)

    def test_hostile_dn_truncated_and_logged_safely(self):
        dn = 'O=' + 'A' * 600 + '\nFORGED log line %s'
        with self.assertLogs('limes.ct.ingest', level='INFO') as lg:
            self.run_ingest(['new.x.com'], issuer=dn)
        self.assertTrue(lg.output)
        self.assertFalse(any('\nFORGED' in m for m in lg.output))
        s = CertSighting.objects.get()
        self.assertLessEqual(len(s.issuer), 500)
        self.assertNotIn('\n', s.issuer)
        self.assertLessEqual(len(ChangeEvent.objects.get().title), 300)

    def test_latency_clamps_skew(self):
        self.run_ingest(['new.x.com'], seen_at=self.now.timestamp() + 50)
        self.assertEqual(float(self.r.lrange(f'limes:ct:lat:{self.now:%Y%m%d}', 0, -1)[0]), 0.0)
        self.assertEqual(eq.snapshot(self.now)['counts']['skew'], 1)

    def test_cert_age_recorded(self):
        rec = self.rec(['new.x.com'])
        rec['not_before'] = self.now - timedelta(seconds=90)
        ingest.ingest(rec, 'certspotter', ingest.load_index(), self.now)
        self.assertAlmostEqual(float(self.r.lrange(f'limes:ct:age:{self.now:%Y%m%d}', 0, -1)[0]), 90, delta=0.01)


class SentEventTest(Base):
    def seed(self):
        ingest.seed_issuers(self.root, {"let's encrypt"}, self.now - timedelta(days=1))

    def test_cert_after_digest_sent_starts_a_new_row(self):
        self.run_ingest(['a.x.com'], tbs='1' * 64)
        ChangeEvent.objects.update(digested_at=self.now)
        self.run_ingest(['b.x.com'], tbs='2' * 64)
        self.assertEqual(sorted(ChangeEvent.objects.values_list('detail__count', flat=True)), [1, 1])
        self.assertEqual(ChangeEvent.objects.filter(digested_at__isnull=True).count(), 1)

    def test_alert_row_already_sent_is_not_folded_into(self):
        args = (self.p, self.root, ['a.x.com'], True, 'Evil CA', self.now)
        ingest.record_cert_event(*args)
        ChangeEvent.objects.update(notified_at=self.now)
        ingest.record_cert_event(*args)
        self.assertEqual(ChangeEvent.objects.filter(immediate=True).count(), 2)

    def test_second_rogue_issuer_gets_its_own_alert(self):
        self.seed()
        self.run_ingest(['a.x.com'], tbs='1' * 64, issuer='O=Evil CA')
        self.run_ingest(['b.x.com'], tbs='2' * 64, issuer='O=Rogue CA')
        titles = sorted(ChangeEvent.objects.filter(immediate=True).values_list('title', flat=True))
        self.assertEqual(titles, ['New certificate for x.com from a new issuer (Evil CA)',
                                  'New certificate for x.com from a new issuer (Rogue CA)'])

    def test_chat_syntax_in_issuer_is_neutralised(self):
        self.seed()
        self.run_ingest(['a.x.com'], issuer='O=<!channel> @everyone <@U123> <http://evil|click> [x](http://e)')
        ev = ChangeEvent.objects.get(immediate=True)
        for ch in '<>@[]':
            self.assertNotIn(ch, ev.title + ev.detail['issuer'])


class MultiRootTest(Base):
    def test_cert_for_two_roots_updates_each(self):
        z = Asset.objects.create(project=self.p, kind='root_domain', value='z.org', scope_tier='owned_root')
        for r in (self.root, z):
            ingest.seed_issuers(r, {"let's encrypt"}, self.now - timedelta(days=1))
        self.run_ingest(['a.x.com', 'b.z.org'], issuer='O=Evil CA')
        hot = ChangeEvent.objects.filter(immediate=True)
        self.assertEqual({e.asset_id for e in hot}, {self.root.id, z.id})
        for r in (self.root, z):
            r.refresh_from_db()
            self.assertIn('evil ca', r.enrichment['ct_issuers']['orgs'])
        self.assertEqual(CertSighting.objects.count(), 1)

    def test_subdomain_root_is_indexed(self):
        shop = Asset.objects.create(project=self.p, kind='root_domain', value='shop.z.com', scope_tier='owned_root')
        Asset.objects.create(project=self.p, kind='root_domain', value='co.uk', scope_tier='owned_root')
        i = ingest.load_index()
        self.assertEqual(i.roots['shop.z.com'], [(self.p.id, shop.id)])
        self.assertNotIn('co.uk', i.roots)
        self.run_ingest(['api.shop.z.com'])
        self.assertEqual(Asset.objects.get(value='api.shop.z.com').parent, shop)


class HostAllowanceTest(Base):
    @override_settings(CT_NEW_HOSTS_PER_HOUR=5)
    def test_hourly_cap_turns_the_rest_into_candidates(self):
        for i in range(3):
            self.run_ingest([f'h{i}-{j}.x.com' for j in range(4)], tbs=f'{i:064x}')
        hosts = Asset.objects.filter(kind='hostname', scope_tier='owned_host').exclude(pk=self.www.pk)
        cands = Asset.objects.filter(kind='hostname', scope_tier='candidate')
        self.assertEqual((hosts.count(), cands.count()), (5, 7))
        self.assertEqual(len(self.queued()), 5)

    def test_redis_down_fails_closed_to_candidates(self):
        from redis.exceptions import ConnectionError as RedisConnectionError
        with mock.patch.object(ingest, 'get_redis_connection', side_effect=RedisConnectionError('x')):
            ingest.ingest(self.rec(['new.x.com']), 'certspotter_api', ingest.load_index(), self.now)
        self.assertEqual(Asset.objects.get(value='new.x.com').scope_tier, 'candidate')

    def test_names_are_upserted_in_sorted_order(self):
        from limes.tasks import inventory
        with mock.patch.object(inventory, 'upsert_hostname_asset', wraps=inventory.upsert_hostname_asset) as up:
            self.run_ingest(['c.x.com', 'a.x.com', 'b.x.com'])
        self.assertEqual([c.args[1] for c in up.call_args_list], ['a.x.com', 'b.x.com', 'c.x.com'])


class CoTenantTest(Base):
    def test_cotenants_become_candidates_with_hourly_cap(self):
        self.run_ingest(['www.x.com', 'shop.other.net'])
        c = Asset.objects.get(value='other.net')
        self.assertEqual((c.scope_tier, c.sources[0]['source']), ('candidate', 'ct'))
        self.assertIn('shared with x.com', c.sources[0]['evidence'])
        with mock.patch.object(intel, 'MAX_CANDIDATES_PER_ROOT', 2):
            self.run_ingest(['www.x.com', 'a.two.net', 'a.three.net'], tbs='b' * 64)
        self.assertEqual(Asset.objects.filter(kind='root_domain', scope_tier='candidate').count(), 2)

    def test_lookalike_never_candidate_or_contacted(self):
        with mock.patch.object(lookalikes, 'watched', return_value=[(self.p.id, 'examp1e.com')]), \
                mock.patch.object(lookalikes, 'record_sighting', return_value=True) as rs:
            self.run_ingest(['www.x.com', 'login.examp1e.com', 'shop.other.net'])
        self.assertTrue(Asset.objects.filter(value='other.net', scope_tier='candidate').exists())
        self.assertFalse(Asset.objects.filter(value__contains='examp1e').exists())
        rs.assert_called_once_with(self.p.id, 'examp1e.com', self.now)
        self.assertEqual(self.queued(), {(self.www.id, 'ct_cert')})

    def test_duplicate_does_not_recount_a_lookalike(self):
        with mock.patch.object(lookalikes, 'watched', return_value=[(self.p.id, 'examp1e.com')]), \
                mock.patch.object(lookalikes, 'record_sighting', return_value=True) as rs:
            self.run_ingest(['login.examp1e.com'])
            self.run_ingest(['login.examp1e.com'], source='certspotter_api')
        self.assertEqual(rs.call_count, 1)
        self.assertEqual(CertSighting.objects.count(), 0)

    def test_lookalike_hook_absent_is_inert(self):
        self.assertIsNone(lookalikes.model())
        self.assertEqual(lookalikes.watched(), [])
        self.assertFalse(lookalikes.record_sighting(self.p.id, 'examp1e.com', self.now))


class IndexTest(Base):
    def test_load_index(self):
        Asset.objects.create(project=self.p, kind='root_domain', value='off.com', scope_tier='owned_root',
                             cadence_tier='off')
        Asset.objects.create(project=self.p, kind='root_domain', value='old.com', scope_tier='owned_root',
                             state='retired')
        Asset.objects.create(project=self.p, kind='root_domain', value='co.uk', scope_tier='owned_root')  # a suffix
        Asset.objects.create(project=self.p, kind='root_domain', value='cand.com', scope_tier='candidate')
        vendor = Asset.objects.create(project=self.p, kind='hostname', value='app.vendor.com', scope_tier='owned_host')
        Asset.objects.create(project=self.p, kind='hostname', value='cand.vendor.com', scope_tier='candidate')
        sub = Asset.objects.create(project=self.p, kind='root_domain', value='api.vendor.com', scope_tier='owned_host')
        with self.assertNumQueries(1):
            i = ingest.load_index()
        self.assertEqual(i.roots, {'x.com': [(self.p.id, self.root.id)]})
        self.assertEqual(i.hosts, {'app.vendor.com': [(self.p.id, vendor.id)], 'api.vendor.com': [(self.p.id, sub.id)]})
        self.assertEqual(i.lookalikes, {})


class ParseRecordTest(TestCase):
    def good(self, **kw):
        d = {'tbs_sha256': 'a' * 64, 'cert_sha256': 'b' * 64, 'dns_names': ['x.com'], 'issuer_dn': 'O=A\x00B',
             'not_before': '2026-10-01T00:00:00Z', 'not_after': 'nonsense', 'log_uri': 'u' * 900, 'entry_index': 7}
        d.update(kw)
        return json.dumps(d).encode()

    def test_parse_record_schema(self):
        r = ingest.parse_record(self.good())
        self.assertEqual((r['entry_index'], r['not_after'], len(r['log_uri']), r['issuer_dn'], r['names_total']),
                         (7, None, 500, 'O=A B', 1))
        self.assertEqual(r['not_before'].year, 2026)
        self.assertIsNone(ingest.parse_record(b'x' * (ingest.SPOOL_MAX_BYTES + 1)))
        self.assertIsNone(ingest.parse_record(b'[1]'))
        self.assertIsNone(ingest.parse_record(b'not json'))
        self.assertIsNone(ingest.parse_record(self.good(tbs_sha256='../../etc')))
        self.assertIsNone(ingest.parse_record(self.good(tbs_sha256='A' * 64)))
        self.assertIsNone(ingest.parse_record(self.good(tbs_sha256='a' * 64 + '\n')))
        self.assertIsNone(ingest.parse_record(self.good(dns_names='x.com')))
        self.assertIsNone(ingest.parse_record(self.good(dns_names=['x.com', 5])))
        self.assertIsNone(ingest.parse_record(b'[' * 100000))
        self.assertIsNone(ingest.parse_record(self.good(entry_index='7'))['entry_index'])
        self.assertIsNone(ingest.parse_record(self.good(entry_index=-1))['entry_index'])
        self.assertIsNone(ingest.parse_record(self.good(entry_index=True))['entry_index'])
        self.assertIsNone(ingest.parse_record(self.good(cert_sha256='zz'))['cert_sha256'])
        self.assertIsNone(ingest.parse_record(self.good(not_before='9999999-01-01T00:00:00Z'))['not_before'])


class PartialSeedTest(Base):
    def test_partial_response_extends_history_without_baselining(self):
        ingest.seed_issuers(self.root, {'A CA'}, self.now, complete=False)
        self.root.refresh_from_db()
        data = self.root.enrichment['ct_issuers']
        self.assertEqual((data['seeded'], set(data['orgs'])), (False, {'a ca'}))
        ingest.seed_issuers(self.root, {'B CA'}, self.now, complete=True)
        self.root.refresh_from_db()
        self.assertTrue(self.root.enrichment['ct_issuers']['seeded'])

    def test_crtsh_response_at_the_row_cap_is_partial(self):
        rows = [{'id': i, 'name_value': f'h{i}.x.com', 'issuer_name': 'O=LE'} for i in range(1, 4)]
        with mock.patch.object(intel, 'MAX_NAMES_PER_ROOT', 3):
            intel.run_crtsh(self.p, self.root, get=Fake(crtsh=(200, rows)))
        self.root.refresh_from_db()
        self.assertFalse(self.root.enrichment['ct_issuers']['seeded'])


class LookalikeRowTest(Base):
    def test_record_sighting_finds_a_unicode_stored_row(self):

        class Row:
            def __init__(self):
                self.ct, self.domain, self.saved = None, 'b\u00fccher.example', False

            def save(self, update_fields=None):
                self.saved = True
        row, seen = Row(), {}

        class QS:
            def select_for_update(self):
                return self

            def filter(self, **kw):
                seen.update(kw)
                return self

            def first(self):
                return row

        class Model:
            objects = QS()
        with mock.patch.object(lookalikes, 'model', return_value=Model):
            self.assertTrue(lookalikes.record_sighting(self.p.id, 'xn--bcher-kva.example', self.now))
        self.assertEqual(seen['domain__in'], {'xn--bcher-kva.example', 'b\u00fccher.example'})
        self.assertEqual(row.ct['count'], 1)


class CrtshSeedTest(TestCase):
    def test_crtsh_still_uses_shared_cotenant_rule_and_seeds_issuers(self):
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        root = Asset.objects.create(project=p, kind='root_domain', value='example.com', scope_tier='owned_root')
        rows = [{'id': 1, 'name_value': 'a.example.com\nco.net', 'issuer_name': "C=US, O=Let's Encrypt, CN=R11"},
                {'id': 2, 'name_value': 'b.example.com', 'issuer_name': 'C=US, O=DigiCert Inc, CN=x'},
                {'id': 'bad', 'name_value': 'c.example.com', 'issuer_name': 'O=Ignored'}]
        out = intel.run_crtsh(p, root, get=Fake(crtsh=(200, rows)))
        self.assertEqual(out['candidates'], 1)
        root.refresh_from_db()
        data = root.enrichment['ct_issuers']
        self.assertTrue(data['seeded'])
        self.assertEqual(set(data['orgs']), {"let's encrypt", 'digicert inc'})

    def test_failed_fetch_does_not_baseline(self):
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        root = Asset.objects.create(project=p, kind='root_domain', value='example.com', scope_tier='owned_root')
        intel.run_crtsh(p, root, get=Fake(crtsh=(None, None)))
        root.refresh_from_db()
        self.assertNotIn('ct_issuers', root.enrichment)


class PruneTest(Base):
    def test_old_sightings_pruned(self):
        for d, tbs in ((401, '1'), (399, '2')):
            CertSighting.objects.create(project=self.p, tbs_sha256=tbs * 64, source='crtsh',
                                        first_seen_at=timezone.now() - timedelta(days=d))
        self.assertEqual(set(continuous.age_assets()), {'stale', 'retired'})
        self.assertEqual(list(CertSighting.objects.values_list('tbs_sha256', flat=True)), ['2' * 64])
