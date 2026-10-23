import hashlib
import logging
import os
import shutil
import tempfile
from datetime import timedelta
from unittest import mock

import dns.exception
import dns.resolver
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from limes import reputation
from limes.alerts.issues import sync_issues
from limes.checks import run
from limes.feeds import sources
from startScan.models import Asset, ChangeEvent, FeedState, IssueSyncState, RiskCheck, TrackedIssue

H = timedelta(hours=1)
DROP4 = [('45.10.0.0/22', 'SBL1')]
DROP6 = [('2a0d:1000::/32', 'SBL2')]


def _ndjson(rows):
    lines = ['{"cidr":"%s","sblid":"%s"}' % r for r in rows]
    lines.append('{"type":"metadata","timestamp":1792730642,"records":%d}' % len(rows))
    return '\n'.join(lines).encode()


class FeedBase(TestCase):
    def setUp(self):
        cache.clear()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        ov = override_settings(LIMES_RESULTS=self.dir, FEEDS_OPTIN=[], SPAMHAUS_DQS_KEY='')
        ov.enable()
        self.addCleanup(ov.disable)
        self.now = timezone.now()
        self.p = Project.objects.create(name='p', slug='p', insert_date=self.now)

    def feed(self, name, blob, age=H):
        path = os.path.join(self.dir, 'feeds', name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(blob)
        FeedState.objects.update_or_create(name=name, defaults={
            'url': sources.FEEDS[name].url, 'sha256': hashlib.sha256(blob).hexdigest(), 'entries': 1, 'status': 'ok',
            'last_good_at': self.now - age, 'fetched_at': self.now - age, 'source_date': self.now - age})

    def feeds(self, drop4=DROP4, drop6=DROP6, asns=((12345, 'EVIL-NET'),), c2=('45.12.0.9',)):
        self.feed('drop_v4', _ndjson(drop4))
        self.feed('drop_v6', _ndjson(drop6))
        self.feed('asndrop', '\n'.join('{"asn":%d,"asname":"%s"}' % a for a in asns).encode() + b'\n' +
                  b'{"type":"metadata","timestamp":1792730642,"records":%d}' % len(asns))
        self.feed('feodo', ('[' + ','.join('{"ip_address":"%s","port":443,"status":"online"}' % i for i in c2) + ']').encode())

    def asset(self, kind, value, parent=None):
        return Asset.objects.create(project=self.p, kind=kind, value=value, scope_tier='owned_host', parent=parent)

    def result(self, asset, check, **kw):
        out = {r.check: r for r in reputation.evaluate_asset(asset, self.now, **kw)}
        return out.get(check)


class EvaluateTests(FeedBase):
    def test_drop_overlap_ip_and_cidr(self):
        self.feeds()
        hit = self.result(self.asset('ip', '45.10.1.5'), 'rep.listed_drop')
        self.assertEqual(hit.status, 'fail')
        self.assertIn('SBL1', hit.evidence['entry'])
        self.assertEqual(hit.evidence['credit'], sources.FEEDS['drop_v4'].credit)
        self.assertEqual(self.result(self.asset('ip', '45.11.0.1'), 'rep.listed_drop').status, 'pass')
        self.assertEqual(self.result(self.asset('cidr', '45.10.2.0/24'), 'rep.listed_drop').status, 'fail')
        self.assertEqual(self.result(self.asset('cidr', '45.8.0.0/14'), 'rep.listed_drop').status, 'fail')
        self.assertEqual(self.result(self.asset('cidr', '46.0.0.0/24'), 'rep.listed_drop').status, 'pass')
        self.assertEqual(self.result(self.asset('cidr', '45.10.4.0/24'), 'rep.listed_drop').status, 'pass')  # next to it
        self.assertEqual(self.result(self.asset('ip', '2a0d:1000::5'), 'rep.listed_drop').status, 'fail')
        self.assertEqual(self.result(self.asset('ip', '2a0d:1001::5'), 'rep.listed_drop').status, 'pass')

    def test_overlapping_entries_and_host_bits(self):
        self.feeds(drop4=[('45.0.0.0/16', 'SBL9'), ('45.10.0.0/22', 'SBL1'), ('99.1.0.0/24', 'SBL3')])
        # an IP after a short entry that sits inside a long one is still caught by the long one
        self.assertEqual(self.result(self.asset('ip', '45.0.200.1'), 'rep.listed_drop').status, 'fail')
        self.assertEqual(self.result(self.asset('ip', '45.11.0.1'), 'rep.listed_drop').status, 'pass')
        # a range written with host bits is normalised
        self.assertEqual(self.result(self.asset('cidr', '99.1.0.77/24'), 'rep.listed_drop').status, 'fail')

    def test_asndrop_matches_asn_assets(self):
        self.feeds()
        hit = self.result(self.asset('asn', 'AS12345'), 'rep.listed_asndrop')
        self.assertEqual(hit.status, 'fail')
        self.assertEqual(hit.evidence['entry'], 'AS12345 EVIL-NET')
        self.assertEqual(self.result(self.asset('asn', 'AS1'), 'rep.listed_asndrop').status, 'pass')

    def test_c2_listing(self):
        self.feeds()
        hit = self.result(self.asset('ip', '45.12.0.9'), 'rep.listed_c2')
        self.assertEqual((hit.status, hit.evidence['credit']), ('fail', 'abuse.ch Feodo Tracker (CC0)'))
        self.assertEqual(reputation.CHECKS['rep.listed_c2'].severity, 4)
        self.assertEqual(self.result(self.asset('ip', '45.12.0.10'), 'rep.listed_c2').status, 'pass')

    def test_stale_feed_gives_error(self):
        self.feeds()
        self.feed('drop_v4', _ndjson(DROP4), age=73 * H)
        ip = self.asset('ip', '45.10.1.5')
        out = self.result(ip, 'rep.listed_drop')
        self.assertEqual((out.status, out.evidence), ('error', {'reason': 'feed data older than 3 x its cadence'}))
        self.assertEqual(self.result(ip, 'rep.listed_c2').status, 'pass')  # Feodo is fresh and still decides
        self.assertEqual(self.result(self.asset('cidr', '46.0.0.0/24'), 'rep.listed_drop').status, 'error')
        FeedState.objects.filter(name='feodo').delete()  # never fetched
        self.assertEqual(self.result(ip, 'rep.listed_c2').status, 'error')
        FeedState.objects.filter(name='asndrop').update(last_good_at=None)
        self.assertEqual(self.result(self.asset('asn', 'AS1'), 'rep.listed_asndrop').status, 'error')

    def test_optin_feed_off_writes_no_row(self):
        self.feeds()
        self.feed('blocklist_de', b'45.13.0.1\n')
        ip = self.asset('ip', '45.13.0.1')
        self.assertIsNone(self.result(ip, 'rep.listed_attacker'))
        with override_settings(FEEDS_OPTIN=['blocklist_de']):
            hit = self.result(ip, 'rep.listed_attacker')
            self.assertEqual((hit.status, hit.evidence['feed']), ('fail', 'blocklist_de'))
            self.assertEqual(reputation.CHECKS['rep.listed_attacker'].severity, 2)
            self.assertEqual(self.result(self.asset('ip', '45.13.0.2'), 'rep.listed_attacker').status, 'pass')

    def test_no_feed_ever_downloaded_gives_no_result(self):
        self.assertEqual(reputation.evaluate_asset(self.asset('ip', '45.10.1.5'), self.now), [])

    def test_hostile_text_is_cleaned(self):
        self.feeds(asns=((666, '<img src=x onerror=alert(1)>'),))
        entry = self.result(self.asset('asn', 'AS666'), 'rep.listed_asndrop').evidence['entry']
        self.assertTrue(not any(c in entry for c in '<>"\'&'), entry)

    def test_dqs_only_when_given(self):
        self.feeds()
        ip = self.asset('ip', '45.11.0.1')
        self.assertIsNone(self.result(ip, 'rep.dnsbl_listed'))
        self.assertEqual(self.result(ip, 'rep.dnsbl_listed', dqs=('listed', '127.0.0.4')).status, 'fail')
        self.assertEqual(self.result(ip, 'rep.dnsbl_listed', dqs=('clean', None)).status, 'pass')
        self.assertEqual(self.result(ip, 'rep.dnsbl_listed', dqs=('error', 'Timeout')).status, 'error')


class RunTests(FeedBase):
    def test_range_listing_not_repeated_per_ip(self):
        self.feeds()
        cidr = self.asset('cidr', '45.10.0.0/24')
        ips = [self.asset('ip', f'45.10.0.{i}', parent=cidr) for i in (1, 2, 3)]
        reputation.evaluate_reputation(self.now)
        self.assertEqual(RiskCheck.objects.get(asset=cidr, check_id='rep.listed_drop').status, 'fail')
        for ip in ips:
            row = RiskCheck.objects.get(asset=ip, check_id='rep.listed_drop')
            self.assertEqual((row.status, row.evidence), ('not_applicable', {'covered_by': '45.10.0.0/24'}))
        issues = TrackedIssue.objects.filter(key='rep.listed_drop', status='open')
        self.assertEqual([i.asset_id for i in issues], [cidr.id])

    def test_first_evaluation_is_silent_then_alerts(self):
        self.feeds()
        IssueSyncState.objects.create(project=self.p, first_synced_at=self.now - timedelta(days=2), roots=['#ips'])
        self.asset('ip', '45.10.1.5')
        self.assertEqual(reputation.evaluate_reputation(self.now), {'checked': 1, 'projects': 1})
        self.assertEqual(TrackedIssue.objects.filter(key='rep.listed_drop').count(), 1)
        self.assertEqual(ChangeEvent.objects.count(), 0)
        reputation.evaluate_reputation(self.now)
        self.assertEqual(ChangeEvent.objects.count(), 0)
        self.asset('ip', '45.10.1.6')
        reputation.evaluate_reputation(self.now)
        ev = ChangeEvent.objects.get()
        self.assertEqual((ev.kind, ev.immediate), ('issue_new', True))
        reputation.evaluate_reputation(self.now)
        self.assertEqual(ChangeEvent.objects.count(), 1)

    def test_a_missing_feed_closes_nothing(self):
        self.feeds()
        IssueSyncState.objects.create(project=self.p, first_synced_at=self.now - timedelta(days=2), roots=['#ips'])
        self.asset('ip', '45.10.1.5')
        reputation.evaluate_reputation(self.now)
        FeedState.objects.filter(name='drop_v4').update(last_good_at=self.now - 100 * H)
        reputation.evaluate_reputation(self.now)
        self.assertEqual(TrackedIssue.objects.get(key='rep.listed_drop').status, 'open')
        self.assertEqual(ChangeEvent.objects.count(), 0)

    def test_monitor_ip_check_writes_rep_rows(self):
        self.feeds()
        ip = self.asset('ip', '45.10.1.5')
        with override_settings(SPAMHAUS_DQS_KEY='k'), mock.patch('dns.resolver.Resolver.resolve', side_effect=AssertionError('DNS')):
            run.run_asset_checks(ip, now=self.now)
        rows = {r.check_id: r.status for r in RiskCheck.objects.filter(asset=ip)}
        self.assertEqual(rows['rep.listed_drop'], 'fail')
        self.assertEqual(rows['rep.listed_c2'], 'pass')
        self.assertNotIn('rep.dnsbl_listed', rows)

    def test_dqs_daily_and_budget(self):
        self.feeds()
        recent, old = self.asset('ip', '45.11.0.1'), self.asset('ip', '45.11.0.2')
        for a, age in ((recent, 2 * H), (old, 30 * H)):
            RiskCheck.objects.create(asset=a, check_id='rep.dnsbl_listed', status='pass', severity=2, evidence={},
                                     last_checked=self.now - age)
        with override_settings(SPAMHAUS_DQS_KEY='k'), \
                mock.patch.object(reputation, 'dqs_lookup', return_value=('listed', '127.0.0.2')) as q, \
                mock.patch.object(reputation.ratelimit, 'take_daily', return_value=False):
            reputation.evaluate_reputation(self.now)
            q.assert_not_called()
            self.assertEqual(RiskCheck.objects.get(asset=old, check_id='rep.dnsbl_listed').status, 'pass')
        with override_settings(SPAMHAUS_DQS_KEY='k'), \
                mock.patch.object(reputation, 'dqs_lookup', return_value=('listed', '127.0.0.2')) as q, \
                mock.patch.object(reputation.ratelimit, 'take_daily', return_value=True):
            reputation.evaluate_reputation(self.now)
            q.assert_called_once_with('45.11.0.2', 'k')
            self.assertEqual(RiskCheck.objects.get(asset=old, check_id='rep.dnsbl_listed').status, 'fail')
            self.assertEqual(RiskCheck.objects.get(asset=recent, check_id='rep.dnsbl_listed').status, 'pass')


class Resolver:
    def __init__(self, answer):
        self.answer, self.names = answer, []

    def __call__(self, name, rdtype):
        self.names.append((name, rdtype))
        if isinstance(self.answer, type) or isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


class DqsTests(SimpleTestCase):
    def q(self, answer, ip='1.2.3.4'):
        r = Resolver(answer)
        return reputation.dqs_lookup(ip, 'abc123', resolve=r), r

    def test_dqs_codes(self):
        out, r = self.q(['127.0.0.2'])
        self.assertEqual(out, ('listed', '127.0.0.2'))
        self.assertEqual(r.names, [('4.3.2.1.abc123.zen.dq.spamhaus.net', 'A')])
        self.assertEqual(self.q(dns.resolver.NXDOMAIN)[0], ('clean', None))
        self.assertEqual(self.q(['127.255.255.254'])[0][0], 'error')
        self.assertEqual(self.q(['127.255.255.255'])[0][0], 'error')
        self.assertEqual(self.q(dns.exception.Timeout)[0], ('error', 'Timeout'))
        self.assertEqual(self.q(['10.1.1.1'])[0][0], 'error')
        self.assertEqual(self.q([], ip='2a0d::1')[0], ('error', 'ipv6 not supported'))
        self.assertEqual(self.q(['127.0.0.2'], ip='not-an-ip')[0][0], 'error')

    def test_dqs_key_redacted_in_logs(self):
        key = 'dqs-secret-123'
        boom = dns.exception.DNSException('no answer for 4.3.2.1.dqs-secret-123.zen.dq.spamhaus.net')
        with self.assertLogs('limes.reputation') as cm:
            state, code = reputation.dqs_lookup('1.2.3.4', key, resolve=Resolver(boom))
        self.assertEqual(state, 'error')
        self.assertTrue(cm.records)
        self.assertNotIn(key, ' '.join(r.getMessage() for r in cm.records) + str(code))
        self.assertNotIn(key, reputation.redact(f'x.{key}.y', key))
