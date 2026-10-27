from unittest import mock

import dns.resolver
from django.core.cache import cache
from django.test import SimpleTestCase

from limes import dangling
from limes.checks import takeover
from limes.intel import ratelimit
from limes.alerts.issues import sync_issues
from startScan.models import Asset, IpAddress, RiskCheck, TrackedIssue
from tests.core.test_dashboard_stats import Base
from tests.core.test_safe_fetch import FakeSession, PUBLIC, stub

GH_UNCLAIMED = b"<html><h1>404</h1><p>There isn't a GitHub Pages site here.</p></html>"
NORMAL_404 = b'<html><h1>404 Not Found</h1>the page you want is gone</html>'


class Body:
    def __init__(self, status, body):
        self.status_code, self.body = status, body

    def iter_content(self, chunk_size=8192):
        yield self.body

    def close(self):
        pass


class PureTest(SimpleTestCase):
    def test_match_table(self):
        for target, want in [('foo.github.io', 'github_pages'), ('app.herokuapp.com.', 'heroku'),
                             ('b.s3-website-us-east-1.amazonaws.com', 's3_bucket'), ('b.s3.amazonaws.com', 's3_bucket'),
                             ('x.azurewebsites.net', 'azure'), ('x.trafficmanager.net', 'azure'),
                             ('x.cloudapp.azure.com', 'azure'), ('x.blob.core.windows.net', 'azure'),
                             ('shop.myshopify.com', 'shopify'), ('x.netlify.app', 'netlify'), ('x.surge.sh', 'surge'),
                             ('x.fastly.net', 'fastly')]:
            self.assertEqual(takeover.match(target), want, target)
        for target in ('github.io.evil.example', 'notgithub.io', 'evil-herokuapp.com', 'cdn.example.com', '', None,
                       'amazonaws.com'):
            self.assertIsNone(takeover.match(target), target)

    def test_fingerprint_needs_status_and_marker(self):
        self.assertEqual(takeover.fingerprint('github_pages', 404, GH_UNCLAIMED), 'github_pages-404')
        self.assertIsNone(takeover.fingerprint('github_pages', 404, NORMAL_404))
        self.assertIsNone(takeover.fingerprint('github_pages', 200, GH_UNCLAIMED))
        self.assertIsNone(takeover.fingerprint('azure', 404, GH_UNCLAIMED))


class DanglingTest(Base):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        patch = mock.patch.object(dangling.ratelimit, 'reserve', return_value=0.0)
        patch.start()
        self.addCleanup(patch.stop)
        self.session = FakeSession(lambda url: Body(404, GH_UNCLAIMED))

    def host(self, name, cname, resolved=True, **kw):
        enrichment = {'dns': {'a': [PUBLIC] if resolved else [], 'aaaa': [], 'cname': [cname] if cname else []}}
        a = self.asset(name, cname=cname, enrichment=enrichment, **kw)
        if resolved:
            a.ip_addresses.add(IpAddress.objects.get_or_create(address=PUBLIC)[0])
        return a

    def run_scan(self, answers=None, **kw):
        # live CNAMEs default to what each asset's stored answer says; a test overrides one to model a changed zone
        live = {(a.value, 'CNAME'): list((a.enrichment.get('dns') or {}).get('cname') or [])
                for a in Asset.objects.filter(project=self.p) if (a.enrichment.get('dns') or {}).get('cname')}
        self.resolve = stub({**live, **(answers if answers is not None else {})})
        return dangling.discover(self.p, self.root, self.now, resolve=self.resolve, sleep=lambda s: None,
                                 session_factory=lambda: self.session, **kw)

    def row(self, name):
        return RiskCheck.objects.get(asset__value=name, check_id='dns.dangling_takeover')

    def web(self, name):  # a resolver that lets resolve_vetted pass for the host
        return {(name, 'A'): [PUBLIC]}

    def test_unclaimed_fingerprint_is_flagged_without_the_body(self):
        self.host('docs.x.com', 'old.github.io')
        out = self.run_scan(self.web('docs.x.com'))
        row = self.row('docs.x.com')
        self.assertEqual((row.status, out['flagged']), ('fail', 1))
        self.assertEqual(row.evidence, {'provider': 'github_pages', 'target': 'old.github.io', 'status': 404,
                                        'fingerprint': 'github_pages-404'})
        self.assertNotIn('GitHub Pages site', repr(row.evidence))
        self.assertEqual(len(self.session.requests), 1)
        url, kw = self.session.requests[0]
        self.assertIn(PUBLIC, url)  # pinned to the vetted address
        self.assertFalse(kw['allow_redirects'])

    def test_a_normal_404_is_not_a_takeover(self):
        self.session.route = lambda url: Body(404, NORMAL_404)
        self.host('docs.x.com', 'live.github.io')
        self.run_scan(self.web('docs.x.com'))
        self.assertEqual(self.row('docs.x.com').status, 'pass')

    def test_nxdomain_at_a_provider_is_flagged_with_no_request(self):
        self.host('app.x.com', 'gone.azurewebsites.net', resolved=False)
        self.run_scan({('app.x.com', 'A'): dns.resolver.NXDOMAIN})
        row = self.row('app.x.com')
        self.assertEqual((row.status, row.evidence['fingerprint'], row.evidence['status']), ('fail', 'nxdomain', None))
        self.assertEqual(self.session.requests, [])

    def test_stored_answer_is_used_before_any_query(self):
        self.host('app.x.com', 'ok.azurewebsites.net')  # resolves per the stored answer; no fingerprint known
        self.run_scan()
        self.assertEqual(self.row('app.x.com').status, 'pass')
        self.assertEqual([c for c in self.resolve.calls if c[1] != 'CNAME'], [])  # only the live CNAME confirmation
        self.assertEqual(self.session.requests, [])

    def test_failed_lookup_is_an_error_not_a_pass(self):
        self.host('app.x.com', 'gone.azurewebsites.net', resolved=False)
        self.run_scan({('app.x.com', 'A'): dns.resolver.NoNameservers})
        self.assertEqual(self.row('app.x.com').status, 'error')

    def test_only_owned_hosts_with_provider_cnames(self):
        self.host('plain.x.com', 'cdn.example.net')
        self.host('none.x.com', None)
        self.host('cand.x.com', 'old.github.io', tier='candidate')
        self.host('other.y.com', 'old.github.io')
        self.host('gone.x.com', 'old.github.io', state='retired')
        self.run_scan()
        self.assertFalse(RiskCheck.objects.filter(check_id='dns.dangling_takeover').exists())
        self.assertEqual(self.session.requests, [])

    def test_private_resolution_is_not_contacted(self):
        self.host('docs.x.com', 'old.github.io')
        self.run_scan({('docs.x.com', 'A'): ['10.0.0.5']})
        self.assertEqual(self.session.requests, [])
        self.assertEqual(self.row('docs.x.com').status, 'error')

    def test_budget_fails_closed(self):
        self.host('docs.x.com', 'old.github.io')
        broken = mock.Mock()
        broken.add.side_effect = ConnectionError('down')
        real = ratelimit.take_daily
        with mock.patch.object(ratelimit, 'take_daily', lambda provider, limit, *a: real(provider, limit, cache=broken)):
            self.run_scan(self.web('docs.x.com'))
        self.assertEqual(self.session.requests, [])
        self.assertFalse(RiskCheck.objects.filter(check_id='dns.dangling_takeover').exists())

    def test_fresh_rows_are_left(self):
        self.host('docs.x.com', 'old.github.io')
        self.run_scan(self.web('docs.x.com'))
        self.run_scan(self.web('docs.x.com'))
        self.assertEqual(len(self.session.requests), 1)

    def issue(self, asset):
        sync_issues(self.p, now=self.now)
        return TrackedIssue.objects.get(asset=asset, key='dns.dangling_takeover')

    def test_a_moved_cname_closes_the_issue(self):
        a = self.host('docs.x.com', 'old.github.io')
        self.run_scan(self.web('docs.x.com'))
        self.assertEqual(self.issue(a).status, 'open')
        a.cname, a.enrichment = 'cdn.example.net', {'dns': {'a': [PUBLIC], 'aaaa': [], 'cname': ['cdn.example.net']}}
        a.save()
        RiskCheck.objects.update(last_checked=self.now - dangling.REFRESH)
        self.run_scan()
        self.assertEqual(self.row('docs.x.com').status, 'pass')
        self.assertEqual(self.issue(a).status, 'fixed')

    def test_a_deleted_record_closes_the_issue_despite_a_stale_asset_cname(self):
        a = self.host('docs.x.com', 'old.github.io')
        self.run_scan(self.web('docs.x.com'))
        self.assertEqual(self.issue(a).status, 'open')
        # the fix: the record is deleted. dnsx never clears Asset.cname; the DNS watch stored the empty answer
        a.enrichment = {'dns': {'a': [], 'aaaa': [], 'cname': []}}
        a.save()
        RiskCheck.objects.update(last_checked=self.now - dangling.REFRESH)
        self.run_scan({('docs.x.com', 'A'): dns.resolver.NXDOMAIN, ('docs.x.com', 'CNAME'): dns.resolver.NXDOMAIN})
        self.assertEqual(self.row('docs.x.com').status, 'pass')
        self.assertEqual(self.issue(a).status, 'fixed')

    def test_stale_asset_cname_alone_is_never_flagged(self):
        self.asset('docs.x.com', cname='old.github.io', enrichment={'dns': {'a': [], 'aaaa': [], 'cname': []}})
        self.run_scan({('docs.x.com', 'A'): dns.resolver.NXDOMAIN})
        self.assertFalse(RiskCheck.objects.filter(check_id='dns.dangling_takeover').exists())

    def test_stored_cname_is_confirmed_live_before_flagging(self):
        self.host('app.x.com', 'gone.azurewebsites.net', resolved=False)
        # stored data still says CNAME, but the zone no longer has it
        self.run_scan({('app.x.com', 'A'): dns.resolver.NXDOMAIN, ('app.x.com', 'CNAME'): dns.resolver.NXDOMAIN})
        self.assertFalse(RiskCheck.objects.filter(check_id='dns.dangling_takeover').exists())
        self.run_scan({('app.x.com', 'A'): dns.resolver.NXDOMAIN, ('app.x.com', 'CNAME'): dns.resolver.NoNameservers})
        self.assertEqual(self.row('app.x.com').status, 'error')  # a failed confirmation is never a finding

    def test_cap_applies_after_the_cname_filter_and_rotates_oldest_first(self):
        for i in range(dangling.MAX_HOSTS):
            self.host(f'h{i:03d}.x.com', 'cdn.example.net')
        self.host('zz.x.com', 'gone.azurewebsites.net', resolved=False)
        self.run_scan({('zz.x.com', 'A'): dns.resolver.NXDOMAIN})
        self.assertEqual(self.row('zz.x.com').status, 'fail')
        with mock.patch.object(dangling, 'MAX_HOSTS', 2):
            for n in ('a1', 'a2', 'a3'):
                self.host(f'{n}.x.com', 'gone.azurewebsites.net', resolved=False)
            answers = {(f'{n}.x.com', 'A'): dns.resolver.NXDOMAIN for n in ('a1', 'a2', 'a3')}
            self.run_scan(answers)
            done = RiskCheck.objects.filter(asset__value__startswith='a', check_id='dns.dangling_takeover').count()
            self.assertEqual(done, 2)
            self.run_scan(answers)
            self.assertEqual(RiskCheck.objects.filter(asset__value__startswith='a', check_id='dns.dangling_takeover').count(), 3)

    def test_total_time_budget_stops_cleanly_and_resumes(self):
        for n in ('a1', 'a2', 'a3'):
            self.host(f'{n}.x.com', 'gone.azurewebsites.net', resolved=False)
        answers = {(f'{n}.x.com', 'A'): dns.resolver.NXDOMAIN for n in ('a1', 'a2', 'a3')}
        ticks = iter(range(0, 100000, dangling.RUN_SECONDS // 2 + 1))
        out = self.run_scan(answers, clock=lambda: next(ticks))
        self.assertEqual(RiskCheck.objects.filter(check_id='dns.dangling_takeover').count(), out['hosts'])
        self.assertLess(out['hosts'], 3)
        self.run_scan(answers)
        self.assertEqual(RiskCheck.objects.filter(check_id='dns.dangling_takeover').count(), 3)

    def test_error_rows_retry_after_six_hours_only(self):
        self.host('app.x.com', 'gone.azurewebsites.net', resolved=False)
        bad = {('app.x.com', 'A'): dns.resolver.NoNameservers}
        self.run_scan(bad)
        self.assertEqual(self.row('app.x.com').status, 'error')
        RiskCheck.objects.update(last_checked=self.now - dangling.ERROR_RETRY / 2)
        self.run_scan(bad)
        self.assertEqual(self.resolve.calls, [])  # too soon
        RiskCheck.objects.update(last_checked=self.now - dangling.ERROR_RETRY)
        self.run_scan(bad)
        self.assertNotEqual(self.resolve.calls, [])

    def test_one_project_cannot_spend_the_whole_daily_budget(self):
        for i in range(6):
            self.host(f'h{i}.x.com', 'old.github.io')
        answers = {(f'h{i}.x.com', 'A'): [PUBLIC] for i in range(6)}
        with mock.patch.object(dangling, 'DAILY_BUDGET', 8):  # a quarter is 2
            self.run_scan(answers)
        self.assertEqual(len(self.session.requests), 2)
