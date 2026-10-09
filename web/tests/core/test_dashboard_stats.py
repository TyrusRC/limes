from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dashboard.models import Project
from dashboard.stats import invalidate, project_stats
from scanEngine.models import EngineType
from startScan.models import EndPoint, IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class StatsTest(TestCase):
    def setUp(self):
        cache.clear()
        now = timezone.now()
        self.project = Project.objects.create(name='p', slug='p', insert_date=now)
        domain = Domain.objects.create(name='d.test', project=self.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
        s1 = Subdomain.objects.create(name='a.d.test', scan_history=scan, target_domain=domain, http_status=200, discovered_date=now)
        Subdomain.objects.create(name='b.d.test', scan_history=scan, target_domain=domain, http_status=0, discovered_date=now)
        ip1, ip2 = IpAddress.objects.create(address='192.0.2.1'), IpAddress.objects.create(address='192.0.2.2')
        s1.ip_addresses.add(ip1, ip2)
        EndPoint.objects.create(http_url='https://a.d.test/', scan_history=scan,
                                target_domain=domain, subdomain=s1, http_status=200, discovered_date=now)
        for sev in (0, 3, 3, 4):
            Vulnerability.objects.create(name='v', severity=sev, scan_history=scan, target_domain=domain, discovered_date=now)

    def test_counts(self):
        s = project_stats(self.project)
        self.assertEqual((s['domain_count'], s['subdomain_count'], s['alive_count']), (1, 2, 1))
        self.assertEqual(s['subdomain_with_ip_count'], 1)  # distinct, not one row per IP
        self.assertEqual((s['high_count'], s['critical_count'], s['info_count']), (2, 1, 1))
        self.assertEqual(s['total_vul_ignore_info_count'], 3)
        self.assertEqual(s['subdomains_in_last_week'][-1], 2)
        self.assertEqual(len(s['last_7_dates']), 7)

    def test_empty_project_returns_zeros(self):
        empty = Project.objects.create(name='e', slug='e', insert_date=timezone.now())
        s = project_stats(empty)
        self.assertEqual((s['subdomain_count'], s['critical_count'], s['total_vul_count']), (0, 0, 0))
        self.assertEqual(s['vulns_in_last_week'], [0] * 7)

    def test_query_budget_and_cache_hit(self):
        with CaptureQueriesContext(connection) as cold:
            project_stats(self.project)
        self.assertLessEqual(len(cold.captured_queries), 25)
        with CaptureQueriesContext(connection) as warm:
            project_stats(self.project)
        self.assertEqual(len(warm.captured_queries), 0)

    def test_invalidate(self):
        project_stats(self.project)
        invalidate(self.project.id)
        with CaptureQueriesContext(connection) as ctx:
            project_stats(self.project)
        self.assertGreater(len(ctx.captured_queries), 0)
