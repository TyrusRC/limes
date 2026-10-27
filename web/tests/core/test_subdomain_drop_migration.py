from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

DROPPED = ['startScan_subdomain', 'startScan_subdomain_technologies', 'startScan_subdomain_ip_addresses',
           'startScan_endpoint', 'startScan_endpoint_techs', 'startScan_cweid', 'startScan_vulnerabilitytags',
           'startScan_vulnerabilityreference', 'startScan_vulnerability_tags', 'startScan_vulnerability_cwe_ids',
           'startScan_vulnerability_references']
WHEN = '2026-01-01T00:00:00Z'


class SubdomainDropMigrationTest(TransactionTestCase):
    """Run the migrations that drop Subdomain / EndPoint over rows in every table they touch: the finding lists
    (tags, CWEs, references) are folded into the finding, CVEs and everything else stay, and the scoring
    baselines do not move."""

    def before(self):
        """Every app at its newest migration except startScan, which stops at the last one before the drop."""
        leaves = MigrationExecutor(connection).loader.graph.leaf_nodes()
        # remediation sits on the newest startScan, so it is unapplied along with the later startScan migrations
        return [n for n in leaves if n[0] not in ('startScan', 'remediation')] + [('startScan', '0039_alert_rule_caps')]

    def migrate(self, targets):
        ex = MigrationExecutor(connection)
        ex.migrate(targets)
        return MigrationExecutor(connection).loader.project_state(targets).apps

    def tearDown(self):
        ex = MigrationExecutor(connection)
        ex.migrate(ex.loader.graph.leaf_nodes())

    def seed(self, apps):
        m = lambda name, app='startScan': apps.get_model(app, name)
        project = m('Project', 'dashboard').objects.create(name='p', slug='p', insert_date=WHEN)
        domain = m('Domain', 'targetApp').objects.create(project=project, name='x.com')
        m('Asset').objects.create(project=project, kind='root_domain', value='x.com', scope_tier='owned_root')
        host = m('Asset').objects.create(project=project, kind='hostname', value='a.x.com', scope_tier='owned_host')
        engine = m('EngineType', 'scanEngine').objects.create(engine_name='e', yaml_configuration='{}')
        scan = m('ScanHistory').objects.create(domain=domain, scan_type=engine, start_scan_date=WHEN)
        m('ScanActivity').objects.create(scan_of=scan, name='vulnerability_scan', title='v', time=WHEN, status=2,
                                         celery_id='root-1')
        tech = m('Technology').objects.create(name='nginx')
        ip = m('IpAddress').objects.create(address='192.0.2.1')
        sub = m('Subdomain').objects.create(scan_history=scan, target_domain=domain, name='a.x.com', http_status=200)
        sub.technologies.add(tech)
        sub.ip_addresses.add(ip)
        ep = m('EndPoint').objects.create(scan_history=scan, target_domain=domain, subdomain=sub,
                                          http_url='https://a.x.com/', http_status=200)
        ep.techs.add(tech)
        Vuln = m('Vulnerability')
        v1 = Vuln.objects.create(scan_history=scan, asset=host, subdomain=sub, endpoint=ep, target_domain=domain,
                                 name='n', template_id='t1', severity=4, http_url='https://a.x.com/')
        v2 = Vuln.objects.create(scan_history=scan, asset=host, name='n2', template_id='t2', severity=1,
                                 http_url='https://a.x.com/x')
        v3 = Vuln.objects.create(scan_history=scan, asset=host, name='n3', template_id='t3', severity=0,
                                 http_url='https://a.x.com/y')
        Tags, Cwe, Ref = m('VulnerabilityTags'), m('CweId'), m('VulnerabilityReference')
        shared = Tags.objects.create(name='xss')
        v1.tags.add(shared, Tags.objects.create(name='owasp'))
        v2.tags.add(shared)
        v1.cwe_ids.add(Cwe.objects.create(name='CWE-79'))
        v1.references.add(Ref.objects.create(url='https://ref.example/2'), Ref.objects.create(url='https://ref.example/1'))
        v1.cve_ids.add(m('CveId').objects.create(name='CVE-2024-1'))
        return scan

    def test_lists_fold_into_findings_and_baselines_stay(self):
        scan = self.seed(self.migrate(self.before()))
        self.assertTrue(set(DROPPED) <= set(connection.introspection.table_names()))
        self.migrate(MigrationExecutor(connection).loader.graph.leaf_nodes())
        self.assertFalse(set(DROPPED) & set(connection.introspection.table_names()))

        from dashboard.models import Project
        from limes import scoring
        from startScan.models import IpAddress, ScanHistory, Technology, Vulnerability
        project = Project.objects.get(slug='p')
        self.assertEqual(scoring.baselines(project), {'x.com': ScanHistory.objects.get(pk=scan.pk)})
        self.assertEqual(scoring.project_score(project)['top_penalties'][0]['issue'], 't1')
        by_key = {v.template_id: v for v in Vulnerability.objects.all()}
        self.assertEqual(len(by_key), 3)
        self.assertEqual((by_key['t1'].tag_names, by_key['t1'].cwe_names), (['xss', 'owasp'], ['CWE-79']))
        self.assertEqual(by_key['t1'].reference_urls, ['https://ref.example/2', 'https://ref.example/1'])
        self.assertEqual([c.name for c in by_key['t1'].cve_ids.all()], ['CVE-2024-1'])
        self.assertEqual((by_key['t2'].tag_names, by_key['t2'].cwe_names, by_key['t2'].reference_urls), (['xss'], [], []))
        self.assertEqual(by_key['t3'].tag_names, [])
        self.assertEqual((IpAddress.objects.count(), Technology.objects.count(), ScanHistory.objects.count()), (1, 1, 1))

    def test_reverse_rebuilds_the_rows_from_the_lists(self):
        self.seed(self.migrate(self.before()))
        self.migrate(MigrationExecutor(connection).loader.graph.leaf_nodes())
        apps = self.migrate(self.before())
        v1 = apps.get_model('startScan', 'Vulnerability').objects.get(template_id='t1')
        self.assertEqual(sorted(t.name for t in v1.tags.all()), ['owasp', 'xss'])
        self.assertEqual([c.name for c in v1.cwe_ids.all()], ['CWE-79'])
        self.assertEqual(sorted(r.url for r in v1.references.all()), ['https://ref.example/1', 'https://ref.example/2'])
        self.assertEqual(apps.get_model('startScan', 'VulnerabilityTags').objects.count(), 2)  # the shared tag once
