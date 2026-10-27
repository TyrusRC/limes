from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

BEFORE = [('startScan', '0035_asset_kind_api'), ('targetApp', '0003_drop_legacy_whois'),
          ('scanEngine', '0009_drop_wordlist_and_configuration'), ('dashboard', '0006_drop_llm_and_api_key_tables')]
DROPPED = ['targetApp_organization', 'targetApp_organization_domains', 'scanEngine_interestinglookupmodel',
           'dashboard_searchhistory', 'startScan_countryiso', 'startScan_subscan']
WHEN = '2026-01-01T00:00:00Z'


class LegacyDropMigrationTest(TransactionTestCase):
    """Run the stage 3 migrations over rows in every table they touch: the tables go, the kept data and the
    scoring baselines stay exactly as they were."""

    def migrate(self, targets):
        ex = MigrationExecutor(connection)
        ex.migrate(targets)
        return MigrationExecutor(connection).loader.project_state(targets).apps

    def tearDown(self):
        ex = MigrationExecutor(connection)
        ex.migrate(ex.loader.graph.leaf_nodes())

    def seed(self, apps):
        m = lambda app, name: apps.get_model(app, name)
        project = m('dashboard', 'Project').objects.create(name='p', slug='p', insert_date=WHEN)
        domain = m('targetApp', 'Domain').objects.create(project=project, name='x.com')
        m('startScan', 'Asset').objects.create(project=project, kind='root_domain', value='x.com', scope_tier='owned_root')
        host = m('startScan', 'Asset').objects.create(project=project, kind='hostname', value='a.x.com', scope_tier='owned_host')
        engine = m('scanEngine', 'EngineType').objects.create(engine_name='e', yaml_configuration='{}')
        Scan, Activity = m('startScan', 'ScanHistory'), m('startScan', 'ScanActivity')
        real = Scan.objects.create(domain=domain, scan_type=engine, start_scan_date='2026-01-01T00:00:00Z')
        Activity.objects.create(scan_of=real, name='vulnerability_scan', title='v', time=WHEN, status=2, celery_id='root-1')
        # newer scan: only a one-host subscan ran its vulnerability stage; the old rule never made it a baseline
        sub_scan = Scan.objects.create(domain=domain, scan_type=engine, start_scan_date='2026-01-02T00:00:00Z')
        Activity.objects.create(scan_of=sub_scan, name='vulnerability_scan', title='v', time=WHEN, status=2, celery_id='sub-1')
        subdomain = m('startScan', 'Subdomain').objects.create(scan_history=sub_scan, target_domain=domain, name='b.x.com')
        subscan = m('startScan', 'SubScan').objects.create(scan_history=sub_scan, subdomain=subdomain, start_scan_date=WHEN,
                                                           status=2, celery_ids=['sub-1'])
        vuln = m('startScan', 'Vulnerability').objects.create(scan_history=real, asset=host, name='n', template_id='t1',
                                                              severity=4, http_url='https://a.x.com/', is_gpt_used=True)
        vuln.vuln_subscan_ids.add(subscan)
        iso = m('startScan', 'CountryISO').objects.create(iso='NL', name='Netherlands')
        ip = m('startScan', 'IpAddress').objects.create(address='192.0.2.1', geo_iso=iso)
        ip.ip_subscan_ids.add(subscan)
        org = m('targetApp', 'Organization').objects.create(name='o', insert_date=WHEN, project=project)
        org.domains.add(domain)
        m('scanEngine', 'InterestingLookupModel').objects.create(keywords='admin')
        m('scanEngine', 'Notification').objects.create(send_interesting_notif=True)
        m('dashboard', 'SearchHistory').objects.create(query='q')
        m('dashboard', 'InAppNotification').objects.create(project=project, title='t', description='d',
                                                           redirect_link='/scan/p/detail/%d' % real.id)
        return real

    def test_tables_drop_and_baselines_stay(self):
        real = self.seed(self.migrate(BEFORE))
        self.assertTrue(set(DROPPED) <= set(connection.introspection.table_names()))
        self.migrate(MigrationExecutor(connection).loader.graph.leaf_nodes())
        self.assertFalse(set(DROPPED) & set(connection.introspection.table_names()))

        from dashboard.models import InAppNotification, Project
        from limes import scoring
        from startScan.models import IpAddress, ScanActivity, ScanHistory, Vulnerability
        project = Project.objects.get(slug='p')
        self.assertEqual(scoring.baselines(project), {'x.com': ScanHistory.objects.get(pk=real.pk)})
        self.assertEqual(scoring.project_score(project)['top_penalties'][0]['issue'], 't1')
        self.assertEqual((Vulnerability.objects.count(), IpAddress.objects.count(), ScanHistory.objects.count()), (1, 1, 2))
        self.assertEqual(sorted(ScanActivity.objects.values_list('celery_id', 'name')),
                         [('root-1', 'vulnerability_scan'), ('sub-1', 'subscan_vulnerability_scan')])
        self.assertEqual(InAppNotification.objects.get().redirect_link, '/scan/p/history/scan')
