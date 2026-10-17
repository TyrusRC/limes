from unittest import mock
from django.test import TestCase
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from dashboard.views import on_user_logged_in
from rest_framework.test import APIClient
from django.utils import timezone
from dashboard.models import Project
from startScan.models import Asset


class AssetListApiTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('u', password='p')
        self.c = APIClient()
        # The app's login signal handler assumes request.user (absent on the test client).
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.c.force_login(self.user)
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.other = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host', parent=self.root)
        Asset.objects.create(project=self.p, kind='hostname', value='b.x.com', scope_tier='candidate', state='missing', parent=self.root)
        Asset.objects.create(project=self.other, kind='hostname', value='secret.y.com', scope_tier='owned_host')

    def _get(self, **params):
        params.setdefault('no_page', '1')
        return self.c.get('/api/listDatatableAsset/', params)

    def _vals(self, **params):
        return {a['value'] for a in self._get(**params).json()}

    def _scored(self, value, confidence):
        return Asset.objects.create(project=self.p, kind='root_domain', value=value, scope_tier='candidate',
                                    confidence=confidence,
                                    confidence_detail={'version': 'attribution-v1', 'score': confidence, 'contributions': []})

    def test_low_confidence_candidates_hidden_by_default(self):
        self._scored('low.net', 0.2)
        self._scored('mid.net', 0.6)
        self.assertNotIn('low.net', self._vals(project='p1'))
        self.assertIn('mid.net', self._vals(project='p1'))
        self.assertIn('b.x.com', self._vals(project='p1'))  # unscored candidates still shown
        self.assertIn('low.net', self._vals(project='p1', show_low='1'))

    def test_hidden_candidate_still_retrievable(self):
        low = self._scored('low.net', 0.2)
        r = self.c.get(f'/api/listDatatableAsset/{low.id}/', {'project': 'p1'})
        self.assertEqual((r.status_code, r.json()['confidence']), (200, 0.2))

    def test_order_by_confidence_nulls_last(self):
        self._scored('mid.net', 0.6)
        self._scored('hi.net', 0.85)
        r = self.c.get('/api/listDatatableAsset/', {'project': 'p1', 'no_page': '1',
                                                    'order[0][column]': '10', 'order[0][dir]': 'desc'})
        vals = [a['value'] for a in r.json()]
        self.assertEqual(vals[:2], ['hi.net', 'mid.net'])

    def test_project_isolation(self):
        vals = self._vals(project='p1')
        self.assertIn('a.x.com', vals)
        self.assertNotIn('secret.y.com', vals)

    def test_no_or_unknown_project_returns_empty(self):
        self.assertEqual(self._get().json(), [])
        self.assertEqual(self._get(project='nope').json(), [])

    def test_facets(self):
        self.assertEqual(self._vals(project='p1', scope_tier='candidate'), {'b.x.com'})
        self.assertEqual(self._vals(project='p1', state='missing'), {'b.x.com'})
        self.assertIn('x.com', self._vals(project='p1', kind='root_domain'))

    def test_parent_value_and_ordering_colmap(self):
        r = self.c.get('/api/listDatatableAsset/', {'project': 'p1', 'no_page': '1',
                                                    'order[0][column]': '0', 'order[0][dir]': 'desc'})
        rows = r.json()
        self.assertEqual([a['value'] for a in rows], ['x.com', 'b.x.com', 'a.x.com'])
        self.assertEqual({a['value']: a['parent_value'] for a in rows}['a.x.com'], 'x.com')

    def test_list_endpoint_is_read_only(self):
        # Writes go through the permission-gated action endpoints only.
        url = f'/api/listDatatableAsset/{self.root.id}/?project=p1'
        self.assertEqual(self.c.delete(url).status_code, 405)
        self.assertEqual(self.c.patch(url, {'scope_tier': 'rejected'}, format='json').status_code, 405)
        self.root.refresh_from_db()
        self.assertEqual(self.root.scope_tier, 'owned_root')

    def test_retrieve_is_project_scoped_and_exposes_parent(self):
        host = Asset.objects.get(value='a.x.com')
        r = self.c.get(f'/api/listDatatableAsset/{host.id}/', {'project': 'p1'})
        self.assertEqual(r.json()['parent'], self.root.id)
        secret = Asset.objects.get(value='secret.y.com')
        self.assertEqual(self.c.get(f'/api/listDatatableAsset/{secret.id}/', {'project': 'p1'}).status_code, 404)

    def test_retrieve_includes_enrichment(self):
        self.root.enrichment = {'ripestat': {'asn': '13335', 'prefix': None, 'holder': 'X', 'fetched_at': 't'}}
        self.root.save()
        r = self.c.get(f'/api/listDatatableAsset/{self.root.id}/', {'project': 'p1'})
        self.assertEqual(r.json()['enrichment']['ripestat']['asn'], '13335')

    def test_no_n_plus_one(self):
        # session + user + asset(+parent join, vuln count) + 3 prefetches
        with self.assertNumQueries(6):
            self._get(project='p1')
        a = Asset.objects.create(project=self.p, kind='hostname', value='c.x.com',
                                 scope_tier='owned_host', parent=self.root)
        a.tags.create(name='t1')
        a.technologies.create(name='nginx')
        a.ip_addresses.create(address='1.2.3.4')
        with self.assertNumQueries(6):  # same count with one more row: does not scale
            rows = self._get(project='p1').json()
        c = next(r for r in rows if r['value'] == 'c.x.com')
        self.assertEqual((c['tags'], c['technologies'], c['ip_addresses'], c['vuln_count']),
                         (['t1'], ['nginx'], ['1.2.3.4'], 0))


class AddAssetsApiTest(TestCase):
    def setUp(self):
        from unittest import mock
        from rolepermissions.roles import assign_role
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.other = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        p = mock.patch('dashboard.stats.invalidate')
        self.inv = p.start()
        self.addCleanup(p.stop)

    def _post(self, user, **body):
        c = APIClient()
        c.force_login(user)
        return c.post('/api/add/assets/', body, format='json')

    def test_bulk_add_validates_and_is_idempotent(self):
        body = dict(project='p1', text='c.x.com\n10.0.0.1\n*.x.com\n8.8.8.8',
                    tier='owned_host', reason='manual')
        msg = self._post(self.admin, **body).json()['message']
        self.assertEqual((msg['added'], msg['skipped'], len(msg['warnings'])), (2, 2, 2))
        vals = set(Asset.objects.filter(project=self.p).values_list('value', flat=True))
        self.assertEqual(vals, {'c.x.com', '8.8.8.8'})
        a = Asset.objects.get(project=self.p, value='c.x.com')
        self.assertEqual((a.scope_tier, a.added_by, a.decision_reason, a.state),
                         ('owned_host', self.admin, 'manual', 'active'))
        self.assertFalse(Asset.objects.filter(project=self.other).exists())
        self.inv.assert_called_with(self.p.id)
        self._post(self.admin, **body)
        self.assertEqual(Asset.objects.filter(project=self.p, value='c.x.com').count(), 1)

    def test_every_entry_accounted(self):
        text = '8.8.8.1-8.8.8.6\nexample.co.uk\nAS12345\n12345\n8.8.8.2/31'
        msg = self._post(self.admin, project='p1', text=text, tier='owned_root').json()['message']
        self.assertEqual((msg['added'], msg['skipped'], msg['existing']), (6, 1, 1))
        self.assertEqual(msg['added'] + msg['existing'] + msg['skipped'], 8)
        self.assertTrue(any('AS12345' in w for w in msg['warnings']))
        self.assertEqual(Asset.objects.filter(project=self.p, kind='cidr').count(), 4)
        self.assertTrue(Asset.objects.filter(project=self.p, kind='asn', value='AS12345').exists())
        self.assertTrue(Asset.objects.filter(project=self.p, kind='root_domain', value='example.co.uk').exists())

    def test_project_range_cap(self):
        from django.test import override_settings
        Asset.objects.create(project=self.p, kind='cidr', value='8.8.0.0/21', scope_tier='owned_root')
        with override_settings(RANGE_ADDRESS_CAP=4096):
            msg = self._post(self.admin, project='p1', entries=['9.9.0.0/20'], tier='owned_root').json()['message']
            self.assertEqual((msg['added'], msg['skipped']), (0, 1))
            self.assertIn('4096', msg['warnings'][0])
            self.assertIn('2048', msg['warnings'][0])
            msg = self._post(self.admin, project='p1', entries=['9.9.0.0/22', '9.9.4.0/22', '9.9.8.0/22'],
                             tier='owned_root').json()['message']
            self.assertEqual((msg['added'], msg['skipped']), (2, 1))  # 2048 in use + two /22 fill the cap; the third is refused

    def test_range_addresses_counts_owned_live_cidrs(self):
        from limes.owned_ranges import addresses, range_addresses
        asn = Asset.objects.create(project=self.p, kind='asn', value='AS1', scope_tier='owned_root')
        mk = lambda v, **kw: Asset.objects.create(project=self.p, kind='cidr', value=v, **{'scope_tier': 'owned_root', **kw})
        mk('8.8.0.0/24'); mk('8.8.1.0/24', parent=asn); mk('8.8.2.0/24', state='retired')
        mk('8.8.3.0/24', scope_tier='candidate')
        self.assertEqual(range_addresses(self.p), 512)
        self.assertEqual(range_addresses(self.p, exclude_parent=asn), 256)
        self.assertEqual((addresses('8.8.8.8'), addresses('2606:4700::/120')), (1, 256))

    def test_manual_source_recorded(self):
        self._post(self.admin, project='p1', entries=['d.x.com'], reason='because')
        a = Asset.objects.get(project=self.p, value='d.x.com')
        self.assertEqual((a.sources[0]['source'], a.sources[0]['evidence']), ('manual', 'because'))
        self._post(self.admin, project='p1', entries=['e.x.com'])
        self.assertEqual(Asset.objects.get(value='e.x.com').sources[0]['evidence'], 'added by adm')

    def test_readding_a_dependency_ip_promotes_it(self):
        Asset.objects.create(project=self.p, kind='ip', value='8.8.8.8', scope_tier='dependency')
        msg = self._post(self.admin, project='p1', entries=['8.8.8.8'], tier='owned_host').json()['message']
        self.assertEqual((msg['added'], msg['existing']), (1, 0))
        self.assertEqual(Asset.objects.get(project=self.p, value='8.8.8.8').scope_tier, 'owned_host')

    def test_entries_list_and_unknown_project(self):
        self.assertEqual(self._post(self.admin, project='p1', entries=['d.x.com']).json()['message']['added'], 1)
        r = self._post(self.admin, project='nope', entries=['e.x.com'])
        self.assertEqual((r.status_code, r.json()['status']), (200, False))
        self.assertFalse(Asset.objects.filter(value='e.x.com').exists())

    def test_without_permission_denied(self):
        r = self._post(self.auditor, project='p1', entries=['f.x.com'])
        self.assertEqual(r.status_code, 403)
        self.assertFalse(Asset.objects.filter(value='f.x.com').exists())

    def test_active_authorized_parsed_strictly(self):
        for raw in ('false', '0', 'no', ''):
            self._post(self.admin, project='p1', entries=['t.co.com'], tier='co_brand', active_authorized=raw)
            self.assertFalse(Asset.objects.get(project=self.p, value='t.co.com').active_authorized, raw)
        self._post(self.admin, project='p1', entries=['t.co.com'], tier='co_brand', active_authorized='true')
        self.assertTrue(Asset.objects.get(project=self.p, value='t.co.com').active_authorized)
        # omitting the key on re-add must not flip the existing value
        self._post(self.admin, project='p1', entries=['t.co.com'], tier='co_brand')
        self.assertTrue(Asset.objects.get(project=self.p, value='t.co.com').active_authorized)

    def test_non_string_input_does_not_500(self):
        r = self._post(self.admin, project='p1', entries=[{'x': 1}, 5, 'g.x.com'])
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.json()['message']['added'], r.json()['message']['skipped']), (1, 2))
        r = self._post(self.admin, project='p1', entries={'a': 1})
        self.assertEqual((r.status_code, r.json()['status']), (200, False))


    def test_readd_never_downgrades_resurrects_or_wipes(self):
        root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root',
                                    decision_reason='ours since 2019')
        rej = Asset.objects.create(project=self.p, kind='hostname', value='r.x.com', scope_tier='rejected')
        cand = Asset.objects.create(project=self.p, kind='hostname', value='k.x.com', scope_tier='candidate')
        msg = self._post(self.admin, project='p1', entries=['x.com', 'r.x.com', 'k.x.com'], tier='owned_host').json()['message']
        root.refresh_from_db(); rej.refresh_from_db(); cand.refresh_from_db()
        self.assertEqual((root.scope_tier, root.decision_reason), ('owned_root', 'ours since 2019'))
        self.assertEqual(rej.scope_tier, 'rejected')
        self.assertEqual((cand.scope_tier, cand.added_by), ('owned_host', self.admin))
        # candidate promotion counts as added; unchanged root is existing; rejected is skipped with a warning
        self.assertEqual((msg['added'], msg['existing'], msg['skipped']), (1, 1, 1))
        self.assertTrue(any('rejected' in w for w in msg['warnings']))

    def test_malformed_body_and_reason_do_not_500(self):
        r = self._post(self.admin, project='p1', entries=['h.x.com'], reason=5)
        self.assertEqual((r.status_code, r.json()['status']), (200, True))
        c = APIClient(); c.force_login(self.admin)
        r = c.post('/api/add/assets/', [1], format='json')
        self.assertEqual((r.status_code, r.json()['status']), (200, False))

    def test_entry_count_is_capped(self):
        r = self._post(self.admin, project='p1', text='\n'.join(f'h{i}.x.com' for i in range(5001)))
        self.assertEqual((r.status_code, r.json()['status']), (200, False))
        self.assertFalse(Asset.objects.filter(project=self.p).exists())

class ConfirmRejectAssetTest(TestCase):
    def setUp(self):
        from rolepermissions.roles import assign_role
        self.admin = User.objects.create_user('adm2', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud2', password='p')
        assign_role(self.auditor, 'auditor')
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.a = Asset.objects.create(project=self.p, kind='hostname', value='c.x.com', scope_tier='candidate', state='missing')
        patcher = mock.patch('dashboard.stats.invalidate')
        self.inv = patcher.start()
        self.addCleanup(patcher.stop)

    def _post(self, user, action, **body):
        body.setdefault('project', 'p1')
        c = APIClient()
        c.force_login(user)
        return c.post(f'/api/action/asset/{action}/', body, format='json')

    def test_confirm_sets_fields_and_invalidates(self):
        r = self._post(self.admin, 'confirm', asset_id=self.a.id, tier='owned_host', reason='mine')
        self.assertEqual(r.json(), {'status': True, 'message': 'confirmed'})
        self.a.refresh_from_db()
        self.assertEqual((self.a.scope_tier, self.a.added_by, self.a.decision_reason, self.a.state),
                         ('owned_host', self.admin, 'mine', 'active'))
        self.inv.assert_called_with(self.p.id)

    def test_confirm_active_authorized_strict(self):
        self._post(self.admin, 'confirm', asset_id=self.a.id, tier='co_brand', active_authorized='false')
        self.a.refresh_from_db()
        self.assertFalse(self.a.active_authorized)
        self._post(self.admin, 'confirm', asset_id=self.a.id, tier='co_brand', active_authorized='true')
        self.a.refresh_from_db()
        self.assertTrue(self.a.active_authorized)

    def test_reject(self):
        r = self._post(self.admin, 'reject', asset_id=self.a.id, reason='nope')
        self.assertEqual(r.json(), {'status': True, 'message': 'rejected'})
        self.a.refresh_from_db()
        self.assertEqual((self.a.scope_tier, self.a.added_by, self.a.decision_reason),
                         ('rejected', self.admin, 'nope'))
        self.inv.assert_called_with(self.p.id)

    def test_without_permission_denied(self):
        for action in ('confirm', 'reject'):
            self.assertEqual(self._post(self.auditor, action, asset_id=self.a.id).status_code, 403)
        self.a.refresh_from_db()
        self.assertEqual(self.a.scope_tier, 'candidate')

    def test_missing_or_invalid_asset(self):
        for action in ('confirm', 'reject'):
            for aid in (999999, 'abc', None):
                r = self._post(self.admin, action, asset_id=aid)
                self.assertEqual((r.status_code, r.json()['status']), (200, False), (action, aid))


    def test_actions_are_project_scoped(self):
        other = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        foreign = Asset.objects.create(project=other, kind='root_domain', value='y.com', scope_tier='candidate')
        for action in ('confirm', 'reject', 'rescan'):
            # another project's id under this project, and no project at all
            for project in ('p1', ''):
                r = self._post(self.admin, action, asset_id=foreign.id, project=project).json()
                self.assertFalse(r['status'], (action, project))
        foreign.refresh_from_db()
        self.assertEqual(foreign.scope_tier, 'candidate')

class RescanAssetApiTest(TestCase):
    def setUp(self):
        from rolepermissions.roles import assign_role
        from targetApp.models import Domain
        self.admin = User.objects.create_user('adm3', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud3', password='p')
        assign_role(self.auditor, 'auditor')
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.domain = Domain.objects.create(project=self.p, name='x.com', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.host = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com',
                                         scope_tier='owned_host', parent=self.root)
        self.cand = Asset.objects.create(project=self.p, kind='root_domain', value='c.com', scope_tier='candidate')
        self.nodom = Asset.objects.create(project=self.p, kind='root_domain', value='nodom.com', scope_tier='owned_root')
        # patch where the names are looked up (limes.continuous.start_asm_scan); nothing really runs
        for target in ('limes.continuous.initiate_scan.apply_async', 'limes.continuous.create_scan_object'):
            p = mock.patch(target)
            m = p.start()
            self.addCleanup(p.stop)
            setattr(self, 'apply_async' if 'apply' in target else 'create', m)
        self.create.return_value = 77
        from scanEngine.models import EngineType
        self.engine = EngineType.objects.create(engine_name='custom', yaml_configuration='{}')
        self.default_engine = EngineType.objects.create(engine_name='default', yaml_configuration='{}',
                                                        default_engine=True)

    def _post(self, user, **body):
        body.setdefault('project', 'p1')
        c = APIClient()
        c.force_login(user)
        return c.post('/api/action/asset/rescan/', body, format='json')

    def test_root_domain_enqueues_asm_scan(self):
        r = self._post(self.admin, asset_id=self.root.id, engine_id=self.engine.id)
        self.assertEqual(r.json(), {'status': True, 'message': 'ASM scan started for x.com'})
        self.create.assert_called_once_with(host_id=self.domain.id, engine_id=self.engine.id,
                                            initiated_by_id=self.admin.id)
        self.apply_async.assert_called_once()
        kw = self.apply_async.call_args.kwargs['kwargs']
        self.assertEqual((kw['scan_mode'], kw['domain_id'], kw['scan_history_id'], kw['initiated_by_id']),
                         ('asm', self.domain.id, 77, self.admin.id))

    def test_without_engine_uses_default_engine(self):
        # The Assets page sends no engine_id.
        self.assertTrue(self._post(self.admin, asset_id=self.root.id).json()['status'])
        self.create.assert_called_once_with(host_id=self.domain.id, engine_id=self.default_engine.id,
                                            initiated_by_id=self.admin.id)

    def test_without_engine_reuses_last_scan_engine(self):
        from startScan.models import ScanHistory
        ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, scan_status=2,
                                   start_scan_date=timezone.now())
        self.assertTrue(self._post(self.admin, asset_id=self.root.id).json()['status'])
        self.create.assert_called_once_with(host_id=self.domain.id, engine_id=self.engine.id,
                                            initiated_by_id=self.admin.id)

    def test_unknown_engine_or_no_default_enqueues_nothing(self):
        for engine_id in (999999, 'abc'):
            r = self._post(self.admin, asset_id=self.root.id, engine_id=engine_id).json()
            self.assertFalse(r['status'])
        self.default_engine.delete()
        self.assertFalse(self._post(self.admin, asset_id=self.root.id).json()['status'])
        self.apply_async.assert_not_called()
        self.create.assert_not_called()

    def test_unsupported_assets_enqueue_nothing(self):
        for a in (self.host, self.cand):
            r = self._post(self.admin, asset_id=a.id).json()
            self.assertFalse(r['status'])
            self.assertIn('not supported', r['message'])
        self.apply_async.assert_not_called()
        self.create.assert_not_called()

    def test_no_domain_record(self):
        r = self._post(self.admin, asset_id=self.nodom.id).json()
        self.assertFalse(r['status'])
        self.assertIn('no Domain record', r['message'])
        self.apply_async.assert_not_called()

    def test_missing_asset(self):
        self.assertFalse(self._post(self.admin, asset_id='abc').json()['status'])

    def test_without_permission_denied(self):
        self.assertEqual(self._post(self.auditor, asset_id=self.root.id).status_code, 403)
        self.apply_async.assert_not_called()


class AssetCadenceApiTest(TestCase):
    def setUp(self):
        from rolepermissions.roles import assign_role
        self.admin = User.objects.create_user('adm4', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud4', password='p')
        assign_role(self.auditor, 'auditor')
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.host = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')

    def _post(self, user, **body):
        body.setdefault('project', 'p1')
        c = APIClient()
        c.force_login(user)
        return c.post('/api/action/asset/cadence/', body, format='json')

    def tier(self, a):
        a.refresh_from_db()
        return a.cadence_tier

    def test_sets_a_known_tier(self):
        for tier in ('crown_jewel', 'inactive', 'off', 'standard'):
            r = self._post(self.admin, asset_id=self.root.id, cadence_tier=tier).json()
            self.assertEqual(r, {'status': True, 'message': f'cadence set to {tier}'})
            self.assertEqual(self.tier(self.root), tier)

    def test_rejects_unknown_tier_and_non_roots(self):
        for body in ({'asset_id': self.root.id, 'cadence_tier': 'hourly'}, {'asset_id': self.root.id},
                     {'asset_id': self.root.id, 'cadence_tier': ['off']}, {'asset_id': self.host.id, 'cadence_tier': 'off'}):
            self.assertFalse(self._post(self.admin, **body).json()['status'], body)
        self.assertEqual((self.tier(self.root), self.tier(self.host)), ('standard', 'standard'))

    def test_needs_scan_permission(self):
        r = self._post(self.auditor, asset_id=self.root.id, cadence_tier='off')
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.tier(self.root), 'standard')

    def test_list_exposes_cadence(self):
        c = APIClient()
        c.force_login(self.admin)
        r = c.get(f'/api/listDatatableAsset/{self.root.id}/', {'project': 'p1'})
        self.assertEqual(r.json()['cadence_tier'], 'standard')


class AssetScoreApiTest(TestCase):
    def setUp(self):
        from datetime import timedelta
        from limes.definitions import SUCCESS_TASK
        from scanEngine.models import EngineType
        from startScan.models import ScanActivity, ScanHistory, Vulnerability
        from targetApp.models import Domain
        self.user = User.objects.create_user('u5', password='p')
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.c = APIClient()
        self.c.force_login(self.user)
        self.p = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        domain = Domain.objects.create(project=self.p, name='x.com', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='x.com', scope_tier='owned_root')
        self.host = Asset.objects.create(project=self.p, kind='hostname', value='a.x.com', scope_tier='owned_host')
        self.cand = Asset.objects.create(project=self.p, kind='root_domain', value='c.com', scope_tier='candidate')
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='e', yaml_configuration='{}'),
                                          start_scan_date=timezone.now() - timedelta(hours=1))
        ScanActivity.objects.create(scan_of=scan, name='vulnerability_scan', title='v', time=timezone.now(), status=SUCCESS_TASK)
        Vulnerability.objects.create(scan_history=scan, asset=self.host, name='<img src=x onerror=alert(1)>', severity=3,
                                     http_url='https://a.x.com/')

    def test_project_score(self):
        r = self.c.get('/api/asset_score/', {'project': 'p1'})
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual((d['score'], d['grade'], d['version'], d['coverage'], d['asset_count']), (799, 'B', 'limes-score-v3', 1.0, 2))
        self.assertEqual(d['top_penalties'][0]['issue'], '<img src=x onerror=alert(1)>')
        self.assertEqual(d['history'], [])

    def test_unknown_project_is_404(self):
        self.assertEqual(self.c.get('/api/asset_score/', {'project': 'nope'}).status_code, 404)
        self.assertEqual(self.c.get('/api/asset_score/').status_code, 404)

    def test_requires_login(self):
        self.assertNotEqual(APIClient().get('/api/asset_score/', {'project': 'p1'}).status_code, 200)

    def test_retrieve_carries_risk_list_does_not(self):
        one = self.c.get(f'/api/listDatatableAsset/{self.host.id}/', {'project': 'p1'}).json()
        self.assertEqual((one['risk']['score'], one['risk']['grade']), (799, 'B'))
        self.assertIsNone(self.c.get(f'/api/listDatatableAsset/{self.cand.id}/', {'project': 'p1'}).json()['risk'])
        rows = self.c.get('/api/listDatatableAsset/', {'project': 'p1', 'no_page': '1'}).json()
        self.assertTrue(all('risk' not in r for r in rows))


class RiskChecksRetrieveTest(AssetScoreApiTest):
    def test_retrieve_lists_risk_checks_failed_first(self):
        from startScan.models import RiskCheck
        RiskCheck.objects.create(asset=self.host, check_id='web.csp_missing', status='pass', severity=1)
        RiskCheck.objects.create(asset=self.host, check_id='web.hsts_missing', status='fail', severity=2, evidence={'k': 'v'})
        RiskCheck.objects.create(asset=self.host, check_id='web.https_missing', status='fail', severity=3)
        rows = self.c.get(f'/api/listDatatableAsset/{self.host.id}/', {'project': 'p1'}).json()['risk_checks']
        self.assertEqual([r['check'] for r in rows], ['web.https_missing', 'web.hsts_missing', 'web.csp_missing'])
        self.assertEqual(rows[0]['severity'], 3)
        self.assertTrue(rows[0]['title'] and rows[0]['fix'])
        self.assertEqual(rows[1]['evidence'], {'k': 'v'})
