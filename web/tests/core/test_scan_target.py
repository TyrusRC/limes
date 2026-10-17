import importlib
from io import StringIO
from unittest import mock

from django.apps import apps
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.views import on_user_logged_in
from limes import continuous, scan_target
from limes.scan_target import OTHER_PROJECT_MSG, ensure_scan_target, has_scan_target
from limes.tasks import attribution, inventory
from startScan.models import Asset
from targetApp.models import Domain


class Base(TestCase):
    def setUp(self):
        self.a = Project.objects.create(name='Alpha Corp', slug='alpha-corp', insert_date=timezone.now())
        self.b = Project.objects.create(name='Beta Secret', slug='beta-secret', insert_date=timezone.now())

    def root(self, value='x.com', project=None, **kw):
        return Asset.objects.create(project=project or self.a, kind='root_domain', value=value,
                                    **{'scope_tier': 'owned_root', **kw})


class ScanTargetTest(Base):
    def test_creates_and_is_idempotent(self):
        r = self.root()
        d1, w1 = ensure_scan_target(r)
        d2, w2 = ensure_scan_target(r)
        self.assertEqual((d1.id, w1, w2), (d2.id, None, None))
        self.assertEqual((Domain.objects.count(), d1.project_id, d1.name), (1, self.a.id, 'x.com'))
        self.assertTrue(has_scan_target(r))
        self.assertIn(r, continuous.due_roots(timezone.now()))

    def test_links_existing_same_project(self):
        d = Domain.objects.create(name='x.com', project=self.a, insert_date=timezone.now())
        self.assertEqual(ensure_scan_target(self.root()), (d, None))
        self.assertEqual(Domain.objects.count(), 1)

    def test_other_project_not_created(self):
        for owner in (self.b, None):
            Domain.objects.all().delete()
            Domain.objects.create(name='x.com', project=owner, insert_date=timezone.now())
            d, msg = ensure_scan_target(self.root('x.com') if not Asset.objects.filter(value='x.com').exists()
                                        else Asset.objects.get(value='x.com'))
            self.assertIsNone(d)
            self.assertEqual(msg, OTHER_PROJECT_MSG.format(value='x.com'))
            for leak in ('Beta', 'beta', 'Secret'):
                self.assertNotIn(leak, msg)
            self.assertEqual(Domain.objects.count(), 1)
            self.assertFalse(has_scan_target(Asset.objects.get(value='x.com')))

    def test_non_roots_ignored(self):
        host = Asset.objects.create(project=self.a, kind='hostname', value='h.x.com', scope_tier='owned_host')
        light = self.root('y.com', scope_tier='owned_host')
        cand = self.root('z.com', scope_tier='candidate')
        for a in (host, light, cand):
            self.assertEqual(ensure_scan_target(a), (None, None))
        self.assertEqual(Domain.objects.count(), 0)

    def test_lost_race_rereads(self):
        r = self.root()
        real = Domain.objects.filter

        def racing_filter(*a, **kw):
            qs = real(*a, **kw)
            if not Domain.objects.exists():  # first read: nothing yet, then another worker creates it
                Domain.objects.create(name='x.com', project=self.a, insert_date=timezone.now())
                return real(pk=-1)
            return qs
        with mock.patch.object(scan_target.Domain.objects, 'filter', side_effect=racing_filter):
            d, w = ensure_scan_target(r)
        self.assertEqual((d.name, w, Domain.objects.count()), ('x.com', None, 1))


class WiredBase(Base):
    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        p = mock.patch('dashboard.stats.invalidate')
        self.inv = p.start()
        self.addCleanup(p.stop)
        self.c = APIClient()
        self.c.force_login(self.admin)

    def post(self, url, **body):
        return self.c.post(url, body, format='json').json()


class WiredPathsTest(WiredBase):
    def test_add_assets_creates_target_and_warns_on_clash(self):
        Domain.objects.create(name='taken.com', project=self.b, insert_date=timezone.now())
        msg = self.post('/api/add/assets/', project='alpha-corp', entries=['new.com', 'taken.com', 'h.new.com'],
                        tier='owned_root')['message']
        self.assertEqual(msg['added'], 3)
        self.assertTrue(Domain.objects.filter(name='new.com', project=self.a).exists())
        self.assertEqual(Domain.objects.filter(name='taken.com').count(), 1)
        self.assertFalse(Domain.objects.filter(name='h.new.com').exists())
        self.assertIn(OTHER_PROJECT_MSG.format(value='taken.com'), msg['warnings'])
        self.assertFalse(any('Beta' in w or 'beta' in w for w in msg['warnings']))

    def test_add_assets_promoting_a_candidate_root_creates_target(self):
        Asset.objects.create(project=self.a, kind='root_domain', value='cand.com', scope_tier='candidate')
        self.post('/api/add/assets/', project='alpha-corp', entries=['cand.com'], tier='owned_root')
        self.assertTrue(Domain.objects.filter(name='cand.com', project=self.a).exists())

    def test_add_as_owned_host_creates_no_target(self):
        self.post('/api/add/assets/', project='alpha-corp', entries=['host.com'], tier='owned_host')
        self.assertEqual(Domain.objects.count(), 0)

    def test_confirm_asset_creates_target_and_returns_warning(self):
        cand = Asset.objects.create(project=self.a, kind='root_domain', value='c.com', scope_tier='candidate')
        r = self.post('/api/action/asset/confirm/', project='alpha-corp', asset_id=cand.id, tier='owned_root')
        self.assertEqual((r['status'], r['message']), (True, 'confirmed'))
        self.assertTrue(Domain.objects.filter(name='c.com', project=self.a).exists())
        Domain.objects.create(name='d.com', project=self.b, insert_date=timezone.now())
        cand = Asset.objects.create(project=self.a, kind='root_domain', value='d.com', scope_tier='candidate')
        r = self.post('/api/action/asset/confirm/', project='alpha-corp', asset_id=cand.id, tier='owned_root')
        self.assertIn(OTHER_PROJECT_MSG.format(value='d.com'), r['message'])
        self.assertEqual(Domain.objects.filter(name='d.com').count(), 1)

    @override_settings(ATTRIBUTION_AUTO_CONFIRM=True)
    def test_apply_decisions_creates_target_only_when_it_wins(self):
        owned = self.root('example.com')
        inventory.record_fact(owned, 'cert', '102', 'crtsh')
        won = Asset.objects.create(project=self.a, kind='root_domain', value='ours.net', scope_tier='candidate')
        lost = Asset.objects.create(project=self.a, kind='root_domain', value='race.net', scope_tier='candidate')
        for a in (won, lost):
            inventory.record_fact(a, 'ns', 'ns1.example.com', 'dns')
            inventory.record_fact(a, 'cert', '102', 'crtsh')
            inventory.record_fact(a, 'delegation', 'ns1.example.com', 'parent')
        attribution.score_project(self.a)
        Asset.objects.filter(pk=lost.pk).update(scope_tier='rejected')  # a human decides first
        self.assertEqual(attribution.apply_decisions(self.a)['auto_confirmed'], 1)
        self.assertTrue(Domain.objects.filter(name='ours.net', project=self.a).exists())
        self.assertFalse(Domain.objects.filter(name='race.net').exists())


class FailureIsolationTest(WiredBase):
    def boom(self):
        return mock.patch.object(scan_target.Domain.objects, 'create', side_effect=RuntimeError('db detail'))

    def test_ensure_never_raises(self):
        with self.boom():
            d, msg = ensure_scan_target(self.root())
        self.assertIsNone(d)
        self.assertEqual(msg, scan_target.FAILED_MSG.format(value='x.com'))
        self.assertNotIn('db detail', msg)

    def test_add_assets_still_adds(self):
        with self.boom():
            r = self.post('/api/add/assets/', project='alpha-corp', entries=['new.com'], tier='owned_root')
        self.assertTrue(r['status'])
        self.assertEqual(r['message']['added'], 1)
        self.assertIn(scan_target.FAILED_MSG.format(value='new.com'), r['message']['warnings'])
        self.assertEqual(Asset.objects.get(value='new.com').scope_tier, 'owned_root')
        self.inv.assert_called_with(self.a.id)

    def test_confirm_still_confirms(self):
        cand = Asset.objects.create(project=self.a, kind='root_domain', value='c.com', scope_tier='candidate')
        with self.boom():
            r = self.post('/api/action/asset/confirm/', project='alpha-corp', asset_id=cand.id, tier='owned_root')
        self.assertTrue(r['status'])
        self.assertIn('could not create a scan target', r['message'])
        cand.refresh_from_db()
        self.assertEqual(cand.scope_tier, 'owned_root')
        self.inv.assert_called_with(self.a.id)

    @override_settings(ATTRIBUTION_AUTO_CONFIRM=True)
    def test_apply_decisions_loop_continues(self):
        inventory.record_fact(self.root('example.com'), 'cert', '102', 'crtsh')
        cands = [Asset.objects.create(project=self.a, kind='root_domain', value=v, scope_tier='candidate')
                 for v in ('one.net', 'two.net')]
        for a in cands:
            inventory.record_fact(a, 'ns', 'ns1.example.com', 'dns')
            inventory.record_fact(a, 'cert', '102', 'crtsh')
            inventory.record_fact(a, 'delegation', 'ns1.example.com', 'parent')
        attribution.score_project(self.a)
        with self.boom(), mock.patch('limes.alerts.events.safe_record') as rec:
            self.assertEqual(attribution.apply_decisions(self.a)['auto_confirmed'], 2)
        self.assertEqual(rec.call_count, 2)
        self.inv.assert_called_with(self.a.id)
        self.assertEqual(Asset.objects.filter(value__in=('one.net', 'two.net'), scope_tier='owned_root').count(), 2)


class RetiredAndReaddTest(WiredBase):
    def test_retired_owned_root_gets_no_domain(self):
        self.assertEqual(ensure_scan_target(self.root(state='retired')), (None, None))
        self.assertEqual(Domain.objects.count(), 0)

    def test_readding_an_existing_root_links_it_after_a_clash_clears(self):
        Domain.objects.create(name='x.com', project=self.b, insert_date=timezone.now())
        self.post('/api/add/assets/', project='alpha-corp', entries=['x.com'], tier='owned_root')
        Domain.objects.all().delete()  # the other project's target is removed
        msg = self.post('/api/add/assets/', project='alpha-corp', entries=['x.com'], tier='owned_root')['message']
        self.assertEqual((msg['added'], msg['existing']), (0, 1))
        self.assertTrue(Domain.objects.filter(name='x.com', project=self.a).exists())


class MigrationTest(Base):
    def test_link_migration_function(self):
        mod = importlib.import_module('startScan.migrations.0025_link_owned_roots')
        self.root('plain.com')
        self.root('linked.com')
        Domain.objects.create(name='linked.com', project=self.a, insert_date=timezone.now())
        self.root('elsewhere.com')
        Domain.objects.create(name='elsewhere.com', project=self.b, insert_date=timezone.now())
        self.root('cand.com', scope_tier='candidate')
        self.root('old.com', state='retired')
        mod.link_owned_roots(apps, None)
        mod.link_owned_roots(apps, None)  # safe to run twice
        self.assertEqual(Domain.objects.get(name='plain.com').project_id, self.a.id)
        self.assertEqual(Domain.objects.filter(name='linked.com').count(), 1)
        self.assertEqual(Domain.objects.get(name='elsewhere.com').project_id, self.b.id)
        self.assertFalse(Domain.objects.filter(name='cand.com').exists())
        self.assertFalse(Domain.objects.filter(name='old.com').exists())


class ReclassifyTest(Base):
    def run_cmd(self):
        out = StringIO()
        call_command('reclassify_roots', stdout=out)
        return out.getvalue()

    def test_reclassify_roots(self):
        user = User.objects.create_user('u', password='p')
        mk = lambda v, **kw: Asset.objects.create(project=self.a, kind='hostname', value=v,
                                                  **{'scope_tier': 'owned_host', **kw})
        co = mk('example.co.uk', added_by=user)
        www = mk('www.example.com', added_by=user)
        found = mk('found.co.uk', parent=self.root('parent.com'))   # discovered, not user-added
        dup = mk('dup.com', added_by=user)
        self.root('dup.com')
        owned = self.root('owned.org')
        out = self.run_cmd()
        for a in (co, www, found, dup):
            a.refresh_from_db()
        self.assertEqual((co.kind, www.kind, found.kind, dup.kind), ('root_domain', 'hostname', 'hostname', 'hostname'))
        self.assertIn('dup.com', out)
        self.assertIn('reclassified=1 linked=', out)
        self.assertTrue(Domain.objects.filter(name='owned.org', project=self.a).exists())
        self.assertIn('created scan target for owned.org', out)
        # second run changes nothing
        before = (Domain.objects.count(), list(Asset.objects.order_by('id').values_list('kind', flat=True)))
        self.assertIn('reclassified=0 linked=0', self.run_cmd())
        self.assertEqual(before, (Domain.objects.count(), list(Asset.objects.order_by('id').values_list('kind', flat=True))))
