"""Regression tests for the second S1 review. Each asserts the CORRECT behaviour and failed before the fix."""
import json
import os
import tempfile

from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rolepermissions.checkers import has_role

from dashboard.models import InAppNotification, Project
from memberships.models import ProjectMember
from remediation.models import RemediationRequest
from reporting.models import ReportRun, ReportSchedule
from scanEngine.models import EngineType, Notification, Proxy
from startScan.alert_models import AlertRule
from startScan.models import Asset, IssueNote, IssueWaiver, ScanHistory, TrackedIssue
from targetApp.models import Domain
from tests.core.access_base import AccessBase
from tests.core.test_access_matrix import all_routes

User = get_user_model()
ENGINE_FORM = {'engine_name': 'x', 'yaml_configuration': 'pwned: true', 'profile': 'normal'}


class Fixture(AccessBase):
    def setUp(self):
        super().setUp()
        self.eng = EngineType.objects.create(engine_name='shared', yaml_configuration='a: 1', default_engine=True)
        self.dom = Domain.objects.create(project=self.p2, name='victim.example', insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(domain=self.dom, scan_type=self.eng, scan_status=2,
                                               start_scan_date=timezone.now())
        self.std = self.client_for(self.user('std', role='standard', global_role='penetration_tester'))


class EngineTest(Fixture):
    """Scan engines are instance-wide: a project member must not add, rewrite or delete them."""

    def test_member_cannot_touch_engines(self):
        for name, kw, form in (('add_engine', {}, ENGINE_FORM), ('update_engine', {'id': self.eng.id}, ENGINE_FORM),
                               ('delete_engine_url', {'id': self.eng.id}, {})):
            r = self.std.post(reverse(name, kwargs={'slug': 'p1', **kw}), form)
            self.assertEqual(r.status_code, 403, name)
        self.eng.refresh_from_db()
        self.assertEqual(self.eng.yaml_configuration, 'a: 1')
        self.assertEqual(EngineType.objects.count(), 1)
        self.assertEqual(ScanHistory.objects.count(), 1)

    def test_global_admin_can_manage_engines(self):
        admin = self.client_for(self.user('root', global_role='sys_admin'))
        r = admin.post(reverse('add_engine', kwargs={'slug': 'p1'}), ENGINE_FORM)
        self.assertEqual(r.status_code, 302)
        self.assertTrue(EngineType.objects.filter(engine_name='x').exists())

    def test_deleting_an_engine_never_erases_scan_history(self):
        with self.assertRaises(Exception) as cm:
            with transaction.atomic():
                self.eng.delete()
        self.assertEqual(type(cm.exception).__name__, 'ProtectedError')
        self.assertEqual(ScanHistory.objects.count(), 1)

    def test_admin_delete_of_an_engine_in_use_is_refused_cleanly(self):
        admin = self.client_for(self.user('root', global_role='sys_admin'))
        r = admin.post(reverse('delete_engine_url', kwargs={'slug': 'p1', 'id': self.eng.id}))
        self.assertLess(r.status_code, 500)
        self.assertTrue(EngineType.objects.filter(pk=self.eng.pk).exists())
        self.assertEqual(ScanHistory.objects.count(), 1)


class ScanFilesTest(Fixture):
    """/media/<target>_<scan id>/ belongs to the scan's project."""

    def get(self, client, scan_id):
        tmp = tempfile.mkdtemp()
        d = os.path.join(tmp, f'victim.example_{scan_id}')
        os.makedirs(d)
        with open(os.path.join(d, 'subdomains_subfinder.txt'), 'w') as f:
            f.write('secret.victim.example\n')
        with override_settings(MEDIA_ROOT=tmp):
            return client.get(f'/media/victim.example_{scan_id}/subdomains_subfinder.txt')

    def test_non_member_gets_404(self):
        c = self.client_for(self.user('nobody', global_role='auditor'))
        self.assertEqual(self.get(c, self.scan.id).status_code, 404)

    def test_member_of_another_project_gets_404(self):
        self.assertEqual(self.get(self.std, self.scan.id).status_code, 404)

    def test_member_of_the_scans_project_gets_the_file(self):
        c = self.client_for(self.user('p2ro', global_role='auditor'))
        ProjectMember.objects.create(user=User.objects.get(username='p2ro'), project=self.p2, role='read_only')
        r = self.get(c, self.scan.id)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r['X-Accel-Redirect'].startswith('/protected_media/victim.example_'))

    def test_unknown_scan_or_odd_folder_names_are_404(self):
        admin = self.client_for(self.user('root', global_role='sys_admin'))
        for folder in (f'victim.example_{self.scan.id + 99}', 'noscan', 'victim.example_x', f'other_{self.scan.id}',
                       f'victim.example_0{self.scan.id}', f'victim.example_{self.scan.id}_'):
            tmp = tempfile.mkdtemp()
            os.makedirs(os.path.join(tmp, folder))
            with open(os.path.join(tmp, folder, 'f.txt'), 'w') as f:
                f.write('x')
            with override_settings(MEDIA_ROOT=tmp):
                self.assertEqual(admin.get(f'/media/{folder}/f.txt').status_code, 404, folder)


class OnboardingTest(AccessBase):
    """First-run setup belongs to a global admin, never to an arbitrary signed-in or SSO-created user."""
    BODY = {'project_name': 'first', 'create_username': 'backdoor', 'create_password': 'Backdoor-pass-123',
            'create_user_role': 'sys_admin'}

    def setUp(self):
        super().setUp()
        Project.objects.all().delete()

    def test_ordinary_user_creates_nothing(self):
        c = self.client_for(self.user('sso-newbie', global_role='auditor'))
        r = c.post(reverse('onboarding'), self.BODY)
        self.assertEqual(Project.objects.count(), 0)
        self.assertFalse(User.objects.filter(username='backdoor').exists())
        self.assertEqual(ProjectMember.objects.count(), 0)
        self.assertIn(r.status_code, (403, 404))

    def test_global_admin_creates_the_project_but_not_a_sys_admin(self):
        c = self.client_for(self.user('root', global_role='sys_admin'))
        c.post(reverse('onboarding'), self.BODY)
        self.assertEqual(Project.objects.filter(slug='first').count(), 1)
        u = User.objects.filter(username='backdoor').first()
        self.assertFalse(u is not None and has_role(u, 'sys_admin'))

    def test_global_admin_can_create_a_non_admin_user(self):
        c = self.client_for(self.user('root', global_role='sys_admin'))
        c.post(reverse('onboarding'), {**self.BODY, 'create_user_role': 'auditor'})
        u = User.objects.get(username='backdoor')
        self.assertTrue(has_role(u, 'auditor'))


class MembersApiTest(AccessBase):
    def test_lists_only_members_of_the_project_who_can_be_named(self):
        ProjectMember.objects.create(user=self.user('p2only', global_role='penetration_tester'), project=self.p2, role='admin')
        self.user('stranger', global_role='penetration_tester')
        self.user('mate', role='standard', global_role='penetration_tester')
        self.user('viewer', role='read_only', global_role='penetration_tester')
        c = self.client_for(self.user('ro', role='read_only', global_role='penetration_tester'))
        r = c.get(reverse('api:members') + '?project=p1')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), ['mate'])

    def test_is_member_needs_membership_of_that_project(self):
        from limes import waivers
        std = self.user('s', role='standard', global_role='penetration_tester')
        ro = self.user('r', role='read_only', global_role='penetration_tester')
        out = self.user('o', global_role='penetration_tester')
        self.assertTrue(waivers.is_member(std, self.p1.id))
        self.assertFalse(waivers.is_member(std, self.p2.id))
        self.assertFalse(waivers.is_member(ro, self.p1.id))
        self.assertFalse(waivers.is_member(out, self.p1.id))
        self.assertFalse(waivers.is_member(None, self.p1.id))


class PortfolioSelectTest(AccessBase):
    def test_read_only_member_can_pick_a_portfolio_for_their_own_view(self):
        from startScan.models import Portfolio
        pf = Portfolio.objects.create(project=self.p1, name='all', tags=['x'])
        c = self.client_for(self.user('ro', role='read_only', global_role='penetration_tester'))
        r = c.post(reverse('api:select_portfolio') + '?project=p1', json.dumps({'project': 'p1', 'portfolio': pf.id}),
                   content_type='application/json')
        self.assertEqual(r.status_code, 200, r.content)


# ---- resolver-driven: no write route reachable by a project member touches anything instance-wide or another project

IGNORE = {'django_session', 'memberships_accessaudit', 'dashboard_feeddismissal', 'memberships_notificationread'}
# What a member of p1 may legitimately write without naming a p2 object (their own project, or their own account).
OWN = {'report_generate', 'api:alert_integration', 'api:subsidiaries'}


def writes():
    with connection.cursor() as c:
        c.execute('select relname, n_tup_ins, n_tup_upd, n_tup_del from pg_stat_xact_user_tables')
        return {r[0]: r[1:] for r in c.fetchall()}


class WriteSweepTest(AccessBase):
    def setUp(self):
        super().setUp()
        self.owner = self.user('owner')
        ProjectMember.objects.create(user=self.owner, project=self.p2, role='admin')
        self.eng = EngineType.objects.create(engine_name='shared', yaml_configuration='{}', default_engine=True)
        dom = Domain.objects.create(project=self.p2, name='y.com', insert_date=timezone.now())
        scan = ScanHistory.objects.create(domain=dom, scan_type=self.eng, scan_status=1, start_scan_date=timezone.now())
        asset = Asset.objects.create(project=self.p2, kind='root_domain', value='y.com', scope_tier='owned_root')
        issue = TrackedIssue.objects.create(project=self.p2, asset=asset, key='k', source='check', severity=2)
        waiver = IssueWaiver.objects.create(issue=issue, kind='false_positive', reason='r', created_by=self.owner)
        IssueNote.objects.create(issue=issue, text='n')
        rr = RemediationRequest.objects.create(project=self.p2, title='t')
        rs = ReportSchedule.objects.create(project=self.p2, name='s', frequency='weekly', delivery='platform')
        rule = AlertRule.objects.create(project=self.p2, name='r', kinds=['issue_new'], channels=['in_app'])
        notif = InAppNotification.objects.create(project=self.p2, title='a', description='d', icon='x')
        glob = [Notification.objects.create().id, Proxy.objects.create().id]
        self.ids = sorted({self.eng.id, dom.id, scan.id, asset.id, issue.id, waiver.id, rr.id, rs.id, rule.id, notif.id,
                           self.owner.id, *glob})

    def one(self, client, method, url, body, api):
        client.raise_request_exception = False
        with transaction.atomic():
            before = writes()
            if method == 'GET':
                client.get(url, {k: v for k, v in body.items() if isinstance(v, str)})
            elif api:
                getattr(client, method.lower())(url + '?project=p1', json.dumps(body), content_type='application/json')
            elif method == 'POST':
                client.post(url, {k: (v if not isinstance(v, list) else v[0]) for k, v in body.items()})
            else:
                getattr(client, method.lower())(url, json.dumps(body), content_type='application/json')
            after = writes()
            transaction.set_rollback(True)
        return sorted(t for t in after if t not in IGNORE and after[t] != before.get(t, (0, 0, 0)))

    def sweep(self, client, methods):
        hits = []
        for name, url, kw in all_routes():
            if name in ('logout', 'login', 'sso_login', 'sso_callback') or name in OWN:
                continue
            for v in (self.ids if any(x == 1 for x in kw.values()) else [None]):
                k2 = {k: ('p1' if k == 'slug' else v) for k in kw}
                u = reverse(name, kwargs=k2) if k2 else reverse(name)
                i = v if v is not None else self.ids[0]
                body = {'project': 'p1', 'id': str(i), 'asset_id': str(i), 'issue_id': str(i), 'waiver_id': str(i),
                        'scan_ids': [i], 'issues': [i], 'pk': str(i), 'approve': True, 'status': 'archived', 'text': 'x',
                        'name': 'zz', 'decision': 'ignore', 'kind': 'false_positive', 'reason': 'x', **ENGINE_FORM}
                for method in methods:
                    changed = self.one(client, method, u, body, u.startswith('/api/'))
                    if changed:
                        hits.append((method, name, u, changed))
        return hits

    def test_a_member_of_p1_writes_nothing_outside_p1(self):
        c = self.client_for(self.user('std', role='standard', global_role='penetration_tester'))
        self.assertEqual(self.sweep(c, ('POST', 'PUT', 'PATCH', 'DELETE')), [])

    def test_read_only_member_writes_nothing_at_all(self):
        c = self.client_for(self.user('ro', role='read_only', global_role='penetration_tester'))
        hits = [h for h in self.sweep(c, ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')) if h[1] != 'api:select_portfolio']
        self.assertEqual(hits, [])

    def test_non_member_writes_nothing_at_all(self):
        c = self.client_for(self.user('nobody', global_role='penetration_tester'))
        self.assertEqual(self.sweep(c, ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')), [])

    def test_the_sweep_is_not_vacuous(self):
        """A global admin does write through the same routes, so an empty result above means the policy held."""
        c = self.client_for(self.user('root', global_role='sys_admin'))
        self.assertTrue(self.sweep(c, ('POST', 'DELETE')))
