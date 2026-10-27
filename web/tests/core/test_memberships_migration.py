from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

BEFORE = [('memberships', '0001_initial')]
AFTER = [('memberships', '0002_backfill_admin_memberships')]


class BackfillMigrationTest(TransactionTestCase):
    def migrate(self, targets):
        ex = MigrationExecutor(connection)
        ex.migrate(targets)
        return MigrationExecutor(connection).loader.project_state(targets).apps

    def tearDown(self):
        ex = MigrationExecutor(connection)
        ex.migrate(ex.loader.graph.leaf_nodes())

    def test_every_existing_user_becomes_admin_of_every_existing_project(self):
        apps = self.migrate(BEFORE)
        User, Project = apps.get_model('auth', 'User'), apps.get_model('dashboard', 'Project')
        users = [User.objects.create(username=n, is_active=a) for n, a in (('a', True), ('b', True), ('off', False))]
        projects = [Project.objects.create(name=s, slug=s, insert_date='2026-01-01T00:00:00Z') for s in ('p1', 'p2')]
        apps = self.migrate(AFTER)
        Member = apps.get_model('memberships', 'ProjectMember')
        got = set(Member.objects.values_list('user_id', 'project_id', 'role'))
        self.assertEqual(got, {(u.pk, p.pk, 'admin') for u in users for p in projects})

    def test_rerun_is_harmless_and_empty_install_is_fine(self):
        apps = self.migrate(BEFORE)
        self.migrate(AFTER)
        self.assertEqual(apps.get_model('memberships', 'ProjectMember').objects.count(), 0)
