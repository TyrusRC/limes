"""Fixture for the access tests (not a test module): two projects, users with explicit memberships only."""
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in
from django.test import Client, TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role

import tests.core
from dashboard.models import Project
from dashboard.views import on_user_logged_in
from memberships.models import ProjectMember


class AccessBase(TestCase):
    def setUp(self):
        tests.core.ENABLED = False  # legacy fixtures hand out admin everywhere; these tests must not
        self.addCleanup(setattr, tests.core, 'ENABLED', True)
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.p1 = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.p2 = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.assertEqual(ProjectMember.objects.count(), 0)

    def user(self, name, role=None, global_role=None, **kw):
        """A user with a role in p1 (None: no membership at all) and optionally a global rolepermissions role."""
        u = get_user_model().objects.create_user(name, password='p', email=f'{name}@example.test', **kw)
        if global_role:
            assign_role(u, global_role)
        if role:
            ProjectMember.objects.create(user=u, project=self.p1, role=role)
        return u

    def client_for(self, user):
        c = Client()
        c.force_login(user)
        return c
