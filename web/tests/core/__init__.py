"""Legacy fixture compatibility: before per-project membership every user could open every project, and most tests
create their users and projects without caring who may see what. While this package is under test, a new user is an
admin of every existing project and a new project has every existing user as admin, exactly what the upgrade
migration does. Tests about access (tests/core/access_base.py) switch this off and set up memberships explicitly."""
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save

from dashboard.models import Project
from memberships.models import ProjectMember

ENABLED = True


def _users_get_projects(sender, instance, created, raw=False, **kw):
    if ENABLED and created and not raw:
        ProjectMember.objects.bulk_create(
            [ProjectMember(user=instance, project=p, role='admin') for p in Project.objects.all()], ignore_conflicts=True)


def _projects_get_users(sender, instance, created, raw=False, **kw):
    if ENABLED and created and not raw:
        ProjectMember.objects.bulk_create(
            [ProjectMember(user=u, project=instance, role='admin') for u in get_user_model().objects.all()],
            ignore_conflicts=True)


post_save.connect(_users_get_projects, sender=get_user_model(), dispatch_uid='legacy_users_get_projects')
post_save.connect(_projects_get_users, sender=Project, dispatch_uid='legacy_projects_get_users')
