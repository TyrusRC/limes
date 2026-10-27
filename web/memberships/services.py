"""Membership changes, each with its audit entry. Views call these and never write ProjectMember directly."""
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q

from memberships.models import ADMIN, ROLES, AccessAudit, ProjectMember


class MemberError(Exception):
    """A refusal with a message that is safe to show to the admin who asked."""
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def audit(actor, project, action, subject='', detail=''):
    AccessAudit.objects.create(
        actor=actor if actor and actor.pk else None, actor_name=getattr(actor, 'username', '') or '',
        project=project, project_slug=project.slug if project else '', action=action,
        subject=subject[:150], detail=detail[:300])


def grant_creator(project, user):
    """The person who creates a project administers it. No-op without a real user (management commands)."""
    if user is not None and getattr(user, 'pk', None):
        ProjectMember.objects.get_or_create(user=user, project=project, defaults={'role': ADMIN})
        audit(user, project, 'project_created', user.username, 'creator became admin')


def _role(role):
    if role not in ROLES:
        raise MemberError('role must be one of: ' + ', '.join(ROLES))
    return role


def find_user(identifier):
    """An existing, active user by exact username or case-insensitive email; ambiguity is refused."""
    ident = (identifier or '').strip()
    if not ident or len(ident) > 254:
        raise MemberError('enter a username or email address')
    # candidates by the database, then an exact comparison in Python on ASCII only (the database folds some
    # non-ASCII letters, such as the dotless i, onto ASCII ones)
    cands = get_user_model().objects.filter(Q(username=ident) | Q(email__iexact=ident), is_active=True)[:20]
    users = [u for u in cands if u.username == ident or (u.email.isascii() and ident.isascii() and u.email.lower() == ident.lower())][:2]
    if len(users) != 1:
        raise MemberError('no single active user matches that username or email' if users else 'no active user with that username or email', 404)
    return users[0]


def _admins_locked(project):
    return list(ProjectMember.objects.select_for_update().filter(project=project, role=ADMIN).values_list('pk', flat=True))


@transaction.atomic
def add_member(actor, project, identifier, role):
    role = _role(role)
    user = find_user(identifier)
    member, created = ProjectMember.objects.get_or_create(user=user, project=project, defaults={'role': role})
    if not created:
        raise MemberError(f'{user.username} is already a member', 409)
    audit(actor, project, 'member_added', user.username, f'role {role}')
    return member


@transaction.atomic
def change_role(actor, project, member_id, role):
    role = _role(role)
    admins = _admins_locked(project)
    member = ProjectMember.objects.select_related('user').filter(project=project, pk=member_id).first()
    if member is None:
        raise MemberError('member not found', 404)
    if member.role == ADMIN and role != ADMIN and admins == [member.pk]:
        raise MemberError('a project needs at least one admin: promote someone else first', 409)
    old, member.role = member.role, role
    member.save(update_fields=['role'])
    audit(actor, project, 'role_changed', member.user.username, f'{old} -> {role}')
    return member


@transaction.atomic
def remove_member(actor, project, member_id):
    admins = _admins_locked(project)
    member = ProjectMember.objects.select_related('user').filter(project=project, pk=member_id).first()
    if member is None:
        raise MemberError('member not found', 404)
    if member.role == ADMIN and admins == [member.pk]:
        raise MemberError('a project needs at least one admin: promote someone else first', 409)
    member.delete()
    audit(actor, project, 'member_removed', member.user.username, f'was {member.role}')
