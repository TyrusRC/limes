"""Who may do what in a project. The one place the answer is computed; the middleware and the MCP server both ask here.

Global access: an active superuser or sys_admin is an admin of every project. Everyone else needs a ProjectMember row.
A user with no row, an inactive user and an anonymous visitor all get None, which callers turn into "not found"."""
from rolepermissions.checkers import has_role

from memberships.models import ADMIN, RANK, ProjectMember


def is_global_admin(user):
    return bool(user and user.is_active and (user.is_superuser or has_role(user, 'sys_admin')))


def role_for(user, project_id):
    if not user or not user.is_authenticated or not user.is_active:
        return None
    if is_global_admin(user):
        return ADMIN
    return ProjectMember.objects.filter(user=user, project_id=project_id).values_list('role', flat=True).first()


def roles_by_slug(user, slugs):
    """{slug: role} for the slugs that exist and that the user may see; the others are absent."""
    from dashboard.models import Project
    if not user or not user.is_authenticated or not user.is_active:
        return {}
    projects = Project.objects.filter(slug__in=slugs)
    if is_global_admin(user):
        return {p.slug: ADMIN for p in projects}
    mine = dict(ProjectMember.objects.filter(user=user, project__in=projects).values_list('project__slug', 'role'))
    return {s: r for s, r in mine.items()}


def projects_for(user):
    from dashboard.models import Project
    if not user or not user.is_authenticated or not user.is_active:
        return Project.objects.none()
    if is_global_admin(user):
        return Project.objects.all()
    return Project.objects.filter(members__user=user)


def is_any_admin(user):
    if not user or not user.is_authenticated or not user.is_active:
        return False
    return is_global_admin(user) or ProjectMember.objects.filter(user=user, role=ADMIN).exists()


def at_least(role, needed):
    return role is not None and RANK[role] >= RANK[needed]
