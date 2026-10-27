"""The Members page and its REST endpoints. Who may call them (project admins) is decided by the middleware; the
rules about last admins and audit live in services."""
import json

from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods, require_POST

from dashboard.models import Project
from memberships import services
from memberships.models import ROLES, AccessAudit, ProjectMember
from memberships.services import MemberError


def _project(slug):
    return Project.objects.get(slug=slug)  # the middleware has already shown it exists and is visible


def _row(m):
    return {'id': m.pk, 'username': m.user.username, 'email': m.user.email, 'role': m.role}


def members(request, slug):
    project = _project(slug)
    rows = ProjectMember.objects.filter(project=project).select_related('user').order_by('user__username')
    return render(request, 'memberships/members.html', {
        'project': project, 'rows': rows, 'roles': ROLES,
        'audit': AccessAudit.objects.filter(project=project).order_by('-created_at', '-id')[:25]})


def _flash(request, fn, ok):
    try:
        fn()
        messages.success(request, ok)
    except MemberError as e:
        messages.error(request, str(e))


@require_POST
def member_add(request, slug):
    p = _project(slug)
    _flash(request, lambda: services.add_member(request.user, p, request.POST.get('user', ''), request.POST.get('role', '')),
           'Member added.')
    return redirect('project_members', slug=slug)


@require_POST
def member_role(request, slug, member_id):
    p = _project(slug)
    _flash(request, lambda: services.change_role(request.user, p, member_id, request.POST.get('role', '')), 'Role changed.')
    return redirect('project_members', slug=slug)


@require_POST
def member_remove(request, slug, member_id):
    p = _project(slug)
    _flash(request, lambda: services.remove_member(request.user, p, member_id), 'Member removed.')
    return redirect('project_members', slug=slug)


def _json(request):
    try:
        data = json.loads(request.body or b'{}')
    except ValueError:
        raise MemberError('body must be JSON')
    if not isinstance(data, dict):
        raise MemberError('body must be a JSON object')
    return data


def _text(data, key):
    v = data.get(key, '')
    if not isinstance(v, str):
        raise MemberError(f'{key} must be text')
    return v


def _reply(fn):
    try:
        return fn()
    except MemberError as e:
        return JsonResponse({'status': False, 'message': str(e)}, status=e.status)


@require_http_methods(['GET', 'POST'])
def members_api(request, slug):
    p = _project(slug)

    def go():
        if request.method == 'GET':
            rows = ProjectMember.objects.filter(project=p).select_related('user').order_by('user__username')
            return JsonResponse({'status': True, 'members': [_row(m) for m in rows]})
        data = _json(request)
        m = services.add_member(request.user, p, _text(data, 'user'), _text(data, 'role'))
        return JsonResponse({'status': True, 'member': _row(m)}, status=201)
    return _reply(go)


@require_http_methods(['PATCH', 'DELETE'])
def member_api(request, slug, member_id):
    p = _project(slug)

    def go():
        if request.method == 'DELETE':
            services.remove_member(request.user, p, member_id)
            return JsonResponse({'status': True})
        m = services.change_role(request.user, p, member_id, _text(_json(request), 'role'))
        return JsonResponse({'status': True, 'member': _row(m)})
    return _reply(go)
