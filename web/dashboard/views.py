import json
import logging


from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.contrib import messages
from django.dispatch import receiver
from django.shortcuts import redirect, render, get_object_or_404
from django.utils import timezone
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from rolepermissions.roles import assign_role, clear_roles
from rolepermissions.decorators import has_permission_decorator
from django.template.defaultfilters import slugify


from dashboard import live
from dashboard.stats import project_stats
from startScan.models import *
from dashboard.models import *
from limes.definitions import *


logger = logging.getLogger(__name__)

def index(request, slug):
    try:
        project = Project.objects.get(slug=slug)
    except Exception as e:
        # if project not found redirect to 404
        return HttpResponseRedirect(reverse('four_oh_four'))

    context = dict(project_stats(project))
    context.update({'dashboard_data_active': 'active', 'project': project,
                    'realtime': live.realtime(project, timezone.now()), 'live_poll_seconds': settings.LIVE_POLL_SECONDS,
                    'live_since': live.newest_id(context.get('recent_changes', []), project)})
    return render(request, 'dashboard/index.html', context)


def profile(request, slug):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(
                request,
                'Your password was successfully changed!')
            return redirect('profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'dashboard/profile.html', {
        'form': form
    })


def api_tokens(request, slug):
    # Personal MCP tokens. The plaintext is rendered once in the create response and is stored nowhere.
    from limes.mcp import tokens
    if not settings.MCP_ENABLED or not Project.objects.filter(slug=slug).exists():
        return HttpResponseRedirect(reverse('four_oh_four'))
    error, new_token, form = None, None, {}
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'revoke':
            tok = get_object_or_404(ApiToken, token_id=request.POST.get('token_id', ''), user=request.user)
            tokens.revoke(tok)
            return redirect('api_tokens', slug=slug)
        if action == 'create':
            form = {'name': request.POST.get('name', ''), 'days': request.POST.get('days', ''),
                    'scope': request.POST.get('scope', '')}
            try:
                days = int(form['days'])
            except ValueError:
                days = None
            try:
                _, new_token = tokens.create_token(request.user, form['name'], days, form['scope'])
                form = {}
            except tokens.TokenError as e:
                error = str(e)
    now = timezone.now()
    rows = []
    for t in request.user.api_tokens.order_by('-created_at', '-id'):
        status = 'revoked' if t.revoked_at else 'expired' if t.expires_at <= now else 'active'
        rows.append({'t': t, 'status': status})
    response = render(request, 'dashboard/api_tokens.html', {
        'rows': rows, 'error': error, 'new_token': new_token, 'form': form,
        'expiry_days': tokens.EXPIRY_DAYS, 'default_days': tokens.DEFAULT_DAYS,
        'writes_enabled': settings.MCP_WRITES_ENABLED})
    response['Cache-Control'] = 'no-store'
    return response


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface(request, slug):
    UserModel = get_user_model()
    users = UserModel.objects.all().order_by('date_joined')
    return render(
        request,
        'dashboard/admin.html',
        {
            'users': users
        }
    )

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def admin_interface_update(request, slug):
    mode = request.GET.get('mode')
    user_id = request.GET.get('user')
    if user_id:
        UserModel = get_user_model()
        user = UserModel.objects.get(id=user_id)
    if request.method == 'GET':
        if mode == 'change_status':
            user.is_active = not user.is_active
            user.save()
    elif request.method == 'POST':
        if mode == 'delete':
            try:
                user.delete()
                messages.add_message(
                    request,
                    messages.INFO,
                    f'User {user.username} successfully deleted.'
                )
                messageData = {'status': True}
            except Exception as e:
                logger.error(e)
                messageData = {'status': False}
        elif mode == 'update':
            try:
                response = json.loads(request.body)
                role = response.get('role')
                change_password = response.get('change_password')
                clear_roles(user)
                assign_role(user, role)
                if change_password:
                    user.set_password(change_password)
                    user.save()
                messageData = {'status': True}
            except Exception as e:
                logger.error(e)
                messageData = {'status': False, 'error': str(e)}
        elif mode == 'create':
            try:
                response = json.loads(request.body)
                if not response.get('password'):
                    messageData = {'status': False, 'error': 'Empty passwords are not allowed'}
                    return JsonResponse(messageData)
                UserModel = get_user_model()
                user = UserModel.objects.create_user(
                    username=response.get('username'),
                    password=response.get('password')
                )
                assign_role(user, response.get('role'))
                messageData = {'status': True}
            except Exception as e:
                logger.error(e)
                messageData = {'status': False, 'error': str(e)}
        return JsonResponse(messageData)
    return HttpResponseRedirect(reverse('admin_interface', kwargs={'slug': slug}))


@receiver(user_logged_out)
def on_user_logged_out(sender, request, **kwargs):
    messages.add_message(
        request,
        messages.INFO,
        'You have been successfully logged out. Thank you ' +
        'for using Limes.')


@receiver(user_logged_in)
def on_user_logged_in(sender, request, **kwargs):
    messages.add_message(
        request,
        messages.INFO,
        'Hi @' +
        request.user.username +
        ' welcome back!')


def search(request, slug):
    return render(request, 'dashboard/search.html')


def four_oh_four(request):
    return render(request, '404.html')


def projects(request, slug):
    context = {}
    context['projects'] = Project.objects.all()
    return render(request, 'dashboard/projects.html', context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def delete_project(request, id):
    obj = get_object_or_404(Project, id=id)
    if request.method == "POST":
        obj.delete()
        responseData = {
            'status': 'true'
        }
        messages.add_message(
            request,
            messages.INFO,
            'Project successfully deleted!')
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            'Oops! Project could not be deleted!')
    return JsonResponse(responseData)


def onboarding(request):
    context = {}
    error = ''

    # check is any projects exists, then redirect to project list else onboarding
    project = Project.objects.first()

    if project:
        slug = project.slug
        return HttpResponseRedirect(reverse('dashboardIndex', kwargs={'slug': slug}))

    if request.method == "POST":
        project_name = request.POST.get('project_name')
        slug = slugify(project_name)
        create_username = request.POST.get('create_username')
        create_password = request.POST.get('create_password')
        create_user_role = request.POST.get('create_user_role')

        insert_date = timezone.now()

        try:
            Project.objects.create(
                name=project_name,
                slug=slug,
                insert_date=insert_date
            )
        except Exception as e:
            error = ' Could not create project, Error: ' + str(e)


        try:
            if create_username and create_password and create_user_role:
                UserModel = get_user_model()
                new_user = UserModel.objects.create_user(
                    username=create_username,
                    password=create_password
                )
                assign_role(new_user, create_user_role)
        except Exception as e:
            error = ' Could not create User, Error: ' + str(e)

    context['error'] = error
    return render(request, 'dashboard/onboarding.html', context)
