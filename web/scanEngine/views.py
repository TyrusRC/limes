import glob
import os
import re
import shutil

from django import http
from django.contrib import messages
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from rolepermissions.decorators import has_permission_decorator

from limes.common_func import *
from limes.tasks import (run_command, send_discord_message, send_slack_message,send_lark_message, send_telegram_message)
from scanEngine.forms import *
from scanEngine.models import *


def index(request, slug):
    engine_type = EngineType.objects.order_by('engine_name').all()
    context = {
        'engine_ul_show': 'show',
        'engine_li': 'active',
        'scan_engine_nav_active': 'active',
        'engine_type': engine_type,
    }
    return render(request, 'scanEngine/index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def add_engine(request, slug):
    form = AddEngineForm()
    if request.method == "POST":
        form = AddEngineForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Scan Engine Added successfully')
            return http.HttpResponseRedirect(reverse('scan_engine_index', kwargs={'slug': slug}))
    context = {
        'scan_engine_nav_active': 'active',
        'form': form
    }
    return render(request, 'scanEngine/add_engine.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_engine(request, slug, id):
    obj = get_object_or_404(EngineType, id=id)
    if request.method == "POST":
        obj.delete()
        responseData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Engine successfully deleted!')
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            'Oops! Engine could not be deleted!')
    return http.JsonResponse(responseData)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def update_engine(request, slug, id):
    engine = get_object_or_404(EngineType, id=id)
    form = UpdateEngineForm(
        initial={
            'yaml_configuration': engine.yaml_configuration,
            'engine_name': engine.engine_name
    })
    if request.method == "POST":
        form = UpdateEngineForm(request.POST, instance=engine)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Engine edited successfully')
            return http.HttpResponseRedirect(reverse('scan_engine_index', kwargs={'slug': slug}))
    context = {
        'scan_engine_nav_active': 'active',
        'form': form
    }
    return render(request, 'scanEngine/update_engine.html', context)


@has_permission_decorator(PERM_MODIFY_INTERESTING_LOOKUP, redirect_url=FOUR_OH_FOUR_URL)
def interesting_lookup(request, slug):
    lookup_keywords = None
    context = {}
    context['scan_engine_nav_active'] = 'active'
    context['interesting_lookup_li'] = 'active'
    context['engine_ul_show'] = 'show'
    form = InterestingLookupForm()
    if InterestingLookupModel.objects.filter(custom_type=True).exists():
        lookup_keywords = InterestingLookupModel.objects.filter(custom_type=True).order_by('-id')[0]
    else:
        form.initial_checkbox()
    if request.method == "POST":
        if lookup_keywords:
            form = InterestingLookupForm(request.POST, instance=lookup_keywords)
        else:
            form = InterestingLookupForm(request.POST or None)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Lookup Keywords updated successfully')
            return http.HttpResponseRedirect(reverse('interesting_lookup', kwargs={'slug': slug}))

    if lookup_keywords:
        form.set_value(lookup_keywords)
        context['interesting_lookup_found'] = True
    context['form'] = form
    context['default_lookup'] = InterestingLookupModel.objects.filter(id=1)
    return render(request, 'scanEngine/lookup.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def tool_specific_settings(request, slug):
    context = {}
    # check for incoming form requests
    if request.method == "POST":

        if 'nucleiFileUpload[]' in request.FILES:
            nuclei_files = request.FILES.getlist('nucleiFileUpload[]')
            upload_count = 0
            for nuclei_file in nuclei_files:
                original_filename = nuclei_file.name if isinstance(nuclei_file.name, str) else nuclei_file.name.decode('utf-8')
                original_filename = re.sub(r'[\\/*?:"<>|]',"", original_filename)
                file_extension = original_filename.split('.')[len(nuclei_file.name.split('.'))-1]
                if file_extension in ['yaml', 'yml']:
                    base_filename = os.path.splitext(original_filename)[0]
                    file_path = '/root/nuclei-templates/' + base_filename + '.yaml'
                    file = open(file_path, "w")
                    file.write(nuclei_file.read().decode("utf-8"))
                    file.close()
                    upload_count += 1
            if upload_count == 0:
                messages.add_message(request, messages.ERROR, 'Invalid Nuclei Pattern, upload only *.yaml extension')
            messages.add_message(request, messages.INFO, f'{upload_count} Nuclei Patterns successfully uploaded')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'nuclei_config_text_area' in request.POST:
            with open('/root/.config/nuclei/config.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('nuclei_config_text_area'))
            messages.add_message(request, messages.INFO, 'Nuclei config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'subfinder_config_text_area' in request.POST:
            with open('/root/.config/subfinder/config.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('subfinder_config_text_area'))
            messages.add_message(request, messages.INFO, 'Subfinder config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'naabu_config_text_area' in request.POST:
            with open('/root/.config/naabu/config.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('naabu_config_text_area'))
            messages.add_message(request, messages.INFO, 'Naabu config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'amass_config_text_area' in request.POST:
            with open('/root/.config/amass.ini', "w") as fhandle:
                fhandle.write(request.POST.get('amass_config_text_area'))
            messages.add_message(request, messages.INFO, 'Amass config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

    context['settings_nav_active'] = 'active'
    context['tool_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'
    nuclei_custom_pattern = [f for f in glob.glob("/root/nuclei-templates/*.yaml")]
    context['nuclei_templates'] = nuclei_custom_pattern
    return render(request, 'scanEngine/settings/tool.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def limes_settings(request, slug):
    context = {}

    total, used, _ = shutil.disk_usage("/")
    total = total // (2**30)
    used = used // (2**30)
    context['total'] = total
    context['used'] = used
    context['free'] = total-used
    context['consumed_percent'] = int(100 * float(used)/float(total))

    context['settings_nav_active'] = 'active'
    context['limes_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'

    return render(request, 'scanEngine/settings/limes.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def notification_settings(request, slug):
    context = {}
    form = NotificationForm()
    notification = None
    if Notification.objects.all().exists():
        notification = Notification.objects.all()[0]
        form.set_value(notification)
    else:
        form.set_initial()

    if request.method == "POST":
        if notification:
            form = NotificationForm(request.POST, instance=notification)
        else:
            form = NotificationForm(request.POST or None)

        if form.is_valid():
            form.save()
            send_slack_message('*Limes*\nCongratulations! your notification services are working.')
            send_lark_message('*Limes*\nCongratulations! your notification services are working.')
            send_telegram_message('*Limes*\nCongratulations! your notification services are working.')
            send_discord_message('**Limes**\nCongratulations! your notification services are working.')
            messages.add_message(
                request,
                messages.INFO,
                'Notification Settings updated successfully and test message was sent.')
            return http.HttpResponseRedirect(reverse('notification_settings', kwargs={'slug': slug}))

    context['settings_nav_active'] = 'active'
    context['notification_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'
    context['form'] = form

    return render(request, 'scanEngine/settings/notification.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def proxy_settings(request, slug):
    context = {}
    form = ProxyForm()
    context['form'] = form

    proxy = None
    if Proxy.objects.all().exists():
        proxy = Proxy.objects.all()[0]
        form.set_value(proxy)
    else:
        form.set_initial()

    if request.method == "POST":
        if proxy:
            form = ProxyForm(request.POST, instance=proxy)
        else:
            form = ProxyForm(request.POST or None)

        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Proxies updated.')
            return http.HttpResponseRedirect(reverse('proxy_settings', kwargs={'slug': slug}))
    context['settings_nav_active'] = 'active'
    context['proxy_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'

    return render(request, 'scanEngine/settings/proxy.html', context)
