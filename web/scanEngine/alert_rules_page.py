"""Settings page 'Alert rules': the shell only. The rules and integration settings are loaded over the REST API
(api.alert_rules) and drawn with textContent, so nothing a scan found is ever parsed as HTML."""
from django.shortcuts import render
from rolepermissions.decorators import has_permission_decorator

from limes.definitions import FOUR_OH_FOUR_URL, PERM_MODIFY_SCAN_CONFIGURATIONS


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def alert_rules_page(request, slug):
    return render(request, 'scanEngine/settings/alert_rules.html')
