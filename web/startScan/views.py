from django.shortcuts import render

from startScan.models import ScanHistory


def scan_history(request, slug):
    scans = (ScanHistory.objects.filter(domain__project__slug=slug).select_related('domain', 'scan_type', 'initiated_by')
             .order_by('-start_scan_date')[:500])  # NOTE: newest 500; upgrade path: server-side paging
    return render(request, 'startScan/history.html', {'scan_history_active': 'active', 'scan_history': scans})


def assets(request, slug):
    return render(request, 'startScan/assets.html', {'assets_active': 'active'})


def issues(request, slug):
    return render(request, 'startScan/issues.html', {'issues_active': 'active'})


def lookalikes(request, slug):
    return render(request, 'startScan/lookalikes.html', {'lookalikes_active': 'active'})
