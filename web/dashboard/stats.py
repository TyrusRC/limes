from datetime import timedelta

from django.core.cache import cache
from django.db.models import Count, Q
from django.db.models.functions import TruncDay
from django.utils import timezone

from startScan.models import (CountryISO, CveId, CweId, EndPoint, IpAddress, Port, ScanActivity, ScanHistory,
                              Subdomain, Technology, Vulnerability, VulnerabilityTags)
from targetApp.models import Domain

STATS_TTL = 60
SEVERITIES = {'unknown_count': -1, 'info_count': 0, 'low_count': 1, 'medium_count': 2, 'high_count': 3, 'critical_count': 4}


def _key(project_id):
    return f'dashboard:stats:{project_id}'


def invalidate(project_id):
    cache.delete(_key(project_id))


def _last_week(qs, field, dates):
    rows = (qs.filter(**{f'{field}__gte': timezone.now() - timedelta(days=7)})
            .annotate(day=TruncDay(field)).values('day').annotate(n=Count('id')).order_by())
    by_day = {row['day'].date(): row['n'] for row in rows}
    return [by_day.get(d, 0) for d in reversed(dates)]


def _compute(project):
    domains = Domain.objects.filter(project=project)
    scans = ScanHistory.objects.filter(domain__project=project)
    subdomains = Subdomain.objects.filter(scan_history__domain__project=project)
    endpoints = EndPoint.objects.filter(scan_history__domain__project=project)
    vulns = Vulnerability.objects.filter(scan_history__domain__project=project)
    ips = IpAddress.objects.filter(ip_addresses__in=subdomains)

    sub = subdomains.aggregate(total=Count('id'), alive=Count('id', filter=~Q(http_status=0)))
    ep = endpoints.aggregate(total=Count('id'), alive=Count('id', filter=Q(http_status=200)))
    sev = vulns.aggregate(**{k: Count('id', filter=Q(severity=v)) for k, v in SEVERITIES.items()})
    dates = [(timezone.now() - timedelta(days=i)).date() for i in range(7)]

    stats = {
        'domain_count': domains.count(),
        'scan_count': scans.count(),
        'subdomain_count': sub['total'] or 0,
        'alive_count': sub['alive'] or 0,
        'subdomain_with_ip_count': subdomains.filter(ip_addresses__isnull=False).distinct().count(),
        'endpoint_count': ep['total'] or 0,
        'endpoint_alive_count': ep['alive'] or 0,
        **{k: v or 0 for k, v in sev.items()},
        'targets_in_last_week': _last_week(domains, 'insert_date', dates),
        'subdomains_in_last_week': _last_week(subdomains, 'discovered_date', dates),
        'vulns_in_last_week': _last_week(vulns, 'discovered_date', dates),
        'scans_in_last_week': _last_week(scans, 'start_scan_date', dates),
        'endpoints_in_last_week': _last_week(endpoints, 'discovered_date', dates),
        'last_7_dates': dates,
        'vulnerability_feed': list(vulns.order_by('-discovered_date')[:50]),
        'activity_feed': list(ScanActivity.objects.filter(scan_of__in=scans).order_by('-time')[:50]),
        'total_ips': ips.count(),
        'most_used_port': list(Port.objects.filter(ports__in=ips).annotate(count=Count('ports')).order_by('-count')[:7]),
        'most_used_ip': list(ips.annotate(count=Count('ip_addresses')).order_by('-count').exclude(ip_addresses__isnull=True)[:7]),
        'most_used_tech': list(Technology.objects.filter(technologies__in=subdomains).annotate(count=Count('technologies')).order_by('-count')[:7]),
        'most_common_cve': list(CveId.objects.filter(cve_ids__in=vulns).annotate(nused=Count('cve_ids')).order_by('-nused').values('name', 'nused')[:7]),
        'most_common_cwe': list(CweId.objects.filter(cwe_ids__in=vulns).annotate(nused=Count('cwe_ids')).order_by('-nused').values('name', 'nused')[:7]),
        'most_common_tags': list(VulnerabilityTags.objects.filter(vuln_tags__in=vulns).annotate(nused=Count('vuln_tags')).order_by('-nused').values('name', 'nused')[:7]),
        'asset_countries': list(CountryISO.objects.filter(ipaddress__in=ips).annotate(count=Count('ipaddress')).order_by('-count')),
    }
    stats['total_vul_count'] = sum(stats[k] for k in SEVERITIES)
    stats['total_vul_ignore_info_count'] = stats['total_vul_count'] - stats['info_count'] - stats['unknown_count']
    return stats


def project_stats(project):
    stats = cache.get(_key(project.id))
    if stats is None:
        stats = _compute(project)
        cache.set(_key(project.id), stats, STATS_TTL)
    return stats
