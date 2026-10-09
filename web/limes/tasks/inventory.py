"""ASM inventory write layer. Live-ORM upserts of Asset/ScanRun/ScanJob.
NOT the migration back-fill (that is startScan/inventory_migrate.py, apps.get_model).
Keyed by (project, kind, value); value normalized via normalize_host so live and
migrated rows share identity."""
import ipaddress

from django.utils import timezone
from limes import scope
from startScan.models import Asset
from startScan.inventory_migrate import normalize_host

STATE_FIELDS = ('http_status', 'page_title', 'webserver', 'content_type',
                'content_length', 'response_time', 'cname', 'is_cdn',
                'cdn_name', 'screenshot_path')

STAGE_BY_TASK = {
    'subdomain_discovery': 'discovery', 'http_crawl': 'probe', 'screenshot': 'probe',
    'port_scan': 'ports', 'fetch_url': 'crawl',
    'vulnerability_scan': 'dast', 'code_audit': 'code',
}


def _append_source(asset, source, evidence, confidence=0.5):
    srcs = asset.sources or []
    if not any(s.get('source') == source and s.get('evidence') == evidence for s in srcs):
        srcs.append({'source': source, 'evidence': evidence,
                     'confidence': confidence, 'seen_at': timezone.now().isoformat()})
        asset.sources = srcs
    return asset


def upsert_root_asset(project, name, request_headers=None):
    value = normalize_host(name)
    if not value:
        return None
    asset, _ = Asset.objects.get_or_create(
        project=project, kind='root_domain', value=value,
        defaults={'scope_tier': 'owned_root'})
    if request_headers and not asset.request_headers:
        asset.request_headers = request_headers
        asset.save(update_fields=['request_headers'])
    asset.mark_missing_or_seen(True)
    return asset


def upsert_hostname_asset(project, name, parent=None, source='discovery',
                          evidence='', scope_tier='owned_host'):
    value = normalize_host(name)
    if not value:
        return None
    asset, _ = Asset.objects.get_or_create(
        project=project, kind='hostname', value=value,
        defaults={'scope_tier': scope_tier, 'parent': parent})
    if parent is not None and asset.parent_id is None:
        asset.parent = parent
    _append_source(asset, source, evidence)
    asset.save()
    asset.mark_missing_or_seen(True)   # never changes scope_tier -> no promotion
    return asset


def owned_ip_space(project):
    # NOTE: one owned-networks query per new IP (see _new_ip_tier). Upgrade: cache per resolution run.
    """Networks a person (or an owned root's import) declared ours: owned ip/cidr assets."""
    nets = []
    for value in Asset.objects.filter(project=project, kind__in=('ip', 'cidr'),
                                      scope_tier__in=('owned_root', 'owned_host')).values_list('value', flat=True):
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return nets


def _new_ip_tier(project, address):
    ip = scope.parse_ip(address)
    if ip is None or scope.is_reserved_ip(ip):
        return 'dependency'
    if any(ip.version == n.version and ip in n for n in owned_ip_space(project)):
        return 'owned_host'
    return 'dependency'


def upsert_ip_asset(project, address, source='probe', evidence=''):
    if not address:
        return None
    asset, created = Asset.objects.get_or_create(
        project=project, kind='ip', value=address,
        defaults={'scope_tier': 'dependency'})
    if created:
        # DNS/probe evidence never promotes: owned only inside declared owned space.
        asset.scope_tier = _new_ip_tier(project, address)
    _append_source(asset, source, evidence)
    asset.save()
    asset.mark_missing_or_seen(True)
    return asset


def update_host_state(asset, **fields):
    changed = []
    for k in STATE_FIELDS:
        if k in fields and fields[k] is not None:
            setattr(asset, k, fields[k]); changed.append(k)
    if changed:
        asset.save(update_fields=changed)


def mirror_subdomain_state(subdomain, project):
    """Mirror a Subdomain's current probe/screenshot state + technologies onto its hostname Asset."""
    if not project:
        return None
    asset = upsert_hostname_asset(project, subdomain.name, source='probe',
                                  evidence='httpx')
    if not asset:
        return None
    update_host_state(asset, http_status=subdomain.http_status, page_title=subdomain.page_title,
                      webserver=subdomain.webserver, content_type=subdomain.content_type,
                      content_length=subdomain.content_length, response_time=subdomain.response_time,
                      cname=subdomain.cname, is_cdn=subdomain.is_cdn, cdn_name=subdomain.cdn_name,
                      screenshot_path=subdomain.screenshot_path)
    for tech in subdomain.technologies.all():
        asset.technologies.add(tech)
    return asset


def finalize_lifecycle(run):
    # NOTE: scans active hostname Assets under one root (.iterator, bounded per root);
    # upgrade path if a root grows very large: a single conditional bulk update.
    n = 0
    qs = Asset.objects.filter(project=run.project, kind='hostname', parent=run.root_asset,
                              state='active', last_seen__lt=run.start_scan_date,
                              scope_tier__in=('owned_root', 'owned_host'))
    for asset in qs.iterator(chunk_size=2000):
        asset.mark_missing_or_seen(False); n += 1
    return n


def record_resolution(asset, record):
    """Write one host's dnsx answer: CNAME, IP assets (via upsert_ip_asset), host->IP links.
    The answer REPLACES the host's links, so a stale (e.g. private) IP cannot veto it forever."""
    from startScan.models import IpAddress
    if record.get('cname'):
        asset.cname = record['cname'][0]
    rows = []
    # NOTE: per-IP queries and IpAddress.address is unindexed. Upgrade: fetch rows once per
    # resolution run with address__in.
    for address in list(record.get('a', [])) + list(record.get('aaaa', [])):
        upsert_ip_asset(asset.project, address, source='dns', evidence=f'host:{asset.value}')
        # address is not unique on the legacy table: reuse the oldest row
        ip = IpAddress.objects.filter(address=address).order_by('id').first() or IpAddress.objects.create(address=address)
        if ip not in rows:
            rows.append(ip)
    asset.ip_addresses.set(rows)
    asset.last_resolved_at = timezone.now()
    asset.save(update_fields=['cname', 'last_resolved_at'])


def owned_root_values(project):
    return set(Asset.objects.filter(project=project, kind='root_domain', scope_tier='owned_root')
               .values_list('value', flat=True))


def upsert_candidate(project, kind, value, source, evidence):
    """New assets start as candidates; an existing asset keeps its tier (rejected is never re-suggested)."""
    value = normalize_host(value)
    if not value:
        return None
    asset, _ = Asset.objects.get_or_create(project=project, kind=kind, value=value,
                                           defaults={'scope_tier': 'candidate'})
    _append_source(asset, source, evidence)
    asset.save(update_fields=['sources'])
    return asset
