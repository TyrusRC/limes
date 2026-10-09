"""Back-fill the Asset inventory from the legacy scan-centric tables.
Functions take an `apps` registry (live or migration-historical) and are idempotent + chunked."""
from django.utils import timezone

CHUNK = 2000


def normalize_host(value):
    return (value or '').strip().rstrip('.').lower()


def _models(apps):
    return {
        'Asset': apps.get_model('startScan', 'Asset'),
        'Subdomain': apps.get_model('startScan', 'Subdomain'),
        'IpAddress': apps.get_model('startScan', 'IpAddress'),
        'Domain': apps.get_model('targetApp', 'Domain'),
    }


def backfill_root_domains(apps):
    m = _models(apps)
    Asset, Domain = m['Asset'], m['Domain']
    created = 0
    for d in Domain.objects.all().iterator(chunk_size=CHUNK):
        value = normalize_host(d.name)
        if not value or d.project_id is None:
            continue
        _, was_created = Asset.objects.get_or_create(
            project_id=d.project_id, kind='root_domain', value=value,
            defaults={'scope_tier': 'owned_root', 'state': 'active',
                      'first_seen': d.insert_date or timezone.now(),
                      'last_seen': d.insert_date or timezone.now(),
                      'request_headers': getattr(d, 'request_headers', None)})
        created += int(was_created)
        cidr = getattr(d, 'ip_address_cidr', None)
        if cidr:
            Asset.objects.get_or_create(project_id=d.project_id, kind='cidr', value=cidr.strip(),
                                        defaults={'scope_tier': 'owned_root', 'state': 'active'})
    return created


def backfill_ip_assets(apps):
    m = _models(apps)
    Asset, IpAddress, Domain = m['Asset'], m['IpAddress'], m['Domain']
    # NOTE: orphan IPs (no linked subdomain) fall back to the first project that has a domain;
    # an IP linked to subdomains in several projects takes the first linked subdomain's project.
    # Ceiling: one query per IP; upgrade path is a single join over the M2M through table.
    first_domain = Domain.objects.exclude(project_id=None).order_by('id').first()
    default_pid = first_domain.project_id if first_domain else None
    seen, created = set(), 0
    for ip in IpAddress.objects.all().iterator(chunk_size=CHUNK):
        value = (ip.address or '').strip()
        if not value:
            continue
        # reverse accessor of Subdomain.ip_addresses (related_name='ip_addresses')
        pid = (ip.ip_addresses.exclude(target_domain__project_id=None)
               .order_by('id').values_list('target_domain__project_id', flat=True).first())
        pid = pid or default_pid
        if pid is None or (pid, value) in seen:
            continue
        seen.add((pid, value))
        _, was_created = Asset.objects.get_or_create(project_id=pid, kind='ip', value=value,
                                                     defaults={'scope_tier': 'owned_host', 'state': 'active'})
        created += int(was_created)
    return created


STATE_FIELDS = ['http_status', 'page_title', 'webserver', 'content_type', 'content_length',
                'response_time', 'cname', 'is_cdn', 'cdn_name', 'screenshot_path']


def backfill_hostname_assets(apps):
    m = _models(apps)
    Asset, Subdomain = m['Asset'], m['Subdomain']
    # NOTE: groups holds one small dict per unique hostname (bounded by unique host count).
    # Upgrade path if that gets too big: DB-side dedup (GROUP BY / DISTINCT ON) per project.
    groups = {}  # (project_id, value) -> {first, last, date, state, root}
    rows = Subdomain.objects.exclude(target_domain=None).exclude(target_domain__project=None).values(
        'name', 'discovered_date', 'target_domain__project_id', 'target_domain__name', *STATE_FIELDS)
    for r in rows.iterator(chunk_size=CHUNK):
        value = normalize_host(r['name'])
        if not value:
            continue
        key = (r['target_domain__project_id'], value)
        d = r['discovered_date']
        state = {f: r[f] for f in STATE_FIELDS}
        g = groups.get(key)
        if g is None:
            groups[key] = {'first': d, 'last': d, 'date': d, 'state': state,
                           'root': normalize_host(r['target_domain__name'])}
        elif d is not None:
            g['first'] = d if g['first'] is None else min(g['first'], d)
            g['last'] = d if g['last'] is None else max(g['last'], d)
            if g['date'] is None or d >= g['date']:
                g['date'], g['state'] = d, state
    created = 0
    root_ids = {}  # (project_id, root_name) -> Asset id or None
    for (project_id, value), g in groups.items():
        rk = (project_id, g['root'])
        if rk not in root_ids:
            root = Asset.objects.filter(project_id=project_id, kind='root_domain', value=g['root']).first()
            root_ids[rk] = root.id if root else None
        fallback = timezone.now()
        defaults = {'scope_tier': 'owned_host', 'state': 'active', 'parent_id': root_ids[rk],
                    'first_seen': g['first'] or fallback, 'last_seen': g['last'] or fallback,
                    **g['state']}
        _, was_created = Asset.objects.get_or_create(
            project_id=project_id, kind='hostname', value=value, defaults=defaults)
        created += int(was_created)
    return created


def backfill_vuln_assets(apps):
    Asset = apps.get_model('startScan', 'Asset')
    Vulnerability = apps.get_model('startScan', 'Vulnerability')
    Subdomain = apps.get_model('startScan', 'Subdomain')
    updated = 0
    for v in Vulnerability.objects.filter(asset__isnull=True).select_related(
            'subdomain', 'endpoint', 'target_domain').iterator(chunk_size=CHUNK):
        # NOTE: project is derived only from target_domain; a vuln with subdomain/endpoint but NULL target_domain is
        # intentionally skipped (left unlinked) rather than mis-attributed to a guessed project.
        project_id = v.target_domain.project_id if v.target_domain_id and v.target_domain.project_id else None
        value = kind = None
        if v.subdomain_id:
            value, kind = normalize_host(v.subdomain.name), 'hostname'
        elif v.endpoint_id and v.endpoint.subdomain_id:
            sub = Subdomain.objects.filter(id=v.endpoint.subdomain_id).first()
            if sub:
                value, kind = normalize_host(sub.name), 'hostname'
        if value is None and v.target_domain_id:
            value, kind = normalize_host(v.target_domain.name), 'root_domain'
        if value is None or project_id is None:
            continue
        asset = Asset.objects.filter(project_id=project_id, kind=kind, value=value).first()
        if asset:
            v.asset_id = asset.id
            v.save(update_fields=['asset'])
            updated += 1
    return updated


def run_all(apps):
    backfill_root_domains(apps)
    backfill_ip_assets(apps)
    backfill_hostname_assets(apps)
    backfill_vuln_assets(apps)


def reverse_all(apps):
    Asset = apps.get_model('startScan', 'Asset')
    Vulnerability = apps.get_model('startScan', 'Vulnerability')
    Vulnerability.objects.update(asset=None)
    # NOTE: unchunked delete — Django's collector loads all Asset rows + self-FK/M2M relations in memory (30s / 200k rows on the 0A seed, within budget). Upgrade path: chunked delete via .iterator()+pk batches if the inventory outgrows memory.
    Asset.objects.all().delete()
