import ipaddress

from django.db import migrations

AUTO_SOURCES = {'probe', 'dns'}


def demote_auto_owned_ips(apps, schema_editor):
    """IPs the old pipeline auto-owned (probe/dns evidence or A0 back-fill, no human decision)
    become dependencies unless they sit inside owned space a person declared."""
    # NOTE: per-row save and O(IPs x owned networks) membership scan; fine for a one-off migration.
    Asset = apps.get_model('startScan', 'Asset')
    owned = Asset.objects.filter(kind__in=('ip', 'cidr'), scope_tier__in=('owned_root', 'owned_host'))
    declared = {}
    for a in owned.exclude(kind='ip', added_by__isnull=True, decision_reason=''):
        try:
            declared.setdefault(a.project_id, []).append(ipaddress.ip_network(a.value, strict=False))
        except ValueError:
            continue
    for a in owned.filter(kind='ip', added_by__isnull=True, decision_reason='').iterator():
        # Anything that is not a list of {'source': auto} dicts is unknown evidence: leave the IP owned.
        srcs = a.sources or []
        if not isinstance(srcs, list) or any(
                not isinstance(s, dict) or s.get('source') not in AUTO_SOURCES for s in srcs):
            continue
        try:
            ip = ipaddress.ip_address(a.value)
        except ValueError:
            continue
        if any(ip.version == n.version and ip in n for n in declared.get(a.project_id, [])):
            continue
        a.scope_tier = 'dependency'
        a.save(update_fields=['scope_tier'])


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0011_asset_dependency_tier'),
    ]

    operations = [
        migrations.RunPython(demote_auto_owned_ips, migrations.RunPython.noop),
    ]
