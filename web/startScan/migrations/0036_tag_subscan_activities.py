from django.db import migrations

PREFIX = 'subscan_'


def tag_subscan_activities(apps, schema_editor):
    """A subscan's stage activity hangs off the parent scan but covers one host. Scoring skipped those through
    SubScan.celery_ids; before SubScan goes, rename them so a later `vulnerability_scan` filter can never pick
    them up as the root's own stage (scoring baselines stay exactly as they were). Commands and logs are kept."""
    SubScan = apps.get_model('startScan', 'SubScan')
    ScanActivity = apps.get_model('startScan', 'ScanActivity')
    ids = {c for row in SubScan.objects.values_list('celery_ids', flat=True) for c in row or []}
    ids.discard('')
    if not ids:
        return
    rows = ScanActivity.objects.filter(celery_id__in=ids).exclude(name__startswith=PREFIX)
    for activity in rows.iterator():
        activity.name = PREFIX + activity.name
        activity.save(update_fields=['name'])


class Migration(migrations.Migration):
    dependencies = [('startScan', '0035_asset_kind_api')]
    operations = [migrations.RunPython(tag_subscan_activities, migrations.RunPython.noop)]
