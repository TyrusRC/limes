import re

from django.db import migrations

BAD = re.compile(r'[^a-z0-9._:/-]+')


def clean(name):
    """The name as limes.tags would accept it: lower case, bad runs become '-', starts alphanumeric, 40 characters."""
    out = BAD.sub('-', (name or '').strip().lower()).lstrip('._:/-')[:40].rstrip('-')
    return out or None


def per_project(apps, schema_editor):
    """Each global tag becomes one tag per project that has assets using it, and the assets move to that copy.
    Global rows are deleted afterwards, including unused ones. Names that clean to the same text merge."""
    Tag = apps.get_model('startScan', 'Tag')
    Through = apps.get_model('startScan', 'Asset').tags.through
    for old in Tag.objects.filter(project__isnull=True):
        name = clean(old.name)
        if name:
            projects = Through.objects.filter(tag_id=old.pk).values_list('asset__project_id', flat=True).distinct()
            for pid in set(projects):
                new, _ = Tag.objects.get_or_create(project_id=pid, name=name)
                ids = list(Through.objects.filter(tag_id=old.pk, asset__project_id=pid).values_list('asset_id', flat=True))
                have = set(Through.objects.filter(tag_id=new.pk, asset_id__in=ids).values_list('asset_id', flat=True))
                Through.objects.bulk_create([Through(asset_id=a, tag_id=new.pk) for a in ids if a not in have])
    Tag.objects.filter(project__isnull=True).delete()  # cascades the old through rows


class Migration(migrations.Migration):

    dependencies = [('startScan', '0032_tag_project')]

    operations = [migrations.RunPython(per_project, migrations.RunPython.noop)]
