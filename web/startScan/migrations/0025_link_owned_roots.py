from django.db import IntegrityError, migrations, transaction
from django.utils import timezone


def link_owned_roots(apps, schema_editor):
    """Give every owned root domain without one a scan target (a Domain) in its own project.

    Inline logic on historical models on purpose: this must not import app code that uses current models.
    A name already used by a Domain of another project (Domain.name is globally unique) is skipped.

    NOTE: the first dispatcher ticks after deploy scan every previously unlinked owned root, throttled by
    MAX_IN_FLIGHT=2 / MAX_DISPATCH_PER_TICK=1.
    """
    Asset = apps.get_model('startScan', 'Asset')
    Domain = apps.get_model('targetApp', 'Domain')
    now = timezone.now()
    for a in Asset.objects.filter(kind='root_domain', scope_tier='owned_root').iterator():
        if Domain.objects.filter(name=a.value).exists():
            continue
        try:
            with transaction.atomic():
                Domain.objects.create(name=a.value, project_id=a.project_id, insert_date=now)
        except IntegrityError:
            pass


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0024_asset_kind_asn'),
        ('targetApp', '0002_remove_domain_h1_team_handle'),
    ]

    operations = [
        migrations.RunPython(link_owned_roots, migrations.RunPython.noop),
    ]
