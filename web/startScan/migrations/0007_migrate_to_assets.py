from django.db import migrations


def forward(apps, schema_editor):
    from startScan.inventory_migrate import run_all
    run_all(apps)


def backward(apps, schema_editor):
    from startScan.inventory_migrate import reverse_all
    reverse_all(apps)


class Migration(migrations.Migration):
    atomic = False
    dependencies = [('startScan', '0006_vulnerability_asset')]
    operations = [migrations.RunPython(forward, backward)]
