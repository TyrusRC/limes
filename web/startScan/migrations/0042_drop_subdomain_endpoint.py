from django.db import migrations


class Migration(migrations.Migration):
    """Subdomain and EndPoint (and the finding links to them) leave: hosts are hostname Assets, the URLs of a run
    live in its results dir. Tag / CWE / reference rows were folded into Vulnerability arrays by 0041."""

    dependencies = [
        ('startScan', '0041_copy_vulnerability_lists'),
    ]

    operations = [
        # their indexes name fields that are removed first; Django cannot recreate such a model when reversing
        migrations.RemoveIndex(model_name='subdomain', name='sub_scan_disc_idx'),
        migrations.RemoveIndex(model_name='subdomain', name='sub_scan_status_idx'),
        migrations.RemoveIndex(model_name='endpoint', name='ep_scan_disc_idx'),
        migrations.RemoveIndex(model_name='endpoint', name='ep_scan_status_idx'),
        migrations.RemoveField(model_name='vulnerability', name='cwe_ids'),
        migrations.RemoveField(model_name='vulnerability', name='endpoint'),
        migrations.RemoveField(model_name='vulnerability', name='references'),
        migrations.RemoveField(model_name='vulnerability', name='subdomain'),
        migrations.RemoveField(model_name='vulnerability', name='tags'),
        migrations.RemoveField(model_name='vulnerability', name='target_domain'),
        migrations.RemoveField(model_name='endpoint', name='scan_history'),
        migrations.RemoveField(model_name='endpoint', name='subdomain'),
        migrations.RemoveField(model_name='endpoint', name='target_domain'),
        migrations.RemoveField(model_name='endpoint', name='techs'),
        migrations.RemoveField(model_name='subdomain', name='ip_addresses'),
        migrations.RemoveField(model_name='subdomain', name='scan_history'),
        migrations.RemoveField(model_name='subdomain', name='target_domain'),
        migrations.RemoveField(model_name='subdomain', name='technologies'),
        migrations.DeleteModel(name='CweId'),
        migrations.DeleteModel(name='EndPoint'),
        migrations.DeleteModel(name='Subdomain'),
        migrations.DeleteModel(name='VulnerabilityReference'),
        migrations.DeleteModel(name='VulnerabilityTags'),
    ]
