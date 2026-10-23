from django.db import migrations


class Migration(migrations.Migration):
    """The recon_note app is gone, so its own migration can no longer drop its table.

    IF EXISTS keeps fresh databases (which never create it) working; the table only
    holds the TodoNote rows that pointed at ScanHistory/Subdomain, nothing points at it.
    """

    dependencies = [('startScan', '0029_cert_sighting')]

    operations = [
        migrations.RunSQL('DROP TABLE IF EXISTS recon_note_todonote CASCADE', migrations.RunSQL.noop),
    ]
