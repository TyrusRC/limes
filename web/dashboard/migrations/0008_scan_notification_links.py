import re

from django.db import migrations

OLD = re.compile(r'^/scan/([^/?#]+)/detail/\d+$')


def to_history(apps, schema_editor):
    """The per-scan detail page is gone; notifications that linked to it now open the project's Scan History."""
    Notification = apps.get_model('dashboard', 'InAppNotification')
    for n in Notification.objects.filter(redirect_link__startswith='/scan/', redirect_link__contains='/detail/').iterator():
        m = OLD.match(n.redirect_link)
        if m:
            n.redirect_link = f'/scan/{m.group(1)}/history/scan'
            n.save(update_fields=['redirect_link'])


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0007_drop_search_history')]
    operations = [migrations.RunPython(to_history, migrations.RunPython.noop)]
