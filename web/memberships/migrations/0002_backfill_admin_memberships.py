from django.db import migrations


def backfill(apps, schema_editor):
    """Before this release every user could see every project, so every existing user becomes an admin of every
    existing project: nothing stops working on upgrade. Tighten it afterwards on the Members page."""
    User = apps.get_model('auth', 'User')
    Project = apps.get_model('dashboard', 'Project')
    Member = apps.get_model('memberships', 'ProjectMember')
    project_ids = list(Project.objects.values_list('pk', flat=True))
    rows = [Member(user_id=uid, project_id=pid, role='admin')
            for uid in User.objects.values_list('pk', flat=True) for pid in project_ids]
    Member.objects.bulk_create(rows, ignore_conflicts=True, batch_size=1000)


class Migration(migrations.Migration):
    dependencies = [('memberships', '0001_initial'), ('dashboard', '0008_scan_notification_links')]
    operations = [migrations.RunPython(backfill, migrations.RunPython.noop)]
