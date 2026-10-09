from django.db import migrations


def stamp_profiles(apps, schema_editor):
    from limes.profiles import map_engine_to_profile
    EngineType = apps.get_model('scanEngine', 'EngineType')
    for engine in EngineType.objects.all():
        engine.profile = map_engine_to_profile(engine.yaml_configuration)
        engine.save(update_fields=['profile'])


class Migration(migrations.Migration):

    dependencies = [
        ('scanEngine', '0003_enginetype_profile'),
    ]

    operations = [
        migrations.RunPython(stamp_profiles, migrations.RunPython.noop),
    ]
