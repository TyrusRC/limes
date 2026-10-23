import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [('startScan', '0033_tags_per_project')]

    operations = [
        migrations.AlterField(
            model_name='tag',
            name='project',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='asset_tags',
                                    to='dashboard.project'),
        ),
        migrations.AlterUniqueTogether(name='tag', unique_together={('project', 'name')}),
    ]
