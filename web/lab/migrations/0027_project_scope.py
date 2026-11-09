from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0026_trafficrecord_last_byte_source"),
    ]

    operations = [
        migrations.AddField(
            model_name="project",
            name="scope_in",
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name="project",
            name="scope_out",
            field=models.JSONField(default=list),
        ),
    ]
