from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lab", "0018_remove_legacy_agent_runtime"),
    ]

    operations = [
        migrations.AddField(
            model_name="trafficrecord",
            name="source_ip",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
    ]
