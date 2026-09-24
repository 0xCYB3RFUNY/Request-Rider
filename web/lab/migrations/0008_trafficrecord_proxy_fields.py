from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("lab", "0007_remove_auditlog")]

    operations = [
        migrations.AddField(
            model_name="trafficrecord",
            name="host",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="trafficrecord",
            name="proxy_event_id",
            field=models.PositiveBigIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="trafficrecord",
            name="proxy_session",
            field=models.BigIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="trafficrecord",
            name="source",
            field=models.CharField(
                choices=[("repeater", "Repeater"), ("proxy", "Proxy")],
                default="repeater",
                max_length=20,
            ),
        ),
    ]
