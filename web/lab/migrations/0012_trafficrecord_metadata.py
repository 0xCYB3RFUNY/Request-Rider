from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0011_alter_trafficrecord_source"),
    ]

    operations = [
        migrations.AddField(
            model_name="trafficrecord",
            name="request_body_base64",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="trafficrecord",
            name="request_body_encoding",
            field=models.CharField(default="utf8", max_length=16),
        ),
        migrations.AddField(
            model_name="trafficrecord",
            name="response_body_base64",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="trafficrecord",
            name="response_body_encoding",
            field=models.CharField(default="utf8", max_length=16),
        ),
        migrations.AddField(
            model_name="trafficrecord",
            name="response_content_type",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="trafficrecord",
            name="tags",
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name="trafficrecord",
            name="notes",
            field=models.TextField(blank=True, default=""),
        ),
    ]
