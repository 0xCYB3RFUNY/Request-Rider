from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("lab", "0004_remove_targetpolicy")]

    operations = [
        migrations.AddField(
            model_name="trafficrecord",
            name="response_size",
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="AppSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("allowed_hosts", models.JSONField(default=list)),
                ("default_timeout", models.PositiveIntegerField(default=30000)),
                ("default_concurrency", models.PositiveIntegerField(default=5)),
                ("default_delay", models.PositiveIntegerField(default=0)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
