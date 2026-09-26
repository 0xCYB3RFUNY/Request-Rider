from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0025_workflow_automation"),
    ]

    operations = [
        migrations.AlterField(
            model_name="trafficrecord",
            name="source",
            field=models.CharField(
                choices=[
                    ("repeater", "Repeater"),
                    ("intruder", "Intruder"),
                    ("last-byte", "Last-Byte Sync"),
                    ("proxy", "Proxy"),
                    ("route-check", "Route check"),
                ],
                default="repeater",
                max_length=20,
            ),
        ),
    ]
