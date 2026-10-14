from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0056_activescanjob"),
    ]

    operations = [
        migrations.AlterField(
            model_name="trafficrecord",
            name="source",
            field=models.TextField(
                choices=[
                    ("repeater", "Repeater"),
                    ("intruder", "Intruder"),
                    ("last-byte", "Last-Byte Sync"),
                    ("proxy", "Proxy"),
                    ("route-check", "Route check"),
                    ("tool", "Tool"),
                ],
                default="repeater",
            ),
        ),
    ]
