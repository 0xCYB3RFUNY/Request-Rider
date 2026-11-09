from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0012_trafficrecord_metadata"),
    ]

    operations = [
        migrations.AddField(
            model_name="intruderattack",
            name="delay_ms",
            field=models.PositiveIntegerField(default=0),
        ),
    ]
