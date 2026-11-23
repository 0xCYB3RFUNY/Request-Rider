from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0061_active_run_checkpoint"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scannerrun",
            name="engine",
            field=models.TextField(
                choices=[
                    ("builtin", "Builtin"),
                    ("templates", "Templates"),
                    ("corpus", "Corpus"),
                    ("active", "Active"),
                    ("openvas", "OpenVAS"),
                ],
                default="builtin",
            ),
        ),
    ]
