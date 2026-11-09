from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0033_remove_scope_policy_semantics"),
    ]

    operations = [
        migrations.DeleteModel(
            name="TrafficSession",
        ),
    ]
