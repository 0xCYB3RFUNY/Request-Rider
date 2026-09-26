from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0017_intruderattack_delay_default"),
    ]

    operations = [
        migrations.DeleteModel(name="AgentEvent"),
        migrations.DeleteModel(name="AgentStep"),
        migrations.DeleteModel(name="AgentRun"),
    ]
