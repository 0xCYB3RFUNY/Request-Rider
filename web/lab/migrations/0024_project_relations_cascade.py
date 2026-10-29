from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0023_targetjob"),
    ]

    operations = [
        migrations.AlterField(
            model_name="finding",
            name="project",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.CASCADE,
                related_name="findings",
                to="lab.project",
            ),
        ),
        migrations.AlterField(
            model_name="intruderattack",
            name="project",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.CASCADE,
                related_name="intruder_attacks",
                to="lab.project",
            ),
        ),
        migrations.AlterField(
            model_name="targetjob",
            name="project",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.CASCADE,
                related_name="target_jobs",
                to="lab.project",
            ),
        ),
        migrations.AlterField(
            model_name="trafficrecord",
            name="project",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.CASCADE,
                related_name="traffic_records",
                to="lab.project",
            ),
        ),
        migrations.AlterField(
            model_name="trafficsession",
            name="project",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.CASCADE,
                related_name="traffic_sessions",
                to="lab.project",
            ),
        ),
    ]
