from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0048_workflowrun_graph_connections_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="workflowrun",
            name="status",
            field=models.TextField(
                choices=[
                    ("queued", "Queued"),
                    ("running", "Running"),
                    ("waiting", "Waiting"),
                    ("paused", "Paused"),
                    ("completed", "Completed"),
                    ("failed", "Failed"),
                    ("cancelled", "Cancelled"),
                    ("interrupted", "Interrupted"),
                ],
                default="queued",
            ),
        ),
        migrations.AlterField(
            model_name="workflownodeexecution",
            name="status",
            field=models.TextField(
                choices=[
                    ("running", "Running"),
                    ("waiting", "Waiting"),
                    ("completed", "Completed"),
                    ("failed", "Failed"),
                ]
            ),
        ),
    ]
