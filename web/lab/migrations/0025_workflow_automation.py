from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0024_project_relations_cascade"),
    ]

    operations = [
        migrations.CreateModel(
            name="Workflow",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(default="Workflow", max_length=160)),
                ("description", models.TextField(blank=True, default="")),
                ("nodes", models.JSONField(default=list)),
                ("connections", models.JSONField(default=list)),
                ("settings", models.JSONField(default=dict)),
                ("metadata", models.JSONField(default=dict)),
                ("version", models.PositiveIntegerField(default=1)),
                ("active", models.BooleanField(default=False)),
                ("schedule", models.CharField(blank=True, default="", max_length=120)),
                ("webhook_slug", models.CharField(blank=True, max_length=96, null=True, unique=True)),
                ("last_run_at", models.DateTimeField(blank=True, null=True)),
                ("next_run_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "project",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="workflows",
                        to="lab.project",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="WorkflowRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("running", "Running"),
                            ("paused", "Paused"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                            ("cancelled", "Cancelled"),
                            ("interrupted", "Interrupted"),
                        ],
                        default="queued",
                        max_length=20,
                    ),
                ),
                (
                    "mode",
                    models.CharField(
                        choices=[("manual", "Manual"), ("schedule", "Schedule"), ("webhook", "Webhook")],
                        default="manual",
                        max_length=20,
                    ),
                ),
                ("trigger_type", models.CharField(default="manual", max_length=40)),
                ("trigger_node_id", models.CharField(blank=True, default="", max_length=120)),
                ("input_data", models.JSONField(default=dict)),
                ("output_data", models.JSONField(default=dict)),
                ("current_node", models.CharField(blank=True, default="", max_length=120)),
                ("logs", models.JSONField(default=list)),
                ("error", models.TextField(blank=True, default="")),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "project",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="workflow_runs",
                        to="lab.project",
                    ),
                ),
                (
                    "workflow",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="runs",
                        to="lab.workflow",
                    ),
                ),
            ],
        ),
    ]
