from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0065_projectsurfacesnapshot"),
    ]

    operations = [
        migrations.CreateModel(
            name="WorkflowTemplate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("slug", models.SlugField(max_length=120, unique=True)),
                ("name", models.TextField()),
                ("description", models.TextField(blank=True, default="")),
                ("category", models.TextField(blank=True, default="security")),
                ("author", models.TextField(blank=True, default="local")),
                ("version", models.TextField(blank=True, default="1.0.0")),
                ("nodes", models.JSONField(default=list)),
                ("connections", models.JSONField(default=list)),
                ("manifest", models.JSONField(default=dict)),
                ("schema_signature", models.TextField(blank=True, default="")),
                ("embedding_mrl", models.BinaryField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "project",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="workflow_templates",
                        to="lab.project",
                    ),
                ),
            ],
            options={
                "ordering": ["-updated_at", "-id"],
            },
        ),
        migrations.CreateModel(
            name="AttackChain",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.TextField()),
                ("objective", models.TextField(blank=True, default="")),
                ("severity", models.TextField(default="high")),
                ("status", models.TextField(default="verified")),
                ("mitre_techniques", models.JSONField(default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="attack_chains",
                        to="lab.project",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at", "-id"],
            },
        ),
        migrations.CreateModel(
            name="AttackStep",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("step_order", models.IntegerField(default=1)),
                ("phase", models.TextField(default="exploitation")),
                ("description", models.TextField()),
                ("finding_identity", models.TextField(blank=True, default="")),
                ("exchange_id", models.IntegerField(blank=True, null=True)),
                ("evidence_provenance", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "chain",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="steps",
                        to="lab.attackchain",
                    ),
                ),
            ],
            options={
                "ordering": ["step_order", "id"],
            },
        ),
    ]
