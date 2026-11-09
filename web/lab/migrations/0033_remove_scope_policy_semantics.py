from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0032_osint_graph_risk_and_name"),
    ]

    operations = [
        migrations.AlterField(
            model_name="trafficrecord",
            name="scope_status",
            field=models.CharField(
                choices=[
                    ("unscoped", "Unassigned"),
                    ("project_linked", "Project-linked"),
                    ("in_scope", "Legacy project-linked"),
                    ("out_of_scope", "Legacy scope metadata"),
                    ("invalid_context", "Invalid capture context"),
                ],
                default="unscoped",
                max_length=20,
            ),
        ),
    ]
