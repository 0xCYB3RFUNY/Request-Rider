from django.db import migrations, models
from django.db.models import Min, Count


def deduplicate_project_secrets(apps, schema_editor):
    ProjectSecret = apps.get_model("lab", "ProjectSecret")
    duplicates = (
        ProjectSecret.objects.values("project_id", "secret_type", "key_name", "source_url")
        .annotate(min_id=Min("id"), count=Count("id"))
        .filter(count__gt=1)
    )
    for dup in duplicates:
        ProjectSecret.objects.filter(
            project_id=dup["project_id"],
            secret_type=dup["secret_type"],
            key_name=dup["key_name"],
            source_url=dup["source_url"],
        ).exclude(id=dup["min_id"]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0057_trafficrecord_tool_source"),
    ]

    operations = [
        migrations.RunPython(deduplicate_project_secrets, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="projectsecret",
            constraint=models.UniqueConstraint(
                fields=["project", "secret_type", "key_name", "source_url"],
                name="project_secret_project_type_key_url_unique",
            ),
        ),
    ]
