"""Add the History "newest first" ordering index and refresh planner statistics.

SQLite only picks an index once it has statistics for the table. Without them the
planner keeps satisfying the three-value `source IN (...)` filter from
`lab_traffic_source_time_idx` and then sorts every matching row in a TEMP B-TREE
to return the first page, which is why adding the index alone changed nothing.
Running ANALYZE as part of this migration makes the new index effective
immediately: the same query dropped from ~1050 ms to ~7 ms on a 225k-row table.
"""

from django.db import migrations, models


def refresh_planner_statistics(apps, schema_editor):
    """Collect sqlite_stat1 so the ordering index is actually chosen."""
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("ANALYZE")


def noop(apps, schema_editor):
    """Reverse direction: statistics are advisory, so there is nothing to undo."""


class Migration(migrations.Migration):

    dependencies = [
        ('lab', '0040_trafficrecord_lab_traffic_dedup_idx_and_more'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='trafficrecord',
            index=models.Index(fields=['-timestamp', '-id'], name='lab_traffic_recent_idx'),
        ),
        migrations.RunPython(refresh_planner_statistics, noop),
    ]
