"""Management command to backfill and reingest secrets from existing TrafficRecord rows."""

from __future__ import annotations

from urllib.parse import urlsplit

from django.core.management.base import BaseCommand
from lab.ingest import KnowledgeBaseIngestor
from lab.models import Project, ProjectSecret, TrafficRecord


class Command(BaseCommand):
    help = "Re-ingest secrets (JWT, passwords, hashes, tokens) from durable TrafficRecord rows into ProjectSecret."

    def add_arguments(self, parser):
        parser.add_argument(
            "--project",
            type=str,
            default="",
            help="Project name or ID to reingest (defaults to all projects if empty).",
        )
        parser.add_argument(
            "--link-unassigned",
            action="store_true",
            help="Link unassigned traffic (project_id=None) whose host matches the project target.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=500,
            help="Number of traffic records to fold in each batch (default: 500).",
        )

    def handle(self, *args, **options):
        project_arg = options.get("project", "").strip()
        link_unassigned = options.get("link_unassigned", False)
        batch_size = max(10, int(options.get("batch_size") or 500))

        if project_arg:
            if project_arg.isdigit():
                projects = list(Project.objects.filter(id=int(project_arg)))
            else:
                projects = list(Project.objects.filter(name__iexact=project_arg))
            if not projects:
                self.stderr.write(f"No project found matching '{project_arg}'")
                return
        else:
            projects = list(Project.objects.all())

        for project in projects:
            self.stdout.write(f"Processing project {project.id} ('{project.name}')...")

            if link_unassigned and project.target:
                target_host = urlsplit(project.target).netloc
                if target_host:
                    linked = TrafficRecord.objects.filter(
                        project__isnull=True, host=target_host
                    ).update(project=project)
                    if linked:
                        self.stdout.write(f"  Linked {linked} previously unassigned traffic records to project.")

            records_qs = TrafficRecord.objects.filter(project=project).order_by("id")
            total = records_qs.count()
            self.stdout.write(f"  Found {total} traffic records for project.")

            initial_secrets = ProjectSecret.objects.filter(project=project).count()
            processed = 0

            for offset in range(0, total, batch_size):
                batch = list(records_qs[offset : offset + batch_size])
                ingestor = KnowledgeBaseIngestor()
                ingestor.add_many(batch)
                ingestor.run()
                processed += len(batch)
                self.stdout.write(f"  Processed {processed}/{total} records...")

            final_secrets = ProjectSecret.objects.filter(project=project).count()
            new_secrets = final_secrets - initial_secrets
            self.stdout.write(
                self.style.SUCCESS(
                    f"Done for project '{project.name}': {new_secrets} new secret(s) created (total: {final_secrets})."
                )
            )
