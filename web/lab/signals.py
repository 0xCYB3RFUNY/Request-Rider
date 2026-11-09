"""Automatic Project knowledge-base ingestion for durable HTTP evidence.

The per-row logic lives in :mod:`lab.ingest` so that batched callers
(`bulk_create` does not emit `post_save`) and this single-row receiver share one
implementation and therefore one definition of the knowledge-base rules.
"""

from django.db.models.signals import post_save
from django.dispatch import receiver

from .ingest import ingest_traffic_record
from .models import TrafficRecord


@receiver(post_save, sender=TrafficRecord)
def ingest_traffic_record_on_save(sender, instance, created, **kwargs):
    if not created or not instance.project_id:
        return
    ingest_traffic_record(instance)
