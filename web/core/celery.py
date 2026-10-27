import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

app = Celery("requestrider")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
