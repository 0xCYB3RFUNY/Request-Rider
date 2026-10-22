import os

from django.apps import AppConfig


class LabConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'lab'

    def ready(self):
        from . import signals  # noqa: F401
        # Start cron recovery in the runserver child process so active local
        # schedules resume after a web restart without starting a scheduler in
        # the autoreloader parent or during tests.
        if os.environ.get('RUN_MAIN') == 'true':
            from .workflow_engine import ensure_scheduler
            ensure_scheduler()
