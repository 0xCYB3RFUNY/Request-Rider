"""Test runner that prepares a UTF-8 test database before Django creates it.

``DiscoverRunner`` is left alone on every other axis: test discovery, ordering,
parallel runs, ``--keepdb``, and the failure messages all behave exactly as
they do upstream. The only addition is the template check, because the failure
it prevents is a ``DataError`` inside an unrelated test.
"""

from __future__ import annotations

import logging

from django.test.runner import DiscoverRunner

from .testdb import connection_kwargs_from_settings, ensure_test_template

logger = logging.getLogger(__name__)


class RequestRiderTestRunner(DiscoverRunner):
    """``DiscoverRunner`` plus an explicit UTF-8 test template."""

    def setup_databases(self, **kwargs):
        from django.conf import settings

        databases = getattr(settings, "DATABASES", {})
        default = databases.get("default", {})
        if default.get("ENGINE") == "django.db.backends.postgresql":
            template = getattr(settings, "POSTGRES_TEST_TEMPLATE", "")
            if template and template != default.get("NAME"):
                ensure_test_template(
                    template,
                    connection_kwargs=connection_kwargs_from_settings(databases),
                )
        return super().setup_databases(**kwargs)
