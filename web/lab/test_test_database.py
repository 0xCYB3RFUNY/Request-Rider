"""The test database has to be UTF-8 on any cluster, and this proves it.

The defect these tests guard is a green test run that only works on one machine.
A cluster created with a non-UTF-8 locale has ``SQL_ASCII`` templates, a test
database built from one cannot store a `§` marker, and the symptom is a
``DataError`` in whichever test happened to save a marked payload. Silencing
that with a hand-created database outside the repository is how the number gets
reported without the environment it came from.
"""

from unittest import mock

import psycopg
from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from django.test import SimpleTestCase, TestCase

from core import testdb


def _maintenance_kwargs():
    from django.conf import settings

    return testdb.connection_kwargs_from_settings(settings.DATABASES)


def _drop_database(name: str) -> None:
    connection = testdb._maintenance_connection(_maintenance_kwargs())
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                psycopg.sql.SQL("DROP DATABASE IF EXISTS {name}").format(
                    name=psycopg.sql.Identifier(name)
                )
            )
    finally:
        connection.close()


def _may_create_databases() -> bool:
    try:
        connection = testdb._maintenance_connection(_maintenance_kwargs())
    except (ImproperlyConfigured, psycopg.OperationalError):
        return False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user")
            row = cursor.fetchone()
    except psycopg.Error:
        return False
    finally:
        connection.close()
    return bool(row and row[0])


class TestTemplateEncodingTests(SimpleTestCase):
    def test_missing_template_has_no_encoding(self) -> None:
        self.assertIsNone(
            testdb.template_encoding(
                "rr_utf8_missing_template_probe", connection_kwargs=_maintenance_kwargs()
            )
        )

    def test_existing_template_reports_its_encoding(self) -> None:
        encoding = testdb.template_encoding(
            "requestrider_utf8_tmpl", connection_kwargs=_maintenance_kwargs()
        )
        # The suite's own template is the one it proves a UTF-8 database from.
        self.assertIn(encoding, {"UTF8", "SQL_ASCII", "LATIN1", "WIN1252"})
        if testdb.ensure_test_template(
            "requestrider_utf8_tmpl", connection_kwargs=_maintenance_kwargs()
        ) == "UTF8":
            self.assertEqual("UTF8", encoding)

    def test_connection_kwargs_omit_an_empty_password(self) -> None:
        kwargs = testdb.connection_kwargs_from_settings(
            {
                "default": {
                    "HOST": "127.0.0.1",
                    "PORT": 55433,
                    "USER": "kali",
                    "PASSWORD": "",
                    "NAME": "requestrider",
                }
            }
        )
        self.assertEqual(kwargs["port"], "55433")
        self.assertNotIn("password", kwargs)

    def test_connection_kwargs_keep_a_password(self) -> None:
        kwargs = testdb.connection_kwargs_from_settings(
            {"default": {"HOST": "db", "USER": "rr", "PASSWORD": "s3cret"}}
        )
        self.assertEqual(kwargs["password"], "s3cret")
        self.assertEqual(kwargs["port"], "5432")


class EnsureTestTemplateTests(SimpleTestCase):
    def setUp(self) -> None:
        testdb._verified.clear()
        self.addCleanup(testdb._verified.clear)

    def test_a_non_utf8_template_is_reported_with_the_fixing_statement(self) -> None:
        # Every cluster that has `template1` has it, and a cluster whose
        # templates are SQL_ASCII has it as SQL_ASCII. Asking for it is how the
        # real defect is reproduced without creating anything.
        encoding = testdb.template_encoding(
            "template1", connection_kwargs=_maintenance_kwargs()
        )
        if encoding in {"UTF8"}:
            self.skipTest("this cluster's template1 is already UTF-8")
        with self.assertRaises(ImproperlyConfigured) as raised:
            testdb.ensure_test_template("template1", connection_kwargs=_maintenance_kwargs())
        message = str(raised.exception)
        self.assertIn("template1", message)
        self.assertIn("CREATE DATABASE", message)
        self.assertIn("ENCODING 'UTF8'", message)

    def test_a_missing_template_without_permission_names_the_statement(self) -> None:
        with self.assertRaises(ImproperlyConfigured) as raised:
            testdb.ensure_test_template(
                "rr_utf8_never_created",
                connection_kwargs=_maintenance_kwargs(),
                allow_create=False,
            )
        message = str(raised.exception)
        self.assertIn("rr_utf8_never_created", message)
        self.assertIn("ENCODING 'UTF8'", message)

    def test_a_name_that_is_not_a_plain_identifier_is_refused(self) -> None:
        with self.assertRaises(ImproperlyConfigured):
            testdb.create_template(
                'bad"; DROP DATABASE requestrider; --', connection_kwargs=_maintenance_kwargs()
            )

    def test_a_verified_template_is_not_queried_again(self) -> None:
        with mock.patch.object(
            testdb, "template_encoding", return_value="UTF8"
        ) as probe:
            self.assertEqual(
                "UTF8",
                testdb.ensure_test_template(
                    "requestrider_utf8_tmpl", connection_kwargs=_maintenance_kwargs()
                ),
            )
            self.assertEqual(
                "UTF8",
                testdb.ensure_test_template(
                    "requestrider_utf8_tmpl", connection_kwargs=_maintenance_kwargs()
                ),
            )
        self.assertEqual(1, probe.call_count)

    def test_duplicate_creation_is_a_success(self) -> None:
        with mock.patch.object(
            testdb,
            "template_encoding",
            side_effect=[None, "UTF8"],
        ), mock.patch.object(testdb, "_maintenance_connection") as connect:
            connection = connect.return_value
            cursor = connection.cursor.return_value.__enter__.return_value
            cursor.execute.side_effect = psycopg.errors.DuplicateDatabase()
            testdb.create_template("rr_utf8_race", connection_kwargs=_maintenance_kwargs())
        connection.close.assert_called_once()

    def test_insufficient_privilege_names_the_role_and_the_statement(self) -> None:
        with mock.patch.object(testdb, "_maintenance_connection") as connect:
            connection = connect.return_value
            cursor = connection.cursor.return_value.__enter__.return_value
            cursor.execute.side_effect = psycopg.errors.InsufficientPrivilege()
            with self.assertRaises(ImproperlyConfigured) as raised:
                testdb.create_template(
                    "rr_utf8_denied", connection_kwargs={"user": "reader"}
                )
        message = str(raised.exception)
        self.assertIn("reader", message)
        self.assertIn("CREATEDB", message)


class TestTemplateCreationTests(TestCase):
    """Create a real template, because the statement is the deliverable."""

    TEMPLATE = "rr_utf8_template_selftest"

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if not _may_create_databases():
            raise cls.skipTest(
                "the current PostgreSQL role may not create databases, so the "
                "creation path cannot be exercised here"
            )
        testdb._verified.clear()
        _drop_database(cls.TEMPLATE)

    @classmethod
    def tearDownClass(cls) -> None:
        if _may_create_databases():
            _drop_database(cls.TEMPLATE)
        testdb._verified.clear()
        super().tearDownClass()

    def test_creating_the_template_makes_it_utf8_and_idempotent(self) -> None:
        kwargs = _maintenance_kwargs()
        self.assertEqual("UTF8", testdb.ensure_test_template(self.TEMPLATE, connection_kwargs=kwargs))
        # A second call must not fail, must not drop, and must not re-create.
        self.assertEqual("UTF8", testdb.ensure_test_template(self.TEMPLATE, connection_kwargs=kwargs))
        testdb._verified.clear()
        self.assertEqual("UTF8", testdb.ensure_test_template(self.TEMPLATE, connection_kwargs=kwargs))
        self.assertEqual("UTF8", testdb.template_encoding(self.TEMPLATE, connection_kwargs=kwargs))

    def test_the_test_database_of_this_run_is_built_from_a_utf8_template(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_setting('server_encoding')")
            self.assertIn(str(cursor.fetchone()[0]).upper(), {"UTF8", "UTF-8"})


class TestRunnerWiringTests(SimpleTestCase):
    """The runner, not a developer, is what makes the guarantee hold."""

    def test_the_runner_is_wired_and_refuses_to_share_the_template(self) -> None:
        from django.conf import settings
        from django.test.runner import DiscoverRunner

        from core.test_runner import RequestRiderTestRunner

        self.assertEqual("core.test_runner.RequestRiderTestRunner", settings.TEST_RUNNER)
        self.assertTrue(issubclass(RequestRiderTestRunner, DiscoverRunner))
        self.assertTrue(settings.POSTGRES_TEST_TEMPLATE)
        self.assertNotEqual(
            settings.POSTGRES_TEST_TEMPLATE, settings.DATABASES["default"]["NAME"]
        )
        self.assertEqual(
            settings.POSTGRES_TEST_TEMPLATE,
            settings.DATABASES["default"]["TEST"].get("TEMPLATE"),
        )

    def test_the_postgres_path_prepares_the_template_before_super(self) -> None:
        from django.conf import settings

        from core.test_runner import RequestRiderTestRunner

        databases = {
            "default": {
                "ENGINE": "django.db.backends.postgresql",
                "NAME": "requestrider",
                "USER": "kali",
                "PASSWORD": "",
                "HOST": "127.0.0.1",
                "PORT": "55433",
            }
        }
        with mock.patch.object(
            settings, "DATABASES", databases
        ), mock.patch(
            "django.test.runner.DiscoverRunner.setup_databases", return_value=[]
        ) as upstream, mock.patch("core.test_runner.ensure_test_template") as ensure:
            runner = RequestRiderTestRunner()
            self.assertEqual([], runner.setup_databases(aliases=["default"]))
        upstream.assert_called_once()
        self.assertEqual(
            settings.POSTGRES_TEST_TEMPLATE, ensure.call_args.args[0]
        )
        self.assertEqual("127.0.0.1", ensure.call_args.kwargs["connection_kwargs"]["host"])

    def test_a_non_postgresql_default_is_left_alone(self) -> None:
        from django.conf import settings

        from core.test_runner import RequestRiderTestRunner

        with mock.patch.object(
            settings, "DATABASES", {"default": {"ENGINE": "django.db.backends.mysql"}}
        ), mock.patch(
            "django.test.runner.DiscoverRunner.setup_databases", return_value=[]
        ), mock.patch("core.test_runner.ensure_test_template") as ensure:
            self.assertEqual(
                [], RequestRiderTestRunner().setup_databases(aliases=["default"])
            )
        ensure.assert_not_called()
