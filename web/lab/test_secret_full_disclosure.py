"""End-to-end: a captured secret reaches every surface as the whole value.

The operator's rule: every secret, always complete — no `[metadata only]`, no
`[REDACTED]`, no fingerprint, no ellipsis. This file walks one captured exchange
from the traffic row through the ingest, the Project hub API, the report summary
and the exported bundle, and asserts the credential survives each hop unchanged.

It also pins the two halves of the ingest that make "complete" true rather than
aspirational: several distinct JWTs on one exchange become several rows, and a
row whose value is already correct is not rewritten by a repeated poll.

`TrafficRecord` has a `post_save` receiver that ingests, so `create()` already
runs the ingest path. The explicit ingestors below are the ones that exercise
the fold itself — dedup, the value write and the rotation — where a signal alone
would not say anything about them.
"""

from django.apps import apps as django_apps
from django.test import Client, TestCase

from lab.ingest import KnowledgeBaseIngestor
from lab.models import Project, ProjectExchange, ProjectSecret, TrafficRecord
from lab.project_context import ProjectContextBuilder
from lab.project_transfer import export_bundle

JWT_A = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.QUFBQUFBQUFBQUFBQUFBQQ"
JWT_B = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjQ1NjcifQ.QkJCQkJCQkJCQkJCQkJCQg"
SESSION = "session=8f14e45fceea167a5a36dedd4bea2543; Path=/; HttpOnly"

PROJECT_URL = "https://app.example.test/api/me"


def capture(project, **overrides):
    """Store one exchange. The `post_save` receiver runs the ingest for it."""
    fields = {
        "project": project,
        "method": "GET",
        "url": PROJECT_URL,
        "request_headers": {
            "Authorization": f"Bearer {JWT_A}",
            "Cookie": f"session={JWT_A}; theme=dark",
        },
        "response_headers": {"Set-Cookie": SESSION},
        "status_code": 200,
        "response_content_type": "application/json",
    }
    fields.update(overrides)
    return TrafficRecord.objects.create(**fields)


def fold(record):
    """Run one record through the batch ingestor and return its counters."""
    ingestor = KnowledgeBaseIngestor()
    ingestor.add(record)
    return ingestor.run()


def stored_values(project):
    return {
        (row.secret_type, row.key_name): row.value_ref
        for row in ProjectSecret.objects.filter(project=project)
    }


class SecretFullDisclosureTests(TestCase):
    """One capture in, the credential out — whole, everywhere."""

    def setUp(self):
        self.project = Project.objects.create(name="disclosure", target="app.example.test")
        self.record = capture(self.project)

    # -- ingest ----------------------------------------------------------

    def test_ingest_stores_the_whole_credential_not_an_empty_reference(self):
        values = stored_values(self.project)
        self.assertEqual(values[("api_key", "Authorization")], f"Bearer {JWT_A}")
        self.assertEqual(values[("cookie", "cookie")], f"session={JWT_A}; theme=dark")
        self.assertEqual(values[("cookie", "set-cookie")], SESSION)
        self.assertEqual(values[("jwt", "JWT token")], JWT_A)
        self.assertNotIn("", values.values())
        self.assertNotIn("[metadata only]", values.values())

    def test_every_distinct_jwt_on_one_exchange_becomes_its_own_row(self):
        """Two credentials on one exchange are two facts, not one overwritten fact.

        The row key is `(project, secret_type, key_name, source_url)`, so the
        second token only exists at all if it gets its own `key_name`.
        """
        capture(
            self.project,
            url="https://app.example.test/api/two",
            request_headers={"Authorization": f"Bearer {JWT_A}", "Cookie": f"alt={JWT_B}"},
            response_headers={},
        )
        jwts = {
            row.key_name: row.value_ref
            for row in ProjectSecret.objects.filter(project=self.project, secret_type="jwt")
        }
        self.assertEqual(jwts, {"JWT token": JWT_A, "JWT token 2": JWT_B})

    def test_a_repeated_poll_does_not_rewrite_or_duplicate_a_row(self):
        counters = fold(self.record)
        self.assertEqual(counters["secrets"], 0)
        self.assertEqual(counters.get("secrets_updated", 0), 0)
        self.assertEqual(
            ProjectSecret.objects.filter(project=self.project, secret_type="jwt").count(), 1
        )
        stored = ProjectSecret.objects.get(
            project=self.project, secret_type="jwt", key_name="JWT token"
        )
        self.assertEqual(stored.value_ref, JWT_A)

    def test_a_rotated_token_is_written_through(self):
        """A stale token is a wrong answer, so a changed value replaces the old one."""
        rotated = capture(
            self.project,
            request_headers={"Authorization": f"Bearer {JWT_B}", "Cookie": ""},
            response_headers={},
        )
        stored = ProjectSecret.objects.get(
            project=self.project, secret_type="api_key", key_name="Authorization"
        )
        # The `post_save` path writes the new credential straight away.
        self.assertEqual(stored.value_ref, f"Bearer {JWT_B}")

        # The batch path has to reach the same answer, and has to do it with one
        # statement rather than one per row. Put the old value back so the fold
        # sees a real difference.
        ProjectSecret.objects.filter(pk=stored.pk).update(value_ref=f"Bearer {JWT_A}")
        counters = fold(rotated)

        self.assertEqual(counters.get("secrets_updated", 0), 1)
        stored.refresh_from_db()
        self.assertEqual(stored.value_ref, f"Bearer {JWT_B}")

    # -- the report ------------------------------------------------------

    def test_the_report_line_carries_the_whole_value(self):
        summary = ProjectContextBuilder(self.project.id).build_summary_markdown()

        self.assertIn(f"value=Bearer {JWT_A}", summary)
        self.assertIn(f"value=session={JWT_A}; theme=dark", summary)
        self.assertIn(f"value={SESSION}", summary)
        self.assertIn(f"value={JWT_A}", summary)
        self.assertIn("## Secrets", summary)
        for placeholder in ("[metadata only]", "[REDACTED]", "[REDACTED_JWT]", "…"):
            self.assertNotIn(placeholder, summary)

    # -- the hub API the table reads --------------------------------------

    def test_the_hub_payload_the_table_renders_carries_the_whole_value(self):
        client = Client()
        session = client.session
        session["active_project_id"] = self.project.id
        session.save()
        response = client.get(f"/api/projects/{self.project.id}/hub")

        self.assertEqual(response.status_code, 200)
        values = {row["value_ref"] for row in response.json()["secret_references"]}
        self.assertIn(f"Bearer {JWT_A}", values)
        self.assertIn(SESSION, values)
        self.assertIn(JWT_A, values)
        self.assertNotIn("", values)

    # -- the bundle ------------------------------------------------------

    def test_the_exported_bundle_carries_the_whole_value(self):
        bundle = export_bundle(self.project)
        values = {row["value_ref"] for row in bundle["secret_references"]}
        self.assertIn(f"Bearer {JWT_A}", values)
        self.assertIn(SESSION, values)
        self.assertIn(JWT_A, values)

    # -- the evidence the backfill reads ----------------------------------

    def test_the_project_exchange_holds_the_headers_the_backfill_reads(self):
        """The backfill is only possible because the evidence is already here."""
        exchange = ProjectExchange.objects.get(project=self.project)
        self.assertEqual(exchange.url, PROJECT_URL)
        self.assertEqual(exchange.request_headers["Authorization"], f"Bearer {JWT_A}")
        self.assertEqual(exchange.response_headers["Set-Cookie"], SESSION)


class BackfillSecretValueTests(TestCase):
    """Migration 0059: rows written with an empty `value_ref` are filled in."""

    @staticmethod
    def backfill():
        # A module whose name starts with a digit is not importable by name, so
        # the migration is loaded the way Django's own migration loader loads it.
        import importlib.util
        from pathlib import Path

        path = Path(__file__).with_name("migrations") / "0059_projectsecret_full_values.py"
        spec = importlib.util.spec_from_file_location("rr_migration_0059", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # The migration reads and writes fields this migration does not change,
        # so the live registry answers `get_model` exactly as a historical one
        # would for these two models.
        module.backfill_secret_values(django_apps, None)

    def setUp(self):
        self.project = Project.objects.create(name="backfill", target="app.example.test")
        capture(self.project)
        # Reproduce the state the operator's database is in right now: secrets
        # detected, values never collected.
        ProjectSecret.objects.filter(project=self.project).update(value_ref="")
        self.assertTrue(ProjectSecret.objects.filter(project=self.project, value_ref="").exists())

    def test_backfill_recovers_every_value_from_the_stored_exchanges(self):
        self.backfill()

        values = stored_values(self.project)
        self.assertEqual(values[("api_key", "Authorization")], f"Bearer {JWT_A}")
        self.assertEqual(values[("cookie", "cookie")], f"session={JWT_A}; theme=dark")
        self.assertEqual(values[("cookie", "set-cookie")], SESSION)
        self.assertEqual(values[("jwt", "JWT token")], JWT_A)
        self.assertNotIn("", values.values())

    def test_backfill_prefers_the_newest_exchange_for_a_url(self):
        """A URL observed twice must yield the credential that is in use now."""
        capture(
            self.project,
            request_headers={"Authorization": f"Bearer {JWT_B}", "Cookie": ""},
            response_headers={},
        )
        ProjectSecret.objects.filter(project=self.project).update(value_ref="")

        self.backfill()
        stored = ProjectSecret.objects.get(
            project=self.project, secret_type="api_key", key_name="Authorization"
        )
        self.assertEqual(stored.value_ref, f"Bearer {JWT_B}")

    def test_backfill_leaves_a_row_alone_when_there_is_no_evidence_for_it(self):
        orphan = ProjectSecret.objects.create(
            project=self.project,
            secret_type="cookie",
            key_name="cookie",
            source_url="https://app.example.test/never-captured",
        )
        self.backfill()
        orphan.refresh_from_db()
        self.assertEqual(orphan.value_ref, "")

    def test_backfill_is_idempotent(self):
        self.backfill()
        before = dict(
            ProjectSecret.objects.filter(project=self.project).values_list("id", "value_ref")
        )
        self.backfill()
        after = dict(
            ProjectSecret.objects.filter(project=self.project).values_list("id", "value_ref")
        )
        self.assertEqual(before, after)