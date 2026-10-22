"""Tests for indexing a crawled page's enrichment into the Project.

The rule these tests exist to hold: the Project stores the credential the crawl
found, in full. A crawl of a public page finds live keys, and a row holding only
a fingerprint makes the analyst who just ran the crawl go and find it again. So
`ProjectSecret.value_ref` carries the value, and it reaches every surface that
lists a secret: the Project hub, the AI snapshot, the report and the bundle.
"""

from django.test import TestCase

from lab.models import OsintEntity, OsintGraph, Project, ProjectEndpoint, ProjectSecret
from lab.project_context import ProjectContextBuilder
from lab.project_transfer import export_bundle
from lab.views import _ingest_target_result

LEAKED_KEY = "AKIAIOSFODNN7SECREtK"


def enrichment_page():
    """One crawled page carrying every enrichment kind the analyser emits."""
    return {
        "url": "https://shop.example.ru/catalog",
        "status": 200,
        "enrich": {
            "notable_files": [
                {"url": "https://shop.example.ru/admin/config.php", "extension": "php", "severity": 5},
                {"url": "https://shop.example.ru/logo.png", "extension": "png", "severity": 1},
            ],
            "secrets": {
                "findings": [
                    {
                        "rule": "np.aws.1",
                        "name": "AWS API Key",
                        "value": LEAKED_KEY,
                        "fingerprint": "AKIAIO…9f8e7d6c",
                        "score": 90,
                        "severity": "critical",
                        "line": 12,
                    }
                ],
                "rejected": [],
                "rules_run": 530,
                "rules_available": 539,
            },
            "external_hosts": ["cdn.tracker.net", "static.example.ru"],
            "subdomains": ["api.example.ru", "cdn.example.ru"],
            "info": [
                {"kind": "email", "value": "sales@example.ru", "line": 3},
                {"kind": "html_comment", "value": "build note", "line": 9},
            ],
            "csrf": {"issues": [{"kind": "insecure", "form": "/login", "method": "POST"}]},
        },
        "enrich_counts": {"secrets": 1, "subdomains": 2, "hosts": 2, "csrf_issues": 1},
    }


class TargetEnrichmentIngestTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="enrich", target="shop.example.ru")

    def ingest(self):
        graph_before = OsintGraph.objects.count()
        _ingest_target_result(self.project, {"pages": [enrichment_page()]})
        return graph_before

    def test_secret_is_stored_as_the_complete_credential(self):
        self.ingest()
        secret = ProjectSecret.objects.get(project=self.project)
        self.assertEqual(secret.key_name, "np.aws.1")
        self.assertEqual(secret.secret_type, "api_key")
        self.assertEqual(secret.source_url, "https://shop.example.ru/catalog")
        # The crawl found the key; a truncated fingerprint would make the operator
        # go and find it again, so the row carries what was actually on the page.
        self.assertEqual(secret.value_ref, LEAKED_KEY)
        self.assertNotIn("…", secret.value_ref)

    def test_a_finding_without_a_value_falls_back_to_its_fingerprint(self):
        page = enrichment_page()
        page["enrich"]["secrets"]["findings"][0].pop("value")
        _ingest_target_result(self.project, {"pages": [page]})
        self.assertEqual(ProjectSecret.objects.get(project=self.project).value_ref, "AKIAIO…9f8e7d6c")

    def test_the_full_credential_reaches_every_project_surface(self):
        self.ingest()
        secret = ProjectSecret.objects.get(project=self.project)
        self.assertIn(LEAKED_KEY, secret.value_ref)
        # The report the operator reads is built from the same rows.
        summary = ProjectContextBuilder(self.project.id).build_summary_markdown()
        self.assertIn(f"value={LEAKED_KEY}", summary)
        # ...and so is the bundle a Project exports.
        bundle = export_bundle(self.project)
        self.assertEqual(bundle["secret_references"][0]["value_ref"], LEAKED_KEY)

    def test_low_severity_secret_is_a_leak_not_an_api_key(self):
        page = enrichment_page()
        page["enrich"]["secrets"]["findings"][0]["severity"] = "low"
        _ingest_target_result(self.project, {"pages": [page]})
        self.assertEqual(ProjectSecret.objects.get(project=self.project).secret_type, "leak")

    def test_subdomains_and_external_hosts_use_the_schema_own_types(self):
        self.ingest()
        subdomains = set(
            OsintEntity.objects.filter(project=self.project, entity_type="subdomain").values_list("identity", flat=True)
        )
        self.assertEqual(subdomains, {"api.example.ru", "cdn.example.ru"})
        external = {
            entity.identity: (entity.properties or {}).get("kind")
            for entity in OsintEntity.objects.filter(project=self.project, entity_type="domain")
        }
        self.assertEqual(external.get("cdn.tracker.net"), "external")
        self.assertEqual(external.get("static.example.ru"), "external")

    def test_email_becomes_an_entity_and_other_info_does_not(self):
        self.ingest()
        addresses = list(
            OsintEntity.objects.filter(project=self.project, entity_type="email").values_list("identity", flat=True)
        )
        self.assertEqual(addresses, ["sales@example.ru"])
        self.assertFalse(
            OsintEntity.objects.filter(project=self.project, entity_type="html_comment").exists()
        )

    def test_ranked_file_is_registered_as_an_endpoint(self):
        self.ingest()
        paths = set(ProjectEndpoint.objects.filter(project=self.project).values_list("path", flat=True))
        self.assertIn("/admin/config.php", paths)

    def test_file_severity_never_enters_the_status_column(self):
        # `ProjectEndpoint.statuses` holds HTTP status codes. Writing a 1..7
        # extension rank into it would make "which status codes does this
        # endpoint return" answer with the file ranking; the first version of the
        # ingest did exactly that.
        self.ingest()
        endpoint = ProjectEndpoint.objects.get(project=self.project, path="/admin/config.php")
        self.assertEqual(endpoint.statuses, [])
        entity = OsintEntity.objects.get(project=self.project, identity="https://shop.example.ru/admin/config.php")
        self.assertEqual(entity.properties.get("file_severity"), 5)

    def test_no_second_record_of_the_secret_is_created(self):
        """`ProjectSecret` is the only place a crawled secret is recorded.

        The graph has no `secret` entity type, and writing one would have meant a
        second copy of the same fact in two places that answer different queries.
        """
        self.ingest()
        self.assertFalse(OsintEntity.objects.filter(project=self.project, entity_type="secret").exists())
        self.assertEqual(ProjectSecret.objects.filter(project=self.project).count(), 1)

    def test_ingest_is_idempotent(self):
        """A second poll of the same snapshot must not duplicate a row."""
        self.ingest()
        first = ProjectSecret.objects.get(project=self.project)
        _ingest_target_result(self.project, {"pages": [enrichment_page()]})
        self.assertEqual(ProjectSecret.objects.filter(project=self.project).count(), 1)
        self.assertEqual(ProjectSecret.objects.get(project=self.project).id, first.id)

    def test_page_without_enrichment_is_unchanged(self):
        _ingest_target_result(self.project, {"pages": [{"url": "https://shop.example.ru/", "status": 200}]})
        self.assertFalse(ProjectSecret.objects.filter(project=self.project).exists())
        self.assertTrue(ProjectEndpoint.objects.filter(project=self.project, path="/").exists())

    def test_finding_without_a_rule_id_is_skipped(self):
        page = enrichment_page()
        page["enrich"]["secrets"]["findings"] = [{"name": "nameless", "fingerprint": "x…y"}]
        _ingest_target_result(self.project, {"pages": [page]})
        self.assertFalse(ProjectSecret.objects.filter(project=self.project).exists())

    def test_graph_is_written_once_for_the_batch(self):
        before = OsintGraph.objects.count()
        self.ingest()
        self.assertEqual(OsintGraph.objects.count(), before + 1)
        graph = OsintGraph.objects.filter(project=self.project, version=1).first()
        self.assertIsNotNone(graph)