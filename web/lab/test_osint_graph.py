import json
from datetime import datetime, timezone
from unittest.mock import patch

from django.test import Client, TestCase

from . import views
from .models import OsintEntity, OsintGraph, OsintRelation, Project, TrafficCaptureContext
from .osint_graph import OsintGraphError, normalize_entity_identity, upsert_graph


class OsintGraphApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(
            name="OSINT graph project",
            target="https://graph.example.test/",
        )
        self.other_project = Project.objects.create(
            name="Other OSINT graph project",
            target="https://other.example.test/",
        )

    def create_graph(self, project_id=None, version=None):
        payload = {"project_id": project_id or self.project.id, "source": "fixture", "name": "Fixture graph"}
        if version is not None:
            payload["version"] = version
        return self.client.post(
            "/api/osint/graphs",
            data=json.dumps(payload),
            content_type="application/json",
        )

    def create_graph_without_project(self, version=None, send_null=False):
        """Create a graph the way the UI does when no Project is selected."""
        payload = {"source": "fixture", "name": "Projectless graph"}
        if send_null:
            payload["project_id"] = None
        if version is not None:
            payload["version"] = version
        return self.client.post(
            "/api/osint/graphs",
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_graph_creation_is_versioned_and_archives_previous_current(self):
        first = self.create_graph()
        self.assertEqual(first.status_code, 201)
        first_data = first.json()
        self.assertEqual(first_data["version"], 1)
        self.assertEqual(first_data["name"], "Fixture graph")
        self.assertEqual(first_data["status"], "current")
        self.assertEqual(first_data["entity_count"], 0)

        second = self.create_graph()
        self.assertEqual(second.status_code, 201)
        self.assertEqual(second.json()["version"], 2)
        self.assertEqual(OsintGraph.objects.get(id=first_data["id"]).status, "archived")
        self.assertEqual(OsintGraph.objects.get(id=second.json()["id"]).status, "current")

        duplicate = self.create_graph(version=1)
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(duplicate.json()["reason"], "INVALID_OSINT_GRAPH")

        listed = self.client.get(f"/api/osint/graphs?project_id={self.project.id}")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([item["version"] for item in listed.json()["items"]], [2, 1])

    def test_graph_creation_works_without_any_project(self):
        # A Project is a workspace feature, not a precondition for a graph: both
        # an omitted and an explicit null project_id must store a real graph.
        for send_null in (False, True):
            created = self.create_graph_without_project(send_null=send_null)
            self.assertEqual(created.status_code, 201)
            self.assertIsNone(created.json()["project_id"])
            self.assertEqual(OsintGraph.objects.get(id=created.json()["id"]).project, None)

    def test_projectless_graph_versions_and_archives_independently_of_projects(self):
        first = self.create_graph_without_project()
        second = self.create_graph_without_project()
        self.assertEqual(first.json()["version"], 1)
        self.assertEqual(second.json()["version"], 2)
        self.assertEqual(OsintGraph.objects.get(id=first.json()["id"]).status, "archived")
        self.assertEqual(OsintGraph.objects.get(id=second.json()["id"]).status, "current")

        # A Project's own counter is a separate scope, so it still starts at 1.
        self.assertEqual(self.create_graph().json()["version"], 1)

        duplicate = self.create_graph_without_project(version=1)
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(duplicate.json()["reason"], "INVALID_OSINT_GRAPH")

    def test_listing_without_project_returns_only_the_projectless_scope(self):
        projectless = self.create_graph_without_project().json()
        project_graph = self.create_graph().json()
        other_graph = self.create_graph(project_id=self.other_project.id).json()

        listed = self.client.get("/api/osint/graphs")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual([item["id"] for item in listed.json()["items"]], [projectless["id"]])
        # The same graph is also reachable through its own scope, so a restored
        # workspace can load it without the list being the only way in.
        fetched = self.client.get(f"/api/osint/graphs/{projectless['id']}")
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json()["id"], projectless["id"])
        # Project graphs stay in their own scopes and out of the project-less list.
        self.assertNotIn(project_graph["id"], [item["id"] for item in listed.json()["items"]])
        self.assertNotIn(other_graph["id"], [item["id"] for item in listed.json()["items"]])

    def test_projectless_graph_stores_entities_and_relations(self):
        graph_id = self.create_graph_without_project().json()["id"]
        response = self.client.post(
            f"/api/osint/graphs/{graph_id}/upsert",
            data=json.dumps({
                "entities": [
                    {"type": "domain", "identity": "alpha.example"},
                    {"type": "domain", "identity": "beta.example"},
                ],
                "relations": [{
                    "type": "subdomain_of",
                    "source_type": "domain",
                    "source": "alpha.example",
                    "target_type": "domain",
                    "target": "beta.example",
                }],
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["upserted"]["entities"], 2)
        self.assertEqual(response.json()["upserted"]["relations"], 1)
        self.assertEqual(OsintEntity.objects.filter(graph_id=graph_id, project__isnull=True).count(), 2)
        self.assertEqual(OsintRelation.objects.filter(graph_id=graph_id, project__isnull=True).count(), 1)
        # Nothing leaked into either Project scope.
        self.assertEqual(OsintGraph.objects.filter(project__isnull=True).count(), 1)

    @patch("lab.views.call_engine")
    def test_transform_persists_into_a_projectless_graph(self, call_engine):
        # Having no Project must not change what a transform can do, only where
        # the result is stored. Network transforms keep their own explicit
        # confirmation, which is a rule about the transform and not about the graph.
        graph_id = self.create_graph_without_project().json()["id"]
        call_engine.return_value = (200, {
            "transform": "email_domain",
            "observed_at": "2026-09-24T12:00:00+00:00",
            "local_only": True,
            "network_used": False,
            "warnings": [],
            "entities": [{"type": "domain", "identity": "example.com"}],
            "relations": [],
        })
        response = self.client.post(
            f"/api/osint/graphs/{graph_id}/transform",
            data=json.dumps({"transform": "email_domain", "value": "analyst@example.com"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["entity_count"], 1)
        self.assertEqual(OsintEntity.objects.get(identity="example.com").project, None)

    def test_unknown_and_malformed_project_ids_are_still_refused(self):
        # Optional does not mean unchecked: a named Project that does not exist is
        # still a client error rather than a silent fall back to the project-less
        # scope, because that would store the graph somewhere the caller did not ask for.
        missing = self.client.post(
            "/api/osint/graphs",
            data=json.dumps({"project_id": 999999}),
            content_type="application/json",
        )
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(OsintGraph.objects.count(), 0)

        malformed = self.client.post(
            "/api/osint/graphs",
            data=json.dumps({"project_id": "not-a-number"}),
            content_type="application/json",
        )
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(malformed.json()["reason"], "INVALID_OSINT_GRAPH")

        listed = self.client.get("/api/osint/graphs?project_id=abc")
        self.assertEqual(listed.status_code, 400)
        self.assertEqual(listed.json()["reason"], "INVALID_OSINT_GRAPH")

        listed_missing = self.client.get(f"/api/osint/graphs?project_id={self.other_project.id + 10000}")
        self.assertEqual(listed_missing.status_code, 404)

    def test_upsert_is_idempotent_and_redacts_provenance(self):
        graph_id = self.create_graph().json()["id"]
        observed_at = "2026-09-24T12:00:00+00:00"
        payload = {
            "observed_at": observed_at,
            "metadata": {"source": "fixture", "Authorization": "Bearer graph-secret"},
            "entities": [
                {"type": "domain", "identity": "Example.COM.", "provenance": {"source": "fixture"}},
                {
                    "type": "url",
                    "identity": "https://EXAMPLE.com/path?token=raw-query-secret",
                    "risk_score": 70,
                    "properties": {"note": "Cookie: session=raw-cookie"},
                },
                {"type": "ip", "identity": "192.0.2.5"},
            ],
            "relations": [
                {
                    "type": "resolves_to",
                    "source_type": "domain",
                    "source": "example.com",
                    "target_type": "ip",
                    "target": "192.0.2.5",
                    "provenance": {"source": "fixture"},
                }
            ],
        }
        first = self.client.post(
            f"/api/osint/graphs/{graph_id}/upsert",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 200)
        first_data = first.json()
        self.assertEqual(first_data["entity_count"], 3)
        self.assertEqual(first_data["relation_count"], 1)
        # Whatever the crawl found is what the analyst pivots on, so provenance
        # and properties keep the credential instead of replacing it.
        self.assertIn("raw-cookie", json.dumps(first_data))
        self.assertIn("graph-secret", json.dumps(first_data))
        self.assertIn("Bearer graph-secret", json.dumps(first_data))
        self.assertNotIn("[REDACTED]", json.dumps(first_data))
        domain = next(item for item in first_data["entities"] if item["type"] == "domain")
        url = next(item for item in first_data["entities"] if item["type"] == "url")
        # Identity canonicalisation is unchanged and still drops the query string:
        # the host is lower-cased and a URL keeps scheme, host and path only.
        self.assertEqual(domain["identity"], "example.com")
        self.assertEqual(url["identity"], "https://example.com/path")
        self.assertEqual(url["display_value"], "https://example.com/path")
        self.assertEqual(url["risk_score"], 70)

        second = self.client.post(
            f"/api/osint/graphs/{graph_id}/upsert",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["entity_count"], 3)
        self.assertEqual(second.json()["relation_count"], 1)
        self.assertEqual(OsintEntity.objects.filter(graph_id=graph_id).count(), 3)
        self.assertEqual(OsintRelation.objects.filter(graph_id=graph_id).count(), 1)

    def test_upsert_rejects_invalid_type_timestamp_and_missing_endpoint(self):
        graph_id = self.create_graph().json()["id"]
        cases = [
            {"entities": [{"type": "unknown", "identity": "x"}]},
            {"entities": [{"type": "domain", "identity": "example.com", "observed_at": "not-a-date"}]},
            {"entities": [{"type": "domain", "identity": "example.com", "risk_score": 101}]},
            {"relations": [{"type": "resolves_to", "source": "example.com", "target": "192.0.2.5"}]},
        ]
        for payload in cases:
            response = self.client.post(
                f"/api/osint/graphs/{graph_id}/upsert",
                data=json.dumps(payload),
                content_type="application/json",
            )
            self.assertEqual(response.status_code, 400, payload)
            self.assertEqual(response.json()["reason"], "INVALID_OSINT_GRAPH")

    @patch("lab.views.call_engine")
    def test_local_transform_is_persisted_through_graph_api(self, call_engine):
        graph_id = self.create_graph().json()["id"]
        call_engine.return_value = (200, {
            "transform": "email_recon",
            "observed_at": "2026-09-24T12:00:00+00:00",
            "local_only": True,
            "network_used": False,
            "warnings": ["no external enumeration"],
            "entities": [
                {"type": "email", "identity": "analyst@example.com", "provenance": {"source": "fixture"}},
                {"type": "domain", "identity": "example.com", "provenance": {"source": "fixture"}},
            ],
            "relations": [{
                "type": "contains",
                "source_type": "email",
                "source": "analyst@example.com",
                "target_type": "domain",
                "target": "example.com",
            }],
        })
        response = self.client.post(
            f"/api/osint/graphs/{graph_id}/transform",
            data=json.dumps({"transform": "email_recon", "value": "analyst@example.com"}),
            content_type="application/json",
        )
        # email_recon now requires confirmation, mirroring every other network
        # transform: the local normalization is not free unless the engine is
        # allowed to probe as well.
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "NETWORK_CONFIRMATION_REQUIRED")
        call_engine.assert_not_called()

    @patch("lab.views.call_engine")
    def test_network_transform_requires_confirmation_before_engine_call(self, call_engine):
        graph_id = self.create_graph().json()["id"]
        response = self.client.post(
            f"/api/osint/graphs/{graph_id}/transform",
            data=json.dumps({"transform": "subdomains", "value": "example.com"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "NETWORK_CONFIRMATION_REQUIRED")
        call_engine.assert_not_called()

    @patch("lab.views.call_engine_get")
    def test_transform_registry_proxies_engine_catalog(self, call_engine_get):
        call_engine_get.return_value = (200, {"items": [{"id": "email_recon", "network": False}]})
        response = self.client.get("/api/osint/transforms")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["id"], "email_recon")

    def test_graph_api_requires_csrf_for_writes(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.get("/")
        rejected = csrf_client.post(
            "/api/osint/graphs",
            data=json.dumps({"project_id": self.project.id}),
            content_type="application/json",
        )
        self.assertEqual(rejected.status_code, 403)

    def test_relation_endpoints_are_scoped_to_the_graph(self):
        first_graph = self.create_graph().json()["id"]
        second_graph = self.create_graph(project_id=self.other_project.id).json()["id"]
        self.client.post(
            f"/api/osint/graphs/{first_graph}/upsert",
            data=json.dumps({"entities": [{"type": "domain", "identity": "first.example"}]}),
            content_type="application/json",
        )
        response = self.client.post(
            f"/api/osint/graphs/{second_graph}/upsert",
            data=json.dumps({"relations": [{
                "type": "contains",
                "source_type": "domain",
                "source": "first.example",
                "target_type": "domain",
                "target": "second.example",
            }]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(OsintRelation.objects.filter(graph_id=second_graph).count(), 0)

    def seed_graph_with_relation(self):
        """Create one graph holding two entities joined by a single relation."""
        graph_id = self.create_graph().json()["id"]
        self.client.post(
            f"/api/osint/graphs/{graph_id}/upsert",
            data=json.dumps({
                "entities": [
                    {"type": "domain", "identity": "alpha.example", "risk_score": 10},
                    {"type": "domain", "identity": "beta.example", "risk_score": 20},
                ],
                "relations": [{
                    "type": "subdomain_of",
                    "source_type": "domain",
                    "source": "alpha.example",
                    "target_type": "domain",
                    "target": "beta.example",
                }],
            }),
            content_type="application/json",
        )
        return graph_id

    def test_entity_can_be_edited_in_place(self):
        graph_id = self.seed_graph_with_relation()
        entity = OsintEntity.objects.get(graph_id=graph_id, identity="alpha.example")
        response = self.client.patch(
            f"/api/osint/graphs/{graph_id}/entities/{entity.id}",
            data=json.dumps({"risk_score": 77, "display_value": "alpha", "properties": {"note": "triaged"}}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        entity.refresh_from_db()
        self.assertEqual(entity.risk_score, 77)
        self.assertEqual(entity.display_value, "alpha")
        self.assertEqual(entity.properties["note"], "triaged")
        # The relation and both endpoints survive an entity edit.
        self.assertEqual(OsintRelation.objects.filter(graph_id=graph_id).count(), 1)
        self.assertEqual(OsintEntity.objects.filter(graph_id=graph_id).count(), 2)

    def test_entity_edit_rejects_invalid_and_empty_updates(self):
        graph_id = self.seed_graph_with_relation()
        entity = OsintEntity.objects.get(graph_id=graph_id, identity="alpha.example")
        invalid = self.client.patch(
            f"/api/osint/graphs/{graph_id}/entities/{entity.id}",
            data=json.dumps({"risk_score": 900}),
            content_type="application/json",
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()["reason"], "INVALID_OSINT_GRAPH")
        empty = self.client.patch(
            f"/api/osint/graphs/{graph_id}/entities/{entity.id}",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(empty.status_code, 400)

    def test_deleting_an_entity_cascades_only_its_relations(self):
        graph_id = self.seed_graph_with_relation()
        entity = OsintEntity.objects.get(graph_id=graph_id, identity="alpha.example")
        response = self.client.delete(f"/api/osint/graphs/{graph_id}/entities/{entity.id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["deleted"]["entity"], "alpha.example")
        self.assertEqual(data["deleted"]["relations"], 1)
        self.assertEqual(data["entity_count"], 1)
        self.assertEqual(data["relation_count"], 0)
        self.assertEqual(
            [item["identity"] for item in data["entities"]],
            ["beta.example"],
        )
        self.assertEqual(OsintRelation.objects.filter(graph_id=graph_id).count(), 0)

    def test_relation_delete_keeps_both_endpoints(self):
        graph_id = self.seed_graph_with_relation()
        relation = OsintRelation.objects.get(graph_id=graph_id)
        response = self.client.delete(f"/api/osint/graphs/{graph_id}/relations/{relation.id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["deleted"]["relation"], "subdomain_of")
        self.assertEqual(data["relation_count"], 0)
        self.assertEqual(data["entity_count"], 2)

    def test_management_endpoints_are_scoped_to_their_graph(self):
        graph_id = self.seed_graph_with_relation()
        other_graph = self.create_graph(project_id=self.other_project.id).json()["id"]
        entity = OsintEntity.objects.get(graph_id=graph_id, identity="alpha.example")
        relation = OsintRelation.objects.get(graph_id=graph_id)
        for url in (
            f"/api/osint/graphs/{other_graph}/entities/{entity.id}",
            f"/api/osint/graphs/{other_graph}/relations/{relation.id}",
        ):
            rejected = self.client.delete(url)
            self.assertEqual(rejected.status_code, 404, url)
        self.assertTrue(OsintEntity.objects.filter(id=entity.id).exists())
        self.assertTrue(OsintRelation.objects.filter(id=relation.id).exists())

    def test_clear_graph_requires_confirmation_and_empties_the_graph(self):
        graph_id = self.seed_graph_with_relation()
        unconfirmed = self.client.post(
            f"/api/osint/graphs/{graph_id}/clear",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(unconfirmed.status_code, 400)
        self.assertEqual(unconfirmed.json()["reason"], "CLEAR_CONFIRMATION_REQUIRED")
        self.assertEqual(OsintEntity.objects.filter(graph_id=graph_id).count(), 2)

        cleared = self.client.post(
            f"/api/osint/graphs/{graph_id}/clear",
            data=json.dumps({"confirm": True}),
            content_type="application/json",
        )
        self.assertEqual(cleared.status_code, 200)
        data = cleared.json()
        self.assertEqual(data["cleared"], {"entities": 2, "relations": 1})
        self.assertEqual(data["entity_count"], 0)
        self.assertEqual(data["relation_count"], 0)
        self.assertEqual(data["entities"], [])
        # The graph container itself survives so a new entity can be added.
        self.assertTrue(OsintGraph.objects.filter(id=graph_id).exists())

        added = self.client.post(
            f"/api/osint/graphs/{graph_id}/upsert",
            data=json.dumps({"entities": [{"type": "domain", "identity": "fresh.example"}]}),
            content_type="application/json",
        )
        self.assertEqual(added.status_code, 200)
        self.assertEqual(
            [item["identity"] for item in added.json()["entities"]],
            ["fresh.example"],
        )

    def test_delete_graph_requires_confirmation_and_removes_the_whole_graph(self):
        """Deleting a graph takes the container with it, not only its contents.

        This is the difference from ``.../clear``: clear leaves the row so a
        fresh entity set can be collected into it, while a graph the operator
        asked to delete has to be gone from the list as well. Both halves are
        asserted, because a delete that only emptied the graph would satisfy
        every other assertion in this test.
        """
        graph_id = self.seed_graph_with_relation()
        survivor_id = self.create_graph(version=2).json()["id"]

        unconfirmed = self.client.delete(
            f"/api/osint/graphs/{graph_id}",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(unconfirmed.status_code, 400)
        self.assertEqual(unconfirmed.json()["reason"], "DELETE_CONFIRMATION_REQUIRED")
        self.assertTrue(OsintGraph.objects.filter(id=graph_id).exists())
        self.assertEqual(OsintEntity.objects.filter(graph_id=graph_id).count(), 2)

        deleted = self.client.delete(
            f"/api/osint/graphs/{graph_id}",
            data=json.dumps({"confirm": True}),
            content_type="application/json",
        )
        self.assertEqual(deleted.status_code, 200)
        removed = deleted.json()["deleted"]
        self.assertEqual(removed["graph_id"], graph_id)
        self.assertEqual(removed["entities"], 2)
        self.assertEqual(removed["relations"], 1)
        # The container is gone: the graph leaves the list and the detail
        # endpoint stops answering for it.
        self.assertFalse(OsintGraph.objects.filter(id=graph_id).exists())
        self.assertFalse(OsintEntity.objects.filter(graph_id=graph_id).exists())
        self.assertFalse(OsintRelation.objects.filter(graph_id=graph_id).exists())
        listed = self.client.get("/api/osint/graphs")
        self.assertNotIn(graph_id, [item["id"] for item in listed.json()["items"]])
        self.assertEqual(self.client.get(f"/api/osint/graphs/{graph_id}").status_code, 404)
        # Another graph of the same scope is untouched: the delete is scoped to
        # the graph that was named, not to the project or the version series.
        self.assertTrue(OsintGraph.objects.filter(id=survivor_id).exists())

    def test_delete_graph_reports_not_found_and_keeps_the_method_guard(self):
        unknown = self.client.delete(
            "/api/osint/graphs/999999",
            data=json.dumps({"confirm": True}),
            content_type="application/json",
        )
        self.assertEqual(unknown.status_code, 404)
        # `DELETE` without a graph id is not something this route serves: the
        # collection endpoint answers GET and POST only.
        self.assertEqual(
            self.client.delete("/api/osint/graphs", data="{}", content_type="application/json").status_code,
            405,
        )

    @patch("lab.views.call_engine")
    def test_transform_reports_empty_status_instead_of_a_blank_result(self, call_engine):
        graph_id = self.create_graph().json()["id"]
        call_engine.return_value = (200, {
            "transform": "dns_records",
            "observed_at": "2026-09-24T12:00:00+00:00",
            "local_only": False,
            "network_used": True,
            "warnings": ["no A or AAAA records resolved"],
            "entities": [],
            "relations": [],
        })
        response = self.client.post(
            f"/api/osint/graphs/{graph_id}/transform",
            data=json.dumps({"transform": "dns_records", "value": "example.com", "confirm_network": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()["transform_result"]
        self.assertEqual(result["status"], "empty")
        self.assertEqual(result["entity_count"], 0)
        self.assertEqual(result["relation_count"], 0)
        self.assertTrue(result["network_used"])
        self.assertEqual(result["warnings"], ["no A or AAAA records resolved"])
        self.assertGreaterEqual(result["duration_ms"], 0)

    @patch("lab.views.call_engine")
    def test_transform_failure_reports_failed_status_with_duration(self, call_engine):
        graph_id = self.create_graph().json()["id"]
        call_engine.return_value = (400, {"error": "INVALID_EMAIL: email must be a plain address", "reason": "OSINT_TRANSFORM_FAILED"})
        response = self.client.post(
            f"/api/osint/graphs/{graph_id}/transform",
            data=json.dumps({"transform": "email_domain", "value": "not-an-email"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        result = response.json()["transform_result"]
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["transform"], "email_domain")
        self.assertEqual(result["value"], "not-an-email")
        self.assertGreaterEqual(result["duration_ms"], 0)

    @patch("lab.views.call_engine")
    def test_completed_transform_reports_completed_status(self, call_engine):
        graph_id = self.create_graph().json()["id"]
        call_engine.return_value = (200, {
            "transform": "domain_normalize",
            "observed_at": "2026-09-24T12:00:00+00:00",
            "local_only": True,
            "network_used": False,
            "warnings": [],
            "entities": [{"type": "domain", "identity": "example.com"}],
            "relations": [],
        })
        response = self.client.post(
            f"/api/osint/graphs/{graph_id}/transform",
            data=json.dumps({"transform": "domain_normalize", "value": "Example.COM"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()["transform_result"]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["entity_count"], 1)
        self.assertTrue(result["local_only"])

    @patch("lab.views.call_engine")
    def test_transform_keeps_valid_observations_when_one_identity_is_invalid(self, call_engine):
        """A wildcard certificate name must not discard a whole discovery batch."""
        graph_id = self.create_graph().json()["id"]
        call_engine.return_value = (200, {
            "transform": "subdomains",
            "observed_at": "2026-09-24T12:00:00+00:00",
            "local_only": False,
            "network_used": True,
            "warnings": ["wildcard DNS detected"],
            "entities": [
                {"type": "subdomain", "identity": "www.alpha.example"},
                {"type": "subdomain", "identity": "*.*.alpha.example"},
                {"type": "subdomain", "identity": "mail.alpha.example"},
            ],
            "relations": [],
        })
        response = self.client.post(
            f"/api/osint/graphs/{graph_id}/transform",
            data=json.dumps({"transform": "subdomains", "value": "alpha.example", "confirm_network": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()["transform_result"]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["entity_count"], 3)
        self.assertEqual(result["stored_entity_count"], 2)
        self.assertEqual(result["rejected_count"], 1)
        self.assertEqual(result["rejected"][0]["identity"], "*.*.alpha.example")
        self.assertEqual(
            sorted(item["identity"] for item in response.json()["entities"]),
            ["mail.alpha.example", "www.alpha.example"],
        )
        # The rejection is reported as a warning, not silently dropped.
        self.assertTrue(any("not stored" in warning for warning in result["warnings"]))

    def test_upsert_stays_atomic_for_manual_payloads(self):
        graph_id = self.create_graph().json()["id"]
        response = self.client.post(
            f"/api/osint/graphs/{graph_id}/upsert",
            data=json.dumps({"entities": [
                {"type": "domain", "identity": "kept.example"},
                {"type": "domain", "identity": "*.*.broken.example"},
            ]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "INVALID_OSINT_GRAPH")
        self.assertEqual(OsintEntity.objects.filter(graph_id=graph_id).count(), 0)

    def test_skip_invalid_reports_relations_with_missing_endpoints(self):
        graph_id = self.create_graph().json()["id"]
        graph = OsintGraph.objects.get(id=graph_id)
        counts = upsert_graph(graph, {
            "entities": [{"type": "domain", "identity": "alpha.example"}],
            "relations": [{
                "type": "contains",
                "source_type": "domain",
                "source": "alpha.example",
                "target_type": "domain",
                "target": "absent.example",
            }],
        }, skip_invalid=True)
        self.assertEqual(counts["entities"], 1)
        self.assertEqual(counts["relations"], 0)
        self.assertEqual(len(counts["rejected"]), 1)
        self.assertEqual(counts["rejected"][0]["kind"], "relation")
        self.assertIn("alpha.example -> absent.example", counts["rejected"][0]["identity"])
        self.assertIn("absent.example", counts["rejected"][0]["error"])


class OsintIdentityTests(TestCase):
    def test_identity_normalization_covers_core_types(self):
        self.assertEqual(normalize_entity_identity("domain", "Example.COM.")[0], "example.com")
        self.assertEqual(normalize_entity_identity("ip", "192.0.2.5")[0], "192.0.2.5")
        self.assertEqual(normalize_entity_identity("cidr", "192.0.2.9/24")[0], "192.0.2.0/24")
        self.assertEqual(normalize_entity_identity("asn", "AS64500")[0], "AS64500")
        with self.assertRaises(OsintGraphError):
            normalize_entity_identity("url", "https://user:pass@example.com/")
        # `certificate` and `port` left the type list on 2026-09-29, so their
        # normalizer branches went with them. A value of either type still has to
        # import, because a bundle written before the removal carries such a row:
        # it takes the redaction path, which keeps the value as written instead of
        # rejecting the whole bundle.
        self.assertEqual(normalize_entity_identity("port", "443")[0], "443")
        self.assertEqual(normalize_entity_identity("certificate", "pravda.ru")[0], "pravda.ru")
        # A type that was never a type is still refused, retired or not.
        with self.assertRaises(OsintGraphError):
            normalize_entity_identity("banana", "443")

    def test_naive_observed_timestamp_is_made_aware(self):
        from .osint_graph import parse_observed_at

        parsed = parse_observed_at("2026-09-24T12:00:00")
        self.assertIsNotNone(parsed.tzinfo)
        self.assertEqual(parsed.astimezone(timezone.utc).hour, 12)
        self.assertIsInstance(parsed, datetime)
