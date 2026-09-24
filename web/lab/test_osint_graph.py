import json
from datetime import datetime, timezone
from unittest.mock import patch

from django.test import Client, TestCase

from .models import OsintEntity, OsintGraph, OsintRelation, Project
from .osint_graph import OsintGraphError, normalize_entity_identity


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
        self.assertNotIn("raw-query-secret", json.dumps(first_data))
        self.assertNotIn("raw-cookie", json.dumps(first_data))
        self.assertNotIn("graph-secret", json.dumps(first_data))
        self.assertIn("Bearer [REDACTED]", json.dumps(first_data))
        domain = next(item for item in first_data["entities"] if item["type"] == "domain")
        url = next(item for item in first_data["entities"] if item["type"] == "url")
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
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["entity_count"], 2)
        self.assertEqual(data["relation_count"], 1)
        self.assertFalse(data["transform_result"]["network_used"])
        call_engine.assert_called_once_with("/proxy/osint/transform", {
            "transform": "email_recon",
            "value": "analyst@example.com",
            "options": {},
            "confirm_network": False,
        })

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


class OsintIdentityTests(TestCase):
    def test_identity_normalization_covers_core_types(self):
        self.assertEqual(normalize_entity_identity("domain", "Example.COM.")[0], "example.com")
        self.assertEqual(normalize_entity_identity("ip", "192.0.2.5")[0], "192.0.2.5")
        self.assertEqual(normalize_entity_identity("cidr", "192.0.2.9/24")[0], "192.0.2.0/24")
        self.assertEqual(normalize_entity_identity("port", "443")[0], "443")
        self.assertEqual(normalize_entity_identity("asn", "AS64500")[0], "AS64500")
        with self.assertRaises(OsintGraphError):
            normalize_entity_identity("url", "https://user:pass@example.com/")
        with self.assertRaises(OsintGraphError):
            normalize_entity_identity("port", "70000")

    def test_naive_observed_timestamp_is_made_aware(self):
        from .osint_graph import parse_observed_at

        parsed = parse_observed_at("2026-09-24T12:00:00")
        self.assertIsNotNone(parsed.tzinfo)
        self.assertEqual(parsed.astimezone(timezone.utc).hour, 12)
        self.assertIsInstance(parsed, datetime)
