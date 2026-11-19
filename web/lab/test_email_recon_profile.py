"""The email recon's answer has to survive the trip into the graph.

Measured 2026-10-16. `email_recon` was registered `network: false`, so the page
never asked for confirmation, sent `confirm_network: false`, and the run returned
the local normalization plus a warning that said social-profile verification was
disabled — while the probe that performs it sat unentered in the engine.

Fixing only that would have been a green test and a still-broken feature, because
the rows it produces were refused on the way in: the engine emits
`entity("profile", "GitHub:analyst", …)` and `normalize_entity_identity` answered
`unsupported OSINT entity type: profile`. `OsintEntity.ENTITY_TYPE_CHOICES` had no
such type, so every finding was discarded and the transform reported itself as
having found nothing — the same silence the operator reported, reached by a
different road.

These tests therefore pin the whole chain on the gateway side, which is where the
second half of the defect lived: the engine's own answer is posted at the endpoint
the page actually calls, and it must come back stored, counted and related.
"""

import json
from unittest.mock import patch

from django.test import TestCase

from lab import views
from lab.models import OsintEntity, OsintGraph, OsintRelation, Project, TrafficCaptureContext


class EmailReconProfilePersistenceTests(TestCase):
    """What the page receives back after a confirmed `email_recon`."""

    def setUp(self):
        self.project = Project.objects.create(name="email-recon")
        self.graph = OsintGraph.objects.create(project=self.project, version=1, name="g")
        self.context = TrafficCaptureContext.objects.create(project=self.project, active=True)

    def engine_answer(self):
        """The shape `osintTransforms.go` produces for a confirmed run."""
        return {
            "transform": "email_recon",
            "observed_at": "2026-10-16T00:00:00+00:00",
            "local_only": False,
            "network_used": True,
            "warnings": [],
            "entities": [
                {
                    "type": "email", "identity": "analyst@example.com",
                    "properties": {"local_part": "analyst"},
                    "provenance": {"source": "local_transform"},
                },
                {
                    "type": "domain", "identity": "example.com",
                    "provenance": {"source": "local_transform"},
                },
                {
                    "type": "profile", "identity": "GitHub:analyst",
                    "properties": {"platform": "GitHub", "status": 200,
                                   "profile_url": "https://github.com/analyst"},
                    "provenance": {"source": "social_http_probe"},
                },
            ],
            "relations": [
                {"type": "contains", "source_type": "email", "source": "analyst@example.com",
                 "target_type": "domain", "target": "example.com"},
                {"type": "accounts_for", "source_type": "email", "source": "analyst@example.com",
                 "target_type": "profile", "target": "GitHub:analyst",
                 "properties": {"status": 200}},
            ],
        }

    @patch("lab.views.call_engine")
    def test_a_confirmed_run_stores_the_profile_and_its_relation(self, call_engine):
        call_engine.return_value = (200, self.engine_answer())
        response = self.client.post(
            f"/api/osint/graphs/{self.graph.id}/transform",
            data=json.dumps({
                "transform": "email_recon", "value": "analyst@example.com",
                "confirm_network": True,
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()

        # The confirmation is forwarded, and the run is recorded as a network one.
        self.assertTrue(call_engine.call_args.args[1]["confirm_network"])
        result = body["transform_result"]
        self.assertFalse(result["local_only"])
        self.assertTrue(result["network_used"])

        # All three entities are in the graph. `profile` is the one that used to be
        # refused, and it is the whole answer, so its absence is what the operator
        # saw.
        stored = {(e.entity_type, e.identity) for e in OsintEntity.objects.filter(graph=self.graph)}
        self.assertIn(("profile", "GitHub:analyst"), stored)
        self.assertIn(("email", "analyst@example.com"), stored)
        self.assertIn(("domain", "example.com"), stored)

        # The status is the evidence: a platform that answered 200 is reported with
        # the status it gave, not as a confirmed ownership.
        profile = OsintEntity.objects.get(graph=self.graph, entity_type="profile")
        self.assertEqual(profile.properties["status"], 200)
        self.assertEqual(profile.properties["platform"], "GitHub")

        # The relation is what makes it usable — the address accounts for the
        # profile, so the analyst can pivot from the address to the account.
        relations = {
            (r.relation_type,
             f"{r.source_entity.entity_type}:{r.source_entity.identity}",
             f"{r.target_entity.entity_type}:{r.target_entity.identity}",
             r.properties.get("status"))
            for r in OsintRelation.objects.filter(graph=self.graph).select_related("source_entity", "target_entity")
        }
        self.assertIn(("accounts_for", "email:analyst@example.com", "profile:GitHub:analyst", 200), relations)
        self.assertIn(("contains", "email:analyst@example.com", "domain:example.com", None), relations)

        # Nothing was dropped on the way in, so nothing is reported as rejected.
        self.assertEqual(result["rejected_count"], 0)

    @patch("lab.views.call_engine")
    def test_the_entity_type_is_declared_not_accidentally_present(self, call_engine):
        """`profile` is a stated type, not a value that slipped past validation."""
        types = {value for value, _ in OsintEntity.ENTITY_TYPE_CHOICES}
        self.assertIn("profile", types)
        # It is emitted by a transform, never accepted as an input: there is no
        # "search for profiles" transform, and offering one would be a dead control.
        self.assertNotIn("profile", views._OSINT_NETWORK_TRANSFORMS)

    @patch("lab.views.call_engine")
    def test_an_unconfirmed_run_is_refused_before_the_engine_is_reached(self, call_engine):
        """The gateway refuses it the same way the engine does.

        Two gates exist and they must agree: `_OSINT_NETWORK_TRANSFORMS` here and
        `transformIsNetwork` in the engine. The second is what actually stopped the
        probe, because the page asks its question from the registry and sends
        `confirm_network` from the same value.
        """
        response = self.client.post(
            f"/api/osint/graphs/{self.graph.id}/transform",
            data=json.dumps({"transform": "email_recon", "value": "analyst@example.com"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "NETWORK_CONFIRMATION_REQUIRED")
        call_engine.assert_not_called()

    def test_email_recon_is_in_the_gateways_network_set(self):
        """The gateway's set is a second copy of the registry's `network` flag.

        It exists to refuse before the engine is called, so an entry that is
        missing from it is a transform the page cannot run at all — the run would
        be forwarded and then rejected by the engine with the operator already
        waiting on a progress bar.
        """
        self.assertIn("email_recon", views._OSINT_NETWORK_TRANSFORMS)

    @patch("lab.views.call_engine_get")
    def test_the_registry_the_page_reads_reports_it_as_network(self, call_engine_get):
        """The dialog is driven by this flag, so its absence is the whole defect."""
        call_engine_get.return_value = (200, {"items": [
            {"id": "email_recon", "network": True, "accepts": ["email"]},
            {"id": "email_domain", "network": False, "accepts": ["email"]},
        ]})
        response = self.client.get("/api/osint/transforms")
        self.assertEqual(response.status_code, 200)
        by_id = {item["id"]: item for item in response.json()["items"]}
        self.assertTrue(by_id["email_recon"]["network"])
        # The local transform is still there for the operator who wants only the
        # normalization and no requests.
        self.assertFalse(by_id["email_domain"]["network"])