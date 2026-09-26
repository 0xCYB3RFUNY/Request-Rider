"""Round-trip and failure-mode tests for the Project bundle transfer.

The bundle is the only export in the product that a *different* installation
consumes, so the properties under test are the ones a hand-off depends on: the
evidence survives intact, the relationships survive without depending on the
exporting database's row numbers, and nothing collides when the same bundle is
imported twice or next to a workspace that already holds the same name.
"""

import json

from django.test import Client, TestCase
from django.utils import timezone

from .models import (
    IntruderAttack,
    OsintEntity,
    OsintGraph,
    OsintRelation,
    Project,
    ProjectEndpoint,
    ProjectSecret,
    ScannerRun,
    TargetJob,
    TrafficCaptureContext,
    TrafficRecord,
    Workflow,
    WorkflowRun,
)
from .project_transfer import PROJECT_BUNDLE_SCHEMA, export_bundle, import_bundle, parse_bundle_body


def build_project(name="Transfer source"):
    """Create a Project holding one of every record type the bundle carries."""
    # Writing the TrafficRecord below runs the knowledge-base ingestor, which
    # registers GET /api/items of its own accord. The explicit endpoint is the
    # POST variant, so the finished workspace holds two, both exported.
    project = Project.objects.create(
        name=name,
        target="https://fixture.test/",
        environment="staging",
        route_profile="direct",
        tech_stack={"frontend": ["nginx"], "database": ["postgres"]},
        notes="Workspace notes that must survive the transfer.",
        metadata={"case": "RR-1"},
    )
    context = TrafficCaptureContext.objects.create(project=project, name="Browser capture")
    endpoint = ProjectEndpoint.objects.create(
        project=project,
        method="POST",
        path="/api/items",
        sample_url="https://fixture.test/api/items?id=7",
        statuses=[200, 500],
        parameters=["id", "page"],
    )
    ProjectSecret.objects.create(
        project=project,
        secret_type="api_key",
        key_name="X-Api-Key",
        value_ref="vault://services/fixture#key",
        source_url="https://fixture.test/admin",
    )
    ScannerRun.objects.create(
        project=project,
        engine="nuclei",
        url="https://fixture.test/",
        summary={"findings_count": 1, "highest_severity": "HIGH"},
        findings=[{"title": "Probe issue", "severity": "HIGH", "evidence": "e"}],
    )
    TargetJob.objects.create(
        project=project,
        capture_context=context,
        job_id="target-original",
        engine_kind="static",
        url="https://fixture.test/",
        status="completed",
        result={"pages": [{"url": "https://fixture.test/", "status": 200}]},
        ingested=True,
    )
    workflow = Workflow.objects.create(
        project=project,
        name="Nightly sweep",
        description="Sweep the fixture host",
        nodes=[{"id": "n1", "type": "output"}],
        connections=[],
        settings={"retries": 1},
        schedule="0 3 * * *",
        active=True,
        webhook_slug="nightly-sweep",
    )
    WorkflowRun.objects.create(
        workflow=workflow,
        project=project,
        status="completed",
        mode="schedule",
        output_data={"pages": 3},
    )
    graph = OsintGraph.objects.create(project=project, name="Graph snapshot", source="osint")
    apex = OsintEntity.objects.create(
        project=project, graph=graph, entity_type="domain", identity="fixture.test", risk_score=10
    )
    host = OsintEntity.objects.create(
        project=project, graph=graph, entity_type="subdomain", identity="api.fixture.test"
    )
    OsintRelation.objects.create(
        project=project,
        graph=graph,
        relation_type="subdomain_of",
        source_entity=host,
        target_entity=apex,
    )
    IntruderAttack.objects.create(
        project=project,
        name="Saved sweep",
        attack_type="sniper",
        base_request={"method": "GET", "url": "https://fixture.test/api/items"},
        payloads=["1", "2"],
        transformations=[{"operation": "urlEncode"}],
        delay_ms=25,
        concurrency=2,
    )
    TrafficRecord.objects.create(
        project=project,
        source="intruder",
        host="fixture.test",
        source_ip="203.0.113.10",
        proxy_event_id=3,
        proxy_session=77,
        capture_context=context,
        scope_status="project_linked",
        method="GET",
        url="https://fixture.test/api/items?id=1",
        request_headers={"Accept": "application/json"},
        request_body="",
        response_headers={"Content-Type": "application/json"},
        response_body='{"ok":true}',
        status_code=200,
        latency_ms=12,
        response_size=11,
    )
    return project, context, endpoint


class ProjectBundleExportTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_export_carries_every_project_scoped_record_type(self):
        project, context, endpoint = build_project()
        response = self.client.get(f"/api/projects/{project.id}/export")
        self.assertEqual(response.status_code, 200)
        bundle = response.json()
        self.assertEqual(bundle["schema"], PROJECT_BUNDLE_SCHEMA)
        self.assertEqual(bundle["project"]["name"], "Transfer source")
        self.assertEqual(bundle["project"]["notes"], "Workspace notes that must survive the transfer.")
        self.assertEqual(bundle["project"]["tech_stack"]["frontend"], ["nginx"])
        self.assertEqual(bundle["counts"]["endpoints"], 2)
        self.assertEqual(bundle["counts"]["scanner_runs"], 1)
        self.assertEqual(bundle["counts"]["target_jobs"], 1)
        self.assertEqual(bundle["counts"]["workflows"], 1)
        self.assertEqual(bundle["counts"]["workflow_runs"], 1)
        self.assertEqual(bundle["counts"]["traffic"], 1)
        self.assertEqual(bundle["counts"]["intruder_attacks"], 1)
        self.assertEqual(bundle["counts"]["capture_contexts"], 1)
        self.assertEqual(bundle["counts"]["osint_graphs"], 1)
        self.assertEqual(bundle["counts"]["osint_entities"], 2)
        self.assertEqual(bundle["counts"]["osint_relations"], 1)
        self.assertEqual(bundle["endpoints"][0]["path"], endpoint.path)
        # A bundle is the one export that carries raw bodies: the whole point is
        # that the imported workspace still holds replayable evidence.
        self.assertEqual(bundle["traffic"][0]["response_body"], '{"ok":true}')
        self.assertEqual(bundle["traffic"][0]["request_headers"], {"Accept": "application/json"})
        self.assertEqual(bundle["traffic"][0]["capture_context"], 0)
        # The capture token is a live correlation secret for one installation,
        # so it is never written into a document that leaves it.
        self.assertNotIn(context.token, json.dumps(bundle))

    def test_export_never_writes_a_secret_value(self):
        project, _, _ = build_project()
        bundle = export_bundle(project)
        secret = bundle["secret_references"][0]
        self.assertEqual(secret["key_name"], "X-Api-Key")
        self.assertEqual(secret["value_ref"], "vault://services/fixture#key")

    def test_export_of_missing_project_is_404_and_wrong_method_is_405(self):
        self.assertEqual(self.client.get("/api/projects/999999/export").status_code, 404)
        project = Project.objects.create(name="Method check")
        self.assertEqual(self.client.post(f"/api/projects/{project.id}/export").status_code, 405)

    def test_export_of_empty_project_still_returns_a_usable_document(self):
        project = Project.objects.create(name="Empty workspace")
        bundle = export_bundle(project)
        self.assertEqual(bundle["project"]["name"], "Empty workspace")
        self.assertEqual(bundle["counts"]["traffic"], 0)
        self.assertEqual(bundle["endpoints"], [])


class ProjectBundleImportTests(TestCase):
    def setUp(self):
        self.client = Client()

    def post(self, bundle):
        return self.client.post(
            "/api/projects/import",
            data=json.dumps(bundle),
            content_type="application/json",
        )

    def test_round_trip_recreates_the_workspace_with_its_relationships(self):
        source, _, _ = build_project()
        response = self.post(export_bundle(source))
        self.assertEqual(response.status_code, 201)
        imported = response.json()["project"]
        # A name is unique per installation, so the import lands beside the
        # source instead of replacing or failing on it.
        self.assertNotEqual(imported["id"], source.id)
        self.assertEqual(imported["name"], "Transfer source (2)")
        project = Project.objects.get(id=imported["id"])

        self.assertEqual(project.environment, "staging")
        self.assertEqual(project.notes, "Workspace notes that must survive the transfer.")
        self.assertEqual(project.metadata["case"], "RR-1")
        self.assertEqual(ProjectEndpoint.objects.filter(project=project).count(), 2)
        self.assertEqual(ProjectSecret.objects.filter(project=project).count(), 1)
        self.assertEqual(ScannerRun.objects.filter(project=project).count(), 1)
        self.assertEqual(TargetJob.objects.filter(project=project).count(), 1)
        self.assertEqual(Workflow.objects.filter(project=project).count(), 1)
        self.assertEqual(WorkflowRun.objects.filter(project=project).count(), 1)
        self.assertEqual(TrafficRecord.objects.filter(project=project).count(), 1)
        self.assertEqual(IntruderAttack.objects.filter(project=project).count(), 1)

        # The graph keeps its shape: two entities and the relation that points
        # from one to the other, resolved inside the bundle rather than by the
        # exporting database's ids.
        graph = OsintGraph.objects.get(project=project)
        entities = {entity.identity: entity for entity in OsintEntity.objects.filter(graph=graph)}
        self.assertEqual(set(entities), {"fixture.test", "api.fixture.test"})
        relation = OsintRelation.objects.get(graph=graph)
        self.assertEqual(relation.source_entity, entities["api.fixture.test"])
        self.assertEqual(relation.target_entity, entities["fixture.test"])
        self.assertEqual(relation.relation_type, "subdomain_of")

        record = TrafficRecord.objects.get(project=project)
        self.assertEqual(record.response_body, '{"ok":true}')
        self.assertEqual(record.source_ip, "203.0.113.10")
        # The record stays linked to the context the export named, and that
        # context got a token of its own.
        self.assertIsNotNone(record.capture_context)
        self.assertEqual(record.capture_context.project_id, project.id)
        self.assertEqual(record.scope_status, "project_linked")

    def test_import_restores_the_observation_time_of_each_exchange(self):
        source, _, _ = build_project()
        original = TrafficRecord.objects.get(project=source)
        observed = timezone.now() - timezone.timedelta(days=3)
        TrafficRecord.objects.filter(pk=original.pk).update(timestamp=observed)
        self.post(export_bundle(source))
        imported = Project.objects.get(name="Transfer source (2)")
        restored = TrafficRecord.objects.get(project=imported)
        # Without this the whole imported History would sort as one burst that
        # happened at the moment of the import.
        self.assertAlmostEqual(
            restored.timestamp.timestamp(), observed.timestamp(), delta=1
        )

    def test_import_issues_its_own_unique_job_ids_and_webhook_slugs(self):
        source, _, _ = build_project()
        self.post(export_bundle(source))
        self.post(export_bundle(source))
        projects = Project.objects.filter(name__startswith="Transfer source")
        self.assertEqual(projects.count(), 3)
        job_ids = list(TargetJob.objects.filter(project__in=projects).values_list("job_id", flat=True))
        # `job_id` is globally unique: a repeated import must not reuse the id
        # the source run already occupies, or the two would be one row.
        self.assertEqual(len(job_ids), len(set(job_ids)))
        imported_ids = list(
            TargetJob.objects.exclude(project=source).values_list("job_id", flat=True)
        )
        self.assertEqual(len(imported_ids), 2)
        self.assertNotIn("target-original", imported_ids)
        slugs = list(Workflow.objects.filter(project__in=projects).values_list("webhook_slug", flat=True))
        self.assertEqual(len(slugs), len(set(slugs)))
        # The source keeps the slug it already owned; the copies are routed
        # somewhere else so one installation's webhook path cannot answer for
        # another one's workflow.
        self.assertIn("nightly-sweep", slugs)
        self.assertEqual(Workflow.objects.get(project=source).webhook_slug, "nightly-sweep")
        self.assertNotEqual(
            Workflow.objects.exclude(project=source).values_list("webhook_slug", flat=True)[0],
            "nightly-sweep",
        )

    def test_imported_workflow_lands_inactive_so_no_schedule_fires_unasked(self):
        source, _, _ = build_project()
        self.assertTrue(Workflow.objects.get(project=source).active)
        self.post(export_bundle(source))
        imported = Project.objects.get(name="Transfer source (2)")
        self.assertFalse(Workflow.objects.get(project=imported).active)

    def test_import_reports_what_it_wrote(self):
        source, _, _ = build_project()
        report = self.post(export_bundle(source)).json()["report"]
        self.assertEqual(report["project_name"], "Transfer source (2)")
        self.assertEqual(report["endpoints"], 2)
        self.assertEqual(report["osint_relations"], 1)
        self.assertEqual(report["traffic"], 1)
        self.assertEqual(report["workflow_runs"], 1)
        self.assertEqual(report["capture_contexts"], 1)

    def test_import_rejects_a_body_that_is_not_a_bundle(self):
        for body in ("", "not json", "[]", json.dumps({"schema": "other.tool/v9", "project": {"name": "x"}})):
            response = self.client.post(
                "/api/projects/import", data=body, content_type="application/json"
            )
            self.assertEqual(response.status_code, 400, body)
            self.assertEqual(response.json()["reason"], "INVALID_PROJECT_BUNDLE")
        self.assertFalse(Project.objects.filter(name="x").exists())

    def test_import_rejects_a_bundle_without_a_name(self):
        response = self.post({"schema": PROJECT_BUNDLE_SCHEMA, "project": {"target": "https://x.test/"}})
        self.assertEqual(response.status_code, 400)
        self.assertIn("name", response.json()["error"])

    def test_import_skips_rows_it_cannot_use_instead_of_failing_the_document(self):
        bundle = {
            "schema": PROJECT_BUNDLE_SCHEMA,
            "project": {"name": "Partly readable"},
            "endpoints": [{"method": "GET"}, {"method": "GET", "path": "/ok"}],
            "osint": {
                "graphs": [{"name": "Graph"}],
                "entities": [
                    {"graph": 0, "type": "domain", "identity": "kept.test"},
                    {"graph": 7, "type": "domain", "identity": "orphan.test"},
                    {"type": "domain"},
                ],
                "relations": [{"graph": 0, "source": 0, "target": 9, "type": "related_to"}],
            },
            "traffic": [{"method": "GET"}, {"method": "GET", "url": "https://kept.test/"}],
            "workflow_runs": [{"workflow": 5, "status": "completed"}],
        }
        response = self.post(bundle)
        self.assertEqual(response.status_code, 201)
        project = Project.objects.get(name="Partly readable")
        # Two, not one: the bundle's own `/ok` row, plus `GET /` which the
        # knowledge-base ingestor registers for the traffic row it accepted.
        self.assertEqual(ProjectEndpoint.objects.filter(project=project).count(), 2)
        self.assertEqual(OsintEntity.objects.filter(project=project).count(), 1)
        self.assertEqual(TrafficRecord.objects.filter(project=project).count(), 1)
        self.assertEqual(WorkflowRun.objects.filter(project=project).count(), 0)
        report = response.json()["report"]
        self.assertEqual(report["endpoints"], 1)
        self.assertEqual(report["osint_entities"], 1)
        self.assertEqual(report["osint_relations"], 0)
        self.assertEqual(report["traffic"], 1)
        self.assertEqual(report["workflow_runs"], 0)

    def test_import_drops_an_unreadable_source_ip_instead_of_failing(self):
        bundle = {
            "schema": PROJECT_BUNDLE_SCHEMA,
            "project": {"name": "Bad address"},
            "traffic": [{"method": "GET", "url": "https://x.test/", "source_ip": "not-an-ip"}],
        }
        response = self.post(bundle)
        self.assertEqual(response.status_code, 201)
        record = TrafficRecord.objects.get(project__name="Bad address")
        self.assertIsNone(record.source_ip)

    def test_import_collapses_a_repeated_endpoint_pair_instead_of_failing(self):
        response = self.post({
            "schema": PROJECT_BUNDLE_SCHEMA,
            "project": {"name": "Duplicate endpoints"},
            "endpoints": [
                {"method": "get", "path": "/api/items", "statuses": [200]},
                {"method": "GET", "path": "/api/items", "statuses": [500]},
            ],
        })
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["report"]["endpoints"], 1)

    def test_import_of_a_bare_project_object_is_accepted(self):
        # A bundle someone extracted by hand is still a bundle.
        response = self.post({"name": "Hand written", "target": "https://x.test/"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["project"]["name"], "Hand written")

    def test_import_requires_post(self):
        self.assertEqual(self.client.get("/api/projects/import").status_code, 405)

    def test_imported_project_can_be_activated_and_re_exported(self):
        source, _, _ = build_project()
        imported_id = self.post(export_bundle(source)).json()["project"]["id"]
        context = self.client.post(
            "/api/project-context",
            data=json.dumps({"project_id": imported_id}),
            content_type="application/json",
        )
        self.assertEqual(context.json()["active_project_id"], imported_id)
        # A second export of the imported workspace must be self-contained: the
        # copy is a real project, not a stub that only the import path understood.
        second = self.client.get(f"/api/projects/{imported_id}/export").json()
        self.assertEqual(second["counts"]["traffic"], 1)
        self.assertEqual(second["counts"]["osint_relations"], 1)
        third_id = self.post(second).json()["project"]["id"]
        self.assertNotEqual(third_id, imported_id)
        self.assertEqual(
            Project.objects.get(id=third_id).traffic_records.count(), 1
        )


class ProjectTransferParsingTests(TestCase):
    def test_parse_reads_bytes_str_and_already_decoded_documents(self):
        self.assertEqual(parse_bundle_body(b'{"name": "a"}'), {"name": "a"})
        self.assertEqual(parse_bundle_body('{"name": "a"}'), {"name": "a"})
        self.assertEqual(parse_bundle_body({"name": "a"}), {"name": "a"})
