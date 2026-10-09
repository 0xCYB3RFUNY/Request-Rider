import json
from unittest.mock import patch

from django.test import Client, TestCase

from .models import Project, TargetJob, TrafficCaptureContext, TrafficRecord
from .views import persist_proxy_history, public_traffic_event


class TrafficCaptureContextApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(
            name="Capture project",
            target="https://capture.example.test/api/",
        )

    def create_context(self, name="Fixture capture", project_id=None):
        return self.client.post(
            "/api/traffic/capture-contexts",
            data=json.dumps({"name": name, "project_id": project_id}),
            content_type="application/json",
        )

    def test_create_requires_explicit_project_and_returns_opaque_token(self):
        missing_project = self.client.post(
            "/api/traffic/capture-contexts",
            data=json.dumps({"name": "Missing project"}),
            content_type="application/json",
        )
        self.assertEqual(missing_project.status_code, 400)
        self.assertIn("project_id is required", missing_project.json()["error"])

        response = self.create_context(project_id=self.project.id)
        self.assertEqual(response.status_code, 201)
        context = response.json()
        self.assertEqual(context["project_id"], self.project.id)
        self.assertTrue(context["active"])
        self.assertNotIn("token", context)
        self.assertRegex(TrafficCaptureContext.objects.get(id=context["id"]).token, r"^[A-Za-z0-9_-]+$")
        self.assertLessEqual(len(TrafficCaptureContext.objects.get(id=context["id"]).token), 64)

        unscoped = self.create_context(name="Unscoped capture", project_id=None)
        self.assertEqual(unscoped.status_code, 201)
        self.assertIsNone(unscoped.json()["project_id"])

        listed = self.client.get("/api/traffic/capture-contexts")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()["items"]), 2)

    def test_context_api_requires_csrf_and_deactivates_without_deleting(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.get("/")
        csrf_token = csrf_client.cookies["csrftoken"].value
        rejected = csrf_client.post(
            "/api/traffic/capture-contexts",
            data=json.dumps({"name": "CSRF capture", "project_id": None}),
            content_type="application/json",
        )
        self.assertEqual(rejected.status_code, 403)

        created = csrf_client.post(
            "/api/traffic/capture-contexts",
            data=json.dumps({"name": "CSRF capture", "project_id": None}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf_token,
        )
        self.assertEqual(created.status_code, 201)
        context_id = created.json()["id"]
        deleted = self.client.delete(f"/api/traffic/capture-contexts/{context_id}")
        self.assertEqual(deleted.status_code, 200)
        self.assertFalse(TrafficCaptureContext.objects.get(id=context_id).active)

    def test_invalid_project_is_rejected(self):
        response = self.create_context(project_id=999999)
        self.assertEqual(response.status_code, 404)


class TrafficCaptureClassificationTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name="Linked capture project",
            target="https://scoped.example.test/api/",
        )
        self.project_linked = TrafficCaptureContext.objects.create(name="Project linked", project=self.project)
        self.unlinked = TrafficCaptureContext.objects.create(name="Unlinked")
        self.unscoped = TrafficCaptureContext.objects.create(name="Unscoped")

    def persist(self, event_id, url, token):
        persist_proxy_history([{
            "id": event_id,
            "session": 77,
            "source": "proxy",
            "method": "GET",
            "url": url,
            "status": 200,
            "capture_context": token,
        }])

    def test_proxy_events_are_linked_without_url_policy_or_deletion(self):
        self.persist(1, "https://scoped.example.test/api/health", self.project_linked.token)
        self.persist(2, "https://outside.example.test/", self.project_linked.token)
        self.persist(3, "https://unscoped.example.test/", self.unscoped.token)
        self.persist(4, "https://scoped.example.test/api/health", "unknown-token")

        records = {
            record.proxy_event_id: record
            for record in TrafficRecord.objects.filter(proxy_session=77)
        }
        self.assertEqual(set(records), {1, 2, 3, 4})
        self.assertEqual(records[1].project_id, self.project.id)
        self.assertEqual(records[1].scope_status, "project_linked")
        self.assertEqual(records[2].project_id, self.project.id)
        self.assertEqual(records[2].scope_status, "project_linked")
        self.assertEqual(records[3].project_id, None)
        self.assertEqual(records[3].scope_status, "unscoped")
        self.assertEqual(records[4].scope_status, "invalid_context")
        self.assertEqual(TrafficRecord.objects.filter(proxy_session=77).count(), 4)

        public = public_traffic_event({
            "id": 1,
            "url": "https://scoped.example.test/api/health",
            "capture_context": self.project_linked.token,
        })
        self.assertNotIn("capture_context", public)
        self.assertEqual(public["capture_context_id"], self.project_linked.id)
        self.assertEqual(public["scope_status"], "project_linked")

        # A repeated event ID is idempotent and does not create a second record.
        self.persist(1, "https://scoped.example.test/api/health", self.project_linked.token)
        self.assertEqual(TrafficRecord.objects.filter(proxy_session=77).count(), 4)


class TargetBrowserCaptureContextTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(name="Browser capture project", target="https://browser.example.test/")
        self.context = TrafficCaptureContext.objects.create(name="Browser capture", project=self.project)

    @patch("lab.views.call_browser_worker")
    @patch("lab.views.call_engine_get", return_value=(200, {"address": ""}))
    def test_browser_target_forwards_validated_context_token(self, _route, worker):
        worker.return_value = (202, {"job_id": "capture-job", "status": "running"})
        response = self.client.post(
            "/api/target-browser",
            data=json.dumps({
                "url": "https://browser.example.test/",
                "capture_context_id": self.context.id,
                "project_id": None,
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        forwarded = worker.call_args.args[1]
        self.assertEqual(forwarded["capture_context"], self.context.token)
        self.assertNotIn("capture_context_id", forwarded)
        job = TargetJob.objects.get(job_id="capture-job")
        self.assertEqual(job.capture_context_id, self.context.id)
        self.assertEqual(job.project_id, self.project.id)

    @patch("lab.views.call_engine_get", return_value=(200, {"address": ""}))
    def test_inactive_context_is_rejected_before_worker_call(self, _route):
        self.context.active = False
        self.context.save(update_fields=["active"])
        response = self.client.post(
            "/api/target-browser",
            data=json.dumps({"url": "https://browser.example.test/", "capture_context_id": self.context.id}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)
