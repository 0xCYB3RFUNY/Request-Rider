"""Tests for F6 Attack Surface Drift & Shadow API Radar."""
import json

from django.test import Client, TestCase

from lab.models import Project, ProjectEndpoint, TrafficRecord
from lab.surface_drift import capture_project_snapshot, compute_surface_drift


class SurfaceDriftTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project, _ = Project.objects.get_or_create(name="SurfaceDriftProject")

    def test_snapshot_capture_and_drift_detection(self):
        ProjectEndpoint.objects.create(
            project=self.project,
            method="GET",
            path="/api/v2/users",
            sample_url="https://target.local/api/v2/users",
            parameters=["page"],
            statuses=[200],
        )
        ProjectEndpoint.objects.create(
            project=self.project,
            method="GET",
            path="/api/admin/stats",
            sample_url="https://target.local/api/admin/stats",
            statuses=[403],
        )
        TrafficRecord.objects.create(
            project=self.project,
            source="proxy",
            method="GET",
            url="https://target.local/static/app.js",
            response_headers={"Content-Security-Policy": "default-src 'self'"},
            response_content_type="application/javascript",
            response_body="console.log('v1');",
            status_code=200,
        )

        s1 = capture_project_snapshot(self.project, label="Baseline S1")

        # Mutate surface for S2: add Shadow API /api/v1/users, add param to /api/v2/users,
        # regress /api/admin/stats 403->200, modify app.js, drop CSP header
        ProjectEndpoint.objects.create(
            project=self.project,
            method="GET",
            path="/api/v1/users",
            sample_url="https://target.local/api/v1/users",
            statuses=[200],
        )
        ep_v2 = ProjectEndpoint.objects.get(project=self.project, path="/api/v2/users")
        ep_v2.parameters = ["page", "debug"]
        ep_v2.save()

        ep_admin = ProjectEndpoint.objects.get(project=self.project, path="/api/admin/stats")
        ep_admin.statuses = [403, 200]
        ep_admin.save()

        TrafficRecord.objects.create(
            project=self.project,
            source="proxy",
            method="GET",
            url="https://target.local/static/app.js",
            response_headers={},
            response_content_type="application/javascript",
            response_body="console.log('v2-modified');",
            status_code=200,
        )

        s2 = capture_project_snapshot(self.project, label="Release S2")
        diff = compute_surface_drift(s1, s2)

        self.assertEqual(diff["counts"]["new_endpoints"], 1)
        self.assertEqual(diff["counts"]["shadow_apis"], 1)
        self.assertEqual(diff["shadow_apis"][0]["path"], "/api/v1/users")
        self.assertEqual(diff["counts"]["new_params"], 1)
        self.assertEqual(diff["new_params"][0]["added_params"], ["debug"])
        self.assertEqual(diff["counts"]["changed_js"], 1)
        self.assertEqual(diff["changed_js"][0]["change"], "modified")
        # Both auth regression (403 -> 200) and CSP header disappearance
        self.assertEqual(diff["counts"]["regressions"], 2)
        self.assertIn("https://target.local/api/v1/users", diff["delta_scan_urls"])

    def test_snapshots_api_endpoints_and_ui_presence(self):
        c1 = self.client.post(
            f"/api/projects/{self.project.id}/snapshots",
            data=json.dumps({"label": "API Snap 1"}),
            content_type="application/json",
        )
        self.assertEqual(c1.status_code, 201)
        s1_id = c1.json()["snapshot"]["id"]

        ProjectEndpoint.objects.create(
            project=self.project,
            method="POST",
            path="/api/internal/export",
            sample_url="https://target.local/api/internal/export",
            statuses=[200],
        )
        c2 = self.client.post(
            f"/api/projects/{self.project.id}/snapshots",
            data=json.dumps({"label": "API Snap 2"}),
            content_type="application/json",
        )
        self.assertEqual(c2.status_code, 201)
        s2_id = c2.json()["snapshot"]["id"]

        diff_resp = self.client.post(
            f"/api/projects/{self.project.id}/snapshots/diff",
            data=json.dumps({"s1_id": s1_id, "s2_id": s2_id}),
            content_type="application/json",
        )
        self.assertEqual(diff_resp.status_code, 200)
        self.assertEqual(diff_resp.json()["counts"]["shadow_apis"], 1)

        html = self.client.get("/").content.decode("utf-8")
        self.assertIn("surface-drift-panel", html)
        self.assertIn("sd-capture-btn", html)
        self.assertIn("sd-diff-btn", html)
