"""Tests for F1 Live Auth Matrix (ProjectAuthProfile CRUD, Secret Resolution, and Matrix API)."""
import json
from unittest.mock import patch

from django.test import Client, TestCase

from lab.models import Project, ProjectAuthProfile, ProjectSecret


class AuthMatrixTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project, _ = Project.objects.get_or_create(name="AuthMatrixTestProject")

    def test_auth_profile_crud_and_baseline_uniqueness(self):
        resp1 = self.client.post(
            "/api/auth-profiles",
            data=json.dumps({
                "project_id": self.project.id,
                "name": "Admin",
                "role_type": "admin",
                "headers": {"Authorization": "Bearer admin-jwt"},
                "is_baseline": True,
            }),
            content_type="application/json",
        )
        self.assertEqual(resp1.status_code, 201)
        admin_id = resp1.json()["profile"]["id"]

        resp2 = self.client.post(
            "/api/auth-profiles",
            data=json.dumps({
                "project_id": self.project.id,
                "name": "User_B",
                "role_type": "user",
                "headers": {"Authorization": "Bearer userb-jwt"},
                "is_baseline": True,
            }),
            content_type="application/json",
        )
        self.assertEqual(resp2.status_code, 201)
        admin_obj = ProjectAuthProfile.objects.get(id=admin_id)
        self.assertFalse(admin_obj.is_baseline)

        list_resp = self.client.get(f"/api/auth-profiles?project_id={self.project.id}")
        self.assertEqual(list_resp.status_code, 200)
        self.assertEqual(list_resp.json()["count"], 2)

        patch_resp = self.client.patch(
            f"/api/auth-profiles/{admin_id}",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        self.assertEqual(patch_resp.status_code, 200)
        self.assertFalse(patch_resp.json()["profile"]["enabled"])

        del_resp = self.client.delete(f"/api/auth-profiles/{admin_id}")
        self.assertEqual(del_resp.status_code, 200)
        self.assertFalse(ProjectAuthProfile.objects.filter(id=admin_id).exists())

    def test_resolve_headers_with_live_project_secret(self):
        secret = ProjectSecret.objects.create(
            project=self.project,
            secret_type="jwt",
            key_name="OPERATOR_JWT",
            value_ref="eyJhbGciOiJIUzI1NiJ9.payload.sig",
            source_url="https://target.local/login",
        )
        profile_auto = ProjectAuthProfile.objects.create(
            project=self.project,
            name="AutoSecretUser",
            role_type="user",
            headers={},
            secret_ref=secret,
        )
        resolved = profile_auto.resolve_headers()
        self.assertEqual(resolved["Authorization"], "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")

        profile_template = ProjectAuthProfile.objects.create(
            project=self.project,
            name="TemplatedUser",
            role_type="user",
            headers={"X-Token": "Token ${secret}"},
            secret_ref=secret,
        )
        resolved_tpl = profile_template.resolve_headers()
        self.assertEqual(resolved_tpl["X-Token"], "Token eyJhbGciOiJIUzI1NiJ9.payload.sig")

    @patch("lab.views.call_engine")
    def test_repeater_auth_matrix_dispatches_to_engine(self, mock_call_engine):
        mock_call_engine.return_value = (
            200,
            {
                "ok": True,
                "elapsed_ms": 12,
                "count": 2,
                "results": [
                    {"role_name": "Admin", "status": 200, "verdict": "BASELINE"},
                    {"role_name": "Anonymous", "status": 401, "verdict": "ENFORCED"},
                ],
            },
        )
        ProjectAuthProfile.objects.create(
            project=self.project,
            name="Admin",
            role_type="admin",
            headers={"Authorization": "Bearer admin123"},
            is_baseline=True,
            enabled=True,
        )
        ProjectAuthProfile.objects.create(
            project=self.project,
            name="Anonymous",
            role_type="anon",
            strip_auth=True,
            enabled=True,
        )

        resp = self.client.post(
            "/api/repeater/auth-matrix",
            data=json.dumps({
                "project_id": self.project.id,
                "base_request": {
                    "method": "GET",
                    "url": "https://target.local/api/orders/1",
                    "headers": {"Authorization": "Bearer admin123"},
                },
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["results"]), 2)
        mock_call_engine.assert_called_once()
        called_path, called_payload = mock_call_engine.call_args[0]
        self.assertEqual(called_path, "/proxy/repeater/auth-matrix")
        self.assertEqual(len(called_payload["roles"]), 2)

    def test_repeater_template_contains_auth_matrix_ui(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.content.decode("utf-8")
        self.assertIn("repeater-auth-matrix-btn", html)
        self.assertIn("auth-matrix-wrap", html)
        self.assertIn("auth-matrix-run-btn", html)
