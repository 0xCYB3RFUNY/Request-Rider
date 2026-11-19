"""Tests for F5 JWT & Crypto Forge Studio."""
import json
from unittest.mock import patch

from django.test import Client, TestCase

from lab.models import Project, ProjectSecret


class JWTForgeTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project, _ = Project.objects.get_or_create(name="JWTForgeProject")

    def test_jwt_context_returns_project_jwt_tokens(self):
        ProjectSecret.objects.create(
            project=self.project,
            secret_type="jwt",
            key_name="ADMIN_JWT",
            value_ref="eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.sig",
            source_url="https://target.local/auth",
        )
        resp = self.client.get(f"/api/jwt/context?project_id={self.project.id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["tokens"]), 1)
        self.assertEqual(data["tokens"][0]["key_name"], "ADMIN_JWT")

    @patch("lab.views.call_engine")
    def test_jwt_forge_resolves_project_secret_and_dispatches_to_engine(self, mock_call_engine):
        sec = ProjectSecret.objects.create(
            project=self.project,
            secret_type="api_key",
            key_name="JWT_HMAC_KEY",
            value_ref="resolved-hmac-secret",
            source_url="https://target.local",
        )
        mock_call_engine.return_value = (
            200,
            {"variants": [{"name": "alg=none", "category": "none", "token": "a.b."}]},
        )
        resp = self.client.post(
            "/api/jwt/forge",
            data=json.dumps({
                "project_id": self.project.id,
                "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
                "secret_id": sec.id,
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        called_path, called_payload = mock_call_engine.call_args[0]
        self.assertEqual(called_path, "/proxy/jwt/forge")
        self.assertEqual(called_payload["hmac_secret"], "resolved-hmac-secret")

    def test_decoder_and_repeater_templates_contain_jwt_forge_ui(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.content.decode("utf-8")
        self.assertIn("jwt-forge-studio", html)
        self.assertIn("jwt-forge-run-btn", html)
        self.assertIn("repeater-jwt-forge-btn", html)
