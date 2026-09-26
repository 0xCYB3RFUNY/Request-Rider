import json

from django.test import Client, TestCase

from .models import Project


class ProjectTargetTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_target_is_descriptive_metadata(self):
        response = self.client.post(
            "/api/projects",
            data=json.dumps({
                "name": "Free-form project",
                "target": "operator note: staging cluster /path?not=validated",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        project = response.json()
        self.assertEqual(project["target"], "operator note: staging cluster /path?not=validated")

    def test_project_api_does_not_accept_or_return_scope_policy(self):
        response = self.client.post(
            "/api/projects",
            data=json.dumps({
                "name": "Organizational project",
                "target": "https://app.example.test/api",
                "scope_in": ["*.example.test"],
                "scope_out": ["https://blocked.example.test/"],
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        project = response.json()
        self.assertNotIn("scope_in", project)
        self.assertNotIn("scope_out", project)
        self.assertEqual(Project.objects.get(id=project["id"]).scope_in, [])
