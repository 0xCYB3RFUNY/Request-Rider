import json

from django.test import Client, TestCase

from .middleware import ACTIVE_PROJECT_SESSION_KEY
from .models import Project


class ProjectContextApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(
            name="Context project",
            target="https://context.example.test/",
        )
        self.other = Project.objects.create(
            name="Other context project",
            target="https://other.example.test/",
        )

    def post_context(self, client, project_id, csrf_token=None):
        headers = {"HTTP_X_CSRFTOKEN": csrf_token} if csrf_token else {}
        return client.post(
            "/api/project-context",
            data=json.dumps({"project_id": project_id}),
            content_type="application/json",
            **headers,
        )

    def test_project_context_requires_csrf_and_updates_session(self):
        client = Client(enforce_csrf_checks=True)
        client.get("/")
        csrf_token = client.cookies["csrftoken"].value

        rejected = self.post_context(client, self.project.id)
        self.assertEqual(rejected.status_code, 403)

        accepted = self.post_context(client, self.project.id, csrf_token)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json()["active_project_id"], self.project.id)
        self.assertEqual(client.session[ACTIVE_PROJECT_SESSION_KEY], self.project.id)

        page = client.get("/")
        self.assertContains(page, f'data-active-project-id="{self.project.id}"')

    def test_query_parameter_cannot_replace_server_project_context(self):
        self.client.get(f"/?project_id={self.other.id}")
        page = self.client.get(f"/?project_id={self.other.id}")
        self.assertNotContains(page, f'data-active-project-id="{self.other.id}"')
        self.assertNotIn(ACTIVE_PROJECT_SESSION_KEY, self.client.session)

        self.post_context(self.client, self.project.id)
        page = self.client.get(f"/?project_id={self.other.id}")
        self.assertContains(page, f'data-active-project-id="{self.project.id}"')

    def test_context_validates_project_and_clears_session(self):
        self.post_context(self.client, self.project.id)
        missing = self.post_context(self.client, 999999)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(self.client.session[ACTIVE_PROJECT_SESSION_KEY], self.project.id)

        cleared = self.post_context(self.client, None)
        self.assertEqual(cleared.status_code, 200)
        self.assertIsNone(cleared.json()["active_project_id"])
        self.assertNotIn(ACTIVE_PROJECT_SESSION_KEY, self.client.session)

    def test_deleted_active_project_is_cleared_by_middleware(self):
        self.post_context(self.client, self.project.id)
        Project.objects.filter(id=self.project.id).delete()
        page = self.client.get("/")
        self.assertContains(page, 'data-active-project-id=""')
        self.assertNotIn(ACTIVE_PROJECT_SESSION_KEY, self.client.session)
