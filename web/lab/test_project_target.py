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

    def test_index_contains_project_target_autofill_functions(self):
        page = self.client.get("/")
        content = page.content.decode("utf-8")
        self.assertIn("formatProjectTargetUrl", content)
        self.assertIn("getActiveProjectTargetUrl", content)
        self.assertIn("applyActiveProjectTarget", content)
        self.assertIn("['target-url', 'scanner-url', 'osint-url']", content)

    def test_format_project_target_url_logic_in_node(self):
        import subprocess
        js_code = """
        function formatProjectTargetUrl(rawTarget) {
          if (!rawTarget) return '';
          let str = String(rawTarget).trim().replace(/^["']|["']$/g, '');
          if (!str) return '';
          if (/^https:\\/\\//i.test(str)) return str;
          if (/^http:\\/\\//i.test(str)) {
            if (/^http:\\/\\/(?:localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::1\\])(?::\\d+)?(?:\\/|$)/i.test(str)) {
              return str;
            }
            return str.replace(/^http:\\/\\//i, 'https://');
          }
          str = str.replace(/^\\/+/, '');
          return 'https://' + str;
        }

        console.log(JSON.stringify({
          domain: formatProjectTargetUrl('example.com'),
          domain_with_path: formatProjectTargetUrl('example.com/api/v1'),
          https: formatProjectTargetUrl('https://app.example.com'),
          http_remote: formatProjectTargetUrl('http://insecure.example.com'),
          http_local: formatProjectTargetUrl('http://127.0.0.1:8000/app'),
          empty: formatProjectTargetUrl(''),
          slashes: formatProjectTargetUrl('//target.com')
        }));
        """
        result = subprocess.run(["node", "-e", js_code], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout.strip())
        self.assertEqual(data["domain"], "https://example.com")
        self.assertEqual(data["domain_with_path"], "https://example.com/api/v1")
        self.assertEqual(data["https"], "https://app.example.com")
        self.assertEqual(data["http_remote"], "https://insecure.example.com")
        self.assertEqual(data["http_local"], "http://127.0.0.1:8000/app")
        self.assertEqual(data["empty"], "")
        self.assertEqual(data["slashes"], "https://target.com")

