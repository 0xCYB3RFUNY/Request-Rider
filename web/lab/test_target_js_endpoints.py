"""Tests for indexing the endpoints a crawled JavaScript file names.

The engine parses JavaScript now (`analyzeJavaScript` in the Go crawler) and
reports the call sites on the page record as `js.endpoints`. These tests pin what
the Project does with them, and each claim is written so that reverting the
decision it checks turns it red.
"""

from django.test import TestCase

from .models import Project, ProjectEndpoint, ProjectSecret
from .views import _ingest_target_result_once


def js_page(url, endpoints, secrets=None, **extra):
    """One crawled page record shaped the way the engine emits it."""
    page = {
        "url": url,
        "method": "GET",
        "status": 200,
        "kind": "javascript",
        "js": {
            "bytes": 4096,
            "ms": 12,
            "endpoints": endpoints,
            "secrets": secrets if secrets is not None else [],
            "links_with_expression": 0,
        },
    }
    page.update(extra)
    return page


class TargetJavaScriptEndpointIndexingTests(TestCase):
    """What a parsed JavaScript call site contributes to the Project knowledge base."""

    def setUp(self):
        self.project = Project.objects.create(name="js-endpoint-indexing")

    def endpoints(self):
        """Every endpoint row for the Project, path first.

        The crawled script is in here too, and it should be: it is a resource
        the crawl fetched, and the existing ingest registers every fetched page.
        The assertions below name it explicitly rather than filtering it away,
        because a helper that hides rows would also hide a row that must not be
        there.
        """
        return list(
            ProjectEndpoint.objects.filter(project=self.project)
            .order_by("path", "method")
            .values_list("path", "method", "parameters")
        )

    def script_path(self):
        return "/assets/app.js"

    def test_call_site_method_and_parameters_are_indexed(self):
        """A method and parameter names are the payload of the finding.

        `register_endpoint` stores a method and a parameter list; a row that kept
        only the path would be indistinguishable from a link the crawler
        followed, and would throw away the only reason to have parsed the file.
        """
        _ingest_target_result_once(
            self.project,
            {
                "pages": [
                    js_page(
                        "https://shop.example/assets/app.js",
                        [
                            {
                                "url": "/api/v1/orders",
                                "method": "POST",
                                "types": ["fetch"],
                                "query_params": [],
                                "body_params": ["id", "coupon"],
                            }
                        ],
                    )
                ]
            },
        )
        self.assertEqual(
            self.endpoints(),
            [
                ("/api/v1/orders", "POST", ["coupon", "id"]),
                (self.script_path(), "GET", []),
            ],
        )

    def test_relative_reference_resolves_against_the_script_url(self):
        """A reference is written relative to the file that contains it.

        `api/v1/users.json` inside `/assets/app.js` is `/assets/api/v1/users.json`.
        Resolving it against the crawl start instead would file it under a path
        that does not exist, and the row would be a statement about nothing.
        """
        _ingest_target_result_once(
            self.project,
            {
                "pages": [
                    js_page(
                        "https://shop.example/assets/app.js",
                        [{"url": "api/v1/users.json", "method": "GET",
                          "types": ["stringLiteral"], "query_params": [], "body_params": []}],
                    )
                ]
            },
        )
        self.assertEqual(
            [path for path, _method, _params in self.endpoints()],
            ["/assets/api/v1/users.json", self.script_path()],
        )

    def test_expression_reference_is_not_indexed(self):
        """`/api/users/EXPR` is a path shape, not a path.

        The engine substitutes EXPR where the program builds the value. Storing
        that as a discovered endpoint puts a row in the Project that no request
        can ever match, which reads as a finding and is not one.
        """
        _ingest_target_result_once(
            self.project,
            {
                "pages": [
                    js_page(
                        "https://shop.example/assets/app.js",
                        [
                            {"url": "/api/users/EXPR", "method": "GET",
                             "types": ["fetch"], "query_params": [], "body_params": []},
                            {"url": "/api/orders", "method": "POST",
                             "types": ["fetch"], "query_params": [], "body_params": []},
                        ],
                    )
                ]
            },
        )
        self.assertEqual(
            [path for path, _method, _params in self.endpoints()],
            ["/api/orders", self.script_path()],
        )

    def test_undeclared_method_is_not_recorded_as_get(self):
        """A call site with no method is not a GET.

        `register_endpoint` defaults an absent method to GET, which is right for
        a crawled page and wrong here: the engine did not observe a method, and
        recording GET would assert one. UNKNOWN keeps the distinction visible
        instead of answering a question the analysis never answered.
        """
        _ingest_target_result_once(
            self.project,
            {
                "pages": [
                    js_page(
                        "https://shop.example/assets/app.js",
                        [{"url": "/api/maybe", "method": "",
                          "types": ["stringLiteral"], "query_params": [], "body_params": []}],
                    )
                ]
            },
        )
        self.assertEqual(
            [(path, method) for path, method, _params in self.endpoints()],
            [("/api/maybe", "UNKNOWN"), (self.script_path(), "GET")],
        )

    def test_secret_value_reaches_the_project_bundle(self):
        """The value is kept, because the analyst has to be able to use it.

        This asserted the opposite before the owner's decision of 2026-09-30: a
        Project bundle is exported, shared and pasted into chats, and the engine
        used to reduce a secret to a rule name and a fingerprint. The reversal is
        deliberate — a key the analyst cannot read is a finding the analyst
        cannot use.

        What this pins is that the *evidence* survives the ingest. The value
        lives in the Target job result, which the bundle copies, and it is not
        written into `ProjectEndpoint`, which is a routing table and has no
        column for a credential.
        """
        secret_value = "AKIA4XQ7PLMN2ZKQWJ3d"
        result = {
            "pages": [
                js_page(
                    "https://shop.example/assets/app.js",
                    [{"url": "/api/v1/x", "method": "GET",
                      "types": ["fetch"], "query_params": [], "body_params": []}],
                    secrets=[
                        {
                            "rule": "aws_access_key_id",
                            "severity": "AWS access key id",
                            "value": secret_value,
                            "fingerprint": "AKIA4X…276136a5bb54",
                            "line": 12,
                            "kind": "AWSAccessKey",
                        }
                    ],
                )
            ]
        }
        _ingest_target_result_once(self.project, result)

        stored = ProjectEndpoint.objects.filter(project=self.project).first()
        # The endpoint is still indexed: a secret finding does not suppress the
        # file it was found in.
        self.assertEqual(stored.path, "/api/v1/x")
        # ProjectEndpoint is a routing table. A credential has no column there,
        # and putting one in would mean adding a column for a value that already
        # has a home.
        for field in ProjectEndpoint._meta.get_fields():
            self.assertNotIn(
                "value",
                field.name,
                f"ProjectEndpoint.{field.name} would hold a credential",
            )
        # The evidence itself is untouched by the ingest.
        self.assertIn(secret_value, str(result))

    def test_page_without_analysis_is_unchanged(self):
        """HTML, CSS and JSON carry no `js` key and must not be affected."""
        _ingest_target_result_once(
            self.project,
            {
                "pages": [
                    {"url": "https://shop.example/", "method": "GET", "status": 200,
                     "kind": "page"},
                    {"url": "https://shop.example/app.css", "method": "GET",
                     "status": 200, "kind": "stylesheet"},
                ]
            },
        )
        self.assertEqual(
            self.endpoints(),
            [("/", "GET", []), ("/app.css", "GET", [])],
        )

    def test_analysis_without_endpoints_is_harmless(self):
        """A parsed file with nothing in it must not raise or write."""
        _ingest_target_result_once(
            self.project,
            {"pages": [js_page("https://shop.example/app.js", [])]},
        )
        self.assertEqual(
            [path for path, _m, _p in self.endpoints()],
            ["/app.js"],
        )

    def test_malformed_analysis_is_skipped(self):
        """The page record is data from a Go process and can be anything.

        `js` as a string, `endpoints` as a dict, an entry as a string: none of
        these is a shape the engine emits, and none of them may raise inside an
        ingest that runs on a dashboard read.
        """
        for broken in (
            "not a dict",
            {"endpoints": {"a": "b"}},
            {"endpoints": ["a string, not a dict"]},
            {"endpoints": [{"url": None}]},
            {"endpoints": [{"url": "   "}]},
        ):
            with self.subTest(js=broken):
                _ingest_target_result_once(
                    self.project,
                    {"pages": [{"url": "https://shop.example/broken.js", "js": broken}]},
                )
        # Only the crawled file itself, and nothing invented from the broken part.
        self.assertEqual(
            [path for path, _m, _p in self.endpoints()],
            ["/broken.js"],
        )

    def test_non_http_reference_is_not_indexed(self):
        """A reference the crawler would never follow is not an endpoint."""
        _ingest_target_result_once(
            self.project,
            {
                "pages": [
                    js_page(
                        "https://shop.example/assets/app.js",
                        [
                            {"url": "mailto:ops@example.com", "method": "",
                             "types": ["stringLiteral"], "query_params": [], "body_params": []},
                            {"url": "data:text/html,x", "method": "",
                             "types": ["stringLiteral"], "query_params": [], "body_params": []},
                        ],
                    )
                ]
            },
        )
        self.assertEqual(
            [path for path, _m, _p in self.endpoints()],
            ["/assets/app.js"],
        )

    def test_javascript_secrets_are_indexed_into_project_secret(self):
        """Secrets discovered in JS analysis must be stored in ProjectSecret."""
        secret_value = "AKIAIOSFODNN7EXAMPLE"
        script_url = "https://shop.example/assets/bundle.js"
        result = {
            "pages": [
                js_page(
                    script_url,
                    [{"url": "/api/v1/x", "method": "GET",
                      "types": ["fetch"], "query_params": [], "body_params": []}],
                    secrets=[
                        {
                            "rule": "aws_access_key_id",
                            "severity": "AWS access key id",
                            "value": secret_value,
                            "fingerprint": "AKIAIO…1234",
                            "line": 42,
                            "kind": "AWSAccessKey",
                        }
                    ],
                )
            ]
        }
        _ingest_target_result_once(self.project, result)

        secret = ProjectSecret.objects.filter(project=self.project).first()
        self.assertIsNotNone(secret)
        self.assertEqual(secret.key_name, "aws_access_key_id")
        self.assertEqual(secret.secret_type, "api_key")
        self.assertEqual(secret.source_url, script_url)
        self.assertEqual(secret.value_ref, secret_value)

    def test_multiple_javascript_secrets_with_same_rule_are_disambiguated(self):
        """Multiple secrets matching the same rule on the same script must both be saved."""
        script_url = "https://shop.example/libs/dataTables.js"
        result = {
            "pages": [
                js_page(
                    script_url,
                    [],
                    secrets=[
                        {
                            "rule": "pinkerton_authorization_basic",
                            "severity": "Authorization Basic",
                            "value": "Basic initialisation",
                            "line": 79,
                        },
                        {
                            "rule": "pinkerton_authorization_basic",
                            "severity": "Authorization Basic",
                            "value": "basic index",
                            "line": 2378,
                        },
                    ],
                )
            ]
        }
        _ingest_target_result_once(self.project, result)

        secrets = list(
            ProjectSecret.objects.filter(project=self.project, source_url=script_url)
            .order_by("id")
            .values("key_name", "secret_type", "value_ref")
        )
        self.assertEqual(len(secrets), 2)
        self.assertEqual(secrets[0]["key_name"], "pinkerton_authorization_basic")
        self.assertEqual(secrets[0]["value_ref"], "Basic initialisation")
        self.assertEqual(secrets[1]["key_name"], "pinkerton_authorization_basic (line 2378)")
        self.assertEqual(secrets[1]["value_ref"], "basic index")
