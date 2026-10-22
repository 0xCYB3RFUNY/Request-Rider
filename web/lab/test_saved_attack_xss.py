"""Regression tests for the stored XSS in the saved-Attack transformation chain.

Measured, not theoretical. The chain that carried the payload was:

    POST /api/intruder/saved   transformations accepted as an arbitrary JSON list
    web/lab/models.py          IntruderAttack.transformations (JSONField) stores it
    intruder_saved_item()      returns the list verbatim to the browser
    index.html                 renderTransformations() wrote `transform.operation`
                               into innerHTML without escaping

so a saved attack whose transformation name read `<img src=x onerror=…>` became a
live element in the operator's session and executed when the attack was loaded.
The live run recorded `document.title === "PWNED"` and `window.__XSS_PROBE === 1`.

These tests hold both halves of the fix:

  * the storage side rejects a name the engine could never execute, so a poisoned
    row is never written;
  * the render side escapes the name, so a row that predates the check, or arrives
    through a project import, still cannot execute.

The render assertion is checked against the page source rather than by running a
browser, because what it guards is precisely the absence of an `escapeHTML` call —
a source-level property that a live DOM test would only observe indirectly.
"""

import json
import re
from pathlib import Path

from django.conf import settings
from django.test import TestCase

from lab.models import IntruderAttack
from lab.views import INTRUDER_TRANSFORM_OPERATIONS, _validate_saved_transformations

PAGE = Path(settings.BASE_DIR) / "templates" / "lab" / "index.html"

XSS_OPERATION = "<img src=x onerror=window.__XSS_PROBE=1>"


class SavedTransformationValidationTests(TestCase):
    """The API refuses a transformation name the engine cannot execute."""

    def test_markup_in_operation_is_rejected(self) -> None:
        """The measured payload: an onerror attribute in the operation name."""
        with self.assertRaises(ValueError) as caught:
            _validate_saved_transformations([{"operation": XSS_OPERATION, "value": ""}])
        self.assertIn("operation must be one of", str(caught.exception))

    def test_script_tag_in_operation_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _validate_saved_transformations([{"operation": "<script>alert(1)</script>"}])

    def test_operation_must_be_a_string(self) -> None:
        with self.assertRaises(ValueError):
            _validate_saved_transformations([{"operation": {"nested": "object"}}])

    def test_entry_must_be_an_object(self) -> None:
        with self.assertRaises(ValueError):
            _validate_saved_transformations(["urlEncode"])

    def test_value_must_be_a_string(self) -> None:
        with self.assertRaises(ValueError):
            _validate_saved_transformations([{"operation": "urlEncode", "value": 12}])

    def test_unknown_name_alongside_a_valid_one_rejects_the_whole_list(self) -> None:
        """A partial save would run fewer steps than the request asked for.

        Dropping the unknown entry instead of failing would hand the operator an
        attack that silently skips a transformation, and the difference would only
        surface in the payloads — so the whole list is refused.
        """
        with self.assertRaises(ValueError):
            _validate_saved_transformations(
                [{"operation": "urlEncode"}, {"operation": XSS_OPERATION}]
            )

    def test_known_operations_pass_through_unchanged(self) -> None:
        payload = [
            {"operation": "urlEncode", "value": "a b"},
            {"operation": "base64Decode"},
            {"operation": "hexDecode", "value": "68656c6c6f"},
        ]
        self.assertEqual(_validate_saved_transformations(payload), payload)

    def test_empty_value_is_omitted_so_the_stored_shape_matches_the_ui(self) -> None:
        """The UI writes `{operation}` for a step with no argument.

        Normalising here keeps a saved definition byte-comparable with the one the
        page would have sent, so a re-run does not depend on storage details.
        """
        self.assertEqual(
            _validate_saved_transformations([{"operation": "urlEncode", "value": ""}]),
            [{"operation": "urlEncode"}],
        )

    def test_every_allowed_operation_is_one_the_engine_implements(self) -> None:
        """The allowlist and the engine must not drift apart.

        A name here that `intruder.TransformPayload` does not implement would be
        stored, rendered, and then fail at run time — the row would exist only to
        produce an error later.
        """
        engine_source = (
            Path(settings.BASE_DIR).parent / "engine" / "pkg" / "intruder" / "intruder.go"
        ).read_text()
        for operation in INTRUDER_TRANSFORM_OPERATIONS:
            self.assertIn(
                f'case "{operation}":',
                engine_source,
                f"{operation} is allowed by the API but not implemented by the engine",
            )

    def test_extra_keys_are_not_carried_into_storage(self) -> None:
        """Only the two fields the engine reads are kept.

        A saved definition is returned to the browser verbatim, so an extra key
        would travel from the request into the page without the renderer having
        any say in whether it is displayed.
        """
        validated = _validate_saved_transformations(
            [{"operation": "urlEncode", "value": "x", "injected": "payload"}]
        )
        self.assertEqual(validated, [{"operation": "urlEncode", "value": "x"}])


class SavedAttackEndpointRejectsPayloadTests(TestCase):
    """The HTTP path refuses the payload instead of storing it."""

    def test_post_saved_attack_with_markup_operation_is_rejected(self) -> None:
        response = self.client.post(
            "/api/intruder/saved",
            data=json.dumps(
                {
                    "name": "xss-probe",
                    "mode": "sniper",
                    "base_request": {
                        "method": "GET",
                        "url": "http://example.com/",
                        "headers": {},
                        "body": "",
                    },
                    "payloads": [["a"]],
                    "transformations": [{"operation": XSS_OPERATION, "value": ""}],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("operation must be one of", response.json()["error"])
        self.assertEqual(
            IntruderAttack.objects.count(),
            0,
            "a rejected definition must not leave a row behind",
        )


class TransformationRendererEscapesTests(TestCase):
    """The renderer escapes the operation name, so an old row cannot execute.

    This is the half of the fix that survives data which predates validation: a
    definition saved before the allowlist existed, or imported with a project
    bundle, still reaches `renderTransformations()`.
    """

    def setUp(self) -> None:
        self.source = PAGE.read_text()

    def _renderer_body(self) -> str:
        start = self.source.index("function renderTransformations()")
        end = self.source.index("function ", start + 10)
        return self.source[start:end]

    def test_operation_is_passed_through_escapehtml(self) -> None:
        body = self._renderer_body()
        # Every other value in this row is already escaped; the operation is the
        # one that was not, and that gap is the vulnerability.
        self.assertRegex(
            body,
            r"escapeHTML\(transform\.operation\)",
            "renderTransformations must escape transform.operation",
        )

    def test_operation_is_not_interpolated_raw(self) -> None:
        """Every interpolation mentioning the operation must be wrapped.

        Checking the negative case is what makes this a test rather than a restate
        of the fix: an interpolation that is exactly `${transform.operation}`
        passes the positive assertion's search for `escapeHTML(...)` nowhere near,
        and it is the shape the live exploit used.
        """
        body = self._renderer_body()
        for expression in re.findall(r"\$\{([^}]*)\}", body):
            if "transform.operation" not in expression:
                continue
            self.assertRegex(
                expression.strip(),
                r"^escapeHTML\(",
                f"transform.operation reaches the DOM unescaped: ${{{expression}}}",
            )

    def test_the_escape_covers_the_five_markup_characters(self) -> None:
        """`escapeHTML` is the project's single escaping helper; a partial one
        would leave a path open. Asserting the character class here means a
        future change to the helper cannot quietly narrow it for this call site.
        """
        match = re.search(r"function escapeHTML\(value\) \{\s*return [^;]+;", self.source)
        self.assertIsNotNone(match, "escapeHTML helper not found")
        for character in ("&", "<", ">", '"', "'"):
            self.assertIn(character, match.group(0))
