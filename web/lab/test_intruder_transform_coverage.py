"""The gateway must accept every transformation the engine runs and the panel offers.

Measured defect, 2026-10-02. The allowlist in `views.py` held eight operations
while `intruder.TransformPayload` implemented nineteen and the transformation
control in the page offered thirteen. An operator who picked `append` — a choice
the panel itself made — was answered `invalid JSON` by `/api/intruder`, which is
a statement about their request and not about the field that was actually wrong.

Two lists are read from the sources themselves rather than restated here, because
a restatement is exactly what went wrong: the Go switch and the HTML `<option>`
list. A name that exists in the engine but not on the panel is not a defect — the
panel is free to offer a subset — while a name on the panel that the gateway
rejects is an operator hitting a wall they cannot see.
"""

from __future__ import annotations

import pathlib
import re
import unittest

from django.test import SimpleTestCase

from lab.views import INTRUDER_TRANSFORM_OPERATIONS, _validate_saved_transformations

ENGINE_DIR = pathlib.Path(__file__).resolve().parents[2] / "engine" / "pkg" / "intruder"
TEMPLATE = pathlib.Path(__file__).resolve().parents[1] / "templates" / "lab" / "index.html"


def engine_transform_operations() -> set[str]:
    """Read the operations out of `TransformPayload`'s own switch."""
    source = ENGINE_DIR.joinpath("intruder.go").read_text(encoding="utf-8")
    body = source.split("func TransformPayload", 1)[1]
    body = body.split("\nfunc ", 1)[0]
    return set(re.findall(r'case "([A-Za-z0-9]+)":', body))


def panel_transform_operations() -> set[str]:
    """Read the operations out of the transformation control in the page."""
    markup = TEMPLATE.read_text(encoding="utf-8")
    if 'id="transform-operation"' not in markup:
        intruder_tab = TEMPLATE.parent / "tabs" / "_intruder.html"
        if intruder_tab.exists():
            markup += "\n" + intruder_tab.read_text(encoding="utf-8")
    select = markup.split('id="transform-operation"', 1)[1].split("</select>", 1)[0]
    return set(re.findall(r'<option value="([A-Za-z]+)"', select))


class IntruderTransformationCoverageTests(SimpleTestCase):
    def test_the_engine_runs_what_the_gateway_accepts(self):
        engine = engine_transform_operations()
        accepted = set(INTRUDER_TRANSFORM_OPERATIONS)
        self.assertEqual(
            accepted - engine,
            set(),
            "the gateway accepts operations the engine cannot run, which would "
            "store a row that renders but never executes",
        )
        self.assertEqual(
            engine - accepted,
            set(),
            "the engine runs operations the gateway rejects, so an operator is "
            "refused a transformation the tool actually has",
        )

    def test_the_panel_offers_only_what_the_gateway_accepts(self):
        offered = panel_transform_operations()
        self.assertTrue(offered, "no transformation control was found in the page")
        self.assertEqual(
            offered - set(INTRUDER_TRANSFORM_OPERATIONS),
            set(),
            "the panel offers transformations the gateway answers with "
            "'invalid JSON'",
        )

    def test_every_engine_operation_survives_validation(self):
        # `prepend` and `append` need a value; the rest must still pass with the
        # value omitted, because a panel that shows the field only for those two
        # sends `{"operation": "…"}` for everything else.
        for operation in sorted(engine_transform_operations()):
            for payload in ({"operation": operation}, {"operation": operation, "value": "x"}):
                with self.subTest(operation=operation, payload=payload):
                    self.assertEqual(
                        _validate_saved_transformations([payload]),
                        [payload if payload.get("value") else {"operation": operation}],
                    )

    def test_an_unknown_operation_is_still_refused(self):
        # The allowlist is a storage guard against a stored XSS, so widening it
        # must not have turned it into "accept anything".
        with self.assertRaises(ValueError):
            _validate_saved_transformations([{"operation": "<img src=x onerror=alert(1)>"}])
        with self.assertRaises(ValueError):
            _validate_saved_transformations([{"operation": "urlEncode", "value": 7}])
        with self.assertRaises(ValueError):
            _validate_saved_transformations(["urlEncode"])