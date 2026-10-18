"""The outline of a graph node has to be one the canvas can actually hit.

Measured 2026-10-01 in the live browser against the vendored Cytoscape 3.33.1,
holding one node at the same coordinates and changing only `shape`:

    round-rectangle   contextmenu + cxttap fired, menu opened
    ellipse          contextmenu + cxttap fired, menu opened
    hexagon          contextmenu + cxttap fired, menu opened
    diamond          no event, no menu
    round-diamond    no event, no menu

Those last two are drawn as a compound, so the hit test finds nothing where the
operator is pointing. The cost was not a missing icon: a `url` or `cidr` entity
had no entity details and no transform menu, which made the transforms that
accept those two types unreachable from the graph.

This test holds the list of outlines that were measured to be clickable. It
fails when an unmeasured one is added, because adding a shape nobody clicked is
exactly how the two broken outlines came back.
"""

import re
import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "lab" / "index.html"

# Measured clickable in the browser on 2026-10-01. `star`, `barrel`,
# `cut-rectangle`, `rectangle`, `triangle` and `heptagon` exist in the bundle but
# were never clicked, so they are not on this list: an outline has to be proven,
# not assumed.
CLICKABLE_SHAPES = frozenset({
    "round-rectangle",
    "ellipse",
    "hexagon",
    "round-tag",
    "pentagon",
    "octagon",
    "concave-hexagon",
    "vee",
})

ENTITY_TYPES = (
    "domain",
    "subdomain",
    "ip",
    "cidr",
    "url",
    "email",
    "username",
    "asn",
    "technology",
    "cloud_asset",
    "profile",
)


def _shape_table(template: str) -> dict:
    match = re.search(
        r"const\s+OSINT_GRAPH_TYPE_SHAPES\s*=\s*\{(.*?)\}", template, re.S
    )
    if match is None:
        raise AssertionError("OSINT_GRAPH_TYPE_SHAPES is not declared in the template")
    shapes = {}
    for entry in re.finditer(r"(\w+)\s*:\s*'([a-z-]+)'", match.group(1)):
        shapes[entry.group(1)] = entry.group(2)
    return shapes


class OsintGraphShapeTests(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE.read_text(encoding="utf-8")
        self.shapes = _shape_table(self.template)

    def test_every_entity_type_has_an_outline(self):
        """A type with no outline draws nothing, and an untyped node is a hole
        in the graph the operator cannot see or click."""
        for entity_type in ENTITY_TYPES:
            with self.subTest(entity_type=entity_type):
                self.assertIn(entity_type, self.shapes)

    def test_every_outline_was_measured_clickable(self):
        """This is the test that fails when a broken outline returns."""
        for entity_type, shape in sorted(self.shapes.items()):
            with self.subTest(entity_type=entity_type, shape=shape):
                self.assertIn(
                    shape,
                    CLICKABLE_SHAPES,
                    f"{entity_type} uses the {shape!r} outline, which was not "
                    "measured to be clickable; click it in the browser and add it "
                    "to CLICKABLE_SHAPES only after that",
                )

    def test_the_two_measured_broken_outlines_are_absent(self):
        """Named separately so the failure says which defect came back and where
        it was measured, instead of only listing a set difference."""
        for shape in ("diamond", "round-diamond"):
            with self.subTest(shape=shape):
                offenders = sorted(
                    entity_type
                    for entity_type, used in self.shapes.items()
                    if used == shape
                )
                self.assertEqual(
                    offenders,
                    [],
                    f"the {shape!r} outline is not clickable in Cytoscape 3.33.1; "
                    f"used by {offenders}",
                )
