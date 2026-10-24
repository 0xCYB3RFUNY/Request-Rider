"""The add-entity dialog has to say what a type can be asked, in both languages.

Measured 2026-10-01 against the engine registry: three of the nine graph types —
``cidr``, ``asn`` and ``technology`` — are accepted by no transform at all, so a
node of those types can never be enriched. Before this the only place that fact
appeared was the node menu, which means after the record already existed.

Two things have to hold, and they fail independently:

1. the hint is computed from the live registry, so a type that starts being
   accepted loses the warning without anyone editing the dialog;
2. the hint is a visible string, so switching language has to redraw it. It is
   rendered imperatively rather than through ``data-i18n``, so ``applyLanguage``
   does not reach it and the toggle hook has to.
"""

import re
import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "lab" / "index.html"

# The types the registry accepts nothing for, measured 2026-10-01.
INERT_TYPES = ("cidr", "asn", "technology")


def _strip_line_comments(body: str) -> str:
    """Drop `//` comments so a test reads code, not the prose around it."""
    return "\n".join(re.sub(r"//.*$", "", line) for line in body.splitlines())


def _function_body(template: str, name: str) -> str:
    match = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", template)
    if match is None:
        raise AssertionError(f"{name} is not declared in the template")
    depth = 0
    for index in range(match.end() - 1, len(template)):
        if template[index] == "{":
            depth += 1
        elif template[index] == "}":
            depth -= 1
            if depth == 0:
                return template[match.end() : index]
    raise AssertionError(f"{name} has no closing brace")


class OsintEntityTypeHintTests(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE.read_text(encoding="utf-8")

    def test_the_dialog_carries_a_hint_element(self):
        self.assertIn(
            'data-role="type-hint"',
            _function_body(self.template, "requestOsintEntityDialog"),
            "the add-entity dialog has nowhere to state what the type can be asked",
        )

    def test_the_hint_comes_from_the_registry_not_from_a_list(self):
        body = _function_body(self.template, "updateOsintEntityTypeHint")
        self.assertIn(
            "osintTransformsForType",
            body,
            "the hint must ask the registry, otherwise a transform that starts "
            "accepting a type keeps warning about it",
        )
        for inert in INERT_TYPES:
            self.assertNotIn(
                f"'{inert}'",
                body,
                f"{inert} is hard-coded in the hint, so the registry and the "
                "dialog can disagree about it",
            )

    def test_switching_language_redraws_the_hint(self):
        """The failure this exists for: the hint keeps the previous language."""
        self.assertIn(
            "if (typeof updateOsintEntityTypeHint === 'function') updateOsintEntityTypeHint();",
            self.template,
            "the language toggle does not redraw the hint, so a string rendered "
            "imperatively stays in the language it was written in",
        )

    def test_the_hint_is_found_before_the_dialog_is_open(self):
        """The failure this exists for, and the one the first version had.

        ``updateOsintEntityTypeHint`` selects the hint through the dialog. A
        selector that requires ``dialog[open]`` finds nothing on the first call,
        because that call happens before ``showModal()`` — so the hint stayed
        blank on exactly the open the operator is looking at, while the same
        function worked on a later language change. Nothing threw, and the
        registry was consulted either way, so the other three tests stayed green.
        """
        # Comments are stripped first: the fix carries a comment that names
        # `dialog[open]` to explain why the selector is not that, and a raw
        # substring test would fail on its own explanation.
        body = _strip_line_comments(_function_body(self.template, "updateOsintEntityTypeHint"))
        self.assertNotIn(
            "dialog[open]",
            body,
            "the hint is looked up through dialog[open], so the call that runs "
            "before showModal() finds nothing and the hint is blank on first open",
        )
        self.assertIn(
            'dialog [data-role="type-hint"]',
            body,
            "the hint must be found regardless of the dialog's open state",
        )

    def test_the_first_render_is_asked_for_explicitly(self):
        dialog = _function_body(self.template, "requestOsintEntityDialog")
        self.assertIn(
            "updateOsintEntityTypeHint()",
            dialog,
            "opening the dialog never asks for the hint, so it is written only "
            "when something else happens to trigger it",
        )

    def test_both_languages_define_the_hint_strings(self):
        for key in ("osint.transformsForType", "osint.transformsTypeInert"):
            definitions = re.findall(
                r"'" + re.escape(key) + r"'\s*:\s*'([^']*)'", self.template
            )
            self.assertEqual(
                len(definitions),
                2,
                f"{key} must be defined once per language dictionary, found {len(definitions)}",
            )
            uk, en = definitions
            self.assertTrue(uk.strip(), f"{key} is empty in Ukrainian")
            self.assertTrue(en.strip(), f"{key} is empty in English")
            self.assertNotEqual(
                uk,
                en,
                f"{key} is identical in both dictionaries, so one of them is not "
                "a translation",
            )
