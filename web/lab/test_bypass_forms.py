"""Tests for the 403-ladder selection the Target node forwards.

The helper exists because three states have to stay apart on the wire: the
operator never asked for a ladder, asked and chose nothing, and named specific
forms. A boolean holds two of those, and the third would silently become one of
the other two — so these tests pin the states rather than the formatting.
"""

from django.test import SimpleTestCase

from lab.views import (
    BYPASS_FORMS_MAX,
    BYPASS_FORM_NAME_MAX,
    _bypass_forms,
)
from lab.workflow_engine import WorkflowValidationError


class BypassFormsSelectionTests(SimpleTestCase):
    def test_absent_means_no_ladder_and_says_so_explicitly(self):
        """An absent key must be an empty selection, not a missing field.

        The engine reads length, so `None` and `[]` are not interchangeable there:
        one of them has to mean "off". Returning `[]` makes the off state a value
        that is actually transmitted.
        """
        for params in ({}, {"bypass_forms": None}, {"bypass_forms": ""}):
            with self.subTest(params=params):
                self.assertEqual(_bypass_forms(params), [])

    def test_named_forms_survive_in_order(self):
        forms = _bypass_forms({"bypass_forms": ["verb-post", "path-semicolon"]})
        self.assertEqual(forms, ["verb-post", "path-semicolon"])

    def test_a_single_string_is_one_form(self):
        """Node parameters arrive from a text field, so a bare string is real."""
        self.assertEqual(_bypass_forms({"bypass_forms": "verb-post"}), ["verb-post"])

    def test_blanks_are_dropped_and_names_are_trimmed(self):
        self.assertEqual(
            _bypass_forms({"bypass_forms": ["  verb-post  ", "", "   "]}), ["verb-post"]
        )

    def test_duplicates_are_removed_because_they_cost_a_request_each(self):
        """A repeated name would be sent twice and counted as two attempts."""
        self.assertEqual(
            _bypass_forms({"bypass_forms": ["verb-post", "verb-post", "verb-head"]}),
            ["verb-post", "verb-head"],
        )

    def test_a_wrong_type_names_the_parameter_instead_of_being_guessed(self):
        for bad in (5, {"a": 1}, object()):
            with self.subTest(bad=bad):
                with self.assertRaises(WorkflowValidationError) as caught:
                    _bypass_forms({"bypass_forms": bad})
                self.assertIn("bypass_forms", str(caught.exception))

    def test_a_non_string_entry_is_refused_rather_than_coerced(self):
        with self.assertRaises(WorkflowValidationError) as caught:
            _bypass_forms({"bypass_forms": ["verb-post", 7]})
        self.assertIn("bypass_forms", str(caught.exception))

    def test_an_over_long_name_is_refused_with_the_bound_named(self):
        with self.assertRaises(WorkflowValidationError) as caught:
            _bypass_forms({"bypass_forms": ["x" * (BYPASS_FORM_NAME_MAX + 1)]})
        message = str(caught.exception)
        self.assertIn(str(BYPASS_FORM_NAME_MAX), message)

    def test_too_many_forms_is_refused_with_the_count_named(self):
        forms = [f"form-{index}" for index in range(BYPASS_FORMS_MAX + 1)]
        with self.assertRaises(WorkflowValidationError) as caught:
            _bypass_forms({"bypass_forms": forms})
        message = str(caught.exception)
        self.assertIn(str(BYPASS_FORMS_MAX), message)
        self.assertIn(str(BYPASS_FORMS_MAX + 1), message)

    def test_the_bound_does_not_reach_the_last_allowed_name(self):
        """The bound refuses more than it allows, which is the point of a bound.

        A limit that also rejects the last legal value is not a limit, it is an
        off-by-one that hides a valid request.
        """
        at_limit = [f"form-{index}" for index in range(BYPASS_FORMS_MAX)]
        self.assertEqual(len(_bypass_forms({"bypass_forms": at_limit})), BYPASS_FORMS_MAX)
        longest_name = "y" * BYPASS_FORM_NAME_MAX
        self.assertEqual(_bypass_forms({"bypass_forms": [longest_name]}), [longest_name])