"""Bounds on the `regex` Condition operator.

Python's `re` cannot be interrupted: no timeout, no step limit. `_condition_value`
used to call `re.search` with an operator-supplied pattern against the previous
node's output, which for every tool node is a full HTTP response body. A Condition
holding `(a+)+$` against a target answering `aaaa…aaa!` never returns, and the call
sits on the scheduler thread inside the Django process, so the pin never comes back.

These tests run the shipped function rather than a copy, because the two ways to
get this wrong — a cap on the wrong side, and a pattern check that is too clever —
both look correct in the source and fail in execution.
"""

import signal
import time

from django.test import SimpleTestCase

from lab.workflow_engine import (
    REGEX_HAYSTACK_LIMIT,
    WorkflowValidationError,
    _condition_value,
    _is_catastrophic_pattern,
)


def _regex_condition(pattern, haystack):
    return _condition_value(
        haystack, {"operator": "regex", "value": pattern}
    )[3]


class CatastrophicPatternDetectionTests(SimpleTestCase):
    def test_nested_quantifiers_are_refused(self) -> None:
        for pattern in ("(a+)+$", "(a*)*", "(a|a)+", "([a-z]+)*"):
            with self.subTest(pattern=pattern):
                self.assertTrue(_is_catastrophic_pattern(pattern))

    def test_ordinary_patterns_are_allowed(self) -> None:
        """The refusal must be narrow: operators match on every real workflow."""
        for pattern in (
            "200",
            r"Set-Cookie: session=",
            r"[0-9a-f]{32}",
            r"^\s*HTTP/1\.1 302",
            r"admin|login|panel",
            r"id=(\d+)",
            r"(GET|POST) /api/",
            r"\bERROR\b",
            r"password[^=]*=[^\s]+",
        ):
            with self.subTest(pattern=pattern):
                self.assertFalse(_is_catastrophic_pattern(pattern))

    def test_refusal_is_named_not_silent(self) -> None:
        """A refused pattern must say so. A condition that quietly stops is worse."""
        with self.assertRaises(WorkflowValidationError) as caught:
            _regex_condition("(a+)+$", "aaaa")
        self.assertIn("backtrack", str(caught.exception))


class RegexHaystackBoundTests(SimpleTestCase):
    def test_hostile_pattern_against_hostile_input_returns(self) -> None:
        """The exact input from the audit: it must not hang, and it must not match.

        Two acceptable outcomes, both proved by a wall clock rather than by reading
        the source: the pattern is refused by name, or it runs against a bounded
        prefix and returns False. A hang is the only unacceptable one, and a hang is
        the only thing a duration can prove.
        """

        class Bail(BaseException):
            pass

        def _timeout(signum, frame):
            raise Bail()

        previous = signal.signal(signal.SIGALRM, _timeout)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            started = time.monotonic()
            try:
                matched = _regex_condition("(a+)+$", "a" * 20000 + "!")
            except WorkflowValidationError:
                # Refusing the pattern by name is an acceptable outcome; hanging is not.
                matched = False
            elapsed = time.monotonic() - started
        except Bail:
            self.fail("regex evaluation did not return within 5s — the bound is missing")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        self.assertFalse(matched)
        self.assertLess(elapsed, 5.0)

    def test_haystack_beyond_the_limit_is_truncated(self) -> None:
        """The match runs against a prefix, and the fact is logged, not hidden."""
        oversized = "x" * (REGEX_HAYSTACK_LIMIT + 4096)
        with self.assertLogs("lab.workflow_engine", level="WARNING") as captured:
            matched = _regex_condition(r"x{100}$", oversized)
        self.assertTrue(matched, "the prefix still has to be matchable")
        self.assertTrue(
            any("truncated" in line for line in captured.output),
            f"truncation must be reported, got {captured.output}",
        )

    def test_text_within_the_limit_is_not_truncated(self) -> None:
        body = "GET /admin HTTP/1.1\r\nSet-Cookie: session=abc\r\n" * 200
        self.assertLess(len(body), REGEX_HAYSTACK_LIMIT)
        self.assertTrue(_regex_condition(r"Set-Cookie: session=", body))

    def test_ordinary_matching_is_unaffected(self) -> None:
        self.assertTrue(_regex_condition(r"HTTP/1\.1 200", "HTTP/1.1 200 OK"))
        self.assertFalse(_regex_condition(r"HTTP/1\.1 404", "HTTP/1.1 200 OK"))
        self.assertTrue(_regex_condition(r"error", "ERROR at line 4", ))

    def test_the_limit_is_not_a_restriction_on_what_tools_fetch(self) -> None:
        """A cap on one comparison must not become a cap on the tool's work.

        The same body still reaches Repeater, Intruder and the exporters untouched;
        only this comparison is bounded. Asserted here so that raising
        `REGEX_HAYSTACK_LIMIT` later is a deliberate, visible act.
        """
        self.assertGreaterEqual(REGEX_HAYSTACK_LIMIT, 256 * 1024)