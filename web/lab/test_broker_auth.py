"""HMAC authentication for the broker envelopes (audit A06-04).

The broker has no authentication: any local process could LPUSH a well-formed
envelope naming a live task_id. These tests pin the signature scheme at the value
level, including the cross-language vector both sides must agree on byte for byte.
"""

import hashlib
import hmac
import json
import os
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from lab.broker_auth import (
    KEY_ENV,
    canonical_bytes,
    sign_envelope,
    signing_enabled,
    verify_envelope_signature,
)
from lab.engine_task_contract import EngineTaskContractError

#: The cross-language vector. The same envelope, key and expected signature are
#: asserted in `engine/broker_auth_test.go`: if either side renders the canonical
#: form differently, one of the two suites goes red. The payload deliberately
#: contains `<`, `>` and non-ASCII, which is where two JSON encoders disagree.
TEST_KEY = "0123456789abcdef" * 4
TEST_ENVELOPE = {
    "created_at": "2026-09-27T09:00:00Z",
    "payload": {
        "note": "<b>ü</b>",
        "url": "http://127.0.0.1:8000/fixture?a=1&b=2",
    },
    "project_id": 7,
    "route_generation": 1,
    "schema_version": 1,
    "task_id": "6f0e8400-e29b-41d4-a716-446655440000",
    "task_type": "target.crawl",
}
TEST_SIG = "cd3c6f6cd2e88639d34c40fe5be144f5dfc7025c7763429579234fe2f7d10109"


def _with_key():
    return patch.dict(os.environ, {KEY_ENV: TEST_KEY})


class CanonicalFormTests(SimpleTestCase):
    def test_keys_are_sorted_and_separators_are_compact(self) -> None:
        self.assertEqual(
            canonical_bytes({"b": 1, "a": [1, 2]}),
            b'{"a":[1,2],"b":1}',
        )

    def test_sig_is_excluded_from_what_is_signed(self) -> None:
        """Otherwise verification could never reproduce the signed bytes."""
        message = dict(TEST_ENVELOPE)
        message["sig"] = "whatever"
        self.assertEqual(canonical_bytes(message), canonical_bytes(TEST_ENVELOPE))

    def test_cross_language_vector(self) -> None:
        """The exact bytes both implementations must sign.

        If Go renders `<`, `>` or `ü` differently, its suite fails on the same
        vector — that is the whole point of pinning it here rather than only
        asserting a roundtrip.
        """
        self.assertEqual(
            canonical_bytes(TEST_ENVELOPE).decode("utf-8"),
            '{"created_at":"2026-09-27T09:00:00Z",'
            '"payload":{"note":"<b>\\u00fc</b>",'
            '"url":"http://127.0.0.1:8000/fixture?a=1&b=2"},'
            '"project_id":7,"route_generation":1,"schema_version":1,'
            '"task_id":"6f0e8400-e29b-41d4-a716-446655440000",'
            '"task_type":"target.crawl"}'.replace("\\u00fc", "ü"),
        )

    def test_cross_language_signature(self) -> None:
        with _with_key():
            signed = sign_envelope(TEST_ENVELOPE)
        self.assertEqual(signed["sig"], TEST_SIG)


class SignVerifyTests(SimpleTestCase):
    def test_roundtrip(self) -> None:
        with _with_key():
            signed = sign_envelope(TEST_ENVELOPE)
            verify_envelope_signature(signed)

    def test_sign_does_not_mutate_its_input(self) -> None:
        original = dict(TEST_ENVELOPE)
        with _with_key():
            sign_envelope(original)
        self.assertEqual(original, TEST_ENVELOPE)

    def test_tampered_payload_is_rejected(self) -> None:
        """A forgery has the right shape by construction — only the signature
        tells it apart. Changing one byte anywhere must fail verification."""
        with _with_key():
            signed = sign_envelope(TEST_ENVELOPE)
            signed["payload"] = dict(signed["payload"])
            signed["payload"]["project_id"] = 8
            with self.assertRaises(EngineTaskContractError) as caught:
                verify_envelope_signature(signed)
            self.assertIn("BAD_SIGNATURE", str(caught.exception))

    def test_missing_signature_is_rejected_when_key_is_set(self) -> None:
        with _with_key():
            with self.assertRaises(EngineTaskContractError) as caught:
                verify_envelope_signature(dict(TEST_ENVELOPE))
            self.assertIn("BAD_SIGNATURE", str(caught.exception))

    def test_wrong_key_is_rejected(self) -> None:
        with _with_key():
            signed = sign_envelope(TEST_ENVELOPE)
        with patch.dict(os.environ, {KEY_ENV: "ff" * 32}):
            with self.assertRaises(EngineTaskContractError):
                verify_envelope_signature(signed)

    def test_compat_mode_accepts_unsigned_without_a_key(self) -> None:
        """Stacks that have not generated a key yet keep working, loudly."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(KEY_ENV, None)
            self.assertFalse(signing_enabled())
            self.assertEqual(sign_envelope(TEST_ENVELOPE), TEST_ENVELOPE)
            verify_envelope_signature(dict(TEST_ENVELOPE))

    def test_malformed_key_is_compat_mode(self) -> None:
        """A typo must not brick the stack, and must not halve the key."""
        with patch.dict(os.environ, {KEY_ENV: "not-hex"}):
            self.assertFalse(signing_enabled())


class PersistRejectsForgeriesTests(TestCase):
    """A forged result must die in validation, before any row moves.

    The consumer turns `EngineTaskContractError` into a dead-letter, so raising
    here is what keeps the forgery as evidence instead of letting it advance a
    real run.
    """

    def _task(self):
        import uuid

        from lab.models import EngineTask

        return EngineTask.objects.create(
            task_id=uuid.uuid4(),
            task_type="request.execute",
            status="published",
            payload={"url": "http://127.0.0.1:8000/fixture"},
        )

    def _result(self, task, event_id=None):
        import uuid

        return {
            "schema_version": 1,
            "task_id": str(task.task_id),
            "event_id": str(event_id or uuid.uuid4()),
            "state": "completed",
            "occurred_at": "2026-09-27T09:00:02Z",
            "result": {"pages": []},
        }

    def test_forged_result_is_rejected_when_key_is_set(self) -> None:
        from lab.engine_broker import persist_engine_result

        task = self._task()
        with _with_key():
            with self.assertRaises(EngineTaskContractError) as caught:
                persist_engine_result(self._result(task))
            self.assertIn("BAD_SIGNATURE", str(caught.exception))
        task.refresh_from_db()
        self.assertEqual(task.status, "published")

    def test_signed_result_is_persisted(self) -> None:
        from lab.engine_broker import persist_engine_result

        task = self._task()
        with _with_key():
            message = sign_envelope(self._result(task))
            saved, created = persist_engine_result(message)
        self.assertTrue(created)
        self.assertEqual(saved.status, "completed")

    def test_unsigned_result_still_works_without_a_key(self) -> None:
        """Compatibility mode: stacks without a key keep their current behavior."""
        import os

        from lab.engine_broker import persist_engine_result

        task = self._task()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(KEY_ENV, None)
            _saved, created = persist_engine_result(self._result(task))
        self.assertTrue(created)
