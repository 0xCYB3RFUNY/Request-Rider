"""A04-08 (LOW) — the provider validator accepted `http`.

The request that goes to an AI provider carries two things worth stealing: the provider
API key in `Authorization: Bearer`, and `attached_evidence`, which is the analyst's raw
target exchanges — headers, cookies, the target's own `Authorization`, bodies. Over plain
`http` both cross the network in clear, to whatever host the endpoint names.

The finding called this Low because every shipped preset defaults to `https` for the real
providers, so it took a deliberate operator action. The fix has to keep the project's own
documented local setup working: `AGENT_LLM_ENDPOINT` points at a local model server, which
is loopback or the `engine` service on the compose network.
"""

import os
import unittest
from unittest import mock

from lab.agent_services import (
    AgentProviderError,
    _insecure_transport_allowed,
    _is_loopback,
    _validate_provider_endpoint,
)


class PlaintextEndpointTests(unittest.TestCase):
    def test_a_remote_plaintext_endpoint_is_refused(self) -> None:
        for endpoint in (
            "http://api.openai.com/v1/chat/completions",
            "http://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            "http://10.0.0.5:11434/v1/chat/completions",
            "http://example.test/v1",
        ):
            with self.subTest(endpoint=endpoint):
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("RR_AGENT_ALLOW_INSECURE_PROVIDER", None)
                    with self.assertRaises(AgentProviderError) as caught:
                        _validate_provider_endpoint(endpoint, "openai")
                message = str(caught.exception)
                self.assertIn("https", message, "the refusal must say what to do instead")

    def test_https_is_always_allowed(self) -> None:
        for endpoint in (
            "https://api.openai.com/v1/chat/completions",
            "https://api.anthropic.com/v1/messages",
            "https://openrouter.ai/api/v1/chat/completions",
        ):
            with self.subTest(endpoint=endpoint):
                _validate_provider_endpoint(endpoint, "openai")

    def test_loopback_plaintext_still_works(self) -> None:
        """The project's documented local setup must keep working; a control that breaks
        it gets switched off rather than satisfied."""
        # Bracketed for the IPv6 forms: `http://::1:8104/` does not parse as a URL with
        # that host, so an unbracketed literal would be testing nothing.
        for host in ("127.0.0.1", "localhost", "[::1]", "127.9.9.9"):
            with self.subTest(host=host):
                os.environ.pop("RR_AGENT_ALLOW_INSECURE_PROVIDER", None)
                _validate_provider_endpoint(f"http://{host}:8104/v1", "ollama")

    def test_the_operator_can_choose_plaintext_deliberately(self) -> None:
        """A limit nobody can change is the thing the project forbids."""
        with mock.patch.dict(os.environ, {"RR_AGENT_ALLOW_INSECURE_PROVIDER": "1"}):
            self.assertTrue(_insecure_transport_allowed())
            _validate_provider_endpoint("http://llm.example.test/v1", "openai")

    def test_the_override_is_not_a_substring_match(self) -> None:
        for value in ("0", "", "no", "false", "off", "maybe", "1x", "true1"):
            with self.subTest(value=value):
                with mock.patch.dict(os.environ, {"RR_AGENT_ALLOW_INSECURE_PROVIDER": value}):
                    self.assertFalse(
                        _insecure_transport_allowed(),
                        f"{value!r} was read as consent",
                    )

    def test_the_override_also_covers_a_private_network_host(self) -> None:
        """The compose network case: `engine:8104` is not loopback from the browser's point
        of view, so it needs the explicit flag rather than a loopback exemption."""
        os.environ.pop("RR_AGENT_ALLOW_INSECURE_PROVIDER", None)
        with self.assertRaises(AgentProviderError):
            _validate_provider_endpoint("http://engine:8104/v1", "openai_compatible")


class LoopbackDetectionTests(unittest.TestCase):
    def test_it_distinguishes_loopback_from_lookalikes(self) -> None:
        cases = {
            "127.0.0.1": True,
            "127.255.255.254": True,
            "::1": True,
            "[::1]": True,
            "localhost": True,
            "10.0.0.1": False,
            "192.168.1.1": False,
            "example.test": False,
            # A name that merely *contains* a loopback address must not qualify: an
            # attacker-controlled DNS name like `127.0.0.1.example.test` would otherwise
            # earn a plaintext exemption.
            "127.0.0.1.example.test": False,
            "localhost.example.test": False,
            "": False,
            None: False,
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(_is_loopback(host), expected)


class UnchangedContractTests(unittest.TestCase):
    def test_a_non_http_url_is_still_refused(self) -> None:
        """The original rule stays: this fix adds a condition, it does not replace one."""
        for endpoint in ("ftp://example.test/v1", "file:///etc/passwd", "not-a-url", "", None):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(AgentProviderError):
                    _validate_provider_endpoint(endpoint, "openai")

    def test_every_shipped_preset_is_https_or_loopback(self) -> None:
        """The presets are what make this Low, and the first version of this test asserted
        "all https" — which was **false**: the `ollama` preset is
        `http://127.0.0.1:11434/v1/chat/completions`. The accurate invariant is the one that
        matters: no shipped preset puts a key on the wire to a remote host in clear.

        Correcting the assertion rather than the code is the point: the code was right to
        exempt loopback, and the test was wrong about which presets that covers."""
        from urllib.parse import urlsplit

        from lab.agent_services import PROVIDER_PRESETS

        exposed = []
        for name, preset in PROVIDER_PRESETS.items():
            parsed = urlsplit(preset[1])
            if parsed.scheme == "https":
                continue
            if not _is_loopback(parsed.hostname):
                exposed.append(f"{name} -> {preset[1]}")
        self.assertEqual(exposed, [], f"presets sending a key in clear: {exposed}")

    def test_the_ollama_preset_still_validates(self) -> None:
        """The one shipped plaintext preset, end to end through the validator."""
        from lab.agent_services import PROVIDER_PRESETS

        os.environ.pop("RR_AGENT_ALLOW_INSECURE_PROVIDER", None)
        _validate_provider_endpoint(PROVIDER_PRESETS["ollama"][1], "ollama")