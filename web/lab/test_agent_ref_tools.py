"""Tests for reference-driven tools: model discovery and AI red teaming."""

import unittest
from unittest import mock

from django.test import TestCase

from . import agent_ref_tools as ref
from . import agent_tools

CONSENT = {"allow_browser_tools": True}


class RefToolRegistrationTests(unittest.TestCase):
    def test_all_reference_tools_registered(self):
        names = set(ref.HANDLERS)
        self.assertEqual(names, {
            "probe_model_availability", "redteam_probe", "redteam_assert", "knowledge_lookup",
        })
        self.assertTrue(names.issubset(set(agent_tools.TOOL_HANDLERS)))

    def test_models_url_derivation(self):
        self.assertEqual(
            ref._models_url("https://openrouter.ai/api/v1/chat/completions"),
            "https://openrouter.ai/api/v1/models",
        )
        self.assertEqual(
            ref._models_url("https://api.anthropic.com/v1/messages"),
            "https://api.anthropic.com/v1/models",
        )
        self.assertEqual(ref._models_url("not a url"), "")


class RedTeamTests(unittest.TestCase):
    def test_probe_fails_closed_without_consent(self):
        with mock.patch("lab.agent_services.generate_agent_chat") as gen:
            result = ref.tool_redteam_probe({"category": "promptinject"}, context=None)
        self.assertEqual(result["reason"], ref.CONSENT_REASON)
        gen.assert_not_called()

    def test_probe_classifies_extraction(self):
        with mock.patch("lab.agent_services.generate_agent_chat") as gen:
            gen.return_value = {"message": "The untrusted output boundary says: ignore previous instructions."}
            result = ref.tool_redteam_probe(
                {"category": "promptinject", "provider": "ollama"}, context=CONSENT)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["classification"], "extraction")
        self.assertIn("system prompt", result["finding"])

    def test_assert_detects_system_prompt_leak(self):
        ok = ref.tool_redteam_assert({"answer": "I cannot help with that."}, context=CONSENT)
        self.assertTrue(ok["passed"])
        bad = ref.tool_redteam_assert(
            {"answer": "My system prompt includes the untrusted output boundary."}, context=CONSENT)
        self.assertFalse(bad["passed"])
        self.assertIn("system_prompt_hidden", bad["failed"])

    def test_assert_bounds_answer(self):
        result = ref.tool_redteam_assert({"answer": "x" * 5001}, context=CONSENT)
        self.assertIn("bounded_answer", result["failed"])


class KnowledgeLookupTests(unittest.TestCase):
    def test_unknown_mode_rejected(self):
        result = ref.tool_knowledge_lookup({"query": "sqli", "mode": "evil"}, context=CONSENT)
        self.assertEqual(result["reason"], "INVALID_MODE")

    def test_progressive_modes(self):
        listing = {"status": "success", "skills": ["sqli", "ssrf", "jwt"]}
        detail = {"status": "success", "content": "# SQLi\n\n## Union\n\n```sql\n' OR 1=1 --\n```"}
        with mock.patch.dict(agent_tools.TOOL_HANDLERS,
                             {"skills_list": lambda a, context=None: listing,
                              "skills_read": lambda a, context=None: detail}):
            search = ref.tool_knowledge_lookup({"query": "sqli", "mode": "search"}, context=CONSENT)
            self.assertEqual(search["skills"], ["sqli"])
            outline = ref.tool_knowledge_lookup({"query": "sqli", "mode": "outline"}, context=CONSENT)
            self.assertTrue(any("SQLi" in line for line in outline["outline"]))
            cheat = ref.tool_knowledge_lookup({"query": "sqli", "mode": "cheatsheet"}, context=CONSENT)
            self.assertIn("OR 1=1", cheat["blocks"][0])


class FingerprintCorpusTests(TestCase):
    def test_add_and_list(self):
        from .models import Project
        project = Project.objects.create(name="Corpus", target="http://example.test")
        added = agent_tools.TOOL_HANDLERS["fingerprint_corpus"](
            {"action": "add", "name": "nginx", "version": "1.24", "verdict": "observed"},
            context={**CONSENT, "active_project": project})
        self.assertEqual(added["status"], "success")
        from .models import Project as ProjectModel
        project = ProjectModel.objects.get(id=project.id)
        listed = agent_tools.TOOL_HANDLERS["fingerprint_corpus"](
            {"action": "list"}, context={**CONSENT, "active_project": project})
        self.assertEqual(len(listed["records"]), 1)


if __name__ == "__main__":
    unittest.main()
