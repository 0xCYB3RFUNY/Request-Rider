"""Tests for flexible dependency management and first-run wizard in start.sh."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
START_SH = REPO_ROOT / "start.sh"


def _run_start(args, env_extra=None, stdin_text=None, timeout=20):
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(START_SH), *args],
        cwd=str(REPO_ROOT),
        env=env,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class StartShDependencyManagementTests(unittest.TestCase):
    def test_bash_syntax_is_valid(self):
        res = subprocess.run(
            ["bash", "-n", str(START_SH)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_help_documents_dependency_management_flags(self):
        res = _run_start(["--help"])
        self.assertEqual(res.returncode, 0, res.stderr)
        for flag in ("--deps", "--install", "--enable", "--disable", "--yes"):
            self.assertIn(flag, res.stdout)

    def test_deps_overview_lists_all_optional_dependencies_and_relationships(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf_path = str(Path(tmp) / "startup.conf")
            res = _run_start(["--deps"], env_extra={"RR_STARTUP_CONF": conf_path})
            self.assertEqual(res.returncode, 0, res.stderr)
            out = res.stdout
            self.assertIn("Карта залежностей Request-Rider", out)
            self.assertIn("ЯДРО", out)
            self.assertIn("Зв'язок:", out)
            self.assertIn("Без неї:", out)
            for key in ("browser", "chromium", "nuclei", "httpx", "gvm", "tor", "ollama", "msfdb", "agents"):
                self.assertIn(key, out)

    def test_enable_and_disable_persist_profile_and_reject_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf_path = Path(tmp) / "startup.conf"
            res = _run_start(
                ["--enable", "ollama,tor", "--disable", "gvm,nuclei"],
                env_extra={"RR_STARTUP_CONF": str(conf_path)},
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue(conf_path.is_file())
            content = conf_path.read_text(encoding="utf-8")
            self.assertIn("RR_ENABLE_OLLAMA=1", content)
            self.assertIn("RR_ROUTE_VIA_TOR=1", content)
            self.assertIn("RR_ENABLE_GVM=0", content)
            self.assertIn("RR_ENABLE_NUCLEI=0", content)

            bad = _run_start(
                ["--enable", "nonexistent_dep"],
                env_extra={"RR_STARTUP_CONF": str(conf_path)},
            )
            self.assertEqual(bad.returncode, 2)
            self.assertIn("невідомий компонент", bad.stderr)

    def test_first_run_interactive_wizard_explains_and_saves_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf_path = Path(tmp) / "startup.conf"
            # Toggle item 7 (Ollama), open dependency details (d), save without starting (w)
            res = _run_start(
                ["--interactive"],
                env_extra={"RR_STARTUP_CONF": str(conf_path)},
                stdin_text="7\nd\nw\n",
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Перший запуск", res.stdout)
            self.assertIn("Nuclei (YAML-сканер)", res.stdout)
            self.assertIn("OpenVAS / GVM сканер", res.stdout)
            self.assertIn("Tor маршрутизація виходу", res.stdout)
            self.assertIn("Ollama (локальна AI LLM)", res.stdout)
            self.assertIn("Карта залежностей Request-Rider", res.stdout)
            self.assertTrue(conf_path.is_file())
            self.assertIn("RR_ENABLE_OLLAMA=1", conf_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
