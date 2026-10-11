#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for tools/capability_probe.py.

The probe's whole value is that its numbers can be re-derived, so these tests
pin the behaviour that decides a number:

* which entry point `classify` claims for each ecosystem (a wrong entry point
  means the help of a *different* program is measured);
* that an option printed by the tool wins over the same option merely declared
  in source — otherwise the matrix overstates the surface;
* that a tool which cannot run yields `failed` **with the reason**, never a
  silent empty row;
* that the subprocess path really executes (a fake tool in a temp dir prints a
  known help, and the probe must return exactly that).

Run: python3 -m unittest discover -s tools -p 'test_*.py' -v
"""

from __future__ import annotations

import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import capability_probe as cp  # noqa: E402


class ClassifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def make(self, rel: str, content: str = "") -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def clone(self, name: str) -> Callable[[str, str], Path]:
        """Build a fixture clone under a directory named like the real clone.

        Entry-point ranking reads the directory name — `cmd/<name>/` is a
        CLI, `cmd/<name>-migrate-scores/` is not — so a fixture in an
        anonymous temp directory cannot exercise it.
        """
        base = self.root / name
        base.mkdir(parents=True, exist_ok=True)

        def writer(rel: str, content: str = "") -> Path:
            p = base / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return p

        return writer

    def test_go_prefers_the_shallowest_cmd_main(self) -> None:
        self.make("go.mod", "module x\n")
        self.make("cmd/integration-test/main.go", "package main\nfunc main(){}\n")
        self.make("cmd/x/main.go", "package main\nfunc main(){}\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "go")
        self.assertEqual(entry, "cmd/x/main.go")

    def test_go_ignores_test_files_and_non_main_packages(self) -> None:
        self.make("go.mod", "module x\n")
        self.make("cmd/tool/main_test.go", "package main\nfunc TestX(){}\n")
        self.make("internal/lib/lib.go", "package lib\n")
        self.make("top.go", "package main\nfunc main(){}\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "go")
        self.assertEqual(entry, "top.go")

    def test_python_picks_the_file_that_has_a_main_guard(self) -> None:
        self.make("setup.py", "from setuptools import setup\n")
        self.make("lib.py", "X = 1\n")
        self.make("run.py", "def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "python")
        self.assertEqual(entry, "run.py")

    def test_data_corpus_is_not_a_program(self) -> None:
        self.make("a.yaml", "id: x\n")
        self.make("b.yml", "id: y\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "data")
        self.assertIsNone(entry)

    def test_a_root_module_named_after_the_clone_wins_without_a_guard(self) -> None:
        """Hunner's hunner.py calls Main_Menu() at import time, with no guard."""
        w = self.clone("Hunner")
        w("hunner.py", "def Main_Menu():\n    pass\nMain_Menu()\n")
        w("modules/hun_listener.py",
          "def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n")
        eco, entry = cp.classify(self.root / "Hunner")
        self.assertEqual(eco, "python")
        self.assertEqual(entry, "hunner.py")

    def test_node_reads_the_bin_entry(self) -> None:
        self.make("package.json", '{"name":"x","bin":{"x":"run.js"}}')
        self.make("run.js", "console.log('hi')\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "node")
        self.assertEqual(entry, "run.js")

    def test_go_prefers_cmd_named_like_the_repo_over_a_sibling_helper(self) -> None:
        """titus ships cmd/titus-migrate-scores/ next to cmd/titus/."""
        w = self.clone("titus")
        w("go.mod", "module x\n")
        w("cmd/titus-migrate-scores/main.go", "package main\nfunc main(){}\n")
        w("cmd/titus/analyze.go", "package main\nfunc main(){}\n")
        w("cmd/titus/main.go", "package main\nfunc main(){}\n")
        eco, entry = cp.classify(self.root / "titus")
        self.assertEqual(eco, "go")
        self.assertEqual(entry, "cmd/titus/main.go")

    def test_go_finds_an_entry_not_named_main_go(self) -> None:
        """pdtm's CLI is cmd/pdtm/pdtm.go."""
        self.make("go.mod", "module x\n")
        self.make("cmd/pdtm/pdtm.go", "package main\nfunc main(){}\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "go")
        self.assertEqual(entry, "cmd/pdtm/pdtm.go")

    def test_go_skips_integration_and_wasm_targets(self) -> None:
        self.make("go.mod", "module x\n")
        self.make("cmd/naabu/main.go", "package main\nfunc main(){}\n")
        self.make("cmd/integration-test/main.go", "package main\nfunc main(){}\n")
        self.make("wasm/main.go", "package main\nfunc main(){}\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(entry, "cmd/naabu/main.go")
        self.assertEqual(eco, "go")

    def test_a_github_action_is_not_a_runnable_tool(self) -> None:
        self.make("action.yaml", "name: x\n")
        self.make("dist/index.js", "console.log(1)\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "action")
        self.assertIsNone(entry)

    def test_an_nse_script_is_not_a_runnable_tool(self) -> None:
        self.make("vulners.nse", "-- comment\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "nse")
        self.assertIsNone(entry)

    def test_a_compose_stack_is_a_lab_not_a_cli(self) -> None:
        self.make("ssl/deprecated-tls/docker-compose.yml", "services: {}\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "lab")
        self.assertIsNone(entry)

    def test_a_flask_app_is_a_webapp_not_a_cli(self) -> None:
        self.make("src/__init__.py", "from flask import Flask\napp = Flask(__name__)\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "webapp")
        self.assertIsNone(entry)

    def test_rust_is_recognised_before_its_python_helpers(self) -> None:
        self.make("Cargo.toml", "[package]\nname = \"dalfox\"\n")
        self.make("src/main.rs", "fn main() {}\n")
        self.make("packaging/build_helper.py", "print(1)\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "rust")
        self.assertEqual(entry, "src/main.rs")

    def test_a_ruby_gem_uses_its_bin_directory(self) -> None:
        self.make("arachni.gemspec", "Gem::Specification.new do |s|\nend\n")
        self.make("bin/arachni", "#!/usr/bin/env ruby\n")
        self.make("lib/arachni.rb", "module Arachni\nend\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "ruby")
        self.assertEqual(entry, "bin/arachni")

    def test_python_never_picks_a_packaging_file_as_its_entry(self) -> None:
        """vulncov's root holds only setup.py; the program is two levels in."""
        self.make("setup.py", "from setuptools import setup\n")
        self.make("vulncov/main.py", "def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "python")
        self.assertEqual(entry, "vulncov/main.py")

    def test_python_never_picks_a_doc_or_test_module(self) -> None:
        self.make("doc/source/conf.py", "project = 'x'\n")
        self.make("tests/e2e/run.py", "def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n")
        self.make("core/main.py", "def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "python")
        self.assertEqual(entry, "core/main.py")

    def test_a_console_script_wins_over_layout_guessing(self) -> None:
        self.make("pyproject.toml", '[project.scripts]\nxsser = "core.main:main"\n')
        self.make("core/main.py", "def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n")
        self.make("helper.py", "def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n")
        eco, entry = cp.classify(self.root)
        self.assertEqual(eco, "python")
        self.assertEqual(entry, "core/main.py")

    def test_a_node_package_one_level_down_is_found_by_name(self) -> None:
        """retire.js keeps its CLI in node/, not in firefox/."""
        w = self.clone("retire.js")
        w("firefox/package.json", '{"name":"firefox","main":"lib/main.js"}')
        w("firefox/lib/main.js", "console.log(1)\n")
        w("node/package.json", '{"name":"node","bin":{"retire":"./lib/cli.js"}}')
        w("node/lib/cli.js", "#!/usr/bin/env node\n")
        eco, entry = cp.classify(self.root / "retire.js")
        self.assertEqual(eco, "node")
        self.assertEqual(entry, "node/lib/cli.js")

    def test_a_python_frontend_subdirectory_is_not_read_as_node(self) -> None:
        """vulnscout has frontend/package.json and is still a Python tool."""
        w = self.clone("vulnscout")
        w("frontend/package.json", '{"name":"frontend","main":"app.js"}')
        w("frontend/app.js", "console.log(1)\n")
        w("src/vulnscout.py", "def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n")
        eco, entry = cp.classify(self.root / "vulnscout")
        self.assertEqual(eco, "python")
        self.assertEqual(entry, "src/vulnscout.py")

    def test_an_unbuilt_node_package_reports_no_entry_rather_than_a_wrong_one(self) -> None:
        w = self.clone("retire.js")
        w("firefox/package.json", '{"name":"firefox","main":"lib/main.js"}')
        w("firefox/lib/main.js", "console.log(1)\n")
        w("node/package.json", '{"name":"node","bin":{"retire":"./lib/cli.js"}}')
        w("simpleserver.py", "print(1)\n")
        eco, entry = cp.classify(self.root / "retire.js")
        self.assertEqual(eco, "node")
        self.assertIsNone(entry)


class FlagTests(unittest.TestCase):
    def test_printed_options_are_extracted_and_deduplicated(self) -> None:
        text = "usage: x [-h] [-u URL] [--timeout N]\n  -u URL, --url URL  target\n"
        flags = cp.parse_help_flags(text)
        self.assertIn("-u", flags)
        self.assertIn("--url", flags)
        self.assertIn("--timeout", flags)
        self.assertIn("-h", flags)
        self.assertEqual(len(flags), len(set(flags)))

    def test_argparse_declaration_yields_both_long_and_short_names(self) -> None:
        src = "p.add_argument('-o', '--output', dest='o')\np.add_argument('--deep')\n"
        flags = cp.declared_python_flags(src)
        self.assertEqual(flags, ["-o", "--output", "--deep"])

    def test_cobra_flag_registration_is_read(self) -> None:
        # The real projectdiscovery shape: the option name is the first quoted
        # literal after the bound variable, not the method name.
        src = (
            'flagSet.BoolVarP(&silent, "silent", "s", false, "")\n'
            'flagSet.StringVarP(&timeout, "timeout", "", "", "")\n'
            'flagSet.BoolVar(&debug, "debug", false, "")\n'
        )
        self.assertEqual(cp.declared_go_flags(src), ["silent", "timeout", "debug"])

    def test_cobra_short_shorthand_is_not_counted_as_an_option(self) -> None:
        src = 'flagSet.BoolVarP(&silent, "silent", "s", false, "")\n'
        self.assertNotIn("s", cp.declared_go_flags(src))

    def test_merge_labels_provenance_so_the_matrix_cannot_overstate(self) -> None:
        merged = cp.merge_flags(["--url"], ["--url", "--secret", "--deep"])
        by_name = {f.name: f.origin for f in merged}
        self.assertEqual(by_name["--url"], "help")
        self.assertEqual(by_name["--secret"], "source")
        self.assertEqual(by_name["--deep"], "source")


class ProbeExecutionTests(unittest.TestCase):
    """These run real subprocesses against fake tools in a temp dir."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_a_tool_that_prints_help_is_reported_as_ran(self) -> None:
        tool = self.root / "tool.py"
        tool.write_text(
            "import sys\n"
            "print('usage: tool [-h] [--url URL] [--timeout N]')\n"
            "print('  --url URL   target')\n"
            "print('  --timeout N seconds')\n",
            encoding="utf-8",
        )
        status, code, out, err, _strat = cp.probe_help(self.root, "tool.py", "python", timeout=20)
        self.assertEqual(status, "ran")
        self.assertEqual(code, 0)
        self.assertIn("--timeout", out)
        self.assertEqual(err, "")

    def test_a_tool_that_dies_reports_failed_with_the_actual_error(self) -> None:
        tool = self.root / "broken.py"
        tool.write_text(
            "import definitely_not_installed_xyz\n", encoding="utf-8"
        )
        status, code, out, err, _strat = cp.probe_help(self.root, "broken.py", "python", timeout=20)
        self.assertEqual(status, "failed")
        self.assertNotEqual(code, 0)
        self.assertIn("definitely_not_installed_xyz", out)
        self.assertIn("ModuleNotFoundError", err)

    def test_a_missing_entry_is_named_not_guessed(self) -> None:
        status, code, _out, err, _strat = cp.probe_help(self.root, "nope.py", "python", timeout=5)
        self.assertEqual(status, "missing-entry")
        self.assertIsNone(code)
        self.assertIn("nope.py", err)

    def test_a_hanging_tool_is_a_timeout_not_a_zero(self) -> None:
        tool = self.root / "hang.py"
        tool.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
        status, code, _out, err, _strat = cp.probe_help(self.root, "hang.py", "python", timeout=1)
        self.assertEqual(status, "timeout")
        self.assertIsNone(code)
        self.assertIn("1", err)

    def test_an_executable_entry_is_launched_directly(self) -> None:
        """The go/other branch execs the file itself; that path must work."""
        tool = self.root / "fakebin"
        tool.write_text(
            "#!/bin/sh\necho 'usage: fakebin [-h] [--json]'\necho '  --json  emit json'\n",
            encoding="utf-8",
        )
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        status, code, out, _err, _strat = cp.probe_help(self.root, "fakebin", "go", timeout=20)
        self.assertEqual(status, "ran")
        self.assertEqual(code, 0)
        self.assertIn("--json", out)

    def test_a_compiled_binary_is_preferred_over_the_source_entry(self) -> None:
        """A Go clone needs `go build`; the matrix must say which one it ran."""
        src = self.root / "clone"
        src.mkdir()
        (src / "main.go").write_text("package main\nfunc main(){}\n", encoding="utf-8")
        binary = self.root / "built"
        binary.write_text(
            "#!/bin/sh\necho 'usage: clone [--from-binary]'\n", encoding="utf-8"
        )
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)

        status, _code, out, _err, _strat = cp.probe_help(
            src, "main.go", "go", timeout=20, binary=binary
        )
        self.assertEqual(status, "ran")
        self.assertIn("--from-binary", out)

        probe = cp.probe_tool(src, timeout=20, binary=binary)
        self.assertEqual(probe.launched_from, "binary")
        self.assertIn("--from-binary", [f.name for f in probe.flags])

    def test_a_missing_binary_is_named_not_silently_skipped(self) -> None:
        status, code, _out, err, _strat = cp.probe_help(
            self.root, "x.py", "python", timeout=5, binary=self.root / "absent"
        )
        self.assertEqual(status, "missing-entry")
        self.assertIsNone(code)
        self.assertIn("absent", err)


class ProbeToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_end_to_end_counts_printed_and_declared_separately(self) -> None:
        d = self.base / "demo"
        d.mkdir()
        (d / "demo.py").write_text(
            "import argparse\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--url')\n"
            "p.add_argument('--hidden-source-only')\n"
            "def main():\n"
            "    p.print_help()\n"
            "if __name__ == '__main__':\n"
            "    main()\n",
            encoding="utf-8",
        )
        probe = cp.probe_tool(d, timeout=20)
        self.assertEqual(probe.ecosystem, "python")
        self.assertEqual(probe.probe_status, "ran")
        names = {f.name: f.origin for f in probe.flags}
        # argparse prints every option it declares, so a tool that ran has all
        # of its options at origin `help`.
        self.assertEqual(names.get("--url"), "help")
        self.assertEqual(names.get("--hidden-source-only"), "help")
        self.assertEqual(probe.flag_count, len(probe.flags))
        self.assertEqual(probe.printed_flag_count, probe.flag_count)

    def test_a_tool_that_cannot_run_reports_declared_flags_as_source_only(self) -> None:
        """This is the case the origin column exists for.

        A tool whose help cannot be printed here still declares its options in
        source. Counting them as `help` would claim a surface nobody observed,
        which is exactly the overstatement the matrix must not contain.
        """
        d = self.base / "broken"
        d.mkdir()
        (d / "broken.py").write_text(
            "import argparse, definitely_not_installed_xyz\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--url')\n"
            "p.add_argument('--only-in-source')\n",
            encoding="utf-8",
        )
        probe = cp.probe_tool(d, timeout=20)
        self.assertEqual(probe.probe_status, "failed")
        self.assertIn("ModuleNotFoundError", probe.error_head)
        names = {f.name: f.origin for f in probe.flags}
        self.assertEqual(names.get("--only-in-source"), "source")
        self.assertEqual(probe.printed_flag_count, 0)
        self.assertGreater(probe.flag_count, 0)

    def test_a_copy_is_flagged_so_the_matrix_can_deduplicate(self) -> None:
        d = self.base / "tool (copy 1)"
        d.mkdir()
        (d / "a.yaml").write_text("id: x\n")
        probe = cp.probe_tool(d, timeout=5)
        self.assertTrue(probe.is_copy)
        self.assertEqual(probe.probe_status, "data-only")

    def test_a_data_corpus_is_not_labelled_as_a_broken_program(self) -> None:
        d = self.base / "corpus"
        d.mkdir()
        for i in range(5):
            (d / f"t{i}.yaml").write_text("id: x\n")
        probe = cp.probe_tool(d, timeout=5)
        self.assertEqual(probe.probe_status, "data-only")
        self.assertEqual(probe.help_lines, 0)

    def test_reserved_dirs_are_not_tools(self) -> None:
        (self.base / "tests").mkdir()
        (self.base / "demo").mkdir()
        (self.base / "demo" / "x.py").write_text("print(1)\n")
        names = [p.name for p in cp.tool_dirs(self.base)]
        self.assertEqual(names, ["demo"])

    def test_a_missing_binaries_directory_fails_loudly(self) -> None:
        """Silently probing without binaries would report every Go tool as
        unrunnable, and the matrix would read as "these tools have no help"."""
        base = self.base / "clone"
        base.mkdir()
        (base / "x.py").write_text("print(1)\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cp.main([str(self.base), "--binaries", str(self.base / "absent")])
        self.assertEqual(rc, 2)
        self.assertIn("бінарників немає", err.getvalue())

    def test_a_missing_base_directory_fails_loudly(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cp.main([str(self.base / "absent")])
        self.assertEqual(rc, 2)
        self.assertIn("немає каталогу", err.getvalue())

    def test_a_relative_root_still_launches_the_tool(self) -> None:
        """subprocess runs with cwd=root, so a relative target used to resolve
    against the tool's own directory and every source-launched tool failed."""
        clone = self.base / "clones" / "demo"
        clone.mkdir(parents=True)
        (clone / "demo.py").write_text(
            "print('usage: demo [--url]')", encoding="utf-8"
        )
        cwd = os.getcwd()
        os.chdir(self.base)
        try:
            status, _code, out, _err, _strat = cp.probe_help(
                Path("clones/demo"), "demo.py", "python", timeout=20
            )
        finally:
            os.chdir(cwd)
        self.assertEqual(status, "ran")
        self.assertIn("--url", out)

    def test_a_rust_clone_is_blocked_not_mis_executed_as_python(self) -> None:
        d = self.base / "rs"
        d.mkdir()
        (d / "src").mkdir()
        (d / "Cargo.toml").write_text("[package]\nname=\"rs\"\n", encoding="utf-8")
        (d / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        probe = cp.probe_tool(d, timeout=10)
        self.assertEqual(probe.ecosystem, "rust")
        self.assertEqual(probe.probe_status, "blocked")
        self.assertIn("cargo", probe.error_head)

    def test_a_second_launch_strategy_is_tried_before_failing(self) -> None:
        """scapy's own parser rejects `--help`; the tool still has a help page."""
        tool = self.base / "scapyish.py"
        tool.write_text(
            "import sys\n"
            "if '--help' in sys.argv:\n"
            "    sys.stderr.write('usage: scapyish [-h]\\n')\n"
            "    sys.exit(2)\n"
            "print('usage: scapyish [-h]\\n  -h  show this help\\n')\n",
            encoding="utf-8",
        )
        status, _code, out, _err, strategy = cp.probe_help(
            self.base, "scapyish.py", "python", timeout=20
        )
        self.assertEqual(status, "ran")
        self.assertIn("show this help", out)
        self.assertEqual(strategy, "flag")

    def test_a_tool_needing_a_package_import_still_runs(self) -> None:
        """dirsearch and vulncov use relative imports and refuse `file.py`."""
        pkg = self.base / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "__main__.py").write_text(
            "from .cli import main\nmain()\n", encoding="utf-8"
        )
        (pkg / "cli.py").write_text(
            "def main():\n    print('usage: pkg [--deep]')\n", encoding="utf-8"
        )
        status, _code, out, _err, strategy = cp.probe_help(
            self.base, "pkg/__main__.py", "python", timeout=20
        )
        self.assertEqual(status, "ran")
        self.assertIn("--deep", out)
        self.assertEqual(strategy, "module")

    def test_a_package_dunder_main_entry_is_run_as_its_directory(self) -> None:
        """dirsearch's entry is `__main__.py`; `python -m __main__` cannot work."""
        # The real layout: the repository directory and the importable
        # package share a name, so `python -m dirsearch` resolves inside it.
        clone = self.base / "dirsearch"
        pkg = clone / "dirsearch"
        (pkg / "lib").mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "__main__.py").write_text(
            "from .lib import banner\nbanner()\n", encoding="utf-8"
        )
        (pkg / "lib" / "__init__.py").write_text(
            "def banner():\n    print('usage: dirsearch [-u URL] [--deep]')\n",
            encoding="utf-8",
        )
        status, _code, out, _err, strategy = cp.probe_help(
            clone, "dirsearch/__main__.py", "python", timeout=20
        )
        self.assertEqual(status, "ran")
        self.assertIn("--deep", out)
        self.assertEqual(strategy, "module")

    def test_markdown_reports_the_measured_totals(self) -> None:
        for name, status_flag in (("a", True), ("b", False)):
            d = self.base / name
            d.mkdir()
            if status_flag:
                (d / "a.py").write_text("print('usage: a [--x]')\n")
            else:
                (d / "a.yaml").write_text("id: 1\n")
        results = [cp.probe_tool(p, timeout=10) for p in cp.tool_dirs(self.base)]
        md = cp.render_markdown(results, self.base)
        self.assertIn("унікальних інструментів:** 2", md)
        self.assertIn("help надруковано:** 1", md)


class PlanCoverageTests(unittest.TestCase):
    """The integration plan must give every clone an explicit position.

    The previous plan mentioned 18 of 45 clones and was silent about the
    other 27 — not closed, not deferred, simply absent. A plan that does not
    name a tool cannot tell the next session whether it was skipped or
    dismissed, so the omission is itself the defect this guards.
    """

    PLAN = Path(__file__).resolve().parent.parent / "Прочее" / "ПЛАН_ІНТЕГРАЦІЙ.md"
    CLONES = Path(__file__).resolve().parent.parent / "Прочее" / "Semple-Интеграции"

    def setUp(self) -> None:
        if not self.PLAN.is_file() or not self.CLONES.is_dir():
            self.skipTest("план або каталог клонів відсутні")

    def clones(self) -> list[str]:
        return sorted(
            d.name for d in self.CLONES.iterdir()
            if d.is_dir() and d.name != "tests"
            and not cp.COPY_SUFFIX.search(d.name)
        )

    def test_every_clone_is_named_in_the_plan(self) -> None:
        # Both sides must be normalised: the plan writes `retire.js` while the
        # directory key strips punctuation, and comparing a stripped key to
        # unstripped text reports a tool the plan plainly contains.
        text = cp.re.sub(r"[^a-z0-9]", "", self.PLAN.read_text(encoding="utf-8").lower())
        missing = [t for t in self.clones()
                   if cp.re.sub(r"[^a-z0-9]", "", t.lower()) not in text]
        self.assertEqual(missing, [], f"не згадані в плані: {missing}")

    def test_the_plan_states_a_position_for_each_row(self) -> None:
        rows = [ln for ln in self.PLAN.read_text(encoding="utf-8").splitlines()
                if cp.re.match(r"^\|\s*\d+\s*\|", ln)]
        self.assertGreaterEqual(len(rows), len(self.clones()))
        for row in rows:
            self.assertTrue(
                any(v in row for v in ("ІНТЕГРУЄМО", "ВІДКЛАДАЄМО", "ЗАКРИТЕ")),
                f"рядок без позиції: {row[:70]}",
            )

    def test_the_matrix_lists_every_clone_too(self) -> None:
        matrix = Path(__file__).resolve().parent.parent / "Прочее" / "МАТРИЦЯ_ЗДАТНОСТЕЙ.md"
        if not matrix.is_file():
            self.skipTest("матриця відсутня")
        text = cp.re.sub(r"[^a-z0-9]", "", matrix.read_text(encoding="utf-8").lower())
        missing = [t for t in self.clones()
                   if cp.re.sub(r"[^a-z0-9]", "", t.lower()) not in text]
        self.assertEqual(missing, [], f"не згадані в матриці: {missing}")


if __name__ == "__main__":
    unittest.main()