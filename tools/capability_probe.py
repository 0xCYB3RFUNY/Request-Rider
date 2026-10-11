#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capability probe for third-party clones.

Purpose
-------
Build a machine-checkable capability matrix out of a directory of cloned
tools, by **actually running each tool's help surface** and recording what it
printed. Where a tool cannot be executed here, the reason is recorded as a
measured fact (`blocked`, with the exact error), never as a guess.

The script never patches a tool, never installs anything into a clone and
never contacts a network target: the only process it starts is the tool's own
help path, under a timeout.

Two rules from the project contract shape this file:

* every number in the matrix must be re-derivable by re-running this script,
  so the matrix is emitted as JSON first and rendered to Markdown from that
  JSON;
* "we could not run it" is a result with a reason, not a silent absence, so
  `probe_help` records the exit code and the first lines of whatever the tool
  actually emitted.

Usage
-----
    python3 tools/capability_probe.py <clones-dir> --json out.json --md out.md
    python3 tools/capability_probe.py <clones-dir> --only naabu vulnx
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

# A clone is a directory that holds source, not a test fixture and not a copy.
COPY_SUFFIX = re.compile(r"\s*\(copy\s+\d+\)\s*$", re.IGNORECASE)
RESERVED_DIRS = {"tests", "test", "testdata", "fixtures", "docs", "doc"}

# Ecosystems we know how to launch. Anything else is reported as `data`,
# because a directory of YAML is a corpus, not a program.
GO_MOD = "go.mod"
CARGO_TOML = "Cargo.toml"
# Directories that hold material rather than the program's own entry point.
# `doc/source/conf.py`, `tests/e2e/run_e2e.py` and `demo/src/dummyapp.py`
# are all Python files and none of them is the tool.
NON_ENTRY_DIRS = {
    "test", "tests", "testing", "testdata", "fixtures", "fixture",
    "integration-test", "integration-test", "integration_tests",
    "functional-test", "functional_tests", "e2e", "benches", "bench",
    "spec", "specs", "testutils",
    "doc", "docs", "example", "examples", "sample", "samples",
    "demo", "demos", "benchmarks", "benchmark", "contrib",
    "scripts", "tools", "packaging", "vendor", "third_party",
    ".config", ".github", ".gitlab", ".idea", ".vscode", ".devcontainer",
    "build", "dist", "node_modules", "venv", ".venv", "site-packages",
    "target", "migrations", "locale", "locales",
}
PY_MAIN = re.compile(r"^def\s+main\s*\(", re.M)
PY_ARGPARSE = re.compile(r"add_argument\(\s*([^)]*)\)")
PY_QUOTED = re.compile(r"""['"]([^'"]+)['"]""")
# An option may be preceded by whitespace, `[`, `(`, `,`, `=` or a quote, and
# never by a word character or another dash (`--foo-bar` is one option, not two).
PY_OPT = re.compile(r"""(?<![\w-])(--?[A-Za-z][\w-]*)""")
NODE_MAIN = "package.json"
# `[project.scripts]` / `[console_scripts]` name the tool's own CLI entry:
# `foo = "pkg.mod:main"` is the one declaration that cannot be wrong, so it is
# preferred over guessing from file layout.
CONSOLE_SCRIPT = re.compile(r"^\s*([\w.-]+)\s*=\s*[\"']([\w.]+):[\w.]+[\"']", re.M)
RUBY_GEM = re.compile(r"^\s*spec\.executables?", re.M)


@dataclass
class Flag:
    """One option as the tool itself declares it."""

    name: str
    origin: str  # "help" (printed) or "source" (declared but never printed)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Probe:
    """Everything measured about one clone."""

    tool: str
    path: str
    ecosystem: str
    entry: str | None
    is_copy: bool
    probe_status: str  # ran | blocked | no-entry | data-only
    launched_from: str  # source | binary | none — what was actually executed
    exit_code: int | None
    help_lines: int
    first_line: str
    error_head: str
    flags: list[Flag] = field(default_factory=list)
    ecosystems_detail: str = ""
    file_counts: dict[str, int] = field(default_factory=dict)

    @property
    def flag_count(self) -> int:
        return len(self.flags)

    @property
    def printed_flag_count(self) -> int:
        return sum(1 for f in self.flags if f.origin == "help")


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------
def classify(root: Path) -> tuple[str, str | None]:
    """Return (ecosystem, entry point relative to root).

    Entry point is only claimed when the file actually looks like a program
    entry: a Go `main` package, a Python console script or `__main__`, a Node
    `bin`, a Rust `main.rs`, or a Ruby gem executable.

    Rust is checked before Python because a Rust project often carries helper
    Python scripts (`build.rs` companions, packaging glue) that would
    otherwise be mistaken for the tool. A GitHub Action and an Nmap NSE
    script are checked first of all: both are directories with real code and
    neither has a program you can run with `--help`.
    """
    if list(root.glob("action.y*ml")):
        return "action", None
    if list(root.glob("*.nse")):
        return "nse", None

    if (root / GO_MOD).is_file():
        return "go", go_entry(root)

    if (root / CARGO_TOML).is_file():
        mains = sorted(
            p.relative_to(root).as_posix()
            for p in root.rglob("main.rs")
            if not is_non_entry(p, root)
        )
        if mains:
            mains.sort(key=lambda s: (s.count("/"), len(s)))
            return "rust", mains[0]
        return "rust", None

    pkg = node_manifest(root, subdirs=False)
    if pkg is not None:
        manifest, base = pkg
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "node", None
        bin_field = data.get("bin")
        candidates: list[str] = []
        if isinstance(bin_field, str):
            candidates.append(bin_field)
        elif isinstance(bin_field, dict):
            candidates.extend(str(v) for v in bin_field.values())
        if isinstance(data.get("main"), str):
            candidates.append(data["main"])
        for cand in candidates:
            if (base / cand).is_file():
                return "node", (cand if base == root else f"{base.name}/{cand}")
        for js in sorted(base.glob("*.js")):
            return "node", (js.name if base == root else f"{base.name}/{js.name}")
        return "node", None

    gemspecs = sorted(root.glob("*.gemspec"))
    if gemspecs:
        for gem in gemspecs:
            if RUBY_GEM.search(read_text(gem)):
                return "ruby", gem.name
        exe_dir = root / "bin"
        if exe_dir.is_dir():
            scripts = sorted(p.name for p in exe_dir.iterdir() if p.is_file())
            if scripts:
                return "ruby", f"bin/{scripts[0]}"
        return "ruby", gemspecs[0].name

    script = python_console_script(root)
    if script:
        return "python", script
    pys = sorted(
        p for p in root.glob("*.py")
        if p.name not in PACKAGING_PY
    )
    for p in pys:
        text = read_text(p)
        if PY_MAIN.search(text) or "__main__" in text:
            return "python", p.name

    # A docker-compose tree or a Flask entrypoint is a deployable service, not
    # a command-line tool, and running its `--help` would start a web server.
    if compose_tree(root):
        return "lab", None
    if any(root.glob("entrypoint*")) or flask_imports(root):
        return "webapp", None

    named_entry = python_named_entry(root)
    if named_entry:
        return "python", named_entry

    guarded_entry = python_deep_entry(root, require_guard=True)
    if guarded_entry:
        return "python", guarded_entry

    pkg = node_manifest(root, subdirs=True)
    if pkg is not None:
        manifest, base = pkg
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "node", None
        for cand in node_entry_candidates(data):
            target = base / cand
            if target.is_file():
                return "node", target.relative_to(root).as_posix()
        return "node", None

    if pys:
        return "python", pys[0].name
    deep = python_deep_entry(root)
    if deep:
        return "python", deep

    if list(root.glob("*.yaml")) or list(root.glob("*.yml")):
        return "data", None
    # No recognised program entry. A directory holding many files is a corpus
    # of something (YAML templates, Burp `.bb` profiles, scan configs), and
    # calling it "other" would hide that it is data with no program in it.
    files = sum(1 for _ in root.rglob("*") if _.is_file())
    return ("data", None) if files >= 5 else ("other", None)


def node_entry_candidates(data: dict) -> list[str]:
    """Declared entry files of a Node manifest, in the order they bind."""
    out: list[str] = []
    bin_field = data.get("bin")
    if isinstance(bin_field, str):
        out.append(bin_field)
    elif isinstance(bin_field, dict):
        out.extend(str(v) for v in bin_field.values())
    if isinstance(data.get("main"), str):
        out.append(data["main"])
    return out


def compose_tree(root: Path) -> bool:
    """A compose file within three levels: a stack of services to run."""
    depth = len(root.parts)
    for p in root.rglob("*.y*ml"):
        if len(p.relative_to(root).parts) <= 3 and p.name.startswith(
            ("docker-compose", "compose")
        ):
            return True
        if len(p.parts) - depth > 3:
            break
    return False


def flask_imports(root: Path) -> bool:
    """A Flask app declares itself at import time.

    vulnscout keeps it in `src/__init__.py` rather than a root `app.py`, so
    the root alone misses it and the tool is misread as a CLI.
    """
    candidates = list(root.glob("*.py"))
    for sub in ("src", "app", "server"):
        d = root / sub
        if d.is_dir():
            candidates.extend(sorted(d.glob("*.py"))[:8])
    for p in candidates:
        text = read_text(p)
        if "from flask import" in text or "Flask(__name__)" in text:
            return True
    return any((root / sub).is_dir() for sub in ("src/routes", "src/views", "app/routes"))


def node_manifest(root: Path, subdirs: bool = True) -> tuple[Path, Path] | None:
    """Locate the Node manifest: at the root, or (optionally) one level down.

    retire.js keeps no manifest at its top level — the package lives in
    `node/package.json` — and reading only the root would report the tool as
    having no Node program at all. But a one-level search is also a trap: a
    Python project with a `frontend/` directory would be read as Node. So the
    subdirectory search is opt-in and runs only after every Python route has
    already failed.
    """
    top = root / NODE_MAIN
    if top.is_file():
        return top, root
    if not subdirs:
        return None
    # A `bin` field is what makes a directory a command-line tool. retire.js
    # holds its CLI in `node/` while `firefox/` is a browser-extension package
    # with only a `main`; picking by directory name or alphabetically would
    # report the extension's `lib/main.js` as the tool's help surface.
    def rank(child: Path) -> tuple[int, str]:
        manifest = child / NODE_MAIN
        has_bin = 1
        try:
            has_bin = 0 if json.loads(manifest.read_text(encoding="utf-8")).get("bin") else 1
        except (OSError, ValueError, AttributeError):
            pass
        return (has_bin, child.name)

    for child in sorted(root.iterdir(), key=rank):
        manifest = child / NODE_MAIN
        if child.is_dir() and manifest.is_file():
            return manifest, child
    return None


def go_entry(root: Path) -> str | None:
    """The `main` package of a Go module.

    Not every Go program puts its entry in `main.go`: pdtm's is
    `cmd/pdtm/pdtm.go`, and titus's real CLI sits in `cmd/titus/` while
    `wasm/main.go` is a browser target. Searching only for `main.go` finds the
    wrong program, so the search is over every file declaring `package main`,
    ranked by how much it looks like a CLI.
    """
    mains = [
        p for p in root.rglob("*.go")
        if not p.name.endswith("_test.go")
        and not is_non_entry(p, root)
        and is_go_main(p)
    ]
    if not mains:
        return None

    def rank(p: Path) -> tuple[int, int, int, int, str]:
        rel = p.relative_to(root).as_posix()
        under_cmd = 0 if rel.startswith("cmd/") else 1
        is_wasm = 0 if "wasm" not in rel.split("/") else 1
        # `cmd/<repo-name>/` is the conventional home of a CLI; titus also
        # ships `cmd/titus-migrate-scores/` and `cmd/titus-score-lint/`, and
        # alphabetical order would pick a migration helper over the CLI.
        module = root.name.rstrip("0123456789-_. ").lower()
        matches = 0 if rel.split("/")[1:2] == [module] else 1
        is_main_go = 0 if p.name == "main.go" else 1
        return (under_cmd, matches, is_wasm, is_main_go, rel)

    return sorted(mains, key=rank)[0].relative_to(root).as_posix()


PACKAGING_PY = {"setup.py", "conftest.py", "noxfile.py", "tasks.py"}


def python_named_entry(root: Path) -> str | None:
    """A root module named after the clone.

    Hunner's `hunner.py` is its CLI and has no `__main__` guard — it calls
    `Main_Menu()` at module level — so a guard-only search skips it and lands
    on `modules/hun_listener.py`, a listener helper. The directory name is a
    stronger statement of intent than a guard.
    """
    key = re.sub(r"[^a-z0-9]", "", root.name.lower())
    for p in sorted(root.glob("*.py")):
        if p.name in PACKAGING_PY:
            continue
        if re.sub(r"[^a-z0-9]", "", p.stem.lower()) == key:
            return p.name
    return None


def python_deep_entry(root: Path, require_guard: bool = False) -> str | None:
    """A runnable module when nothing sits at the repository root.

    Preference order is by how much the file looks like the tool's own CLI:
    a `__main__` guard first, then a `main.py`/`__main__.py` name, then the
    shallowest remaining module. Packaging files never qualify — picking
    `setup.py` measures the build script, not the program.

    With `require_guard`, only modules that actually run themselves qualify.
    That distinction decides retire.js: its `simpleserver.py` has no guard and
    is a demo helper, so a guard-only search correctly reports no Python entry
    and lets the Node package win instead.
    """
    files = [
        p for p in root.rglob("*.py")
        if p.name not in PACKAGING_PY and not is_non_entry(p, root)
    ]
    if not files:
        return None

    def guarded(p: Path) -> bool:
        text = read_text(p)
        return "__main__" in text or bool(PY_MAIN.search(text))

    with_guard = [p for p in files if guarded(p)]
    if require_guard:
        pool = with_guard
        if not pool:
            return None
    else:
        pool = with_guard or [p for p in files if p.name in {"main.py", "__main__.py", "cli.py"}] or files
    # Among guarded modules, the conventional entry names win over the shallow
    # one: xsser's `core/dork.py` is guarded too, and depth alone would pick a
    # helper over `core/main.py`.
    name_rank = {"__main__.py": 0, "main.py": 1, "cli.py": 2, "app.py": 3, "run.py": 4}
    pool.sort(key=lambda p: (name_rank.get(p.name, 5), len(p.relative_to(root).parts), p.as_posix()))
    return pool[0].relative_to(root).as_posix()


def is_non_entry(path: Path, root: Path) -> bool:
    """True when `path` lives under a directory that cannot hold the CLI."""
    try:
        parts = path.relative_to(root).parts[:-1]
    except ValueError:
        return False
    return any(part.lower() in NON_ENTRY_DIRS for part in parts)


def python_console_script(root: Path) -> str | None:
    """Resolve `[project.scripts]` / `[console_scripts]` to a runnable file.

    `foo = "pkg.mod:main"` becomes `pkg/mod.py` when such a module exists.
    A declaration with no matching module is ignored rather than trusted.
    """
    for meta in ("pyproject.toml", "setup.cfg"):
        path = root / meta
        if not path.is_file():
            continue
        for _name, module in CONSOLE_SCRIPT.findall(read_text(path)):
            candidate = module.replace(".", "/") + ".py"
            if (root / candidate).is_file():
                return candidate
            pkg_init = root / module.replace(".", "/") / "__init__.py"
            if pkg_init.is_file():
                return pkg_init.relative_to(root).as_posix()
    return None


def is_go_main(path: Path) -> bool:
    return bool(re.search(r"^package\s+main\s*$", read_text(path), re.M))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def count_files(root: Path, limit: int = 40_000) -> dict[str, int]:
    """Extension histogram, used as the corpus-size evidence in the matrix."""
    hist: dict[str, int] = {}
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "vendor"}]
        for name in filenames:
            total += 1
            if total > limit:
                hist["<truncated>"] = 1
                return hist
            ext = Path(name).suffix.lower() or "<none>"
            hist[ext] = hist.get(ext, 0) + 1
    return dict(sorted(hist.items(), key=lambda kv: -kv[1]))


# --------------------------------------------------------------------------
# flag extraction
# --------------------------------------------------------------------------
def parse_help_flags(text: str) -> list[str]:
    """Option tokens as the tool itself printed them."""
    seen: list[str] = []
    for raw in PY_OPT.findall(text or ""):
        name = raw.strip()
        if name in {"-", "--"}:
            continue
        if name not in seen:
            seen.append(name)
    return seen


def declared_python_flags(source: str) -> list[str]:
    """Options an argparse/Click tool declares, whether or not it printed them.

    `add_argument('-o', '--output', dest='o')` declares two options; taking
    only the first quoted token would silently halve the count.
    """
    out: list[str] = []
    for chunk in PY_ARGPARSE.findall(source or ""):
        for token in PY_QUOTED.findall(chunk):
            if token.startswith("-") and token not in out:
                out.append(token)
    return out


# pflag registers a cobra option either bound to a variable —
# `cmd.Flags().BoolVarP(&silent, "silent", "s", …)` — or bare —
# `cmd.Flags().StringP("listen", …)`. The receiver is a variable (`cmd`,
# `flagSet`, `options`), not the literal text `Flags()`, so the pattern must
# not require it. The option name is the first quoted literal, not the method.
_GO_FLAG_BOUND = re.compile(r"\.\s*[A-Z]\w*VarP?\(\s*&?[\w.]+\s*,\s*['\"]([\w.-]+)['\"]")
_GO_FLAG_BARE = re.compile(r"\.\s*[A-Z]\w*P\(\s*['\"]([\w.-]+)['\"]")


def declared_go_flags(source: str) -> list[str]:
    """Options a cobra/pflag tool declares."""
    out: list[str] = []
    for name in _GO_FLAG_BOUND.findall(source or "") + _GO_FLAG_BARE.findall(source or ""):
        if name not in out:
            out.append(name)
    return out


def declared_node_flags(source: str) -> list[str]:
    out: list[str] = []
    for group in re.findall(
        r"\.option\(\s*['\"]([^'\"]+)['\"]", source or ""
    ) + re.findall(r"\.addOption\(\s*['\"]([^'\"]+)['\"]", source or ""):
        for name in re.split(r"[,\s]+", group):
            if name.startswith("-") and name not in out:
                out.append(name)
    return out


def merge_flags(printed: Iterable[str], declared: Iterable[str]) -> list[Flag]:
    """Printed wins; declared fills the gap and is labelled as such."""
    merged: list[Flag] = [Flag(name=n, origin="help") for n in printed]
    known = {f.name for f in merged}
    for name in declared:
        if name not in known:
            merged.append(Flag(name=name, origin="source"))
            known.add(name)
    return merged


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------
HELP_ARGS = {
    "go": ["-h"],
    "python": ["--help"],
    "node": ["--help"],
    "ruby": ["--help"],
}


def launch_strategies(root: Path, entry: str, ecosystem: str) -> list[tuple[str, list[str]]]:
    """Ways to ask this tool for its help, most direct first.

    Several clones refuse a plain `python file.py --help`: dirsearch and
    vulncov use relative imports and must be started as a package, and scapy's
    own option parser does not know `--help`. Trying one command and reporting
    the failure would measure the launcher's limits, not the tool.
    """
    target = (root / entry).resolve()
    py = sys.executable
    strategies: list[tuple[str, list[str]]] = []
    if ecosystem == "go":
        return [("source", [str(target), "-h"])]
    if ecosystem == "node":
        return [("source", [shutil.which("node") or "node", str(target), "--help"])]
    if ecosystem == "ruby":
        return [("source", [shutil.which("ruby") or "ruby", str(target), "--help"])]

    strategies.append(("source", [py, str(target), "--help"]))
    if entry.endswith(".py"):
        stem = Path(entry).with_suffix("").as_posix()
        if stem == "__main__":
            # dirsearch's entry is its top-level `__main__.py`; the runnable
            # module is the package directory, and `python -m __main__` fails
            # with the very relative-import error we are trying to avoid.
            stem = root.name
        module = stem.replace("/", ".")
        strategies.append(("module", [py, "-m", module, "--help"]))
    for flag in ("-h", "help"):
        strategies.append(("flag", [py, str(target), flag]))
    return strategies


def probe_help(root: Path, entry: str, ecosystem: str, timeout: int,
               binary: Path | None = None, python: str | None = None
               ) -> tuple[str, int | None, str, str, str]:
    """Run the tool's help path.

    `binary` is a compiled executable for a tool whose source cannot be
    launched directly (a Go clone needs `go build` first). `python` overrides
    the interpreter, so a probe can run a clone against a virtualenv holding
    its dependencies instead of the system interpreter.

    Returns (status, exit_code, printed_output, error_head, strategy).

    `status` is one of: ran, timeout, missing-entry, blocked, failed. "failed"
    means every strategy was tried and the tool printed no help; the last
    error it emitted is returned verbatim rather than guessed at.
    """
    if binary is not None:
        binary = binary.resolve()
        if not binary.is_file():
            return "missing-entry", None, "", f"бінарника {binary.name} немає", "none"
        strategies = [("binary", [str(binary), "-h"] if ecosystem == "go"
                       else [str(binary), "--help"])]
    else:
        if ecosystem == "rust":
            # A Rust clone needs `cargo`; running its `.rs` file with python
            # measures nothing, so this is reported rather than attempted.
            return "blocked", None, "", "потрібен cargo build; cargo у середовищі відсутній", "none"
        if not (root / entry).is_file():
            return "missing-entry", None, "", f"entry {entry} не є файлом", "none"
        strategies = launch_strategies(root, entry, ecosystem)
        if python:
            strategies = [
                (name, [python if cmd[0] == sys.executable else cmd[0]] + cmd[1:])
                for name, cmd in strategies
            ]

    env = dict(os.environ)
    env.setdefault("NO_COLOR", "1")
    env.setdefault("TERM", "dumb")
    env["COLUMNS"] = "200"
    env["LINES"] = "100"
    # A clone that imports its own package needs the repository root importable.
    env["PYTHONPATH"] = os.pathsep.join(
        [str(root.resolve()), env.get("PYTHONPATH", "")]
    ).strip(os.pathsep)

    last = ("failed", None, "", "", "none")
    for name, cmd in strategies:
        try:
            proc = subprocess.run(
                cmd, cwd=str(root.resolve()), capture_output=True, text=True,
                timeout=timeout, env=env, check=False,
            )
        except subprocess.TimeoutExpired:
            last = ("timeout", None, "", f"не завершився за {timeout} с", name)
            continue
        except OSError as exc:
            last = ("missing-python", None, "", f"{type(exc).__name__}: {exc}", name)
            continue

        out = (proc.stdout or "") + (proc.stderr or "")
        lines_out = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if proc.returncode == 0 and out.strip():
            return "ran", proc.returncode, out, "", name
        # A failure's informative line is its LAST line: a Python traceback
        # ends with `ModuleNotFoundError: ...`, while its first line is the
        # useless "Traceback (most recent call last):".
        last = ("failed", proc.returncode, out,
                (lines_out[-1] if lines_out else ""), name)
    return last


# --------------------------------------------------------------------------
# per-tool probe
# --------------------------------------------------------------------------
def probe_tool(root: Path, timeout: int = 20, binary: Path | None = None,
               python: str | None = None) -> Probe:
    ecosystem, entry = classify(root)
    name = root.name
    is_copy = bool(COPY_SUFFIX.search(name))
    counts = count_files(root)

    probe = Probe(
        tool=name,
        path=str(root),
        ecosystem=ecosystem,
        entry=entry,
        is_copy=is_copy,
        probe_status="no-entry",
        launched_from="none",
        exit_code=None,
        help_lines=0,
        first_line="",
        error_head="",
        file_counts=counts,
        ecosystems_detail="",
    )

    if ecosystem == "data":
        probe.probe_status = "data-only"
        probe.ecosystems_detail = "корпус даних, програми немає"
        return probe
    if entry is None and binary is None:
        probe.probe_status = "no-entry"
        probe.ecosystems_detail = "екосистему визначено, точку входу ні"
        return probe

    status, code, out, head, strategy = probe_help(
        root, entry or "", ecosystem, timeout, binary=binary, python=python
    )
    probe.probe_status = status
    probe.launched_from = "binary" if binary is not None else strategy
    probe.exit_code = code
    probe.help_lines = len(out.splitlines()) if out else 0
    probe.first_line = next((ln.strip() for ln in out.splitlines() if ln.strip()), "")
    # `failed` and `blocked` both carry the reason; a blocked tool that
    # reports nothing reads as "no problem" rather than "could not run".
    probe.error_head = head if status in ("failed", "blocked") else ""

    printed = parse_help_flags(out) if out else []
    source_text = ""
    if ecosystem == "python":
        source_text = "\n".join(read_text(p) for p in sorted(root.rglob("*.py"))[:80])
    elif entry:
        source_text = read_text(root / entry)
    declared: list[str] = []
    if ecosystem == "python":
        declared = declared_python_flags(source_text)
    elif ecosystem == "go":
        gofiles = [p for p in root.rglob("*.go") if not p.name.endswith("_test.go")]
        declared = declared_go_flags("\n".join(read_text(p) for p in gofiles[:200]))
    elif ecosystem == "node":
        declared = declared_node_flags("\n".join(
            read_text(p) for p in list(root.rglob("*.js"))[:80]
        ))
    probe.flags = merge_flags(printed, declared)
    probe.ecosystems_detail = describe(ecosystem, entry, probe)
    return probe


def describe(ecosystem: str, entry: str, probe: Probe) -> str:
    src = "з бінарника" if probe.launched_from == "binary" else "з джерела"
    if probe.probe_status == "ran":
        return f"{entry} надрукував {probe.help_lines} рядків {src}"
    if probe.probe_status == "data-only":
        return "корпус даних, програми немає"
    if probe.probe_status == "missing-entry":
        return f"немає чого запускати: {probe.error_head}"
    if probe.probe_status == "timeout":
        return f"help не завершився: {probe.error_head}"
    return f"help упав, код {probe.exit_code}: {probe.error_head[:120]}"


# --------------------------------------------------------------------------
# matrix
# --------------------------------------------------------------------------
def tool_dirs(base: Path, only: Iterable[str] | None = None) -> list[Path]:
    wanted = {w.lower() for w in only} if only else None
    out = []
    for child in sorted(base.iterdir()):
        if not child.is_dir() or child.name in RESERVED_DIRS:
            continue
        if wanted and child.name.lower() not in wanted:
            continue
        out.append(child)
    return out


def render_markdown(results: list[Probe], base: Path) -> str:
    live = [p for p in results if not p.is_copy]
    ran = [p for p in live if p.probe_status == "ran"]
    lines: list[str] = []
    lines.append("# Матриця здатностей клонів")
    lines.append("")
    lines.append(f"**Джерело:** `{base}` · **унікальних інструментів:** {len(live)}")
    lines.append(f"**Серед них help надруковано:** {len(ran)}")
    lines.append("")
    lines.append("Числа нижче виміряно прогоном `tools/capability_probe.py`: кожен рядок")
    lines.append("має стан `ran` / `blocked` і лічильник опцій, а не оцінку.")
    lines.append("")
    lines.append("| інструмент | екосистема | стан help | опцій | з help | з коду | рядків help |")
    lines.append("|---|---|---|---:|---:|---:|---:|")
    for p in sorted(live, key=lambda x: x.tool.lower()):
        lines.append(
            f"| `{p.tool}` | {p.ecosystem} | {p.probe_status} | {p.flag_count} | "
            f"{p.printed_flag_count} | {p.flag_count - p.printed_flag_count} | {p.help_lines} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Capability probe for cloned tools")
    ap.add_argument("base", type=Path, help="directory with clones")
    ap.add_argument("--json", type=Path, dest="json_out")
    ap.add_argument("--md", type=Path, dest="md_out")
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--binaries", type=Path, default=None,
                    help="directory with compiled binaries named after the clone")
    ap.add_argument("--python", default=None,
                    help="interpreter used for python clones (e.g. a virtualenv)")
    ap.add_argument("--include-copies", action="store_true")
    args = ap.parse_args(argv)

    if not args.base.is_dir():
        print(f"немає каталогу: {args.base}", file=sys.stderr)
        return 2
    if args.binaries is not None and not args.binaries.is_dir():
        # Probing without the binaries would silently measure every Go tool as
        # unrunnable, and the matrix would read as "these tools have no help".
        print(f"каталогу бінарників немає: {args.binaries}", file=sys.stderr)
        return 2

    results = []
    for root in tool_dirs(args.base, args.only):
        if COPY_SUFFIX.search(root.name) and not args.include_copies:
            continue
        binary = None
        if args.binaries is not None:
            candidate = args.binaries / root.name
            if not candidate.is_file():
                # a clone whose binary was named differently, e.g. a multi-cmd repo
                for alt in sorted(args.binaries.iterdir()):
                    if alt.is_file() and alt.name.startswith(root.name.rstrip("0123456789")):
                        candidate = alt
                        break
            if candidate.is_file():
                binary = candidate
        results.append(probe_tool(root, timeout=args.timeout, binary=binary,
                                  python=args.python))

    payload = [asdict(p) | {"flag_count": p.flag_count, "printed": p.printed_flag_count} for p in results]
    if args.json_out:
        args.json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.md_out:
        args.md_out.write_text(render_markdown(results, args.base), encoding="utf-8")
    ran = sum(1 for p in results if p.probe_status == "ran")
    print(f"інструментів: {len(results)}  help надруковано: {ran}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())