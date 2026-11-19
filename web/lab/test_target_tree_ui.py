"""Regression tests for Target Map file-type icons and terminal-like tree connectors."""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOGIC_PATH = ROOT / "templates" / "lab" / "includes" / "_active_scanner_logic.html"
STYLES_PATH = ROOT / "templates" / "lab" / "includes" / "_app_styles.html"
APP_CSS_PATH = ROOT / "static" / "css" / "app.css"


def _extract_tree_js(logic_text: str) -> str:
    start = logic_text.index("const TARGET_FILE_ICONS = {")
    end = logic_text.index("function setTargetTreeExpanded(expanded)")
    return logic_text[start:end]


class TargetTreeUITests(unittest.TestCase):
    def test_distinct_file_icons_and_tree_connectors(self):
        logic_text = LOGIC_PATH.read_text(encoding="utf-8")
        tree_js = _extract_tree_js(logic_text)

        node_script = f"""
const escapeHTML = s => String(s ?? '').replace(/[&<>"']/g, c => ({{
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}}[c]));
const tr = k => k;
const targetTreeEl = {{ innerHTML: '' }};
const $ = id => (id === 'target-tree' ? targetTreeEl : null);

{tree_js}

const pages = [
  {{ url: 'https://example.test/index.html', status: 200 }},
  {{ url: 'https://example.test/api/users.json', status: 200 }},
  {{ url: 'https://example.test/api/v2/schema', status: 200, content_type: 'application/json' }},
  {{ url: 'https://example.test/assets/js/app.js', status: 200 }},
  {{ url: 'https://example.test/assets/js/types.ts', status: 200 }},
  {{ url: 'https://example.test/assets/css/main.css', status: 200 }},
  {{ url: 'https://example.test/assets/img/logo.svg', status: 200 }},
  {{ url: 'https://example.test/assets/img/hero.png', status: 200 }},
  {{ url: 'https://example.test/assets/fonts/inter.woff2', status: 200 }},
  {{ url: 'https://example.test/docs/manual.pdf', status: 200 }},
  {{ url: 'https://example.test/docs/report.csv', status: 200 }},
  {{ url: 'https://example.test/docs/notes.txt', status: 200 }},
  {{ url: 'https://example.test/config/app.yaml', status: 200 }},
  {{ url: 'https://example.test/admin/login.php', status: 200 }},
  {{ url: 'https://example.test/scripts/worker.py', status: 200 }},
  {{ url: 'https://example.test/backup.zip', status: 200 }},
  {{ url: 'https://example.test/dump.sql', status: 200 }},
  {{ url: 'https://example.test/module.wasm', status: 200 }},
  {{ url: 'https://example.test/unknown.xyz', status: 404 }},
];

renderTargetTree(pages);
const html = targetTreeEl.innerHTML;

// Collect rendered file entries
const fileMatches = [...html.matchAll(/<span class="tree-file" data-file-type="([^"]+)">(.*?)<\\/span>\\s*(?=<span class="tree-file"|<\\/details>|$)/gs)];
const files = fileMatches.map(m => {{
  const inner = m[2];
  const iconM = inner.match(/<span class="tree-file-icon" title="([^"]+)" aria-hidden="true">(<svg[\\s\\S]*?<\\/svg>)<\\/span>/);
  const nameM = inner.match(/<span class="file-label">([^<]+)<\\/span>/);
  const guides = [...inner.matchAll(/<span class="tree-guide" aria-hidden="true">([^<]+)<\\/span>/g)].map(g => g[1]);
  const branchM = inner.match(/<span class="tree-branch" aria-hidden="true">([^<]+)<\\/span>/);
  return {{
    type: m[1],
    label: iconM ? iconM[1] : null,
    svg: iconM ? iconM[2] : null,
    name: nameM ? nameM[1] : null,
    guides,
    branch: branchM ? branchM[1] : null,
  }};
}});

// Collect rendered folder summaries
const folderMatches = [...html.matchAll(/<summary>(.*?)<\\/summary>/g)];
const folders = folderMatches.map(m => {{
  const inner = m[1];
  const nameM = inner.match(/<span class="folder-label">([^<]+)<\\/span>/);
  const guides = [...inner.matchAll(/<span class="tree-guide" aria-hidden="true">([^<]+)<\\/span>/g)].map(g => g[1]);
  const branchM = inner.match(/<span class="tree-branch" aria-hidden="true">([^<]+)<\\/span>/);
  return {{
    name: nameM ? nameM[1] : null,
    guides,
    branch: branchM ? branchM[1] : null,
  }};
}});

console.log(JSON.stringify({{ html, files, folders }}));
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            js_path = Path(tmpdir) / "check_tree.mjs"
            js_path.write_text(node_script, encoding="utf-8")
            proc = subprocess.run(
                ["node", str(js_path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        self.assertEqual(proc.returncode, 0, f"Node check failed: {proc.stderr}")
        data = json.loads(proc.stdout)

        files_by_name = {f["name"]: f for f in data["files"]}
        self.assertEqual(len(files_by_name), 19)

        # Every file type has a dedicated icon & type
        expected_types = {
            "index.html": "html",
            "users.json": "json",
            "schema": "json",
            "app.js": "js",
            "types.ts": "ts",
            "main.css": "css",
            "logo.svg": "svg",
            "hero.png": "image",
            "inter.woff2": "font",
            "manual.pdf": "pdf",
            "report.csv": "sheet",
            "notes.txt": "text",
            "app.yaml": "config",
            "login.php": "php",
            "worker.py": "python",
            "backup.zip": "archive",
            "dump.sql": "sql",
            "module.wasm": "binary",
            "unknown.xyz": "other",
        }
        for name, expected_type in expected_types.items():
            self.assertIn(name, files_by_name)
            self.assertEqual(files_by_name[name]["type"], expected_type, f"Wrong type for {name}")
            self.assertTrue(files_by_name[name]["svg"], f"Missing SVG icon for {name}")
            self.assertTrue(files_by_name[name]["label"], f"Missing icon label for {name}")

        # Verify distinct SVG icons across distinct types
        type_to_svg = {f["type"]: f["svg"] for f in data["files"]}
        self.assertEqual(len(set(type_to_svg.values())), len(type_to_svg), f"Duplicate SVG icons across types")

        # Verify tree connectors (├──, └──, │   ,     )
        folders_by_name = {f["name"]: f for f in data["folders"]}
        self.assertEqual(folders_by_name["api/"]["branch"], "├── ")
        self.assertEqual(folders_by_name["v2/"]["guides"], ["│   "])
        self.assertEqual(folders_by_name["v2/"]["branch"], "├── ")
        self.assertEqual(files_by_name["schema"]["guides"], ["│   ", "│   "])
        self.assertEqual(files_by_name["schema"]["branch"], "└── ")
        self.assertEqual(files_by_name["users.json"]["guides"], ["│   "])
        self.assertEqual(files_by_name["users.json"]["branch"], "└── ")

        # Root's last entry is a file (unknown.xyz), so it gets '└── '
        self.assertEqual(files_by_name["unknown.xyz"]["guides"], [])
        self.assertEqual(files_by_name["unknown.xyz"]["branch"], "└── ")

        # Last folder at root is 'scripts/' because files follow folders, so it has '├── '
        self.assertEqual(folders_by_name["scripts/"]["branch"], "├── ")
        self.assertEqual(files_by_name["worker.py"]["guides"], ["│   "])
        self.assertEqual(files_by_name["worker.py"]["branch"], "└── ")

    def test_styles_do_not_force_generic_file_emoji(self):
        for path in (STYLES_PATH, APP_CSS_PATH, LOGIC_PATH):
            content = path.read_text(encoding="utf-8")
            self.assertNotRegex(
                content,
                r'\.file-label::?before\s*\{[^}]*content:\s*"📄"',
                f"Generic file emoji ::before still present in {path}",
            )


if __name__ == "__main__":
    unittest.main()
