"""Regression tests for findings shared by Scanner and the Project dashboard."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = WEB_ROOT / "templates" / "lab"
INDEX = TEMPLATE_ROOT / "index.html"
ACTIVE_SCANNER = TEMPLATE_ROOT / "includes" / "_active_scanner_logic.html"


def function_source(source: str, name: str) -> str:
    match = re.search(r"(?:async\s+)?function\s+%s\s*\(" % re.escape(name), source)
    if match is None:
        raise AssertionError("function %s was not found" % name)
    start = match.start()
    index = source.index("{", match.end() - 1)
    depth = 0
    while index < len(source):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
        index += 1
    raise AssertionError("function %s has no closing brace" % name)


class ScannerLiveFindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node") or "/usr/bin/node"
        cls.active_source = ACTIVE_SCANNER.read_text(encoding="utf-8")
        cls.index_source = INDEX.read_text(encoding="utf-8")

    def run_node(self, source: str) -> dict:
        completed = subprocess.run(
            [self.node, "-e", source],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout.strip().splitlines()[-1])

    def test_script_partials_do_not_close_the_parent_inline_script(self):
        partials = (
            ACTIVE_SCANNER,
            TEMPLATE_ROOT / "includes" / "_project_transfer.html",
            TEMPLATE_ROOT / "includes" / "_export_reports_shared.html",
            TEMPLATE_ROOT / "includes" / "_ui_preferences.html",
        )
        for partial in partials:
            with self.subTest(partial=partial.name):
                self.assertNotRegex(
                    partial.read_text(encoding="utf-8"),
                    r"(?im)^\s*</?script\b",
                )

    def test_scanner_view_state_exists_before_the_initial_language_redraw(self):
        declaration = self.index_source.index("let scannerActiveView = 'cms';")
        initial_redraw = self.index_source.index("\napplyLanguage();")
        self.assertLess(declaration, initial_redraw)
        self.assertNotIn("workspaceLabels", self.active_source)

    def test_project_transfer_partial_is_inside_the_application_script(self):
        script_start = self.index_source.index(
            '<script nonce="{{ csp_nonce }}">\nlet language'
        )
        include = self.index_source.index(
            '{% include "lab/includes/_project_transfer.html" %}'
        )
        script_end = self.index_source.index("</script>", script_start)
        self.assertLess(script_start, include)
        self.assertLess(include, script_end)

    def test_corpus_checks_for_the_same_endpoint_keep_distinct_fingerprints(self):
        source = "\n\n".join(
            function_source(self.active_source, name)
            for name in ("getFindingFingerprint", "normalizeCorpusFinding")
        )
        result = self.run_node(
            source
            + """
const target = 'https://qa.invalid/';
const first = normalizeCorpusFinding({
  CheckID: 'check-one', Method: 'GET', Path: '/same', StatusCode: 200,
  Description: 'same response'
}, target);
const second = normalizeCorpusFinding({
  CheckID: 'check-two', Method: 'GET', Path: '/same', StatusCode: 200,
  Description: 'same response'
}, target);
const repeated = normalizeCorpusFinding({
  CheckID: 'check-one', Method: 'GET', Path: '/same', StatusCode: 200,
  Description: 'same response'
}, target);
console.log(JSON.stringify({
  first: getFindingFingerprint(first),
  second: getFindingFingerprint(second),
  repeated: getFindingFingerprint(repeated)
}));
"""
        )
        self.assertNotEqual(result["first"], result["second"])
        self.assertEqual(result["first"], result["repeated"])

    def test_dashboard_load_more_reaches_every_finding(self):
        source = "\n\n".join(
            function_source(self.index_source, name)
            for name in ("renderHubFindingsList", "showMoreHubFindings")
        )
        result = self.run_node(
            source
            + """
let hubActiveFindingsCache = Array.from({length: 120}, (_, index) => ({
  id: `finding-${index}`, title: `Finding ${index}`, severity: 'MEDIUM',
  endpoint: `https://qa.invalid/${index}`
}));
let hubSelectedFilter = 'ALL';
let hubFindingsVisibleCount = 50;
let language = 'en';
const container = {innerHTML: '', querySelectorAll: () => []};
const badge = {textContent: ''};
const more = {hidden: true};
const moreButton = {textContent: ''};
function $(id) {
  return {
    'hub-findings-feed-list': container,
    'hub-findings-badge': badge,
    'hub-findings-more': more,
    'hub-findings-more-btn': moreButton
  }[id] || null;
}
function tr(key, values = {}) {
  return `Show more · ${values.count} of ${values.total}`;
}
function escapeHTML(value) { return String(value ?? ''); }
function localizeFindingTitle(value) { return value; }
function renderMethodBadge(value) { return value; }
function visibleCount() {
  return (container.innerHTML.match(/class="hub-finding-card"/g) || []).length;
}
const counts = [];
renderHubFindingsList();
counts.push(visibleCount());
showMoreHubFindings();
counts.push(visibleCount());
showMoreHubFindings();
counts.push(visibleCount());
console.log(JSON.stringify({
  counts, badge: badge.textContent, hidden: more.hidden, label: moreButton.textContent
}));
"""
        )
        self.assertEqual(result["counts"], [50, 100, 120])
        self.assertEqual(result["badge"], 120)
        self.assertTrue(result["hidden"])
        self.assertEqual(result["label"], "Show more · 120 of 120")

    def test_cms_and_active_finding_localization_js(self):
        source = "\n\n".join(
            function_source(self.index_source, name)
            for name in (
                "localizeSeverity",
                "localizeFindingCategory",
                "localizeFindingTitle",
                "localizeFindingDesc",
                "localizeFindingRemediation",
                "localizeFindingEvidence",
            )
        )
        result = self.run_node(
            source
            + """
let language = 'uk';
function tr(key) { return key; }

const outUk = {
  sev: localizeSeverity('HIGH'),
  cat: localizeFindingCategory('admin'),
  titleCms: localizeFindingTitle('WordPress Login Interface Disclosed'),
  titleSafe: localizeFindingTitle('Strict-Transport-Security Header Missing'),
  descCms: localizeFindingDesc('CMS platform WordPress identified via passive signatures and HTML structure.'),
  remCms: localizeFindingRemediation('Restrict administrative endpoints to trusted IP addresses, enforce multi-factor authentication (MFA), and keep CMS core and plugins updated.'),
  evCms: localizeFindingEvidence('HTTP 200 received from /wp-login.php.')
};

language = 'en';
const outEn = {
  sev: localizeSeverity('HIGH'),
  cat: localizeFindingCategory('admin'),
  titleCms: localizeFindingTitle('WordPress Login Interface Disclosed'),
  descCms: localizeFindingDesc('CMS platform WordPress identified via passive signatures and HTML structure.')
};

console.log(JSON.stringify({uk: outUk, en: outEn}));
"""
        )
        uk = result["uk"]
        self.assertEqual(uk["sev"], "ВИСОКИЙ")
        self.assertEqual(uk["cat"], "Адміністрування")
        self.assertEqual(uk["titleCms"], "Відкритий інтерфейс входу WordPress (wp-login.php)")
        self.assertEqual(uk["titleSafe"], "Відсутній заголовок Strict-Transport-Security (HSTS)")
        self.assertIn("Платформу CMS WordPress ідентифіковано", uk["descCms"])
        self.assertIn("Обмежте доступ до адміністративних інтерфейсів", uk["remCms"])
        self.assertEqual(uk["evCms"], "Отримано відповідь HTTP 200 від /wp-login.php.")

        en = result["en"]
        self.assertEqual(en["sev"], "HIGH")
        self.assertEqual(en["cat"], "ADMIN")
        self.assertEqual(en["titleCms"], "WordPress Login Interface Disclosed")
        self.assertIn("passive signatures", en["descCms"])

    def test_render_cms_findings_localized_in_uk(self):
        loc_sources = "\n\n".join(
            function_source(self.index_source, name)
            for name in (
                "localizeSeverity",
                "localizeFindingCategory",
                "localizeFindingTitle",
                "localizeFindingDesc",
                "localizeFindingRemediation",
                "localizeFindingEvidence",
            )
        )
        cms_source = function_source(self.active_source, "renderCmsFindings")
        result = self.run_node(
            loc_sources
            + "\n\n"
            + cms_source
            + """
let language = 'uk';
function tr(key) { return key; }
function escapeHTML(str) { return String(str ?? ''); }

const document = {
  createElement: (tag) => ({
    tagName: tag,
    className: '',
    style: {},
    innerHTML: '',
    addEventListener: () => {}
  })
};

const resultsNode = { hidden: true };
const bodyNode = {
  children: [],
  replaceChildren: (...nodes) => { bodyNode.children = nodes; }
};

function $(id) {
  if (id === 'scanner-cms-results') return resultsNode;
  if (id === 'scanner-cms-body') return bodyNode;
  return null;
}

const payload = {
  findings: [
    {
      severity: 'HIGH',
      category: 'admin',
      title: 'WordPress Login Interface Disclosed',
      evidence: 'HTTP 200 received from /wp-login.php.',
      recommendation: 'Restrict administrative endpoints to trusted IP addresses, enforce multi-factor authentication (MFA), and keep CMS core and plugins updated.'
    }
  ]
};

renderCmsFindings(payload);
const html = bodyNode.children.map(c => c.innerHTML).join('\\n');
console.log(JSON.stringify({ html }));
"""
        )
        html = result["html"]
        self.assertIn("ВИСОКИЙ", html)
        self.assertIn("Адміністрування", html)
        self.assertIn("Відкритий інтерфейс входу WordPress (wp-login.php)", html)
        self.assertIn("Отримано відповідь HTTP 200 від /wp-login.php.", html)
        self.assertIn("Обмежте доступ до адміністративних інтерфейсів", html)


if __name__ == "__main__":
    unittest.main()
