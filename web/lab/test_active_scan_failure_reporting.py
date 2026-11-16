"""Відмова активного скану має бути видна в UI, а не читатися як успіх.

Знайдено виміром на живій цілі 2026-10-03: активний скан із
`Request timeout = 1 ms` повертав `state: failed` і `error` з причиною, а UI
показував phase `Scan failed`, порожній note і рядок статусу
`Active scan finished: 0 findings, target …` — тобто провалений замір виглядав як
замір «знахідок немає», а причина не потрапляла ніде. Причина в коді:
`pollActiveScan()` передавав у `renderActiveScan()` лише звіт, а той для
**кожного** термінального стану (`completed`, `cancelled`, `failed`) писав рядок
успіху й не малював `answer.error`. До того `slot.current = null` виконувався
для будь-якого виходу, тому відмова ще й зносила доказ попереднього заміру.

Тест виконує справжні функції сторінки, витягнуті з `index.html`, у `node` з
підмінами навколо них. Перевіряється не текст, а поведінка: який рядок статусу
пишеться, який toast, що потрапляє в note панелі прогресу і що залишається в
таблиці знахідок. Мутація (відкат однієї зміни) робить тест червоним — це
перевірено окремо.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "lab" / "index.html"

# Функції сторінки, які треба виконати справжніми, а не переписаними в тесті.
FUNCTIONS = ("stopActiveScanTicker", "activeScanPercent", "activeScanStats", "applyActiveScanProgress", "renderActiveScan")

NEW_KEYS = (
    "scanner.activeFailedLine",
    "scanner.activeFailedShort",
    "scanner.activeFailedNoReason",
    "scanner.activeCancelledLine",
    "scanner.activeKeptPrevious",
)

DRIVER = r"""
%(functions)s

// Підміни навколо функцій сторінки: те, що вони бачать, і те, що ми хочемо
// прочитати назовні. `tr` повертає ключ із підстановками, тому перевірка не
// залежить від формулювання рядка, а від того, який саме ключ обрано і чи
// підставлено причину.
let activeScanTicker = null;
let currentScanner = null;
let activeScanRun = null;
const calls = {status: [], toasts: [], progress: [], findings: [], exportDisabled: []};
function tr(key, variables = {}) {
  let value = key;
  for (const [name, replacement] of Object.entries(variables)) {
    value = `${value}{${name}=${String(replacement)}}`;
  }
  return value;
}
function setScannerStatusLine(text) { calls.status.push(String(text)); }
function showToast(title, message, tone = 'info') { calls.toasts.push({title, message, tone}); }
function setScanProgress(options) { calls.progress.push(options); }
function renderActiveScanFindings(report) { calls.findings.push(report); }
const exportNode = {disabled: false};
function $(id) { return id === 'scanner-export-active' ? exportNode : null; }
const scannerViews = {active: {current: null, exportSelect: 'scanner-export-active'}};

const scenario = JSON.parse(process.argv[2]);
activeScanRun = scenario.run || null;
if (scenario.previous !== undefined) scannerViews.active.current = scenario.previous;
renderActiveScan(scenario.data);
console.log(JSON.stringify({
  calls,
  slot: scannerViews.active.current,
  exportDisabled: exportNode.disabled,
  currentScanner
}));
"""


def function_source(template: str, name: str) -> str:
    """Тіло однієї функції сторінки, зрізане по парних дужках.

    Дужки рахуються лише після закриття списку параметрів: `function f(x = {})`
    має фігурну дужку в значенні за замовчуванням, і зріз по ній обрізав би
    функцію до першої ж рядки тіла.
    """
    start = template.find(f"function {name}(")
    if start < 0:
        raise AssertionError(f"{name} is not in the template")
    parens = 0
    index = start + len(f"function {name}(") - 1
    body = None
    while index < len(template):
        character = template[index]
        if character == "(":
            parens += 1
        elif character == ")":
            parens -= 1
        elif character == "{" and parens <= 0:
            body = index
            break
        index += 1
    if body is None:
        raise AssertionError(f"{name} has no opening brace for its body")
    depth = 0
    for position in range(body, len(template)):
        character = template[position]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return template[start:position + 1]
    raise AssertionError(f"{name} has no closing brace")


def run_node(template: str, scenario: dict) -> dict:
    driver = DRIVER % {"functions": "\n\n".join(function_source(template, name) for name in FUNCTIONS)}
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "scenario.mjs"
        script.write_text(driver, encoding="utf-8")
        completed = subprocess.run(
            ["node", str(script), json.dumps(scenario)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    if completed.returncode != 0:
        raise AssertionError(f"node failed: {completed.stderr.strip()[:400]}")
    return json.loads(completed.stdout)


@unittest.skipUnless(shutil.which("node"), "node is required to run the page's own functions")
class ActiveScanFailureReportingTests(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE.read_text(encoding="utf-8")

    def last_status(self, result) -> str:
        self.assertTrue(result["calls"]["status"], "no status line was written at all")
        return result["calls"]["status"][-1]

    def test_a_failed_run_says_so_and_names_the_reason(self):
        """The defect itself: a dead run must not read as a finished one."""
        result = run_node(self.template, {
            "run": {"state": "failed", "startedAt": 0, "progress": {"phase": "failed", "findings": 0}},
            "data": {
                "state": "failed",
                "error": "active: GET https://www.pravda.ru/: Client.Timeout exceeded while awaiting headers",
                "result": None,
            },
        })
        status = self.last_status(result)
        self.assertIn("scanner.activeFailedLine", status)
        self.assertNotIn("scanner.activeDoneLine", status)
        self.assertIn("Client.Timeout exceeded while awaiting headers", status)
        self.assertEqual(result["calls"]["toasts"][-1]["tone"], "error")
        self.assertIn("Client.Timeout", result["calls"]["toasts"][-1]["message"])
        # The progress panel's note is where an operator looks after a failure.
        self.assertEqual(result["calls"]["progress"][-1]["note"],
                         "active: GET https://www.pravda.ru/: Client.Timeout exceeded while awaiting headers")
        self.assertTrue(result["calls"]["progress"][-1]["failed"])

    def test_a_failed_run_without_a_reason_says_so_rather_than_blank(self):
        result = run_node(self.template, {
            "run": {"state": "failed", "startedAt": 0, "progress": {"phase": "failed"}},
            "data": {"state": "failed", "error": "", "result": None},
        })
        status = self.last_status(result)
        self.assertIn("scanner.activeFailedLine", status)
        self.assertIn("scanner.activeFailedNoReason", status)
        self.assertNotIn("scanner.activeDoneLine", status)
        self.assertEqual(result["calls"]["toasts"][-1]["tone"], "error")

    def test_a_failed_run_does_not_wipe_the_evidence_of_the_previous_one(self):
        previous = {"engine": "active", "url": "https://www.pravda.ru/", "findings": [{"id": "P-1"}]}
        result = run_node(self.template, {
            "run": {"state": "failed", "startedAt": 0, "progress": {"phase": "failed"}},
            "previous": previous,
            "data": {"state": "failed", "error": "context deadline exceeded", "result": None},
        })
        self.assertEqual(result["slot"], previous)
        self.assertFalse(result["exportDisabled"], "the export was disabled by a run that proved nothing")
        self.assertIn("scanner.activeKeptPrevious", self.last_status(result))

    def test_a_failed_run_with_a_report_keeps_that_report(self):
        report = {"target": "https://www.pravda.ru/", "findings": [{"id": "A-1"}], "stats": {"verified": 1}}
        result = run_node(self.template, {
            "run": {"state": "failed", "startedAt": 0, "progress": {"phase": "failed", "findings": 1}},
            "data": {"state": "failed", "error": "context deadline exceeded", "result": report},
        })
        self.assertEqual(result["slot"]["findings"], report["findings"])
        self.assertEqual(result["slot"]["engine"], "active")
        self.assertEqual(result["calls"]["findings"][-1], result["slot"])
        self.assertIn("context deadline exceeded", self.last_status(result))

    def test_a_cancelled_run_has_its_own_line_and_no_error_toast(self):
        result = run_node(self.template, {
            "run": {"state": "cancelled", "startedAt": 0, "progress": {"phase": "cancelled"}},
            "data": {"state": "cancelled", "error": "", "url": "https://www.pravda.ru/"},
        })
        status = self.last_status(result)
        self.assertIn("scanner.activeCancelledLine", status)
        self.assertNotIn("scanner.activeDoneLine", status)
        self.assertNotIn("scanner.activeFailedLine", status)
        self.assertEqual(result["calls"]["toasts"], [], "a cancel is a state the operator asked for")
        self.assertTrue(result["exportDisabled"], "there is no report, so there is nothing to export")

    def test_a_completed_run_still_reports_its_findings(self):
        report = {"target": "https://www.pravda.ru/", "findings": [{"id": "A-1"}, {"id": "A-2"}], "stats": {}}
        result = run_node(self.template, {
            "run": {"state": "completed", "startedAt": 0, "progress": {"phase": "completed", "findings": 2}},
            "data": {"state": "completed", "error": None, "result": report},
        })
        status = self.last_status(result)
        self.assertIn("scanner.activeDoneLine", status)
        self.assertIn("count=2", status)
        self.assertIn("https://www.pravda.ru/", status)
        self.assertEqual(result["calls"]["progress"][-1]["note"], "")
        self.assertFalse(result["exportDisabled"])

    def test_a_restored_completed_run_when_active_scan_run_is_null_shows_completed_not_running(self):
        report = {
            "target": "https://www.pravda.ru/",
            "findings": [{"id": "A-1"}],
            "stats": {"verified": 311, "capped": 62, "requests": 12596},
        }
        result = run_node(self.template, {
            "run": None,
            "data": {"state": "completed", "error": None, "result": report},
        })
        progress = result["calls"]["progress"][-1]
        self.assertEqual(progress["phase"], "completed")
        self.assertEqual(progress["percent"], 100)
        self.assertTrue(progress["done"])
        self.assertFalse(progress["failed"])

    def test_every_new_line_exists_in_both_languages_and_differs(self):
        translations_file = Path(__file__).resolve().parents[1] / "templates" / "lab" / "includes" / "_translations.html"
        source_text = self.template + (translations_file.read_text(encoding="utf-8") if translations_file.exists() else "")
        for key in NEW_KEYS:
            with self.subTest(key=key):
                found = re.findall(r"'" + re.escape(key) + r"'\s*:\s*'([^']*)'", source_text)
                self.assertEqual(len(found), 2, f"{key}: {len(found)} entries, expected one per dictionary")
                uk, en = found
                self.assertTrue(uk.strip() and en.strip(), f"{key} is empty in one language")
                self.assertNotEqual(uk, en, f"{key} is the same in both languages")


if __name__ == "__main__":
    unittest.main()