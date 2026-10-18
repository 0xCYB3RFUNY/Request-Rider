"""Перезапуск рушія не має викидати вже знайдене.

Знайдено за зауваженням оператора 2026-10-10: прогін корпусу зник, і UI показав
«прогін втрачено». Але рушій тримає job у пам'яті — зник **процес**, а не
**звіт**: сторінка вже мала кожну знахідку цього прогону у workspace-снапшоті, і
повідомлення про помилку витирало завершену роботу.

Тест виконує справжній `restoreCorpusJob` сторінки в `node` з підмінами: `fetch`
відповідає 404 (двигун перезапустився), а сторінка тримає N знахідок.
Перевіряється поведінка, а не текст: що викликається і що залишається на екрані.

Другий випадок — надто: якщо знахідок немає, відновлювати нічого, і тоді
повідомлення про помилку є правильною відповіддю.
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
FUNCTIONS = ("setCorpusStatus", "showProgress", "setCorpusProgress",
             "setCorpusRunning", "finishCorpusRun", "restoreCorpusJob")

DRIVER = r"""
%(functions)s

// Підміни навколо функцій сторінки: те, що вони бачать, і те, що ми хочемо
// прочитати назовні. `tr` повертає ключ, тому перевірка не залежить від
// формулювання рядка, а від того, який саме ключ обрано і чи підставлено число.
const calls = {status: [], progress: [], finished: [], running: []};
function tr(key, variables = {}) {
  let value = key;
  for (const [name, replacement] of Object.entries(variables)) {
    value = `${value}{${name}=${String(replacement)}}`;
  }
  return value;
}
function escapeCorpus(value) { return String(value == null ? '' : value); }
function setCorpusStatus(text, tone) { calls.status.push({text: String(text), tone}); }
function showProgress(on) { calls.progress.push(!!on); }
function setCorpusProgress(job) { calls.progress.push({job}); }
function setCorpusRunning(on) { calls.running.push(!!on); }
function finishCorpusRun(data) { calls.finished.push(data); }
function openCorpusStream() {}
function stopCorpusStream() {}
function stopCorpusPolling() {}

const scenario = JSON.parse(process.argv[2]);
corpusFindings = scenario.findings || [];
corpusJobId = scenario.jobId || 'corpus-1';

(async () => {
  await restoreCorpusJob(corpusJobId);
  console.log(JSON.stringify({calls, corpusFindings: corpusFindings.length}));
})();
"""


def function_source(template: str, name: str) -> str:
    """Тіло однієї функції сторінки, зрізане по парних дужках."""
    match = re.search(r"(?:async\s+)?function\s+%s\s*\(" % re.escape(name), template)
    if match is None:
        raise AssertionError("функція %s не знайдена в шаблоні" % name)
    start = match.start()
    index = template.index("{", match.end() - 1)
    depth = 0
    while index < len(template):
        character = template[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return template[start:index + 1]
        index += 1
    raise AssertionError("не знайдено кінець тіла функції %s" % name)


class CorpusRunSurvivesAnEngineRestartTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node") or "/usr/bin/node"
        self.template = TEMPLATE.read_text(encoding="utf-8")
        self.body = "\n\n".join(function_source(self.template, name) for name in FUNCTIONS)

    def run_page(self, scenario: dict) -> dict:
        driver = DRIVER % {"functions": self.body}
        # Сторінка звертається до рушія через відносний шлях, тож підміняється
        # саме `fetch`: 404 — це те, що рушій відповідає на job, якого в ньому
        # більше немає після перезапуску.
        driver = driver.replace(
            "const scenario = JSON.parse(process.argv[2]);",
            "const scenario = JSON.parse(process.argv[2]);\n"
            "async function fetch() {\n"
            "  return {ok: false, status: 404, json: async () => ({error: 'no corpus job'})};\n"
            "}\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "driver.js"
            script.write_text(driver, encoding="utf-8")
            completed = subprocess.run(
                [self.node, str(script), json.dumps(scenario)],
                capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout.strip().splitlines()[-1])

    def test_findings_are_restored_when_the_engine_forgot_the_job(self):
        findings = [
            {"CheckID": "exposed-git", "Method": "GET", "Path": "/.git/config", "StatusCode": 200},
            {"CheckID": "nginx-status", "Method": "GET", "Path": "/nginx_status", "StatusCode": 200},
        ]
        result = self.run_page({"findings": findings, "jobId": "corpus-1"})

        self.assertEqual(len(result["calls"]["finished"]), 1,
                         "звіт прогону не відновлено: рушій забув job, а screen показує помилку замість його знахідок")
        restored = result["calls"]["finished"][0]
        self.assertEqual(restored["finding_count"], 2)
        self.assertEqual([row["Path"] for row in restored["findings"]],
                         ["/.git/config", "/nginx_status"])

        self.assertEqual(result["corpusFindings"], 2,
                         "знахідки зникли зі сторінки разом із помилкою")
        statuses = [call["text"] for call in result["calls"]["status"]]
        self.assertTrue(any("scanner.corpusRestored" in text for text in statuses),
                        "статус має казати, що звіт відновлено, а не що прогін втрачено: %r" % statuses)
        self.assertFalse(any("scanner.corpusLost" in text for text in statuses),
                        "прогін, знахідки якого збережені, не є втраченим: %r" % statuses)

        self.assertIn(False, result["calls"]["running"],
                      "відновлений звіт не повинен лишати кнопку скасування натиснутою")

    def test_a_run_with_no_findings_still_reports_that_it_is_gone(self):
        # Нема чого відновлювати: тоді повідомлення про помилку є чесною
        # відповіддю, і приховувати її ніде.
        result = self.run_page({"findings": [], "jobId": "corpus-1"})

        self.assertEqual(result["calls"]["finished"], [],
                         "порожній звіт викликає finishCorpusRun: нічого відновлювати")
        statuses = [call["text"] for call in result["calls"]["status"]]
        self.assertTrue(any("scanner.corpusLost" in text for text in statuses),
                        "прогін без знахідок має прямо сказати, що його немає: %r" % statuses)


if __name__ == "__main__":
    unittest.main()