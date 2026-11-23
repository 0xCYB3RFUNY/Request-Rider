"""Перевірка відновлення активних процесів після перезавантаження сторінки.

Тестує справжні JS-функції сторінки (`rememberActiveScanJob`,
`restoreActiveScanJob`, `rememberOsintTransformJob`, `restoreOsintTransformJob`,
`restoreWorkflowRun`) у Node.js із підміною DOM, localStorage та fetch.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ACTIVE_SCANNER_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "templates"
    / "lab"
    / "includes"
    / "_active_scanner_logic.html"
)
PROJECT_TRANSFER_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "templates"
    / "lab"
    / "includes"
    / "_project_transfer.html"
)


def extract_function(template: str, name: str) -> str:
    """Витягує тіло однієї функції з шаблону по парних фігурних дужках."""
    match = re.search(r"(?:async\s+)?function\s+%s\s*\(" % re.escape(name), template)
    if match is None:
        raise AssertionError("Функція %s не знайдена в шаблоні" % name)
    start = match.start()
    index = template.index("{", match.end() - 1)
    depth = 0
    while index < len(template):
        ch = template[index]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return template[start : index + 1]
        index += 1
    raise AssertionError("Не знайдено кінець тіла функції %s" % name)


NUCLEI_DRIVER = r"""
const activeScanJobStorageKey = 'scanner-active-nuclei-job';
const activeScanJobMetaStorageKey = 'scanner-active-nuclei-meta';

const storage = new Map(Object.entries(%(initial_storage)s));
const localStorage = {
  getItem: k => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: k => storage.delete(k),
};

const nodes = {};
function $(id) {
  if (!nodes[id]) nodes[id] = {id, value: '', textContent: '', hidden: true, disabled: false, replaceChildren() {}};
  return nodes[id];
}

const calls = {progress: [], view: [], reportState: [], rendered: [], followed: [], stoppedTicker: 0, persisted: 0};
let scannerRun = null;
let scannerTemplateReport = [];
let scannerTemplateFiltered = [];
let scannerTemplateEntries = [];
let scannerTemplateShown = 0;
let scannerTemplateExpanded = new Set();
let scannerTemplateLiveFolders = new Map();
const liveTemplateNames = new Set();

function tr(k, vars = {}) { return k; }
function formatScanProgress(p = {}) { return p.templates ? [['templates', String(p.templates)]] : []; }
function scanProgressNote(p = {}) { return ''; }
function setScannerView(v, opts) { calls.view.push({v, opts}); }
function setScanProgress(p) { calls.progress.push(p); }
function setScannerReportState(s) { calls.reportState.push(s); }
function renderScannerTemplateRun(data, count, url) { calls.rendered.push({data, count, url}); }
function queueWorkspacePersistence() { calls.persisted += 1; }
function stopScanTicker() { calls.stoppedTicker += 1; }
async function followScannerJob(jobId, opts) {
  calls.followed.push({jobId, hasOnFinish: typeof opts?.onFinish === 'function'});
}
async function fetch(url) {
  const resp = %(fetch_response)s;
  return {
    ok: resp.status >= 200 && resp.status < 300,
    status: resp.status,
    json: async () => resp.body
  };
}

%(functions)s

(async () => {
  await restoreActiveScanJob();
  console.log(JSON.stringify({
    storage: Object.fromEntries(storage),
    scannerRun,
    calls,
    statusText: $('scanner-nuclei-status').textContent,
    resultsHidden: $('scanner-tpl-results').hidden,
    perfileTitleHidden: $('scanner-tpl-perfile-title').hidden
  }));
})();
"""


OSINT_AND_WORKFLOW_DRIVER = r"""
const storage = new Map(Object.entries(%(initial_storage)s));
const localStorage = {
  getItem: k => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: k => storage.delete(k),
};
const nodes = {};
function $(id) {
  if (!nodes[id]) nodes[id] = {id, value: '', textContent: '', hidden: true, disabled: false};
  return nodes[id];
}
const calls = {osintPolled: [], osintLoaded: [], wfPolled: [], wfRendered: []};
let osintGraphId = null;
let osintTransformJobId = null;
let osintTransformRunSequence = 0;
let workflowCurrentId = null;
let workflowCurrentRun = null;

function tr(k) { return k; }
function startOsintTransformTimer() {}
function stopOsintTransformTimer() {}
async function loadOsintGraph(id) { calls.osintLoaded.push(id); }
async function pollOsintTransformJob(jobId, opts) { calls.osintPolled.push({jobId, opts}); }
function renderWorkflowRuns(runs) { calls.wfRendered.push(runs); }
function pollWorkflowRun(runId) { calls.wfPolled.push(runId); }

async function readJSON(res) {
  if (!res.ok) throw Object.assign(new Error('HTTP ' + res.status), {status: res.status});
  return res.json();
}
async function fetch(url) {
  const map = %(fetch_map)s;
  const hit = map[url] || {status: 404, body: {error: 'not found'}};
  return {
    ok: hit.status >= 200 && hit.status < 300,
    status: hit.status,
    json: async () => hit.body
  };
}

%(functions)s

(async () => {
  await restoreOsintTransformJob();
  await restoreWorkflowRun();
  console.log(JSON.stringify({
    storage: Object.fromEntries(storage),
    osintTransformJobId,
    osintGraphId,
    workflowCurrentId,
    workflowCurrentRun,
    calls
  }));
})();
"""


class StatePersistenceRestoreTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node") or "/usr/bin/node"
        self.active_tpl = ACTIVE_SCANNER_TEMPLATE.read_text(encoding="utf-8")
        self.transfer_tpl = PROJECT_TRANSFER_TEMPLATE.read_text(encoding="utf-8")

    def _run_node(self, script_text: str) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "driver.js"
            path.write_text(script_text, encoding="utf-8")
            proc = subprocess.run(
                [self.node, str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_nuclei_restore_running_job_reattaches_stream(self):
        funcs = "\n\n".join([
            extract_function(self.active_tpl, "rememberActiveScanJob"),
            extract_function(self.active_tpl, "restoreActiveScanJob"),
        ])
        script = NUCLEI_DRIVER % {
            "initial_storage": json.dumps({
                "scanner-active-nuclei-job": "job-nuc-1",
                "scanner-active-nuclei-meta": json.dumps({"startedAt": 1000, "url": "https://example.test"}),
            }),
            "fetch_response": json.dumps({
                "status": 200,
                "body": {
                    "job_id": "job-nuc-1",
                    "state": "running",
                    "progress": {"phase": "running", "percent": 42, "templates": 10},
                },
            }),
            "functions": funcs,
        }
        res = self._run_node(script)
        self.assertEqual(len(res["calls"]["followed"]), 1)
        self.assertEqual(res["calls"]["followed"][0]["jobId"], "job-nuc-1")
        self.assertEqual(res["scannerRun"]["jobId"], "job-nuc-1")
        self.assertFalse(res["scannerRun"]["paused"])
        self.assertFalse(res["resultsHidden"])
        self.assertFalse(res["perfileTitleHidden"])
        self.assertEqual(res["statusText"], "scanner.progressScanning")
        self.assertIn("scanner-active-nuclei-job", res["storage"])

    def test_nuclei_restore_paused_job_preserves_paused_state(self):
        funcs = "\n\n".join([
            extract_function(self.active_tpl, "rememberActiveScanJob"),
            extract_function(self.active_tpl, "restoreActiveScanJob"),
        ])
        script = NUCLEI_DRIVER % {
            "initial_storage": json.dumps({"scanner-active-nuclei-job": "job-nuc-2"}),
            "fetch_response": json.dumps({
                "status": 200,
                "body": {"job_id": "job-nuc-2", "state": "paused", "progress": {"phase": "paused", "percent": 55}},
            }),
            "functions": funcs,
        }
        res = self._run_node(script)
        self.assertTrue(res["scannerRun"]["paused"])
        self.assertEqual(res["statusText"], "scanner.progressPaused")
        self.assertEqual(res["calls"]["followed"][0]["jobId"], "job-nuc-2")

    def test_nuclei_restore_completed_job_renders_report_and_clears_storage(self):
        funcs = "\n\n".join([
            extract_function(self.active_tpl, "rememberActiveScanJob"),
            extract_function(self.active_tpl, "restoreActiveScanJob"),
        ])
        script = NUCLEI_DRIVER % {
            "initial_storage": json.dumps({
                "scanner-active-nuclei-job": "job-nuc-3",
                "scanner-active-nuclei-meta": json.dumps({"startedAt": 1000, "url": "https://example.test"}),
            }),
            "fetch_response": json.dumps({
                "status": 200,
                "body": {
                    "job_id": "job-nuc-3",
                    "state": "completed",
                    "result": {
                        "url": "https://example.test",
                        "findings": [{"title": "XSS"}],
                        "templates": [{"name": "xss.yaml", "status": "matched"}],
                    },
                },
            }),
            "functions": funcs,
        }
        res = self._run_node(script)
        self.assertEqual(res["calls"]["followed"], [])
        self.assertEqual(len(res["calls"]["rendered"]), 1)
        self.assertEqual(res["calls"]["rendered"][0]["count"], 1)
        self.assertEqual(res["calls"]["persisted"], 1)
        self.assertNotIn("scanner-active-nuclei-job", res["storage"])
        self.assertNotIn("scanner-active-nuclei-meta", res["storage"])

    def test_nuclei_restore_404_clears_stale_storage(self):
        funcs = "\n\n".join([
            extract_function(self.active_tpl, "rememberActiveScanJob"),
            extract_function(self.active_tpl, "restoreActiveScanJob"),
        ])
        script = NUCLEI_DRIVER % {
            "initial_storage": json.dumps({"scanner-active-nuclei-job": "gone-job"}),
            "fetch_response": json.dumps({"status": 404, "body": {"error": "unknown"}}),
            "functions": funcs,
        }
        res = self._run_node(script)
        self.assertEqual(res["calls"]["followed"], [])
        self.assertNotIn("scanner-active-nuclei-job", res["storage"])

    def test_osint_and_workflow_restore_active_jobs(self):
        funcs = "\n\n".join([
            "const osintTransformStorageKey = 'rr-osint-transform-job';",
            extract_function(self.active_tpl, "rememberOsintTransformJob"),
            extract_function(self.active_tpl, "restoreOsintTransformJob"),
            extract_function(self.transfer_tpl, "restoreWorkflowRun"),
        ])
        script = OSINT_AND_WORKFLOW_DRIVER % {
            "initial_storage": json.dumps({
                "rr-osint-transform-job": json.dumps({
                    "jobId": "osint-1", "graphId": 7, "transform": "subdomains", "value": "example.com"
                }),
                "rr-active-workflow-run": json.dumps({"runId": 99, "workflowId": 12}),
            }),
            "fetch_map": json.dumps({
                "/api/osint/graphs/7/transform/jobs/osint-1": {"status": 200, "body": {"state": "running"}},
                "/api/workflows/runs/99": {"status": 200, "body": {"id": 99, "status": "running", "workflow_id": 12}},
            }),
            "functions": funcs,
        }
        res = self._run_node(script)
        self.assertEqual(res["osintTransformJobId"], "osint-1")
        self.assertEqual(res["osintGraphId"], 7)
        self.assertEqual(res["calls"]["osintPolled"][0]["jobId"], "osint-1")
        self.assertEqual(res["workflowCurrentId"], 12)
        self.assertEqual(res["calls"]["wfPolled"], [99])


if __name__ == "__main__":
    unittest.main()
