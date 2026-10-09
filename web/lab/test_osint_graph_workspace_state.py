"""Стан OSINT-workspace має описувати те, що на полотні.

Виміряно 2026-10-03 на живому стенді: сторінка завантажує граф (237 вузлів),
але перший клік по вкладці OSINT **стирає** його — `currentOsintGraph` стає
null, вузлів 0, лічильник показує `CREATE OR SELECT A GRAPH TO RENDER
ENTITIES.`, і граф треба відновлювати кнопкою Refresh.

Причина в коді: `loadOsintGraphs()` малює `desired` на старті, але не записує
його у стан жодного workspace. `restoreWorkspaceState()` читає
`state.graphId` і, коли він порожній, викликає `loadOsintGraph('')` — а це
єдиний шлях, що спорожнює полотно. Стан знімається лише під час persist, а
persist після стартового завантаження ніхто не ініціював.

Тест виконує справжню функцію сторінки, витягнуту з `index.html`, у `node`:
перевіряє, що порожній OSINT-workspace отримує `graphId`, що воркспейс із
власним графіхом не змінюється, що інші види не зачеплені, і що виклик
провід реально стоїть у `loadOsintGraphs` після вдалого завантаження.
Мутація (прибрати виклик або змінити умову) робить тест червоним.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "lab" / "index.html"

HELPER = "syncOsintGraphIntoWorkspaceStates"

DRIVER = r"""
%(helper)s

const scenario = JSON.parse(process.argv[2]);
let workspaceContexts = new Map((scenario.workspaces || []).map(item => [item.id, {id: item.id, kind: item.kind, state: item.state}]));
syncOsintGraphIntoWorkspaceStates(scenario.graphId);
console.log(JSON.stringify([...workspaceContexts.values()].map(c => ({id: c.id, kind: c.kind, state: c.state}))));
"""


def helper_source(template: str) -> str:
    """Тіло функції сторінки, зрізане по парних дужках."""
    start = template.index(f"function {HELPER}(")
    parens = 0
    index = start + len(f"function {HELPER}(") - 1
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
        raise AssertionError(f"{HELPER} has no opening brace for its body")
    depth = 0
    for position in range(body, len(template)):
        character = template[position]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return template[start:position + 1]
    raise AssertionError(f"{HELPER} has no closing brace")


def run_node(template: str, scenario: dict) -> list:
    driver = DRIVER % {"helper": helper_source(template)}
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "scenario.mjs"
        script.write_text(driver, encoding="utf-8")
        completed = subprocess.run(["node", str(script), json.dumps(scenario)],
                                   capture_output=True, text=True, timeout=60)
    if completed.returncode != 0:
        raise AssertionError(f"node failed: {completed.stderr.strip()[:400]}")
    return json.loads(completed.stdout)


@unittest.skipUnless(shutil.which("node"), "node is required to run the page's own function")
class OsintGraphWorkspaceStateTests(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE.read_text(encoding="utf-8")

    def test_a_workspace_that_names_no_graph_gets_the_one_on_screen(self):
        """The defect itself: the first tab click used to empty a visible graph."""
        result = run_node(self.template, {
            "graphId": "7",
            "workspaces": [{"id": "osint-1", "kind": "osint", "state": {"url": "", "graphId": ""}}],
        })
        self.assertEqual(result[0]["state"]["graphId"], "7")
        self.assertEqual(result[0]["state"]["url"], "", "the rest of the state must survive")

    def test_a_workspace_with_a_graph_of_its_own_is_left_alone(self):
        """The rule the restore path exists for: no workspace inherits another's graph."""
        result = run_node(self.template, {
            "graphId": "7",
            "workspaces": [{"id": "osint-1", "kind": "osint", "state": {"graphId": "3"}}],
        })
        self.assertEqual(result[0]["state"]["graphId"], "3")

    def test_other_workspace_kinds_are_not_touched(self):
        result = run_node(self.template, {
            "graphId": "7",
            "workspaces": [
                {"id": "repeater-1", "kind": "repeater", "state": {"url": "https://x.test"}},
                {"id": "scanner-1", "kind": "scanner", "state": {}},
                {"id": "osint-1", "kind": "osint", "state": {"graphId": ""}},
            ],
        })
        by_id = {item["id"]: item for item in result}
        self.assertEqual(by_id["repeater-1"]["state"], {"url": "https://x.test"})
        self.assertNotIn("graphId", by_id["scanner-1"]["state"])
        self.assertEqual(by_id["osint-1"]["state"]["graphId"], "7")

    def test_no_graph_on_screen_changes_nothing(self):
        result = run_node(self.template, {
            "graphId": "",
            "workspaces": [{"id": "osint-1", "kind": "osint", "state": {"graphId": ""}}],
        })
        self.assertEqual(result[0]["state"].get("graphId", ""), "")

    def test_a_workspace_without_state_at_all_is_given_one(self):
        result = run_node(self.template, {
            "graphId": "7",
            "workspaces": [{"id": "osint-1", "kind": "osint"}],
        })
        self.assertEqual(result[0]["state"], {"graphId": "7"})

    def test_load_graphs_calls_the_sync_after_a_successful_load(self):
        """The wiring. Without the call the helper exists and nothing calls it."""
        body = self.template[self.template.index("async function loadOsintGraphs("):]
        body = body[:body.index("\n}\n")]
        call = re.search(
            r"await loadOsintGraph\(desired\);\s*(?://[^\n]*\n\s*)*"
            r"syncOsintGraphIntoWorkspaceStates\(desired\);",
            body,
        )
        self.assertIsNotNone(
            call,
            "loadOsintGraphs must record the graph it loaded, right after loading it",
        )

    def test_the_sync_runs_before_the_persist_that_writes_it(self):
        body = self.template[self.template.index("async function loadOsintGraphs("):]
        body = body[:body.index("\n}\n")]
        sync_at = body.index(f"{HELPER}(desired)")
        persist_at = body.index("queueWorkspacePersistence()", sync_at)
        self.assertLess(sync_at, persist_at,
                        "the state has to be updated before the persist that stores it")


if __name__ == "__main__":
    unittest.main()