"""Regression tests for Target table badges layout and #rr-tip stability during crawl."""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "templates" / "lab" / "index.html"
STYLES_PATH = ROOT / "templates" / "lab" / "includes" / "_app_styles.html"
LOGIC_PATH = ROOT / "templates" / "lab" / "includes" / "_active_scanner_logic.html"


def _extract_dom_sinks_dialog_html(index_text: str) -> str:
    start = index_text.index('<dialog id="target-dom-sinks-dialog"')
    end = index_text.index("</dialog>", start) + len("</dialog>")
    return index_text[start:end]


def _extract_dom_sinks_js(logic_text: str) -> str:
    start = logic_text.index("function formatTargetDomSinksText(page)")
    end = logic_text.index("$('target-network-filter').addEventListener('change'")
    return logic_text[start:end]


def _extract_rr_tip_js(logic_text: str) -> str:
    start = logic_text.index("const RR_TIP_DELAY_MS = 220;")
    end = logic_text.index("// renderTargetEnrichBadge states the finding on the row itself.")
    return logic_text[start:end]


def _extract_badge_renderers_js(logic_text: str) -> str:
    anti_start = logic_text.index("function renderTargetAntiDetectBadge(page)")
    render_end = logic_text.index("function targetPageItem(page)")
    return logic_text[anti_start:render_end]


def _build_test_html() -> str:
    styles = STYLES_PATH.read_text(encoding="utf-8")
    logic = LOGIC_PATH.read_text(encoding="utf-8")
    rr_tip_js = _extract_rr_tip_js(logic)
    renderers_js = _extract_badge_renderers_js(logic)
    styles_clean = re.sub(r"</?style[^>]*>", "", styles)
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
:root {{
  --bg: #0b121b; --panel: #101926; --panel-2: #152131; --line: #223247;
  --text: #e2ecf7; --muted: #8ea3bc; --accent: #43d9a3; --orange: #f59e0b;
  --purple: #a970ff; --purple-strong: #8b5cf6; --danger: #ef4444; --warning: #f59e0b;
}}
body {{ margin: 0; background: var(--bg); color: var(--text); font-family: sans-serif; }}
{styles_clean}
</style>
</head>
<body>
<main>
  <section id="target" class="active">
    <div id="target-status"></div>
    <div id="target-meta"></div>
    <div class="exchange-list">
      <table class="target-table">
        <colgroup>
          <col class="target-col-index">
          <col class="target-col-depth">
          <col class="target-col-status">
          <col class="target-col-url">
          <col class="target-col-type">
          <col class="target-col-time">
          <col class="target-col-actions">
        </colgroup>
        <thead>
          <tr>
            <th>#</th><th>Depth</th><th>Status</th><th>URL</th><th>Type</th><th>Time</th><th>Actions</th>
          </tr>
        </thead>
        <tbody id="target-results"></tbody>
      </table>
    </div>
  </section>
</main>
<script>
const $ = id => document.getElementById(id);
const escapeHTML = s => String(s ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
const tr = k => ({{
  'target.map': 'Map',
  'target.pages': 'pages',
  'target.unknown': 'unknown',
  'target.noMatches': 'No matches',
  'target.noPages': 'No pages',
  'target.antiDetect': 'Anti-detect',
  'target.antiDetectTitle': 'Anti-detect active',
  'target.antiDetectNativeTitle': 'Native runtime',
  'target.antiDetectNativeRuntime': 'Runtime',
  'target.antiDetectApplied': 'Applied',
  'target.antiDetectOff': 'Off',
  'target.autoTitle': 'Auto actions',
  'target.autoActions': 'Auto',
  'target.jsLabel': 'JS',
  'target.enrichLabel': 'Enrich',
  'target.enrichTitle': 'Enrichment findings',
  'row.sendRepeater': 'Send to Repeater',
  'row.moreActions': 'More actions',
}}[k] || k);

let currentTargetMap = {{pages: []}};
let targetFilter = '';
let targetSort = 'index';
let activeTargetMapId = 'map-1';
let activeProjectId = null;
let targetNetworkFilter = 'all';
let targetCheckpoint = null;

function renderStatusBadge(s) {{ return `<span class="status-badge">${{escapeHTML(s)}}</span>`; }}
function renderMethodBadge(m) {{ return `<span class="method-badge">${{escapeHTML(m)}}</span>`; }}
function formatUrlMarkup(u) {{ return `<span>${{escapeHTML(u)}}</span>`; }}
function targetAutoSummary() {{ return ''; }}
function targetJsSummary() {{ return ''; }}
function targetEnrichSummary() {{ return ''; }}
function renderRunCheckpoint() {{}}
function targetRunControls() {{}}
function syncExportMenuAvailability() {{}}
function renderTargetTree() {{}}
function targetEnrichSearchText() {{ return []; }}
function targetJsState(page) {{ return page._jsState || null; }}
function targetEnrichState(page) {{ return page._enrichState || null; }}
function targetAutoActions(page) {{ return page.auto_actions || []; }}

function renderTargetJsBadge(page) {{
  const s = targetJsState(page);
  if (!s) return '';
  const detail = s.detail || 'JS findings line 1\\nJS findings line 2';
  return `<span class="status-badge target-row-badge target-js-badge is-ok" role="button" tabindex="0" data-tip="${{escapeHTML(detail)}}" title="${{escapeHTML(detail)}}" aria-label="JS"><span class="rr-badge-text">JS ${{escapeHTML(s.label || '3 ep')}}</span></span>`;
}}

function renderTargetEnrichBadge(page) {{
  const s = targetEnrichState(page);
  if (!s) return '';
  const detail = s.detail || 'Enrich findings line 1\\nEnrich findings line 2';
  return `<span class="status-badge target-row-badge target-enrich-badge is-muted" role="button" tabindex="0" data-tip="${{escapeHTML(detail)}}" title="${{escapeHTML(detail)}}" aria-label="Enrich"><span class="rr-badge-text">Enrich</span></span>`;
}}

{rr_tip_js}
{renderers_js}

window.__clickedBadges = [];
$('target-results').addEventListener('click', e => {{
  const js = e.target.closest('.target-js-badge');
  if (js) window.__clickedBadges.push('js');
  const dom = e.target.closest('.target-dom-sinks-btn');
  if (dom) window.__clickedBadges.push('dom');
  const enrich = e.target.closest('.target-enrich-badge');
  if (enrich) window.__clickedBadges.push('enrich');
}});

window.__samplePage = (extraText = '') => ({{
  url: 'https://example.com/app.js',
  depth: 1,
  status: 200,
  content_type: 'application/javascript',
  time: 42,
  _jsState: {{ label: '4 ep · 2 sinks', detail: 'JS Endpoint /api/v1/user\\nSink innerHTML' + extraText }},
  _enrichState: {{ detail: 'Subdomain api.example.com' }},
  dom_sinks: [{{ sink: 'innerHTML', tainted: true }}, {{ sink: 'eval', tainted: false }}],
  anti_detect: {{ plan: {{ enabled: true }}, measured: {{ measured: true, webdriver: 'undefined', applied: ['webdriver'], userAgent: 'Mozilla/5.0' }} }},
  auto_actions: [{{ kind: 'form', status: 'submitted', method: 'post', action: '/login' }}],
}});
</script>
</body>
</html>"""


NODE_CDP_RUNNER = r"""
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const htmlPath = process.argv[2];
const html = fs.readFileSync(htmlPath, 'utf8');
const userDataDir = fs.mkdtempSync('/tmp/rr-cdp-');

function findChrome() {
  for (const p of ['/usr/bin/chromium', '/usr/bin/google-chrome', '/usr/bin/chromium-browser']) {
    if (fs.existsSync(p)) return p;
  }
  throw new Error('No chromium binary found');
}

const chrome = spawn(findChrome(), [
  '--headless=new',
  '--no-sandbox',
  '--disable-gpu',
  '--remote-debugging-port=0',
  `--user-data-dir=${userDataDir}`,
  '--window-size=1280,800',
  'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });

let stderrBuf = '';
let done = false;

function cleanup() {
  try { chrome.kill('SIGKILL'); } catch (_) {}
  try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
}

chrome.stderr.on('data', async (chunk) => {
  stderrBuf += chunk.toString();
  const m = stderrBuf.match(/DevTools listening on (ws:\/\/[^\s]+)/);
  if (!m || done) return;
  done = true;
  try {
    const browserWs = m[1];
    const port = new URL(browserWs).port;
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const pageTarget = targets.find(t => t.type === 'page') || targets[0];
    const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

    let seq = 0;
    const pending = new Map();
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { res, rej } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) rej(new Error(msg.error.message));
        else res(msg.result);
      }
    };
    const cdp = (method, params = {}) => new Promise((res, rej) => {
      const id = ++seq;
      pending.set(id, { res, rej });
      ws.send(JSON.stringify({ id, method, params }));
    });
    const evalJs = async (expression) => {
      const r = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
      return r.result ? r.result.value : undefined;
    };
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));

    await cdp('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
    const tree = await cdp('Page.getFrameTree');
    await cdp('Page.setDocumentContent', { frameId: tree.frameTree.frame.id, html });
    await sleep(50);

    await evalJs(`renderTargetMap({ map_id: 'm1', status: 'running', visited: 1, pages: [window.__samplePage()] });`);

    const jsBox = await evalJs(`(() => {
      const r = document.querySelector('tr[data-index="0"] .target-js-badge').getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    })()`);

    await cdp('Input.dispatchMouseEvent', { type: 'mouseMoved', x: jsBox.x, y: jsBox.y });
    await sleep(300);

    const tipBefore = await evalJs(`(() => {
      const tip = document.getElementById('rr-tip');
      return { exists: !!tip, hidden: tip ? tip.hidden : true, text: tip ? tip.textContent : '' };
    })()`);

    await evalJs(`(() => {
      window.__tipHidCount = 0;
      const tip = document.getElementById('rr-tip');
      const obs = new MutationObserver(() => { if (tip.hidden) window.__tipHidCount += 1; });
      obs.observe(tip, { attributes: true, attributeFilter: ['hidden'] });
    })()`);

    for (let i = 0; i < 4; i++) {
      await evalJs(`renderTargetMap({ map_id: 'm1', status: 'running', visited: ${i + 2}, pages: [window.__samplePage(' poll-${i}')] });`);
      await sleep(100);
    }

    const tipAfter = await evalJs(`(() => {
      const tip = document.getElementById('rr-tip');
      return {
        hidden: tip.hidden,
        hidCount: window.__tipHidCount,
        text: tip.textContent,
        ownerConnected: !!(rrTipOwner && rrTipOwner.isConnected),
      };
    })()`);

    const layout = await evalJs(`(() => {
      const td = document.querySelector('#target-results tr[data-index="0"] td:last-child');
      const tdRect = td.getBoundingClientRect();
      const items = Array.from(td.querySelectorAll('.quick-actions > *')).map(el => {
        const r = el.getBoundingClientRect();
        return {
          cls: el.className,
          isBadge: el.classList.contains('status-badge'),
          left: r.left, right: r.right, top: r.top, bottom: r.bottom,
          width: r.width, height: r.height,
          cx: r.left + r.width / 2, cy: r.top + r.height / 2,
        };
      });
      return { tdRect: { left: tdRect.left, right: tdRect.right }, items };
    })()`);

    for (const sel of ['.target-js-badge', '.target-dom-sinks-btn', '.target-enrich-badge']) {
      const pt = await evalJs(`(() => {
        const r = document.querySelector('tr[data-index="0"] ${sel}').getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`);
      await cdp('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
      await cdp('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
    }
    const clicked = await evalJs(`window.__clickedBadges`);

    ws.close();
    console.log(JSON.stringify({ tipBefore, tipAfter, layout, clicked }));
    cleanup();
    process.exit(0);
  } catch (err) {
    console.error(err);
    cleanup();
    process.exit(1);
  }
});

setTimeout(() => {
  if (!done) {
    console.error('Timed out waiting for DevTools');
    cleanup();
    process.exit(1);
  }
}, 10000);
"""


class TargetBadgesUITests(unittest.TestCase):
    def test_tooltip_does_not_flicker_and_badges_do_not_overlap(self):
        html = _build_test_html()
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "test.html"
            runner_path = Path(tmpdir) / "runner.js"
            html_path.write_text(html, encoding="utf-8")
            runner_path.write_text(NODE_CDP_RUNNER, encoding="utf-8")

            proc = subprocess.run(
                ["node", str(runner_path), str(html_path)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"CDP runner failed: {proc.stderr}")
            data = json.loads(proc.stdout)

        # 1. Tooltip stability during crawl re-renders
        self.assertTrue(data["tipBefore"]["exists"])
        self.assertFalse(data["tipBefore"]["hidden"])
        self.assertIn("JS Endpoint /api/v1/user", data["tipBefore"]["text"])

        self.assertFalse(data["tipAfter"]["hidden"], "Tooltip should remain visible across crawl re-renders")
        self.assertEqual(data["tipAfter"]["hidCount"], 0, "Tooltip must not hide/flicker during crawl re-renders")
        self.assertTrue(data["tipAfter"]["ownerConnected"], "rrTipOwner must be rebound to the new badge element")
        self.assertIn("poll-3", data["tipAfter"]["text"])

        # 2. Uniform badge heights, containment, and zero overlap
        layout = data["layout"]
        badges = [it for it in layout["items"] if it["isBadge"]]
        self.assertEqual(len(badges), 5)
        heights = [round(b["height"], 1) for b in badges]
        self.assertEqual(len(set(heights)), 1, f"All badges must have identical height, got {heights}")
        for b in badges:
            self.assertGreater(b["width"], 20, f"Badge too narrow: {b}")
            self.assertGreaterEqual(b["left"], layout["tdRect"]["left"] - 1, f"Badge overflows left: {b}")
            self.assertLessEqual(b["right"], layout["tdRect"]["right"] + 1, f"Badge overflows right: {b}")

        items = layout["items"]
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                a, b = items[i], items[j]
                overlap_x = min(a["right"], b["right"]) - max(a["left"], b["left"])
                overlap_y = min(a["bottom"], b["bottom"]) - max(a["top"], b["top"])
                self.assertFalse(
                    overlap_x > 0.5 and overlap_y > 0.5,
                    f"Items overlap: {a['cls']} and {b['cls']}",
                )

        # 3. Every clickable badge actually receives real pointer clicks
        self.assertEqual(data["clicked"], ["js", "dom", "enrich"])

    def test_dom_sinks_badge_opens_modal_dialog_without_overlapping_site_map(self):
        styles = STYLES_PATH.read_text(encoding="utf-8")
        styles_clean = re.sub(r"</?style[^>]*>", "", styles)
        logic = LOGIC_PATH.read_text(encoding="utf-8")
        index_html = INDEX_PATH.read_text(encoding="utf-8")
        dialog_html = _extract_dom_sinks_dialog_html(index_html)
        renderers_js = _extract_badge_renderers_js(logic)
        dom_sinks_js = _extract_dom_sinks_js(logic)

        html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
:root {{
  --bg: #0b121b; --panel: #101926; --panel-2: #152131; --line: #223247;
  --text: #e2ecf7; --muted: #8ea3bc; --accent: #43d9a3; --orange: #f59e0b;
  --purple: #a970ff; --purple-strong: #8b5cf6; --danger: #ef4444; --warning: #f59e0b;
  --radius: 8px;
}}
body {{ margin: 0; background: var(--bg); color: var(--text); font-family: sans-serif; }}
{styles_clean}
</style>
</head>
<body>
<main>
  <section id="target" class="active">
    <div id="target-status"></div>
    <div id="target-meta"></div>
    <div class="target-preview" style="height:260px;overflow:auto;">
      <div id="target-tree" class="target-tree">
        <div class="tree-file">login.php 200</div>
        <div class="tree-file">dashboard.php 200</div>
      </div>
    </div>
    <div class="exchange-list">
      <table class="target-table">
        <tbody id="target-results"></tbody>
      </table>
    </div>
  </section>
</main>
{dialog_html}
<script>
const $ = id => document.getElementById(id);
const escapeHTML = s => String(s ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
const tr = k => k;
let currentTargetMap = {{pages: []}};
let targetFilter = '';
let targetSort = 'index';
let activeTargetMapId = 'map-1';
let targetNetworkFilter = 'all';
let targetCheckpoint = null;
function renderStatusBadge(s) {{ return `<span>${{escapeHTML(s)}}</span>`; }}
function renderMethodBadge(m) {{ return `<span>${{escapeHTML(m)}}</span>`; }}
function formatUrlMarkup(u) {{ return `<span>${{escapeHTML(u)}}</span>`; }}
function targetAutoSummary() {{ return ''; }}
function targetJsSummary() {{ return ''; }}
function targetEnrichSummary() {{ return ''; }}
function renderRunCheckpoint() {{}}
function targetRunControls() {{}}
function syncExportMenuAvailability() {{}}
function renderTargetTree() {{}}
function targetEnrichSearchText() {{ return []; }}
function targetJsState() {{ return null; }}
function targetEnrichState() {{ return null; }}
function targetAutoActions() {{ return []; }}
function renderTargetJsBadge() {{ return ''; }}
function renderTargetEnrichBadge() {{ return ''; }}
function rrTipSnapshotIn() {{ return null; }}
function rrTipRestoreIn() {{}}
{renderers_js}
{dom_sinks_js}
renderTargetMap({{
  map_id: 'm1',
  status: 'completed',
  visited: 1,
  pages: [{{
    url: 'http://127.0.0.1:8088/login.php',
    depth: 0,
    status: 200,
    content_type: 'text/html',
    time: 441,
    dom_sinks: [
      {{
        sink: 'innerHTML',
        tainted: true,
        value: '<img src=x onerror="window.__xss=1">',
        location: {{ file: 'http://127.0.0.1:8088/app.js', line: 35, column: 29 }},
        stack: 'Error\\n  at render@http://127.0.0.1:8088/app.js:35:29',
        last_fetch: '/api/session'
      }},
      {{
        sink: 'eval',
        tainted: false,
        value: 'async () => true',
        stack: 'recordSink@debugger eval code:35:29'
      }}
    ]
  }}]
}});
</script>
</body>
</html>"""

        runner_js = r"""
const { spawn } = require('child_process');
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
const userDataDir = fs.mkdtempSync('/tmp/rr-cdp-dom-');
function findChrome() {
  for (const p of ['/usr/bin/chromium', '/usr/bin/google-chrome', '/usr/bin/chromium-browser']) {
    if (fs.existsSync(p)) return p;
  }
  throw new Error('No chromium binary found');
}
const chrome = spawn(findChrome(), [
  '--headless=new', '--no-sandbox', '--disable-gpu',
  '--remote-debugging-port=0', `--user-data-dir=${userDataDir}`,
  '--window-size=1280,800', 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
let stderrBuf = '';
let done = false;
function cleanup() {
  try { chrome.kill('SIGKILL'); } catch (_) {}
  try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
}
chrome.stderr.on('data', async (chunk) => {
  stderrBuf += chunk.toString();
  const m = stderrBuf.match(/DevTools listening on (ws:\/\/[^\s]+)/);
  if (!m || done) return;
  done = true;
  try {
    const port = new URL(m[1]).port;
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const pageTarget = targets.find(t => t.type === 'page') || targets[0];
    const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
    let seq = 0;
    const pending = new Map();
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { res, rej } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) rej(new Error(msg.error.message));
        else res(msg.result);
      }
    };
    const cdp = (method, params = {}) => new Promise((res, rej) => {
      const id = ++seq;
      pending.set(id, { res, rej });
      ws.send(JSON.stringify({ id, method, params }));
    });
    const evalJs = async (expression) => {
      const r = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
      return r.result ? r.result.value : undefined;
    };
    await cdp('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
    const tree = await cdp('Page.getFrameTree');
    await cdp('Page.setDocumentContent', { frameId: tree.frameTree.frame.id, html });

    const beforeTree = await evalJs(`(() => {
      const el = document.getElementById('target-tree');
      const r = el.getBoundingClientRect();
      return { top: r.top, height: r.height, parentChildren: el.parentElement.children.length };
    })()`);

    const btnPt = await evalJs(`(() => {
      const r = document.querySelector('.target-dom-sinks-btn').getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    })()`);
    await cdp('Input.dispatchMouseEvent', { type: 'mousePressed', x: btnPt.x, y: btnPt.y, button: 'left', clickCount: 1 });
    await cdp('Input.dispatchMouseEvent', { type: 'mouseReleased', x: btnPt.x, y: btnPt.y, button: 'left', clickCount: 1 });

    const afterOpen = await evalJs(`(() => {
      const dlg = document.getElementById('target-dom-sinks-dialog');
      const treeEl = document.getElementById('target-tree');
      const r = treeEl.getBoundingClientRect();
      const body = document.getElementById('target-dom-sinks-dialog-body');
      return {
        dialogOpen: !!(dlg && dlg.open),
        drawerExists: !!document.getElementById('target-dom-sinks-drawer'),
        treeTop: r.top,
        treeHeight: r.height,
        previewChildren: treeEl.parentElement.children.length,
        fileText: document.getElementById('target-dom-sinks-dialog-file').textContent,
        bodyText: body.textContent,
        hasExplain: !!body.querySelector('.target-dom-sinks-explain'),
        badgeTip: document.querySelector('.target-dom-sinks-btn')?.getAttribute('data-tip') || '',
        injectedImgCount: body.querySelectorAll('img').length,
        xssRan: Boolean(window.__xss),
        copyText: dlg.dataset.copyText || '',
      };
    })()`);

    const closePt = await evalJs(`(() => {
      const r = document.getElementById('target-dom-sinks-dialog-close').getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    })()`);
    await cdp('Input.dispatchMouseEvent', { type: 'mousePressed', x: closePt.x, y: closePt.y, button: 'left', clickCount: 1 });
    await cdp('Input.dispatchMouseEvent', { type: 'mouseReleased', x: closePt.x, y: closePt.y, button: 'left', clickCount: 1 });

    const afterClose = await evalJs(`Boolean(document.getElementById('target-dom-sinks-dialog').open)`);
    ws.close();
    console.log(JSON.stringify({ beforeTree, afterOpen, afterClose }));
    cleanup();
    process.exit(0);
  } catch (err) {
    console.error(err);
    cleanup();
    process.exit(1);
  }
});
setTimeout(() => { if (!done) { console.error('Timed out'); cleanup(); process.exit(1); } }, 10000);
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "dom_sinks.html"
            runner_path = Path(tmpdir) / "runner.js"
            html_path.write_text(html, encoding="utf-8")
            runner_path.write_text(runner_js, encoding="utf-8")
            proc = subprocess.run(
                ["node", str(runner_path), str(html_path)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"CDP runner failed: {proc.stderr}")
            data = json.loads(proc.stdout)

        before = data["beforeTree"]
        opened = data["afterOpen"]
        self.assertTrue(opened["dialogOpen"], "Clicking DOM Sinks badge must open #target-dom-sinks-dialog")
        self.assertFalse(opened["drawerExists"], "Legacy inline #target-dom-sinks-drawer must not be injected")
        self.assertEqual(opened["previewChildren"], before["parentChildren"], "Site map preview must not receive extra elements")
        self.assertAlmostEqual(opened["treeTop"], before["top"], delta=0.5, msg="#target-tree must not be shifted down")
        self.assertAlmostEqual(opened["treeHeight"], before["height"], delta=0.5, msg="#target-tree height must stay intact")
        self.assertEqual(opened["fileText"], "http://127.0.0.1:8088/login.php")
        self.assertIn("innerHTML", opened["bodyText"])
        self.assertIn("TAINTED FLOW", opened["bodyText"])
        self.assertIn("eval", opened["bodyText"])
        self.assertIn("/api/session", opened["bodyText"])
        self.assertTrue(opened["hasExplain"], "Dialog must include an explanatory block describing DOM Sinks")
        self.assertIn("innerHTML ×1", opened["badgeTip"])
        self.assertIn("target.domSinksTipAction", opened["badgeTip"])
        self.assertEqual(opened["injectedImgCount"], 0, "Untrusted sink payload must be HTML-escaped")
        self.assertFalse(opened["xssRan"], "Untrusted sink payload must never execute")
        self.assertIn("DOM Sinks Telemetry (http://127.0.0.1:8088/login.php):", opened["copyText"])
        self.assertFalse(data["afterClose"], "Close button must close #target-dom-sinks-dialog")

    def test_vulnx_interactive_badges_dom_rendering(self):
        logic = LOGIC_PATH.read_text(encoding="utf-8")
        frag_code = logic[logic.index("function extractFindingCveId"):logic.index("function renderScanner")]
        html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"></head>
<body>
  <div id="container"></div>
  <script>
    {frag_code}

    // 1. Finding with URL-based PoC
    const finding1 = {{
      cve: ["CVE-2017-5638"],
      is_kev: true,
      epss_score: 0.9712,
      known_ransomware_campaign_use: "Known",
      references: ["https://github.com/vulhub/vulhub/tree/master/struts2/s2-045"],
      age_in_days: 120
    }};
    const badges1 = formatVulnxBadges(finding1);
    const dom1 = renderVulnxBadgesDOM(finding1);
    const block1 = document.createElement('div');
    block1.id = 'b1';
    block1.appendChild(dom1);
    document.getElementById('container').appendChild(block1);

    // 2. Finding with curl_command only
    const finding2 = {{
      cve: ["CVE-2020-14882"],
      curl_command: "curl -X POST http://127.0.0.1:8089/exploit",
    }};
    const badges2 = formatVulnxBadges(finding2);
    const dom2 = renderVulnxBadgesDOM(finding2);
    const block2 = document.createElement('div');
    block2.id = 'b2';
    block2.appendChild(dom2);
    document.getElementById('container').appendChild(block2);

    // 3. Finding with Sploitus link
    const finding3 = {{
      cve: ["CVE-2018-11776"],
      references: ["https://sploitus.com/exploit?id=PACKETSTORM:149008"],
    }};
    const badges3 = formatVulnxBadges(finding3);
    const dom3 = renderVulnxBadgesDOM(finding3);
    const block3 = document.createElement('div');
    block3.id = 'b3';
    block3.appendChild(dom3);
    document.getElementById('container').appendChild(block3);
  </script>
</body>
</html>"""

        runner_js = r"""
const { spawn } = require('child_process');
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
const userDataDir = fs.mkdtempSync('/tmp/rr-cdp-vulnx-');
function findChrome() {
  for (const p of ['/usr/bin/chromium', '/usr/bin/google-chrome', '/usr/bin/chromium-browser']) {
    if (fs.existsSync(p)) return p;
  }
  throw new Error('No chromium binary found');
}
const chrome = spawn(findChrome(), [
  '--headless=new', '--no-sandbox', '--disable-gpu',
  '--remote-debugging-port=0', `--user-data-dir=${userDataDir}`,
  '--window-size=1280,800', 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
let stderrBuf = '';
let done = false;
function cleanup() {
  try { chrome.kill('SIGKILL'); } catch (_) {}
  try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (_) {}
}
chrome.stderr.on('data', async (chunk) => {
  stderrBuf += chunk.toString();
  const m = stderrBuf.match(/DevTools listening on (ws:\/\/[^\s]+)/);
  if (!m || done) return;
  done = true;
  try {
    const port = new URL(m[1]).port;
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const pageTarget = targets.find(t => t.type === 'page') || targets[0];
    const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
    let seq = 0;
    const pending = new Map();
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { res, rej } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) rej(new Error(msg.error.message));
        else res(msg.result);
      }
    };
    const cdp = (method, params = {}) => new Promise((res, rej) => {
      const id = ++seq;
      pending.set(id, { res, rej });
      ws.send(JSON.stringify({ id, method, params }));
    });
    const evalJs = async (expression) => {
      const r = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
      return r.result ? r.result.value : undefined;
    };
    const tree = await cdp('Page.getFrameTree');
    await cdp('Page.setDocumentContent', { frameId: tree.frameTree.frame.id, html });

    const result = await evalJs(`(() => {
      const b1 = document.getElementById('b1');
      const b2 = document.getElementById('b2');
      const b3 = document.getElementById('b3');
      const links1 = Array.from(b1.querySelectorAll('a')).map(a => ({ text: a.textContent, href: a.href, title: a.title, target: a.target }));
      const spans1 = Array.from(b1.querySelectorAll('span')).map(s => ({ text: s.textContent, title: s.title }));
      const pocBtn2 = b2.querySelector('.vulnx-poc-copy');
      const links3 = Array.from(b3.querySelectorAll('a')).map(a => ({ text: a.textContent, href: a.href, title: a.title, target: a.target }));
      return {
        text1: b1.textContent,
        links1,
        spans1,
        text2: b2.textContent,
        hasPocBtn2: !!pocBtn2,
        pocBtn2Role: pocBtn2 ? pocBtn2.getAttribute('role') : null,
        pocBtn2Title: pocBtn2 ? pocBtn2.title : null,
        text3: b3.textContent,
        links3
      };
    })()`);

    console.log(JSON.stringify(result));
    cleanup();
    process.exit(0);
  } catch (err) {
    console.error(err);
    cleanup();
    process.exit(1);
  }
});
setTimeout(() => { if (!done) { console.error('Timed out'); cleanup(); process.exit(1); } }, 10000);
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "badges.html"
            runner_path = Path(tmpdir) / "runner.js"
            html_path.write_text(html, encoding="utf-8")
            runner_path.write_text(runner_js, encoding="utf-8")
            proc = subprocess.run(
                ["node", str(runner_path), str(html_path)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"CDP runner failed: {proc.stderr}")
            data = json.loads(proc.stdout)

        # Verify block 1 text content and badges
        for token in ["[KEV]", "EPSS 97.1%", "[RANSOMWARE]", "[PoC]", "120d"]:
            self.assertIn(token, data["text1"])

        kev_link = next(l for l in data["links1"] if l["text"] == "[KEV]")
        self.assertEqual(kev_link["target"], "_blank")
        self.assertIn("cisa.gov", kev_link["href"])
        self.assertIn("CVE-2017-5638", kev_link["href"])

        epss_link = next(l for l in data["links1"] if "EPSS" in l["text"])
        self.assertEqual(epss_link["target"], "_blank")
        self.assertEqual(epss_link["href"], "https://www.first.org/epss/")

        poc_link = next(l for l in data["links1"] if l["text"] == "[PoC]")
        self.assertEqual(poc_link["target"], "_blank")
        self.assertEqual(poc_link["href"], "https://github.com/vulhub/vulhub/tree/master/struts2/s2-045")

        # Verify block 2 (curl_command copy button)
        self.assertIn("[PoC]", data["text2"])
        self.assertTrue(data["hasPocBtn2"])
        self.assertEqual(data["pocBtn2Role"], "button")
        self.assertIn("copy", data["pocBtn2Title"].lower())

        # Verify block 3 (Sploitus link)
        self.assertIn("[PoC]", data["text3"])
        poc_link3 = next(l for l in data["links3"] if l["text"] == "[PoC]")
        self.assertEqual(poc_link3["target"], "_blank")
        self.assertEqual(poc_link3["href"], "https://sploitus.com/exploit?id=PACKETSTORM:149008")


if __name__ == "__main__":
    unittest.main()
