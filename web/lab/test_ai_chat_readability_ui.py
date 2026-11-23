"""Regression tests for the AI agent chat reading experience.

The transcript is the one view pane whose job is to be read. These tests hold
the two properties that were lost when answers got denser: prose is formatted
and escaped even when the answer also contains a fenced code block, and the
fullscreen reading dialog exists with its larger type scale.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGIC_PATH = ROOT / "templates" / "lab" / "includes" / "_active_scanner_logic.html"
STYLES_PATH = ROOT / "templates" / "lab" / "includes" / "_app_styles.html"
INDEX_PATH = ROOT / "templates" / "lab" / "index.html"
TEMPLATE_PATH = ROOT / "templates" / "lab" / "tabs" / "_ai.html"
APP_CSS_PATH = ROOT / "static" / "css" / "app.css"


def _format_function_js(logic_text):
    start = logic_text.index("function formatAiMessageContent(rawText) {")
    end = logic_text.index("\nfunction renderAgentChat()", start)
    return logic_text[start:end]


class AIChatReadabilityTests(unittest.TestCase):
    def test_prose_is_formatted_and_escaped_next_to_code_blocks(self):
        logic = LOGIC_PATH.read_text(encoding="utf-8")
        script = f"""
const escapeHTML = s => String(s ?? '').replace(/[&<>"']/g, c => ({{
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}}[c]));
const tr = k => k;
{_format_function_js(logic)}
console.log(formatAiMessageContent('## Заголовок\\n\\nТекст **жирний** та `код`\\n\\n```http\\nGET / HTTP/1.1\\n```\\n\\n<script>alert(1)</script>'));
"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            result = subprocess.run(["node", path], capture_output=True, text=True, timeout=20)
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        html = result.stdout
        self.assertIn("<h3>Заголовок</h3>", html)
        self.assertIn("<strong>жирний</strong>", html)
        self.assertIn('<code class="ai-inline-code">код</code>', html)
        self.assertIn("ai-code-block-container", html)
        self.assertIn("GET / HTTP/1.1", html)
        # Untrusted text must never be inserted as markup.
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_reading_font_choice_is_applied_and_persisted(self):
        logic = LOGIC_PATH.read_text(encoding="utf-8")
        start = logic.index("const AI_READING_FONT_KEY =")
        end = logic.index("\n// ---- Agent browser workspace (mini-OS) ----", start)
        block = logic[start:end]
        script = f"""
const store = {{}};
globalThis.localStorage = {{
  getItem: k => store[k] === undefined ? null : store[k],
  setItem: (k, v) => {{ store[k] = v; }}
}};
const props = {{}};
globalThis.document = {{
  documentElement: {{ style: {{ setProperty: (k, v) => {{ props[k] = v; }} }} }},
  querySelectorAll: () => []
}};
const $ = () => null;
{block}
applyAiReadingFont(17);
console.log(props['--ai-msg-size'] + '|' + store['requestrider-ai-reading-font']);
"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            result = subprocess.run(["node", path], capture_output=True, text=True, timeout=20)
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "17px|17")

    def test_fullscreen_dialog_and_trigger_exist(self):
        index = INDEX_PATH.read_text(encoding="utf-8")
        ai = TEMPLATE_PATH.read_text(encoding="utf-8")
        self.assertIn('id="ai-fullscreen-dialog"', index)
        self.assertIn('class="ai-fullscreen-dialog"', index)
        # A native <dialog> already exposes role=dialog, Escape and the focus
        # trap; an explicit role would be redundant, so assert the element.
        self.assertIn('<dialog id="ai-fullscreen-dialog"', index)
        self.assertIn('id="ai-fullscreen-log-slot"', index)
        self.assertIn('id="ai-fullscreen-input-slot"', index)
        self.assertIn('type="range" id="ai-font-size"', index)
        self.assertIn('id="ai-font-size-value"', index)
        self.assertIn('id="ai-fullscreen-btn"', ai)

    def test_reading_type_scale_is_present_in_both_stylesheets(self):
        for path in (STYLES_PATH, APP_CSS_PATH):
            css = path.read_text(encoding="utf-8")
            self.assertIn("font-size: var(--ai-msg-size, 13px);", css, path)
            self.assertIn("line-height: 1.55;", css, path)
            self.assertIn(".ai-fullscreen-dialog .agent-chat-message {", css, path)
            self.assertIn("font-size: var(--ai-msg-size, 14px);", css, path)
            self.assertIn("line-height: 1.7;", css, path)
            # The size is a visible user choice, not a hidden cap.
            self.assertIn(".ai-fullscreen-font-range {", css, path)
            # The composer is deliberately compact in this view.
            self.assertIn(".ai-fullscreen-input-slot #agent-chat-input {", css, path)
            self.assertIn("min-height: 32px;", css, path)


    def test_compact_header_controls_and_fullscreen_identical_slot(self):
        index = INDEX_PATH.read_text(encoding="utf-8")
        ai = TEMPLATE_PATH.read_text(encoding="utf-8")
        # Header has compact mode pills
        self.assertIn('class="ai-mode-pills"', ai)
        self.assertIn('id="agent-react-autonomous-mode"', ai)
        self.assertIn('id="agent-use-project-context"', ai)
        self.assertIn('id="agent-swarm-mode"', ai)
        # Swarm drawer exists and is collapsed by default
        self.assertIn('id="ai-continuity-controls"', ai)
        self.assertIn('style="display:none"', ai)
        self.assertIn('id="agent-swarm-workers"', ai)
        self.assertIn('id="agent-swarm-intents"', ai)
        self.assertIn('id="agent-continuity-status-btn"', ai)
        # Fullscreen dialog hosts the identical main container
        self.assertIn('id="ai-fullscreen-main-slot"', index)

        # Zero-overlap header styles present in both stylesheets
        for path in (STYLES_PATH, APP_CSS_PATH):
            css = path.read_text(encoding="utf-8")
            self.assertIn("margin-left: auto;", css, path)
            self.assertIn("overflow-x: auto;", css, path)
            self.assertIn("max-width: 110px;", css, path)
            self.assertIn("@media (max-width: 1250px)", css, path)

    def test_structured_settings_panel_and_tool_profile_selector(self):
        index = INDEX_PATH.read_text(encoding="utf-8")
        ai = TEMPLATE_PATH.read_text(encoding="utf-8")
        logic = LOGIC_PATH.read_text(encoding="utf-8")

        # Header decluttered: font slider moved to settings modal, model badge is clickable
        self.assertNotIn('class="ai-inline-font-control"', ai)
        self.assertIn('<button type="button" class="ai-model-badge" id="ai-current-model-badge"', ai)
        self.assertIn('id="agent-tool-profile"', ai)

        # Settings panel organized into 3 sections with segmented tool_profile control
        self.assertIn('id="ai-dialog-provider"', index)
        self.assertIn('id="ai-dialog-tool-profile-group"', index)
        for value in ("auto", "compact", "full"):
            self.assertIn(f'id="ai-dialog-tool-profile-{value}"', index)
            self.assertIn(f'name="ai-dialog-tool-profile" value="{value}"', index)
        self.assertIn('id="ai-dialog-tool-profile-hint"', index)
        self.assertIn('class="ai-inline-font-control ai-settings-font-control"', index)

        # JS wiring sends tool_profile, persists it, and opens modal on model badge click
        self.assertIn("tool_profile: getSelectedAgentToolProfile()", logic)
        self.assertIn("toolProfile: getSelectedAgentToolProfile()", logic)
        self.assertIn("$('ai-current-model-badge')?.addEventListener('click', openAiSettingsDialog);", logic)

        # Both stylesheets define the structured modal and segmented selector styles
        for path in (STYLES_PATH, APP_CSS_PATH):
            css = path.read_text(encoding="utf-8")
            self.assertIn(".ai-settings-section {", css, path)
            self.assertIn(".ai-profile-segmented {", css, path)
            self.assertIn(".ai-profile-option:has(input:checked)", css, path)
            self.assertIn("font-variant-numeric: tabular-nums;", css, path)

    def test_fullscreen_dialog_supports_adaptive_ui_scale(self):
        ui_prefs = (ROOT / "templates" / "lab" / "includes" / "_ui_preferences.html").read_text(encoding="utf-8")
        logic = LOGIC_PATH.read_text(encoding="utf-8")
        # Both stylesheets must divide viewport dimensions by --rr-ui-scale
        for path in (STYLES_PATH, APP_CSS_PATH):
            css = path.read_text(encoding="utf-8")
            self.assertIn("width: calc(100vw / var(--rr-ui-scale, 1));", css, path)
            self.assertIn("height: calc(100vh / var(--rr-ui-scale, 1));", css, path)

        # JS logic defines syncAiFullscreenSize and wires it to scale changes, resize and open
        self.assertIn("function syncAiFullscreenSize()", logic)
        self.assertIn("syncAiFullscreenSize()", logic)
        self.assertIn("window.addEventListener('resize', syncAiFullscreenSize);", logic)
        self.assertIn("syncAiFullscreenSize", ui_prefs)


if __name__ == "__main__":
    unittest.main()
