"""Test Tab Settings, DNS APIs, and UI Preferences (Roadmap N2)."""
import json
from django.test import TestCase, Client
from django.urls import reverse


class TabSettingsAPITest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_dns_config_get(self):
        response = self.client.get(reverse('dns-config'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('mode', data)
        self.assertIn('custom_server', data)
        self.assertIn('doh_url', data)
        self.assertIn('tls_fingerprint', data)

    def test_dns_config_post_valid(self):
        payload = {
            "mode": "doh",
            "custom_server": "1.0.0.1:53",
            "doh_url": "https://dns.google/resolve",
            "tls_fingerprint": "firefox",
            "force_ttl0": True,
        }
        response = self.client.post(
            reverse('dns-config'),
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["mode"], "doh")
        self.assertEqual(data["doh_url"], "https://dns.google/resolve")
        self.assertEqual(data["tls_fingerprint"], "firefox")
        self.assertTrue(data["force_ttl0"])

    def test_dns_config_post_invalid(self):
        response = self.client.post(
            reverse('dns-config'),
            data="not a json",
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)

    def test_dns_flush_post(self):
        response = self.client.post(reverse('dns-flush'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("flushed_at", data)

    def test_dns_flush_method_not_allowed(self):
        response = self.client.get(reverse('dns-flush'))
        self.assertEqual(response.status_code, 405)

    def test_index_renders_settings_dialog_and_palette(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        # Check tab settings modal exists
        self.assertIn('id="tab-settings-modal"', content)
        # Check command palette exists
        self.assertIn('id="cmd-palette-dialog"', content)
        # Check header settings button exists
        self.assertIn('id="header-settings-btn"', content)
        # Check settings navigation sections exist
        self.assertIn('data-settings-section="sec-appearance"', content)
        self.assertIn('data-settings-section="sec-dns"', content)
        self.assertIn('data-settings-section="sec-tool"', content)
        self.assertIn('data-settings-section="sec-shortcuts"', content)
        # Check unified Target export menu exists
        self.assertIn('data-export-menu="target"', content)
        # Ensure Target workspace does not clip export dropdown menu
        self.assertIn('#target > .workspace { flex:0 0 auto; height:auto; min-height:min(430px,52vh); overflow:visible }', content)
        self.assertIn('#target .export-menu { position:relative; z-index:50; }', content)
        # Check tool sub-nav and tool panes exist for all instruments
        all_tools = [
            'repeater', 'target', 'intruder', 'scanner', 'osint',
            'traffic', 'proxy', 'ai', 'comparer', 'decoder',
            'projects', 'automation', 'history'
        ]
        for tool in all_tools:
            self.assertIn(f'data-tool-tab="{tool}"', content)
            self.assertIn(f'id="tool-pane-{tool}"', content)
        # Check unified .tool-corner-actions with both FAQ and gear buttons across all 13 tool tabs
        for tool in all_tools:
            self.assertIn(f'class="tab-faq-trigger icon-btn" data-tab="{tool}"', content)
            self.assertIn(f'class="tab-settings-trigger icon-btn" data-tab="{tool}"', content)
        self.assertEqual(content.count('class="tool-corner-actions"'), 13)
        # Ensure Proxy settings only expose real SOCKS5 route controls without fictional intercept checkboxes
        self.assertIn('id="setting-proxy-route-address"', content)
        self.assertIn('id="setting-proxy-check-url"', content)
        self.assertIn('id="setting-proxy-check-timeout"', content)
        self.assertNotIn('setting-proxy-intercept-req', content)
        self.assertNotIn('setting-proxy-intercept-res', content)
        self.assertNotIn('setting-proxy-scope-only', content)
        self.assertNotIn('Intercept incoming client HTTP requests', content)
        self.assertNotIn('Intercept outgoing server HTTP responses', content)

    def test_translations_contain_settings_keys(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        # Check both UK and EN translations for modalTitle and presets
        self.assertIn("'settings.modalTitle': 'Налаштування вкладки'", content)
        self.assertIn("'settings.modalTitle': 'Tab Settings'", content)
        self.assertIn("'settings.themePreset': 'Тема оформлення (Theme Preset)'", content)
        self.assertIn("'settings.themePreset': 'Theme Preset'", content)
        self.assertIn("'settings.cmdPaletteHint'", content)

    def test_faq_covers_all_settings_and_features_across_all_13_tools(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        all_tools = [
            'osint', 'repeater', 'intruder', 'scanner', 'target',
            'traffic', 'history', 'comparer', 'decoder', 'proxy',
            'ai', 'automation', 'projects'
        ]
        for tool in all_tools:
            self.assertIn(f'data-faq-tab="{tool}"', content)
            self.assertIn(f'id="faq-pane-{tool}"', content)

        # Verify key settings & features are documented inside the FAQ dialog
        required_faq_markers = [
            'Graph Layout Engine',
            'Transform Job Controls',
            'Export PoC',
            'Pretty / Raw',
            'JWT Forge',
            'Detect a successful login',
            'Transformations (13',
            'OpenVAS (GVM)',
            'Resend requests that never answered',
            '403 bypass ladder',
            'Compare static/browser',
            'Auto-scroll live traffic stream',
            'Theme Preset (13',
            'Adaptive UI Scaling',
            'Default Sort Order &amp; Compact Density',
            'Ignore dynamic headers &amp; Sync Scroll',
            'Default Output &amp; Auto-detect',
            'JWT &amp; Crypto Forge Studio',
            'DNS Resolver Modes &amp; Flush Cache',
            'System Persona &amp; Providers',
            'Node Timeout, Snap Grid &amp; Minimap',
            'Template Store, Node Inspector',
            'Dashboard Auto-Refresh &amp; Strict Scope',
            'Attack Surface Drift &amp; Shadow API Radar',
        ]
        for marker in required_faq_markers:
            self.assertIn(marker, content)

    def test_soft_light_and_dark_themes_rendered(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('id="header-theme-toggle"', content)
        self.assertIn('<option value="softLight"', content)
        self.assertIn('<option value="softDark"', content)
        self.assertIn('softLight: {', content)
        self.assertIn('softDark: {', content)
        self.assertIn("html[data-theme-mode=\"light\"]", content)
        self.assertIn("html[data-theme-preset]:not([data-theme-preset=\"default\"]):not([data-theme-mode=\"light\"])", content)
        self.assertIn("'settings.themeSoftLight'", content)
        self.assertIn("'settings.themeSoftDark'", content)
        self.assertIn("const fallbackDark = prefs?.appearance?.lastDarkTheme || 'default';", content)

    def test_raw_syntax_color_pickers_and_preview_rendered(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        expected_picker_ids = [
            'setting-color-syn-method',
            'setting-color-syn-key',
            'setting-color-syn-string',
            'setting-color-syn-number',
            'setting-color-syn-literal',
            'setting-color-syn-tag',
            'setting-color-syn-attr',
            'setting-color-syn-punct',
            'setting-color-syn-marker',
            'setting-color-syn-comment',
            'setting-color-syn-cookie',
            'setting-color-syn-cookie-value',
            'setting-color-syn-sensitive',
            'setting-color-syn-sensitive-fg',
        ]
        for picker_id in expected_picker_ids:
            self.assertIn(f'id="{picker_id}"', content)
        self.assertIn('id="raw-syntax-live-preview"', content)
        self.assertIn("'settings.rawSyntaxPalette': 'Кольори підсвічування RAW-панелі (Syntax Highlighting)'", content)
        self.assertIn("'settings.rawSyntaxPalette': 'RAW Panel Syntax Highlighting Colors'", content)
        self.assertIn("root.style.setProperty('--syn-key', custom.synKey)", content)
        self.assertIn("root.style.setProperty('--syn-marker', custom.synMarker)", content)
