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
        # Check tool sub-nav and tool panes exist for all instruments
        for tool in ['repeater', 'target', 'intruder', 'scanner', 'osint', 'traffic', 'proxy', 'ai', 'comparer', 'decoder']:
            self.assertIn(f'data-tool-tab="{tool}"', content)
            self.assertIn(f'id="tool-pane-{tool}"', content)
        # Check tab-settings-trigger gear buttons exist across tool tabs
        for tool in ['repeater', 'target', 'intruder', 'scanner', 'osint', 'traffic', 'proxy']:
            self.assertIn(f'class="tab-settings-trigger icon-btn" data-tab="{tool}"', content)
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
