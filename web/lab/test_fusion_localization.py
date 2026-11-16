"""Unit tests for Request-Rider Multi-Engine Fusion Report Localization (Ukrainian)."""

import json
from django.test import TestCase

from lab.report_localization import (
    localize_finding_title,
    localize_finding_desc,
    localize_finding_remediation,
    localize_finding_evidence,
    localize_level,
    localize_owasp,
    localize_finding,
    localize_compound_chain,
)
from lab.fusion_report import generate_fusion_html_report, generate_fusion_sarif


class FusionReportLocalizationTests(TestCase):
    def test_finding_title_localization_uk(self):
        cases = [
            ("Input Transformation Analysis (shell in the path)", "Аналіз перетворення вхідних даних (командна оболонка у ланцюжку виконання)"),
            ("Input Transformation Analysis (unwrapped (no escaping layer observed))", "Аналіз перетворення вхідних даних (без екранування (рівень екранування не виявлено))"),
            ("Input Transformation Analysis (single escape layer (backslash-consuming, quote-escaping))", "Аналіз перетворення вхідних даних (один рівень екранування (поглинає зворотні слеші, екранує лапки))"),
            ("Input Transformation Analysis (double escape layer)", "Аналіз перетворення вхідних даних (подвійний рівень екранування)"),
            ("prototype pollution: query merges a key path", "Забруднення прототипу (Prototype Pollution): через параметри URL (query) виконується небезпечне злиття ключів"),
            ("prototype pollution: form merges a key path", "Забруднення прототипу (Prototype Pollution): через дані форми (form) виконується небезпечне злиття ключів"),
            ("Забруднення прототипу (Prototype Pollution): query merges a key path", "Забруднення прототипу (Prototype Pollution): через параметри URL (query) виконується небезпечне злиття ключів"),
            ("Shellshock: an injected command executed through User-Agent", "Вразливість Shellshock (CVE-2014-6271): виконано інжектовану команду через заголовок User-Agent"),
            ("OS Command Injection (Echo-Based, IFS substitution)", "Впровадження команд ОС (RCE) (на основі виводу echo, підстановка $IFS)"),
            ("OS Command Injection (Time-Based Blind, semicolon)", "Впровадження команд ОС (RCE) (сліпа на основі затримок часу, крапка з комою)"),
            ("User Input Reflected Without Encoding (potential XSS)", "Вхідні дані віддзеркалюються без екранування (потенційний XSS)"),
            ("Reflected XSS (context: attribute, executable markup confirmed)", "Віддзеркалений XSS (контекст: attribute, виконання розмітки підтверджено)"),
            ("CORS Misconfiguration (origin reflected)", "Некоректна конфігурація CORS (віддзеркалення Origin)"),
            ("CORS with Credentials: All Subdomains Trusted", "CORS з обліковими даними: довіра до всіх піддоменів"),
            ("CSS Injection (Reflected)", "Впровадження CSS (віддзеркалене)"),
            ("Cacheable HTTPS Response Carrying Per-Recipient Data", "HTTPS-відповідь кешується та містить конфіденційні персональні дані"),
            ("Client-Side JSON Injection (DOM-based): 0x00200370", "Клієнтська JSON-ін'єкція (DOM-базована): 0x00200370"),
            ("Code Injection (php concatenation)", "Впровадження довільного коду (конкатенація в PHP)"),
            ("Content Security Policy: Allows Untrusted Script Execution ('unsafe-inline')", "Політика безпеки контенту (CSP): дозволяє виконання довільних скриптів ('unsafe-inline')"),
            ("Content Security Policy: Missing form-action (Allows Form Hijacking)", "Політика безпеки контенту (CSP): відсутня директива form-action (загроза Form Hijacking)"),
            ("Cookie Missing HttpOnly and Secure (session_id)", "У Cookie відсутні атрибути HttpOnly та Secure (session_id)"),
            ("Hardcoded Secret Reference: cookie (set-cookie)", "Виявлено посилання на вшитий секрет: cookie (set-cookie)"),
            ("Server-Side Template Injection (Jinja2 / Twig (compact))", "Впровадження серверних шаблонів (SSTI) (Jinja2 / Twig (compact))"),
            ("filter bypass: script element reaches the page through a filter that blocked the plain shape", "Обхід фільтрації (WAF bypass): елемент <script> потрапляє на сторінку через фільтр"),
        ]
        for src, expected in cases:
            with self.subTest(title=src):
                self.assertEqual(localize_finding_title(src, "uk"), expected)

    def test_english_passthrough(self):
        title = "OS Command Injection (Echo-Based, IFS substitution)"
        self.assertEqual(localize_finding_title(title, "en"), title)

    def test_escaping_stack_desc_localization(self):
        desc = "The escaping stack between this parameter and its sink was measured from outside rather than assumed. This is not itself a vulnerability: it is the condition that decides which injection classes can succeed here..."
        loc = localize_finding_desc(desc, "uk")
        self.assertIn("Стек екранування між цим параметром і його приймачем", loc)
        self.assertIn("нейтралізує пейлоади з лапками", loc)

    def test_proto_pollution_full_localization(self):
        desc = "The probe's own value was reflected, so the key path reached a merge that copied it. A prototype pollution is only reachable through a merge that copies keys it was not asked to copy, so the row names the key path that was written rather than a payload on its own."
        loc_desc = localize_finding_desc(desc, "uk")
        self.assertIn("Значення тестового зонда віддзеркалилося у відповіді", loc_desc)
        self.assertIn("Забруднення прототипу (Prototype Pollution)", loc_desc)

        rem = "Reject `__proto__`, `constructor` and `prototype` in any key path that reaches a recursive merge or a deep clone, and merge into a null-prototype object (`Object.create(null)`) where the language allows it. Lodash's `merge`, `defaultsDeep` and every hand-written `deepMerge` are the usual place."
        loc_rem = localize_finding_remediation(rem, "uk")
        self.assertIn("Блокуйте ключі `__proto__`, `constructor` та `prototype`", loc_rem)
        self.assertIn("Object.create(null)", loc_rem)

        ev = "this run's marker came back in the answer and was not on the page before: rrppqewb6kfy97"
        loc_ev = localize_finding_evidence(ev, "uk")
        self.assertEqual(loc_ev, "Маркер поточного запуску повернувся у відповіді сервера і був відсутній на сторінці раніше: rrppqewb6kfy97")

    def test_remediation_localization(self):
        rem = "Do not build shell commands from user input. Use argument arrays or a language-native API."
        loc = localize_finding_remediation(rem, "uk")
        self.assertIn("Не створюйте команди командної оболонки", loc)

    def test_evidence_localization(self):
        ev = "characters consumed by the escaping stack: [\\ ' \"]; values arrive undecoded: true"
        loc = localize_finding_evidence(ev, "uk")
        self.assertIn("Символи, поглинуті стеком екранування: [\\ ' \"]", loc)
        self.assertIn("значення надходять недекодованими: так", loc)

    def test_levels_and_owasp_localization(self):
        self.assertEqual(localize_level("Level 1: Go Active Engine", "uk"), "Рівень 1: Активний рушій Go")
        self.assertEqual(localize_level("Level 2: Corpus Suite", "uk"), "Рівень 2: Набір перевірок корпусу")
        self.assertEqual(localize_level("Level 3: DOM & Secret Assets", "uk"), "Рівень 3: Клієнтські DOM-витоки та секрети")
        self.assertEqual(localize_level("Level 4: Compound Chains", "uk"), "Рівень 4: Складені ланцюжки атак")

        self.assertEqual(localize_owasp("A03:2021-Injection", "uk"), "A03:2021-Ін'єкції (Injection)")
        self.assertEqual(localize_owasp("A08:2021-Software and Data Integrity Failures", "uk"), "A08:2021-Порушення цілісності ПЗ та даних")

    def test_compound_chain_localization(self):
        chain = {
            "title": "Compound Attack Chain: Web Cache Deception & Public Response Leaking",
            "severity": "HIGH",
            "endpoint": "https://example.com/api",
            "participating_levels": ["Level 1: Go Active Engine", "Level 3: DOM & Secret Assets"],
            "mechanism": "Dynamic responses cached by intermediary CDN/proxy nodes using static file suffixes allow unauthenticated third parties to retrieve cached sensitive user records.",
            "remediation": "Configure Cache-Control headers with no-store or private for user-dependent endpoints and disallow path suffix extension rewriting on reverse proxies.",
        }
        loc = localize_compound_chain(chain, "uk")
        self.assertIn("Складений ланцюжок атаки: обман вебкешу", loc["title"])
        self.assertIn("Рівень 1: Активний рушій Go", loc["participating_levels"])
        self.assertIn("Динамічні відповіді, кешовані", loc["mechanism"])
        self.assertIn("Налаштуйте заголовки Cache-Control", loc["remediation"])

    def test_generate_fusion_html_report_uk(self):
        fusion_data = {
            "project": {"id": 1, "name": "Тестовий проект", "target": "https://example.com"},
            "generated_at": "2026-10-22T10:00:00Z",
            "severity_summary": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 2},
            "levels_summary": {"level1_active_scan": 1, "level2_corpus": 0, "level3_dom_and_assets": 1, "level4_ai_compound_chains": 1},
            "security_score": 75,
            "grade": "B",
            "owasp_breakdown": {"A03:2021-Injection": 1, "A08:2021-Software and Data Integrity Failures": 1},
            "compound_chains": [
                {
                    "chain_id": "CHAIN-01",
                    "title": "Compound Attack Chain: Web Cache Deception & Public Response Leaking",
                    "severity": "HIGH",
                    "endpoint": "https://example.com/api",
                    "participating_levels": ["Level 1: Go Active Engine"],
                    "mechanism": "Dynamic responses cached by intermediary CDN/proxy nodes using static file suffixes allow unauthenticated third parties to retrieve cached sensitive user records.",
                    "remediation": "Configure Cache-Control headers with no-store or private for user-dependent endpoints and disallow path suffix extension rewriting on reverse proxies.",
                    "findings_included": ["ACT-01"],
                }
            ],
            "unified_findings": [
                {
                    "id": "ACT-01",
                    "level": "Level 1: Go Active Engine",
                    "engine": "active",
                    "title": "Input Transformation Analysis (shell in the path)",
                    "severity": "CRITICAL",
                    "endpoint": "https://example.com/search",
                    "method": "GET",
                    "module": "escaping",
                    "owasp_category": "A03:2021-Injection",
                    "cwe": "CWE-78",
                    "evidence": "characters consumed by the escaping stack: [\\ ' \"]; values arrive undecoded: true",
                    "poc_curl": "curl -i 'https://example.com/search?q=1'",
                    "description": "The escaping stack between this parameter and its sink was measured from outside rather than assumed.",
                    "remediation": "Do not build shell commands from user input. Use argument arrays or a language-native API.",
                }
            ]
        }
        html = generate_fusion_html_report(fusion_data, lang="uk")
        self.assertIn('<html lang="uk">', html)
        self.assertIn("Зведений мультирушійний звіт безпеки", html)
        self.assertIn("Рівень 1: Активний рушій Go", html)
        self.assertIn("Аналіз перетворення вхідних даних (командна оболонка у ланцюжку виконання)", html)
        self.assertIn("Складений ланцюжок атаки: обман вебкешу", html)
        self.assertIn("Опис:", html)
        self.assertIn("Рекомендації:", html)
        self.assertIn("Докази:", html)

    def test_generate_fusion_sarif_uk(self):
        fusion_data = {
            "project": {"id": 1, "name": "Тестовий проект", "target": "https://example.com"},
            "unified_findings": [
                {
                    "id": "ACT-01",
                    "level": "Level 1: Go Active Engine",
                    "engine": "active",
                    "title": "OS Command Injection (Echo-Based, IFS substitution)",
                    "severity": "CRITICAL",
                    "endpoint": "https://example.com/cmd",
                    "module": "cmdi",
                    "owasp_category": "A03:2021-Injection",
                    "cwe": "CWE-78",
                    "evidence": "output matched 437",
                    "poc_curl": "curl -i 'https://example.com/cmd'",
                    "description": "OS command injection allows arbitrary command execution.",
                    "remediation": "Do not build shell commands from user input.",
                }
            ]
        }
        sarif = generate_fusion_sarif(fusion_data, lang="uk")
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["name"], "Впровадження команд ОС (RCE) (на основі виводу echo, підстановка $IFS)")
        result = sarif["runs"][0]["results"][0]
        self.assertIn("Впровадження команд ОС (RCE)", result["message"]["text"])
        self.assertIn("Не створюйте команди командної оболонки", result["properties"]["remediation"])

    def test_cms_and_safe_recon_localization_uk(self):
        cases = [
            ("CMS Detection: WordPress", "Виявлення CMS: WordPress"),
            ("CMS Reconnaissance: Joomla!", "Розвідка CMS: Joomla!"),
            ("WordPress Login Interface Disclosed", "Відкритий інтерфейс входу WordPress (wp-login.php)"),
            ("WordPress REST API Users Enumeration", "Перерахування користувачів WordPress через REST API"),
            ("WordPress XML-RPC Interface Exposed", "Відкритий інтерфейс XML-RPC WordPress"),
            ("WordPress Configuration / Debug Exposure", "Витік конфігурації / журналу налагодження WordPress"),
            ("Joomla! Admin Login Page Disclosed", "Відкрита панель адміністрування Joomla!"),
            ("Joomla! Configuration / Manifest Exposure", "Витік конфігурації / маніфесту Joomla!"),
            ("Drupal Admin Login Page Disclosed", "Відкрита панель входу Drupal"),
            ("Drupal Changelog / Install Script Disclosed", "Виявлено changelog або скрипт встановлення Drupal"),
            ("1C-Bitrix Admin Panel Disclosed", "Відкрита адміністративна панель 1C-Бітрікс"),
            ("OpenCart Admin Login Disclosed", "Відкрита панель адміністратора OpenCart"),
            ("Magento Admin Interface Disclosed", "Відкритий інтерфейс адміністратора Magento"),
            ("PrestaShop Admin / Install Probe", "Зондування панелі керування / інсталятора PrestaShop"),
            ("Ghost Admin / API Probe", "Зондування інтерфейсу адміністрування / API Ghost"),
            ("Strapi Admin / API Probe", "Зондування інтерфейсу адміністрування / API Strapi"),
            ("Directus Admin / API Probe", "Зондування інтерфейсу адміністрування / API Directus"),
            ("Shopify Public Surface Fingerprint", "Відбиток публічної платформи Shopify"),
            ("Strict-Transport-Security Header Missing", "Відсутній заголовок Strict-Transport-Security (HSTS)"),
            ("Content-Security-Policy Header Missing", "Відсутній заголовок Content-Security-Policy (CSP)"),
            ("X-Frame-Options / Clickjacking Protection Missing", "Відсутній захист від Clickjacking (X-Frame-Options)"),
            ("X-Content-Type-Options Header Missing", "Відсутній заголовок X-Content-Type-Options"),
            ("Referrer-Policy Header Missing", "Відсутній заголовок Referrer-Policy"),
            ("Permissions-Policy Header Missing", "Відсутній заголовок Permissions-Policy"),
            ("Cookie Missing Secure Flag", "У Cookie відсутній атрибут Secure"),
            ("Cookie Missing HttpOnly Flag", "У Cookie відсутній атрибут HttpOnly"),
            ("Cookie Missing SameSite Attribute", "У Cookie відсутній атрибут SameSite"),
            ("Outdated TLS Protocol Negotiated", "Узгоджено застарілий протокол TLS"),
            ("Server Software Banner Disclosed", "Розкрито банер серверного програмного забезпечення (Server)"),
            ("Backend Technology Disclosed", "Розкрито технологію бекенду (X-Powered-By)"),
            ("Web Application Firewall Detected", "Виявлено міжмережевий екран вебзастосунків (WAF)"),
            ("Open Path Probe: /wp-config.php.bak", "Виявлено відкритий шлях: /wp-config.php.bak"),
            ("Corpus status check: wp-login", "Перевірка стану корпусу: wp-login"),
            ("Corpus signature probe: drupal-core", "Зондування сигнатури корпусу: drupal-core"),
        ]
        for src, expected in cases:
            with self.subTest(title=src):
                self.assertEqual(localize_finding_title(src, "uk"), expected)

        desc = "CMS platform WordPress identified via passive signatures and HTML structure."
        loc_desc = localize_finding_desc(desc, "uk")
        self.assertIn("Платформу CMS WordPress ідентифіковано", loc_desc)

        rem = "Restrict administrative endpoints to trusted IP addresses, enforce multi-factor authentication (MFA), and keep CMS core and plugins updated."
        loc_rem = localize_finding_remediation(rem, "uk")
        self.assertIn("Обмежте доступ до адміністративних інтерфейсів", loc_rem)

        ev = "HTTP 200 received from /wp-login.php."
        loc_ev = localize_finding_evidence(ev, "uk")
        self.assertEqual(loc_ev, "Отримано відповідь HTTP 200 від /wp-login.php.")
