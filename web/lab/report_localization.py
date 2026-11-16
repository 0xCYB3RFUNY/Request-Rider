"""Comprehensive Security Report Localization for Request-Rider (Ukrainian & English).

Translates finding titles, descriptions, remediations, evidence, attack chains,
inspection levels, and OWASP Top 10 categories to Ukrainian when Ukrainian locale is active.
"""

import re

# 1. 4 Inspection Levels
LEVEL_NAMES = {
    "uk": {
        "Level 1: Go Active Engine": "Рівень 1: Активний рушій Go",
        "Level 2: Corpus Scanner": "Рівень 2: Сканер корпусу перевірок",
        "Level 2: Corpus Suite": "Рівень 2: Набір перевірок корпусу",
        "Level 3: DOM & Secret Assets": "Рівень 3: Клієнтські DOM-витоки та секрети",
        "Level 3: DOM Taint & Assets": "Рівень 3: Клієнтські DOM-витоки та секрети",
        "Level 4: Compound Chains": "Рівень 4: Складені ланцюжки атак",
        "Level 4: AI Compound Chains": "Рівень 4: Складені ланцюжки атак",
        "Level 4: ReAct AI Compound Attack Chains": "Рівень 4: Складені ланцюжки атак ReAct AI",
    },
    "en": {}
}

# 2. OWASP Top 10 2021 Descriptions
OWASP_NAMES = {
    "uk": {
        "A01:2021-Broken Access Control": "A01:2021-Порушення контролю доступу",
        "A02:2021-Cryptographic Failures": "A02:2021-Криптографічні помилки",
        "A03:2021-Injection": "A03:2021-Ін'єкції (Injection)",
        "A04:2021-Insecure Design": "A04:2021-Небезпечна архітектура",
        "A05:2021-Security Misconfiguration": "A05:2021-Некоректна конфігурація безпеки",
        "A06:2021-Vulnerable and Outdated Components": "A06:2021-Вразливі та застарілі компоненти",
        "A07:2021-Identification and Authentication Failures": "A07:2021-Помилки ідентифікації та автентифікації",
        "A08:2021-Software and Data Integrity Failures": "A08:2021-Порушення цілісності ПЗ та даних",
        "A09:2021-Security Logging and Monitoring Failures": "A09:2021-Збої журналювання та моніторингу",
        "A10:2021-Server-Side Request Forgery": "A10:2021-Підробка запитів на стороні сервера (SSRF)",
    }
}

# 3. Severity labels
SEVERITY_NAMES = {
    "uk": {
        "CRITICAL": "КРИТИЧНА",
        "HIGH": "ВИСОКА",
        "MEDIUM": "СЕРЕДНЯ",
        "LOW": "НИЗЬКА",
        "INFO": "ІНФО",
    }
}


def localize_level(level_str: str, lang: str = "uk") -> str:
    if lang != "uk" or not level_str:
        return level_str
    for k, v in LEVEL_NAMES["uk"].items():
        if k in level_str:
            return level_str.replace(k, v)
    if level_str.startswith("Level 1"):
        return level_str.replace("Level 1", "Рівень 1")
    if level_str.startswith("Level 2"):
        return level_str.replace("Level 2", "Рівень 2")
    if level_str.startswith("Level 3"):
        return level_str.replace("Level 3", "Рівень 3")
    if level_str.startswith("Level 4"):
        return level_str.replace("Level 4", "Рівень 4")
    return level_str


def localize_owasp(owasp_str: str, lang: str = "uk") -> str:
    if lang != "uk" or not owasp_str:
        return owasp_str
    for k, v in OWASP_NAMES["uk"].items():
        if k in owasp_str:
            return owasp_str.replace(k, v)
    return owasp_str


def localize_finding_title(title: str, lang: str = "uk") -> str:
    """Localize security finding title into Ukrainian."""
    if lang != "uk" or not title:
        return title or ""

    s = title.strip()

    # 1. Input Transformation Analysis (підтримка вкладених дужок)
    m = re.match(r"^Input Transformation Analysis\s*\((.+)\)$", s, re.I)
    if m:
        sub = m.group(1).lower()
        if "shell in the path" in sub:
            kind = "командна оболонка у ланцюжку виконання"
        elif "unwrapped" in sub:
            kind = "без екранування (рівень екранування не виявлено)"
        elif "single escape" in sub:
            kind = "один рівень екранування (поглинає зворотні слеші, екранує лапки)"
        elif "double escape" in sub:
            kind = "подвійний рівень екранування"
        elif "unclassified" in sub:
            kind = "некласифіковано"
        else:
            kind = m.group(1)
        return f"Аналіз перетворення вхідних даних ({kind})"

    # 2. Prototype Pollution
    m = re.match(r"^(?:prototype pollution|Забруднення прототипу \(Prototype Pollution\)):\s*(.+)$", s, re.I)
    if m:
        detail = m.group(1).strip()
        m2 = re.match(r"^(\w+)\s+merges a key path$", detail, re.I)
        if m2:
            channel = m2.group(1).lower()
            ch_map = {
                "query": "через параметри URL (query) виконується небезпечне злиття ключів",
                "form": "через дані форми (form) виконується небезпечне злиття ключів",
                "path": "через шлях запиту (path) виконується небезпечне злиття ключів",
                "json_proto_object": "через JSON-об'єкт __proto__ виконується небезпечне злиття ключів",
                "json_nested_proto": "через вкладений JSON __proto__ виконується небезпечне злиття ключів",
                "json_constructor": "через JSON constructor.prototype виконується небезпечне злиття ключів",
                "json_array_proto": "через масив JSON __proto__ виконується небезпечне злиття ключів",
                "json_deep_proto": "через глибокий JSON __proto__ виконується небезпечне злиття ключів",
            }
            detail = ch_map.get(channel, f"через {channel} виконується небезпечне злиття ключів")
        return f"Забруднення прототипу (Prototype Pollution): {detail}"

    # 3. Shellshock
    m = re.match(r"^Shellshock:\s*(.+)$", s, re.I)
    if m:
        detail = m.group(1).strip()
        detail = detail.replace("an injected command executed through User-Agent", "виконано інжектовану команду через заголовок User-Agent")
        return f"Вразливість Shellshock (CVE-2014-6271): {detail}"

    # 4. OS Command Injection
    m = re.match(r"^OS Command Injection\s*\(([^,]+),\s*([^)]+)\)$", s, re.I)
    if m:
        mode_raw = m.group(1).lower()
        mode = "на основі виводу echo" if "echo-based" in mode_raw else ("сліпа на основі затримок часу" if "time-based" in mode_raw else m.group(1))
        syntax_raw = m.group(2).lower()
        syntax_map = {
            "semicolon": "крапка з комою",
            "ifs substitution": "підстановка $IFS",
            "backtick": "зворотні лапки (backticks)",
            "pipe": "конвеєр (pipe)",
            "dollar subshell": "підстановка $(...)",
            "newline": "переведення рядка",
            "brace grouping": "групування дужками {cmd}",
            "or": "оператор OR (||)",
            "and": "оператор AND (&&)",
        }
        syntax = syntax_map.get(syntax_raw, m.group(2))
        return f"Впровадження команд ОС (RCE) ({mode}, {syntax})"

    # 5. User Input Reflected
    m = re.match(r"^User Input Reflected Without Encoding\s*\(([^)]+)\)$", s, re.I)
    if m:
        sub = m.group(1).replace("potential XSS", "потенційний XSS").replace("potential xss", "потенційний XSS")
        return f"Вхідні дані віддзеркалюються без екранування ({sub})"

    # 6. Reflected XSS
    m = re.match(r"^Reflected XSS\s*\((.+)\)$", s, re.I)
    if m:
        sub = m.group(1).replace("context", "контекст").replace("executable markup confirmed", "виконання розмітки підтверджено")
        return f"Віддзеркалений XSS ({sub})"

    # 7. Backup File Served
    m = re.match(r"^Backup File Served\s*\(([^)]+)\)(.*)$", s, re.I)
    if m:
        tail = f" {m.group(2).strip()}" if m.group(2).strip() else ""
        return f"Віддається резервна копія файлу ({m.group(1)}){tail}"

    # 8. CORS Misconfiguration
    m = re.match(r"^CORS Misconfiguration\s*\(([^)]+)\)$", s, re.I)
    if m:
        reason = "віддзеркалення Origin" if m.group(1).lower() == "origin reflected" else m.group(1)
        return f"Некоректна конфігурація CORS ({reason})"

    if re.match(r"^CORS with Credentials:\s*All Subdomains Trusted$", s, re.I):
        return "CORS з обліковими даними: довіра до всіх піддоменів"

    # 9. CSS Injection
    if re.match(r"^CSS Injection\s*\(Reflected\)$", s, re.I):
        return "Впровадження CSS (віддзеркалене)"

    # 10. Cacheable HTTPS Response
    if re.match(r"^Cacheable HTTPS Response Carrying Per-Recipient Data$", s, re.I):
        return "HTTPS-відповідь кешується та містить конфіденційні персональні дані"

    # 11. Client-Side JSON Injection
    m = re.match(r"^Client-Side JSON Injection\s*\(([^)]+)\):\s*(.+)$", s, re.I)
    if m:
        kind = "віддзеркалена DOM-базована" if "reflected" in m.group(1).lower() else "DOM-базована"
        return f"Клієнтська JSON-ін'єкція ({kind}): {m.group(2)}"

    # 12. Code Injection
    m = re.match(r"^Code Injection\s*\(([^)]+)\)$", s, re.I)
    if m:
        kind = m.group(1).replace("php concatenation", "конкатенація в PHP").replace("python percent format", "форматування % у Python")
        return f"Впровадження довільного коду ({kind})"

    # 13. Content Security Policy
    m = re.match(r"^Content Security Policy:\s*(.+)$", s, re.I)
    if m:
        det = m.group(1).strip()
        if "Allows Untrusted Script Execution" in det:
            det = "дозволяє виконання довільних скриптів ('unsafe-inline')"
        elif "Allows Untrusted Style Execution" in det:
            det = "дозволяє виконання небезпечних стилів ('unsafe-inline')"
        elif "Missing form-action" in det:
            det = "відсутня директива form-action (загроза Form Hijacking)"
        elif "Missing frame-ancestors" in det:
            det = "відсутня директива frame-ancestors (загроза Clickjacking)"
        elif "Wildcard Script Source" in det:
            det = "джерело скриптів містить маску wildcard (*)"
        return f"Політика безпеки контенту (CSP): {det}"

    # 14. Cookies
    m = re.match(r"^Cookie Manipulation\s*\(([^)]+)\):\s*(.+)$", s, re.I)
    if m:
        kind = "віддзеркалена DOM-базована" if "reflected" in m.group(1).lower() else "DOM-базована"
        return f"Маніпуляція Cookie ({kind}): {m.group(2)}"

    m = re.match(r"^Cookie Missing\s+(.+?)\s*\(([^)]+)\)$", s, re.I)
    if m:
        attrs = m.group(1).replace("and", "та")
        return f"У Cookie відсутні атрибути {attrs} ({m.group(2)})"

    m = re.match(r"^Duplicate Cookies Set in Response\s*\(([^)]+)\)$", s, re.I)
    if m:
        return f"Дублювання встановлення Cookie у відповіді ({m.group(1)})"

    # 15. Cross-Domain Script
    if re.match(r"^Cross-Domain Script Include$", s, re.I):
        return "Міждоменне підключення скриптів (Cross-Domain Script)"

    # 16. DOM Data & Web Message & Link Manipulation
    m = re.match(r"^DOM Data Manipulation\s*\(([^)]+)\):\s*(.+)$", s, re.I)
    if m:
        kind = "віддзеркалена DOM-базована" if "reflected" in m.group(1).lower() else "DOM-базована"
        return f"Маніпуляція даними DOM ({kind}): {m.group(2)}"

    m = re.match(r"^HTML5 Web Message Manipulation\s*\(([^)]+)\):\s*(.+)$", s, re.I)
    if m:
        kind = "віддзеркалена DOM-базована" if "reflected" in m.group(1).lower() else "DOM-базована"
        return f"Маніпуляція повідомленнями Web Message ({kind}): {m.group(2)}"

    m = re.match(r"^Link Manipulation\s*\(([^)]+)\):\s*(.+)$", s, re.I)
    if m:
        kind = "віддзеркалена DOM-базована" if "reflected" in m.group(1).lower() else "DOM-базована"
        return f"Маніпуляція посиланнями ({kind}): {m.group(2)}"

    m = re.match(r"^Denial of Service\s*\(([^)]+)\):\s*(.+)$", s, re.I)
    if m:
        kind = "віддзеркалена DOM-базована" if "reflected" in m.group(1).lower() else "DOM-базована"
        return f"Відмова в обслуговуванні ({kind}): {m.group(2)}"

    # 17. Dynamic page served unchanged
    m = re.match(r"^Dynamic page served unchanged for the static path\s*(\S*)$", s, re.I)
    if m:
        return f"Динамічна сторінка віддається без змін для статичного шляху {m.group(1)}"

    # 18. Google API Key & Secrets
    if re.match(r"^Google API Key Exposure\s*\(unverified\)$", s, re.I):
        return "Витік Google API Key (неверифікований)"

    m = re.match(r"^Hardcoded Secret Reference:\s*(.+)$", s, re.I)
    if m:
        return f"Виявлено посилання на вшитий секрет: {m.group(1)}"

    # 19. HTML Charset & HTTP Response Splitting
    if re.match(r"^HTML Charset Missing$", s, re.I):
        return "Відсутня кодова сторінка (Charset) в HTML"

    if re.match(r"^HTTP Response Splitting\s*\(percent-encoded\)$", s, re.I):
        return "Розщеплення HTTP-відповіді (HTTP Response Splitting, percent-encoded)"

    # 20. LDAP Injection
    m = re.match(r"^LDAP Injection\s*\(([^)]+)\)$", s, re.I)
    if m:
        sub = m.group(1).replace("filter widening", "розширення фільтра").replace("filter break", "злам фільтра").replace("wildcard", "маска wildcard")
        return f"LDAP-ін'єкція ({sub})"

    # 21. Missing Security Headers
    m = re.match(r"^Missing Security Headers\s*\(([^)]+)\)$", s, re.I)
    if m:
        return f"Відсутні безпекові заголовки ({m.group(1)})"

    # 22. NoSQL Injection
    m = re.match(r"^NoSQL Injection\s*\(([^)]+)\)$", s, re.I)
    if m:
        sub = m.group(1).replace("operator injection", "ін'єкція оператора")
        return f"NoSQL-ін'єкція ({sub})"

    # 23. Open Redirect
    m = re.match(r"^Open Redirect\s*\(([^)]+)\)$", s, re.I)
    if m:
        sub = m.group(1).replace("client-side", "клієнтське").replace("plain", "пряме").replace("protocol-relative", "protocol-relative")
        return f"Відкрите перенаправлення ({sub})"

    # 24. Published email & phone
    m = re.match(r"^Published email address\s*\(([^)]+)\)$", s, re.I)
    if m:
        return f"Опубліковано адресу електронної пошти ({m.group(1).replace('distinct', 'унікальних')})"

    m = re.match(r"^Published phone number\s*\(([^)]+)\)$", s, re.I)
    if m:
        return f"Опубліковано номер телефону ({m.group(1).replace('distinct', 'унікальних')})"

    # 25. RSC Action
    if "React Server Components Action Handled" in s:
        return "Обробка дій React Server Components (RSC): виявлено envelope помилки Flight"

    # 26. Dependent Response
    m = re.match(r"^(.+)-Dependent Response$", s, re.I)
    if m:
        return f"Відповідь сервера залежить від заголовка {m.group(1)}"

    # 27. ReDoS
    m = re.match(r"^Regular expression grows super-linearly with the parameter\s*\(([^)]+)\)$", s, re.I)
    if m:
        detail = m.group(1).replace("alternating classes, as in length or charset checks", "чергування класів символів / перевірка довжини")
        detail = detail.replace("number validation with a decimal point", "валідація чисел з десятковою крапкою")
        detail = detail.replace("repetition followed by a backslash, as in escape handling", "повторення зі зворотним слешем (екранування)")
        return f"Суперлінійне зростання регулярного виразу (ReDoS) ({detail})"

    # 28. URL Override
    if "Request URL Override Honoured" in s:
        return "Перевизначення URL запиту прийнято сервером (URL Override)"

    # 29. SSTI
    m = re.match(r"^Server-Side Template Injection\s*\((.+)\)$", s, re.I)
    if m:
        return f"Впровадження серверних шаблонів (SSTI) ({m.group(1)})"

    if re.match(r"^Template injection → code execution$", s, re.I):
        return "Впровадження шаблонів → виконання довільного коду (RCE)"

    # 30. Unrestricted HTTP Method
    if re.match(r"^Unrestricted HTTP Method\s*\(PUT accepted\)$", s, re.I):
        return "Необмежений HTTP-метод (дозволено метод PUT)"

    # 31. XPath Injection
    m = re.match(r"^XPath Injection\s*\(([^)]+)\)$", s, re.I)
    if m:
        sub = m.group(1).replace("boolean differential", "булевий диференціал")
        return f"XPath-ін'єкція ({sub})"

    # 32. Filter bypass (WAF/Filter evasion)
    m = re.match(r"^filter bypass:\s*(.+?)\s+reaches the page through a filter that blocked the plain shape$", s, re.I)
    if m:
        reason = m.group(1)
        reason_map = {
            "attribute-like tag name": "ім'я тегу у стилі атрибута",
            "bogus attribute pair": "фіктивна пара атрибутів",
            "javascript uri": "псевдопротокол javascript:",
            "mixed encoding, javascript uri": "змішане кодування з javascript:",
            "nul byte then smart quote": "нульовий байт з типографічною лапкою",
            "percent-encoded tag, raw angle": "відсоткове кодування тегу з кутовою дужкою",
            "percent-encoded whole tag": "повне відсоткове кодування тегу",
            "script element": "елемент <script>",
            "single-quoted handler": "обробник подій в одинарних лапках",
            "slash as tag separator": "слеш як роздільник тегу",
            "uppercase tag with regex source": "тег верхнього регістру",
        }
        r_uk = reason_map.get(reason.lower(), reason)
        return f"Обхід фільтрації (WAF bypass): {r_uk} потрапляє на сторінку через фільтр"

    # 33. CMS & Platform Detection
    m = re.match(r"^CMS Detection:\s*(.+)$", s, re.I)
    if m:
        return f"Виявлення CMS: {m.group(1)}"
    m = re.match(r"^CMS Reconnaissance:\s*(.+)$", s, re.I)
    if m:
        return f"Розвідка CMS: {m.group(1)}"
    if re.match(r"^WordPress Login Interface Disclosed$", s, re.I):
        return "Відкритий інтерфейс входу WordPress (wp-login.php)"
    if re.match(r"^WordPress REST API Users Enumeration$", s, re.I):
        return "Перерахування користувачів WordPress через REST API"
    if re.match(r"^WordPress XML-RPC Interface Exposed$", s, re.I):
        return "Відкритий інтерфейс XML-RPC WordPress"
    if re.match(r"^WordPress Configuration / Debug Exposure$", s, re.I):
        return "Витік конфігурації / журналу налагодження WordPress"
    if re.match(r"^Joomla! Admin Login Page Disclosed$", s, re.I):
        return "Відкрита панель адміністрування Joomla!"
    if re.match(r"^Joomla! Configuration / Manifest Exposure$", s, re.I):
        return "Витік конфігурації / маніфесту Joomla!"
    if re.match(r"^Drupal Admin Login Page Disclosed$", s, re.I):
        return "Відкрита панель входу Drupal"
    if re.match(r"^Drupal Changelog / Install Script Disclosed$", s, re.I):
        return "Виявлено changelog або скрипт встановлення Drupal"
    if re.match(r"^1C-Bitrix Admin Panel Disclosed$", s, re.I):
        return "Відкрита адміністративна панель 1C-Бітрікс"
    if re.match(r"^OpenCart Admin Login Disclosed$", s, re.I):
        return "Відкрита панель адміністратора OpenCart"
    if re.match(r"^Magento Admin Interface Disclosed$", s, re.I):
        return "Відкритий інтерфейс адміністратора Magento"
    if re.match(r"^PrestaShop Admin / Install Probe$", s, re.I):
        return "Зондування панелі керування / інсталятора PrestaShop"
    if re.match(r"^Ghost Admin / API Probe$", s, re.I):
        return "Зондування інтерфейсу адміністрування / API Ghost"
    if re.match(r"^Strapi Admin / API Probe$", s, re.I):
        return "Зондування інтерфейсу адміністрування / API Strapi"
    if re.match(r"^Directus Admin / API Probe$", s, re.I):
        return "Зондування інтерфейсу адміністрування / API Directus"
    if re.match(r"^Shopify Public Surface Fingerprint$", s, re.I):
        return "Відбиток публічної платформи Shopify"

    # 34. Infrastructure & Safe Recon Findings
    if re.match(r"^Target Host Unreachable$", s, re.I):
        return "Цільовий хост недосяжний"
    if re.match(r"^Public HTTP Service Discovered$", s, re.I):
        return "Виявлено публічний HTTP-сервіс"
    if re.match(r"^Public HTTPS Service Discovered$", s, re.I):
        return "Виявлено публічний HTTPS-сервіс"
    if re.match(r"^Strict-Transport-Security Header Missing$", s, re.I):
        return "Відсутній заголовок Strict-Transport-Security (HSTS)"
    if re.match(r"^Content-Security-Policy Header Missing$", s, re.I):
        return "Відсутній заголовок Content-Security-Policy (CSP)"
    if re.match(r"^X-Frame-Options / Clickjacking Protection Missing$", s, re.I):
        return "Відсутній захист від Clickjacking (X-Frame-Options)"
    if re.match(r"^X-Content-Type-Options Header Missing$", s, re.I):
        return "Відсутній заголовок X-Content-Type-Options"
    if re.match(r"^Referrer-Policy Header Missing$", s, re.I):
        return "Відсутній заголовок Referrer-Policy"
    if re.match(r"^Permissions-Policy Header Missing$", s, re.I):
        return "Відсутній заголовок Permissions-Policy"
    if re.match(r"^Cookie Missing Secure Flag$", s, re.I):
        return "У Cookie відсутній атрибут Secure"
    if re.match(r"^Cookie Missing HttpOnly Flag$", s, re.I):
        return "У Cookie відсутній атрибут HttpOnly"
    if re.match(r"^Cookie Missing SameSite Attribute$", s, re.I):
        return "У Cookie відсутній атрибут SameSite"
    if re.match(r"^Outdated TLS Protocol Negotiated$", s, re.I):
        return "Узгоджено застарілий протокол TLS"
    if re.match(r"^Server Software Banner Disclosed$", s, re.I):
        return "Розкрито банер серверного програмного забезпечення (Server)"
    if re.match(r"^Backend Technology Disclosed$", s, re.I):
        return "Розкрито технологію бекенду (X-Powered-By)"
    if re.match(r"^Web Application Firewall Detected$", s, re.I):
        return "Виявлено міжмережевий екран вебзастосунків (WAF)"
    m = re.match(r"^Open Path Probe:\s*(.+)$", s, re.I)
    if m:
        return f"Виявлено відкритий шлях: {m.group(1)}"
    if re.match(r"^Potentially Dangerous HTTP Method Allowed$", s, re.I):
        return "Дозволено потенційно небезпечний HTTP-метод"
    if re.match(r"^Scan Completed with No High-Risk Exposures$", s, re.I):
        return "Сканування завершено без виявлення загроз високого ризику"
    m = re.match(r"^Corpus status check:\s*(.+)$", s, re.I)
    if m:
        return f"Перевірка стану корпусу: {m.group(1)}"
    m = re.match(r"^Corpus signature probe:\s*(.+)$", s, re.I)
    if m:
        return f"Зондування сигнатури корпусу: {m.group(1)}"

    # 35. Generic Fallbacks for standard categories
    if re.match(r"^SQL Injection\s*(.*)$", s, re.I):
        tail = s[13:].strip()
        return f"Впровадження SQL-коду (SQLi) {tail}".strip()
    if re.match(r"^Cross-Site Scripting\s*(.*)$", s, re.I):
        tail = s[21:].strip()
        return f"Міжсайтовий скриптинг (XSS) {tail}".strip()
    if re.match(r"^Server-Side Request Forgery\s*(.*)$", s, re.I):
        tail = s[27:].strip()
        return f"Підробка запитів на стороні сервера (SSRF) {tail}".strip()
    if re.match(r"^Directory Traversal\s*(.*)$", s, re.I) or re.match(r"^Path Traversal\s*(.*)$", s, re.I):
        return "Обхід шляху каталогів (Path Traversal)"
    if re.match(r"^XML External Entity\s*(.*)$", s, re.I):
        return "Впровадження зовнішніх XML-сутностей (XXE)"
    if re.match(r"^Insecure Deserialization\s*(.*)$", s, re.I):
        return "Небезпечна десеріалізація даних"
    if re.match(r"^GraphQL Introspection\s*(.*)$", s, re.I):
        return "Розкриття схеми GraphQL (Introspection)"

    return s


def localize_finding_desc(desc: str, lang: str = "uk") -> str:
    """Localize finding description into Ukrainian."""
    if lang != "uk" or not desc:
        return desc or ""

    s = desc.strip()

    # Escaping stack analysis
    if "escaping stack between this parameter and its sink was measured" in s:
        return (
            "Стек екранування між цим параметром і його приймачем (sink) було виміряно ззовні, а не припущено. "
            "Сам по собі цей стан не є вразливістю: це умова, що визначає, які класи ін'єкцій можуть досягти успіху. "
            "Один шар екранування нейтралізує пейлоади з лапками і вимагає обходу через зворотний слеш; "
            "два шари споживають обидва і вимагають ширшого пейлоаду; параметр без екранування означає, що захисний "
            "фільтр проти SQLi чи RCE ніколи не застосовувався між цим параметром і обробником."
        )

    # Shellshock
    if "Shellshock" in s or "an injected command executed through User-Agent" in s:
        return "Критична вразливість виконання системних команд через підстановку функції у заголовку User-Agent (Shellshock, CVE-2014-6271)."

    # Command Injection
    if "echo-based" in s.lower() or "command injection" in s.lower():
        if "evaluated as an expression rather than compared as text" in s:
            return "Значення параметра було обчислено сервером як вираз замість порівняння як тексту. Арифметика інжекції підтвердила виконання довільних команд на сервері."
        return "Критична вразливість віддаленого виконання команд (RCE). Дозволяє виконувати довільні системні інструкції на сервері."

    # Prototype Pollution
    if "The probe's own value was reflected, so the key path reached a merge that copied it" in s or (
        "probe's own value was reflected" in s and "prototype" in s.lower()
    ):
        return (
            "Значення тестового зонда віддзеркалилося у відповіді, отже шлях ключів досяг операції злиття (merge), "
            "яка його скопіювала. Забруднення прототипу (Prototype Pollution) можливе лише через злиття, що копіює "
            "непередбачені ключі, тому в записі вказано шлях ключів, який було перезаписано, а не сам пейлоад окремо."
        )
    if "the answer grew a pollution key this run's probe writes" in s or "The probe wrote a key the application then read back" in s:
        return (
            "Тестовий зонд записав ключ, який застосунок потім прочитав назад. Забруднення прототипу (Prototype Pollution) "
            "можливе лише через злиття, що копіює непередбачені ключі, тому в записі вказано шлях ключів, який було "
            "перезаписано, а не сам пейлоад окремо."
        )
    if "The probe made the application fail while naming a prototype-shaped value" in s:
        return (
            "Тестовий зонд спричинив збій у роботі застосунку (HTTP 500) при зверненні до прототипної властивості. "
            "Забруднення прототипу (Prototype Pollution) можливе лише через злиття, що копіює непередбачені ключі, "
            "тому в записі вказано шлях ключів, який було перезаписано, а не сам пейлоад окремо."
        )
    if "A prototype pollution is only reachable through a merge that copies keys it was not asked to copy" in s:
        return (
            "Забруднення прототипу (Prototype Pollution) можливе лише через операцію злиття об'єктів (merge), яка копіює "
            "непередбачені ключі, тому в записі вказано шлях ключів, який було перезаписано, а не сам пейлоад окремо."
        )
    if "prototype pollution" in s.lower() or "merges a key path" in s:
        return "Вразливість забруднення прототипу (Prototype Pollution). Дозволяє модифікувати Object.prototype через параметри запиту або тіла, що веде до зміни логіки програми або виконання довільного коду."

    # ReDoS
    if "super-linearly" in s or "answered" in s and "ms for" in s:
        return "Час обробки параметра зростає суперлінійно (нелінійно) від довжини вхідних даних, що свідчить про вразливість регулярного виразу до відмови в обслуговуванні (ReDoS)."

    # Secret Reference
    if "potential secret or token reference" in s:
        return "Виявлено потенційний токен або ключ доступу у клієнтських ресурсах або мережевому трафіку."

    # CSP
    if "policy omits form-action" in s:
        return "Політика безпеки контенту (CSP) пропускає директиву form-action. У разі HTML-ін'єкції зловмисник може перехопити відправку форми."
    if "policy omits frame-ancestors" in s:
        return "Політика CSP не містить frame-ancestors, що дозволяє вбудовувати сайт у фрейми (Clickjacking)."

    # CORS
    if "Access-Control-Allow-Origin" in s:
        return "Сервер повертає надмірно дозволяючі заголовки CORS, що дозволяє стороннім веб-сайтам зчитувати відповіді на автентифіковані запити користувача."

    # Cache Deception
    if "cached by intermediary CDN" in s or "cacheable" in s.lower():
        return "Динамічні відповіді з персональними даними кешуються проміжними проксі-вузлами через некоректні заголовки Cache-Control або суфікси статичних файлів."

    # URL Override
    if "answered as if it had been a request for" in s:
        return "Сервер прийняв заголовок перевизначення URL (X-Original-URL / X-Rewrite-URL) та віддав конфіденційний внутрішній ресурс."

    # CMS & Recon Findings
    m = re.match(r"^CMS platform (.+) identified via passive signatures.*$", s, re.I)
    if m:
        return f"Платформу CMS {m.group(1)} ідентифіковано за пасивними сигнатурами та структурою ресурсу."
    if re.match(r"^The target host could not be reached.*$", s, re.I):
        return "Не вдалося встановити зв'язок із цільовим хостом під час перевірки доступності."
    if re.match(r"^The target serves an unencrypted HTTP service.*$", s, re.I):
        return "Ціль надає відкритий незашифрований HTTP-сервіс, чутливий до перехоплення та модифікації трафіку."
    if re.match(r"^The target serves an HTTPS service.*$", s, re.I):
        return "Ціль надає захищений HTTPS-сервіс для шифрування транспортного рівня."
    if re.match(r"^The HTTP Strict-Transport-Security \(HSTS\) header is missing.*$", s, re.I):
        return "Заголовок HTTP Strict-Transport-Security (HSTS) відсутній, що уможливлює атаки пониження протоколу (SSL-stripping)."
    if re.match(r"^Content-Security-Policy \(CSP\) is missing.*$", s, re.I):
        return "Заголовок Content-Security-Policy (CSP) відсутній, що послаблює захист браузера від XSS та небажаних ін'єкцій."
    if re.match(r"^X-Frame-Options is missing and CSP frame-ancestors is absent.*$", s, re.I):
        return "Заголовок X-Frame-Options відсутній, а CSP frame-ancestors не налаштовано; інтерфейс може бути вбудований у чужі фрейми (Clickjacking)."
    if re.match(r"^X-Content-Type-Options is missing.*$", s, re.I):
        return "Заголовок X-Content-Type-Options відсутній; браузери можуть помилково визначати MIME-тип контенту (MIME sniffing)."
    if re.match(r"^Referrer-Policy header is missing.*$", s, re.I):
        return "Заголовок Referrer-Policy відсутній; повні URL-адреси з параметрами можуть витікати через заголовок Referer."
    if re.match(r"^Permissions-Policy header is missing.*$", s, re.I):
        return "Заголовок Permissions-Policy відсутній; сайт не обмежує доступ браузера до мікрофона, камери чи геолокації."
    m = re.match(r"^Cookie (.+) was set without the Secure attribute.*$", s, re.I)
    if m:
        return f"Cookie {m.group(1)} встановлено без атрибута Secure, що дозволяє його передачу відкритим текстом через HTTP."
    m = re.match(r"^Cookie (.+) was set without the HttpOnly attribute.*$", s, re.I)
    if m:
        return f"Cookie {m.group(1)} встановлено без атрибута HttpOnly; клієнтський JavaScript має прямий доступ до значення cookie."
    m = re.match(r"^Cookie (.+) was set without an explicit SameSite attribute.*$", s, re.I)
    if m:
        return f"Cookie {m.group(1)} встановлено без явного атрибута SameSite, що підвищує ризик атак підробки міжсайтових запитів (CSRF)."
    if re.match(r"^The server supports an obsolete TLS version.*$", s, re.I):
        return "Сервер підтримує застарілу версію TLS з відомими криптографічними недоліками."
    if re.match(r"^The Server HTTP response header reveals detailed software or version information\.", s, re.I):
        return "Заголовок відповіді Server розкриває інформацію про версію серверного програмного забезпечення."
    if re.match(r"^The X-Powered-By HTTP response header reveals the underlying backend framework or language\.", s, re.I):
        return "Заголовок відповіді X-Powered-By розкриває інформацію про фреймворк або мову програмування бекенду."
    if re.match(r"^A Web Application Firewall \(WAF\) was identified.*$", s, re.I):
        return "Виявлено міжмережевий екран вебзастосунків (WAF) або захисний проксі-вузол."
    if re.match(r"^Sensitive administrative, configuration, or debug endpoint responded with HTTP.*$", s, re.I):
        return "Чутливий адміністративний, конфігураційний або налагоджувальний ендпоінт відповів доступним HTTP-кодом під час безпечного зондування."
    if re.match(r"^Potentially dangerous HTTP methods such as PUT, DELETE.*$", s, re.I):
        return "Дозволено потенційно небезпечні HTTP-методи (PUT, DELETE тощо), які можуть дозволити несанкціоновану модифікацію файлів."
    if re.match(r"^The passive and non-destructive active probes did not detect any high-severity misconfigurations or exposed sensitive paths\.", s, re.I):
        return "Пасивні та безпечні активні зондування не виявили критичних невідповідностей безпеки або відкритих чутливих шляхів."
    m = re.match(r"^Corpus status verification for (.+?)\.", s, re.I)
    if m:
        return f"Перевірка стану корпусу для {m.group(1)}."
    m = re.match(r"^Corpus signature probe for (.+?)\.", s, re.I)
    if m:
        return f"Зондування сигнатури корпусу для {m.group(1)}."

    return s


def localize_finding_remediation(rem: str, lang: str = "uk") -> str:
    """Localize remediation advice into Ukrainian."""
    if lang != "uk" or not rem:
        return rem or ""

    s = rem.strip()

    if "Set form-action 'self'" in s:
        return "Встановіть директиву form-action 'self' або явно дозволені цільові ендпоінти у заголовку Content-Security-Policy."

    if "frame-ancestors" in s:
        return "Додайте директиву 'frame-ancestors none' або 'frame-ancestors self' до Content-Security-Policy для захисту від Clickjacking."

    if "Do not build shell commands from user input" in s:
        return "Не створюйте команди командної оболонки з вхідних даних користувача. Використовуйте безпечні масиви аргументів або вбудовані API без виклику shell."

    if "Do not dynamically reflect Origin headers" in s:
        return "Не віддзеркалюйте динамічно заголовок Origin та не довіряйте значенню 'null'. Підтримуйте суворий список дозволених доменів (allowlist) на стороні сервера."

    if "Move the credential server-side" in s or "Remove secret keys" in s:
        return "Видаліть конфіденційні ключі та токени з клієнтських скриптів. Перенесіть автентифікацію на сторону сервера і проведіть ротацію скомпрометованих секретів."

    if "Filter on structure, not on spelling" in s:
        return "Фільтруйте за структурою, а не за написанням: парсіть значення там, де воно обробляється, і застосовуйте суворий білий список допустимих символів."

    if "Bind the value as a parameter instead of concatenating" in s:
        return "Прив'язуйте значення як параметри замість конкатенації у рядок запиту або шлях."

    if "Contextually encode user input" in s:
        return "Контекстно кодуйте вхідні дані користувача перед підстановкою в HTML/CSS атрибути, або уникайте виведення неперевірених даних."

    if "Configure Cache-Control headers with no-store" in s:
        return "Налаштуйте заголовки Cache-Control: no-store, private для динамічних сторінок користувача та забороніть небезпечний перезапис шляхів на зворотних проксі."

    if "Reject `__proto__`, `constructor` and `prototype` in any key path" in s or (
        "__proto__" in s and "constructor" in s and "prototype" in s and "deepMerge" in s
    ):
        return (
            "Блокуйте ключі `__proto__`, `constructor` та `prototype` у будь-якому шляху ключів, що потрапляє до "
            "рекурсивного злиття (merge) або глибокого клонування об'єктів. За можливості зливайте дані в об'єкт із "
            "нульовим прототипом (`Object.create(null)`). Типовими місцями виникнення є функції Lodash `merge`, "
            "`defaultsDeep` або власні реалізації `deepMerge`."
        )

    if "Object.freeze(Object.prototype)" in s or "prototype" in s.lower():
        return "Використовуйте Object.freeze(Object.prototype), перевіряйте заборонені ключі (__proto__, constructor, prototype) або створіть порожні мапи через Object.create(null)."

    # CMS & Infrastructure Remediations
    if re.match(r"^Restrict administrative endpoints to trusted IP addresses.*$", s, re.I):
        return "Обмежте доступ до адміністративних інтерфейсів за допомогою списків дозволених IP, увімкніть багатофакторну автентифікацію (MFA) та оновіть ядро CMS і плагіни до актуальних версій."
    if re.match(r"^Redirect all HTTP traffic to HTTPS.*$", s, re.I):
        return "Налаштуйте перенаправлення (HTTP 301) всього HTTP-трафіку на HTTPS."
    if re.match(r"^Enable HTTP Strict Transport Security.*$", s, re.I):
        return "Увімкніть HTTP Strict Transport Security (HSTS) із тривалим max-age (наприклад, 31536000) та includeSubDomains."
    if re.match(r"^Deploy a restrictive Content-Security-Policy.*$", s, re.I):
        return "Розгорніть обмежувальну політику Content-Security-Policy (CSP) для запобігання XSS та міжсайтовим ін'єкціям."
    if re.match(r"^Set X-Frame-Options: DENY or SAMEORIGIN.*$", s, re.I):
        return "Встановіть заголовок X-Frame-Options: DENY або SAMEORIGIN і налаштуйте CSP директиву frame-ancestors."
    if re.match(r"^Set X-Content-Type-Options: nosniff.*$", s, re.I):
        return "Встановіть заголовок X-Content-Type-Options: nosniff для блокування помилкового визначення MIME-типів."
    if re.match(r"^Set Referrer-Policy to strict-origin-when-cross-origin.*$", s, re.I):
        return "Встановіть заголовок Referrer-Policy у значення strict-origin-when-cross-origin або no-referrer."
    if re.match(r"^Configure Permissions-Policy.*$", s, re.I):
        return "Налаштуйте заголовок Permissions-Policy для явного обмеження небажаних функцій браузера."
    if re.match(r"^Add the Secure flag to all sensitive cookies.*$", s, re.I):
        return "Додайте атрибут Secure до всіх сесійних cookie, щоб вони передавалися виключно через HTTPS."
    if re.match(r"^Add the HttpOnly flag to cookies.*$", s, re.I):
        return "Додайте атрибут HttpOnly до сесійних cookie для захисту від викрадення через XSS."
    if re.match(r"^Set SameSite=Lax or SameSite=Strict.*$", s, re.I):
        return "Встановіть атрибут SameSite=Lax або SameSite=Strict для запобігання CSRF-атакам."
    if re.match(r"^Disable outdated TLS 1.0 and 1.1.*$", s, re.I):
        return "Вимкніть застарілі протоколи TLS 1.0 та TLS 1.1; вимагайте використання щонайменше TLS 1.2 або TLS 1.3."
    if re.match(r"^Suppress or obfuscate the Server header.*$", s, re.I):
        return "Приховайте або обфускуйте заголовок Server у конфігурації вебсервера для запобігання розкриттю версії."
    if re.match(r"^Remove the X-Powered-By header.*$", s, re.I):
        return "Видаліть заголовок X-Powered-By з конфігурації бекенд-сервера або застосунку."
    if re.match(r"^Ensure WAF rules are actively enforced.*$", s, re.I):
        return "Переконайтеся, що правила WAF активні та блокують відомі вектори атак на додаток до захисту на рівні коду."
    if re.match(r"^Restrict access to sensitive administrative or backup files.*$", s, re.I):
        return "Обмежте публічний доступ до чутливих адміністративних або резервних файлів через конфігурацію вебсервера."
    if re.match(r"^Disable unnecessary HTTP methods.*$", s, re.I):
        return "Вимкніть невикористовувані HTTP-методи (PUT, DELETE тощо) у конфігурації вебсервера або контролера."
    if re.match(r"^Continue regular vulnerability scanning.*$", s, re.I):
        return "Продовжуйте регулярне сканування вразливостей і підтримуйте програмне забезпечення системи в актуальному стані."

    return s


def localize_finding_evidence(ev: str, lang: str = "uk") -> str:
    """Localize finding evidence strings into Ukrainian."""
    if lang != "uk" or not ev:
        return ev or ""

    s = ev.strip()
    m = re.match(r"^characters consumed by the escaping stack:\s*\[(.*?)\];\s*values arrive undecoded:\s*(true|false)$", s, re.I)
    if m:
        chars = m.group(1) or "жодного"
        undecoded = "так" if m.group(2).lower() == "true" else "ні"
        return f"Символи, поглинуті стеком екранування: [{chars}]; значення надходять недекодованими: {undecoded}"

    m = re.match(r"^this run's marker came back in the answer and was not on the page before:\s*(.+)$", s, re.I)
    if m:
        return f"Маркер поточного запуску повернувся у відповіді сервера і був відсутній на сторінці раніше: {m.group(1)}"

    m = re.match(r"^the answer grew a pollution key this run's probe writes:\s*(.+)$", s, re.I)
    if m:
        return f"Відповідь сервера містить ключ забруднення, записаний тестовим зондом поточного запуску: {m.group(1)}"

    m = re.match(r"^the request failed with\s+(.+?)\s+and the message names\s+(`[^`]+`|\"[^\"]+\"),\s*which the same surface did not do without the probe$", s, re.I)
    if m:
        return f"Запит завершився помилкою {m.group(1)}, і повідомлення містить {m.group(2)}, чого не спостерігалося для цього ресурсу без зонда"

    if s.startswith("Secret reference observed:"):
        return s.replace("Secret reference observed:", "Виявлено посилання на секрет:")

    if "this run's marker came back in the answer" in s:
        return s.replace("this run's marker came back in the answer", "маркер поточного запуску повернувся у відповіді сервера")

    # CMS & Recon Evidence
    m = re.match(r"^HTTP (\d+) received from (.+)\.$", s, re.I)
    if m:
        return f"Отримано відповідь HTTP {m.group(1)} від {m.group(2)}."
    m = re.match(r"^Technology:\s*(.+)$", s, re.I)
    if m:
        return f"Технологія: {m.group(1)}"
    m = re.match(r"^Page marker:\s*(.+)$", s, re.I)
    if m:
        return f"Маркер сторінки: {m.group(1)}"
    m = re.match(r"^(.+)\s+signature detected on target\.$", s, re.I)
    if m:
        return f"На цілі виявлено сигнатуру {m.group(1)}."
    m = re.match(r"^Meta generator tag exposed:\s*(.+)$", s, re.I)
    if m:
        return f"Виявлено метатег generator: {m.group(1)}"
    m = re.match(r"^Passive inspection did not identify signatures for (.+)\.$", s, re.I)
    if m:
        return f"Пасивна перевірка не виявила сигнатур для {m.group(1)}."
    if re.match(r"^No specialized API framework banner detected passively; proceeding with endpoint probes\.$", s, re.I):
        return "Специфічних банерів API-фреймворку пасивно не виявлено; триває перевірка ендпоінтів."
    if re.match(r"^Strict-Transport-Security header was not sent over HTTPS connection\.$", s, re.I):
        return "Заголовок Strict-Transport-Security не було надіслано через HTTPS-з'єднання."
    if re.match(r"^Content-Security-Policy header was not sent by the target\.$", s, re.I):
        return "Заголовок Content-Security-Policy не було надіслано сервером цілі."
    if re.match(r"^Neither X-Frame-Options nor CSP frame-ancestors was configured\.$", s, re.I):
        return "Не налаштовано ані заголовок X-Frame-Options, ані директиву CSP frame-ancestors."
    if re.match(r"^X-Content-Type-Options header was not set to nosniff\.$", s, re.I):
        return "Заголовок X-Content-Type-Options не встановлено у значення nosniff."
    if re.match(r"^Referrer-Policy header is absent\.$", s, re.I):
        return "Заголовок Referrer-Policy відсутній."
    if re.match(r"^Permissions-Policy \(Feature-Policy\) header is absent\.$", s, re.I):
        return "Заголовок Permissions-Policy (Feature-Policy) відсутній."
    m = re.match(r"^Server header:\s*(.+)$", s, re.I)
    if m:
        return f"Заголовок Server: {m.group(1)}"
    m = re.match(r"^X-Powered-By header:\s*(.+)$", s, re.I)
    if m:
        return f"Заголовок X-Powered-By: {m.group(1)}"
    m = re.match(r"^Cookie (.+) was set without Secure\.$", s, re.I)
    if m:
        return f"Cookie {m.group(1)} встановлено без прапорця Secure."
    m = re.match(r"^Cookie (.+) was set without HttpOnly\.$", s, re.I)
    if m:
        return f"Cookie {m.group(1)} встановлено без прапорця HttpOnly."
    m = re.match(r"^Cookie (.+) did not advertise an explicit SameSite policy\.$", s, re.I)
    if m:
        return f"Cookie {m.group(1)} не містить явної політики SameSite."
    m = re.match(r"^The target negotiated (?:legacy )?(.+)\.$", s, re.I)
    if m:
        return f"Ціль погодила протокол {m.group(1)}."
    m = re.match(r"^Negotiated protocol:\s*(.+)$", s, re.I)
    if m:
        return f"Узгоджений протокол: {m.group(1)}"
    m = re.match(r"^WAF vendors:\s*(.+)$", s, re.I)
    if m:
        return f"Постачальники WAF: {m.group(1)}"
    m = re.match(r"^(.+) returned HTTP (\d+) \(read-only probe; content was not retained\)\.$", s, re.I)
    if m:
        return f"{m.group(1)} повернув HTTP {m.group(2)} (безпечне зондування; вміст не зберігався)."
    m = re.match(r"^Allow header:\s*(.+)$", s, re.I)
    if m:
        return f"Заголовок Allow: {m.group(1)}"
    m = re.match(r"^The target did not surface obvious public exposures during the (.+) scan\.$", s, re.I)
    if m:
        return f"Під час сканування {m.group(1)} на цілі не виявлено очевидних відкритих загроз."

    return s


def localize_compound_chain(chain: dict, lang: str = "uk") -> dict:
    """Localize a Level 4 Compound Attack Chain object into Ukrainian."""
    if lang != "uk":
        return chain

    c = dict(chain)
    title = c.get("title", "")
    if "Cross-Origin Token Theft" in title:
        c["title"] = "Складений ланцюжок атаки: викрадення міждоменних токенів та компрометація облікового запису"
        c["mechanism"] = "Надмірно дозволяючі заголовки CORS у поєднанні з небезпечною обробкою токенів/облікових даних дозволяють сторонньому зловмисному домену викрадати сесійні токени жертви через автентифіковані міждоменні запити."
        c["remediation"] = "Обмежте Access-Control-Allow-Origin явно визначеними довіреними джерелами, забороніть облікові дані з wildcard та налаштуйте атрибут SameSite=Lax або Strict для cookie."
    elif "Web Cache Deception" in title:
        c["title"] = "Складений ланцюжок атаки: обман вебкешу та витік персональних відповідей"
        c["mechanism"] = "Динамічні відповіді, кешовані проміжними вузлами CDN/проксі через суфікси статичних файлів, дозволяють неавтентифікованим користувачам отримувати кешовані конфіденційні записи інших користувачів."
        c["remediation"] = "Налаштуйте заголовки Cache-Control зі значеннями no-store або private для ендпоінтів користувача та забороніть перезапис розширень суфіксів шляху на зворотних проксі-серверах."

    if "participating_levels" in c and isinstance(c["participating_levels"], list):
        c["participating_levels"] = [localize_level(lvl, lang="uk") for lvl in c["participating_levels"]]

    return c


def localize_finding(finding: dict, lang: str = "uk") -> dict:
    """Return a localized copy of a unified finding dictionary."""
    if lang != "uk":
        return finding

    f = dict(finding)
    f["title"] = localize_finding_title(f.get("title", ""), lang="uk")
    if f.get("description"):
        f["description"] = localize_finding_desc(f["description"], lang="uk")
    if f.get("remediation"):
        f["remediation"] = localize_finding_remediation(f["remediation"], lang="uk")
    if f.get("evidence"):
        f["evidence"] = localize_finding_evidence(f["evidence"], lang="uk")
    if f.get("level"):
        f["level"] = localize_level(f["level"], lang="uk")
    if f.get("owasp_category"):
        f["owasp_category"] = localize_owasp(f["owasp_category"], lang="uk")

    return f
