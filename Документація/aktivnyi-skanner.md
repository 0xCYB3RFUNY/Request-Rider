# Активний сканер

## Що це

Активний сканер обходить ціль, досліджує поверхню атаки та перевіряє кандидатів
уразливостей понад **70 спеціалізованими модулями виявлення**, згрупованими за
рівнями (endpoint, parameter, host). Кожна знахідка отримує **рівень** —
`verified` або `potential` — ендпоінт, детальне доказове поле (evidence), а коли
модуль це дозволяє — окремий **доказ впливу (proof of impact)**: другий запит,
який має спрацювати, щоб оператор побачив беззаперечний наслідок уразливості.

Це інструмент `Scanner → Active & Corpus Scanner` вкладки Scanner. Він об'єднує
евристичний динамічний аналіз та сигнатурний Corpus-сканер, працює в режимі
реального часу (SSE), має власні контролі життєвого циклу завдань (пауза, відновлення,
перевідправка) та роздільний експорт знахідок.

> **Межі роботи.** Сканер збирає докази, а не здійснює деструктивні атаки.
> Доказ впливу — це окремий запит із доведеним очікуваним наслідком (читання нечутливого
> маркера/файлу, виконання математичного виразу в шаблоні), а не руйнування даних цілі.
> Усі запити виконуються через єдиний generation-aware passive proxy з підтримкою Direct
> або SOCKS5/Tor, відображаються у вкладках Traffic та History.

---

## Архітектура та виявлення SPA / API (Клієнтський аналіз)

Сучасні односторінкові застосунки (SPA: React, Vue, Angular) часто не містять
традиційних HTML-форм на сторінках входу або каталогах. Для виявлення їхньої повної
поверхні атаки активний сканер реалізує:

1. **SPA Discovery**: під час краулінгу сторінок сканер аналізує підключені
   same-origin JavaScript файли (скрипти бандлів) та видобуває відносні й абсолютні
   API-маршрути (`/api/...`, `/rest/...`, `/auth/...`, `/v1/...` тощо), додаючи їх
   до черги обходу.
2. **Candidate Points (Евристика точок атаки)**: функція `CandidatePointsForURL`
   автоматично генерує точки входу для типових безформних API-ендпоінтів:
   - Ендпоінти аутентифікації (`/login`, `/auth`, `/signin`): синтезує параметри `email`, `password`, `username`.
   - Пошук та вибірка (`/search`, `/find`, `/query`): синтезує параметри `q`, `query`, `id`.
   - Ресурси та IDOR/BOLA (`/user`, `/product`, `/basket`, `/feedback`): генерує параметри ідентифікаторів `id`.
   - Скидання паролів (`/reset-password`, `/forgot-password`): синтезує параметри `email`, `answer`, `new`, `repeat`.
   - Платні функції та членство (`/deluxe-membership`): перевіряє параметри `paymentMode`, `UserId`.
3. **Розширені цікаві шляхи (Interesting Paths)**: вбудований перелік дефолтних шляхів
   включає `/api-docs`, `/api-docs/openapi.json`, `/api-docs/swagger.json`, `/v2/api-docs`,
   `/api/v2`, `/b2b/v2`, `/ftp`, `/support/logs`, `/.well-known/security.txt`,
   `/rest/chatbot/respond`, `/rest/user/reset-password`, `/rest/deluxe-membership`,
   `/rest/basket/2`, `/profile`.

---

## Модулі виявлення

Реєстр та порядок виконання модулів визначено у функції `modulesWith` (`engine/pkg/active/scan.go`).
Модулі виконуються за принципом «від найдешевших до ресурсомістких»:

### 1. Endpoint / Passive / Header Readers (читання baseline без зайвих запитів)
- `Exposure`: 13 патернів структурних секретів у тілі відповіді (AWS AKIA, PEM PRIVATE KEY, GitHub токени, Stripe `sk_live_`, Slack, JWT, Google AIza, connection strings, паролі).
- `Misconfig`: некоректні конфігурації CORS (дзеркалення Origin з/без credentials), відсутність захисних заголовків (CSP, X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy), directory listing.
- `CORS`: спеціалізована перевірка правил міждоменного обміну.
- `CSP`: глибокий семантичний аналіз політики Content Security Policy (unsafe-inline, unsafe-eval, слабкі джерела).
- `ResponseHeaders`: перевірка узгодженості та безпеки заголовків відповіді.
- `MixedContent`: виявлення завантаження HTTP-ресурсів на HTTPS-сторінках.
- `PII`: виявлення персональних даних (номери карток, паспорти, e-mail).
- `Cookies`: атрибути безпеки (Secure, HttpOnly, SameSite).
- `SessionFixation`: перевірка оновлення ідентифікатора сесії після авторизації.
- `CSRF`: перевірка наявності анти-CSRF токенів та методів відправки форм.
- `Methods`: аналіз дозволених HTTP-методів (OPTIONS, PUT, DELETE, TRACE).
- `SourceDisclosure`: розкриття вихідного коду через бекапи, тимчасові файли та коментарі.
- `FormSemantics`: семантика форм (передача паролів через GET, відсутність автокомпліту тощо).
- `ScriptIncludeOfAnotherDomain`: підключення сторонніх неперевірених JS-скриптів.
- `CacheableSecurityResponse`: кешування відповідей із чутливими даними.
- `SessionTokenInURL`: передача сесійних токенів у query-параметрах URL.
- `SQLStatementInParameter`: наявність SQL-конструкцій безпосередньо у значеннях параметрів клієнта.
- `DOMSinks`: аналіз клієнтських скриптів на наявність небезпечних приймачів (eval, innerHTML, document.write).
- `JSLibrary`: визначення застарілих та вразливих версій клієнтських бібліотек.
- `SSI`: Server-Side Includes ін'єкції.
- `WebCacheDeception`: обман веб-кешу через шляхові маніпуляції (`/profile/test.css`).
- `CachePoisoning`: отруєння кешу через неключові заголовки (`X-Forwarded-Host`, `X-Original-URL`).
- `GraphQL`: детекція та інтроспекція GraphQL ендпоінтів.
- `OpenAPI`: пошук та валідація публічних специфікацій OpenAPI/Swagger.
- `Smuggling`: базові розбіжності HTTP Request Smuggling (CL.TE / TE.CL).
- `Shellshock`: вектори CVE-2014-6271 у заголовках CGI.
- `HeaderBehavior`: аналіз реакції сервера на нестандартні заголовки.
- `ReDoS`: виявлення катастрофічного бектрекінгу регулярних виразів.
- `TLSCertificate`: перевірка валідності, терміну дії та безпеки сертифікатів.
- `ClientSideDesync`: розсинхронізація HTTP/1.1 з'єднань на боці браузера/клієнта.
- `SMTPInjection`: ін'єкції CRLF у поштові форми та параметри.
- `BackupFiles`: інтелектуальна генерація кандидатів резервних копій на основі шляху сторінки (`.bak`, `~`, `.old`).

### 2. Out-Of-Band (OAST) сімейство
- `OutOfBand`: детекція сліпих уразливостей через реєстрацію OAST-зворотних викликів (DNS/HTTP).
- `outOfBandXML`: OAST вектори через зовнішні сутності XML (XXE).
- `outOfBandCommand`: OAST вектори через команди виклику DNS/curl.
- `outOfBandHeader`: OAST вектори у заголовках запиту.

### 3. Parameter-Level / Injection модулі
- `Redirect`: Open Redirect через 12 векторів (protocol-relative, backslash, `@`, tabs, клієнтські навігатори).
- `SSRF`: Server-Side Request Forgery до 127.0.0.1, localhost, IPv6 [::1], метаданих AWS (`169.254.169.254`) та GCP (`metadata.google.internal`).
- `SQLi`: поглиблена детекція трьома техніками:
  - Error-based: 15 підписів СУБД (PostgreSQL, MySQL, SQLite, MSSQL, Oracle), включаючи розширені маркери SQLite (`sqlite_error`, `sequelizedatabaseerror`, `unrecognized token`, `sql error or missing database`).
  - Breakout-проби: 14 векторів, включаючи специфічні UNION-проби під SQLite/ORM.
  - Boolean differential та UNION injection.
- `XSS`: контекстно-залежний Reflected XSS (HTML-body, attribute, script-string) з ескалацією корисного навантаження.
- `XSSEscape`: аналіз фільтрації спецсимволів (`<`, `>`, `"`, `'`).
- `ClientTemplate`: ін'єкція клієнтських шаблонів (AngularJS, Vue, lodash).
- `LFI`: локальне включення файлів (абсолютні шляхи, traversal, змішані `....//`, Windows `win.ini`, PHP-обгортки).
- `DOMVectors`: виявлення складних DOM XSS зв'язок через джерела (sources) та стоки (sinks).
- `CMDi`: Command Injection через ехо-вирази `echo $((19*23))` = 437 та сліпі затримки `sleep N`.
- `SSTI`: Server-Side Template Injection для Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble.
- `NoSQL`: NoSQL ін'єкції у MongoDB/CouchDB оператори (`$ne`, `$gt`, `$regex`).
- `XPath` & `LDAP`: ін'єкції в XML/каталоги.
- `XXE`: XML External Entity ін'єкції.
- `CodeInjection`: пряме виконання коду в інтерпретаторах (eval, assert, php code).
- `CRLF`: розщеплення HTTP-заголовків (HTTP Response Splitting).
- `JWT`: слабкі підписи, none-алгоритми та маніпуляції з клеймами.
- `FormHijack`: підміна атрибута `action` форми.
- `CSSInjection`: ін'єкція стилів для крадіжки чутливих даних.
- `SerializedObject`: детекція небезпечної десеріалізації Java/PHP/Python.
- `ProtoPollution`: Prototype Pollution у JavaScript/Node.js бекендах (14 проб на злиття об'єктів).
- `URLOverride`: підміна URL через заголовки `X-Rewrite-URL`, `X-Original-URL`.
- `Base64Parameter`: ін'єкції у base64-кодовані параметри.
- `XMLInjection`: порушення структури XML.
- `ReactServerFlight`: перевірка безпеки React Server Components (Flight actions).

### 4. Host-Level та Business Logic модулі
- `fingerprint`: пасивна ідентифікація стеку технологій та серверних банерів.
- `Escaping`: перевірка механізмів екранування символів бекендом.
- `HiddenParams`: підбір прихованих параметрів за словником аналізатора JS.
- `AuthBypassExt`: обхід авторизації через розширення шляхів (`.json`, `/`, `.php`).
- `HiddenPaths`: брутфорс чутливих адміністративних та системних шляхів.
- `ViteFSRead`: виявлення вразливостей читання файлової системи через Vite dev-сервер (`/@fs/`).
- `CrossDomain`: аналіз файлів `crossdomain.xml` та `clientaccesspolicy.xml`.
- `JsonWebKeySet`: аналіз безпеки опублікованих ключів JWKS (`/.well-known/jwks.json`).
- `ASPDotNet`: перевірка специфічних артефактів та конфігурацій ASP.NET (elmah.axd, trace.axd).
- `BusinessLogic`: перевірка багатоетапної бізнес-логіки:
  - BOLA / IDOR на об'єктах користувачів, кошиків та замовлень.
  - Обхід перевірок оплати (payment tampering: зміна цін, кількості, безкоштовні режими).
  - Скидання паролів без знання поточного секрету.
  - Повторне використання одноразових операцій.
- `StoredClass`: верифікація збережених станів (Stored XSS / Stored Injection) шляхом перевірки повторного відображення збережених даних на всіх сторінках цілі.

---

## Рівні знахідки та доказ впливу

| Рівень | Що означає |
|---|---|
| `verified` | Є детермінований fingerprint або успішний другий запит, який підтвердив очікуваний наслідок уразливості. |
| `potential` | Відповідь цілі аномально відрізняється від baseline, але однозначного підтвердження отримати не вдалося. Потребує ручної перевірки. |

### Доказ впливу (Proof of Impact)
Модуль `engine/pkg/active/exploit.go` автоматично генерує верифіковані докази:
- **SQLi**: `UNION SELECT '<canary>',NULL...` з точним числом колонок та перевіркою вилучення маркера.
- **SSTI**: виконання математичного виразу `{{ '<canary>' ~ A*B }}`.
- **CMDi**: виконання команди `; echo <canary>` з виведенням маркера в окремому рядку.
- **LFI**: читання системного файлу `/etc/os-release` через вивірену глибину traversal.

---

## Керування життєвим циклом (Пауза, Продовження, Відновлення)

Сканер підтримує повний набір операцій керування через `engine/pkg/runstate`:
- **Пауза (`pause`)**: негайно призупиняє генерацію запитів, вивільняє з'єднання у пулі та фіксує стан черги.
- **Продовження (`resume`)**: відновлює сканування з точки зупинки без дублювання перевірок.
- **Автоматична зупинка на серії збоїв (`Streak`)**: якщо ціль починає відхиляти запити (20 помилок поспіль), сканер автоматично стає на паузу (`DefaultFailurePause = 20`), сигналізуючи оператору про обрив зв'язку.
- **Перевідправка (`resend`)**: надсилає повторно лише ті запити, які зазнали мережевого збою або таймауту.
- **Збереження прогресу (Checkpoints)**: стан обходу зберігається, усуваючи ризик втрати зібраних знахідок при аварійному закритті вкладки.

---

## Інтерфейс, профілі, параметри та експорт знахідок

### Профілі та параметри Active Scanner (`#scanner-active-*`)
- **Профілі сканування (`#scanner-active-profile`)**:
  - `full` (за замовчуванням) — усі **79 модулів** (`engine/pkg/active/scan.go`);
  - `fast` — 22 базові модулі швидкої перевірки;
  - `api` — 25 API-орієнтованих модулів + увімкнений `MassAssignment`;
  - `llm` — 7 модулів (`exposure`, `misconfig`, `cors`, `response_headers`, `llm_security`, `ssrf`, `out_of_band`);
  - `stealth` — 12 пасивних/мінімально інвазивних модулів.
  - Серед 79 модулів також наявні `ArgumentInjection`, `ErrorDisclosure`, `LLMSecurity`, `MassAssignment`, `FileUpload`, `RateLimit`, `KnownCVEs`.
- **Основні параметри та значення за замовчуванням**:
  - `#scanner-active-max-pages` (`max_pages`): `0` (без обмеження);
  - `#scanner-active-max-depth` (`max_depth`): `2` (`-1` = без обмеження);
  - `#scanner-active-concurrency` (`concurrency`): `8`;
  - `#scanner-active-delay` (`delay_ms`) та `#scanner-active-blind-delay` (`blind_delay_ms`): `0`;
  - `#scanner-active-timeout` (`timeout_ms`): `placeholder="15000"` (`active.DefaultTimeout = 15s`, JS-fallback при порожньому полі — `5000`);
  - `#scanner-active-failure-pause` (`failure_pause`): `placeholder="20"` (`runstate.DefaultFailurePause = 20`, `-1` вимикає);
  - `#scanner-active-recorded` (`recorded_failures`): `placeholder="200"` (`runstate.DefaultRecordedFailures = 200`);
  - прапорці: `#scanner-active-same-origin` (`checked`), `#scanner-active-follow-redirects` (`unchecked`), `#scanner-active-include-corpus` (`checked`);
  - опційні списки `#scanner-active-params` та `#scanner-active-wordlist` (ліміт бекенду `200000` рядків).
- **Налаштування (`⚙️` → `#tool-pane-scanner`)**: `#setting-scanner-profile` (`Safe`, `Standard` [дефолт], `Aggressive`), `#setting-scanner-timeout` (`3–30` с, дефолт `10`).

### Меню експорту (`#scanner-export-active`)
У вкладці Scanner доступне єдине меню експорту `#scanner-export-active` (а також окремий експорт OpenVAS):
1. **`Active Scan` та `All Combined`**:
   - **JSON**: повний сирий звіт знахідок з усіма технічними полями, curl-командами та evidence.
   - **HTML**: інтерактивний звіт у фірмовому темному стилі з фільтрами та копіюванням PoC.
   - **CSV**: таблиця знахідок (один рядок на знахідку).
   - **XML**: структурований XML-звіт (`<scanner_report>`).
   - **Metasploit XML**: `<MetasploitV4>` XML для імпорту в `msfconsole` через `db_import`.
2. **`Corpus Scan`**:
   - Експорт результатів корпусного сканера за **6521** сигнатурними перевірками у форматах **JSON**, **HTML**, **CSV** та **XML** (без `msf-xml`).
3. **`Export OpenVAS ▾`**:
   - Експорт результатів OpenVAS (GVM) у форматах JSON, HTML, CSV, XML та Metasploit XML.

Також забезпечено строгу дедуплікацію знахідок у Live Dashboard за унікальними відбитками (`getFindingFingerprint`), виключаючи появу однакових вразливостей у таблиці.

---

## OpenVAS (GVM) та GMP-автентифікація

У вкладці **Scanner → OpenVAS (GVM)** реалізовано інтеграцію з демоном `gvmd` за протоколом GMP (через Unix-сокет `/run/gvmd/gvmd.sock` або TLS `GVM_HOST:GVM_PORT`):
- **Автоматичне підхоплення облікових даних**: при запуску через `start.sh` скрипт автоматично завантажує `GVM_USER` та `GVM_PASSWORD` з `data/gvm.env` (або змінних оточення) і передає їх у веб-сервер.
- **Облікові дані в інтерфейсі**: у панелі OpenVAS доступні поля `GVM user` (за замовчуванням `admin`) та `GVM password`. Значення зберігаються лише в `sessionStorage` поточної вкладки браузера й передаються виключно в тілі `POST`-запитів (`/api/scanner/openvas/status`, `/api/scanner/openvas/scan`, `/api/scanner/openvas/sync`), без передачі паролів у URL.
- **Діагностика `Check gvmd`**: перевіряє доступність `gvmd` (`<get_version/>`), доступність веб-панелі GVM (`https://127.0.0.1:9392`) та статус GMP-автентифікації (`auth_configured`, `authenticated`, `auth_error`).
- **Запуск і синхронізація**:
  - `Run OpenVAS Scan` створює ціль і задачу в `gvmd`, запускає сканування та опитує прогрес до завершення;
  - `Sync from GVM` підтягує список задач (`POST /api/scanner/openvas/sync` з `action: "list"`) та імпортує результати вибраного або останнього звіту в `ScannerRun(engine="openvas")`;
  - `Import OpenVAS XML` імпортує локальний OpenVAS XML-звіт із захистом від XXE (`DOCTYPE`/`ENTITY`).
  - Якщо `gvmd` відхиляє неавтентифіковану команду (`Only command GET_VERSION is allowed before AUTHENTICATE`), API повертає HTTP `401` (`auth_required: true`), а інтерфейс автоматично фокусує поле пароля GVM.
- **Вибір рушія у полі `Сканер` (`Scanner`)**:
  - Оскільки `gvmd` є менеджером задач і може керувати кількома типами сканерів, у полі `Сканер` обирається конкретний виконавець (без дублів і заглушок після завантаження опцій із `gvmd`):
    - **`OpenVAS Default` (`ospd-openvas`)** — реальний активний мережевий сканер, який перевіряє хости та порти за допомогою NVT-тестів;
    - **`CVE`** — вбудований у стандартний GVM пасивний режим, який **не сканує мережу**, а лише бере вже відомі версії ПЗ з бази активів GVM (Asset Management) і звіряє їх із таблицею CVE.
- **Керування задачами, GSA-параметри та модальні діалоги (`_scanner.html`)**:
  - **Таблиця задач (`#scanner-openvas-tasks-body`)** підтримує кнопки дій: `Start`, `Stop`, `Resume` (для `stopped`/`interrupted`), `Sync` (`/api/scanner/openvas/sync`), `Delete` (`ultimate="0"`) та неактивний стан `Stopping...` (`stop requested`). Додатково наявні `#scanner-openvas-task-select`, `#gvm-refresh-options-btn`, `#gvm-new-port-list-btn`, `#gvm-new-credential-btn`, `#scanner-openvas-panel-link` (`https://127.0.0.1:9392`) і прогрес-бар `#scanner-openvas-progress`.
  - **Секція `GVM Scan Settings` (`#scanner-openvas-settings`)**:
    - *Target & Credentials*: `#gvm-target-name` (`Auto (RR-<target>)`), `#gvm-hosts`, `#gvm-exclude-hosts`, `#gvm-port-list` (дефолт `"All TCP and Nmap top 100 UDP"`), `#gvm-alive-tests` (10 опцій, дефолт `"Consider Alive"`), `#gvm-ssh-cred` / `#gvm-ssh-port` (`22`), `#gvm-smb-cred`, `#gvm-esxi-cred`, `#gvm-snmp-cred`, `#gvm-reverse-lookup-only`, `#gvm-reverse-lookup-unify`.
    - *Task, Scanner & Schedule*: `#gvm-task-name` (`Auto (RR-Scan-<target>)`), `#gvm-scan-config` (`"Full and fast"`), `#gvm-scanner` (`"OpenVAS Default"`), `#gvm-hosts-ordering` (`sequential` | `random` | `reverse`), `#gvm-max-checks` (`4`, `1–100`), `#gvm-max-hosts` (`20`, `1–200`), `#gvm-source-iface`, `#gvm-min-qod` (`70`, `0–100`), `#gvm-schedule`, `#gvm-alert`, `#gvm-auto-delete` (`no` | `keep`), `#gvm-auto-delete-data` (`5`, `1–100`), `#gvm-comment`, `#gvm-start-immediately` (`checked`), `#gvm-add-to-assets` (`checked`), `#gvm-apply-overrides` (`checked`), `#gvm-alterable` (`unchecked`).
  - **Модальні діалоги**: `#gvm-credential-dialog` (типи `up`, `usk`, `snmp`, `pw`) та `#gvm-port-list-dialog` (дефолт `"Custom TCP Ports"`, `"T:21-25,80,443,3000,8000,8080"`). Дефолти підключення в `openvas_client.py`: `/run/gvmd/gvmd.sock`, `127.0.0.1:9390`, `timeout=30.0`, `tls_verify=False`.

---

## Код та реалізація

- [engine/pkg/active/](../engine/pkg/active) — детектори, оркестрація, аналіз точок входу, ланцюжки та докази впливу.
- [engine/pkg/active/detect_business_logic.go](../engine/pkg/active/detect_business_logic.go) — перевірки BOLA, IDOR та бізнес-логіки.
- [engine/pkg/active/points.go](../engine/pkg/active/points.go) — парсинг точок входу та евристика `CandidatePointsForURL`.
- [engine/pkg/active/scan_crawl.go](../engine/pkg/active/scan_crawl.go) — краулер з підтримкою видобутку маршрутів із клієнтського JS.
- [engine/scanner_active.go](../engine/scanner_active.go) — оркестрація завдань сканування, контроль життєвого циклу, SSE-стрімінг.
- [web/lab/openvas_client.py](../web/lab/openvas_client.py) — GMP-клієнт для `gvmd`, парсер OpenVAS XML і діагностика статусу/автентифікації.
- [web/lab/xml_exports.py](../web/lab/xml_exports.py) — генерація та парсинг `<MetasploitV4>` XML, виклик `msfconsole db_import`.
- [web/templates/lab/tabs/_scanner.html](../web/templates/lab/tabs/_scanner.html) — розмітка панелі, OpenVAS (GVM) та кнопок роздільного експорту.
- [web/templates/lab/includes/_active_scanner_logic.html](../web/templates/lab/includes/_active_scanner_logic.html) — клієнтська логіка обробки подій, дедуплікації, OpenVAS GMP та експорту.

---

## Кластеризація, Data-Only YAML та Fixture-Only CI

- **Кластеризація та адаптивний backoff**:
  - `ResponseClusterer` (`engine/pkg/active/cluster.go`) автоматично групує однотипні WAF/помилкові відповіді, а `Transport` (`engine/pkg/active/transport.go`) реагує на `429/503` та заголовок `Retry-After`.
- **Data-only YAML схема (`IsDataOnlyHTTP`)**:
  - Прев'ю шаблонів у Go Scanner позначає чисті HTTP-шаблони полем `data_only: true` (`engine/pkg/scanner/document.go`).
- **Вихідні Webhook-сповіщення (`ScannerRun.upsert_findings`)**:
  - Нові знахідки за порогом `FINDING_WEBHOOK_MIN_SEVERITY` асинхронно відправляються після `transaction.on_commit` (`_notify_finding_webhook` у `web/lab/models.py`).
- **Fixture-only CI та SARIF 2.1.0 валідатор**:
  - Локальний прогін без зовнішніх цілей: `python3 scripts/ci_fixture_runner.py` (перевірка SARIF 2.1.0, `manage.py check` та Go-тестів).

