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
- **Автоматична зупинка на стрику збоїв (`Streak`)**: якщо ціль починає відхиляти запити (20 помилок поспіль), сканер автоматично стає на паузу (`DefaultFailurePause = 20`), сигналізуючи оператору про обрив зв'язку.
- **Перевідправка (`resend`)**: надсилає повторно лише ті запити, які зазнали мережевого збою або таймауту.
- **Збереження прогресу (Checkpoints)**: стан обходу зберігається, усуваючи ризик втрати зібраних знахідок при аварійному закритті вкладки.

---

## Інтерфейс та роздільний експорт знахідок

У вкладці Scanner доступні незалежні контролі експорту:
1. **`Export Active ▾`**:
   - **JSON**: повний сирий звіт знахідок з усіма технічними полями, curl-командами та evidence.
   - **HTML**: інтерактивний звіт у фірмовому темному стилі з фільтрами та копіюванням PoC.
   - **CSV**: таблиця знахідок (один рядок на знахідку).
2. **`Export Corpus ▾`**:
   - Експорт результатів корпусного сканера за 5522 сигнатурними перевірками у форматах JSON, HTML та CSV.

Також забезпечено строгу дедуплікацію знахідок у Live Dashboard за унікальними відбитками (`getFindingFingerprint`), виключаючи появу однакових вразливостей у таблиці.

---

## Код та реалізація

- [engine/pkg/active/](../engine/pkg/active) — детектори, оркестрація, аналіз точок входу, ланцюжки та докази впливу.
- [engine/pkg/active/detect_business_logic.go](../engine/pkg/active/detect_business_logic.go) — перевірки BOLA, IDOR та бізнес-логіки.
- [engine/pkg/active/points.go](../engine/pkg/active/points.go) — парсинг точок входу та евристика `CandidatePointsForURL`.
- [engine/pkg/active/scan_crawl.go](../engine/pkg/active/scan_crawl.go) — краулер з підтримкою видобутку маршрутів із клієнтського JS.
- [engine/scanner_active.go](../engine/scanner_active.go) — оркестрація завдань сканування, контроль життєвого циклу, SSE-стрімінг.
- [web/templates/lab/tabs/_scanner.html](../web/templates/lab/tabs/_scanner.html) — розмітка панелі та кнопок роздільного експорту.
- [web/templates/lab/includes/_active_scanner_logic.html](../web/templates/lab/includes/_active_scanner_logic.html) — клієнтська логіка обробки подій, дедуплікації та експорту.
