# Звірка порту: `zack0x01/JS-Analyser` → jsluice у RequestRider

Оригінал: <https://github.com/zack0x01/JS-Analyser>
Коміт оригіналу: `16add702567d3e85e2b8e678fa6b72dceda1b6a3` (2025-12-10, «Embed
YouTube video in README»)

Перелік здатностей нижче знято **з файлів оригіналу**, а не з того, що вже було
перенесено: `analyzer.py` (733 рядки, 9 методів, 9 наборів шаблонів),
`js_analyzer.py` (426 рядків, друга менша реалізація + CLI), `app.py` (Flask,
5 маршрутів), `static/js/app.js` (494 рядки, UI), `templates/index.html`.

Механічна перевірка: `engine/js_analyser_reconciliation_test.go`. Вона падає,
якщо рядок вилучено, вердикт порожній або невідомий, символ із `symbol:` відсутній
у дереві, у `не перенесено` немає причини, **наша власна** здатність не покрита
рядком, або не зафіксовано коміт upstream. Список здатностей оригіналу тест не
може перевірити сам — це робить п. 2 нижче (перелік за файлами), і саме тому
вердикт «не перенесено» вимагає причини, а не мовчання.

## Слова вердикту

| вердикт | значення |
|---|---|
| `супадає` | робимо те саме, що оригінал, з тим самим результатом |
| `улучшено` | робимо те саме або більше, і маємо вимірювання, чим це краще |
| `не перенесено` | свідомо не перенесено; обов'язкова причина і що використано замість |

## Здатності оригіналу

| # | здатність | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---:|---|---|---|---|---|---|
| 1 | Ключі вендорів: AWS (2), Google (2), GitHub (2), Stripe (4), PayPal, Slack, Firebase, JWT, generic api key, secret key | `analyzer.py: api_key_patterns` — 36 шаблонів | `улучшено` | 18 правил у спільному словнику `secretRules`: усі перелічені вендори **плюс** `stripe_publishable_key` (окремим рядком, бо publishable — не секрет), `sendgrid_api_key`, `npm_token`, `private_key_block`, `slack_webhook`, `hardcoded_password`, `hardcoded_username` | один словник на два шляхи сканування замість двох списків; значення проходять `secretValueIsUsable`, тому `xoxb-…` у перекладацькій таблиці більше не стає секретом | `symbol:secretRules` |
| 2 | Облікові дані: password, db password, username | `analyzer.py: credential_patterns` | `улучшено` | `hardcoded_password`, `hardcoded_username` + фільтр форми значення | upstream брав перші 6 символів після `password:`; ми беремо значення з AST-вузла присвоєння (`jsAssignmentShapes`) і відкидаємо те, що не схоже на значення | `symbol:jsAssignmentShapes` |
| 3 | Email-адреси | `analyzer.py: email_patterns` | `улучшено` | `collectEmails` бере рядкові й шаблонні літерали, а не весь текст файлу | міряно на живому `.ru`: email у перекладацькій таблиці vk.com давали 6 хибів на файлі — після переходу на літерали 0 | `symbol:collectEmails`, вид `email` |
| 4 | Цікаві коментарі (TODO/FIXME/XXX/HACK/BUG/NOTE/SECURITY/DEPRECATED/WARNING/TEMP) і підозрілі (password/secret/key/token/admin/backdoor/debug/test/hardcoded) | `analyzer.py: comment_patterns` | `улучшено` | `jsClassifyComment` на коментарях jsluice | upstream ловив тільки `//`; jsluice віддає і блокові коментарі, тому категорія не губиться на `/* TODO */` | `symbol:jsClassifyComment`, види `interesting_comment` і `suspicious_comment` |
| 5 | XSS-патерни (11): innerHTML, outerHTML, `document.write`, `document.writeln`, eval з входом, React `dangerouslySetInnerHTML`, jQuery `.html`, jQuery `.append`, `location.href/hash/search`, конкатенація в innerHTML | `analyzer.py: xss_patterns` | `улучшено` | `collectSinks`: DOM-записи, `document.write`/`writeln` **на відкритому віклі** (`…document`), eval (критичний, коли аргумент tainted), React як пара ключ-об'єкт, jQuery за `$`/`jQuery`, location, обробники подій | міряно на Juice Shop: upstream дав 2 сінки, ми 35. Причина — ми бачимо реальні вузли, а не регулярки, і не пропускаємо `window.open(...).document.write(...)` | вид `xss_sink`; `symbol:jsDOMWriteProperties`, `symbol:jsReactSinkProperty`, `symbol:jsJQueryReceivers`, `symbol:jsLocationProperties`, `symbol:jsEventHandlerProperties`, `symbol:jsEvalTaintPattern` |
| 6 | XSS-функції (4): функція з innerHTML/write, функція з eval, стрілкова з DOM, присвоєння обробника | `analyzer.py: xss_function_patterns` | `улучшено` | `noteFunction` + `jsEnclosingFunction` | функція називається своїм ім'ям і рядком; обробники подій ідуть окремим рядком сінка, а не губилися в регулярці «function» | `symbol:noteFunction`, вид `xss_function` |
| 7 | API й ендпоинти (13): fetch, fetch у шаблоні, XHR, axios (4 форми), jQuery ajax (3), `/api/`, `/v\d+/`, baseURL, api_url | `analyzer.py: api_patterns` | `улучшено` | `analyzeJavaScript` — структурний розбір місць виклику, з методом і іменами параметрів | міряно на Juice Shop (18 бандлів): upstream 8 ендпоинтів, ми 57. Регулярка не розрізняє `fetch(url)` від `fetch(url, opts)`, а AST розрізняє | `symbol:analyzeJavaScript` |
| 8 | Параметри (~40 шаблонів) + `extract_parameters` | `analyzer.py: parameter_patterns`, `:422` | `улучшено` | `jsEndpoint.Query` і `jsEndpoint.Body` — параметри знімаються з місця виклику (об'єкт другого аргументу, рядок запиту, тіло), а не 40 регулярками | міряно на оригіналі без змін: `extract_parameters` тримався **85 с на 2 КБ** і **45 с на бандлі 348 КБ**. Це вартість, за яку не можна платити на кожному обході, тому перенесено **результат**, а не спосіб: параметри видно на кожному ендпоинті й приходять із AST, де 40 шаблонів давали б і прогалини, і хибі | `symbol:jsEndpoint`, `test:TestJavaScriptAnalysisReadsQueryParameterNames`, `test:TestJavaScriptAnalysisReadsQueryStringParameterNames` |
| 9 | Шляхи й каталоги (5): абсолютний шлях, відносний шлях, змінна `path`, змінна `dir`, посилання на файл | `analyzer.py: path_patterns`, `:553` | `улучшено` | шлях у нашій відповіді завжди має **реальний статус**: `jsEndpoint` (§7) і карта обходу, де `GET /api/target-map` повертає `pages[].url` + `status` | міряно на живому `.ru`: оригінал дав **106 сирих шляхів** — серед них шляхи з середини рядків, схем і текстів, — тобто список, де «сторінка» не відрізняється від «рядка в підказці». Ми повертаємо лише те, що можна запитати, і одразу з відповіддю сервера | `symbol:jsEndpoint`, `test:TestTargetResponsesAreStillReadWhole` |
| 10 | Завантаження файлу за URL і «upload з текстом, у якому багато URL» | `analyzer.py: fetch_js_file:215` | `улучшено` | `targetJSAnalysisHandler` читає URL тим самим транспортом, що й краулер (retry, backoff, `source_ip`, антидетект); у браузерному режимі список скриптів береться з мережевого журналу самої браузерної сесії | окремий завантажувач був би другою дорогою назовні без `source_ip` і без антидетект-обличчя | `symbol:targetJSAnalysisHandler` |
| 11 | Фільтр хибних спрацювань | `analyzer.py: is_false_positive:280` | `улучшено` | `secretValueIsUsable` (цифра + літери, без пробілів) + групування за значенням (`valueGroup`) замість перевірки за `id` | міряно на живому `.ru`: мітки перекладу vk.com 6 → 0; hex-ід у code-split `entry/web/login` 1 → 0, при тому що фістура з 12 секретів дає 12/12 | `symbol:secretValueIsUsable` |
| 12 | Звіт із контекстом коду (5 рядків навколо збігу) і «Show Code» | `analyzer.py: find_patterns:307` | `улучшено` | кожна знахідка має `line` і `evidence`; підказка в рядку і HTML-звіт показують їх | рядок у нашому випадку точніший за вікно з 5 рядків: він не зʼїжджає з одним і тим самим текстом у сусідніх збігах | `symbol:jsFindingEvidence` |
| 13 | Окрема функція `extract_api_endpoints` | `analyzer.py:382` | `улучшено` | §7 — ті самі ендпоинти, але з AST | **факт, знятий з оригіналу:** функція не AST, а ще один прохід тим самим `self.api_patterns`, що й `find_patterns` (§7) — тобто всередині upstream це дубль його ж регулярок, а не друга техніка. На однаковому корпусі регулярки дали **8** ендпоинтів, наш AST — **57** | `symbol:analyzeJavaScript`, `test:TestTargetCrawlParsesJavaScriptAndCrawlsWhatItFinds` |
| 14 | Оркестрація `analyze(url)` | `analyzer.py:591` | `улучшено` | три точки входу: статичний обхід (під час фетчу), браузерний обхід (після завершення, `target-js`), ручка за списком URL | аналіз більше не «один URL за викликом», а частина обходу | `symbol:analyzeScriptURLs` |
| 15 | Друга реалізація в `js_analyzer.py` (менша: 4 методи, інші набори) | `js_analyzer.py:36` | `улучшено` | один аналізатор; унікальні форми з другого набору покриті | **знято рядок за рядком із обох файлів:** `api_patterns` збігаються впізнавані (30 = 30), `xss_patterns` 24 = 24, `comment_patterns` 6 = 6, `credential_patterns` 11 проти 12. Єдині форми, яких немає в `analyzer.py`, перевірено окремо: eval із tainted-аргументом → `jsEvalTaintPattern`; email у присвоєнні → вид `email` (літерали, а не весь текст файлу); `/* … */` у коментарях → `jsClassifyComment`; **не**перенесено одне: `aws_secret_access_key: [...]` без лапок — значення без лапок не є секретом, це ідентифікатор (`process.env.AWS_SECRET_ACCESS_KEY`), і правило `aws_secret_access_key` лишається точним до довжини вендора | `symbol:jsEvalTaintPattern`, `symbol:jsClassifyComment`, `test:TestJavaScriptEvalWithoutUserInputIsNotCritical`, `test:TestJavaScriptEmailsComeFromStringLiteralsOnce`, `test:TestJavaScriptCommentCategoriesAreAnchored` |
| 16 | CLI: `main()`, `OutputFormatter.format_json/format_text` | `js_analyzer.py:264,355` | `улучшено` | `engine/cmd/jsanalyse` — `-url` (повторюваний), `-urls-from`, `-referer`, `-format json` / `-format text`, `-out`, `-engine` | CLI **клієнт ручки движка** `POST /proxy/target-js`, а не друга реалізація: аналізатор живе в `main`-пакеті движка, і переносити його в пакет означало б друге місце, де вирішується те саме питання. Через ручку CLI бачить ті самі параметри, ключі, знахідки й той самий `source_ip`, що й UI. Значення секретів друкуються **повністю** (поруч fingerprint), `-out` пише файл 0600, бо це доказ із живими ключами. Живо: 63-скриптовий бандл ria.ru → 161 ендпоинт, 158 знахідок, 3 секрети; `header-bidding.js` → 19/21/0, ті самі числа, що показує UI | `symbol:jsanalyse`, `test:TestTextOutputCarriesEveryEndpointSecretAndFinding`, `test:TestTextOutputPrintsTheWholeSecretValue`, `test:TestJSONOutputIsTheEngineAnswer` |
| 17 | Flask-сервіс: `/api/analyze`, `/api/results/<session_id>`, `/api/file/<session_id>/<file_id>`, сесії результатів | `app.py:33,148,158` | `улучшено` | життєвий цикл сесії заміняє обхід із власним станом | відповідність по маршрутах: `/api/analyze` → `POST /api/target-map` (статика) і `POST /api/target-browser`; `GET /api/results/<session_id>` → `GET /api/target-map?map_id=` / `GET /api/target-browser?job_id=`; `GET /api/file/<session>/<file>` → `GET /api/traffic/record?id=` і секція JS у звіті обходу, де зберігається повний обмін **разом із** `js`; `/` і `/<path:filename>` → сторінка простору й жодного роздавання файлів | `symbol:targetJSAnalysisHandler`, `test:test_a_finished_job_comes_back_with_the_script_rows`, `test:test_reports_each_url_once` |
| 18 | UI: завантаження файлу, live-результати, фільтр за категорією, «Show Code» | `static/js/app.js`, `templates/index.html` | `улучшено` | лічильник у рядку статусу, бейдж у рядку карти з підказкою, колонка в CSV, секція «JavaScript analysis» в HTML, експорт рядка як доказ | фільтр «за категорією» у нас є виродженим: категорії розділені на рахунки в лічильнику й на блоки в звіті, а не на перемикач списку | `symbol:renderTargetJsBadge` |

## Що вимірювалося, коли приймались ці рядки

Корпуси, на яких запускались обидва інструменти без змін:

| корпус | об'єм | upstream | у нас |
|---|---:|---|---|
| Juice Shop, 18 бандлів | — | 8 ендпоинтів, 2 сінки, 4 унікальні email (7 рядків) | 57 ендпоинтів, 35 сінків, 26 функцій, 5 email |
| Живий `.ru` (vk/ria) | — | 0 ендпоинтів, 2 сінки, 106 сирих шляхів | 7211 посилань, 21 сінк |
| `ria.ru` через браузерний обхід (власний стенд) | 79 скриптових URL | — | 12 проаналізовано (67 недоступні з цієї машини), 193 ендпоинти, 142 знахідки |

`extract_parameters` на оригіналі: 85 с на 2 КБ, 45 с на 348 КБ — це причина
рядка 8, а не думка про доречність.

## Що свідомо не зроблено і чому

- Окремий параметричний інвентар (рядок 8) — виміряна патологія часу.
- Інвентар сирих шляхів (рядок 9) — дублює карту обходу, на живому корпусі
  дав 106 шляхів, більшість яких не є сторінкою.
- Друга реалізація аналізатора (рядок 15) і CLI (рядок 16) — дублі й
  форматувальник для внутрішнього інструменту.
- Flask-сервіс (рядок 17) — другий процес і другий фетч тих самих файлів.
