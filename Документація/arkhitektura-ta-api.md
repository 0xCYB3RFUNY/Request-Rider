<img width="2912" height="1440" alt="Gemini_Generated_Image_s92k5ts92k5ts92k" src="https://github.com/user-attachments/assets/94771d81-1972-418f-ba69-71e64743a44a" />

# RequestRider

RequestRider — локальний інструмент для ручного QA, аналізу HTTP-трафіку та
дозволеного тестування власних систем. Проєкт об’єднує Django UI, Go engine,
PostgreSQL History, passive MITM proxy і явний маршрут Direct або SOCKS5/Tor.

> Використовуйте інструмент лише проти систем, якими ви володієте або на
> тестування яких маєте явний дозвіл. Tor, VPN, Docker і віртуальна машина не
> роблять несанкціоноване тестування дозволеним.

## Зміст

- [Архітектура](#архітектура)
- [Можливості](#можливості)
- [Швидкий локальний запуск](#швидкий-локальний-запуск)
- [Docker Compose](#docker-compose)
- [Маршрутизація через Direct або SOCKS5/Tor](#маршрутизація-через-direct-або-socks5tor)
- [Passive MITM і локальний CA](#passive-mitm-і-локальний-ca)
- [Основний workflow](#основний-workflow)
- [API](#api)
- [Перевірка та діагностика](#перевірка-та-діагностика)
- [Безпека](#безпека)
- [Документація функцій](#документація-функцій)
- [Пов’язані документи](#повязані-документи)

## Актуальний стан проєкту

Реалізовані та перевірені targeted/regression-тестами й живим браузером:

- Projects: створення, редагування, вибір і каскадне видалення пов'язаних
  History, Traffic, Intruder та Target записів;
- session metadata, schema versioning і IndexedDB для великих workspace
  snapshots;
- єдиний Django `EngineClient`, стабільні engine errors і malformed-response
  handling;
- ARIA tabs, accessible prompt/confirm dialogs та keyboard smoke coverage;
- static і browser-driven Target із fixtures, form confirmation, network
  evidence і exports;
- Scanner profiles із read-only checks;
- повна двомовна UI-локалізація Ukrainian/English для статичних, динамічних,
  збережених і відновлених станів усіх вкладок, а також для Project hub,
  дій у рядках, діалогів підтвердження та a11y-підписів. Перемикання мови
  перемальовує кожен view, а не лише активну вкладку, і не робить жодного
  запиту до сервера;
- **активний скан** (`Scanner → Active scan`) — обслідування цілі з перевіркою
  кандидатів уразливостей дев'ятьма модулями виявлення і доказом впливу через
  окремий другий запит. Довідник —
  [aktivnyi-skanner.md](./Документація/aktivnyi-skanner.md).

Перелік виконаних елементів зберігається в [ROADMAP.md](./ROADMAP.md), а
детальні зміни та результати перевірок — у
[DEVELOPMENT_LOG.md](./DEVELOPMENT_LOG.md). Нові завдання виконуються лише
за ітераційним алгоритмом з [AGENTS.md](./AGENTS.md): одне завдання,
повний набір застосовних тестів, browser smoke-test для UI і лише потім
наступний пункт.

## Архітектура

### Локальний режим

```text
Browser :8000
    -> Django web gateway + PostgreSQL History
    -> Go engine :8081
         -> outbound HTTP execution
         -> Intruder / Target / OSINT / Scanner
         -> passive MITM proxy :8080
         -> Direct або SOCKS5/Tor
     -> AI provider transport (окремий cancelable backend socket)
```

### Docker Compose

```text
Browser :8000
    -> web container
         -> engine:8081
              -> tor:9050
              -> passive proxy :8080
         -> postgres:5432
```

`web` відповідає за UI, workspace і browser-facing API та під час старту
застосовує міграції PostgreSQL. `engine` виконує HTTP-операції, Intruder,
Target, OSINT, Scanner і passive capture; AI provider socket залишається
backend-операцією з окремим cancelable transport. `tor` — окремий SOCKS5
upstream у Compose-мережі. Дані PostgreSQL зберігаються у named volume
`postgres_data`; локальний Django також може під’єднатись до цього сервісу через
`127.0.0.1:5432`.

Локальні сервіси за замовчуванням використовують loopback:

```text
127.0.0.1:8000  Django UI
127.0.0.1:8080  passive HTTP MITM proxy
127.0.0.1:8081  Go engine API
127.0.0.1:9050  локальний SOCKS5 Tor
```

Не запускайте локальний і Docker-режим одночасно: вони використовують однакові
порти. У Docker web передає browser-worker `PASSIVE_PROXY_URL=http://engine:8080`,
а локально за замовчуванням використовується `http://127.0.0.1:8080`.

### Структура репозиторію

У корені лежить лише те, що потрібно для роботи застосунку. Обслуговуючі
агента файли (зовнішні тести, fixtures, бібліотека skills) винесені за межі
застосунку, а конфіг OpenCode лишається в корені — саме звідти OpenCode
його читає.

```text
Request-Rider/
├── web/                  Django UI + gateway (Python 3.12, Django 5)
├── engine/               Go engine, passive proxy, Intruder/Target/Scanner
├── browser-worker/       Python + Playwright headless Firefox worker
├── data/                 локальний CA, логи, OSINT-експорти (gitignored)
├── tor/                  SOCKS5-контейнер
├── bin/                  runtime-бінарники, зокрема nuclei (gitignored)
├── contracts/            версіоновані envelope брокера (engine-task/result-v1.json)
├── screenshots/          знімки екрана для посібника користувача
├── Документація/         довідники окремих інструментів
├── .opencode/            OpenCode: встановлені skills + skills-assets
├── opencode.json         OpenCode permission.skill
├── AGENTS.md             правила роботи агента в цьому репозиторії
├── SESSION-CLAIMS.md     реєстр сесій: хто який файл тримає (за AGENTS.md)
├── start.sh              єдиний вхід: перевіряє, встановлює, піднімає весь стек
├── run-engine.sh         ручний запуск без підготовки середовища
├── docker-compose.yml    робочий Compose-стенд
├── README.md, ROADMAP.md, DEVELOPMENT_LOG.md, SECURITY.md
└── */Dockerfile, .gitignore
```

У корені лежить те, що потрібно для роботи застосунку, плюс метафайли
агентської дисципліни (`AGENTS.md`, `SESSION-CLAIMS.md`) та матеріали
посібника (`screenshots/`).

## Можливості

- **Repeater** — raw HTTP editor, повторне надсилання, перегляд відповіді,
  збереження exchange у History.
- **Intruder** — Sniper, Battering Ram, Pitchfork, Cluster Bomb, dictionaries,
  transformations, parallel workers, pause/resume/cancel, polling,
  JSON/CSV export і review summary перед запуском із target, route,
  delay/concurrency та оцінкою jobs. Великі словники редагуються у textarea
  без inline preview, щоб не розтягувати панель.
- **Target** — асинхронна статична карта сайту та окремий browser-driven режим
  із вибором Firefox, Chromium, Chrome, Edge або WebKit для JS-rendered маршрутів
  і network evidence; обидва режими мають
  pages/depth/delay, same-origin, cancel і JSON/CSV/HTML export. Browser-driven
  режим передається через локальний generation-aware passive proxy, тому browser
  exchanges мають той самий Direct/SOCKS5/Tor route і `source_ip`, що й Repeater.
  Browser worker повторно використовує process-level Playwright/browser runtime;
  кожен job має окремий context, який закривається після завершення або cancel.
  Його network
  evidence можна відфільтрувати за API/XHR/fetch, документами, скриптами або
  іншими ресурсами та передати endpoint у Repeater, Intruder чи Scanner.
  Для SPA можна додати послідовність `click`/`fill` actions за CSS-селекторами,
  а `Compare static/browser` показує URL, які знайдені лише одним із режимів.
  Navigation mode виконує лише read-only навігацію. Form mode вимагає
  щонайменше одну `click` або `fill` action і окреме підтвердження перед
  запуском, оскільки такі дії можуть змінювати стан цілі. Для повторюваних
  локальних перевірок доступний fixture-сервер:
  `fixture-сервер` браузерного воркера.
  Browser crawl використовує паралельні вкладки, не додає
  штучної затримки за замовчуванням і блокує image/font/media ресурси; `Delay
  ms` можна збільшити вручну для обережнішого темпу.

Target не використовує `robots.txt` як обмеження доступу: `Allow`/`Disallow`
є рекомендаціями для пошукових роботів, а не механізмом авторизації. Static
crawler читає з `robots.txt` лише `Sitemap:`-посилання; browser-driven режим
не застосовує robots directives. Використовуйте це лише для дозволених цілей.
- **OSINT** — DNS/IP, MX/NS/TXT, HTTP metadata, redirects, technologies,
  cookies, security headers, robots/sitemap і пасивні WAF-сигнали; окремий
  Entity Graph canvas показує durable entities/relations,
  details drawer, filters, deterministic layout і explicit transforms.
  Проєкт для роботи з графом **не потрібен**: якщо його не вибрано, граф живе
  у scope без проєкту, а список показує саме цей scope.
  Зовнішні джерела не обвалюють transform: `subdomains` опитує **п'ять
  паралельних індексів Certificate Transparency** (crt.sh, crt.name,
  certspotter, shodan-ctl, ctlogs.dev) і зливає їхні відповіді, тому недоступність
  crt.sh не зупиняє розвідку, а `wayback_urls` читає **два незалежні хости**:
  два індекси Internet Archive (CDX → timemap) і потім публічні колекції
  Common Crawl. Кілька індексів за одним hostname ділять ліміт цього hostname,
  а `web.archive.org` відповідає `429` кожному клієнту з однієї адреси виходу —
  саме тому другий хост потрібен, а не просто другий шлях. `429` читається як
  прохання повернутися: інтерес називає очікування в `Retry-After`, і воно
  визначає паузу (обмежену 20 с, щоб зайнятий індекс не робив transform
  «завислим»); пауза є звичайним checkpoint-ом, тож Pause/Cancel і зміна route
  переривають її. Обрив з'єднання або таймаут handshake повторюються як стан
  мережі, а свідома відмова (`403`/`404`/`401`/`410`) — ні. Архівні відповіді
  читаються потоково, зберігаючи вже прочитані рядки, якщо архів обриває
  відповідь; порожня колекція не вважається відповіддю, тож ланцюг іде далі,
  а кожен пройдений мимо індекс називається у warnings поруч із тим, хто
  відповів. Частковий результат позначається явно — у warnings і в
  metadata (`cert_indexes`, `archive_*`). Опціональні ключі до індексів
  (`CERTSPOTTER_API_TOKEN`, `CTLOGS_API_KEY`) читаються лише з оточення.
  **Керована конкурентність — явне поле, а не прихований cap.** Фази, що
  розбивають роботу на багато однакових запитів, мають пул робітників, і
  оператор керує його розміром одним полем `Concurrency` у діалозі transform
  (ключ `concurrency`; `dns_concurrency` приймається далі для збережених
  конфігурацій). Сьогодні це дві фази: DNS brute-force у `subdomains` і перевірка
  кандидатів у `s3_buckets`. Поле показується **за реєстром engine**
  (`GET /api/osint/transforms` → `concurrency`, `concurrency_default`), а не за
  списком імен у діалозі, тому наступна фаза з пулом отримає контроль
  автоматично, і жодна не отримає поле, яке нічого не робить. Межа не зменшує
  можливостей: пул обмежує, скільки запитів одночасно, і **нікогда** скільки їх
  буде; застосоване значення повертається в `metadata.concurrency` /
  `dns_concurrency`, тож реальне число видно, а не випливає з припущень. Порядок
  результату не залежить від порядку завершення, тому два прогони одного
  словника дають однакові рядки. Ланцюги, де порядок проходження є частиною
  відповіді, пулу не мають свідомо: для `wayback_urls` «який індекс відповів
  першим, а які пройшли мимо» є змістом результату, а не деталлюю.
  **Межі з'єднання — явні, задокументовані й видимі.** `engine/http_bounds.go`
  тримає чотири стадії, на яких з'єднання може зависнути без прогресу: dial
  (30 с), TLS handshake (15 с), response header (60 с), idle connection (90 с).
  Кожна перекривається з оточення — `RR_DIAL_TIMEOUT_MS`,
  `RR_TLS_HANDSHAKE_TIMEOUT_MS`, `RR_RESPONSE_HEADER_TIMEOUT_MS`,
  `RR_IDLE_CONN_TIMEOUT_MS` — і **жодна не має верхнього cap**: оператор, чия
  ціль повільна, піднімає межу явно. Межі застосовуються до кожного транспорту
  engine (генераційний, shared/passive, ephemeral) через один шлях, тому новий
  транспорт не може про них забути. Діалер має і `keepalive`, бо помічає
  з'єднання, померле мовчки, — той випадок, коли header-deadline не має чого
  чекати. Значення, що реально задіяні, **`GET /health` повертає разом з `ok`**:
  межа, яку можна знайти лише в коді, — це межа, з якою ніхто не може нічого
  зробити. Нечитабеве або нульове значення змінної падає на задокументований
  default, а не мовчки знімає межу.
  **Різниця між доказом і службою.** Відповідь цілі (Repeater, Intruder,
  Repeater Burst, Last-Byte Sync) читається **повністю завжди** — обрізаний обмін
  це втрачена знахідка. Відповідь, яку engine читає для власного обліку (зовнішній
  IP, JSON OAST-провайдера, публічний профіль), обмежена `readControlPlaneBody`:
  1 MiB за замовчуванням, `RR_CONTROL_PLANE_BODY_LIMIT_BYTES`. Перевищення — це
  помилка з назвою ліміту, а не тихий обріз, бо обрізаний JSON падає з парсингу з
  причиною, не пов'язаною з реальною проблемою.
  **Завершені job-и звільняються.** `attacks`, `targetMaps`, `oastListeners`,
  `bursts` і `lastByteJobs` раніше ніколи не видалялися, тож довша сесія
  накопичувала кожну атаку, обхід, burst і listener разом із результатами. Тепер
  один sweeper на процес (не таймер на job — це той самий ріст у іншій формі)
  звільняє завершені job-и через **60 хвилин** за замовчуванням,
  `RR_FINISHED_JOB_RETENTION_MINUTES`, без верхнього cap. Вікно навмисно велике:
  UI відновлює polling після reload, тож надто раннє звільнення виглядало б як
  втрачений запуск. Job у нетермінальному стані не звільняється ніколи, і
  звільнення attack закриває його spill-файл.
  Помилка трансформації не викидає вже зібране: `400`-відповідь несе
  `warnings`, `entities`, `relations`, `metadata` і `source_ip` поруч із
  `error`/`reason`.
  Архівні URL канонізуються: credentials, fragments, default ports і
  traversal-шляхи не стають ідентифікаторами графа. Transform виконується як
  **background-job** з кнопками **Pause / Continue / Cancel** і живими
  лічильниками прогресу; результат понад 2000 рядків записується **повністю**
  у CSV/JSONL файл, який відкривається в новій вкладці або завантажується, а
  граф зберігає одну entity-вказівку — жоден рядок не відкидається.

  **Сторінка результату.** `GET /api/osint/graphs/<id>/files/<name>` віддає
  **переглядач**, а не сирий текст: лічильники реальних рядків, пошук у всіх
  колонках одразу, чіпи типів з реальними кількостями, сортування колонок,
  серверна пагінація (50/100/200/500/1000 рядків) і лічильник
  `1–200 of 19 171`. Сторінка — flex-колонка на `100%` висоти, тому таблиця
  забирає весь простір вікна і **сторінка не прокручується**: на висоті
  вікна 700px видно 16 рядків без прокручування, на 900px — усі 96 сторінок
  лишаються доступними. Колонка, порожня в усьому файлі, прибирається, а
  факт прибирання **показується** сторінкою. Розмір сторінки — це вікно у
  повний файл, а не обрізання: кожен рядок лишається доступним через пошук,
  чіпи типів, сирий текст (`?raw=1`) і завантаження (`?download=1`).
  `GET .../files/` — каталог файлів цього графа; обидві форми URL
  (`/files` і `/files/`) ведуть на нього, а не в 404.
  Обидві сторінки **рендеряться на сервері тією мовою, якою говорить
  воркспейс**: застосунок дублює свій вибір у cookie `requestrider-language`,
  а звіт читає її й ніколи `Accept-Language`. Перемикач на звіті — посилання
  `?lang=<інша>`, на яке сервер віддає `303`, записує cookie і повертає на ту
  саму URL без `lang`, тож змінюється вся сторінка, фільтри не губляться, а
  JavaScript звіту не потрібен — на ньому взагалі немає `<script>`.
  Мітка виду рядка `link` — `зв’язок` в UA, тоді як значення фільтра лишається
  `?type=link`, щоб збережене посилання працювало в обох мовах. Дані, а не
  слова сторінки (назви колонок, типи сутностей і зв'язків, `provenance`,
  імена файлів і графів), однакові в обох мовах задумово. Правило й
  перевірки — у `AGENTS.md`, розділ «Ключові домовленості».

  **Хост, а не зона.** CT-індекси індексовані за зоною: запит
  `crt.name?apex=www.lafann.ru` повертає `400 not an apex`, а індекси, які
  запит приймають, відповідають самим хостом. Тому `subdomains` на
  subdomain-вході будує ланцюг зон (`www.lafann.ru` → `lafann.ru`), запитує
  кожну власним запитом і зупиняється на першій, що дала нові імена; публічний
  суфікс запитом не йде. Підміна **проголошується**: імена стають `subdomain`
  саме цієї зони, зона й запитаний хост лишаються окремими `domain`-сутностями,
  а `warnings` і `metadata.cert_zone` / `cert_input` / `cert_zones_queried`
  показують, що саме запитано (в UI — чіп `zone: <host>`). Відмова індексу
  (`4xx`) не повторюється, на відміну від тимчасового `5xx`/`429`.

  **Керування існуючими entities.** Обраний entity (клік по вузлу) або relation
  (клік по ребру) відкриває drawer з деталями та діями: `Edit`, `Delete entity`,
  `Run transform on this value`, `Copy value`, `Use in OSINT checks`, а для
  relation — `Delete relation` і перехід до його endpoint entities. Ті самі дії
  `Edit` / `Delete entity` доступні з контекстного меню (ПКМ по вузлу).
  Кнопка `Clear graph` очищає entities і relations поточного графа після
  підтвердження, і контейнер графа лишається — новий entity можна додати
  одразу після очищення. Усі операції CSRF-protected і суворо scoped до
  власного `graph_id`: entity чи relation з іншого графа дає `404`.

  **Export graph HTML.** `Export graph HTML` зберігає самодостатній звіт без
  CDN і будь-яких зовнішніх ресурсів. Звіт відтворює ті самі правила графа, що
  й застосунок: `.osint-graph-edge-hit` — прозорий corridor, а не заливка за
  замовчуванням, інакше кожен зв'язок малювався чорною смугою поверх лінії та
  перехоплював показові події вузла.

  Плашка вузла має ширину 220 одиниць під мітку, а крок колонок — 230,
  тому corridor, що виходить із вузла вбік, лежить під цією плашкою. Щоб
  обидва об'єкти лишалися доступними, натиск розводиться з координат у
  фіксованому порядку: **коло вузла → entity**, **corridor поза колом →
  relation**, **плашка без corridor поверх → entity**, інакше — панорама.
  Corridor обрізається за радіусом кола, тож навіть у щільній розкладці
  він лишається клікабельним.

  Звіт має власний інтерактивний шар: пан (`pointerdown` + drag), зум колесом
  миші навколо курсора, кнопки `−` / `+` з відсотком, `Fit` (забудовує вид під
  розмір сцени), перетягування вузла разом із його зв'язками, клік і
  `Enter`/`Space` для entity та relation, фільтр, який ховає зв'язок разом із
  прихованим endpoint, і `Download JSON`. Перетягування ділить на масштаб
  `getScreenCTM()`, тому вузл іде за курсором за будь-якого зуму. Усі значення
  екрануються через `escapeText`, а `properties` і `provenance` показуються
  замість порожнього `metadata`.

  **Статус transform.** Кожен запуск показує явний стан замість порожнього
  результату: `running` (з таймером, що відлічує секунди), `completed`,
  `empty` (transform завершився, але нічого не знайшов) або `failed` (з
  текстом помилки движка). Панель показує `local only` / `network`, тривалість у
  мс і список warnings. `transform_result.status`, `stored_entity_count`,
  `stored_relation_count`, `rejected_count`, `rejected[]` і `duration_ms`
  приходять у відповіді API.

  **Часткові результати.** Зовнішні адаптери legitимно повертають identities,
  які граф не може зберігти (наприклад certificate wildcard `*.*.example.com`
  або label з підкресленням `_dmarc.example.com`). Під час ingestion transform
  такі рядки **відкидаються поодинці** і перелічуються в `rejected` та warnings,
  а не знищують весь batch: `subdomains` для великого домену міг знайти 1308
  entities і втратити всі через одну wildcard-identity. Ручний
  `/api/osint/graphs/<id>/upsert` лишається атомарним, щоб помилка введення
  залишалася явною.
- **Scanner Pro** — read-only перевірки CMS/public paths, TLS,
  cookies, methods, headers і configuration exposure signals. Завантажені
  Nuclei-шаблони виконуються справжнім бінарником, а
  звіт показує **результат по кожному YAML-файлу**: назва файлу, template id,
  CVE/CWE, статус і причину для кожного файлу, який не дав результату
  перевірки цілі. Статусів рівно дев'ять: `matched`, `not_matched`,
  `no_request`, `skipped`, `invalid`, `duplicate`, `workflow`, `flow` і
  `uncompiled`. Останні три названо окремо саме тому, що жоден із них не є
  `skipped`: `workflow` — оркестратор, який виконав свої підшаблони, але не є
  matcher'ом сам; `flow` — документ із top-level `flow:`, який бінарник у цьому
  запуску не скомпілював; `uncompiled` — файл із зарезервованим тегом `fuzz`,
  який бінарник відкидає замість виконання (на офіційному корпусі таких 37).
  **Покриття шаблонів.** Спершу набір **дедуплікується за вмістом** (SHA-256),
  а не за назвою: на реальній збірці з 734 748 файлів лише 382 396 унікальних,
  тобто 564 857 файлів (77 %) — побайтові копії; копія отримує власний рядок зі
  статусом `duplicate`, а не зникає. Далі `nuclei -validate` питає в самого
  бінарника, які документи він відмовився вантажити, і причина відмови на файлі
  цитується дослівно замість власного здогадки. Список блоків документа взятий
  з власного парсера nuclei (`templates.Template`), тому `http`, `requests`
  (legacy-синонім), `dns`, `ssl`, `websocket`, `whois`, `tcp` (нинішня назва
  `network`), `headless`, `code`, `file`, `javascript`, `fuzzing`, `workflows`,
  `jarm`, `asn`, `port` і `multi` усі реально виконуються. Прапорці, яких
  вимагає документ (`-code`, `-file`, `-headless`, `-egm`, `-esc`), додаються
  автоматично; `-dast` виконується в окремому виклику, бо він скасовує виклик
  без fuzzing-шаблонів; `-pt` не додається ніколи, бо він **замінює** весь
  набір типів. Нарешті набір **розкладається на стільки викликів, скільки
  потрібно**, щоб у кожному було не більше одного файлу на template-id:
  бінарник завантажує рівно один файл на id, тому без цього кожен наступний
  файл із тим самим id зникав мовчки. Рядок плану над командою показує число
  викликів, причину розкладання, кількість згорнутих копій і кількість
  відмовлених документів. Одне вікно завантаження приймає файли або цілу папку
  (drag & drop з обходом каталогів), великі папки йдуть чанками, панель
  `Scan options` замінює інтерактивні прапорці nuclei.
  Вкладка має **три** внутрішні сторінки — **CMS scan**, **Nuclei scan** і
  **Active scan** — з окремим результатом, окремим станом і окремим експортом
  на кожну. Експорт — меню `Export ▾` з форматами
  JSON / HTML / CSV і **інтерактивним HTML-звітом у фірмовому стилі** (живий
  пошук, фільтри статусу, сортування; самодостатний, без зовнішніх ресурсів).
  **Активний скан** (`Active scan`) обходить ціль, перевіряє кандидатів
  дев'ятьма модулями — `exposure`, `misconfig`, `redirect`, `ssrf`, `sqli`,
  `xss`, `lfi`, `cmdi`, `ssti` — і будує ланцюжки з семи правил. Знахідка
  отримує рівень `verified` або `potential` і, коли модуль це дозволяє,
  доказ впливу: окремий другий запит, який має спрацювати, щоб оператор
  побачив не реакцію, а наслідок. Повний довідник —
  [aktivnyi-skanner.md](./Документація/aktivnyi-skanner.md). У активного скану
  є лише `cancel`: паузи немає свідомо, і API повертає `400` на невідомий
  action, а не вигадує стан.
- **Comparer** — Words і Bytes.
- **Decoder** — URL, Base64, Base64 URL-safe, HTML, Hex, byte, JSON і SHA-256.
- **Traffic** — live SSE-потік passive proxy, Repeater і Intruder.
- **History** — записи PostgreSQL для завершених exchange, tags/notes,
  export/import.
- **AI** — аналіз лише явно прикріплених оператором evidence; автономного
  виконання дій немає.
- **Automation** — візуальний редактор workflow із canvas, вузлами Repeater,
  Target, OSINT, Scanner, Intruder, Decoder, Comparer, AI, умовами, розкладом і
  webhook-тригерами; workflow зберігається у PostgreSQL разом із Project.
  Локальний runtime лишається стандартним. `WORKFLOW_CELERY_ENABLED=1`
  передає WorkflowRun у Celery task worker; граф, input/output checkpoints,
  pause/cancel state і node events зберігаються в PostgreSQL, а SSE читає
  persisted events і працює між web/worker процесами. Scheduler і webhook
  activation ще не є distributed/HA. Redis, Celery publisher,
  Go task consumer і Django result persistence мають
  реалізацію; broker dispatch доступний для Repeater і static Target
  workflow nodes за явним feature flag. Локальний executor відновлює DAG з
  node checkpoints після web restart; Celery worker підтримує окремий run
  execution. Живий lifecycle брокера перевірено end-to-end
  (success, redelivery без повторної дії, error, restart recovery, cancel,
  malformed dead-letter);
  idempotency зовнішніх side effects переживає рестарт engine, бо outcome
  зберігається в broker. Distributed scheduler і multi-main HA не реалізовані. Active URL-вузли
  використовують URL, переданий оператором, а Intruder і browser actions вимагають
  explicit confirmation; `Repeater Burst` додатково є manual-only і не може
  входити до schedule/webhook graph.
  У вкладках інструментів доступна кнопка `Send to Automation`: вона читає
  поточний workspace, додає або оновлює відповідний типовий вузол, зберігає
  workflow і перемикає на Automation. В inspector можна також використати
  `Use current workspace`, відкрити вузол у відповідному інструменті та
  редагувати типові поля (Repeater method/URL/headers/body, Target parameters,
  Intruder mode/dictionaries/transformations, Decoder/Comparer operations тощо).
  API-каталог `/api/workflows/node-types` повертає ці поля разом із defaults,
  тому canvas не залежить від окремого списку параметрів. У toolbar Automation
  кожний збережений граф має `graph_schema_version` (поточний формат — `1`);
  поле окреме від `version`, що рахує редакції workflow. Старі записи й імпорти
  без цього поля трактуються як схема `1`, а невідома версія відхиляється
  явною помилкою замість некоректної інтерпретації графа.
  Кожен WorkflowRun також зберігає окремий checkpoint для кожного вузла:
  незмінний snapshot graph/version, вхід, вихід, стан і timestamps
  експортуються в project bundle. Старі записи отримують graph snapshot під
  час міграції, тому подальше редагування workflow не змінює граф уже
  запущеного run. Виконані
  вузли можуть відновити свій output без повторного виклику інструмента;
  невизначений `running`/`failed` checkpoint не повторюється автоматично,
  оскільки зовнішня дія могла відбутися до втрати відповіді. Queued/running
  DAG після restart продовжується лише між завершеними вузлами; paused runs
  і незавершені checkpoints переходять у `interrupted` для ручної перевірки.
  Project import також перетворює незавершені runs на `interrupted`, щоб
  перенесений bundle не запускав зовнішні дії автоматично.
  Брокерний вузол більше не тримає Django-потік: він публікує durable
  `EngineTask` із кореляцією, переводить `WorkflowRun` у стан `waiting` і
  звільняє worker. Результат движка застосовує `consume_engine_results`, який
  перезапускає DAG із checkpoint — повторна доставка результату не запускає
  наступний вузол удруге. Вузол, що публікує кілька задач (Repeater зі
  списком запитів), зберігає отримані результати й `task_id` у власному
  checkpoint і продовжується з того запиту, який був у польоті; пауза
  зупиняє граф, а не зовнішню дію, і відповідь зберігається до `Resume`.
  Route drain скасовує і `waiting`-запуски, надсилаючи `engine.task.cancel`
  їхньому активному завданню. Станом `waiting` керує лише результат
  відповідної задачі, тому restart не повторює зовнішню дію.
   доступний `Template Store`: локальний каталог `/api/workflow-templates` із
   категоріями, preview, required variables та import у новий canvas. Import
   сам по собі не створює активний job і не запускає граф; workflow зберігається
   лише після окремого `Save`. `Save as template` зберігає лише граф і
   metadata у browser-local catalog, не змішуючи їх із workflow snapshot.
   Template Store також містить baseline-пакет із read-only reconnaissance,
   API headers, schema endpoint discovery, asset inventory та advisory AI
   triage playbooks, а також manual-only high-risk canary templates для
   BOLA/IDOR differential, race timing, WAF rules, synthetic JWT claims,
   XXE → local OAST та read-only CI/CD exposure review. Це не реальні
   credential/authorization attacks: payloads, tokens і callbacks можуть
   бути лише local fixture canary, а кожен active template має explicit
   confirmation перед запуском.
   Automation також має окремий `Repeater Burst` для manual, parallel
   review: Django передає user-controlled iterations/concurrency/delay/timeout,
   Go виконує job із cancellation, TLS verification та History persistence.
   Burst заборонений у schedule/webhook graphs і не є raw Last-Byte sync.
   `Last-Byte Sync` — окремий manual-only raw HTTP/1.1 POST/PUT/PATCH job:
   Go надсилає всі bytes крім фінального, утримує останній byte за явним
   hold, перевіряє TLS certificate chain і не використовує redirects або
   automatic retries.
   Automation також має `OAST Listener` → payload URL → `OAST Collect`
   contract; provider endpoint і timeout задаються користувачем.
   `timeout_sec` вузла — це скільки оператор чекає на callback, і воно не
   скорочується жодною внутрішньою межею. Натомість кожен **окремий виклик**
   провайдера має власний явний deadline, щоб провайдер, який прийняв з'єднання
   і не відповідає, не тримав run у стані `running`: `RR_OAST_REQUEST_TIMEOUT_MS`
   (engine, 15 с), `RR_OAST_GATEWAY_TIMEOUT_MS` (Django, 20 с) і
   `RR_SOURCE_IP_LOOKUP_TIMEOUT_MS` (engine, 5 с) перекривають ці межі.
   Нечитабеве або нульове значення повертає задокументований default, а не
   мовчки вбирає межу.
- **Workspace** — окремі вкладки інструментів, autosave і session JSON.
- **Спільна таблиця** — History, Traffic та Intruder заповнюють свою секцію, а
  роздільник над таблицею має рівно два напрямки: підтягування вверх купує
  більше рядків (сторінка скролиться), підтягування вниз повертає таблицю на
  початкове місце без діри внизу секції. За замовчуванням drag не може зробити
  таблицю меншою за виділений їй простір. Перетягнувши вище хедера, таблиця
  розкривається на весь екран, перекриваючи навігацію; `Enter`, стрілки та
  `Escape` доступні з клавіатури, а `Escape` повертає таблицю на її попередню
  висоту. Поведінка однакова на History, Traffic, Target та Intruder.
- **Target — виняток із заповнення** — його workspace містить усю форму обходу
  (731 px контролів), тому він лишається на своїй висоті (`flex:0 0 auto`), а
  таблиця результатів має власну стелю `48vh` з мінімумом 300 px. Стиснутий
  workspace обрізав би форму і зробив `Build map` ненатисненою: панель показує
  все донизу, і сторінка скролиться до форми. Вікно карти (`.target-preview`)
  розтягнуте на всю висоту секції поруч із формою, а довге дерево скролиться
  всередині карти, а не розтягує секцію.
- **Рядки стану обмежені** — помилка engine чи browser-worker приходить одним
  багаторядковим рядком, тому `.status`, `.toast` і `pre` мають стелю висоти,
  перенос довгих слів і власний скрол. Повідомлення лишається читабельним
  повністю, але не перетворює сторінку на 27 000 px.
- **Мова** — перемикач Ukrainian/English у хедері перемальовує всі view
  одразу, а не лише активну вкладку, і не робить запитів до сервера. Дані з
  сервера, власні імена інструментів (`Repeater`, `OAST Listener`, `Sniper`),
  абревіатури та значення, що йдуть на бекенд, лишаються без перекладу.

Scanner та інші активні інструменти не замінюють дозвіл на тестування і не
призначені для реального exploit, brute force, fuzzing або access-control bypass.
High-risk Automation templates — це лише local/synthetic canary
scenarios з explicit confirmation; вони не містять реальних credentials,
external OAST providers або автоматичного destructive action.

## Швидкий локальний запуск

### Єдиний вхід: `./start.sh`

```bash
./start.sh
```

`start.sh` — це весь цикл застосунку в одному файлі: він перевіряє кожну
залежність, **встановлює відсутню**, піднімає весь стек і віддає керування
терміналу. Кожен крок спершу перевіряє, чи вже готово, і лише тоді встановлює,
тому повторний запуск нічого не перевстановлює.

```bash
./start.sh            # встановити чого бракує, підняти весь стек
./start.sh --check    # те саме + блок «Команды проверки» (go test -race, Django tests, node --check)
./start.sh --status   # нічого не встановлювати, лише показати стан сервісів
```

Що робить послідовно:

| Крок | Що перевіряє і що ставить |
|---|---|
| 1 | системні пакети: `curl`, `git`, `golang-go`, `nodejs`, `npm`, `postgresql-client`, `redis-tools`, `redis-server`, `tor`, `python3-venv` |
| 2 | `go mod download` — модулі движка качаються до старту, а не під час першого запиту |
| 3 | `web/.venv` + `web/requirements.txt` (Django, psycopg, celery, redis) |
| 4 | `browser-worker/.venv` + `playwright` |
| 5 | рушій Playwright Firefox — перевіряється **бінарник**, а не імпорт пакета |
| 6 | nuclei: `RR_NUCLEI_BINARY` → `bin/nuclei` → системний → збірка закріпленої версії |
| 7 | кластер PostgreSQL у `data/pg` на `127.0.0.1:55433` + база `requestrider` |
| 8 | Redis на `127.0.0.1:6379` з AOF |
| 9 | Tor — **лише** якщо рух справді через нього (`RR_ROUTE_VIA_TOR=1`) |
| 10 | Go engine на `:8081` і passive proxy на `:8080` |
| 11 | browser-worker на `:8090` |
| 12 | `manage.py migrate` |
| 13 | Celery worker і `manage.py consume_engine_results` — **лише** якщо увімкнено брокерний шлях |
| 14 | Django `runserver` на `:8000` — лишається на передньому плані |

Типовим є **процесний** runtime workflow, як і в `run-engine.sh`, тому
`WORKFLOW_CELERY_ENABLED` і `WORKFLOW_ENGINE_BROKER_ENABLED` за замовчуванням
`0`, а Celery і споживач результатів не піднімаються: без брокерного шляху
немає задач, які вони споживали б. Щоб увімкнути брокерний шлях:

```bash
WORKFLOW_CELERY_ENABLED=1 WORKFLOW_ENGINE_BROKER_ENABLED=1 ./start.sh
```

Кожна змінна з оточення має пріоритет (`RUNSERVER_PORT`, `ENGINE_PORT`,
`PROXY_PORT`, `WORKER_PORT`, `POSTGRES_PORT`, `REDIS_PORT`, `SOCKS_PORT`,
`POSTGRES_HOST`, `POSTGRES_USER`, `POSTGRES_DB`), тому скрипт працює на
сусідньому стенді, не ламаючи його. Журнали сервісів — у `data/logs/`,
один файл на процес; перевірки `--check` — там само, з префіксом `check-`.

`Ctrl+C` зупиняє engine, browser-worker, Celery, споживач результатів і web.
Те, що вже працювало до запуску скрипта, не зупиняється.

Пароль root потрібен лише коли справді бракує системного пакета. У
неінтерактивному середовищі (CI, cron) скрипт не падає на `sudo`, а друкує
точну команду для ручного встановлення.

### Ручний запуск (коли скрипт не підходить)

`run-engine.sh` лишається тим самим, чим був: він **не** встановлює системні
пакети, не піднімає Redis, Celery і споживач результатів, і не готує
PostgreSQL. `start.sh` не замінює його контракт, а додає поверх нього кроки
підготовки середовища.

Для локального запуску потрібні Go, Python 3, `curl`, `venv` або `virtualenv`
та доступний локальний PostgreSQL. PostgreSQL є єдиною базою даних застосунку.

`web/core/settings.py` вимагає `POSTGRES_HOST` (або `DATABASE_URL`) ще на
імпорті настроек, тому `run-engine.sh` має власні значення PostgreSQL за
замовчуванням і працює у свіжому терміналі без ручного експорту:

```text
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=55433
POSTGRES_USER=<поточний користувач ОС>
POSTGRES_DB=requestrider
```

Кожна змінна з оточення має пріоритет над цими значеннями, а скрипт друкує
використаний кластер перед міграцією — пароль у вивід не потрапляє:

```bash
./run-engine.sh
# [run-engine] using PostgreSQL kali@127.0.0.1:55433/requestrider
```

Для іншого кластера задайте змінні явно. Docker Compose публікує
`127.0.0.1:5432` з користувачем `requestrider`, тому для нього:

```bash
export POSTGRES_HOST=127.0.0.1
export POSTGRES_PORT=5432
export POSTGRES_DB=requestrider
export POSTGRES_USER=requestrider
export POSTGRES_PASSWORD='your-local-postgres-password'
./run-engine.sh
```

`run-engine.sh` запускає Go engine, browser worker і Django UI; UI доступний на
`http://127.0.0.1:8000/`. Порт Django теж задається змінною, бо `:8000`
часто вже зайнятий іншим стендом, і тоді весь успішний старт падає на
`That port is already in use`:

```bash
RUNSERVER_PORT=8010 ./run-engine.sh    # UI на http://127.0.0.1:8010/
```

Типове значення — `8000`, тобто `./run-engine.sh` без змінних веде себе
як раніше. Те саме для browser-worker: доки порт був зашитий у `PORT=8090`,
скрипт не міг підняти worker на вільному порту й мовчки переиспользував
чужий процес на `:8090`, що ламає ізоляцію тестів:

```bash
WORKER_PORT=28030 RUNSERVER_PORT=28031 ./run-engine.sh
```

Перевірка:

```bash
curl http://127.0.0.1:8081/health
curl -I http://127.0.0.1:8000/
```

Для брокерних Engine tasks локально потрібен Redis. Django/Celery читає
`CELERY_BROKER_URL`, а Go consumer запускається лише за наявності
`ENGINE_BROKER_URL`; обидва мають вказувати на той самий broker, і Redis — єдиний
підтримуваний транспорт: старий `amqp://` падає з помилкою, що називає
заміну, а не мовчки публікує нікуди. Поточний
consumer підтримує `request.execute` і `target.crawl`; broker dispatch
увімкнений лише для static Target і Repeater workflow nodes, коли задано
`WORKFLOW_ENGINE_BROKER_ENABLED=1`. За замовчуванням nodes лишаються на
наявному HTTP шляху; додайте цю змінну до середовища Django, а
`ENGINE_BROKER_URL` — до середовища Go. Go не читає Celery protocol.
Запускайте Celery worker та Go engine, а Django result consumer — окремим
процесом:

```bash
export CELERY_BROKER_URL='redis://127.0.0.1:6379/0'
export ENGINE_BROKER_URL="$CELERY_BROKER_URL"
./run-engine.sh
```

`POSTGRES_*` тут не дублюються: `run-engine.sh` уже має локальні значення за
замовчуванням, а для Docker-кластера їх задають явно, як показано вище.

Якщо Redis ще не запущено:

```bash
redis-server --port 6379 --bind 127.0.0.1 --appendonly yes   # або docker compose up -d redis
```

Broker пересилає байт у байт task/result JSON
(`contracts/engine-task-v1.json`, `contracts/engine-result-v1.json`), а надійність
виражена явно: повідомлення забирається одним `BLMOVE` у
`<queue>.inflight`, `ack` його звільняє, `requeue` повертає в чергу, `reject`
переносить у `<queue>.dead`, а на старті consumer повертає залишки `.inflight` у
чергу і відтворює записаний outcome замість повторного запиту. Redis потрібен
версії 6.2+ (`LMOVE`/`BLMOVE`); Django consumer перевіряє це на старті.

Живий end-to-end прогін брокера (Django → Celery → Redis → Go → Redis →
PostgreSQL) перевіряється з перевірками success, redelivery, error, restart,
cancel і dead-letter.

У другому терміналі повторно задайте `POSTGRES_*` і `CELERY_BROKER_URL`,
активуйте середовище та запустіть Celery worker. `run-engine.sh` ці значення
експортує тільки у своєму процесі, тому Celery запускається з ними явно — такі
самі, які надрукував `run-engine.sh`:

```bash
cd web
. .venv/bin/activate
export POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=55433 POSTGRES_DB=requestrider
export POSTGRES_USER=kali
export CELERY_BROKER_URL='redis://127.0.0.1:6379/0'
celery -A core worker --loglevel=info
```

Для Docker-кластера це `POSTGRES_PORT=5432`,
`POSTGRES_USER=requestrider` і обов'язковий `POSTGRES_PASSWORD`.

У третьому терміналі повторіть ці `POSTGRES_*` та `CELERY_BROKER_URL` значення
і виконайте `python manage.py consume_engine_results`. Без
`ENGINE_BROKER_URL` Go engine працює зі своїм чинним HTTP API.

Docker Compose-конфігурація PostgreSQL збережена для Docker-розгортання; її
налаштування описане в розділі нижче.

Локальний `runserver` працює через WSGI та не підтримує WebSocket project live
stream. UI спочатку перевіряє `GET /api/project-events/status`; при відповіді
`{"websocket": false}` він не створює помилкове з’єднання. Для ASGI-розгортання
через `core.asgi` endpoint повертає `true`, і live project events залишаються
доступними.

## Docker Compose

Docker Compose — окремий варіант розгортання; локальний запуск вище працює без
Docker.

Переконайтеся, що Docker daemon доступний:

```bash
docker ps
```

Якщо користувач щойно доданий до групи `docker`, застосуйте нову групу без
перезавантаження:

```bash
newgrp docker
```

Збірка і запуск:

```bash
export POSTGRES_PASSWORD='set-a-strong-local-password'
docker compose build
docker compose up -d
docker compose ps
```

Compose створює вісім сервісів:

| Сервіс | Роль | Внутрішня адреса |
|---|---|---|
| `tor` | SOCKS5 Tor upstream | `tor:9050` |
| `engine` | Go API і passive proxy | `engine:8081`, `engine:8080` |
| `browser-worker` | Playwright browser worker | `browser-worker:8090` |
| `postgres` | PostgreSQL database | `postgres:5432` |
| `web` | Django UI і gateway | `web:8000` |
| `redis` | Durable task/result message broker | `redis:6379` |
| `celery` | Django task worker | internal |
| `engine-results` | Django result queue consumer | internal |

У `docker-compose.yml` engine отримує:

```text
ROUTE_ADDRESS=tor:9050
PROXY_LISTEN_ADDR=0.0.0.0:8080
ENGINE_LISTEN_ADDR=0.0.0.0:8081
```

`0.0.0.0` тут потрібен лише всередині контейнера, щоб Docker network могла
доставити трафік до сервісу. На host порти публікуються тільки на
`127.0.0.1`.

Перевірка:

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/route
docker compose logs --no-color tor
```

У логах Tor має з’явитися:

```text
Bootstrapped 100% (done)
```

Зупинка:

```bash
docker compose stop
```

Видалення контейнерів і мережі:

```bash
docker compose down
```

Видалення образів цього Compose-проєкту:

```bash
docker compose down --rmi all
```

Не використовуйте `docker system prune`, якщо не хочете видалити ресурси
інших проєктів.

### Робочий стенд: `docker-stand.sh`

`docker-compose.yml` сам по собі не піднімається, і це не збереження в клік.
`docker-stand.sh` — єдина точка керування робочим стендом: вона створює
`data/run/compose.env` із секретами, перевіряє середовище, збирає образи,
піднімає вісім сервісів і чекає справжньої готовності.

```bash
./docker-stand.sh            # підняти (те саме, що up)
./docker-stand.sh check      # перевірити ланцюг хост → web → engine
./docker-stand.sh direct on  # маршрут напряму (Tor не потрібен)
./docker-stand.sh direct off # маршрут через Tor
./docker-stand.sh tor        # діагностика Tor: завантаження, мости, транспорт
./docker-stand.sh stop       # зупинити, томи цілі
```

Два розбіжності, які він закриває, виміряні, а не припущені:

- `engine/main.go` і `browser-worker/worker.py` відмовляються вешати слухач на
  `0.0.0.0` без `RR_ALLOW_NON_LOOPBACK_BIND=1`, а compose виставляє саме
  `0.0.0.0` обом. Без overlay рухок не піднімався, а воркер йшов у перезапуск
  з `exit=1`.
- обидва сервіси відповідають 403 на не-loopback `Host`, а під контейнерами Django
  звертається до них за ім'ям сервісу. Правка — у `internal_service_headers`
  (`web/lab/engine_client.py`); вона ж несла ключ в `open_engine_stream`, без
  якого жива стрічка подій віддавала 403.

Порти стенда — 28xxx/25xxx, а не 8000/8080/8081, і це навмисно: вони не
перетинаються з нативним стендом `start.sh`, тому обидва можуть стояти
одночасно. Назову проєкту — `request-rider`, задано явно: саме це ім'я
очікує проєктний compose.

`data/run/` у `.gitignore`, тому секрети, torrc і файл мостів у репозиторій не
потрапляють.

### Tor у контейнері: obfs4 і мости

На мережі, яка втручається в з'єднання з ретрансляторами, Tor не піднімається
ні за яких налаштувань. Виміряно на цій машині: сокет до ретранслятора
відкривається, а TLS-рукопожаття обривається — однаково на чотирьох різних
реле, і з боку `openssl s_client`, і з боку самого Tor, тоді як звичайний HTTPS з
того самого хоста відповідає. Тобто це не DNS, не сховище сертифікатів і не
фільтр портів, і жодна версія `ca-certificates` тут не помогає.

Рятує лише обфускація `obfs4`. Образ її містить, а мости — ні: вони
видаються під конкретну мережу і за CAPTCHA, тож у репозиторій їм не місце.

1. Отримайте мости на <https://bridges.torproject.org> (тип **obfs4**).
2. Покладіть їх у `data/run/tor.bridges`, по одному рядку на міст:

   ```text
   Bridge obfs4 <ip>:<port> <відбиток 40 hex> cert=<base64>
   ```

3. Пересоздайте контейнер і перевірте:

   ```bash
   ./docker-stand.sh restart tor
   ./docker-stand.sh tor
   ```

   `data/run/tor.bridges` порожній — скрипт працює без мостів і лише
   попереджає; `torrc` монтується в контейнер, тому додавання моста не потребує
   перезбирання образу. Рядок без префікса `Bridge ` (типовіша помилка копіювання)
   розпізнається і виправляється, а не відкидається.

Коли `Bootstrapped 100% (done)` — маршрут через Tor працює:

```bash
curl --socks5-hostname 127.0.0.1:29050 https://check.torproject.org/api/ip
```

Вибір Direct чи Tor переживає перезапуск: `direct on` і `direct off` записують
рішення в `data/run/stand.route`, і наступні `up`/`restart` піднімають рухок так
само. Мовчки режим не перемикається — анонімність і пряме з'єднання різні
рішення, і приймає їх оператор.

#### Як перевірити, що маршрутизація справді працює

Перевірка «контейнер запущений» нічого не доводить: рухок може бути живий і
при цьому виходити напряму. Дивніся на вихідний IP.

**1. Двихок своїм маршрутом** — це той самий ендпоінт, який смикає кнопка
«Check connection» в UI, і він ходить на `check.torproject.org` через
поточний маршрут:

```bash
docker compose -p request-rider -f docker-compose.yml \
  -f docker-stand.overlay.yml exec -T web python -c '
import os, django, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings"); django.setup()
from lab.engine_client import EngineClient
s, p = EngineClient(os.environ["ENGINE_URL"]).request(
    "POST", "/route/check", {"url": "http://check.torproject.org/", "timeout_ms": 120000}, timeout=240)
print(p["route"], p["external_ip"])'
```

Очікується `route = {address: tor:9050}` і `external_ip = {ip: …, is_tor: true}`.

**2. Пасивний прокси** — цим шляхом реально йде трафік до цілі, і він
перехоплює TLS, тож клієнт має довіряти CA рухка з `data/ca/ca.crt`:

```bash
curl --cacert data/ca/ca.crt -x http://127.0.0.1:28080 \
     https://check.torproject.org/api/ip
```

Без `--cacert` запит впаде з `SSL: UNEXPECTED_EOF_WHILE_READING` — це не поломка
проксі, а те, що клієнт не довіряє підробленому сертифікату.

**3. Контроль.** `./docker-stand.sh direct on` і повторити пункт 1: `route` має
стати порожнім, а IP — іншим. Саме ця різниця доводить, що вимірювання
залежить від налаштування, а не від збігу.

##### Важливо про цю машину: `Direct` тут не означає «без Tor»

Виміряно 2026-10-02. В режимі Direct рухок виходить на `185.220.100.253` з
`is_tor: true`, і це **той самий IP, що й у самого хоста**. Причину знайдено:
локального тунелю немає (`tun`/`wg` відсутні), `eth0` має адресу `10.0.2.15` за
шлюзом `10.0.2.2` — це NAT віртуальної машини, — а `/etc/resolv.conf` містить
резолвери самого Tor (`208.67.222.222`, `208.67.220.220`).

Тобто трафік анонімізує **шлюз**, а не стенд. Наслідок для загрози:

| режим | вихідний IP (виміряно) | хто анонімізує |
|---|---|---|
| `tor` | `147.90.234.88`, `is_tor: true` | власний контейнер Tor стенду |
| `direct` | `185.220.100.253`, `is_tor: true` | шлюз мережі поза машиною |

Тобто на цій машині `direct on` **не означає** «ваш реальний IP видно»: він і так
не видно, але й контролює анонімізацію не стенд, а шлюз. Якщо потрібен
контроль над тим, ким виходите, це треба вирішувати на шлюзі або через власний
тунель — режим у стенді цього не змінює.

##### Про два шари анонімізації на цій машині

`direct on` не означає «ваш реальний IP видно», але й не означає, що анонімізацією
керуєте ви. Тут про те, хто саме виводить трафик.

```text
RequestRider (у контейнері)
   └─► власний Tor-контейнер стенду, обфускація obfs4
          └─► мережа віртуальної машини, шлюз 10.0.2.2
                 └─► ??? — тут Tor-вихід 185.220.100.253
                        └─► інтернет
```

Виміряно 2026-10-02: локального тунелю немає (`tun`/`wg` відсутні), `eth0` =
`10.0.2.15/24` за шлюзом `10.0.2.2`, `/etc/resolv.conf` містить резолвери Tor
(`208.67.222.222`, `208.67.220.220`), вихід хоста — Tor-вихід, і саме такий самий
IP контейнер показує в режимі Direct. Механізм шлюзу **не доведено**: це може бути
провайдерський VPN, а не «Tor на NAT». Висновок один, але й механізм — лише
обґрунтоване припущення, а не перевірений факт.

**Своє тунель замість шлюзового** означає маршрут, який піднімаєте ви: WireGuard
або SSH-тунель до VPS, яким володієте. Він стає маршрутом за замовчуванням, і
тоді вирішуєте ви, а не шлюз. Що це змінює конкретно:

- **вихідний IP ваш** і сталий. Для пентест-інструмента це не дрібниця: спільний
  Tor-вихід ділиться з кимось ще, і блокування та репутація накопичуються на IP,
  а не на вас.
- **немає третьої сторони** між вами і ціллю.
- **менша затримка**: зараз два шари (Tor поверх Tor), один тунель — один хоп.
- **немає залежності від налаштувань шлюза**: якщо Tor у шлюзі зламається,
  `direct` стане або «голим», або мертвим, і ви дізнаєтеся про це постфактум.

**Чого це не змінює для самого RequestRider.** Для інструмента шар **вже ваш**:
цеп будує контейнер `tor` стенду, вихід визначає він, а obfs4 улаштована саме так,
щоб нижній шар не бачив цілі — шлюз бачить з'єднання з мостом і нечитамий шум, але
не знає, куди ви йдете. Тому Tor-вихід шлюзу не робить інструмент менш анонімним
і не стоїть між вами і ціллю для трафіку стенду. Він стосується всього іншого на
машині: браузер, оновлення, `curl` у терміналі.

**Рішення не прийнято.** Сервера зараз немає, тож власний тунель не
налаштовувався. Коли з'явиться — починати не з нього, а з повного заміру
поточного шляху, інакше є ризик поставити тунель **поверх** шлюзового Tor і
отримати той самий подвійний шар, вже без контролю. Вимірювання вище для цього
підходять: вони показують, чи шлюз усе ще анонімізує.

## Маршрутизація через SOCKS5/Tor

Маршрут налаштовується у вкладці **Tor/Proxy**.

- Порожня адреса — **Direct**.
- `127.0.0.1:9050` — локальний Tor при локальному запуску.
- `tor:9050` — Tor-контейнер для engine у Docker Compose.
- Будь-який інший доступний SOCKS5 `host:port` — віддалений або локальний
  SOCKS5-проксі.

Після введення адреси натисніть **Apply route**. **Cancel route** очищає
адресу і повертає Direct. Обидві дії виконують route-generation drain:
скасовують активні Repeater/Intruder/Target/OSINT/Scanner/Burst/Last-Byte/OAST,
AI та workflow-операції старого покоління, закривають browser-worker jobs
і не допускають змішування старого та нового маршруту. **Check connection**
перевіряє ціль, latency, HTTP status, зовнішню IP-адресу через
`https://check.torproject.org/api/ip` і показує `IsTor`; типове поле перевірки
за замовчуванням — `https://check.torproject.org/`.

Для ручної перевірки у браузері можна використовувати:

| Сервіс | URL | Призначення |
|---|---|---|
| Tor Project | <https://check.torproject.org/> | Перевірка, чи визначається браузер як підключений через Tor |
| Tor Project API | <https://check.torproject.org/api/ip> | JSON із зовнішньою IP та прапорцем `IsTor` |
| ifconfig.me | <https://ifconfig.me/ip> | Зовнішня IP у plain text |
| icanhazip | <https://icanhazip.com/> | Зовнішня IP у plain text |
| ipinfo.io | <https://ipinfo.io/json> | IP та базова інформація у JSON |

Щоб ручна перевірка показувала Tor-маршрут, браузер має використовувати
`127.0.0.1:8080` як HTTP/HTTPS proxy для RequestRider або `127.0.0.1:9050`
як SOCKS5. Посилання в UI саме по собі не змінює маршрут браузера. Не
надсилайте через сторонні IP-сервіси секретні дані й враховуйте, що кожен
сервіс бачить IP-адресу та час запиту.

### Як проходить трафік

Для активних інструментів:

```text
Repeater / Intruder / Target / OSINT / Scanner
    -> Go engine transport
    -> Direct або SOCKS5/Tor
    -> target
```

Для браузерного трафіку:

```text
Browser
    -> HTTP proxy 127.0.0.1:8080
    -> passive MITM
    -> той самий outbound transport
    -> Direct або SOCKS5/Tor
    -> target
```

Repeater, Intruder, static Target, OSINT і Scanner не проходять повторно через
`:8080`; вони використовують той самий route manager без подвійного MITM.
Browser-driven Target навпаки свідомо проходить через локальний passive proxy,
щоб network evidence мали route generation і `source_ip`. Усі події публікуються
у спільний Traffic Store.

У Docker engine не може використовувати `127.0.0.1:9050` для Tor-контейнера:
це loopback самого engine-контейнера. Використовуйте саме `tor:9050`.

Source IP metadata запускає **один свіжий lookup для кожного логічного outbound
exchange** через `https://check.torproject.org/api/ip` і той самий активний
Direct/SOCKS5 route. Process-wide кеш відсутній: наступний exchange бачить
нову IP-адресу, навіть якщо API змінюється щосекунди; помилка lookup дає
порожнє значення, але ніколи не повертає старий IP. Для довгих job і passive
browser traffic lookup не витрачає budget цільового запиту; поки lookup не
завершився, результат має явний `source_ip_pending`, а Traffic/History row
backfill-иться після свіжого значення. Значення потрапляє в
повний Traffic/History evidence для Repeater, Intruder, Burst, Last-Byte,
passive proxy та route check; уже збережені historical rows не переписуються
після наступного route switch. Якщо SOCKS5 недоступний, outbound-запит має
завершитися явною помилкою, а не непомітним fallback у Direct.

## Passive MITM і локальний CA

Engine автоматично створює:

```text
data/ca/ca.crt
data/ca/ca.key
```

Для HTTPS імпортуйте `data/ca/ca.crt` лише в окремий тестовий профіль
браузера. `data/ca/ca.key` — приватний ключ і не повинен потрапляти до Git,
логів або сторонніх систем.

Налаштування браузера:

```text
HTTP proxy:  127.0.0.1
HTTP port:   8080
HTTPS proxy:  127.0.0.1
HTTPS port:  8080
```

Traffic є in-memory Store engine. Pending exchange спочатку показується зі
статусом `pending`, після відповіді оновлюється тим самим ID. Перезапуск engine
або очищення Traffic видаляє незбережені live events. **Save row** переносить
вибраний exchange у Django History/PostgreSQL.

Системні запити браузера, наприклад Firefox Push Service, можуть потрапляти у
Traffic. Це не обов’язково трафік тестованого сайту; використовуйте окремий
профіль браузера і не відкривайте особисті сесії через MITM.

## Основний workflow

1. Визначте письмовий scope і дозвіл на тестування.
2. Запустіть локальний або Docker Compose режим, але не обидва одночасно.
3. Перевірте `/health`, активний route і зовнішню IP.
4. Якщо потрібен браузерний Traffic, імпортуйте CA в тестовий профіль і
   встановіть proxy `127.0.0.1:8080`.
5. Почніть із Repeater, потім використовуйте Target/OSINT/Scanner для
   read-only аналізу.
6. Для Intruder задайте мінімальні dictionaries, concurrency і delay.
7. Зберігайте лише потрібні записи, очищайте cookies, tokens і exports після
   завершення.
8. Для повторюваної автоматизації відкрийте `Automation`, зберіть workflow з
   trigger-вузлом і інструментами, збережіть його в активному Project та запускайте
   вручну або активуйте webhook/розклад.
9. Щоб перенести вже налаштований інструмент, заповніть його вкладку та
   натисніть `Send to Automation`; після переходу перевірте вибраний вузол у
   canvas і за потреби скористайтеся `Open in tool` або `Use current workspace`.

## API

### Django gateway

| Method | Endpoint | Призначення |
|---|---|---|
| `GET` | `/` | UI |
| `POST` | `/api/execute` | Repeater |
| `POST` | `/api/intruder` | Запуск Intruder |
| `GET` | `/api/intruder?attack_id=<id>` | Статус і результати |
| `DELETE` | `/api/intruder?attack_id=<id>` | Cancel Intruder |
| `GET/POST` | `/api/intruder/saved` | Збережені конфігурації атак |
| `GET/POST/DELETE` | `/api/intruder/saved/<id>` | Перегляд, оновлення або видалення конфігурації |
| `POST` | `/api/intruder/saved/<id>/run` | Повторний запуск збереженої конфігурації |
| `POST` | `/api/target-map` | Target map |
| `GET/DELETE` | `/api/target-map?map_id=<id>` | Статус або cancel |
| `POST` | `/api/target-browser` | Запуск browser-driven Target |
| `GET/DELETE` | `/api/target-browser?job_id=<id>` | Статус або cancel browser job |
| `GET/POST` | `/api/projects` | Список або створення Project/workspace |
| `GET/PATCH/DELETE` | `/api/projects/<id>` | Перегляд, зміна або видалення Project |
| `POST` | `/api/project-context` | Встановлення або очищення server-backed active Project |
| `POST` | `/api/projects/import` | Імпорт project bundle (створює **новий** Project) |
| `GET` | `/api/projects/<id>/hub` | Project Hub: доказова база робочого простору |
| `GET` | `/api/projects/<id>/export` | Повний бандл `requestrider.project/v1` |
| `GET` | `/api/project-events/status` | Capability live project WebSocket для WSGI/ASGI |
| `GET` | `/static/vendor/<path>` | Вендорений вбудований бандл (без CDN) |

Вкладка `Projects` містить окреме меню керування workspace: вибір активного
Project, створення, редагування назви, target, environment і route profile,
а також видалення через підтвердження. Видалення Project є каскадним:
пов’язані History, Intruder, Target jobs і Workflows
також видаляються. Операція незворотна. У шапці залишається лише індикатор активного
Project.

Активний Project зберігається у валідованому Django session і встановлюється
лише через CSRF-protected `POST /api/project-context`. `?project_id` ігнорується,
а `localStorage` залишається лише browser mirror; reload читає server value.
Middleware надає `request.active_project`, очищає deleted/invalid ID і не робить
цей session context authorization boundary для shared/multi-user deployment.

`POST`/`PATCH /api/projects` зберігають `scope_in` та `scope_out` як legacy
metadata, але вони не є execution policy і не блокують інструменти. active
workflow tools використовують URL, переданий оператором.

`Project` приймає необмежені `tech_stack` та `notes`. `ProjectSecret` не має
окремого поля `value` саме тому, що `value_ref` і є повним значенням credential'а;
зберігаються type, key name, **значення** та source metadata.
`ProjectContextBuilder` формує project-scoped Markdown/AI context із endpoints,
Workflows, TargetJobs, `## Secrets` із **повними** значеннями JWT, cookies і
Authorization, та `## Notes` (default-on). Сирі тіла запитів і відповідей у сам
summary не інлайняться — вони лишаються в capture archive і Project exchanges.
Детальний контракт
— у [`Документація/project-hub.md`](./Документація/project-hub.md). AI Assistant
додає цей context лише за one-shot checkbox активного Project; після запиту
consent скидається, а відсутність active Project повертає explicit error.

Passive Traffic має явний `TrafficCaptureContext`: оператор вказує
`project_id` або `null`, а сервер підставляє opaque token у browser-driven Target
через `X-RequestRider-Capture-Context` лише через local proxy route. Token не
повертається browser API; proxy не пересилає цей internal header upstream;
Django класифікує evidence як `in_scope`, `out_of_scope`, `unscoped` або
`invalid_context`. Out-of-scope exchange зберігається і не видаляється. Token
не є authorization credential і не замінює shared-mode auth/ACL.

OSINT transforms є explicit: network adapters запускаються лише з
`confirm_network=true`, а їхні результати не обмежуються application
count/body budget. Output redact-иться і upsert-иться у вибраний graph. Жоден
transform не запускається неявно з passive OSINT discovery.

У OSINT workspace граф створюється й редагується через CSRF-protected API.
Активний Project тут необов'язковий: `POST /api/osint/graphs` приймає
`project_id: null`, а `GET /api/osint/graphs` без `project_id` повертає графи
scope без проєкту. Невірний `project_id` (не існує або не число) лишається
помилкою, а не тихим переходом у scope без проєкту.
Local native SVG canvas не має CDN/third-party runtime: selection, details,
right-click transform menu, filter, grid/radial auto-layout і повне
відображення graph. 500+ node Firefox smoke, persistence після reload,
console та network cleanup входять у зовнішній browser-сценарій.

| `POST` | `/api/osint` | Passive OSINT перевірки цілі |
| `GET/POST` | `/api/osint/graphs` | Versioned OSINT graphs; `project_id` **необовʼязковий** (без нього — scope без проєкту) |
| `GET` | `/api/osint/graphs/<id>` | Entities, relations and provenance |
| `DELETE` | `/api/osint/graphs/<id>` | Видалення графа разом із контейнером (`{"confirm": true}`); на відміну від `clear`, рядок графа зникає зі списку |
| `POST` | `/api/osint/graphs/<id>/upsert` | Idempotent graph upsert (атомарний: одна некоректна identity відхиляє весь batch) |
| `PATCH/DELETE` | `/api/osint/graphs/<id>/entities/<entity_id>` | Редагування `risk_score`/`display_value`/`properties`/`provenance` або видалення entity разом із її relations |
| `DELETE` | `/api/osint/graphs/<id>/relations/<relation_id>` | Видалення одного relation без видалення його endpoint entities |
| `POST` | `/api/osint/graphs/<id>/clear` | Очищення графа (`{"confirm": true}`); контейнер графа зберігається |
| `GET` | `/api/osint/transforms` | Transform registry |
| `POST` | `/api/osint/graphs/<id>/transform` | Explicit transform run з graph persistence і `transform_result.status` |
| `POST` | `/api/osint/graphs/<id>/transform/jobs` | Transform як background-job → `job_id` |
| `GET` | `/api/osint/graphs/<id>/transform/jobs/<job_id>` | Стан, прогрес і частковий результат transform-а |
| `POST` | `/api/osint/graphs/<id>/transform/jobs/<job_id>/<action>` | `pause`, `resume` або `cancel` transform-а |
| `GET` | `/api/osint/graphs/<id>/files/` | Каталог файлів результату графа (`/files` без слэша теж), серверний рендер у мові cookie `requestrider-language` |
| `GET` | `/api/osint/graphs/<id>/files/<name>` | Переглядач результату: пошук, чіпи типів, сортування, серверна пагінація поверх **повного** файлу; теж серверний рендер у мові cookie |
| `GET` | `/api/osint/graphs/<id>/files/<name>?raw=1` | Байти файлу як є, без розмітки |
| `GET` | `/api/osint/graphs/<id>/files/<name>?download=1` | Ті самі байти завантаженням |
| `POST` | `/api/scanner` | Scanner Pro |
| `POST` | `/api/scanner/nuclei` | Запуск завантажених Nuclei-шаблонів із per-file звітом |
| `POST` | `/api/scanner/nuclei/upload` | Один чанк завантажених шаблонів → `upload_id` |
| `POST` | `/api/scanner/nuclei/run` | Запуск staged-шаблонів із `Scan options` |
| `POST` | `/api/scanner/nuclei/local` | Локальний прогін шаблонів із top-level `flow:`, які сам бінарник не виконає |
| `POST` | `/api/scanner/nuclei/jobs` | Background-job запуску → `job_id` і живий прогрес |
| `GET` | `/api/scanner/nuclei/jobs/<id>` | `state` + `progress` (лічильники nuclei) + фінальний `result` |
| `GET` | `/api/scanner/nuclei/jobs/<id>/stream` | SSE: `progress`, `template` (live-рядок на файл), `done` |
| `POST` | `/api/scanner/nuclei/jobs/<id>/pause` | Пауза запуску (`SIGSTOP`), стан `paused` |
| `POST` | `/api/scanner/nuclei/jobs/<id>/resume` | Продовження з того ж місця, стан `running` |
| `POST` | `/api/scanner/nuclei/jobs/<id>/cancel` | Скасування запуску |
| `POST` | `/api/scanner/active/jobs` | Активний скан як background-job → `job_id` і прогрес |
| `GET` | `/api/scanner/active/jobs/<id>` | `state` + `progress` + фінальний звіт; звіт один раз записується в `ScannerRun` |
| `GET` | `/api/scanner/active/jobs/<id>/stream` | SSE: `progress` і `done` |
| `POST` | `/api/scanner/active/jobs/<id>/cancel` | Скасування; паузи немає, невідомий action → `400` |
| `GET` | `/api/scanner/report` | Серверний HTML-звіт Scanner із allow-list валідацією та Django-екрануванням |
| `GET/PUT` | `/api/route` | Читання або зміна маршруту |
| `POST` | `/api/route/check` | Перевірка route і source IP |
| `GET` | `/api/history` | History; `limit`/`offset` задають вікно, `total` — розмір усього збігу |
| `GET` | `/api/history/export` | Export History |
| `DELETE` | `/api/history/<id>` | Видалення запису |
| `PATCH` | `/api/history/<id>` | Редагування tags/notes запису |
| `POST` | `/api/history/import` | Імпорт записів History (legacy backend-ендпоїнт, у UI не виводиться) |
| `POST` | `/api/history/bulk` | Масове видалення |
| `GET/DELETE` | `/api/traffic` | Traffic live-snapshot або очищення. `DELETE` очищає і in-memory Store, і durable-архів `TrafficRecord` з `source="proxy"`; `repeater`/`intruder`/`last-byte` не чіпає, бо це результати History |
| `GET` | `/api/traffic/records` | Вікно довічного пасивного архіву з БД (`limit`/`offset`/`detail`, `total`) |
| `GET` | `/api/traffic/record` | Повний обмін одного збереженого рядка (`id`) |
| `GET` | `/api/traffic/detail` | Деталі одного live-обміну за `id` |
| `GET` | `/api/traffic/stream` | Traffic SSE |
| `POST` | `/api/traffic/save` | Save Traffic row |
| `POST` | `/api/traffic/annotate` | Tags/notes |
| `GET/POST` | `/api/traffic/capture-contexts` | Явні passive capture contexts |
| `GET/PATCH/DELETE` | `/api/traffic/capture-contexts/<id>` | Перегляд, rename/activate або deactivate context |
| `POST` | `/api/agent/chat` | Один AI chat turn; `include_project_context` лише за explicit one-shot opt-in |
| `GET` | `/api/workflows/node-types` | Каталог типів вузлів Automation |
| `GET` | `/api/workflow-templates` | Локальний каталог Template Store |
| `GET/POST` | `/api/workflows` | Список або створення workflow |
| `GET/PATCH/DELETE` | `/api/workflows/<id>` | Перегляд, редагування або видалення workflow |
| `GET` | `/api/workflows/<id>/export` | Export workflow JSON |
| `POST` | `/api/workflows/import` | Import workflow JSON |
| `POST` | `/api/workflows/<id>/run` | Запуск workflow вручну |
| `POST` | `/api/workflows/<id>/activate` | Активація webhook/розкладу |
| `POST` | `/api/workflows/<id>/deactivate` | Деактивація workflow |
| `GET` | `/api/workflows/runs` | Історія виконань workflow |
| `GET` | `/api/workflows/runs/<id>` | Статус, результат і журнал вузлів |
| `GET` | `/api/workflows/runs/<id>/stream` | SSE live node events |
| `GET` | `/api/workflows/runs/<id>/export` | Export run JSON/Markdown |
| `POST` | `/api/workflows/runs/<id>/<action>` | `pause`, `resume` або `cancel` запуску |
| `ALL` | `/api/workflows/hooks/<slug>` | Webhook-тригер workflow |

### Помилки engine gateway

Django gateway повертає явні структуровані помилки від Go engine. Основні
значення `reason`:

- `ENGINE_UNAVAILABLE` — engine недоступний на рівні з'єднання;
- `ENGINE_HTTP_ERROR` — engine відповів HTTP-помилкою; поле `status` містить
  upstream status;
- `ENGINE_INVALID_RESPONSE` — відповідь engine порожня, не є коректним JSON
  або має непідтримувану форму.

Malformed responses і помилки transport не перетворюються на успішні відповіді.

UI-вкладки мають WAI-ARIA зв'язки `tablist`/`tab`/`tabpanel`, підтримують
клавіатурне перемикання стрілками та використовують локальні dialogs для
введення і підтвердження дій.

### Go engine

```text
GET    /health
GET    /route
PUT    /route
POST   /route/check
POST   /proxy/request
POST   /proxy/intruder
GET    /proxy/intruder/<attack_id>
DELETE /proxy/intruder/<attack_id>
POST   /proxy/target-map
GET    /proxy/target-map/<map_id>
DELETE /proxy/target-map/<map_id>
POST   /proxy/target-js
POST   /proxy/osint
GET    /proxy/osint/transforms
POST   /proxy/osint/transform
POST   /proxy/osint/transform/jobs
GET    /proxy/osint/transform/jobs/<job_id>
POST   /proxy/scanner
GET    /proxy/scanner/corpus/stats
POST   /proxy/scanner/corpus/run
POST   /proxy/scanner/corpus/jobs
GET    /proxy/scanner/corpus/jobs/<job_id>
GET    /proxy/scanner/corpus/jobs/<job_id>/stream
POST   /proxy/scanner/active/jobs
GET    /proxy/scanner/active/jobs/<job_id>
POST   /proxy/scanner/active/jobs/<job_id>/cancel
GET    /proxy/scanner/active/jobs/<job_id>/stream
POST   /proxy/repeater-burst
GET    /proxy/repeater-burst/<burst_id>
DELETE /proxy/repeater-burst/<burst_id>
POST   /proxy/repeater-burst/<burst_id>  {"action":"pause|resume"}
POST   /proxy/last-byte
GET    /proxy/last-byte/<last_byte_id>
DELETE /proxy/last-byte/<last_byte_id>
POST   /proxy/last-byte/<last_byte_id>  {"action":"pause|resume"}
POST   /proxy/oast
GET    /proxy/oast/<listener_id>
DELETE /proxy/oast/<listener_id>
GET    /events
GET    /events/detail
POST   /events/annotate
GET    /events/stream
```

## Перевірка та діагностика

З кореня репозиторію:

```bash
cd engine && go test ./... -count=1
cd engine && go test ./... -count=1 -race
cd ../web && python manage.py check
cd web && python manage.py test -v 2
```

Тестова база створюється з UTF-8 шаблону `POSTGRES_TEST_TEMPLATE`
(типово `requestrider_utf8_tmpl`), і `core.test_runner.RequestRiderTestRunner`
**створює цей шаблон сам**, якщо його немає: `CREATE DATABASE ... TEMPLATE
template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'` з `template0`, якого не
можна змінити. Кластер із `SQL_ASCII`-шаблонами інакше підсовує тестовій базі
нездатність зберігати маркер Intruder `§`, і падіння виглядає як `DataError`
усередині випадкового тесту. Наявний шаблон не перекодовується й не
пере створюється: якщо його кодування не UTF-8, помилка називає потрібну
команду, а роль без `CREATEDB` отримує ту саму команду замість тихої відмови.

Перевірка inline JavaScript виконується вбудованим блоком `./start.sh --check`
(`node --check` по інлайнових скриптах сторінки). Звичайний рецепт із
`re.search(r"<script>(.*)</script>", ...)` **на цій сторінці не працює** і
падає однаково до і після будь-якої правки: скрипт відкривається тегом з
`nonce`, перед ним підключено вендорний `cytoscape`, а сторінка будує
HTML-документи як JS-шаблонні літерали й закриває їх екрануваним термінатором,
тому сплайс по першому `</script>` розрізає літерал навпіл.

Docker-диагностика:

```bash
docker compose ps
docker compose logs --no-color --tail=100 tor engine web
docker system df
df -h /
```

Типові проблеми:

| Симптом | Причина | Дія |
|---|---|---|
| `permission denied /var/run/docker.sock` | користувач не в групі Docker | `newgrp docker` або новий login |
| `address already in use` | локальний режим уже займає порт | зупинити один режим перед запуском іншого |
| Tor не працює | bootstrap ще не завершився | дочекатися `Bootstrapped 100% (done)` |
| Docker Tor не доступний з engine | використано `127.0.0.1` замість service DNS | у Compose використовувати `tor:9050` |
| `no space left on device` | переповнений host або Docker cache | звільнити місце і перевірити `docker system df` |
| HTTPS certificate error | CA не імпортований у тестовий профіль | імпортувати `data/ca/ca.crt` |

## Безпека

Розширені рекомендації щодо LUKS, VPN/kill switch, firewall, VM, Docker,
секретів, CA і безпечного scope зберігаються в [`SECURITY.md`](SECURITY.md).
Це практична пам’ятка, а не гарантія абсолютної анонімності або безпеки.

## Документація функцій

Кожна велика функція описана окремим файлом у папці
[Документація](./Документація):

| Функція | Документ |
|---|---|
| Proxy, маршрутизація і passive MITM | [прокси.md](./Документація/proxy.md) |
| Repeater | [povtoryuvach.md](./Документація/povtoryuvach.md) |
| Intruder | [intruder.md](./Документація/intruder.md) |
| Target карта цілі | [karta-cili.md](./Документація/karta-cili.md) |
| OSINT | [osint.md](./Документація/osint.md) |
| Scanner Pro | [scanner-pro.md](./Документація/scanner-pro.md) |
| Активний скан | [aktivnyi-skanner.md](./Документація/aktivnyi-skanner.md) |
| Comparer | [porivniuvach.md](./Документація/porivniuvach.md) |
| Decoder | [dekoder.md](./Документація/dekoder.md) |
| Tor/Proxy operator workflow | [tor-proksi.md](./Документація/tor-proksi.md) |
| Passive Traffic | [pasivnyi-trafik.md](./Документація/pasivnyi-trafik.md) |
| History | [istoriia.md](./Документація/istoriia.md) |
| AI Assistant | [ai-asystent.md](./Документація/ai-asystent.md) |
| Template Store Automation | [template-store.md](./Документація/template-store.md) |
| OAST Listener | [oast.md](./Документація/oast.md) |
| Практичні сценарії Automation | [automation-сценарії.md](./Документація/automation-сценарії.md) |
| Workspaces і Session | [robochi-prostory-sesii.md](./Документація/robochi-prostory-sesii.md) |
| Project Hub і Target Knowledge Base | [project-hub.md](./Документація/project-hub.md) |

## Пов’язані документи

- [Контракт брокера Django ↔ Go Engine](./Документація/broker-contract.md) — версійовані task/result envelopes та правила delivery/ack.

- [`SECURITY.md`](SECURITY.md) — операційна безпека та checklist.
- [`ROADMAP.md`](ROADMAP.md) — короткий актуальний план розвитку.
- [`AGENTS.md`](AGENTS.md) — єдина істина про правила роботи агента в цьому
  репозиторії; читається **першим**.
- [`SESSION-CLAIMS.md`](SESSION-CLAIMS.md) — реєстр сесій: хто який файл
  тримає зараз.
- [`posibnyk-korystuvacha.md`](Документація/posibnyk-korystuvacha.md) —
  повний посібник користувача: від встановлення до практичних сценаріїв.
- [`Документація/`](Документація/) — актуальні довідники Repeater, Intruder,
  Target, Scanner, Proxy, Traffic, History, Decoder, Comparer, OSINT, AI та
  workspace/session.
