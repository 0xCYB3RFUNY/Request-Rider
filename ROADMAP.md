# Roadmap RequestRider

## Статус roadmap

Цей файл містить лише невиконаний backlog (`[ ]`). Виконані пункти видалено
для читабельності; історія виконаних робіт зберігається в
`DEVELOPMENT_LOG.md`. Кожен пункт backlog вважається нереалізованим до повного
проходження targeted/regression тестів і browser smoke-test.

Під кожним пунктом курсивом додано коротке пояснення запланованої фічі.

## Automation / Workflows

Поточний runtime є process-local і не є distributed queue; multi-main HA,
webhook signing та proxy-trigger можуть бути окремими майбутніми ітераціями.
Брокерна частина вже працює: Redis, Celery publisher, Go consumer і Django
result persistence, перевірено наскрізно живим прогоном.

### Наступні ітерації

- [ ] Додати сумісність із self-hosted Interactsh API та DNS/HTTPS/SMTP
  provider fixtures після локального HTTP contract.

  > Пояснення: планується підтримка зовнішнього OAST-провайдера типу Interactsh як альтернативи вбудованому loopback-лістенеру, з фістурами для кожного протоколу.

- [ ] Додати server-backed `WorkflowTemplate` CRUD, community manifests,
  schema signing та import preview.

  > Пояснення: планується серверне сховище шаблонів workflows з підписом схем і попереднім переглядом імпорту, замість лише локального каталогу.

- [ ] Додати Nuclei/Postman converters лише після canonical graph validation.

  > Пояснення: планується конвертація Nuclei/Postman у канонічний граф RequestRider, але тільки після готової серверної валідації графа.

## Session/workspace

- [ ] Забезпечити наскрізну project-isolation для звичайних Repeater/Intruder,
  proxy snapshots, OSINT/Scanner, Traffic sessions, History filters і reports;
  не прив’язувати весь proxy traffic до одного глобального active Project.

  > Пояснення: планується повна ізоляція даних між проєктами в усіх інструментах і звітах, без привʼязки всього proxy-трафіку до одного активного проєкту.

- [ ] Додати versioned browser `uiPreferences` із migration/validation для
  layout, split ratios, shortcut profile та per-workspace view modes.

  > Пояснення: планується версіоноване сховище UI-налаштувань у браузері з міграціями, щоб розкладка і шорткати не ламалися між версіями.

## Accessibility

## Scanner та Findings

- [ ] Зробити profiles behaviorally different: окремі read-only checks,
  explicit per-profile budgets і targeted tests; зараз профіль лише
  metadata.

  > Пояснення: планується, щоб кожен профіль сканера реально виконував свій набір read-only перевірок з окремим бюджетом, а не був лише підписом.

- [x] Додати server-side escaping HTML export і allow-list validation
  severity/status/confidence.

  > Пояснення: планується безпечний HTML-експорт findings з серверним екрануванням і перевіркою довідникових полів за allow-list.

- [ ] Замінити truncating fingerprint на stable evidence-aware identity та
  idempotent upsert для повторного Save.

  > Пояснення: планується стабільний ідентифікатор finding за evidence, щоб повторне збереження оновлювало запис, а не створювало дублікат.

> Статус 2026-10-01. Пункт 2 закрито з виміром: серверний рендер існував із
> 2026-09-30, але жодного виклику з UI (`grep 'api/scanner/report' index.html` = 0),
> тому HTML-експорт збирався в браузері. Тепер `cms`/`nuclei` йдуть на
> `/api/scanner/report`, `active` лишається клієнтським (його находки несуть
> surface/payload/tier, а ендпоїнт описує per-file документ). Жива перевірка:
> підсаджені `<img onerror>` і `<script>` повертаються екранизованими, на живому
> прогоні 80 шаблонів `rejected: 0`. Мутація (повернення на клієнтський рендер)
> червоніє 6 з 11 тестів.
>
> Пункт 1 і пункт 3 **не закрито** — обидва лишилися `[ ]`. Пункт 1
> перевірено виміром і підтверджено як незроблений: `engine/main.go` звав
> `runSafeScannerContext` **без** профілю, тіка профіль лише ехом у відповідь.
> Пункт 3 не торкався.
>
> Знайдене при повній перевірці корпусу належить не цим пунктам, а окремій
> знахідці, яку вони спричинили: **207
> workflow-шаблонів** (`nuclei-templates/workflows`) відкидалися з причиною
> `missing info.severity`, хоча `nuclei -validate` каже `All templates validated
> successfully`. Виправлено три речі: вимога severity більше не діє на документ,
> єдиний блок якого `workflows`; у виклик додано `-w <dir>` (workflow не
> шаблон, `-t` відмовляє весь виклик із `no templates provided for scan`, exit 1 —
> виміряно на v3.11.1); введено статус `workflow`, бо `skipped` означає «не
> виконувався», а підшаблони виконуються (9 HTTP-з'єднань на локальній фікстурі).
> Корпус перевірено повністю, 98 502 файли по 14 чанках, `duplicated=0` у
> кожному. Деталі й мутації — у `DEVELOPMENT_LOG.md`.


## Стратегічний backlog, узгоджений 2026-09-24

Цей backlog виникає з аудиту поточного коду, а не з припущень про наявність
функцій. Він виконується залежно від security/data foundation; один пункт за
раз проходить targeted tests, regression suite та live browser smoke-test.

### P0. Project Hub, scope і ізоляція даних

### P1. OSINT Entity Graph та local transforms

- [ ] Додати DNS records A/AAAA/CNAME/MX/NS/TXT/SOA/CAA з explicit errors;
  wildcard DNS detection і cancellation мають бути обов’язковими.

  > Пояснення: планується повний збір DNS-записів з явними помилками, детектом wildcard і обовʼязковим скасуванням довгих задач.


- [ ] Додати email/username recon, paste/breach lookup, GHDB link generator
  та GitHub public metadata як окремі bounded transforms з redaction.

  > Пояснення: планується розвідка за email/username, перевірка витоків і GitHub-метадані окремими обмеженими трансформами з маскуванням.


**Референси архітектури:** [Argus](https://github.com/cotcollective/argus) (MIT,
local-first modules), [Flowsint](https://github.com/reconurge/flowsint)
(Apache-2.0, graph/enricher ideas), [Osiris](https://github.com/simplifaisoul/osiris)
(MIT, live activity/UI ideas). Argus не робить запити приватними: локальним є
виконання, але public endpoints/websites всё одно бачать запит. Код сторонніх
проєктів не копіювати без окремого license/NOTICE audit.

Canvas реалізовано на **React Flow** (рішення власника 2026-09-27,
замість попереднього native SVG). Це єдина стороння бібліотека на сторінці:
бандл вендорений локально, без CDN і зовнішніх fetch, і підключається лише
на view Automation — решта `index.html` лишається самодостатною, чотири
інваріанти розкладки, 967 ключів i18n і наявні E2E-тести не змінюються.
Повний React-rewrite застосунку не входив у рішення і не планується.
Bounded 1000-node budget зберігається. Live ingestion залишається окремим
backlog пунктом.

### P1. OSINT → Scanner pipeline

- [ ] Додати data-only scanner template schema до YAML preview. Виняток,
  sanctioned 2026-09-25 власником: дозволено обмежене HTTP-only виконання
  Nuclei-подібних шаблонів (request + matchers status/words/regex, без коду
  і shell); див. `engine/pkg/scanner` і `DEVELOPMENT_LOG.md`.

  > Пояснення: планується data-only схема шаблонів сканера без коду і shell; виняток — обмежене HTTP-виконання Nuclei-подібних matchers за ENV-бюджетами.

- [ ] Додати context-aware mutations після baseline/response clustering;
  bounded OAST, adaptive 429/503 backoff і browser-rendered evidence.

  > Пояснення: планується мутаційне сканування після кластеризації базових відповідей, з адаптивними паузами і браузерними доказами.


### P1. Automation, SessionMacro та API security

- [ ] Додати AttackChain/AttackStep/evidence provenance після stable IDs;
  не перевикористовувати execution DAG як semantic security graph.

  > Пояснення: планується семантичний граф ланцюжка атаки з provenance evidence, окремо від технічного DAG виконання.

### P1. Protocols, client-side та API security

- [ ] Додати protocol metadata і local H2 fixture/TLS tests до WebSocket,
  gRPC/Protobuf, H3/QUIC та frame-level features.

  > Пояснення: планується метадані протоколів і локальні фікстури для WebSocket, gRPC, H3/QUIC з тестами TLS.

- [ ] Додати WebSocket capture/replay, gRPC `.proto`/`.desc` introspection і
  bounded binary mutations; raw bytes і metadata мають залишатися
  розрізнюваними.

  > Пояснення: планується захоплення і повтор WebSocket, інтроспекція gRPC-схем і обмежені бінарні мутації без змішування байтів і метаданих.

- [ ] Додати JavaScript source-map/AST analysis, local taint evidence,
  browser WebSocket events та витягування секретів.

  > Пояснення: планується аналіз JS source-map/AST з локальними taint-доказами
  
- [ ] Додати OpenAPI/Postman import, GraphQL introspection/schema inspection,
  BOLA role matrix і JWT allowlist/signature verification fixtures.

  > Пояснення: планується імпорт API-специфікацій, інтроспекція GraphQL, матриця BOLA-ролей і фікстури перевірки JWT.

- [ ] Додати H2 single-packet лише як manual-only best-efffork experiment з
  low-level `x/net/http2.ClientConn`, blocking body gates та PING barrier;
  не гарантувати і не тестувати deterministic one-TCP-packet semantics.

  > Пояснення: планується ручний експеримент відправки H2 одним пакетом без гарантії детермінованої TCP-семантики.

### P1. UI/UX та interaction primitives

- [ ] Спершу додати semantic status/tag tokens, accessible progress,
  toast service та versioned `uiPreferences`; не вводити docking раніше.

  > Пояснення: планується базова дизайн-система статусів, доступних прогресів і тостів перед будь-яким докуванням панелей.

- [ ] Додати shared action registry, right-click/keyboard context menu,
  conflict-free command palette і shortcut profiles.

  > Пояснення: планується єдиний реєстр дій з контекстним меню, палітрою команд і профілями шорткатів.

- [ ] Додати resizable Repeater split, Pretty/Raw/Hex, escaped syntax/JWT
  rendering, persistent visual diff і safe allow-listed DSL search.

  > Пояснення: планується регульований спліт Repeater, режими перегляду, підсвітка JWT і безпечний пошук за DSL.

- [ ] Додати OSINT graph/Findings Kanban, live activity bar та localization
  усіх dynamic states без color-only meaning.

  > Пояснення: планується Kanban для графа і findings зі стрічкою активності і повною локалізацією динамічних станів.

- [ ] Додати browser tests для layout persistence, keyboard operation,
  language switch, XSS/binary/malformed input, console та failed requests.

  > Пояснення: планується набір браузерних тестів на розкладку, клавіатуру, мови, биті входи і помилки запитів.

### P2. Collaboration, integrations та CLI/CI


- [ ] Додати fixture-only CI для checks/tests/E2E/SARIF validation; CI не
  запускає зовнішні active targets без isolated explicit configuration.

  > Пояснення: планується CI лише на фістурах без звернень до зовнішніх цілей, окрім явно ізольованої конфігурації.
# План TODO для розвитку RequestRider

> **Цей файл містить лише невиконаний беклог.** Виконані пункти прибрано для
> читабельності; історія виконаних робіт — у `DEVELOPMENT_LOG.md`, правила
> проєкту — в `AGENTS.md`. Кожен пункт вважається нереалізованим до повного
> проходження targeted/regression-перевірок і, для browser-facing змін, живого
> browser smoke-test.

Робота виконується малими ітераціями: кожна зміна має окремі критерії приймання,
міграційний/зворотно-сумісний шлях і тести до переходу на наступний пункт.

## Мета й підхід

Побудувати поетапний, перевірюваний план модернізації інфраструктури,
Go/browser workers, REST та OSINT-інтеграцій і наявної Automation.

## Перевірений стан проєкту (2026-09-28)

- `docker-compose.yml` містить вісім сервісів: `tor`, `engine`,
  `browser-worker`, `web`, `celery`, `engine-results`, PostgreSQL і **Redis**.
  RabbitMQ прибрано 2026-09-27 рішенням власника: Redis — єдиний брокер engine
  task transport.
- Брокерний шлях перевірений наскрізно **живим прогоном**:
  (Django → Celery → Redis → Go → Redis → PostgreSQL), сценарії success,
  redelivery без повторної зовнішньої
  дії, error, restart recovery, cancel, malformed dead-letter.
- PostgreSQL — єдиний рушій; інших рушіїв у коді й документації немає. Тестова
  база створюється з UTF-8 шаблону, і `core.test_runner` створює сам
  відсутній шаблон, тож `python manage.py test` зелена на новому кластері.
- Workflow має `Workflow` / `WorkflowRun` / `WorkflowNodeExecution`, JSON-поля
  для вузлів і зв’язків, канонізацію графа, перевірку циклів, типізований
  condition, schedule/webhook/manual triggers, SSE, журнал вузлів,
  cancel/pause/resume, JSON/Markdown export і project bundle. Runtime і
  scheduler лишаються process-local: після перезапуску незавершені запуски
  переходять у `interrupted`, а безпечні межі відновлюються з checkpoint-ів.
- Брокерні вузли workflow dispatch-яться лише за
  `WORKFLOW_ENGINE_BROKER_ENABLED=1` (Repeater `request.execute`, static Target
  `target.crawl`); для решти типів вузлів HTTP-шлях лишається default.
- `browser-worker/worker.py` має process-level Playwright runtime із
  кешованими browser processes, окремий `BrowserContext` на job, блокування
  image/font/media через `page.route()` і гарантоване закриття контекстів.
- Automation UI має власний canvas, palette та inspector. React Flow,
  Cytoscape.js і Monaco Editor — дозволений стек, але **не підключені**;
  підключення кожної — окреме рішення власника з умовою локально вендореного
  бандлу.

## Узгоджені межі та архітектурні рішення

1. Дотримуватись `AGENTS.md`. Заборона стосується **політик щодо цілей**, а явні
   технічні межі (таймаути, керована конкурентність, квоти, межі пісочниці)
   дозволені за умови, що вони видимі, перекриваються явним введенням і не
   звужують можливостей інструменту.
2. PostgreSQL є єдиною базою даних; Docker Compose — альтернативний спосіб
   розгортання, а не обов’язковий залежність застосунку.
3. **Redis — єдиний брокер**, транспорт не обирається. Старий `amqp://` падає з
   помилкою, що називає заміну. Go engine не йде через kombu: той обгортає
   повідомлення власним envelope, тож Go залежав би від фреймінгу чужого проєкту.
   Celery лишається на kombu.
4. **Nuclei v3 SDK — відхилено 2026-09-27, лишається керований binary runner.**
   SDK не має pause/resume, а `ExecuteCallbackWithCtx` відкидає помилку
   `ExecuteScanWithOpts`, тобто втрачаються exit status, stdout і stderr.
   Це послабило б явність помилок. Production dependency не додано:
   `engine/go.mod` не містить `projectdiscovery/*`.
5. REST API планувати як DRF endpoint/serializer contract; вибір API
   автентифікації відкладено і не вважається готовим до зовнішнього доступу.
6. Neo4j лишається feasibility-рішенням після вимірювання; міграцію не планувати
   без доказу, що реляційне сховище є вузьким місцем.
7. Тригери нотифікацій прив’язувати до `ScannerRun.findings`: модель `Finding`
   видалена міграцією `0037_delete_finding.py`.
8. `Source of truth` — `web/lab/models.py`; міграція обов’язкова на кожну зміну
   моделі. Усі 16 моделей мають читачів/письменників; мертвих таблиць і колонок
   немає (перевірено 2026-09-28).

## Детальний TODO

### Фаза 2. Go Engine

#### 2.1 Контрольована конкурентність — наступний

- Замінити неконтрольований спавн горутин на керований worker pool там, де
  фаза роздільняє великий словник на кандидатів. Зразок — `engine/burst.go`
  (`chan` + `sync.WaitGroup`) і вже реалізований DNS-bruteforce у
  `engine/osint_transforms.go`.
- Кожна межа має бути: (1) явним полем запиту або задокументованим default,
  (2) перекритною користувачем, (3) видимою в UI/рядку стану, (4) такою, що не
  відсікає жодну ціль, жоден обсяг і жодну глибину.
- Pause/Continue/Cancel має лишатися спостережним між кандидатами, а прогрес
  лишається справжнім лічильником, а не оцінкою UI.
- Межа захищає від завислої горутини й мертвого з’єднання, а не від великої
  роботи: будь-який словник і будь-яка глибина лишаються доступними.

**Приймання:** pool реально обмежує одночасні з’єднання, cancel/pause
спостережні між кандидатами, лічильник прогресу дорівнює фактично
обробленим, regression-тести доводять відсутність витоку горутин.

#### 2.3 HTTP client та context

- Аудит pooling завершено 2026-09-27: transport створюється на кожне route
  generation у `engine/routing.go`, і HTTP handler-и передають йому
  `s.requestTransport()`. Один глобальний `http.Client` окремий pool не усуне,
  а глобальний `Transport` суперечив би route generation, passive proxy
  (`DisableKeepAlives: true`) і raw Last-Byte.
- Реалізувати `context.WithTimeout` у функціях, що роблять зовнішні запити без
  явного cancellation path (`engine/osint_transforms.go`, archive-індекси,
  `engine/last_byte.go` за наявними полями). Кожен deadline — з явного поля
  запиту або задокументованого default, перекритий користувачем і видимий у
  статусі.
- Зберегти route/proxy/TLS/cancel поведінку; не вводити прихованих
  timeout/concurrency defaults. Додати regression-тести на відсутність витоку
  горутин.

**Приймання:** спільний transport не ламає route/proxy/TLS/cancel поведінку;
жодна зовнішня функція не лишається без cancellation path.

#### 2.4 Пасивна смуга збігів (`pkg/operators`)

- Імпортувати **вузький rung** `nuclei/v3/pkg/operators` (627 пакетів у графі).
  **Не** `pkg/templates` (1 801) і **не** `lib` (2 138): наш YAML-парсер
  перевірено на 40 000 реальних шаблонів із 0 хибних відмов.
- Переписати ~25 рядків `responseToDSLMap` (неекспортована в nuclei) — це єдина
  точка зв’язку з версією, її треба покрити тестом на ключі `status_code`,
  `body`, `all_headers`, `header`, `request`, `response`, `duration`,
  `content_length`, `host`, `matched`, `type`, `template-id`.
- Межа пам’яті: **вимогу `ExecutorOptions.DoNotCache = true` змінено 2026-09-29
  за виміром.** `protocols.ExecutorOptions` лежить у `pkg/protocols`, який **не**
  входить у граф 627 пакетів (`go list -deps` показує `pkg/operators` без
  `pkg/protocols`, `pkg/protocols/http` і `pkg/templates`). Тієї межі в цьому
  rung просто немає; натомість nuclei тримає власні процесні LRU-кеші
  (`pkg/operators/cache`), і ось вони є тим, у що корпус вростає. Керуються
  явно: `SetPassiveCompileCacheLimits(regexes, dsl)` + читне
  `PassiveCompileCacheLimit()`, дефолт 4096.
  **Виміряно на `~/.local/nuclei-templates` (13 764 файли, nuclei v3.11.1):**
  живий heap +**21.0 MB** без межі і **+1.2 MB** з межею 256 — тобто смуга
  корпус не тримає, а пік 79–503 MB керований **одним** шаблоном, а не
  кількістю: `wordpress-plugin-detect.yaml` (9.6 MB YAML) сам дає 356 MB
  піку. Тобто «пік не зростає з розміром батча» виконується, але пік задає
  найбільший шаблон у батчі, а не батч.
- Межі можливостей: лише `http`/`requests`/`file`-шаблони, чиї matchers є чистими
  функціями від (запит, відповідь). Без `code`, `javascript`, `headless`, `dns`,
  `network`, без payloads/fuzzing/clustering. TLS-матчери не працюватимуть, доки
  не переписано `enrichEventWithTLSMetadata`.
- **Правило «рівно один request-блок» додано 2026-09-29.** Перша версія
  відмовляла кожен шаблон з `internal: true` matcher — це виміряно хибно:
  `matcher.Internal` не читається ніколи в оцінці nuclei, лише у
  десериалізаторі flow (`pkg/tmplexec/exec.go`), тож смуга викидала 968
  справжніх шаблонів. Правильна причина — інша: два й більше request-блоків
  означають послідовність, а один збережений обмін не може сказати, який блок
  його породів. Виміряно: 10 896 шаблонів мають рівно один блок (79.3%).
- Це **окремий** шлях: без `exec.Command`, без процесу nuclei, без `SIGSTOP`.
  Не змінює `Start scan`, pause/resume, `-ms`-звіт чи розкладку інвокацій.

**Приймання (виміряно 2026-09-29):** офіційний корпус 13 764 файлів —
**9 962 (72.4 %)** смуга оцінює, кожну відмову називаючи причиною; нуль
запитів до цілі (`TestTheBandSendsNothingToTheTarget` рахує звернення до
живого listener'а); живий heap +1.2 MB на весь корпус.

### Фаза 3. Browser Worker

#### 3.2 Navigation timeout

- Блокування image/font/media виконано через `page.route()`; перевірка
  має охоплювати image/font/media та контрольний `document`.
- Додати `page.goto(..., timeout=...)` і navigation timeout у browser job, обидва
  з явного поля запиту або задокументованого default, перекриті користувачем і
  видимі в статусі job.
- Межа не має змінювати доступність цілей: будь-який target і будь-який
  navigation mode лишаються доступними.

**Приймання:** довгий navigation дає явну помилку з timeout у статусі job, а не
нескінченне очікування; будь-яка ціль і будь-який режим лишаються доступними.

### Фаза 3.1 Browser Worker

#### 3.1 Повернути привʼязку хоста до ендпоинта пула

- [ ] Повернути здатність «один хост — один вихід» (`ProxyPool.endpoint_for`).

  > Пояснення: вилучено 2026-10-04 за рішенням власника. Причина виміряна, а
  > не оцінена: у продукті не було **жодного** виклику, тобто здатність жила
  > лише у власних тестах, а поле `origins` у звіті обходу завжди було 0.
  > Зелений тест на непрацюючій функції доводить лише те, що функція написана.
  > Повертати варто разом із викликом у обході і разом із виміром на живій
  > цілі: один хост — стабільно одна адреса протягом усього обходу, два різні
  > хости — різні адреси. Реєстр звірки вже має рядок `не перенесено` із
  > причиною, а механічний гейт (`upstreams_reconciliation_test.go`) тепер
  > перевіряє символи й у шарі `browser-worker`, тому рядок не може
  > розійтися з кодом непомітно.

### Фаза 4. REST API та OSINT

#### 4.1 DRF API

- Підключити Django REST Framework і написати serializers/views для
  `ScannerRun`, workflow запуску та результатів, з перевіркою project context і
  стабільною формою помилок.
- Зберегти чинні JSON endpoints і session/CSRF-поведінку browser UI; визначити
  версіонування API та тести сумісності.
- Автентифікацію Token/JWT відкладено. Не вважати API готовим до зовнішнього
  доступу до вибору auth, перевірок авторизації та явного погодження exposure
  model.

**Приймання:** serializers/endpoints мають schema, validation, permissions tests
і не змінюють поточні API-контракти.

#### 4.2 OSINT enrichment

- Звірити `engine/osint_collector.go`, `web/lab/models.py` та поточний OSINT
  graph ingestion/upsert contract.
- Реалізувати provider interface для Shodan/Censys/VirusTotal; конкретні
  provider-и та необхідні поля/квоти погодити перед підключенням.
- Зберігати API credentials поза кодом і log-ами; описати opt-in, provider
  errors, duplicate/idempotent observations і provenance (provider, observed
  time, entity relation).
- Публікувати enrichment tasks через брокер; приймати та атомарно зберігати
  результати в Django, оновлювати project graph і повідомляти UI без блокування
  основного scan.
- Додати fixture-based tests без реальних зовнішніх credentials/API calls.

**Приймання:** entity та graph edges оновлюються повторювано, походження й
помилки збережені, секрети відсутні в логах, тести не звертаються до зовнішніх
мереж.

#### 4.3 Neo4j feasibility — decision gate

- Виміряти поточні OSINT graph query patterns, обсяги, індекси та latency.
- Порівняти реляційну модель з Neo4j на репрезентативному локальному dataset;
  оцінити backup/export, транзакційність, deployment/Compose та складність
  dual-write.
- Міграцію планувати лише якщо benchmark підтвердить, що реляційна БД є
  bottleneck; до цього PostgreSQL лишається authoritative store.

### Фаза 5. Scripting та notifications

#### 5.1 Webhooks та notifications

- Додати Django notifications models/configuration для destination, event types,
  severity threshold, active state та пов’язаного Project.
- Тригер — `ScannerRun.findings` (модель `Finding` видалена міграцією
  `0037_delete_finding.py`); порівнювати severity за фактичними полями nuclei
  findings.
- Створювати notification job лише після commit транзакції
  (`on_commit`/outbox), щоб не губити повідомлення й не надсилати їх для
  відкотених змін.
- Celery task надсилає JSON payload до налаштованого webhook; визначити формат,
  delivery status, retry policy, redaction, duplicate handling та історію помилок.
  Секрети destination зберігати безпечним способом і не логувати headers/token/body.
- Додати local fixture receiver для Slack/Telegram/Discord-сумісних payloads,
  unit/integration tests та UI керування після погодження UX.

**Приймання:** критична знахідка створює одну відтворювану async notification;
недоставка видима в журналі, чутливі поля редагуються, тести не звертаються до
зовнішніх мереж.

### Фаза 6. Automation до надійного DAG runtime

#### 6.1 Зміцнити наявний graph contract

- Не створювати дублюючу `WorkflowDefinition` чи `ExecutionLog` таблиці:
  `Workflow.nodes/connections` та `WorkflowRun` уже зберігають канонічний граф і
  execution history.
- Уточнити JSON schema/versioning для nodes, edges/connections, params та node
  output; версіонування вже зберігається в `graph_schema_version` із міграцією
- Додати targeted tests на unknown nodes, duplicate IDs, invalid handles, cycles,
  disconnected branches, malformed params і graph import.
- Зберегти `WorkflowRun` як execution log і durable node checkpoints з
  input/output, started/finished state та resume cursor для broker-based resume.

**Приймання:** невідома версія схеми відхиляється явно, старі графи читаються як
v1, checkpoints переживають restart без повторного зовнішнього виклику.

#### 6.2 Оркестрація, черга та відновлення

- Додати node executor registry / спільний `BaseNode`-подібний interface для
  валідації, виконання, нормалізації output і явної помилки; адаптувати
  поточні node runners без зміни публічних параметрів.
- Для Go-bound вузла записувати checkpoint і task correlation до publish;
  переводити `WorkflowRun` у durable waiting state, не утримуючи Django thread.
- Outcome consumer перевіряє correlation/idempotency, зберігає output і
  відновлює наступні вузли. Повторний результат не має запускати наступну ноду
  вдруге.
- Відновлювати queued/running/waiting runs після restart; не позначати живі
  broker-backed задачі `interrupted` лише через перезапуск web process.
- Зберегти умову/розгалуження, branching output, merge semantics, cancel,
  pause/resume, SSE, export/import, manual/schedule/webhook triggers і project
  context.

**Приймання:** сценарій Trigger → OSINT/Subdomain Engine → Scanner/Nuclei →
Condition → Notify проходить із broker result/resume, execution history
відновлюється після Django restart, duplicate events не створюють повторних дій.

#### 6.3 Automation editor та дебаг-інструменти

- Вендорити React Flow як локальний бандл і підключити лише на canvas
  Automation. Без CDN, без зовнішніх fetch, без повного frontend build.
- Зберегти node palette, connections, inspector, локалізацію, клавіатурну
  доступність та поточний API. Додати node run state, queued/waiting
  checkpoint, output/error inspector, retry/resume та execution timeline після
  готовності backend API.
- Перевірити draft/save/import/export, reload/persistence, branch display,
  SSE/reconnect та помилки на живому браузері; не змінювати наявні UI патерни
  поза потрібним Automation flow.

**Приймання:** оператор бачить для кожної ноди стан і безпечний JSON output,
може відрізнити помилку/очікування/завершення, а reload/reconnect не губить
стан виконання.

### Фаза 7. Завершення кожної ітерації

- Додавати targeted тести поряд зі зміненими модулями, міграційні тести на
  PostgreSQL, broker contract tests і failure/restart tests.
- Запускати застосливі перевірки з `AGENTS.md`: Django `check` і tests, Go
  `go test ./... -count=1` і `-race`, `git diff --check`; browser-facing зміни
  також перевіряти живим браузером, включно з console/network та persistence.
- Оновлювати україномовні `README.md`, відповідні довідники та
  `DEVELOPMENT_LOG.md`; не позначати пункт завершеним до проходження критеріїв.
- Дотримуватись «Гарбейж-колектор: прибирання мертвого»: усе, що завів ця
  ітерація і більше не працює, прибирається з доказом мертвості.

## Основні залежності

- Фаза 2.1 → 2.3 → 2.4: керована конкурентність задає каркас, у якому
  deadline-и й passive-смуга отримують ту саму семантику checkpoint-ів.
- Брокерна інфраструктура вже готова, тому 4.2 і 5.1 спираються на неї без
  додаткової роботи над чергою.
- DRF serializers можуть розроблятися окремою ітерацією; зовнішня публікація
  блокується до рішення з автентифікації.
- Neo4j — лише benchmark/decision після оптимізації та вимірювання PostgreSQL.
- React Flow підключається після того, як backend API для 6.3 буде готовий:
  інакше редактор отримає поля, яких ще немає в contract.
