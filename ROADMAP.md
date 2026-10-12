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

- [ ] Замінити truncating fingerprint на stable evidence-aware identity та
  idempotent upsert для повторного Save.

  > Пояснення: планується стабільний ідентифікатор finding за evidence, щоб повторне збереження оновлювало запис, а не створювало дублікат.


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


### Фаза 3. Browser Worker

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

- Фаза 2.1 → 2.3: керована конкурентність задає каркас, у якому
  deadline-и отримують семантику checkpoint-ів (пасивну смугу 2.4 закрито 2026-09-29).
- Брокерна інфраструктура вже готова, тому 4.2 і 5.1 спираються на неї без
  додаткової роботи над чергою.
- DRF serializers можуть розроблятися окремою ітерацією; зовнішня публікація
  блокується до рішення з автентифікації.
- Neo4j — лише benchmark/decision після оптимізації та вимірювання PostgreSQL.
- React Flow підключається після того, як backend API для 6.3 буде готовий:
  інакше редактор отримає поля, яких ще немає в contract.
EXEC_MODE=AGENTS_MD_STRICT

AGENTS.md: застосовано пункти 0, 1, 2, 3, 4, 7, 8, 10, 11, 12, 16, 17.

---

### ФІКСАЦІЯ ПЛАНУ (Етап 3 і 4 за AGENTS.md)

```
ЦЕЛЬ:
Провести пріоритизацію всіх відкритих завдань з ROADMAP.md за ступенем критичності та важливості впровадження «тут і зараз», враховуючи архітектурні залежності, ризики цілісності даних, стабільність рушія та наявний фундамент кодової бази.

РАЗРЕШЁННЫЕ ФАЙЛЫ:
- Жодних (завдання є аналітичною експертною оцінкою та побудовою плану впровадження).

ЗАПРЕЩЁННЫЕ ФАЙЛЫ:
- Усі файли проекту захищені від несанкціонованих змін.

ПЛАН:
1. Проаналізувати всі невиконані завдання з очищеного ROADMAP.md.
2. Розподілити завдання за 4 рівнями пріоритету:
   - Рівень 1: Блокуючий фундамент та цілісність даних (P0 / «Тут і зараз»).
   - Рівень 2: Надійність виконання та виявлення загроз (P1 / Найближчі ітерації).
   - Рівень 3: Продуктивність оператора та інтерфейсні примітиви (P1-P2 / UX-шар).
   - Рівень 4: Спеціалізовані протоколи, зовнішні інтеграції та експерименти (P2-P3 / Довгостроковий беклог).
3. Для кожного завдання надати: технічне обґрунтування «чому саме зараз», ризики відкладання та залежності.
4. Скласти покроковий план черговості взяття в роботу перших 3 завдань.

ОБЯЗАТЕЛЬНЫЕ ПРОВЕРКИ:
- Відповідність архітектурним рішенням у ROADMAP.md (Redis єдиний брокер, Postgres єдина БД, заборона прихованих лімітів).
- Відповідність інваріантам безпеки та цілісності даних.

ОЖИДАЕМЫЙ РЕЗУЛЬТАТ:
Чітка, інженерно обґрунтована черга впровадження завдань із ROADMAP.md.

ОГРАНИЧЕНИЯ:
- Тільки українська мова.
- Жодних змін файлів без прямої команди.
```

---

## ПРІОРИТИЗАЦІЯ ЗАВДАНЬ З ROADMAP.MD («ТУТ І ЗАРАЗ»)

Пріоритизація побудована за інженерним принципом **Data Integrity & Runtime Stability First**: не можна надбудовувати складні сканери, воркфлоу чи протоколи над системою, де трафік різних проектів перемішується, горутини ризикують підвиснути при затримках мережі, а профілі сканування є лише декоративними текстовими метаданими.

---

### 🔴 РІВЕНЬ 1: БЛОКУЮЧИЙ ФУНДАМЕНТ І ЦІЛІСНІСТЬ ДАНИХ (P0 — «ВПРОВАДЖУВАТИ ЗАРАЗ»)

Ці 4 завдання є базовими інваріантами безпеки, без яких результати роботи інших модулів є ненадійними або можуть змішуватися між цілями:

#### 1. Наскрізна project-ізоляція даних (Session/workspace)
* **Що зробити**: Розв'язати жорстку прив'язку всього проксі-трафіку, історії, Repeater, Intruder та снапшотів до єдиного глобального активного проекту в браузері. Ввести явний `project_id` у контекст кожного запиту та сесії.
* **Чому зараз**: Якщо оператор досліджує декілька цілей або перемикає проект, трафік і сесійні дані змішуються. Це ризик витоку конфіденційних даних клієнтів/цілей і некоректних звітів.
* **Ризик відкладання**: Чим більше інструментів підключається до брокера та сховища, тим складніше пізніше розділяти монолітний потік трафіку.

#### 2. Повний cancellation path та `context.WithTimeout` у Go Engine (Фаза 2.3)
* **Що зробити**: Гарантувати, що **кожна** функція, яка здійснює зовнішні мережеві запити (архівні індекси, OSINT-трансформи, сканери), має контекст із дедлайном, керованим параметрами запиту або задокументованим значенням за замовчуванням, і коректно реагує на переривання клієнтом.
* **Чому зараз**: Поточний рушій може накопичувати підвислі горутини при «мовчазних» або повільних з'єднаннях цілі, блокуючи сокети та воркерів.
* **Ризик відкладання**: Падіння продуктивності, споживання дескрипторів сокетів і неможливість гарантованого скасування завдань.

---

### 🟡 РІВЕНЬ 2: НАДІЙНІСТЬ РАНТАЙМУ ТА РОЗШИРЕННЯ АНАЛІЗУ (P1 — НАСТУПНИЙ КРОК)

Завдання, які розширюють практичну здатність інструменту виявляти вразливості та автоматизувати ланцюжки:

#### 3. Повні DNS records (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA) та Wildcard DNS detection (OSINT)
* **Що зробити**: Об'єднати можливості `routeResolver` ([dns_route.go](file:///home/kali/Downloads/Request-Rider%20v1.2/engine/dns_route.go)) у повноцінний трансформ, що збирає всі типи записів, явно повідомляє про відсутність кожного типу та обов'язково перевіряє випадкові піддомени на wildcard-відповідь перед запуском брутфорсу.
* **Чому важливо**: Без wildcard-детекту брутфорс піддоменів породжує тисячі хибних сутностей на доменах із налаштованим `* -> IP`.

#### 4. Повернення `ProxyPool.endpoint_for` (Фаза 3.1 Browser Worker)
* **Що зробити**: Повернути здатність «один хост — один вихід» у [proxy_pool.py](file:///home/kali/Downloads/Request-Rider%20v1.2/browser-worker/proxy_pool.py) разом із прямим викликом у циклі обходу та вимірюванням на живій цілі.
* **Чому важливо**: Браузерний обхід без affinity хоста постійно стрибає між різними IP-адресами, що викликає розрив cookie/сесії або блокування WAF під час авторизованого обходу.

#### 5. Брокерна оркестрація та стійке відновлення DAG-вузлів (Фаза 6.2 Automation)
* **Що зробити**: Забезпечити переведення `WorkflowRun` у довговічний стан очікування (durable waiting) при відправці задач у Go через Redis, щоб рестарт веб-процесу не переводив активні брокерні задачі в статус `interrupted`.
* **Чому важливо**: Робить можливими довгі автоматизовані ланцюжки (Recon → Scanner → Condition) без ризику втрати прогресу при оновленні чи перезапуску веб-сервера.

#### 6. Вихідні Webhook-сповіщення на знахідки ScannerRun (Фаза 5.1)
* **Що зробити**: Створити Celery-задачу через `transaction.on_commit` для відправки JSON-пейлоадів у зовнішні системи (Slack/Telegram/вебхуки) при появі знахідок вище заданого порогу severity.

---

### 🟢 РІВЕНЬ 3: ПРОДУКТИВНІСТЬ ОПЕРАТОРА ТА РОБОЧИЙ ПРОСТІР (P2)

Покращення щоденної роботи дослідника в інтерфейсі:

#### 7. Repeater: режими Pretty/Raw/Hex, візуальний diff та рендеринг JWT
* **Що зробити**: Додати в Repeater зручні вкладки перегляду відповідей (структурований, сирий, шістнадцятковий), порівняння двох відповідей (visual diff) та розбір JWT токенів у заголовках.

#### 8. Розширення Command Palette та єдиний Action Registry
* **Що зробити**: Перетворити палітру команд із простого перемикача вкладок на єдиний реєстр дій (швидкий запуск сканування, копіювання cURL, очищення сесії, налаштування проксі).

#### 9. Версіоновані налаштування `uiPreferences`
* **Що зробити**: Зібрати всі розпорошені значення `localStorage` (розміри сплітів, розкладка, видимі колонки) в єдину валідовану структуру з номером схеми та міграціями.

#### 10. GHDB link generator та dedicated paste lookup (OSINT)
* **Що зробити**: Додати генерацію цільових посилань на Google Dorks для домену/хоста та перевірку публічних paste-сервісів.

---

### ⚪ РІВЕНЬ 4: СПЕЦІАЛІЗОВАНІ ПРОТОКОЛИ ТА ЕКСПЕРИМЕНТИ (P3 — ДОВГОСТРОКОВО)

Завдання, які потребують окремих значних досліджень або зовнішніх платних залежностей:

* **Протокольні розширення**: WebSocket capture/replay, gRPC .proto introspection, H3/QUIC.
* **H2 single-packet experiment**: експеримент відправки пакетів без гарантії семантики одного TCP-сегмента.
* **OpenAPI/Postman імпорт та GraphQL інтроспекція**: конвертація API-специфікацій у граф атак.
* **Платні OSINT-інтеграції**: Shodan/Censys платні API (наразі відхилено на користь локальних та безкоштовних джерел).
* **Neo4j міграція**: відкладено до моменту, поки PostgreSQL справляється з навантаженням графів.

---

## ПОТОЧНИЙ СПРИНТ (ТОП-3 «ТУТ І ЗАРАЗ»)

1. [x] **Крок 1**: **Поведінкові відмінності профілів сканера + wappalyzergo** ([main.go](file:///home/kali/Downloads/Request-Rider%20v1.2/engine/main.go)) — реалізовано профілі з бюджетами зондувань та пряму інтеграцію wappalyzergo.
2. [x] **Крок 2**: **Stable evidence-aware identity знахідок та ідемпотентний upsert** ([models.py](file:///home/kali/Downloads/Request-Rider%20v1.2/web/lab/models.py), [views.py](file:///home/kali/Downloads/Request-Rider%20v1.2/web/lab/views.py)) — впроваджено `compute_finding_identity` та `upsert_findings` для `ScannerRun`.
3. [ ] **Крок 3**: **Wildcard DNS detection + повні DNS-записи** ([osint_transforms.go](file:///home/kali/Downloads/Request-Rider%20v1.2/engine/osint_transforms.go), [dns_route.go](file:///home/kali/Downloads/Request-Rider%20v1.2/engine/dns_route.go)) — захищає OSINT-граф від засмічення фіктивними піддоменами при подальшій роботі.

