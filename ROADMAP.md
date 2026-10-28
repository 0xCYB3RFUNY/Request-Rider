# Roadmap RequestRider

## Статус roadmap та архітектурне позиціонування

> **Архітектурне позиціонування:** Request-Rider є **автономним локальним інструментом тестувальника/пентестера** для роботи безпосередньо на робочій станції (single-user local security tool). Застосунок не є SaaS/хмарним багатокористувацьким сервісом і не потребує складних multi-tenant ізоляцій, розподілених кластерів або зовнішніх важких СУБД.
> **Головні інженерні пріоритети:** максимальна локальна швидкодія (Zero-lag UI), ощадне споживання пам'яті (RAM) та CPU на машині тестувальника, швидкість обробки великих масивів трафіку/пейлоадів та надійність локального браузерного флоту.

Цей файл містить лише невиконаний backlog (`[ ]`). Виконані пункти видалено
для читабельності; історія виконаних робіт зберігається в
`DEVELOPMENT_LOG.md`. Кожен пункт backlog вважається нереалізованим до повного
проходження targeted/regression тестів і browser smoke-test.

Під кожним пунктом курсивом додано коротке пояснення запланованої фічі.

## Перевірено та вилучено з backlog (оновлено 2026-10-26)

Розбір backlog проведено по коду, а не за текстом: кожен знятий пункт має
доказ (файл, рядок або команда). Список наведено тут, щоб наступна сесія не
витрачала час на повторну перевірку.

| Знятий пункт | Доказ реалізації |
|---|---|
| Поведінкові профілі сканера з окремими бюджетами + `wappalyzergo` | `engine/go.mod:13`, `engine/main.go:2440-2444` (`wappalyzerClient`), `web/lab/views.py:3840,6198` (`profile` у payload/params) |
| Stable evidence-aware identity знахідок та ідемпотентний upsert | `web/lab/models.py:323` `compute_finding_identity`, `web/lab/models.py:387-409` `ScannerRun.upsert_findings`; виклики `web/lab/active_scanner_views.py:337-400`, `web/lab/agent_tools.py:380-420` |
| Email/username recon, paste/breach lookup, GHDB link generator, GitHub public metadata | `engine/osint_transforms.go:112` `email_recon`, `:121` `username_search`, `:127` `ghdb_links`, `:160` `breach_exposure`, `:1430` сутність `username` із provenance `github_public_api` |
| Повні DNS-записи A/AAAA/CNAME/MX/NS/TXT/SOA/CAA + wildcard detection | `engine/osint_transforms.go:2040-2090` (A/AAAA, CNAME, MX, NS, TXT, SOA, CAA з explicit errors), `:3520` `detectWildcardDNS` + `:4569` окремий probe |
| Host affinity `ProxyPool.endpoint_for(url)` у browser-worker | `browser-worker/proxy_pool.py`, виклик у crawl_worker |
| Керована конкурентність у DNS/bucket брутфорсі та Repeater Burst | `engine/osint_transforms.go:4611-4624` (`bruteForceSubdomains`, worker queue), `:921-947` (`checkBucketCandidates`), `engine/burst.go:148-160` (батчі по `Concurrency` + `WaitGroup`) |
| Версіоновані налаштування `uiPreferences` | `web/templates/lab/index.html:13711` `migrateUIPreferences`, snapshot/валідація |
| Semantic status/tag tokens, accessible progress, toast service | токени в `:root`, `.scanner-progress-*` (з `percent == -1`), `.toast` з `toast-success|warning|error` |
| Right-click/keyboard контекстне меню рядка | `web/templates/lab/index.html:2196` `#ctx-menu role="menu"`, openRowMenu, делегування по `data-ctx-*` |
| H2 single-packet як manual-only експеримент | `engine/last_byte.go:399-401` — весь HTTP/2 burst пишеться одним user-space буфером; детермінованого one-packet delivery не заявляється |
| Registry node-екзекуторів workflow | `web/lab/workflow_engine.py:1223-1236` `node_executors`, `:1632` resolve за типом |
| Брокерна оркестрація і durable checkpoint вузлів | `web/lab/engine_broker.py:94` `EngineTaskDeferred`, `:210` відкладення, `:308-333` idempotent-відновлення за checkpoint; `web/lab/workflow_engine.py:1965-2008` `_recover_interrupted` |
| Вихідні webhook-сповіщення на workflow-тригери | `web/lab/workflow_engine.py:64,196` тип вузла `webhook_trigger`, `ALL /api/workflows/hooks/<slug>` |
| ~~Target: вікно з двома рівними запитами (клік по рядку / пункт у kebab `⋯`)~~ | **Знято рішенням оператора 2026-10-16**, до реалізації не дійшло. Готовий тригер при цьому лишається валідним для майбутніх правок: пункт у kebab `⋯` / right-click меню `#ctx-menu` для таблиці Target вже існує |
| **N5. Пауза і продовження для активного сканера та краулера Target** (знято 2026-10-22) | `engine/pkg/runstate/` (`Gate`, `ErrPaused`), `engine/scanner_active.go` (`POST /api/scanner/active/<id>/control action=pause|resume`), `engine/main.go:3018` (`POST /api/target/map/<id>/control action=pause|resume`), тести `engine/scanner_active_pause_test.go`, `engine/target_map_pause_test.go` |
| **N6. Переотправка невідправлених запитів + детектор обриву** (знято 2026-10-22) | `engine/pkg/runstate/` (`Ledger`, `ClassifyTransportError`, `Streak`, `DefaultFailurePause = 20`), автоматична зупинка на стрику відмов, `POST /api/scanner/active/<id>/resend`, тести `TestTheAutomaticPauseFiresOnAStreakOfTransportFailures`, `TestResendReissuesOnlyTheRequestsThatNeverAnswered` |
| **N7. Збереження стану і прогресу з відновленням фронтиру** (знято 2026-10-22) | `runstate.Checkpoint` у `ActiveScanJob` та `TargetJob`, серіалізація фронтиру, звіт причин відмов, відновлення з checkpoint без втрати черги у `engine/scanner_active.go` та `engine/main.go` |
| **N3. Антидект у кожному інструменті та прибирання `RequestRider-*` з UA** (знято 2026-10-22) | Ротація `RandomUserAgent()` у `UserAgent.txt` для всіх інструментів: `engine/user_agents.go`, `engine/pkg/active/user_agents.go`, `engine/pkg/scanner/user_agents.go`, `engine/anti_detect.go`, `engine/main.go` (route-check, scanner, osint). Вилучено `RequestRider` із UA. Тести `corpus_user_agent_test.go`, `osint_archive_test.go`, `anti_detect_test.go` |
| **N8. Zero-lag Navigation & Модульний розпил `index.html`** (знято 2026-10-22) | `web/templates/lab/tabs/` (`_projects.html`, `_proxy.html`, `_repeater.html`, `_intruder.html`, `_target.html`, `_osint.html`, `_scanner.html`, `_comparer.html`, `_decoder.html`, `_ai.html`, `_automation.html`, `_history.html`, `_traffic.html`); `content-visibility: hidden` для `.tab`, коалесценція `pendingWorkspaceRestoreFrame` з `cancelAnimationFrame`, `requestAnimationFrame` для `applyOverlayEdges`, безпечний debounce 600мс з `requestIdleCallback` для `persistWorkspaces`; регресійні тести `lab.test_api_contract` (57/57 OK) |
| **N2. Шестерня налаштувань у вкладках (Tab Settings Gear)** (знято 2026-10-26) | `uiPreferences v2` схема з міграцією, CSS custom properties теми (Default, Burp, Cyberpunk, Monokai, High Contrast), кастомний DNS & DoH, інлайн-перейменування табів (двоклік/F2), уніфікований діалог `_tab_settings_dialog.html`, Command Palette `Ctrl+K`, повна UA/EN локалізація, тести `test_tab_settings` (64/64 OK), browser E2E smoke test (0 помилок) |
| ~~Shared action registry та розширені shortcut profiles~~ | **Знято рішенням оператора 2026-10-26**, окремий Action Registry визнано надлишковим: базової Command Palette `Ctrl+K` та прив'язки дій у `#ctx-menu` достатньо |

**Виправлення суперечностей у самому файлі (2026-10-16).**

- Раніше блок «P1. OSINT Entity Graph» стверджував, що canvas реалізовано на
  **React Flow**. Виміряно: `grep -c reactflow web/templates/lab/index.html` → **0**,
  вендореного бандлу React Flow у `web/static/vendor/` немає. Підключено
  **Cytoscape.js 3.33.1** (`:3237` `<script src="/static/vendor/cytoscape-3.33.1.min.js" nonce>`,
  `:16143` і `:16803` ініціалізація canvas OSINT-графа). React Flow, Cytoscape для
  Automation і Monaco Editor **не підключені**; Automation canvas — власний.
- Раніше «Перевірений стан проєкту» стверджував, що React Flow/Cytoscape/Monaco
  «не підключені». Cytoscape підключено, решта — ні.

## Automation / Workflows

Поточний runtime є process-local і оптимізований для локального запуску на хості.
Брокерна частина працює через локальний Redis, Celery publisher, Go consumer і Django
result persistence.

### Наступні ітерації

- [ ] Додати server-backed `WorkflowTemplate` CRUD, community manifests,
      schema signing та import preview.

  > Пояснення: планується серверне сховище шаблонів workflows з підписом схем і попереднім переглядом імпорту, замість лише локального каталогу. Моделі `WorkflowTemplate` у `web/lab/models.py` немає.

- [ ] Додати Nuclei/Postman converters лише після canonical graph validation.

  > Пояснення: планується конвертація Nuclei/Postman у канонічний граф RequestRider, але тільки після готової серверної валідації графа. Наразі нормалізація є лише для n8n-стилю (`web/lab/workflow_engine.py:526-575`).

## Session/workspace

<!-- Project isolation та versioned uiPreferences завершено / знято рішенням оператора -->

## Accessibility

<!-- Окремих невиконаних пунктів немає: точки перевірки a11y вбудовані в кожен пункт
     backlog (focus-visible, aria-pressed/haspopup, контраст токенів). -->

## Scanner та Findings

<!-- Обидва пункти цього розділу реалізовано 2026-10-16 перевіркою коду —
     див. таблицю «Перевірено та вилучено з backlog». Пункт про поведінкові профілі
     закритий `wappalyzergo` + бюджетами зондувань, пункт про stable identity —
     `compute_finding_identity` / `upsert_findings`. -->

## Нові пункти (2026-10-22)

### N1. Локальна модель ембеддингів EmbeddingGemma (On-Demand аналіз аномалій та ендпоінтів)

- [ ] Інтегрувати **EmbeddingGemma** (Google DeepMind, `google/embeddinggemma-300m`,
      308M параметрів, побудована з Gemma 3) як локальний он-деманд ембеддер — без
      зовнішнього API-ключа, без CDN і без постійного споживання пам'яті в простої.

  > Пояснення: модель призначена саме для on-device роботи: 308M параметрів,
  > < 200 MB RAM у квантизації (Q4/Q8), контекст 2K токенів, розмірність вектора
  > 768 з Matryoshka-варіантами 256/128, 100+ мов. Локальний запуск через Ollama
  > (`ollama pull embeddinggemma`, `keep_alive: 60s`, `POST /api/embed`) або
  > llama.cpp (`ggml-org/embeddinggemma-300M-GGUF`). Ліцензія — Gemma Terms of Use.

  **Фокусні сфери застосування (де ембеддинги дійсно ефективні):**
  1. **Intruder Outlier Detection:** автоматичне виявлення семантичних аномалій
     у фазингу. Замість ненадійного побайтового `Content-Length` та статус-кодів
     (які часто спотворюються CSRF-токенами, таймстемпами або WAF), обчислюється
     косинусна відстань відповідей до baseline-відповіді. Відповіді з аномальним
     змістом (інший стек-трейс, обхід авторизації, прихований витік даних)
     автоматично маркуються високим `Anomaly Score` і піднімаються вгору таблиці.
  2. **Target Juiciness Triage:** автоматичне ранжування та категоризація
     знайдених краулером (Katana / Browser-worker) та JS-аналізатором ендпоінтів
     і параметрів за семантичною близькістю до словника критичних цілей
     (`admin`, `debug`, `upload`, `auth/token/reset`, `impersonate`, `webhook`).
     Оператор одразу отримує шортлист найбільш цікавих векторів атаки.

  **Відкинуто як неефективне:**
  - Семантичний пошук по сирій історії History/Traffic: у реальному пентесті
    пошук ведеться за точними детермінованими полями (статус, метод, хост, regex),
    де `PostgreSQL GIN / pg_trgm` чи `ILIKE` працюють швидше і без витрат RAM.

  **Під питанням (backlog-кандидат):**
  - Семантична дедуплікація та root-cause групування звітів сканера: відкладено,
    оскільки більшість знахідок уже структурується за `template_id` / `cwe`,
    а обсяг звітів зазвичай переглядається оператором вручну.

  **Вимоги до пам'яті та ресурсів:**
  - **On-Demand Lifecycle:** модель вивантажується з оперативної пам'яті
    після завершення пакетного аналізу (`keep_alive: 60s` в Ollama / тимчасовий
    процес); у режимі простою споживання RAM = 0 MB.
  - **Matryoshka 128 / 256 dim:** зрізання вихідного вектора до 128/256 значень
    заощаджує базу даних (512 байт на вектор) і дозволяє рахувати косинусну
    подібність у пам'яті Django за кілька мілісекунд без сторонніх бібліотек.
  - **Сховище векторів:** `bytea` або `jsonb` у PostgreSQL без обов'язкової
    прив'язки до `pgvector`.

### N4. Тест нашого MCP на локальних моделях Ollama

- [ ] Прогнати `request-rider-mcp` з **локальними моделями Ollama** як мозком
      агента і зафіксувати вимірюваний результат.

  > Пояснення: MCP-інструменти вже проганялися прямими HTTP-викликами без LLM
  > (`/tmp/opencode/agent-combat-mcp4.py`, 11/11 завдань), тобто протокол MCP
  > і поведінку локальної моделі **не перевіряли взагалі**. Стан на машині:
  > `which ollama` → not found, `ss -tln | grep 11434` → порт вільний,
  > локальних моделей немає.

  **Обсяг (що саме перевіряється):**
  - підняти локальний Ollama без системного сервісу (тимчасовий каталог,
    `OLLAMA_HOST=127.0.0.1`), витягнути модель із tool-calling
    (`qwen3` або `llama3.1` — Ollama приймає `tools` у `/v1/chat/completions`);
  - підключитися до `request-rider-mcp/server.py` **реальним MCP-клієнтом**
    через stdio (JSON-RPC), а не HTTP-шимом: інакше перевіряється не MCP;
  - прогнати ReAct-цикл «модель → `tools/list` → виклики інструментів →
    підсумок» на тих самих завданнях, що й бойовий прогін (project
    list/switch, history read, raw send, target crawl, OOB, scanner), щоб
    результати були порівнянні;
  - стенд — **ізольований** за правилом «Тести своего коду — в ізольованій
    середовищі»: окремий checkout, окремі `POSTGRES_DB` і `data/`, власні
    порти (`RR_GATEWAY_URL`, `RR_ENGINE_URL`, `RR_WORKER_URL`), жодного
    `pkill` за шаблоном імені.

  **Артефакт і приймання:** у репозиторії лишається таблиця вимірів (% завершених
  завдань, кроків на завдання, час, помилки формату відповіді, кількість
  некоректних аргументів інструментів) і транскрипт одного повного циклу;
  стенд, Ollama та браузери гасяться **по записаним PID**; результат порівнюється
  з минулим бойовим прогоном (100 % на прямих HTTP-викликах).

  **Побічний дефект, який закривається тут:** `request-rider-mcp/README.md`
  заявляє, що сервер потребує лише стандартної бібліотеки
  (`json`, `sys`, `os`, `urllib`, `base64`, `ssl`), але `server.py` імпортує
  `mcp.server.mcpserver` і `httpx` (і це підтверджено `requirements.txt`).
  Документація й код мають описувати одну реальність.

## Стратегічний backlog, узгоджений 2026-09-24

Цей backlog виникає з аудиту поточного коду, а не з припущень про наявність
функцій. Він виконується залежно від security/data foundation; один пункт за
раз проходить targeted tests, regression suite та live browser smoke-test.

### P1. OSINT Entity Graph та local transforms

<!-- Email/username recon (`email_recon`, `username_search`), breach-lookup
     (`breach_exposure`), GHDB link generator (`ghdb_links`) і GitHub public
     metadata реалізовані — див. таблицю «Перевірено та вилучено з backlog».
     DNS-записи A/AAAA/CNAME/MX/NS/TXT/SOA/CAA з explicit errors і wildcard
     DNS detection реалізовано в Go Engine. -->

Canvas OSINT-графа реалізовано на **Cytoscape.js 3.33.1** — локально
вендорений бандл `web/static/vendor/cytoscape-3.33.1.min.js`, без CDN і зовнішніх
fetch. Bounded 1000-node budget, keyboard-accessible DOM-вузли та відсутність
color-only значень збережені. **React Flow не підключено**, і підключення
Canvas Automation залишається окремим backlog-пунктом (див. Фаза 6.3).

**Референси архітектури:** [Argus](https://github.com/cotcollective/argus) (MIT,
local-first modules), [Flowsint](https://github.com/reconurge/flowsint)
(Apache-2.0, graph/enricher ideas), [Osiris](https://github.com/simplifaisoul/osiris)
(MIT, live activity/UI ideas). Argus не робить запити приватними: локальним є
виконання, але public endpoints/websites всё одно бачать запит. Код сторонніх
проєктів не копіювати без окремого license/NOTICE audit.

### P1. OSINT → Scanner pipeline

- [ ] Додати data-only scanner template schema до YAML preview. Виняток,
      sanctioned 2026-09-25 власником: дозволено обмежене HTTP-only виконання
      Nuclei-подібних шаблонів (request + matchers status/words/regex, без коду
      і shell); див. `engine/pkg/scanner` і `DEVELOPMENT_LOG.md`.

  > Пояснення: планується data-only схема шаблонів сканера без коду і shell; виняток — обмежене HTTP-виконання Nuclei-подібних matchers за ENV-бюджетами. Термін «data-only» у коді відсутній (`grep -rn "data-only" engine/pkg/scanner → 0`).

- [ ] Додати **clustering-based** context-aware mutations та adaptive
      429/503 backoff у активний сканер.

  > Пояснення: кластеризація базових відповідей і мутації залежно від кластера
  > ще не реалізовані (`grep -rn "cluster" engine/pkg/active → 0`,
  > `grep -rn "Retry-After" engine/pkg/active → 0`). Bounded OAST уже є
  > (`engine/pkg/active/detect_out_of_band.go`), browser-rendered evidence теж
  > (`engine/pkg/active/browser.go`), тому лишилися саме кластеризація і backoff.

### P1. Automation, SessionMacro та API security

- [ ] Додати AttackChain/AttackStep/evidence provenance після stable IDs;
      не перевикористовувати execution DAG як semantic security graph.

  > Пояснення: планується семантичний граф ланцюжка атаки з provenance evidence, окремо від технічного DAG виконання. Моделі `AttackChain`/`AttackStep` у `web/lab/models.py` немає.

### P1. Protocols, client-side та API security

- [ ] Додати protocol metadata і local H2 fixture/TLS tests до WebSocket,
      gRPC/Protobuf, H3/QUIC та frame-level features.

  > Пояснення: планується метадані протоколів і локальні фікстури для WebSocket, gRPC, H3/QUIC з тестами TLS. Спеціального коду цих протоколів у `engine/` немає.

- [ ] Додати WebSocket capture/replay, gRPC `.proto`/`.desc` introspection і
      bounded binary mutations; raw bytes і metadata мають залишатися
      розрізнюваними.

  > Пояснення: планується захоплення і повтор WebSocket, інтроспекція gRPC-схем і обмежені бінарні мутації без змішування байтів і метаданих.

- [ ] Додати JavaScript source-map/AST analysis та local taint evidence;
      browser WebSocket events.

  > Пояснення: аналізу JS source-map/AST ще немає (`grep -rn "sourceMappingURL\|sourcemap" engine web/lab → 0`). Витягування секретів реалізоване (`engine/osint_secrets.go`, `engine/osint_secrets_scan.go`), тому воно з пункту зняте.

- [ ] Додати OpenAPI/Postman import, GraphQL introspection/schema inspection,
      BOLA role matrix і JWT allowlist/signature verification fixtures.

  > Пояснення: планується імпорт API-специфікацій, інтроспекція GraphQL, матриця BOLA-ролей і фікстури перевірки JWT. Рендеринг JWT у відповідях уже є (`web/templates/lab/index.html:1906-1909` `.http-jwt-*`), fixture-перевірка підпису — ні.

### P1. UI/UX та interaction primitives

- [ ] Додати в Repeater режими перегляду **Pretty / Raw**.

  > Пояснення: перемикач між відформатованим поданням (Pretty для JSON/XML/HTML) та сирим байтовим потоком (Raw) у відповіді Repeater. Режими Hex та visual diff знято за рішенням оператора як надлишкові для першої черги (для порівняння є вкладка Comparer).

- [ ] Додати OSINT graph/Findings Kanban, live activity bar та localization
      усіх dynamic states без color-only meaning.

  > Пояснення: планується Kanban для графа і findings зі стрічкою активності і повною локалізацією динамічних станів.

- [ ] Додати browser tests для layout persistence, keyboard operation,
      language switch, XSS/binary/malformed input, console та failed requests.

  > Пояснення: browser E2E-тестів UI в репозиторії немає: `grep -rln playwright web/lab/*.py → 0`, а `test_divider_never_covers_the_raw_block`, на який посилаються `README.md:583`, `AGENTS.md:1105` і `Документация/posibnyk-porystuvacha.md:580`, у коді відсутній. Пункт лишається відкритим доти, доки тест реально існуватиме.

### P2. Collaboration, integrations та CLI/CI

- [ ] Додати fixture-only CI для checks/tests/E2E/SARIF validation; CI не
      запускає зовнішні active targets без isolated explicit configuration.

  > Пояснення: планується CI лише на фікстурах без звернень до зовнішніх цілей, окрім явно ізольованої конфігурації. Каталогу `.github/` у репозиторії немає.

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

## Перевірений стан проєкту (переглянуто 2026-10-16)

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
- Automation UI має власний canvas, palette та inspector.
  **Фактичний стан бандлів (2026-10-16):** підключено лише **Cytoscape.js
  3.33.1** (OSINT Entity Graph, локальний бандл, без CDN); **React Flow** і
  **Monaco Editor** — дозволений стек, але **не підключені** (0 згадувань у
  `web/templates/lab/index.html`). Підключення кожного — окреме рішення власника
  з умовою локально вендореного бандлу.

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
9. **Ідентифікація інструменту у трафіку — неявне рішення, яке треба переглянути**
   (2026-10-16). Пункт N3 скасовує попереднє рішення, зафіксоване в
   `engine/anti_detect.go`; до його реалізації документ і код мають описувати
   один стан, а не два.

## Детальний TODO

### Фаза 2. Go Engine

#### 2.1 Контрольована конкурентність

<!-- Виконано: worker pool у DNS- і bucket-брутфорсі та батчі Repeater Burst.
     Див. таблицю «Перевірено та вилучено з backlog». -->

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
  статусі. **Виміряно 2026-10-16:** `grep -c "WithTimeout" engine/osint_transforms.go` → **0**,
  тож пункт лишається відкритим.
- Зберегти route/proxy/TLS/cancel поведінку; не вводити прихованих
  timeout/concurrency defaults. Додати regression-тести на відсутність витоку
  горутин.

**Приймання:** спільний transport не ламає route/proxy/TLS/cancel поведінку;
жодна зовнішня функція не лишається без cancellation path.

### Фаза 3. Browser Worker

#### 3.1 Привʼязка хоста до ендпоинта пула

<!-- Виконано: ProxyPool.endpoint_for реалізовано та інтегровано в crawl_worker -->

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
  provider-и та необхідні поля/квоти погодити перед підключенням. **Виміряно
  2026-10-16:** жодного з цих провайдерів у коді немає — єдині збіги `shodan`
  трапляються лише в регулярках секретів (`engine/pkg/enrich/secrets_data.go`).
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

#### 4.3 Архітектурне рішення щодо Neo4j: відхилено на користь локальної БД

- Дослідження та оцінка: перехід на окрему графову СУБД Neo4j відхилено. Оскільки Request-Rider є автономним локальним інструментом тестувальника, введення важкої Java/JVM бази (Neo4j) призводить до невиправданого споживання оперативної пам'яті (від 1-2 ГБ лише під JVM) та ускладнює локальне розгортання.
- Рішення: поточна реляційна модель у локальній БД повністю покриває зв'язки сутностей OSINT/графа без додаткового оверхеду. Authoritative store лишається локальна БД.

### Фаза 5. Scripting та notifications

#### 5.1 Webhooks та notifications

- Моделі `Notification` у `web/lab/models.py` немає: створити Django
  notifications models/configuration для destination, event types, severity
  threshold, active state та пов’язаного Project. Webhook-тригер для workflows
  уже існує (`webhook_trigger`, `ALL /api/workflows/hooks/<slug>`) — потрібен
  саме вихідний канал для знахідок.
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

<!-- Registry node-екзекуторів, durable waiting state через EngineTaskDeferred та
     idempotent-відновлення за checkpoint реалізовані. Лишається: повне
     відновлення queued/running/waiting runs після рестарту web-процесу без
     позначення живих брокерних задач `interrupted`, і доведення цього тестом на
     реальному рестарті, а не на моках. -->

#### 6.3 Automation editor та дебаг-інструменти

- Вендорити React Flow як локальний бандл і підключити лише на canvas
  Automation. Без CDN, без зовнішніх fetch, без повного frontend build.
  **Статус 2026-10-16: не виконано** — `grep -c reactflow
  web/templates/lab/index.html` → 0, бандлу в `web/static/vendor/` немає.
- Зберегти node palette, connections, inspector, локалізацію, клавіатурну
  доступність та поточний API. Додати node run state, queued/waiting
  checkpoint, output/error inspector, retry/resume та **візуальну** execution
  timeline після готовності backend API. **Виміряно 2026-10-16:** стан вузлів
  зараз видно лише сирим JSON у панелі `workflow-log`
  (`web/templates/lab/index.html:24658`, `timeline: current.node_executions.map(...)`);
  візуального індикатора стану вузла на canvas, retry/resume кнопок та окремого
  інспектора output/error немає (`grep -n "nodeState|runState" web/templates/lab/index.html` → 0;
  `retry` є лише для перевірки engine в шапці та для Target).
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

---

## ПРІОРИТИЗАЦІЯ ЗАВДАНЬ (оновлено 2026-10-26)

Пріоритизація побудована за інженерним принципом **Data Integrity & Runtime
Stability First**: не можна надбудовувати складні сканери, воркфлоу чи протоколи
над системою, де трафік різних проектів перемішується, горутини ризикують
підвиснути при затримках мережі, а профілі сканування є лише декоративними
текстовими метаданими.

### 🔴 РІВЕНЬ 1: БЛОКУЮЧИЙ ФУНДАМЕНТ (P0 — «ВПРОВАДЖУВАТИ ЗАРАЗ» / НАЙВИЩИЙ ПРІОРИТЕТ)

#### 1. Повний cancellation path та `context.WithTimeout` у Go Engine (Фаза 2.3)

- **Що зробити**: Гарантувати, що **кожна** функція, яка здійснює зовнішні
  мережеві запити, має контекст із дедлайном і коректно реагує на переривання
  клієнтом. Виміряно: `engine/osint_transforms.go` має **0** `WithTimeout`.
- **Чому зараз**: рушій може накопичувати підвислі горутини при «мовчазних» або
  повільних з'єднаннях цілі, блокуючи сокети та воркерів.
- **Ризик відкладання**: падіння продуктивності, споживання дескрипторів
  сокетів і неможливість гарантованого скасування завдань.

### 🟡 РІВЕНЬ 2: НАДІЙНІСТЬ РАНТАЙМУ ТА АНАЛІЗ (P1 — НАСТУПНИЙ КРОК)

#### 2. Clustering-based мутації та adaptive backoff у активному сканері

- **Що зробити**: кластеризація базових відповідей і мутації залежно від
  кластера; `429/503` з `Retry-After` → backoff.
- **Чому важливо**: без кластеризації мутації б'ють у порожнечі, а без backoff
  сканер отримує бан замість результату.

#### 3. Відновлення брокерних workflow-ранів після рестарту web-процесу (Фаза 6.2)

- **Що зробити**: не переводити живі брокерні задачі в `interrupted` лише
  через рестарт web, і довести це тестом на реальному рестарті.
- **Чому важливо**: робить можливими довгі ланцюжки (Recon → Scanner → Condition)
  без ризику втрати прогресу при оновленні чи перезапуску веб-сервера.

#### 4. Вихідні Webhook-сповіщення на знахідки ScannerRun (Фаза 5.1)

- **Що зробити**: `transaction.on_commit` + Celery-задача для JSON-пейлоадів у
  Slack/Telegram/вебхуки за порогом severity.

### 🟢 РІВЕНЬ 3: ПРОДУКТИВНІСТЬ ОПЕРАТОРА (P2)

#### 5. Repeater: режими перегляду Pretty / Raw

- **Що зробити**: швидкий перемикач між відформатованим поданням (Pretty для JSON, XML, HTML)
  та сирим байтовим потоком (Raw) у відповіді Repeater.
  (Hex-режим та вбудований visual diff знято за рішенням оператора: для порівняння є окрема вкладка Comparer).

### ⚪ РІВЕНЬ 4: СПЕЦІАЛІЗОВАНІ ПРОТОКОЛИ, ЛОКАЛЬНА AI ТА ЕКСПЕРИМЕНТИ (P3)

- **Нові відкриті пункти:**
  - **N1. EmbeddingGemma (On-Demand Outliers & Triage)** — локальні ембеддинги
    для детекції аномалій у Intruder та пріоритезації цікавих ендпоінтів (Juiciness
    Triage). Он-деманд завантаження без зайвого споживання RAM у простої. Варто
    раніше за решту P3, бо це ощадливий локальний функціонал (308M, MRL 128/256),
    який вирішує реальну задачу аналізу великих масивів фазингу.
  - **N4. Тест MCP на локальних Ollama-моделях** — довести, що наш MCP-сервер
    реально керується локальною моделлю через stdio-протокол, а не лише
    прямими HTTP-викликами; артефакт — таблиця вимірів на ізольованому стенді.
- **Протокольні розширення**: WebSocket capture/replay, gRPC `.proto` introspection, H3/QUIC.
- **H2 single-packet experiment**: виконано як Last-Byte Sync
  (`engine/last_byte.go`); у backlog лишається лише deterministic one-TCP-packet
  semantics, якої інструмент не обіцяє.
- **OpenAPI/Postman імпорт та GraphQL інтроспекція**: конвертація
  API-специфікацій у граф атак.
- **Платні OSINT-інтеграції**: Shodan/Censys платні API (наразі відхилено на
  користь локальних та безкоштовних джерел).
- **Neo4j міграція**: відкладено до моменту, поки PostgreSQL справляється з
  навантаженням графів.

---

## НАСТУПНИЙ КРОК

Порядок актуального беклогу за пріоритетом:

**Абсолютний пріоритет (впроваджувати зараз) — Фаза 2.3: Повний cancellation path та `context.WithTimeout` у Go Engine:**
Рушій здійснює мережеві виклики (зокрема `engine/osint_transforms.go`), де наразі відсутні тайм-аути контексту (`0 WithTimeout`). Це загрожує зависанням горутин і блокуванням сокетів при повільних з'єднаннях. Кожен мережевий запит має отримати контекст із дедлайном і коректно реагувати на переривання.

**Наступні бекенд-завдання (Рівень 2 / P1):**
1. **Clustering-based мутації та adaptive backoff:** кластеризація базових відповідей у активному сканері та врахування `Retry-After` (429/503).
2. **Відновлення брокерних workflow-ранів (Фаза 6.2):** не позначати живі брокерні завдання `interrupted` при рестарті веб-сервера.
3. **Вихідні Webhook-сповіщення (Фаза 5.1):** надійні нотифікації на знахідки `ScannerRun.findings`.

**Продуктивність оператора та локальний AI (Рівень 3–4 / P2–P3):**
- **Repeater:** режими перегляду Pretty / Raw у відповідях.
- **N1 (EmbeddingGemma):** локальний он-деманд аналізатор аномалій Intruder та ранжування ендпоінтів.
- **N4 (Тест MCP на Ollama):** верифікація tool-calling через реальний stdio JSON-RPC.
