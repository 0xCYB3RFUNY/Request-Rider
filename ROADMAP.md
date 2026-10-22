# Roadmap RequestRider

## Статус roadmap та архітектурне позиціонування

> **Архітектурне позиціонування:** Request-Rider є **автономним локальним інструментом тестувальника/пентестера** для роботи безпосередньо на робочій станції (single-user local security tool). Застосунок не є SaaS/хмарним багатокористувацьким сервісом і не потребує складних multi-tenant ізоляцій, розподілених кластерів або зовнішніх важких СУБД.
> **Головні інженерні пріоритети:** максимальна локальна швидкодія (Zero-lag UI), ощадне споживання пам'яті (RAM) та CPU на машині тестувальника, швидкість обробки великих масивів трафіку/пейлоадів та надійність локального браузерного флоту.

Цей файл містить лише невиконаний backlog (`[ ]`). Виконані пункти видалено
для читабельності; історія виконаних робіт зберігається в
`DEVELOPMENT_LOG.md`. Кожен пункт backlog вважається нереалізованим до повного
проходження targeted/regression тестів і browser smoke-test.

Під кожним пунктом курсивом додано коротке пояснення запланованої фічі.

## Перевірено та вилучено з backlog (2026-10-16)

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
| Версіоновані налаштування `uiPreferences` | `web/templates/lab/index.html:13026` `migrateUIPreferences`, `:13076-13097` snapshot/валідація |
| Semantic status/tag tokens, accessible progress, toast service | токени в `:root`, `.scanner-progress-*` (з `percent == -1`), `.toast` з `toast-success\|warning\|error` |
| Right-click/keyboard контекстне меню рядка | `web/templates/lab/index.html:2167` `#ctx-menu role="menu"`, `:25826` `openRowMenu`, `:25868` делегування по `data-ctx-*` |
| H2 single-packet як manual-only експеримент | `engine/last_byte.go:399-401` — весь HTTP/2 burst пишеться одним user-space буфером; детермінованого one-packet delivery не заявляється |
| Registry node-екзекуторів workflow | `web/lab/workflow_engine.py:1223-1236` `node_executors`, `:1632` resolve за типом |
| Брокерна оркестрація і durable checkpoint вузлів | `web/lab/engine_broker.py:94` `EngineTaskDeferred`, `:210` відкладення, `:308-333` idempotent-відновлення за checkpoint; `web/lab/workflow_engine.py:1965-2008` `_recover_interrupted` |
| Вихідні webhook-сповіщення на workflow-тригери | `web/lab/workflow_engine.py:64,196` тип вузла `webhook_trigger`, `ALL /api/workflows/hooks/<slug>` |
| ~~Target: вікно з двома рівними запитами (клік по рядку / пункт у kebab `⋯`)~~ | **Знято рішенням оператора 2026-10-16**, до реалізації не дійшло. Готовий тригер при цьому лишається валідним для майбутніх правок: пункт у kebab `⋯` / right-click меню `#ctx-menu` для таблиці Target вже існує |

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

## Нові пункти (2026-10-16)

### N1. Локальна модель ембеддингів EmbeddingGemma

- [ ] Інтегрувати **EmbeddingGemma** (Google DeepMind, `google/embeddinggemma-300m`,
      308M параметрів, побудована з Gemma 3) як локальний ембеддер — без
      зовнішнього API-ключа і без CDN.

  > Пояснення: модель призначена саме для on-device роботи: 308M параметрів,
  > < 200 MB RAM у квантизації, контекст 2K токенів, розмірність вектора 768 з
  > Matryoshka-варіантами 512/256/128, 100+ мов. Локальний запуск через Ollama
  > (`ollama pull embeddinggemma`, 622 MB, потрібен Ollama ≥ v0.11.10,
  > `POST /api/embed`) або llama.cpp (`ggml-org/embeddinggemma-300M-GGUF`,
  > Q8_0 334 MB). Ліцензія — Gemma Terms of Use.

  **Де застосовується (перша ітерація):** семантичний пошук по History/Traffic,
  групування близьких (near-duplicate) запитів і відповідей, пошук за Finding та
  сутністю OSINT-графа, семантичний пошук по секретах/секрет-файндінгах.

  **Обмеження, які має містити перша ітерація:** ембеддінг — це **додатковий**
  шлях, а не замінаHost/Method/URL фільтрів; вектор зберігається разом із
  версією моделі, і старі вектори не змішуються з новими; якщо модель не
  завантажена — пошук працює як зараз, без помилки.

  **Відкрите рішення (зняти окремою ітерацією):** сховище векторів —
  `pgvector` у PostgreSQL (новий розширення) чи `bytea`/`jsonb` + косинусна
  схожість у Django без нових залежностей. Обране рішення фіксується тут.

### N2. Шестерёнка налаштувань у вкладках

- [ ] Додати в кожну вкладку кнопку-шестерёнку, яка відкриває діалог
      налаштувань **саме цієї вкладки**.

  > Пояснення: зараз налаштування розкидані по панелях (фільтри, сортування,
  > видимість блоків, розміри) і частина з них живе поза view. Шестерёнка дає
  > одну точку входу для налаштувань конкретної вкладки.

  **Вимоги:** переиспользувати наявний versioned `uiPreferences`
  (`migrateUIPreferences`, `web/templates/lab/index.html:13026`) з розширенням
  схеми, а **не** створювати другий незалежний механізм збереження; усі ключі
  через `data-i18n` в обох словниках; повний набір станів контролу
  (default → hover → focus-visible → active → disabled → loading/error/empty);
  збереження переживає reload; панель не ламає чотири інваріанти розкладки.

### N3. Антидект у кожному інструменті та прибирання `RequestRider-*` з UA

- [ ] Інтегрувати наш антидект (`engine/anti_detect.go`, browser-worker
      anti-detect runtime) у **кожен** інструмент — **Repeater, Intruder,
      OSINT, сканери** — і прибрати з вихідного трафіку юзер-агентів
      `RequestRider-*`, щоб ціль не бачила інструмент.

  > Пояснення: зараз окремі шляхи надсилають ідентифікацію інструменту:
  > `engine/main.go:991` `RequestRider-RouteCheck/1.0`, `:2306` і `:2679`
  > `RequestRider-OSINT/1.0`, `:3102` і `:3113` `RequestRider-Scanner/1.0`.
  > `UserAgent.txt` у корені репозиторію **не читається жодним кодом**
  > (`grep -rn "UserAgent.txt" engine web → 0`), тобто рандомізації UA
  > фактично немає.

  **Суперечність, яку треба зняти перед реалізацією:** `engine/anti_detect.go`
  фіксує попереднє рішення власника — «User-Agent залишається саме таким, як
  його формує Go, бо RequestRider має лишатись впізнаваним як себе, а переписаний
  User-Agent — це брехня». Пункт N3 **скасовує** це рішення; при реалізації
  треба одночасно оновити коментар у `engine/anti_detect.go` і запис у
  `DEVELOPMENT_LOG.md`, інакше код суперечитиме власному правилу.

  **Вимоги:** ідентифікація прибирається **з усього вихідного трафіку**
  (OSINT, сканери, route-check, Repeater/Intruder, capture-контекст);
  антидект-профіль (UA + `Sec-Fetch-*` + cookies + TLS-відпечаток) — **явна
  настройка** оператора з видимим станом, а не прихована підміна; `UserAgent.txt`
  або підключається як джерело профілів, або видаляється з репозиторію, щоб
  мертвий файл не лишався.

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

### N5. Пауза і продовження для активного сканера та краулера Target

- [ ] Додати `pause` / `resume` для **активного сканера** і для **краулера
      Target**, щоб довгий прогін можна було зупинити на місці обриву, а не
      тільки вбити.

  > Пояснення: сьогодні ці два інструменти — єдині, де паузи немає. Nuclei-джоби
  > вже мають `/cancel`, `/pause`, `/resume` (`engine/main.go:1831-1838`,
  > SIGSTOP/SIGCONT), browser-driven Target — `cancel|pause|resume`
  > (`web/lab/views.py:3351`). Але активний сканер має **лише cancel**
  > (`engine/scanner_active.go:560-566`: «Cancel is the only control this job
  > has. Pause would freeze the run between probes…», і
  > `web/lab/active_scanner_views.py:485-490` приймає тільки `action=cancel`),
  > а статичний краулер Target — тільки `DELETE` з переходом у `cancelling`
  > (`engine/main.go:3136-3155`, `web/lab/views.py:2783`). Тобто це не нова
  > концепція, а незакрита частина вже наявної семантики.

  **Вимоги:** пауза має бути **спостережною між зондами** (як у nuclei), а не
  «заморозкою на місці»; стан `paused` пишеться в `ActiveScanJob` /
  `TargetJob` і виживає reload; `resume` продовжує **від фронтиру**, а не
  починає заново (див. N7); повні стани в UI (`idle → running → paused → …`),
  клавіатура, i18n × 2 мови; `cancel` лишається.

  **Чесна вимога до самої паузи (закриття зауваження з `scanner_active.go`):
  пауза має відпускати сокети.** Зауваження в коді слушне — «заморожений» прогін
  тримає сокети й увагу цілі. Тому пауза зупиняє видачу нових зондів **і**
  дочекатися/закриває in-flight з'єднання цього job-а, а рядок стану показує,
  що саме зроблено («зупинено між зондами, N зондів у польоті скинуто»).
  Інакше це та сама пауза, яку код відхилив.

### N6. Переотправка не відправлених і зависших запитів + детектор обриву

- [ ] Рахувати транспортні збої, мати чергу «не відправлено / зависло» з
      кнопкою **Resend** і автоматично ставити прогін на паузу, коли обрив
      стає очевидним.

  > Пояснення (міряно на експорті оператора
  > `~/Downloads/traffic-all-1792156334896.json`, 500 обмінів, 14.3 хв,
  > контекст `active-scanner · https://auraexchange.pro`): **499 з 500 обмінів
  > з помилкою — 99.8 %**, і жоден із них не відповів. Latency
  > p50/p95/max = **15000 / 15003 / 15085 мс**, тобто кожен зонд спалив повний
  > 15-секундний таймаут; 248 `net/http: request canceled while waiting for
  > connection` (виснаження пулу з'єднань), 185 timeout/deadline,
  > 50 `connection reset by peer`, 9 `context canceled`, 6 `net/http: request
  > canceled`, 1 `EOF`. Без помилки — **1** обмін.

  **Вимоги:**
  - класифікувати транспортний збій і рахувати **послідовні** збої;
  - черга «не відправлено / зависло» саме тих запитів, які **не дали відповіді**,
    з видимою причиною, і кнопка `Resend` (для запитів, які змінили стан, —
    через наявне явне підтвердження, як для інших state-changing дій);
  - автоматична пауза при N послідовних транспортних збоях із **названою
    причиною** і останнім успішним зондом (за правилом «предел не повинен
    заважати»: поріг явний, перекривається оператором і видимий у стані —
    прихованої зупинки бути не може);
  - повторний зонд не плодить дублі знахідок (`compute_finding_identity` +
    `upsert_findings` уже це вміють);
  - помилка **зберігається**, а не зникає: без відповіді запис лишається
    доказом того, що запит не пройшов.

### N7. Збереження стану і прогресу прогону з поверненням на місце збою

- [ ] Зберігати фронтир прогону (що вже пропробовано, що відповіло, що
      впало, які знахідки) так, щоб після обриву можна було **подивитися, де
      почалося**, усунути причину (маршрут, API-ключ, проксі, креденшли) і
      **продовжити з цього місця**, а не починати 5568 запитів спочатку.

  > Пояснення (міряно на експортах оператора): `scanner-active-1792155734472.html`
  > показує, що run дійшов до **Requests 5568 / Surfaces 11089 / Pages 1121 /
  > Findings 9** (8 proven, 1 unverified), тоді як останні 500 обмінів —
  > 99.8 % помилок. Тобто продуктивна частина прогону й мертва не відрізняються
  > одна від одної після факту. `target-map-1792155653533.html` вивантажено,
  > коли краулер ще був у стані **687 pages · running** — прогрес жив тільки
  > в пам'яті, і єдиним способом його побачи був експорт.

  **Вимоги:**
  - фронтир пишеться в БД разом із job-ом (`ActiveScanJob` / `TargetJob`), а не
    тільки в пам'ять процесу; переживає reload і рестарт web/engine — за тим
    самим принципом, що вже працює для workflow-нод
    (`web/lab/engine_broker.py:308-333`), тобто **без другого механізму**;
  - у UI видно: останній успішний зонд, перший збій, лічильники за класами
    помилок, «звідки продовжувати»;
  - `Resume from checkpoint` після зміни причини + явний `Restart from zero`
    (продовження — за бажанням оператора, прихованої зупинки не буде);
  - стан прогону входить у workspace snapshot, як решта view.

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

- [ ] Додати shared action registry, conflict-free command palette і shortcut
      profiles. Контекстне меню рядка вже існує (`#ctx-menu`) і є готовим
      патерном для реєстру.

  > Пояснення: єдиний реєстр дій з палітрою команд і профілями шорткатів. Command palette у коді відсутня (у `index.html` є лише палітра вузлів Automation).

- [ ] Додати в Repeater режими перегляду **Pretty / Raw / Hex** і persistent
      visual diff між двома обмінами; allow-listed DSL-пошук по відповіді.

  > Пояснення: регульований спліт уже є (`.table-resizer`, `web/templates/lab/index.html:347-351`), Comparer із word/hex diff уже є (`:455-457`, `:6845-6862`), JWT-підсвітка теж. Не лишилося: режими перегляду Pretty/Raw/Hex і persistent diff **у самому Repeater**.

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

## ПРІОРИТИЗАЦІЯ ЗАВДАНЬ (оновлено 2026-10-16)

Пріоритизація побудована за інженерним принципом **Data Integrity & Runtime
Stability First**: не можна надбудовувати складні сканери, воркфлоу чи протоколи
над системою, де трафік різних проектів перемішується, горутини ризикують
підвиснути при затримках мережі, а профілі сканування є лише декоративними
текстовими метаданими.

### 🔴 РІВЕНЬ 1: БЛОКУЮЧИЙ ФУНДАМЕНТ (P0 — «ВПРОВАДЖУВАТИ ЗАРАЗ»)

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

#### 5. Пауза/продовження активного сканера і краулера Target (N5)

- **Що зробити**: `pause` / `resume` для тих двох інструментів, де її сьогодні
  немає; пауза зупиняє видачу зондів **і** відпускає in-flight з'єднання.
- **Чому зараз**: довгий прогін можна лише вбити, а вбитий прогін нічим не
  відрізняється від того, що зупинився через блокування цілі.

#### 6. Переотправка завислих і не відправлених запитів + детектор обриву (N6)

- **Що зробити**: черга «не відправлено / зависло» з `Resend`, лічильник
  послідовних транспортних збоїв і автоматична пауза з названою причиною.
- **Чому важливо**: виміряно на реальному прогоні — **499 з 500** обмінів
  помилка, кожен спалив повні 15 с, а 248 із них навіть не вийшли з пулу
  з'єднань. Без лічильника збоїв і кнопки повтору оператор спалює 30 хвилин
  без жодного результату.

#### 7. Збереження прогресу прогону і повернення на місце збою (N7)

- **Що зробити**: фронтир прогону в БД (`ActiveScanJob` / `TargetJob`), видно
  «де почалося», `Resume from checkpoint` після зміни маршруту/ключа/проксі.
- **Чому важливо**: прогін дійшов до 5568 запитів, але в останніх 500 усі
  збої — продуктивну частину й мертву видно однаково. Без фронтиру
  продовження немає, є лише повний повтор.

### 🟢 РІВЕНЬ 3: ПРОДУКТИВНІСТЬ ОПЕРАТОРА (P2)

#### 8. Шестерёнка налаштувань у вкладках (N2)

- **Що зробити**: єдина точка налаштувань на вкладку поверх versioned
  `uiPreferences`.

#### 9. Repeater: Pretty/Raw/Hex і persistent visual diff

- **Що зробити**: режими перегляду й порівняння двох обмінів у самому Repeater;
  спліт і JWT-підсвітка вже є.

#### 10. Версіоновані налаштування `uiPreferences` — розширення під N2

- **Що зробити**: розширити наявну схему, а не створювати друге сховище.

#### 11. Command palette та єдиний Action Registry

- **Що зробити**: єдиний реєстр дій (швидкий запуск сканування, cURL, очищення
  сесії, налаштування проксі) поверх наявного `#ctx-menu`.

### ⚪ РІВЕНЬ 4: СПЕЦІАЛІЗОВАНІ ПРОТОКОЛИ, ЛОКАЛЬНА AI ТА ЕКСПЕРИМЕНТИ (P3)

- **Нові пункти 2026-10-16:**
  - **N1. EmbeddingGemma** — локальні ембеддинги для семантичного пошуку по
    History/Traffic/Findings/OSINT і групування близьких обмінів. Варто раніше за
    решту P3, бо це найдешевший локальний AI-функціонал (308M, < 200 MB RAM)
    і він не потребує жодного ключа.
  - **N4. Тест MCP на локальних Ollama-моделях** — довести, що наш MCP-сервер
    реально керується локальною моделлю через stdio-протокол, а не лише
    прямими HTTP-викликами; артефакт — таблиця вимірів на ізольованому стенді.
  - **N3. Антидект у кожному інструменті** — Repeater, Intruder, OSINT, сканери;
    прибрати `RequestRider-*` з UA. Потребує зняття рішення, зафіксованого в
    `engine/anti_detect.go` (див. розділ «Узгоджені межі», п. 9).
- **N5 / N6 / N7** (пауза, resend, збереження прогресу) **не належать до P3**:
  вони вже винесені в Рівень 2, бо заважають не в майбутньому, а на першому ж
  довгому прогоні — доказ наведено в їхніх пунктах.
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

Порядок уже поточного беклогу за пріоритетом описано вище.

**Найближча ітерація — N6 → N7 → N5 (разом, бо це одна історія):** на реальному
прогоні 499 з 500 обмінів закінчилися помилкою, кожен спалив повні 15 с, а
повернутися до місця обриву було неможливо. N6 дає «де почалося» і повтор,
N7 — збережений фронтир і `Resume from checkpoint`, N5 — саму паузу, без якої
N6 доводиться імітувати прибійком. Порядок саме такий: пауза без збереженого
стану некорисна, а стан без можливості повторної відправки — теж.

Далі: **N2 (шестерёнка налаштувань)** — невелика browser-facing зміна з одним
backend-контрактом (розширення наявного versioned `uiPreferences`).
**N1 (EmbeddingGemma)** йде одразу після неї, бо не торкається існуючих шляхів
даних і не потребує ключа. **N4 (тест MCP на локальних Ollama-моделях)** —
окрема вимірювальна ітерація, вона не змінює продукт і лише доводить, що
протокол MCP керується локальною моделлю. **N3 (антидект)** починається лише
після того, як оператор зніме рішення, зафіксоване в `engine/anti_detect.go`.