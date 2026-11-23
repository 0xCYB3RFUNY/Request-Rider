# Практичні сценарії Automation

> Документація практичних сценаріїв та вузлів конструктора автоматизацій (Automation).
> Архітектура системи: [arkhitektura-ta-api.md](./arkhitektura-ta-api.md).

## Мета

Сценарії показують реальний операторський workflow: результат одного
інструменту не передається як «магічний AI action», а спочатку стає явним
evidence. AI аналізує лише прикріплений результат, після чого оператор сам
вибирає наступний інструмент, URL, параметри та підтвердження.

Усі приклади нижче виконуються на локальному fixture-сервері і не
використовують зовнішню ціль.

## 1. Від fuzzing до наступного crawl

```text
Intruder: GET /search?q={{payload}}
    -> Intruder results (status/body/length/payload)
    -> Send results to AI
    -> AI: FACT / HYPOTHESIS / next safe check
    -> оператор обирає URL
    -> Target або Repeater workflow
    -> окремий Run / confirmation
```

Перевірка:

1. Відкрити `Intruder`, ввести paired marker і малий словник.
2. Дочекатися `completed` і натиснути `Send results to AI`.
3. Перевірити `Attached to chat`: має бути `Intruder results`.
4. Надіслати запит до локального AI provider і перевірити, що відповідь
   містить рекомендацію, а не виконаний tool call.
5. За потреби створити Target/Repeater workflow через `Send to Automation`
   або вручну в canvas. AI не запускає активний запит автоматично.

Автоматизований regression: `test_intruder_results_handoff_to_ai_and_operator_approved_target_followup`.

## 2. Repeater exchange → AI → Target

```text
Repeater baseline exchange
    -> Send exchange to AI
    -> AI аналізує status/body/headers
    -> оператор обирає URL для наступної перевірки
    -> Target workflow
```

Перевірка: `test_repeater_exchange_handoff_to_ai_and_target_followup`.

## 3. Target map → AI → Repeater

```text
Target static/browser map
    -> page URLs, network evidence, JS/API requests
    -> Send map to AI
    -> AI групує URLs і пропонує baseline
    -> оператор обирає один URL
    -> Repeater baseline
    -> Comparer/Decoder/AI evidence за потреби
```

Важливо: browser network evidence не означає, що URL підтверджений як
endpoint. AI має відокремлювати `FACT`, `HYPOTHESIS` та `UNKNOWN`.

Перевірка: `test_target_map_handoff_to_ai_and_repeater_followup` і
`test_target_browser_fixture_requires_confirmation_and_collects_network`.

## 4. OSINT → AI → Scanner/Target

```text
OSINT DNS/HTTP/TLS/redirects
    -> Send OSINT to AI
    -> AI формує read-only hypotheses
    -> Scanner read-only pass
    -> Target map лише після вибору hostname/URL
```

Не передавати в AI повний secret set без потреби; evidence проходить явний
вибір оператора та redaction, без application count/body budget.

Перевірка: `test_osint_handoff_to_ai_and_scanner_followup`.

## 5. Scanner findings → AI → Target

```text
Scanner findings + evidence
    -> Send scan to AI
    -> AI пріоритезує перевірки
    -> оператор створює Target/Scanner workflow
    -> findings зберігаються з evidence_before/after
```

Scanner не виконує fuzzing, brute force або exploit. AI може лише
запропонувати наступний read-only крок.

Перевірка: `test_scanner_handoff_to_ai_and_target_followup`.

## 6. Workflow AI node

```text
Manual trigger
    -> Repeater / інструментальний вузол
    -> AI Agent
    -> Output
```

AI node отримує результат попереднього вузла як повний workflow input після
redaction.
Це не замінює явне прикріплення evidence у вкладці AI: для production-like
аналізу краще використовувати `Send ... to AI` і перевірити вкладений
контекст перед запуском.

Перевірка: `test_workflow_ai_node_receives_repeater_evidence`.

## Загальні правила безпеки

- Дії Intruder і Browser Target потребують explicit confirmation.
- URL активних вузлів береться з операторського payload; `Project` не є
  execution policy.
- AI не має shell, arbitrary filesystem або arbitrary HTTP tools.
- Після AI-рекомендації оператор перевіряє URL, method, dictionary, delay,
  concurrency та інші явно задані параметри перед запуском.
- Export/import workflow не є дозволом на запуск; активний workflow запускається
  окремою кнопкою.
- Runtime залишається process-local; Redis/Celery/distributed queue не є
  частиною цих сценаріїв.

## Автоматизована перевірка

Тестовий runner піднімає випадковий local fixture і local fake LLM, перевіряє
canvas, інспектор, підтвердження, persistence, branch/merge, pause/resume/cancel,
webhook/schedule, export/import, Template Store та evidence handoffs. Після
завершення він видаляє створені workflow і fixture-specific записи.

`Apply/Cancel route` є окремим workflow kill switch: active run cleanup
відбувається до закриття admission, а child tool cancellations не дають run
завершитися як `completed` зі старим route generation.

## Backlog розширених playbooks

Запропоновані у реальних програмах Bug Bounty сценарії — ESI, XXE/OAST,
WebAuthn challenge replay, CI/CD webhook poisoning, HMAC mobile signing,
inventory exhaustion, RAG poisoning, WAF mutation та Last-Byte race — не
вмикаються в MVP автоматично. Їхній пріоритетний порядок:

1. **Read-only baseline:** exposed `.git`, security headers, CORS, GraphQL
   schema, JS assets, response diff.
2. **Active fuzzing:** Intruder із confirmation, локальні словники та
   user-controlled timeout/delay/concurrency.
3. **OAST/self-hosted adapter:** local loopback contract уже реалізовано;
   наступний крок — сумісність із self-hosted Interactsh API та окремі
   DNS/HTTPS/SMTP provider fixtures. Public endpoint не є default.
4. **Race/Last-Byte node:** окремий node type з configurable burst, cancel,
   fixed TLS verification і ручним запуском; не вбудовувати його в звичайний
   Repeater без окремого modal.
5. **Community templates:** server-backed validation і підписи manifests перед
   імпортом.

## Безпечний контракт OAST у DAG

Щоб payload можна було передати в Intruder/Target **до** появи callback,
OAST flow не повинен блокувати весь граф на register. Для наступної ітерації
використовуються дві фази:

```text
OAST Listener (start) -> payload_url + listener_id
    -> Intruder / Target / Repeater з payload_url
    -> OAST Collect (wait) -> events / correlation evidence
```

`start` реєструє fixture/self-hosted session і повертає URL майже миттєво.
`wait` має окремий timeout, cancellation і read-only polling. Якщо callback не
прийшов, workflow завершується `completed` з `triggered: false`, а не
підміняє результат success-подібним event. Public Interactsh, fixed token і
відкритий outbound callback не є defaults; перший fixture є local loopback.

## Repeater Burst

`Repeater Burst` — окремий confirmation-gated node для parallel review:

```text
Manual Trigger -> Repeater Burst -> Comparer -> Output
```

Django передає URL і user-controlled `iterations`, `concurrency`, `delay_ms` та
`timeout_ms` у Go через `POST /proxy/repeater-burst`. Значення без верхньої
межі; `timeout_ms=0` вимикає timeout. Далі використовується
`GET /proxy/repeater-burst/<id>`, а cancellation викликає `DELETE`. Дозволені
лише read-only методи `GET`, `HEAD`, `OPTIONS`; `iterations` і `concurrency`
мають бути позитивними, а delay/timeout — невід'ємними. Go не виконує redirect,
не робить окремий source-IP lookup для кожної iteration, не повторює запити
і зберігає TLS verification. Response headers, body та aggregate results
зберігаються повністю без truncation. Кожен успішний exchange записується у
History; snapshot містить `status`, `total`, `completed`, `failed` і
впорядковані `results`.

Node є manual-only: schedule/webhook triggers заборонені, а active workflow
потребує explicit confirmation. Це orchestration contract, а не raw
Last-Byte TCP/TLS attack; режим raw burst залишається experimental і не має
default execution path.

---

## Автоматичний генератор ланцюжків залежностей (`Stateful Traffic Correlation & Auto-Chaining`)

**Призначення:** одноклікова побудова параметризованого графа `Workflow` із серії послідовних HTTP-обмінів (`History` / `Traffic`) без ручного написання регулярних виразів.

### Як це працює
1. Виділіть чекбоксами 2–15 послідовних обмінів у таблиці **Історія** або **Трафік** (наприклад: `GET /login` → `POST /login` → `POST /api/profile/update`).
2. Відкрийте контекстне меню рядка (`#ctx-menu`) і натисніть **«🔗 Побудувати ланцюжок в Automation»**.
3. Аналізатор `web/lab/traffic_chaining.py` автоматично виявляє у ранніх відповідях:
   - `Set-Cookie` пари (сесійні куки);
   - заголовки `Location`, `X-CSRF-Token`, `Authorization`, `ETag`;
   - JSON-поля тіла відповіді (токени, ідентифікатори, коди);
   - приховані HTML `<input type="hidden">` та `<meta name="csrf-token">`.
4. Якщо ці значення (або їх URL/Base64-кодовані варіанти) зустрічаються в наступних запитах (у URL, заголовках чи тілі), статичні значення замінюються на динамічні посилання `{{nodes.<step_id>.extracted.<key>}}`, а в джерело-вузол додається правило `extract`.

---

## Серверні шаблони `WorkflowTemplate`, підпис схем та конвертери (Nuclei / Postman / OpenAPI / AttackChain)

1. **`WorkflowTemplate` CRUD, HMAC-SHA256 підпис та Import Preview**:
   - `GET/POST /api/workflow-templates`, `GET/DELETE /api/workflow-templates/<id>` — збереження шаблонів у БД із підписом `schema_signature` (`hmac-sha256:...`).
   - `POST /api/workflow-templates/preview` — попередній перегляд імпортованого бандлу з перевіркою канонічного графа та валідності підпису (`signature_valid`).
2. **Конвертери Nuclei YAML та Postman Collection v2.1 (`POST /api/workflows/convert`)**:
   - Перетворюють data-only HTTP шаблони Nuclei або Postman-колекції у канонічний граф Request-Rider (`manual_trigger` → `repeater`) із обов'язковою перевіркою через `validate_workflow`. Небезпечні `code`/`headless`/`javascript`/`file` блоки при імпорті відхиляються.
3. **Семантичний граф `AttackChain` / `AttackStep` (`GET/POST /api/attack-chains`)**:
   - Окремий від технічного DAG виконання семантичний граф ланцюжка атаки, де кожен крок (`AttackStep`) має `finding_identity`, `exchange_id` та `evidence_provenance`.
4. **Імпорт API-специфікацій та протокольний інспектор**:
   - `POST /api/specs/import` — імпорт OpenAPI 3.x / Swagger 2.0 безпосередньо в `ProjectEndpoint` та аналіз GraphQL `__schema` інтроспекції (`queries`, `mutations`, `sensitive_fields`).
   - `POST /api/protocols/inspect` — розбір метаданих WebSocket (RFC 6455), gRPC (5-байтове фреймування + Protobuf wire fields), HTTP/2, HTTP/3/QUIC, `.proto` інтроспекція та обмежені бінарні мутації (raw bytes завжди відокремлені в `raw_bytes_b64`).


## Розширена палітра інструментів платформи (39 вузлів)

До палітри **Automation** (`web/lab/workflow_engine.py`, `web/lab/views.py`, `web/templates/lab/includes/_project_transfer.html`) інтегровано прямі детерміновані вузли для всіх нових модулів платформи:
- **Сканери:** `active_scanner` (DAST + F8/F9), `nuclei_scan` (директорії шаблонів Nuclei), `corpus_scan`, `openvas_scan`.
- **Атаки та аналіз:** `auth_matrix` (F1 Live Auth Matrix), `jwt_forge` (F5 JWT & Crypto Forge), `target_js_analyze` (F7 JS/DOM аналіз), `osint_transform` (графові OSINT-трансформи).
- **Платформа, інфраструктура та звітність:** `surface_diff` (F6 знімки поверхні атаки та diff), `poc_generate` (F10 Python/Playwright/Go/cURL PoC), `spec_import` (OpenAPI/GraphQL), `protocol_inspect` (WebSocket/gRPC/Protobuf), `route_manage` (Direct/Tor), `dns_manage` (System/Custom/DoH/Flush), `history_search`, `finding_record`, `report_export` (SARIF/HTML/JSON Fusion Report).

### UI-контролі, параметри вузлів та налаштування (`⚙️`)
- **Браузери вузла `target_browser` (`workflow_engine.py`)**: підтримуються виключно `["firefox", "chromium"]` (за замовчуванням `"firefox"`).
- **Операції вузла `decoder`**: крім 21 базової операції UI, підтримується `jwtDecode`.
- **Експорт (`#workflow-export`)**: dropdown-меню підтримує формати **JSON** та **XML**.
- **Керування полотном та виконанням (`web/templates/lab/tabs/_automation.html`)**: `#workflow-zoom-out`/`#workflow-zoom-value`/`#workflow-zoom-in`/`#workflow-fit`/`#workflow-auto-layout`/`#workflow-minimap`, а також `#workflow-run-pause`, `#workflow-run-resume`, `#workflow-run-cancel`.
- **Налаштування (`⚙️` → `#tool-pane-automation`)**: `#setting-automation-timeout` (`Default Node Execution Timeout (sec)`, `5–3600`, дефолт `120`), `#setting-automation-snap` (`checked`), `#setting-automation-minimap` (`checked`).
