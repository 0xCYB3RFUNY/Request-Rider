# Функція AI Assistant та Автономний ReAct Агент (v1.2)

> Документація інтерактивного AI-асистента та автономного ReAct-агента.
> Архітектура системи: [arkhitektura-ta-api.md](./arkhitektura-ta-api.md).

У платформі Request-Rider реалізовано дворівневу архітектуру взаємодії зі штучним інтелектом:
1. **Інтерактивний AI Assistant (`POST /api/agent/chat`)**: швидкий аналіз прикріплених доказів (evidence) без автономних викликів мережі.
2. **Автономний ReAct Агент (`POST /api/agent/run`)**: багатокроковий цикл дослідження цілі (Thought → Action → Observation → Finding) із прямим доступом до 16 інструментів платформи та Model Context Protocol (MCP).

## Повна архітектурна схема

```text
[Браузер / Зовнішня IDE через MCP (Antigravity/Cursor)]
    │
    ├── Режим консультації: POST /api/agent/chat
    │     └── CSRF -> Redacted Context Builder -> LLM Provider -> Structured Response
    │
    └── Автономний ReAct цикл: POST /api/agent/run
          └── agent_loop.py (max_steps, loop limit)
                ├── Thought (Міркування моделі)
                ├── Action (Вибір одного з 16 інструментів MCP):
                │     ├── history_search -> пошук у базі TrafficRecord
                │     ├── request_send -> Go Engine (MITM/Direct) -> з міткою ai_agent
                │     ├── finding_record -> фіксація в ScannerRun (identity_hash)
                │     ├── report_ingest -> імпорт HTML/JSON/HAR звітів
                │     └── normalize / encode / decode / random_string / skills
                └── Observation -> повернення результату моделі для наступного кроку
```

## 1. Input і validation

`agent_chat()` приймає JSON із повідомленням, provider settings і evidence.
Перевіряються JSON shape, required fields, provider configuration та явні
one-shot settings; application-level history/traffic/body/message/request
ceilings не застосовуються. Некоректний JSON, невідомий evidence або
provider error повертаються як structured error, а не як удавана відповідь AI.

## 2. Формування evidence context

Browser передає вже вибрані rows, а Django формує контекст без count/body
budget. Context може містити:

```text
History exchange
Traffic exchange
Intruder result
operator message
```

Для кожного exchange зберігаються method, URL, headers, body, status,
response headers/body, latency, size і source IP; credentials, cookies та
інші secret markers проходять redaction. Body не обрізається application
truncation helper-ом.

## 3. Explicit Project context

Checkbox `Include active Project context for this message` має one-shot
семантику: consent діє лише для наступного POST і автоматично скидається після
success або error. Без active Project checkbox disabled. API приймає лише
boolean `include_project_context`; `true` без server-validated active Project
повертає `PROJECT_CONTEXT_REQUIRED`.

Server бере `request.active_project`, запускає `ProjectContextBuilder` і додає
summary з endpoints, Findings, Workflows, TargetJobs, technology metadata та
secret references. Notes default-off; raw headers/bodies, URL query credentials,
cookies, Authorization/CSRF і plaintext values відсутні. Shared evidence і
Project context передаються разом без application total-context cap.

## 4. Provider call

Після validation Django викликає `generate_agent_chat()` у
`agent_services.py`. Provider credentials і network call залишаються на
backend. Frontend не виконує provider HTTP напряму і не отримує секрети.

AI може пояснювати evidence, порівнювати відповіді і пропонувати наступні
ручні QA-кроки, але не запускає їх сам.

Під час `Apply/Cancel route` активний provider request отримує cancel через
backend transport; workflow AI node переходить у `cancelled`, а stale provider
result не повертається як success. Це стосується kill switch, не авторизації
AI-викликів.

## 5. Безпековий контур та розмежування повноважень

У системі діє суворе розмежування прав:

1. **Режим чату-консультанта (`/api/agent/chat`)**:
   - Категорично заборонено надсилати будь-які запити до рушія чи зовнішніх цілей.
   - Займається виключно пасивним поясненням доказів, порівнянням і генерацією гіпотез.

2. **Режим автономного ReAct агента (`/api/agent/run`)**:
   - **Дозволено**: формувати зондуючі HTTP-запити через `request_send` виключно до цілей у рамках дозволеного скоупу проєкту.
   - **Дозволено**: шукати в історії трафіку (`history_search`) та реєструвати знахідки в базі (`finding_record`).
   - **Суворо заборонено**:
     - Деструктивні дії, DoS-атаки та спроби виконання команд операційної системи (RCE).
     - Зміна конфігурації проксі, рушія або маршруту (/route).
     - Несанкціоноване сканування внутрішніх IP-адрес хмари або локального оточення (SSRF захист).
     - Будь-який запит поза схемою валідованих інструментів відхиляється.

## 6. API і файли

```text
POST /api/agent/chat
```

- [web/lab/views.py](../web/lab/views.py) — CSRF, validation, context.
- [web/lab/agent_services.py](../web/lab/agent_services.py) — provider
  adapter/error boundary.
- [web/templates/lab/index.html](../web/templates/lab/index.html) — chat UI і
  explicit evidence selection.


## Code walkthrough: AI

### DOM та handlers

AI UI має provider/model controls, chat input, send button, clear і evidence attachments.
Вибір History, Traffic, Intruder, OSINT або Scanner додає explicitly selected evidence.
`renderAgentChat` перерисовує log із ролями user/tool/assistant.
`renderAttachedEvidence` показує короткий summary, а не приховує payload.
`sendAgentChat` читає provider, model, prompt та `agentChatContext`.
Кнопка Send вимикається на час запиту через `agentChatBusy`.
Clear очищає `agentChatMessages` і attached context у browser state.

### JS call chain і payload

`sendAgentChat` -> `renderAgentChat` -> `fetch('/api/agent/chat')`.
Payload містить provider, model, messages, redacted evidence context і
one-shot `include_project_context`. Django формує повний контекст без
application count/body/message budget; helper-и redaction не виконують
truncation. Після response додається assistant message і UI знову викликає
`renderAgentChat`.

### Django validation та result

`web/core/urls.py` веде POST `/api/agent/chat` до `agent_chat`.
View перевіряє JSON object, повідомлення та provider-specific config.
Invalid input проходить `_agent_error` і повертається explicit 400.
Поточний runtime не виконує browser actions або engine requests від імені AI.
Result пишеться тільки в `agentChatMessages` та DOM chat log.

### State, errors, limitations

Evidence не прикріплюється автоматично: оператор обирає його явно. Project
context також не додається автоматично: checkbox діє для одного запиту й
скидається у `finally`. При HTTP error `sendAgentChat` показує error message,
скидає busy state та consent.
AI не додає нові History/Traffic records самостійно.
Context не має application count/body/message ceiling перед відправленням;
secret redaction і provider validation лишаються обов'язковими.
Пов'язані symbols: `sendAgentChat`, `renderAgentChat`,
`renderAttachedEvidence`, `_compact_chat_context`, `agent_chat`.
Файли: `web/templates/lab/index.html`, `web/lab/views.py`,
`web/core/urls.py`, `AGENT_USER_GUIDE.md`, `README.md`.

## Трасування повного lifecycle

1. Оператор спочатку створює evidence у Repeater, Intruder, Target, Scanner,
   History або Traffic. AI не сканує workspace самостійно.
2. Кнопка `Send ... to AI` додає конкретний exchange/result до
   `agentChatContext`. У chat payload потрапляє лише явно прикріплений
   context плюс повідомлення оператора.
3. За потреби оператор одноразово вмикає checkbox Project context. UI показує
   активний Project; без нього checkbox disabled.
4. `sendAgentChat` блокує повторне натискання, рендерить user message і
   виконує один POST. Provider credentials залишаються backend-only.
5. `agent_chat` перевіряє CSRF, JSON shape, provider config і required fields.
   Якщо opt-in увімкнено, server бере validated active Project, формує
   redacted summary і передає його разом з evidence без count/body/message
   budget.
6. `generate_agent_chat` обирає adapter і виконує provider call. Це analysis
   boundary: adapter не отримує право викликати engine або browser actions.
7. Успішний provider response повертається як assistant message і додається
   в локальний chat log. Error response проходить `_agent_error`, busy state
   скидається, попередні messages не стираються.
8. One-shot Project consent скидається після success або error. Clear видаляє
   тільки локальні messages/attachments і не змінює source evidence чи jobs.
9. Reload відновлює лише передбачений browser chat/workspace state; provider
   runtime, секрети, Project consent і server-side conversation не стають
   частиною export.

### Контрольні точки безпеки

Перевіряйте: explicit attachment + one-shot Project consent → redacted payload
→ CSRF/provider validation → adapter response → visible assistant/error →
consent reset → no engine side effect.
Будь-яке твердження AI є аналізом evidence, а не автоматичним доказом
уразливості; наступну активну дію оператор запускає окремо.

## Evidence handoff для практичного QA

Після fuzzing, Target map, OSINT або Scanner результат можна передати AI
явною кнопкою `Send ... to AI`. У відповідь AI має розділяти підтверджені
факти, гіпотези та невідомі дані; вона не виконує crawler чи fuzzing сама.
Оператор читає recommendation, обирає URL і створює follow-up workflow:

```text
tool result -> attached evidence -> AI analysis -> operator-selected URL
    -> Repeater / Target / Scanner workflow -> explicit Run
```

Для Intruder/Target Browser активна дія потребує confirmation, а URL
передається оператором. Локальні end-to-end сценарії та fake LLM описані
в [`automation-сценарії.md`](automation-сценарії.md).

---

## 7. Автономний ReAct Агент та MCP-Сервер (v2.0 — Повний спектр інструментів)

Починаючи з версії v2.0, агент Request-Rider забезпечує **100% покриття всіх 15 воркспейсів платформи**:

1. **Інтерактивний чат-асистент (`/api/agent/chat`)**: One-turn аналіз заздалегідь прикріплених доказів без права самостійної відправки мережевих запитів.
2. **Автономний ReAct агент (`/api/agent/run`)**: Багатокроковий дослідницький цикл (Thought -> Action -> Observation -> Final Answer), що має доступ до **71 інструменту** вбудованого реєстру (`web/lab/agent_tools.py`).
3. **Високопродуктивний FastMCP Сервер (`request-rider-mcp/server.py`)**: Надає **62 стандартизованих інструменти** та доступ до 550+ скілів кібербезпеки для зовнішніх систем (Antigravity IDE, Claude Desktop, Cursor, OpenCode runtime, Google Harness 2).

### 7.1. Структура реєстру інструментів (71 інструмент)

| Категорія | Інструменти | Можливості та відповідальність |
|---|---|---|
| **Core & Utilities** | `request_send`, `history_search`, `finding_record`, `url_encode`, `url_decode`, `base64_encode`, `base64_decode`, `random_string`, `normalize_http`, `data_transform` | Сирі HTTP запити, пошук в історії, фіксація вразливостей, кодування/хешування та нормалізація. |
| **Platform & Projects** | `platform_status`, `project_list`, `project_create`, `project_switch_active`, `project_get_knowledge_hub`, `project_update`, `project_delete`, `project_export`, `project_import`, `project_fusion_report` | Повний життєвий цикл проєктів, перемикання скоупу, експорт/імпорт бандлів, Unified Security Fusion Report. |
| **Proxy & History** | `history_get_records`, `history_get_transaction_raw`, `history_record_action`, `history_export_records`, `traffic_control`, `traffic_capture_contexts`, `kebab_send_to_tool` | Керування перехопленням, контексти захоплення, відправка в інші модулі (Kebab), тегування, помітки, експорт історії. |
| **Target & Sitemap** | `target_get_sitemap`, `target_run_crawl`, `target_job_action`, `target_js_analyze`, `target_bypass_403` | Краулер (Go/Browser), ієрархічне дерево цілі, аналіз JS ендпоінтів та секретів, автоматизований 403 Bypass. |
| **Repeater** | `repeater_send_raw_http`, `repeater_burst_test`, `repeater_last_byte_sync`, `repeater_burst_status`, `repeater_burst_cancel`, `repeater_last_byte_status`, `repeater_last_byte_cancel` | Повтор запитів, паралельні Race Condition тести (Burst), синхронізація Last-Byte за стандартом HTTP/1.1 і HTTP/2. |
| **Intruder** | `intruder_start_attack`, `intruder_get_attack_results`, `intruder_action`, `intruder_saved_attacks`, `intruder_fuzz` | Високошвидкісний фазинг маркерів `§...§`, пауза/зупинка, збереження атак та шаблонів. |
| **Scanner** | `scanner_cms_recon`, `scanner_active_start`, `scanner_job_status`, `scanner_get_findings`, `scanner_active_action`, `scanner_corpus_stats`, `scanner_corpus_start`, `scanner_corpus_action`, `scanner_report_generate` | DAST сканування, розвідка CMS, керування активними завданнями, сканування корпусу шаблонів, зведені звіти. |
| **OSINT & Transforms** | `osint_lookup`, `osint_transform_list`, `osint_run_transform`, `osint_recon_action`, `osint_graph_manage`, `osint_job_action`, `osint_file_manage` | 33 утиліти OSINT, візуальний граф зв'язків, фонові розвідувальні завдання, керування файлами результатів. |
| **OAST / OOB** | `oob_generate`, `oob_poll`, `oast_listener_manage` | Out-of-Band взаємодії (DNS/HTTP/SMTP), аналіз зворотних викликів, керування локальним OAST лістенером. |
| **Automation & DAG** | `workflow_catalog`, `workflow_manage`, `workflow_execute` | Каталог типів вузлів та шаблонів, створення та редагування DAG-пайплайнів, запуск та моніторинг виконання. |
| **Route, Tor & DNS** | `route_manage`, `route_check`, `dns_manage` | Керування проксі та Tor SOCKS5h маршрутизацією, перевірка зовнішнього IP, конфігурація та очищення DNS-кешу. |
| **Reports & Skills** | `report_ingest`, `skills_list`, `skills_read`, `harness2_status`, `harness2_run_demo`, `harness_pipeline_info` | Імпорт зовнішніх звітів сканерів, доступ до бібліотеки 550+ скілів, інтеграція з Agent Harness та Google Harness 2. |

### 7.2. Завантаження та аудит файлових звітів

Інтерфейс агента (`web/templates/lab/index.html`) та бекенд підтримують імпорт зовнішніх артефактів:
- **Підтримувані формати**: HTML (звіти краулера/мапи цілей), JSON (структуровані знахідки сканера), HAR (HTTP-архіви), TXT (списки ендпоінтів).
- **Обробка**: Файл парситься на клієнті або на сервері через регулярні вирази й DOM-селектори, витягуються посилання, форми, приховані коментарі та підозрілі параметри.
- **Ін'єкція в контекст**: Витягнуті сутності пакуються у блок `attached_evidence` з міткою `type: file_report`, після чого агент отримує первинний вектор атаки.

### 7.3. Зовнішній FastMCP Сервер (`request-rider-mcp/server.py`)

Для керування Request-Rider із зовнішніх агентських середовищ (Antigravity IDE, Claude Desktop, Cursor, OpenCode тощо) реалізовано FastMCP сервер (Model Context Protocol via stdio):
- **62 зареєстрованих інструменти**, що покривають усі ключові шари платформи.
- **550+ вбудованих скілів з кібербезпеки** (доступні через `skills_list` та `skills_read`).
- **Підтримка детермінованого Agent Harness** (`harness_runner.py verify`).
- **Затримка диспетчеризації**: менше 1 мс на операцію для локальних операцій.

### 7.4. Експорт звітів AI вкладки (HTML / JSON)

У верхню панель вкладки AI додано уніфіковане меню експорту (`#ai-export-btn`):
- **JSON експорт**: Вивантажує повну історію сесії агента з метаданими (timestamp, проект, статус кроків, прикріплені докази та інструментальні виклики).
- **HTML аудит-звіт**: Генерує автономний, адаптивний темний звіт із брендуванням Request-Rider, картками Thought/Action/Observation, підсвічуванням статус-кодів та резюме знахідок, готовий для передачі оператору або клієнту.

### 7.5. Каталог скілів з кібербезпеки та інтеграція Burp Suite

Платформа містить каталог із понад 850 навичок, доступних як внутрішньому агенту, так і через MCP. Зокрема інтегровано офіційні інструкції Burp Suite:
- **`burp-suite`**: Конфігурація проксі, scope-фільтрація, налаштування Match & Replace, списки навантажень для Intruder.
- **`burpsuite-expert`**: Повна методологія тестування складних сценаріїв (обхід WAF, тестування токенів сесії, фазинг бізнес-логіки, верифікація IDOR/BOLA та перевірка ін'єкцій).
