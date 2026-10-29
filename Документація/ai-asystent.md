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

## 7. Автономний ReAct Агент та MCP-Сервер (v1.2+)

Починаючи з версії v1.2, платформа підтримує два взаємодоповнюючі режими роботи ШІ:

1. **Інтерактивний чат-асистент (`/api/agent/chat`)**: One-turn аналіз заздалегідь прикріплених доказів без права самостійної відправки мережевих запитів.
2. **Автономний ReAct агент (`/api/agent/run`)**: Багатокроковий дослідницький цикл (Thought -> Action -> Observation -> Final Answer), що має доступ до повнофункціонального реєстру інструментів.

### 7.1. Реєстр інструментів агента (`web/lab/agent_tools.py`)

Агент оперує стандартизованими JSON-інструментами (сумісними зі специфікаціями MCP та OpenAI Function Calling):

| Інструмент | Опис | Дія в системі |
|------------|------|---------------|
| `history_search` | Пошук у базі перехоплених HTTP-запитів (`TrafficRecord`) проекту | Фільтрація за URL, методом, статусом та ключовими словами без побічних ефектів. |
| `request_send` | Формування та відправка сирого HTTP-запиту через Go-проксі рушій | Виклик `/proxy/request`, збереження відповіді в базі `TrafficRecord` із міткою джерела `ai_agent`. |
| `finding_record` | Реєстрація підтвердженої вразливості або аномалії | Автоматичний розрахунок `identity_hash` та збереження/оновлення у звіт `ScannerRun` проекту. |
| `url_encode` / `url_decode` | URL-кодування та декодування пейлоадів | Безпечна підготовка рядків із спецсимволами (`+`, `%20`) без галюцинацій моделі. |
| `base64_encode` / `base64_decode` | Base64-кодування та декодування | Підтримка стандартного та URL-safe формату для токенів, сесій і бінарних ін'єкцій. |
| `random_string` | Криптографічна генерація випадкових токенів | Створення нонсів довжиною до 1024 символів (набори `hex`, `digits`, `alpha`, `alphanumeric`, `special`). |
| `normalize_http` | Нормалізація CRLF прелюдії (стиль PortSwigger) | Забезпечення стандарту RFC `\r\n` для заголовків при збереженні тіла (payload) недоторканим. |
| `oob_generate` | Генерація OOB-маркера та SSRF/XXE шаблонів | Створення токена `rroob_<hex>` та готових векторів для сліпих атак (аналог Burp Collaborator). |
| `oob_poll` | Опитування історії трафіку на предмет зворотних викликів | Швидкий пошук у базі історії (індекс шляху) для підтвердження спрацювання сліпого вектора. |

### 7.2. Завантаження та аудит файлових звітів

Інтерфейс агента (`web/templates/lab/index.html`) та бекенд підтримують імпорт зовнішніх артефактів:
- **Підтримувані формати**: HTML (звіти краулера/мапи цілей), JSON (структуровані знахідки сканера), HAR (HTTP-архіви), TXT (списки ендпоінтів).
- **Обробка**: Файл парситься на клієнті або на сервері через регулярні вирази й DOM-селектори, витягуються посилання, форми, приховані коментарі та підозрілі параметри.
- **Ін'єкція в контекст**: Витягнуті сутності пакуються у блок `attached_evidence` з міткою `type: file_report`, після чого агент отримує первинний вектор атаки.

### 7.3. Зовнішній MCP-сервер (`tools/mcp/server.py`)

Для керування Request-Rider із зовнішніх агентських середовищ (Antigravity IDE, Claude Desktop, Cursor, OpenCode тощо) реалізовано високопродуктивний MCP-сервер (Model Context Protocol via stdio):
- **16 зареєстрованих інструментів**:
  - Стан та історія: `request_rider_status`, `request_rider_history_search`.
  - Відправка запитів: `request_rider_request_send`, `request_rider_request_send_h2` (нативний HTTP/2 клієнт).
  - Нормалізація та утиліти: `request_rider_normalize_http`, `request_rider_url_encode`, `request_rider_url_decode`, `request_rider_base64_encode`, `request_rider_base64_decode`, `request_rider_random_string`.
  - OOB взаємодія: `request_rider_oob_generate`, `request_rider_oob_poll`.
  - Автономний агент та звіти: `request_rider_agent_run`, `request_rider_report_ingest`.
  - База навичок: `request_rider_skills_list`, `request_rider_skills_read`.
- **Затримка диспетчеризації**: менше 1 мс на операцію для локальних інструментів кодування та нормалізації.

### 7.4. Експорт звітів AI вкладки (HTML / JSON)

У верхню панель вкладки AI додано уніфіковане меню експорту (`#ai-export-btn`):
- **JSON експорт**: Вивантажує повну історію сесії агента з метаданими (timestamp, проект, статус кроків, прикріплені докази та інструментальні виклики).
- **HTML аудит-звіт**: Генерує автономний, адаптивний темний звіт із брендуванням Request-Rider, картками Thought/Action/Observation, підсвічуванням статус-кодів та резюме знахідок, готовий для передачі оператору або клієнту.

### 7.5. Каталог скілів з кібербезпеки та інтеграція Burp Suite

Платформа містить каталог із понад 850 навичок, доступних як внутрішньому агенту, так і через MCP. Зокрема інтегровано офіційні інструкції Burp Suite:
- **`burp-suite`**: Конфігурація проксі, scope-фільтрація, налаштування Match & Replace, списки навантажень для Intruder.
- **`burpsuite-expert`**: Повна методологія тестування складних сценаріїв (обхід WAF, тестування токенів сесії, фазинг бізнес-логіки, верифікація IDOR/BOLA та перевірка ін'єкцій).
