# Функція AI Assistant: повний шлях контексту

> Актуально на 2026-09-25. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).
> Детальний перелік зняття application-level обмежень — у
> [звіті про видалені обмеження](видалені-обмеження.md).

AI Assistant — Django endpoint для одного chat turn. Він не має автономного
доступу до engine: аналізує тільки evidence, яке оператор явно додав із
History, Traffic або Intruder, і — лише після one-shot checkbox — повний
redacted context активного Project.

## Повна схема

```text
Browser AI tab
    -> selected provider/model + message
    -> explicitly attached evidence
    -> optional one-shot active Project context
    -> POST /api/agent/chat
    -> CSRF-protected Django agent_chat()
    -> validate JSON and provider config
    -> build redacted context
    -> generate_agent_chat()
    -> provider response/error
    -> JSON answer
    -> browser chat
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

## 5. Обмеження дій

AI не має права самостійно:

```text
POST /proxy/request
POST /proxy/intruder
POST /proxy/target-map
змінювати /route
надсилати форми
виконувати exploit або bypass
```

Будь-який активний запит запускається лише окремою дією оператора в
відповідному інструменті.

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
в [`automation-сценарії.md`](automation-сценарії.md) і
[`agent-workspace/tests/e2e/README.md`](../agent-workspace/tests/e2e/README.md).
