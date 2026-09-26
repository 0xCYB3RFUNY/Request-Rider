# AI-вкладка RequestRider

AI-вкладка призначена для аналізу конкретних результатів ручного тестування.
Вона не надсилає весь workspace автоматично.

## Актуальний стан ітерацій

AI працює лише з evidence, яке оператор явно прикріпив через UI. Зміна мови
не повинна змінювати або втрачати прикріплені дані. Після змін у AI або
пов'язаних workspace виконуйте алгоритм з [AGENTS.md](./AGENTS.md):
перевірка правил, targeted і regression-тести, живий браузер, reload і
перевірка console/network.

## Робочий сценарій

1. Виконайте потрібну дію у Repeater, OSINT, Target Map, Scanner або Intruder.
2. У History/Traffic виберіть потрібні рядки, якщо треба передати лише їх.
3. Натисніть відповідну кнопку `Send ... to AI`.
4. Відкрийте AI, поставте питання про прикріплені дані.
5. Перегляньте блок `Attached to chat` і переконайтеся, що прикріплено саме
   потрібне evidence.

Кнопки прикріплення передають дані в локальний стан браузерного чату. Нове
звичайне повідомлення без натиснутої кнопки не викликає завантаження History,
Traffic або іншого workspace context.

## Що можна передати

- повний Repeater request/response;
- результати Intruder;
- Target Map;
- OSINT і Scanner results;
- вибрані або доступні History records;
- вибрані або доступні Traffic records;
- власне operator observation у тексті повідомлення.

Exchange передається без автоматичного приховування полів: headers, cookies,
Authorization, JWT, request/response body, payloads, status, content type,
size, latency, tags і notes можуть бути частиною evidence. Для remote provider
перевірте політику endpoint-а та допустимість передачі цих даних.

## Provider

Для локальної інфраструктури використовуйте Ollama. Також доступні OpenAI,
Anthropic, OpenRouter, Gemini, Groq, Mistral і custom OpenAI-compatible
endpoint. API key надсилається adapter-ом у заголовку та не записується у
chat context.

Provider відповідає текстовим аналізом. AI не запускає Repeater, Intruder,
OSINT, Scanner, Target Map або інші функції RequestRider. Для remote provider
використовується HTTPS; локальний Ollama працює через loopback.

## Як ставити питання

Добре працюють запити:

- «Порівняй ці два response і назви спостережувані відмінності».
- «Які endpoint-и в цьому Target Map виглядають реальними, а які схожі на SPA
  fallback?»
- «Проаналізуй Intruder results і запропонуй мінімальну наступну перевірку».
- «Знайди підозрілі security headers у прикріплених Traffic records».

Просіть AI відокремлювати факти від гіпотез. Observable change не є автоматично
доказом уразливості.


# AI Chat Runtime RequestRider

Цей документ описує поточну AI-функцію RequestRider. Це conversational chat
для аналізу явно прикріплених оператором спостережень, а не автономного
виконання довгих місій.

## Поточний workflow

```text
ручний OSINT / Target Map / Scanner / Repeater / Intruder / History / Traffic
        ↓
оператор натискає Send ... to AI
        ↓
прикріплені exchange/results зберігаються в стані чату
        ↓
оператор ставить питання у вкладці AI
        ↓
POST /api/agent/chat
        ↓
provider аналізує лише повідомлення та прикріплений evidence
```

Контекст не завантажується автоматично для звичайного повідомлення. Це
дозволяє окремо передавати результат Intruder, конкретні History/Traffic
записи, Repeater exchange або результати OSINT/Scanner/Target Map.

## API

Поточний browser-facing AI API:

| Метод | Шлях | Призначення |
|---|---|---|
| `POST` | `/api/agent/chat` | Один conversational turn |

Приклад запиту:

```json
{
  "provider": "ollama",
  "messages": [
    {"role": "user", "content": "Проаналізуй прикріплені endpoint-и"}
  ],
  "context": {
    "kind": "request_rider_selected_evidence",
    "attached_evidence": {
      "history": [{"url": "https://target.example/api", "status": 200}]
    }
  }
}
```

`context` приймається тільки у формі `attached_evidence`, яку створюють кнопки
`Send ... to AI`. Без прикріпленого evidence до provider передаються лише
системна інструкція та chat messages. Backend компактно обмежує розмір
прикріпленого evidence. Повний request/response context може містити cookies,
Authorization, JWT, параметри, payloads, headers і binary body у base64.
Оператор сам натискає кнопку передачі й обирає provider.

## Provider connection

Підтримуються `ollama`, `openai`, `anthropic`, `openrouter`, `gemini`, `groq`,
`mistral` та `openai_compatible`. Mock provider у продукті відсутній;
`unittest.mock` у тестах використовується лише для patching.

AI не має tools, execution profile, доступу до History/Traffic API, Go engine,
shell, filesystem або arbitrary HTTP. Він може лише сформувати текстову
аналітичну відповідь через обраний provider. Remote provider endpoint має
використовувати HTTPS; локальний Ollama дозволений лише на loopback.

AI endpoint захищений Django CSRF-проверкою. Frontend передає CSRF token у
заголовку, а backend відхиляє старі execution payloads та не запускає жодну
операцію RequestRider з відповіді provider.

## Межі достовірності

LLM відділяє факт, гіпотезу та наступну перевірку. Один HTTP `200` не доводить
існування endpoint-а у SPA: для цього аналізуються body fingerprint, size,
content type, headers, status і `same_as_baseline`. `verify_blackbox_change`
підтверджує лише спостережувану зміну, а не автоматично вразливість.

Активні інструменти зберігають чинні scope, execution profile, budget,
rate-limit, concurrency та audit-перевірки. Post-compromise фази не
виконуються; `prepare_controlled_phase` створює лише checklist.

## Важливі файли

- `web/lab/agent_services.py` — provider adapters і prompt;
- `web/lab/views.py` — chat endpoint та evidence compaction;
- `web/templates/lab/index.html` — AI UI та кнопки прикріплення evidence;
- `web/core/urls.py` — browser-facing routes.
