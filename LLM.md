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
