# Функція Repeater: повний шлях виконання

> Актуально на 2026-09-25. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).
> Детальний перелік зняття application-level обмежень — у
> [звіті про видалені обмеження](видалені-обмеження.md).

Repeater — не просто форма URL. Це browser workflow, який перетворює raw
HTTP editor на структурований JSON, передає його через Django gateway у Go
engine, виконує через поточний transport і розкладає один exchange одночасно
в UI, live Traffic та SQLite History.

## Повна схема

```text
Browser Repeater
    -> normalize raw request
    -> POST /api/execute
    -> Django execute()
    -> call_engine("/proxy/request")
    -> Go server.request()
    -> addRequestTraffic()              pending event
    -> executeContext()
    -> http.Client + shared transport
    -> Direct або SOCKS5/Tor
    -> target
    -> read response
    -> completeRequestTraffic()         same event ID
    -> Django TrafficRecord.objects.create()
    -> response inspector + History + Traffic
```

## 1. Що вводить UI

Repeater використовує один raw editor. Browser JavaScript витягує method, URL,
headers і body, після чого формує:

```json
{
  "method": "POST",
  "url": "https://example.test/login",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": "{\"user\":\"qa\"}"
}
```

Raw editor не виконує запит самостійно. Browser надсилає лише JSON на Django.
Це дозволяє gateway застосувати єдині нормалізацію, логування і збереження.

## 2. Django gateway

`POST /api/execute` обробляє `views.execute()`:

1. перевіряє HTTP method;
2. розбирає JSON;
3. викликає `normalize_payload()`;
4. передає payload у `call_engine("/proxy/request", payload)`;
5. якщо engine повернув завершений HTTP response, створює `TrafficRecord`;
6. повертає engine result браузеру з тим самим HTTP status.

Gateway не перетворює `4xx/5xx` target response на помилку: за наявності
`result.status` це завершений exchange, який зберігається в History.

## 3. Pending Traffic до upstream

Go `server.request()` спочатку викликає:

```go
eventID := s.addRequestTraffic(input, s.ensureSourceIP(ctx))
```

У Store додається event:

```text
source = repeater
method, url, host
request_headers, request_body
source_ip
status = pending
```

Store присвоює стабільний `ID`, cursor і негайно broadcast-ить подію через
SSE. Тому Traffic може показати запит ще до отримання відповіді.

## 4. Фактичне виконання

`executeContext()`:

1. повторно гарантує Source IP через `ensureSourceIP()`;
2. підставляє `GET`, якщо method порожній;
3. створює `http.NewRequestWithContext`;
4. копіює всі caller headers;
5. використовує `s.requestTransport()`;
6. вимикає automatic redirects через `ErrUseLastResponse`;
7. читає response body повністю;
8. flatten-ить multi-value headers;
9. повертає status, status text, latency, size, headers, body і encoding.

UTF-8 body повертається як `body`. Binary body повертається порожнім `body`
із `body_encoding=base64` і окремим `body_base64`.

## 5. Завершення Traffic event

Після успіху `completeRequestTraffic(eventID, result, nil)` оновлює саме
попередній event:

```text
same ID
    -> status
    -> response_headers
    -> response_body
    -> response_content_type
    -> response_size
    -> latency_ms
```

При transport/TLS/read failure оновлюється лише `error`; штучний HTTP status
не створюється. SSE отримує друге повідомлення з тим самим event ID.

## 6. History

Django створює SQLite row тільки коли engine result має HTTP `status`.
Зберігаються method, URL, request headers/body, response headers/body,
encoding, content type, size, latency і `source_ip`.

Таким чином:

```text
Traffic = live in-memory lifecycle
History = durable completed Repeater exchange
```

## 7. API і код

```text
POST /api/execute
POST /proxy/request
GET  /api/history
GET  /api/traffic
```

- [web/templates/lab/index.html](../web/templates/lab/index.html) — editor,
  send action і inspectors.
- [web/lab/views.py](../web/lab/views.py) — gateway і History persistence.
- [engine/main.go](../engine/main.go) — request, executeContext і Traffic
  lifecycle.
- [engine/routing.go](../engine/routing.go) — Direct/SOCKS5 transport.
- [web/lab/models.py](../web/lab/models.py) — `TrafficRecord`.


## Code walkthrough: Repeater

### DOM

Repeater uses `#repeater-host`, `#repeater-path`, `#send`, `#copy`,
`#repeater-compare-response`, `#clear`, and `#repeater-send-ai`.
Raw request editor state is held by the active repeater workspace.
Response request/response inspectors are updated after execution.

### JS chain

Send click -> `send` -> raw editor parser -> payload builder.
Payload is normalized before `fetch('/api/execute')`.
Response passes `readJSON`, then response renderer and exchange state.
Completed exchange can call `saveHistory`, comparer, or AI attachment.
Copy reads rendered response; Clear resets current workspace fields.

### JSON and gateway

The logical payload contains method, URL, headers and body; optional query/cookies
are normalized by Django `normalize_payload` into URL and Cookie header.
`POST /api/execute` -> `views.execute` -> `normalize_payload` ->
`call_engine('/proxy/request', payload)`.
Invalid JSON is 400; engine status/body are returned explicitly.
A completed HTTP 4xx/5xx is still a response and is persisted.

### Go chain and storage

Go `server.request` -> `requestInput` decode -> `execute` -> `executeContext`.
Transport uses route manager and captures status, headers, body, size and time.
Django creates `TrafficRecord(source='repeater')` for completed responses.
Engine publishes pending/completed exchange to Traffic Store and SSE.
History is SQLite; Traffic is Go memory until saved/reloaded.

### Buttons, errors, limits

Send disables/re-enables around fetch and displays explicit error text.
Copy is browser clipboard only and does not create a record.
Compare sends response string to comparer, not backend.
Clear does not delete History or Traffic records.
No retry is silently performed; timeout/network errors remain errors.
Symbols/files: `send`, raw parser/render helpers in `index.html`,
`execute`, `normalize_payload`, `call_engine` in `views.py`,
`server.request`, `executeContext` in `engine/main.go`.

### Inspector highlight

Панель відповіді `#response` і read-only `Raw`-превʼю інспектора запиту
(`#ri-raw-preview`, оновлюється в `riRefresh()`) рендеряться через спільний
`highlightHTTPText`: request line, статус, заголовки, чутливі
`Authorization`/`Cookie`/`Set-Cookie`/`X-API-Key` (`http-sensitive-token`) і
ключі-секрети в тілі (`password`, `token`, `secret`, `credit_card`, `email`,
`auth`, включно з JSON `"key":` формою). Copy читає `textContent`, тому
копіює чистий текст без markup. Редагований raw editor лишається
`<textarea>` і не підсвічується технічно.

## Трасування повного lifecycle

1. Оператор відкриває Repeater workspace, вводить raw request і натискає
   `Send`. До мережі ще нічого не надсилається: UI лише читає editor state.
2. Parser визначає request line, URL, headers і body. Некоректний URL або
   порожній метод перетворюються на явну помилку до/під час gateway validation.
3. `normalize_payload()` приводить метод, URL, headers, query і cookies до
   єдиного engine contract. Browser не обходить цей шар прямим викликом Go.
4. Go створює pending Traffic event **до** outbound dial. Через це оператор
   бачить незавершений exchange навіть під час повільного DNS/TLS/upstream.
5. Route manager вибирає Direct або налаштований SOCKS5/Tor transport. Route
   не перемикається непомітно на Direct при помилці.
6. Response або transport error проходить одним із двох завершальних шляхів:
   HTTP response зберігає status/body, а network/TLS/read failure зберігає
   explicit error без вигаданого status.
7. Django створює durable History row лише для завершеного HTTP exchange.
   Traffic event оновлюється тим самим ID, тому live і durable представлення
   не утворюють дублікати.
8. UI оновлює response inspector, metadata, workspace state і доступні
   actions (Comparer, Decoder, AI). Clear очищає лише поточний workspace,
   а не History/Traffic.
9. Після reload відновлюються поля workspace та останній локальний response,
   але memory-only engine Traffic і незавершений outbound job не гарантуються.

### Перенесення налаштувань в Automation

Кнопка `Send to Automation` у toolbar вкладки Repeater читає поточний active
workspace, повторно розбирає raw request і передає у workflow typed-вузол
`repeater` з `method`, `url`, `headers`, `body` та `delay_ms`. Для нового draft
автоматично додається manual trigger; наявний workflow зберігається через
`PATCH /api/workflows/<id>`, а для нового — `POST /api/workflows`.

Після переходу в Automation inspector показує типові поля Repeater. Кнопки
`Use current workspace` і `Open in tool` дозволяють повторно взяти параметри з
відкритої вкладки або завантажити node params у Repeater. Перенесення не
виконує outbound-запит і не змінює History; лише workflow/workspace state.

### Контрольні точки та діагностика

- Browser: `send`/`readJSON`, `automationNodeFromTool()` і response renderer.
- Gateway: `execute` → `normalize_payload` → `call_engine`.
- Engine: `server.request` → `executeContext` → Traffic Store.
- Persistence: `TrafficRecord.objects.create` для History.
- Перевіряти потрібно HTTP status, source/route metadata, повторну появу
  record у History і відсутність console/network помилок.
