# Функція Repeater: повний шлях виконання

> Документація ручного редактора та повторювача HTTP-запитів (Repeater).
> Архітектура системи: [arkhitektura-ta-api.md](./arkhitektura-ta-api.md).

Repeater — не просто форма URL. Це browser workflow, який перетворює raw
HTTP editor на структурований JSON, передає його через Django gateway у Go
engine, виконує через поточний transport і розкладає один exchange одночасно
в UI, live Traffic та PostgreSQL History.

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
5. використовує `s.requestTransport()` (із увімкненим ALPN `h2` / `ForceAttemptHTTP2: true`);
6. вимикає automatic redirects через `ErrUseLastResponse`;
7. читає response body повністю;
8. flatten-ить multi-value headers;
9. повертає `proto` (`resp.Proto`), status, status text, latency, size, headers, body і encoding.

### 4.1. Робота з HTTP/2 та версіями протоколу

Repeater підтримує прозору взаємодію з **HTTP/2**:
- **Авто-узгодження (Auto-negotiate):** Якщо запит іде на `https://` і сервер підтримує `h2`, Go-рушій автоматично виконує рукостискання по HTTP/2, повертаючи в панелі статусу `HTTP/2.0 200 OK`.
- **Шестерня налаштувань (`⚙️` / Tab Settings):** У тулбарі Repeater праворуч розміщена іконка налаштувань (або `Ctrl + K`), де в полі **«HTTP Protocol Version»** доступні опції: `Auto-negotiate`, `Force HTTP/1.0`, `Force HTTP/1.1`, `Force HTTP/2`.
- **Збереження у History:** У полі запису `TrafficRecord` зберігається фактично використана версія протоколу.

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

Django створює PostgreSQL row тільки коли engine result має HTTP `status`.
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
History is PostgreSQL; Traffic is Go memory until saved/reloaded.

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

---

## Динамічні інлайн-макроси запитів `{{...}}` (Hackvertor-style Tags)

У Request-Rider реалізовано вбудований препроцесор інлайн-макросів (ROADMAP F2, `engine/macro_eval.go`). Він дозволяє записувати динамічні функції, кодування, хеші та генератори безпосередньо в рядок запиту, заголовки або тіло HTTP-пакета.

Обчислення виконується в Go-рушії безпосередньо перед відправкою кожного пакету, що гарантує генерацію свіжих значень для кожного запиту в **Repeater**, **Intruder**, **Repeater Burst** та **Last-Byte Sync**. Якщо макроси у запиті відсутні, спрацьовує оптимізований fast-path (0 мс накладних витрат).

### Повна таблиця підтримуваних макросів

| Категорія | Макрос | Опис та приклад результату |
|---|---|---|
| **Кодування** | `{{b64(текст)}}` | Стандартне Base64-кодування (`{{b64(admin)}}` → `YWRtaW4=`) |
| | `{{b64url(текст)}}` | Base64 URL-safe без padding (`{{b64url(hello world)}}` → `aGVsbG8gd29ybGQ`) |
| | `{{url_enc(текст)}}` | URL Percent-encoding (`{{url_enc(a b&c=d)}}` → `a+b%26c%3Dd`) |
| | `{{hex(текст)}}` | Шістнадцяткове кодування (`{{hex(admin)}}` → `61646d696e`) |
| | `{{html_enc(текст)}}` | Екранування HTML-сутностей (`{{html_enc(<script>)}}` → `&lt;script&gt;`) |
| **Криптографія та хеші** | `{{sha256(текст)}}` | Hex-хеш SHA-256 (64 символи) |
| | `{{md5(текст)}}` | Hex-хеш MD5 (32 символи) |
| | `{{hmac_sha256(ключ, дані)}}` | Підпис HMAC-SHA256 для API-запитів (`{{hmac_sha256(secret, payload)}}`) |
| **Генератори (на кожен пакет)** | `{{uuid4()}}` | Справжній RFC 4122 v4 UUID (`c23f8b1a-5b12-4a90-84c1-419b12d8a011`) |
| | `{{ts_sec()}}` | Поточний Unix Timestamp у секундах (`1794794856`) |
| | `{{ts_ms()}}` | Поточний Unix Timestamp у мілісекундах (для захисту від replay-атак) |
| | `{{rand_int(min, max)}}` | Випадкове ціле число в діапазоні (`{{rand_int(1000, 9999)}}`) |
| | `{{rand_str(довжина)}}` | Випадковий буквено-цифровий рядок (`{{rand_str(32)}}`) |
| | `{{nonce(байт)}}` | Випадкова криптографічна hex-послідовність (`{{nonce(16)}}` → 32 hex символи) |
| **Секрети та JWT** | `{{$secret.KEY_NAME}}` | Безпечна підстановка секрету проєкту або змінної оточення без витоку в UI |
| | `{{jwt_sign(hdr, pld, key)}}` | Генерація підписаного JWT токена (`header.payload.signature`) |

### Правила вкладеності (Nested Evaluation)
Макроси підтримують вкладеність до 16 рівнів і розгортаються рекурсивно зсередини назовні:
- `{{b64({{sha256(admin)}})}}` — спочатку обчислить хеш `admin`, а потім закодує його в Base64.
- `Authorization: Bearer {{$secret.API_KEY}}` — безпечно вставить токен перед відправкою.
- `X-Request-Nonce: {{nonce(8)}}-{{ts_ms()}}` — згенерує унікальний одноразовий ідентифікатор на кожен повторний клік кнопки `Send` або кожен пакет у Burst.

### Приклад використання у raw-редакторі Repeater

```http
POST /api/v2/checkout HTTP/1.1
Host: shop.target.test
Authorization: Bearer {{$secret.TEST_TOKEN}}
X-Request-ID: {{uuid4()}}
X-Timestamp: {{ts_ms()}}
X-Signature: {{hmac_sha256(my_api_secret, {{ts_ms()}})}}
Content-Type: application/json

{
  "order_id": "{{rand_int(100000, 999999)}}",
  "client_nonce": "{{nonce(16)}}",
  "promo_code": "{{b64(DISCOUNT_2026)}}"
}
```
При кожній відправці (зокрема у пакетному режимі гонки станів `Repeater Burst`) кожен запит матиме власний унікальний `order_id`, `client_nonce`, свіжий `X-Timestamp` та валідний `X-Signature`.

---

## Мульти-акторна матриця авторизації (`Live Auth Matrix`)

**Призначення:** швидка перевірка порушень контролю доступу (**BOLA / IDOR / BFLA / Missing Function Level Access Control**) шляхом одночасного (конкурентного, за 1 мережевий RTT) повторного відправлення поточного HTTP-запиту з правами різних користувачів і ролей проєкту (`Admin`, `Manager`, `User_A`, `User_B`, `Anonymous`).

### Як налаштувати та користуватися
1. Відкрийте вкладку **Repeater** і підготуйте базовий запит (наприклад, `GET /api/v1/orders/1054` або `POST /api/admin/users/delete` з токеном власника/адміна).
2. Натисніть кнопку **`🛡️ Auth Matrix`** (укр. `Матриця доступу`) на верхній панелі інструментів.
3. У лівій частині панелі (**Профілі ролей**) додайте тестових акторів проєкту:
   - **Role name:** назва ролі (`Admin`, `Manager`, `User_B`, `Anonymous`).
   - **Role type:** `admin`, `manager`, `user`, `anon`, `custom`.
   - **Header & Value:** заголовок авторизації (наприклад, `Authorization` → `Bearer <token_user_b>` або `Cookie` → `session=...`). Якщо роль прив'язана до запису `ProjectSecret` через API, використовуйте `${secret}` — сервер автоматично підставить актуальний токен при запуску.
   - **Strip auth (`Без авторизації`):** автоматично вирізає з базового запиту всі авторизаційні заголовки (`Authorization`, `Cookie`, `X-API-Key`, `X-Auth-Token`, `X-Session-ID`, `X-CSRF-Token`) для перевірки анонімного доступу.
   - **Baseline (`Еталон`):** позначає роль, відповідь якої вважається еталонною для власника ресурсу (якщо не позначено — еталоном служить вихідний запит із редактора Repeater).
4. Натисніть **`▶ Run Matrix`**. Go-рушій (`POST /proxy/repeater/auth-matrix`) конкурентно виконає запит для всіх увімкнених ролей, порівняє HTTP-статуси, розміри та структурні JSON-відбитки ключів (`extractJSONKeysFingerprint`) і виведе таблицю результатів.

### Розшифровка вердиктів матриці
| Вердикт | Значення | Інтерпретація для пентестера |
|---|---|---|
| ℹ️ `BASELINE` | Еталонна відповідь | Базовий запит власника ресурсу (наприклад, `200 OK` із повним JSON). |
| 🔒 `ENFORCED` | Доступ заблоковано | Сервер повернув `401`, `403`, `404` або перенаправлення на сторінку логіну. Контроль доступу працює коректно. |
| 🚨 `BYPASSED_IDENTICAL` | Повний обхід (Критично) | Чужа роль або анонім отримали такий самий статус `2xx` та ідентичне тіло / структуру JSON-ключів, як і власник. Прямий доказ **BOLA/IDOR** або **BFLA**. |
| ⚠️ `BYPASSED_PARTIAL` | Частковий обхід / витік | Роль отримала `2xx`-відповідь із частковим перетином полів JSON або іншим обсягом даних. Потребує ручної перевірки на частковий витік даних. |
| ❌ `ERROR` | Мережева помилка | Таймаут або помилка транспортного рівня при виконанні запиту. |

### Побайтове порівняння у `Comparer`
У правому стовпці кожної ролі в таблиці результатів натисніть **`↔ Compare`**. Інтерфейс автоматично відкриє вкладку **Comparer**, завантаживши еталонну відповідь (`Baseline`) ліворуч, а відповідь перевіреної ролі — праворуч для точного побайтового або текстового diff-аналізу.

---

## Хронограф гонок станів та мульти-ендпоінтний бар'єр (`Race Sync / Last-Byte Barrier`)

**Призначення:** детерміноване виявлення вразливостей **Race Condition** (подвійне списання балансу, багаторазове використання промокодів, TOCTOU) як для серії однакових запитів, так і для **різних HTTP-ендпоінтів одночасно** (наприклад, `POST /api/coupon/apply` + `POST /api/order/checkout`).

### Як це працює на рівні мережі (Go Last-Byte Barrier)
1. Для кожного запиту в пачці Go-рушій відкриває TCP-з'єднання, виконує TLS-рукостискання й надсилає весь HTTP-запит **без останнього байта тіла**.
2. Усі сокети стають на спільний бар'єр синхронізації (`sync.WaitGroup` + `releaseCh`) і чекають завершення `Hold (ms)`.
3. Коли всі потоки готові, бар'єр знімається одночасно — і останні байти падають у мережу з мінімальним розльотом (`Race Window Spread (µs)`).
4. Для кожного запиту вимірюються мікросекундні фази (`t_connect_done_us`, `t_tls_done_us`, `t_last_byte_sent_us`, `t_first_byte_recv_us`, `t_done_us`).

### Як користуватися в Repeater
1. Відкрийте вкладку **Repeater** і натисніть кнопку **`⏱️ Race Sync`** (`Гонки (Sync)`).
2. Оберіть режим:
   - **Однозапитний режим:** залиште чергу порожньою, вкажіть `Copies` (напр., `10`) і `Hold (ms)` (напр., `50`).
   - **Мульти-ендпоінтний режим:** формуйте різні запити в редакторі Repeater і додавайте їх у чергу кнопкою **`+ Add Current Request`**.
3. Натисніть **`🚀 Fire Barrier`**.
4. Проаналізуйте **SVG-хронограф** (смуги фаз Connect/TLS → Barrier Hold → TTFB → Body Read) і показник **`Race Window Spread (µs)`**. Якщо кілька запитів одночасно повернули `200 OK` (позначені значком `⚡`) замість `409 Conflict`, це вказує на Race Condition.

---

## Компілятор відтворюваних PoC-експлойтів (`One-Click Export PoC` — F10)

У тулбарі **Repeater** та контекстному меню `#ctx-menu` (`History` / `Traffic`) доступна генерація автономних відтворюваних PoC-скриптів у 4 форматах (`POST /api/poc/generate`):

- **Python PoC (`reproduce_poc.py`)**: Zero-dependency скрипт на Python 3 stdlib (`urllib.request`, `ssl`), який відтворює HTTP-запит, перевіряє статус-код, маркер доказу чи затримку й повертає код виходу `0` (`[+] VULNERABLE`) або `1` (`[-] NOT REPRODUCED / PATCHED`).
- **Playwright (`reproduce_browser_poc.py`)**: скрипт браузерного відтворення DOM/XSS/CSRF із гарантованим закриттям браузера у `finally`.
- **Go Race PoC (`reproduce_poc.go`)**: конкурентний Go-експлойт (`sync.WaitGroup`) для відтворення Race Condition.
- **cURL (`reproduce_poc.sh`)**: форматована команда `curl` з прапорцями маршруту та заголовками.
