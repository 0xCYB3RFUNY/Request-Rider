# Функція Intruder: повний шлях атаки і результатів

> Документація фаззера (Intruder): режими комбінування пейлоадів, маркери та обробка результатів.
> Архітектура системи: [arkhitektura-ta-api.md](./arkhitektura-ta-api.md).

Intruder — асинхронний генератор і виконавець HTTP jobs. UI формує одну
базову raw request із marker-ами, Django передає attack definition, Go
генерує jobs, виконує їх worker pool-ом і повертає результати частинами.

## Повна схема

```text
UI raw request + markers + dictionaries
    -> POST /api/intruder
    -> Django intruder()
    -> POST /proxy/intruder
    -> attack ID
    -> marker parsing + transformations
    -> Generate(mode)
    -> worker pool
    -> executeContext() per job
    -> GET /proxy/intruder/<id>
    -> Django persist_intruder_results()
    -> Intruder table + Traffic + History
```

## 1. Формування definition

UI надсилає:

```json
{
  "base_request": {
    "method": "GET",
    "url": "https://example.test/search?q=§term§",
    "headers": {},
    "body": ""
  },
  "mode": "sniper",
  "payloads": [["admin", "test"]],
  "dictionaries": {},
  "transformations": [],
  "delay_ms": 150,
  "concurrency": 1
}
```

Marker-и підтримують `§name§`, `{{name}}` і `%name%`. Parser проходить URL,
headers і body у wire order; глобальний offset означає, що positions
замінюються в єдиній послідовності.

## 2. Django lifecycle

`views.intruder()` розділяє операції:

- `POST` — передати definition і запустити attack;
- `GET` — прочитати status/results;
- `POST action=pause|resume` — керувати lifecycle;
- `DELETE` — cancel engine attack.

Django може зберегти `IntruderAttack` для повторного запуску, але оперативний
progress і result state живуть у Go process memory.

## 3. Генерація jobs

`intruder.Generate()` відхиляє definition без marker або payload set:

- **Sniper** створює job для кожного marker окремо, решта values порожні;
- **Battering Ram** повторює один payload у всі marked positions;
- **Pitchfork** бере однаковий index у dictionaries до shortest;
- **Cluster Bomb** рекурсивно будує Cartesian product.

Перед replacement кожен payload проходить `TransformPayload()` зліва направо:

```text
urlEncode -> prepend -> base64Encode -> append
```

Невідома transformation або malformed decode зупиняє generation з explicit
error. Binary bytes не відкидаються через відсутність UTF-8.

## 4. Worker execution

Go створює `attack` із cancel context, `resumeCh`, counters і result state.
Worker pool бере jobs із channel. `delay_ms > 0` серіалізує запити з паузою;
`concurrency` визначає кількість workers без прихованого верхнього cap.

Кожен job:

1. замінює markers у URL, headers і body;
2. викликає `executeContext()` (використовує вихідний транспорт із підтримкою HTTP/2 ALPN `h2`, що забезпечує мультиплексування запитів);
3. зберігає HTTP result або explicit error;
4. публікує exchange у Traffic як `source=intruder`;
5. збільшує completed/failed.

### 4.1. HTTP/2 Мультиплексування та атаки на стан гонки (Last-Byte Sync)

- При фазингу HTTPS-цілей пул з'єднань рушія автоматично узгоджує протокол HTTP/2 через розширення ALPN.
- Для перевірки вразливостей стану гонки (Race Conditions) використовується спеціалізований рушій **Last-Byte Sync** (`engine/last_byte.go`): він виконує парсинг фреймів HTTP/2 (з валідацією довжини кадру від 9 байт) і притримує фінальні байти запитів для їх одночасної синхронної відправки на ціль (Single-Packet Attack). В актуальному UI інтерактивна панель керування Last-Byte Barrier (`⏱️ Race Sync` / `#repeater-race-btn`) розміщена у вкладці **Repeater** (`_repeater.html` → `/api/repeater/last-byte`).

Окремі job start/complete logs не пишуться, щоб великі атаки не перевантажували
terminal і disk; залишаються aggregate lifecycle logs.

## 5. Polling і deduplication

`GET /proxy/intruder/<id>` повертає `status`, counters, `result_offset` і
порцію `results`. UI запитує наступну порцію через offset і додає лише нові
virtualized rows.

Django передає `proxy_session` та `proxy_event_id`, тому повторний polling не
створює дублікати History. Result має generated request поруч із response:
method, URL, payload, status, size, time, headers, body і source IP.

## 6. Pause, resume, cancel

Pause блокує видачу нових jobs через `resumeCh`, але не обриває поточний
outbound exchange. Resume відкриває канал. DELETE викликає context cancel і
переводить attack у `cancelled`.

`pagehide` не скасовує атаку. Cancel можливий тільки явною кнопкою.

## 7. API і файли

```text
POST   /api/intruder
GET    /api/intruder?attack_id=<id>
POST   /api/intruder?attack_id=<id>&action=pause|resume
DELETE /api/intruder?attack_id=<id>
GET/POST /api/intruder/saved
POST   /api/intruder/saved/<id>/run
POST   /proxy/intruder
GET    /proxy/intruder/<id>
DELETE /proxy/intruder/<id>
```

- [web/templates/lab/tabs/_intruder.html](../web/templates/lab/tabs/_intruder.html)
- [web/lab/views.py](../web/lab/views.py)
- [engine/main.go](../engine/main.go)
- [engine/pkg/intruder/intruder.go](../engine/pkg/intruder/intruder.go)
- [web/lab/models.py](../web/lab/models.py)


## Code walkthrough: Intruder

### UI handlers

The UI reads raw request editor, marker selection, mode, dictionaries,
transformations, concurrency and delay controls.
Run builds a `base_request` and payload sets.
Save calls `/api/intruder/saved`; load calls GET saved configurations.
Pause/resume uses action query; Cancel uses DELETE.
Polling updates the compact result table incrementally.
Each result can open full request/response inspector or Comparer.

Inline preview словника не рендериться: великі словники залишаються лише в
textarea і не розтягують панель Intruder. Це не змінює серіалізацію
transformations, підрахунок jobs чи виконання атаки.

### Exact request/state

The logical POST contains `base_request`, `mode`, `payloads` or `dictionaries`,
`transformations`, `delay_ms`, and `concurrency`.
`POST /api/intruder` returns `attack_id` and initial state.
`GET /api/intruder?attack_id=id&since=n` повертає усі доступні нові
results, `result_offset`, progress і lifecycle status; application-level
result cap не застосовується.
`POST ...?attack_id=id&action=pause|resume` changes lifecycle state.
`DELETE /api/intruder?attack_id=id` cancels the attack.

### Django chain

`views.intruder` branches GET, DELETE, action POST, or start POST.
Start parses JSON and normalizes `base_request`.
It calls `call_engine('/proxy/intruder', payload)`.
GET calls `call_engine_get` and `persist_intruder_history` using offset.
DELETE calls `call_engine_delete`; action calls `call_engine_action`.
Saved config view stores `IntruderAttack` in PostgreSQL and can rerun it.

### Go chain

`server.intruder` -> marker position extraction -> `intruder.Generate`.
Transformations run left-to-right before job creation.
`runAttack` executes generated jobs with worker pool or sequential delay mode.
Each job replaces markers in URL, headers and body.
`executeContext` performs the outbound request through route transport.
`publishIntruderTraffic` emits pending/completed Traffic events.
`intruderStatus` -> `attackSnapshot` returns incremental results.

### Branches and storage

Sniper, Battering Ram, Pitchfork and Cluster Bomb select different generators.
HTTP 4xx/5xx with a response are valid results; no-response is `error`.
Pause/resume changes scheduling, cancel closes context.
Django persists each new result once using proxy session/event IDs.
Go attack state is in memory and disappears after restart.
PostgreSQL History remains after restart; Traffic is memory-only unless saved.

### Buttons and symbols

Run starts; Save stores; Load hydrates; Pause/Resume controls lifecycle.
Cancel is the only destructive attack action and requires explicit click.
Clear removes displayed result state but does not cancel unless specified by UI.
Result rows keep two quick icons (Inspect, Repeater) and hide the rest in the
`⋯` floating menu (`#ctx-menu`): Compare, Repeater, Send to Automation (новий
Repeater-вузол з тригером через `sendRequestToAutomation`). Повторний клік по
`⋯` закриває меню; шапка меню показує `#індекс · статус` рядка.
Symbols: `runIntruder`, polling/render functions, `persist_intruder_history`,
`intruder_saved`, `server.intruder`, `runAttack`, `intruderStatus`,
`attackSnapshot`, `intruder.Generate`; files `index.html`, `views.py`,
`main.go`, `pkg/intruder/intruder.go`, `models.py`.

## Трасування повного lifecycle

1. UI спочатку показує review: target, method, route, mode, delay,
   concurrency і estimated jobs. Запуск до перевірки definition не вважається
   початком атаки.
2. Raw request розбирається в marker positions у wire order. Dictionary,
   payload sets і transformations перевіряються до POST; відсутній marker або
   payload дає explicit validation error.
3. Django нормалізує definition і створює/повертає attack context лише після
   успішного виклику engine. Невдалий engine response не маскується під
   запущену атаку.
4. Go materializes jobs згідно з mode, після чого worker pool бере jobs із
   черги без прихованого count ceiling. `delay_ms` регулює старт наступного
   job, `concurrency` регулює одночасно активні workers.
5. Кожен job отримує власний generated request, проходить transformations,
   route transport і `executeContext`. HTTP 4xx/5xx є нормальним результатом,
   а відсутність response — окремим error.
6. Для кожного exchange Go публікує pending/completed Traffic events. Polling
   через `since`/`result_offset` забирає лише нову порцію, тому повторний
   запит не дублює таблицю або History.
7. Pause зупиняє видачу нових jobs, resume продовжує той самий attack context,
   Cancel закриває context. Поточний низькорівневий request може завершитися
   перед фінальним `cancelled`.
8. Після completion UI залишає результати доступними для inspect, Compare,
   Repeater, AI, Automation (`#intruder-send-automation`) та експорту у 4 форматах (`#intruder-export`: **JSON**, **HTML**, **CSV**, **XML**). Saved attack зберігає definition, але не
   гарантує збереження runtime progress після restart Go.

### Додаткові параметри UI, детектор успішного логіну та налаштування (`⚙️`)
- **Блок `Detect a successful login` (`#intruder-detection`)**: прапорець `#detect-enabled` (`checked`), 5 чіпів сигналів (`#detect-signals`: `status`, `redirect`, `cookie`, `length`, `body`), `#detect-tolerance` (`min="0"`, дефолт `32`), `#detect-calibration` (`min="1"`, `max="100"`, дефолт `3`), правила (`#detect-rule-type`: `body_contains`, `body_not_contains`, `header_contains`, `status_equals`; `#detect-rule-regex`), фільтр `#attack-only-matches` (`Only matches`) і сортування за колонкою `Match`.
- **13 трансформацій пейлоада (`#transform-operation`)**: `urlEncode`, `base64Encode`, `base64UrlEncode`, `hexEncode`, `htmlEntityEncode`, `jsonEscape`, `unicodeEscape`, `whitespaceNormalize`, `trim`, `lowercase`, `uppercase`, `prepend`, `append`.
- **Target Override та результати**: `#intruder-host`, `#intruder-port`, `#intruder-https`, `#clear-attack`, `#attack-sort` / `#attack-sort-direction`.
- **Налаштування (`⚙️` → `#tool-pane-intruder`) та кутові дії**: `.tab-faq-trigger` (`❓ FAQ`), `.tab-settings-trigger` (`⚙️`: `#setting-intruder-mode` = `sniper`, `#setting-intruder-concurrency` = `1`, `#setting-intruder-delay` = `150`, `#setting-intruder-detect-enabled` = `checked`, `#setting-intruder-autoscroll` = `checked`).
9. Після reload відновлюються локальні settings/result view, а durable
   Intruder/History records залишаються в PostgreSQL незалежно від engine memory.

### Контрольні точки

Перевіряйте послідовно: marker parser → job estimate → `POST /api/intruder`
→ `attack_id` → incremental polling → pause/resume/cancel → deduplicated
History → final export. На кожній точці помилка має залишатися видимою, а
часткові результати — доступними для аналізу.

---

## Використання інлайн-макросів `{{...}}` в Intruder

Препроцесор макросів Go-рушія (`engine/macro_eval.go`) підтримується і в Intruder. Це дозволяє поєднувати позиційні маркери пейлоадів `§...§` із динамічними генераторами та трансформаціями:

1. **Динамічний захист від блокування за Replay:**
   Якщо цільовий сервер вимагає унікальний `X-Request-ID` або підпис часу `X-Timestamp` на кожен запит, вставте в шаблон запиту:
   ```http
   X-Request-ID: {{uuid4()}}
   X-Timestamp: {{ts_ms()}}
   ```
   Intruder генеруватиме нове значення часу та UUID для кожної ітерації окремо.

2. **Комбінація з маркерами фаззингу:**
   - Хешування або кодування маркера «на льоту»:
     ```http
     POST /api/login HTTP/1.1
     ...
     {"user": "§admin§", "hash": "{{sha256(§password§)}}", "nonce": "{{nonce(8)}}"}
     ```
   - Захист HMAC-підписом:
     ```http
     X-Signature: {{hmac_sha256($secret.API_KEY, §payload§)}}
     ```
Підстановка маркерів `§...§` виконується на етапі генерації запитів, після чого Go-рушій у `executeContext` розгортає всі макроси `{{...}}` перед відправкою у сокет.
