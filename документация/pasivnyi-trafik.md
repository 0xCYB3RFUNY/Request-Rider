# Функція Passive Traffic: повний lifecycle

> Актуально на 2026-09-24. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).

Passive Traffic — це локальний GoProxy MITM, in-memory Store, SSE-потік,
інспекція і явне збереження вибраного exchange.

## Повна схема

```text
Browser proxy 127.0.0.1:8080
    -> goproxy.ServeHTTP
    -> AlwaysMitm for CONNECT
    -> captureRequest()
    -> Store.Add(pending)
    -> shared transport
    -> target
    -> captureResponse()
    -> Store.Update(same ID)
    -> /events/stream
    -> Django traffic_stream()
    -> Traffic table
```

## 1. Startup

Engine створює `passive.NewStore()`, shared transport і
`passive.NewProxy(store, transport, sourceIPCallback)`. Proxy реєструє:

```text
HandleConnect(AlwaysMitm)
blockFirefoxPush
captureRequest
captureResponse
```

Listener працює на `PROXY_LISTEN_ADDR`, default `127.0.0.1:8080`. HTTPS MITM
використовує локальний `data/ca/ca.crt`; приватний `ca.key` не публікується.

## 2. captureRequest

Для кожного browser request:

1. body читається через `readAndRestore`;
2. оригінальний body відновлюється новим reader;
3. headers flatten-яться;
4. binary body кодується base64;
5. SourceIP callback визначає IP через поточний route;
6. створюється Event із `source=proxy`, session, method, URL, host;
7. Store присвоює ID/cursor і одразу broadcast-ить pending event;
8. ID і start time зберігаються у `ProxyCtx.UserData`.

### Явний capture context

Оператор може створити `TrafficCaptureContext` через
`POST /api/traffic/capture-contexts`. Payload містить `name` та обов’язковий
`project_id` або явний `null`; active Project не підставляється автоматично.
Сервер зберігає opaque token і сам підставляє його у browser-driven Target як
`X-RequestRider-Capture-Context` лише коли browser worker справді використовує
local proxy route; token не повертається browser API, direct route не додає
internal header до upstream.

Go proxy читає header перед upstream forwarding і видаляє його з request, тому
token не потрапляє на ціль і не записується у captured request headers. Django
резолвить token у context, перевіряє URL через Project scope і додає до
`TrafficRecord` fields `capture_context_id` та `scope_status`:

- `in_scope` — URL входить до explicit Project scope;
- `out_of_scope` — evidence зберігається, але не приписується Project;
- `unscoped` — context без Project або без token;
- `invalid_context` — token не знайдено.

Live Traffic/SSE віддає browser-safe `capture_context_id`, назву та
`scope_status`, але не показує token. Деактивація context не видаляє вже
збережені exchanges.

## 3. captureResponse

Upstream використовує той самий `http.Transport`, що Repeater/Intruder.
`captureResponse()`:

1. дістає `captureState`;
2. читає і відновлює response body;
3. бере status, headers, type, size;
4. рахує latency від capture start;
5. оновлює event за тим самим ID;
6. повертає response браузеру.

Якщо response nil через transport/TLS failure, статус не вигадується: event
має explicit `error`.

## 4. Store і SSE

Store зберігає `events`, `subscribers`, `nextID`, `nextCursor`, `replay`.
`Add()` публікує event, `Update()` публікує оновлення, `List()` дає snapshot,
`SubscribeSince(cursor)` атомарно повертає backlog і підписує клієнта.
Повільний subscriber не блокує proxy.

```text
GET /events          snapshot hydration
GET /events/stream   cursor backlog + live events
GET /api/traffic     Django snapshot
GET /api/traffic/stream Django SSE proxy
```

Django читає SSE пострічково і не буферизує повний stream.

## 5. UI, persistence і clear

Traffic table показує source, source IP, host, method, URL, status, size,
content type і actions. View відкриває повний inspector. `Save row` створює
durable `TrafficRecord`; proxy event не потрапляє в History автоматично.

`DELETE /api/traffic` викликає Store.Clear: це очищає memory snapshot, а не
завантажує його заново. Restart engine також видаляє live events.

## 6. API і код

```text
GET/DELETE /api/traffic
GET         /api/traffic/stream
POST        /api/traffic/save
POST        /api/traffic/annotate
GET/POST    /api/traffic/capture-contexts
GET/PATCH/DELETE /api/traffic/capture-contexts/<id>
GET         /events
GET         /events/stream
POST        /events/annotate
```

- [engine/pkg/passive/passive.go](../engine/pkg/passive/passive.go)
- [engine/main.go](../engine/main.go)
- [web/lab/views.py](../web/lab/views.py)
- [web/templates/lab/index.html](../web/templates/lab/index.html)
- [browser-worker/worker.py](../browser-worker/worker.py)
- [web/lab/models.py](../web/lab/models.py)
- [web/lab/test_traffic_capture_context.py](../web/lab/test_traffic_capture_context.py)
- [engine/pkg/ca/ca.go](../engine/pkg/ca/ca.go)


## Code walkthrough: Traffic

### UI handlers

Traffic load calls `GET /api/traffic` for snapshot.
`startTrafficStream` opens `GET /api/traffic/stream` as SSE.
Each event updates the table through `scheduleTrafficRender`.
Refresh sends `DELETE /api/traffic` and clears current live snapshot.
Save row sends `POST /api/traffic/save`.
Annotation sends `POST /api/traffic/annotate` with tags and notes.
Rows can open Repeater, Intruder, Comparer, Decoder or AI.

### Gateway and engine

`views.traffic` branches GET/DELETE, calls engine `/events`.
`traffic_stream` reads SSE line-by-line from engine `/events/stream`.
Go `/events` GET returns `store.List`; DELETE calls `store.Clear`.
Go `/events/stream` replays cursor backlog and flushes small events.
`/events/annotate` validates id/tags/notes and updates Store event.

### Event lifecycle

Active request first creates pending event with an id.
Completion updates the same id with status, headers, body and timing.
Sources include proxy, repeater, intruder and route-check.
SSE cursor is persisted client-side for reconnect/backlog replay.
Django `persist_proxy_history` writes selected/completed proxy events to SQLite.
Save row guarantees durable History for selected Traffic exchange.

### Errors and limits

Malformed stream lines are surfaced as stream/gateway errors.
Missing URL on save gives 400; missing event gives explicit invalid error.
Clear deletes Go memory snapshot but does not delete SQLite History.
Restart loses unpersisted Go events.
No artificial event cap is applied before explicit clear.
Symbols/files: `loadTraffic`, `startTrafficStream`, `renderTraffic`,
`saveTraffic`, `annotateTraffic` in `index.html`; `traffic`,
`traffic_stream`, `save_traffic`, `annotate_traffic` in `views.py`;
Store and handlers in `main.go`, `pkg/passive/passive.go`.

## Трасування повного lifecycle

1. На startup engine створює CA/transport/Store і proxy listener. Browser
   certificate trust потрібен для HTTPS MITM; приватний key не виходить за
   межі локальної CA directory.
2. CONNECT або plain HTTP проходить proxy handler. `captureRequest` знімає
   body без руйнування upstream reader, читає й видаляє internal capture
   header, додає pending event і зберігає capture state у request context.
3. Store присвоює event ID/cursor і broadcast-ить його snapshot/SSE clients.
   UI може показати pending row ще до завершення upstream.
4. Upstream використовує route-aware shared transport. На response
   `captureResponse` читає body, рахує latency, flatten-ить headers і
   оновлює той самий event ID. Transport failure залишає explicit error.
5. Django `/api/traffic` дає snapshot, а `/api/traffic/stream` проксуює SSE
   пострічково. Gateway додає browser-safe scope metadata; token не повертається.
   Browser cursor дозволяє reconnect/backlog без повного reload.
6. `renderTraffic` оновлює таблицю через scheduled render, інспектори й
   action buttons. Save/annotate є explicit gateway calls і не виконуються
   автоматично для кожного passive event.
7. Clear видаляє in-memory Store, restart engine робить те саме; вже збережені
   `TrafficRecord` у SQLite залишаються доступними в History.
8. Reload спочатку гідрує snapshot, потім підключає stream із cursor. Якщо
   backlog недоступний, UI показує явний stream error, а не вигадує дані.

### Контрольні точки

`listener → capture pending → cursor/SSE → upstream → update same ID →
render → save/annotate → reconnect/clear` — повний trace Traffic. Для
діагностики перевіряйте event ID, cursor, source, статус pending/completed,
SSE reconnect і різницю між live Store та durable History.
