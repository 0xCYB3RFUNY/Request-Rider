# Tor/Proxy

> Актуально на 2026-09-25. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).
> Детальний перелік зняття application-level обмежень — у
> [звіті про видалені обмеження](видалені-обмеження.md).

## Призначення

Tor/Proxy налаштовує маршрут outbound-запитів engine.
Порожня адреса означає Direct.
Непорожня адреса означає SOCKS5 `host:port`.
Це не змінює налаштування proxy самого браузера.
Для passive MITM браузер окремо використовує локальний `:8080`.

## UI схема

Секція `#proxy` описана в `web/templates/lab/index.html`.
`#route-address` редагує SOCKS5 address.
`#route-apply` застосовує нову конфігурацію.
`#route-cancel` надсилає порожню address.
`#route-check-url` задає check target; типове значення —
`https://check.torproject.org/`.
`#route-check-timeout` задає timeout milliseconds.
`#route-check` запускає перевірку.
`#route-summary` показує protocol/address/status.
`#route-check-result` показує target/IP outcome.

На старті `loadRoute` робить `GET /api/route`.
`applyRoute` робить `PUT /api/route`.
Payload точний: `{"address":"127.0.0.1:9050"}`.
`cancelRoute` використовує `{"address":""}`.
`checkRoute` надсилає `{"url":"https://check.torproject.org/","timeout_ms":15000}`.
Зовнішня IP перевіряється окремим запитом через
`https://check.torproject.org/api/ip`; результат містить `is_tor`.

## Django gateway

`web/core/urls.py` маршрутизує `/api/route` і `/api/route/check`.
`views.route` приймає GET та POST/PUT.
GET повертає engine snapshot.
POST/PUT вимагає JSON object.
Address trim-иться перед передачею.
Неправильний method дає 405.
Malformed route JSON дає 400 `invalid route: ...`.
`views.route_check` приймає лише POST.
URL є обов'язковим absolute HTTP(S) target.
Timeout є явним user parameter; `0` означає без timeout, верхня межа не
застосовується.
Invalid payload дає 400 `invalid route check: ...`.

## Project live transport

`GET /api/project-events/status` повертає `{"websocket": true}` лише коли
Django запущено через ASGI `core.asgi`. У локальному WSGI `runserver` response
має `false`, тому UI не створює гарантовано помилковий WebSocket reconnect.
Це не змінює Direct/SOCKS5 routing і не блокує жоден tool.

## Go route manager

`engine/main.go` реєструє `/route` та `/route/check`.
`routeManager` знаходиться в `engine/routing.go`.
Для Direct `net.Dialer` не отримує прихованого application timeout/keepalive
ceiling.
Для SOCKS5 використовується `x/net/proxy.SOCKS5`.
Невалідний SOCKS5 configuration дає `INVALID_ROUTE`.
Після set engine закриває idle connections, скасовує generation context старого
route і не допускає, щоб старий lease використав новий dialer. Source IP metadata
виконує один свіжий запит на кожен exchange через
`https://check.torproject.org/api/ip`; process-wide кеш відсутній, тому перший
exchange після зміни також має власний lookup і не очікує «pending refresh».
Помилка
SOCKS5 не робить silent fallback у Direct. Transport усіх активних інструментів
і passive proxy використовує актуальний `dialContext` після перемикання.

## Route check flow

`routeCheck` валідує absolute target URL.
Default timeout — 15 s.
HTTP client не слідує redirects.
Спочатку GET-иться target через поточний transport.
Результат має status, status_code/status_text або error.
Latency записується в `latency_ms`.
Окремо GET-иться `https://check.torproject.org/api/ip`.
IP JSON очікує поля `ip` та `IsTor`; failure не підставляє старий IP.
External result має status, status_code, ip/is_tor, error і latency_ms.
Загальний status error, якщо target request failed.
IP може бути unavailable незалежно від target.

## Traffic, state, limitations

Target та IP subrequests публікуються у Traffic Store.
Успішний external IP оновлює source IP target event.
UI render показує `Route`, target outcome, External IP і Checked.
Route config живе в Go memory і зникає після restart.
UI route fields не зберігаються у workspace localStorage state: після reload
`loadRoute` читає actual server snapshot. Persistent proxy workspace містить лише
check URL/timeout/result fields.
Traffic events memory-only до Save row/clear/restart.
Активні інструменти не проходять повторно через MITM :8080.
Symbols/files: `loadRoute`, `applyRoute`, `cancelRoute`, `checkRoute`,
`renderRouteCheck`, `views.route`, `views.route_check`,
`server.route`, `server.routeCheck`, `routeManager.set`,
`routeManager.dialContext`; файли `index.html`, `views.py`, `urls.py`,
`main.go`, `routing.go`.

## Додатковий literal walkthrough

### DOM handlers

`loadRoute` читає GET result і викликає `updateRouteSummary`.
`applyRoute` читає `#route-address`, disable-ить Apply і робить PUT.
`cancelRoute` робить PUT з empty address і відновлює Direct.
`checkRoute` читає target/timeout, disable-ить Check і робить POST.
`renderRouteCheck` наповнює result/status blocks.

### Backend sequence

Django route -> `views.route` або `views.route_check`.
`call_engine_get`/`call_engine` формують internal engine URL.
Go `server.route` -> `routes.set` -> transport.CloseIdleConnections.
Go `server.routeCheck` -> target client.Get -> publishRouteCheckTraffic.
Потім client.Get(sourceIPCheckURL) -> IP parse -> store.Update.
Response повертається через gateway у browser.

### States and errors

Direct state має `{address:""}`.
SOCKS5 state має trimmed `{address:"host:port"}`.
Invalid method/payload — 405/400.
Invalid SOCKS address — `INVALID_ROUTE`.
Target failure зберігає target error і загальний status error.
IP failure не обов'язково робить target failure.
Events отримують pending/completed lifecycle і live SSE consumers.
Route config після restart не відновлюється з SQLite.

## Трасування повного lifecycle

1. На відкритті вкладки UI читає route snapshot із engine після restore
   workspace; route address, protocol і summary не беруться зі старих
   workspace/localStorage полів.
2. Apply trim-ить address і передає PUT. Django route barrier тимчасово
   закриває admission, engine атомарно готує новий dialer, скасовує старий
   route generation, закриває idle connections і лише потім нові exchange
   бачать route. Workflow, browser-worker і provider sockets старого покоління
   отримують cancel.
3. Direct — порожня address і `net.Dialer`; SOCKS5 — validated host/port і
   `x/net/proxy`. Невдалий set не робить silent fallback у Direct.
4. Check запускає target request через актуальний transport, потім окремий
   external-IP request. Два результати можуть мати різні помилки й latency.
5. Go публікує route-check subrequests у Traffic з pending/completed lifecycle,
   Django повертає summary у browser, UI локалізує status/labels.
6. Cancel route є explicit PUT з empty address. Він повертає Direct для
   наступних з'єднань і скасовує активні операції старого route generation;
   вже відкритий Repeater/Intruder/Target/Last-Byte/passive exchange не
   залишається виконуватися через старий dialer.
7. Reload відновлює browser workspace text, але route fields повторно отримує
   actual engine snapshot; якщо engine restart-нувся, Direct є лише фактичним
   станом після нового GET, а не старим localStorage fallback.

### Контрольні точки

`GET snapshot → edit → PUT set → close idle → new outbound dial → route check
target/IP → Traffic events → explicit cancel → reload`. Для діагностики
порівнюйте configured address, summary protocol, target status, external IP,
latency і engine route state.
