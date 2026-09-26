# Функція Proxy і маршрутизація мережевих запитів

> Актуально на 2026-09-25. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).
> Детальний перелік зняття application-level обмежень — у
> [звіті про видалені обмеження](видалені-обмеження.md).

Цей документ описує фактичну реалізацію функції Proxy у RequestRider:
налаштування вихідного маршруту, виконання активних запитів через Direct або
SOCKS5/Tor, роботу локального passive MITM proxy та шлях подій до Traffic,
History і Source IP.

## 1. Два різні проксі-механізми

У проєкті є два пов’язані, але різні механізми:

1. **Спільний вихідний маршрут для активних інструментів** — Direct або
   SOCKS5/Tor. Його використовують Repeater, Intruder, Target, OSINT,
   Scanner, route check і upstream passive proxy.
2. **Локальний passive MITM proxy** на `127.0.0.1:8080`. Через нього можна
   пропускати браузерний HTTP/HTTPS-трафік, перехоплювати запити та відповіді
   і показувати їх у Traffic.

Активні інструменти не проходять повторно через локальний MITM-порт `:8080`.
Вони використовують той самий outbound transport і публікують завершені
обміни безпосередньо у спільний Traffic Store.

## 2. Загальна архітектура

```text
Browser :8000
    -> Django web gateway
        -> Go engine :8081
            -> shared http.Transport
                -> Direct або SOCKS5/Tor
                    -> target server
```

Для браузерного трафіку через passive MITM:

```text
Browser
    -> HTTP/HTTPS proxy 127.0.0.1:8080
        -> Go passive MITM proxy
            -> shared http.Transport
                -> Direct або SOCKS5/Tor
                    -> target server
```

Локальні адреси за замовчуванням:

```text
127.0.0.1:8000  Django UI
127.0.0.1:8080  passive HTTP MITM proxy
127.0.0.1:8081  Go engine API
127.0.0.1:9050  локальний SOCKS5 Tor
```

У Docker engine використовує адресу Tor-сервісу в мережі Compose:

```text
tor:9050
```

`127.0.0.1:9050` у контейнері означав би loopback самого engine-контейнера, а
не Tor-контейнер.

## 3. Додавання SOCKS5-маршруту в UI

У вкладці **Tor/Proxy** поле `SOCKS5 address` приймає адресу формату:

```text
host:port
```

Приклади:

```text
127.0.0.1:9050
tor:9050
proxy.example:1080
```

Порожнє значення означає Direct:

```text
address = ""
```

Підказка UI повідомляє, що вибраний маршрут застосовується до Repeater,
Intruder, Target, OSINT, Scanner і upstream passive proxy.

Відповідна розмітка і browser JavaScript розташовані у
[web/templates/lab/index.html](../web/templates/lab/index.html).

## 4. Повний маршрут застосування конфігурації

```text
Browser
    |
    | PUT /api/route
    v
Django :8000
    |
    | POST /route
    v
Go engine :8081
    |
    | routeManager.set(...)
    v
Новий dialer Direct або SOCKS5
    |
    | CloseIdleConnections()
    | наступні запити повторно перевіряють source IP
    v
Наступні запити використовують новий маршрут
```

### Крок 1. UI надсилає конфігурацію

Функція `applyRoute()` відправляє:

```http
PUT /api/route
Content-Type: application/json

{
  "address": "127.0.0.1:9050"
}
```

### Крок 2. Django gateway

Django endpoint `GET/PUT /api/route`:

1. читає JSON;
2. витягує `address`;
3. передає адресу Go engine;
4. повертає відповідь engine браузеру.

Django не виконує активний target-запит самостійно. Його роль — browser-facing
gateway.

Реалізація знаходиться у
[web/lab/views.py](../web/lab/views.py), URL map — у
[web/core/urls.py](../web/core/urls.py).

### Крок 3. Go engine змінює route manager

Go endpoint `GET/PUT /route` передає конфігурацію до `routeManager.set`.
Реалізація знаходиться у
[engine/main.go](../engine/main.go) та
[engine/routing.go](../engine/routing.go).

Якщо адреса порожня:

```text
routeManager
    -> net.Dialer
    -> target напряму
```

Якщо адреса задана:

```text
routeManager
    -> SOCKS5 dialer
    -> SOCKS5 host:port
    -> target
```

Для SOCKS5 використовується `golang.org/x/net/proxy`. Стандартні змінні
`HTTP_PROXY` або `HTTPS_PROXY` для цього маршруту не використовуються.

## 5. Спільний HTTP transport

Після створення route manager engine створює один спільний
`http.Transport`.

```text
http.Client
    -> shared http.Transport
        -> routeManager.dialContext
            -> Direct net.Dialer
            або
            -> SOCKS5 dialer
```

У transport:

```go
Proxy: nil
DialContext: m.dialContext
```

Тобто вибір маршруту відбувається на рівні встановлення TCP-з'єднання, а не
через URL-префікс або системну proxy-змінну.

## 6. Маршрут Repeater

```text
Browser
    -> POST /api/execute
    -> Django :8000
    -> POST /proxy/request
    -> Go engine :8081
    -> executeContext(...)
    -> http.Client
    -> shared transport
    -> Direct або SOCKS5/Tor
    -> target
```

Go створює outbound HTTP-запит з методом, URL, заголовками і body, після чого
виконує його через shared transport. Redirects не виконуються автоматично:
перший HTTP-відповідь повертається оператору для аналізу.

Після завершення:

1. Go повертає status, headers, body, size, latency і source IP;
2. Repeater event оновлюється у Traffic Store;
3. Django зберігає завершений exchange у SQLite History;
4. браузер показує відповідь у Repeater і таблицях.

## 7. Маршрут Intruder

```text
Browser
    -> POST /api/intruder
    -> Django
    -> POST /proxy/intruder
    -> Go engine
    -> payload generation
    -> worker pool
    -> executeContext() для кожного job
    -> shared transport
    -> Direct або SOCKS5/Tor
    -> target
```

Кожен job є окремим HTTP-запитом із згенерованим payload. Для кожного
результату зберігаються method, URL, status, response size, latency, body та
source IP.

Завершені Intruder exchange публікуються в Traffic Store із:

```text
source = "intruder"
```

Django також зберігає результати атаки в History без повторного дублювання під
час інкрементального polling.

## 8. Маршрут Target, OSINT і Scanner

Усі ці активні інструменти використовують той самий transport:

```text
Target / OSINT / Scanner
    -> Go engine
    -> shared http.Transport
    -> Direct або SOCKS5/Tor
    -> target
```

Після `Apply route` нова адреса застосовується до нових запитів цих
інструментів. Окремої proxy-конфігурації для кожного інструмента немає:
маршрут є спільним для process-wide engine.

## 9. Перевірка маршруту і зовнішнього IP

Кнопка `Check connection` викликає:

```http
POST /api/route/check
```

Django передає запит у:

```http
POST /route/check
```

Go виконує через shared transport два незалежні запити:

```text
1. заданий target URL
2. https://check.torproject.org/api/ip
```

Для target відображаються:

- доступність;
- HTTP status;
- latency;
- помилка, якщо з'єднання не встановлено.

Для Tor Project API відображаються:

- зовнішня IP;
- latency;
- HTTP status;
- помилка, якщо endpoint недоступний.

Приклад відповіді API IP:

```json
{
  "IsTor": true,
  "IP": "203.0.113.10"
}
```

У коді IP валідовується через `net.ParseIP`. Значення не зберігається в
process-wide кеші: кожен outbound exchange окремо звертається до endpoint.

## 10. Автоматичне визначення Source IP

Перед кожним активним або passive-запитом engine запускає один свіжий
`ensureSourceIP` через `https://check.torproject.org/api/ip` і той самий
generation-bound transport. Для Repeater lookup очікується до result; для
Intruder, Burst, Last-Byte і passive proxy значення оновлюється для кожного
exchange, а passive event спочатку публікується як pending. Process-wide cache
немає.

```text
Кожен exchange
    |
    v
GET https://check.torproject.org/api/ip
    |
    v
shared transport
    |
    v
Direct або SOCKS5/Tor
    |
    v
прочитати і валідовати IP
    |
    v
вписати IP у поточний Traffic/History result
```

Після зміни маршруту engine:

```text
закриває idle connections
    -> кожен наступний запит все одно робить окрему перевірку IP
```

Тому History і Traffic показують IP саме поточного вихідного маршруту, а не
старе значення до зміни proxy.

Якщо SOCKS5 недоступний, запит завершується явною помилкою. Непомітного
fallback у Direct немає.

## 11. Локальний passive MITM proxy

Engine додатково слухає:

```text
127.0.0.1:8080
```

Браузер потрібно налаштувати так:

```text
HTTP proxy:  127.0.0.1
HTTP port:   8080
HTTPS proxy: 127.0.0.1
HTTPS port:  8080
```

Для HTTPS використовується локальний CA:

```text
data/ca/ca.crt
data/ca/ca.key
```

У тестовому профілі браузера потрібно довірити лише `ca.crt`. Приватний ключ
`ca.key` не можна публікувати, комітити або додавати до журналів.

Passive proxy створюється через GoProxy і використовує той самий shared
transport, тому його upstream-маршрут змінюється разом із маршрутом активних
інструментів.

## 12. HTTP-запит через passive proxy

```text
Browser
    -> GET http://target/
    -> 127.0.0.1:8080
    -> captureRequest()
    -> pending Traffic event
    -> shared transport
    -> Direct або SOCKS5/Tor
    -> target
```

`captureRequest()`:

1. читає request body;
2. відновлює body, щоб upstream отримав ті самі bytes;
3. фіксує method, URL, host і headers;
4. визначає Source IP;
5. створює pending event;
6. пропускає запит далі.

## 13. HTTPS-запит через passive MITM

```text
Browser
    -> CONNECT target:443
    -> 127.0.0.1:8080
    -> GoProxy AlwaysMitm
    -> локальний CA завершує TLS для тестового браузера
    -> captureRequest()
    -> shared transport
    -> Direct або SOCKS5/Tor
    -> target:443
```

MITM працює лише для браузера, який довіряє локальному тестовому CA. Це не
змінює маршрут активного Repeater або Intruder.

## 14. Отримання відповіді passive proxy

Після upstream-відповіді викликається `captureResponse()`:

1. читається response body;
2. body відновлюється і повертається браузеру;
3. записуються HTTP status і headers;
4. зберігається body або його base64-представлення;
5. обчислюються response size і latency;
6. оновлюється той самий Traffic event за тим самим ID.

Lifecycle:

```text
Request received
    -> Traffic event: pending, ID=123
    -> upstream request
    -> response received
    -> Traffic event: ID=123, status=200, response body
```

Якщо HTTP-відповіді немає через transport або TLS failure, event зберігає
явну `error`, а не штучний успішний status.

## 15. Як дані потрапляють у Traffic

```text
Go passive Store
    -> GET /events
    -> GET /events/stream
    -> Django /api/traffic
    -> Browser Traffic table
```

SSE передає pending event і наступне оновлення того самого exchange. У Traffic
можуть бути джерела:

```text
proxy
repeater
intruder
route-check
```

Traffic Store живе в пам'яті engine. Перезапуск engine або очищення Traffic
видаляє незбережені live events. `Save row` переносить вибраний exchange у
Django History/SQLite.

## 16. Як дані потрапляють у History

History є SQLite-сховищем Django:

```text
Repeater завершився
    -> Django отримав response
    -> TrafficRecord.objects.create(...)
    -> History API
    -> History table
```

Intruder результати зберігаються під час polling із `result_offset`,
`proxy_session` і `proxy_event_id`, щоб один result не створював дублікати.

Passive proxy events спочатку є лише live Traffic. Вони не додаються в History
автоматично, доки оператор не використає `Save row`.

## 17. Що відбувається при Cancel route

```http
PUT /api/route
Content-Type: application/json

{
  "address": ""
}
```

Після цього:

```text
SOCKS5 route вимикається
    -> routeManager повертається до net.Dialer
        -> скасовується старий route generation
            -> закриваються idle connections
                -> кожен новий запит окремо перевіряє IP
                    -> нові запити йдуть напряму
```

Apply/Cancel route є momentary kill switch: активні engine jobs, passive
exchanges, workflow runs, browser-worker jobs і provider requests старого
generation скасовуються. Новий маршрут гарантовано використовується для
нових з'єднань; старий exchange не може перейти на новий dialer після barrier.

## 18. Підтримувані та непідтримувані режими

Підтримується:

```text
Direct
SOCKS5 host:port
SOCKS5/Tor
спільний маршрут для всіх активних інструментів
спільний маршрут для upstream passive proxy
```

Через поточний UI не реалізовано:

```text
HTTP proxy
HTTPS proxy
Proxy username/password
кілька proxy одночасно
окремий proxy для кожного інструмента
proxy rotation
```

## 19. Основні API

### Django gateway

```text
GET/PUT /api/route
POST    /api/route/check
POST    /api/execute
POST    /api/intruder
POST    /api/target-map
GET     /api/traffic
GET     /api/traffic/stream
POST    /api/traffic/save
```

### Go engine

```text
GET  /route
PUT  /route
POST /route/check
POST /proxy/request
POST /proxy/intruder
GET  /proxy/intruder/<attack_id>
GET  /proxy/target-map/<map_id>
GET  /events
GET  /events/stream
```

## 20. Пов'язані файли реалізації

- [engine/routing.go](../engine/routing.go) — Direct і SOCKS5 dialer.
- [engine/main.go](../engine/main.go) — engine API, shared transport, route
  check, source IP, Repeater, Intruder і listeners.
- [engine/pkg/passive/passive.go](../engine/pkg/passive/passive.go) — passive
  MITM, CA, capture lifecycle і Traffic Store.
- [web/lab/views.py](../web/lab/views.py) — Django gateway, History і Traffic.
- [web/core/urls.py](../web/core/urls.py) — browser-facing API routes.
- [web/templates/lab/index.html](../web/templates/lab/index.html) — Proxy UI.
- [README.md](../README.md) — загальна архітектура і запуск.


## Literal code walkthrough

### DOM controls and handlers

Proxy tab uses `#route-address`, `#route-apply`, `#route-cancel`.
Check UI uses `#route-check-url`, `#route-check-timeout`, `#route-check`.
`loadRoute` runs during initialization and fills address/summary.
`applyRoute` disables Apply, sends PUT, then calls `updateRouteSummary`.
`cancelRoute` sends an empty address and restores Direct label.
`checkRoute` disables Check and calls `renderRouteCheck`.

### JSON and Django chain

Route payload is exactly `{"address":"host:port"}`.
Cancel payload is exactly `{"address":""}`.
Check payload is `{"url":"https://check.torproject.org/","timeout_ms":15000}` за
замовчуванням UI; користувач може задати інше значення, а `0` вимикає timeout.
`web/core/urls.py` maps `/api/route` and `/api/route/check`.
`views.route` GET uses `call_engine_get('/route')`.
PUT/POST uses `call_engine('/route', {'address': address})`; успішна відповідь
містить `generation` та `kill_switch` з переліком скасованих web/workflow/
browser operations. `GET` залишається read-only і не запускає drain.
`views.route_check` validates URL and timeout before `call_engine`.
Malformed JSON, wrong method and invalid ranges have explicit errors.

### Go chain and transitions

`server.route` -> JSON decode -> `routes.set` -> close idle connections.
`routeManager.set` selects Direct dialer or x/net SOCKS5 dialer.
All active HTTP clients use `routeManager.dialContext`.
`server.routeCheck` builds client with timeout and no redirect follow.
Target GET -> `publishRouteCheckTraffic` -> target result.
IP GET -> JSON `ip` parse -> `store.Update` source IP.
Both events are available to `/events` and `/events/stream`.

### Storage and limitations

Route config is Go memory only; no SQLite persistence.
Workspace stores UI fields in localStorage.
Traffic event is Go memory until Save row.
External IP endpoint availability is independent of target availability.
Proxy mode does not automatically configure browser proxy settings.
Symbols/files: `loadRoute`, `applyRoute`, `cancelRoute`, `checkRoute`,
`renderRouteCheck`, `route`, `route_check`, `routeManager.set`,
`routeManager.dialContext`, `server.routeCheck`, `index.html`, `views.py`,
`main.go`, `routing.go`, `pkg/passive/passive.go`.

## Трасування повного lifecycle

1. Browser відкриває вкладку й отримує фактичний route snapshot через
   `loadRoute`; локально збережений workspace не вважається authoritative
   станом engine.
2. Apply проходить DOM validation, trim-ить address і відправляє PUT у Django.
   Gateway перевіряє method/JSON, Go route handler валідує SOCKS5, скасовує
   старий generation і перемикає dialer. `CloseIdleConnections` відділяє старі
   keep-alive від нових запитів; активні exchanges отримують context cancel.
3. Наступний Repeater/Intruder/OSINT/Scanner/Target exchange викликає спільний
   `dialContext` і окремий source-IP lookup, тому route застосовується
   централізовано, а не копіюється в кожен інструмент.
4. Check створює два логічні probes: target і external IP. Перший визначає
   target status/error, другий — фактичний egress IP; помилка другого не
   стирає валідний результат першого.
5. Обидва probes публікуються в Traffic як pending/completed events. UI
   `renderRouteCheck` відображає summary, status, latency і локалізовані
   labels, а Save row є окремою дією оператора.
6. Cancel route передає empty address, повертає Direct для нових dial і
   скасовує активні старі exchanges. Status/result після barrier не можуть
   виглядати як successful old-route completion.
7. Engine restart очищає route config і live Traffic. UI після reload має
   повторно отримати engine state; старі route-check rows залишаються лише
   якщо їх було явно збережено в History.

### Контрольні точки

`actual snapshot → validated PUT → routeManager.set → idle close → shared
transport → target/IP probes → Traffic update → render/save → cancel/reload`.
Під час troubleshooting порівнюйте UI address, engine `/route`, event source,
target status, external IP і route metadata у завершеному exchange.
