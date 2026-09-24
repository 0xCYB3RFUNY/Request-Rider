# OSINT

> Актуально на 2026-09-24. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).

## Призначення і межі

OSINT — пасивний збір відкритих DNS та HTTP-метаданих для однієї URL-цілі.
Вкладка не є повноцінним crawler і не виконує JavaScript.
Вона не зберігає live result автоматично в History або SQLite; durable
Entity Graph записується лише через explicit graph API. Запити виконуються Go
engine через поточний Direct/SOCKS5 transport.
Працювати слід лише з дозволеними цілями.

## Entity Graph foundation

Для durable Project knowledge додано окремий graph contract:

- `OsintGraph` — name, версія, `schema_version`, current/archived status, source і metadata;
- `OsintEntity` — normalized identity, type, risk score, properties, provenance, `observed_at`;
- `OsintRelation` — typed edge між entities того самого graph.

Entities мають project-scoped unique identity та idempotent upsert. Підтримані
типи: Domain, Subdomain, IP, CIDR, URL, Email, Username, ASN, Certificate,
Technology, Port, Cloud asset. Relations мають bounded allow-list типів.

API:

```text
GET/POST /api/osint/graphs
GET      /api/osint/graphs/<id>
POST     /api/osint/graphs/<id>/upsert
```

`POST /api/osint/graphs` вимагає explicit `project_id`; `?project_id` лише
фільтрує list і не змінює active Project session. Upsert приймає лише bounded
entities/relations, canonicalizes URL без query credentials, redacts common
secret markers у provenance та не приймає arbitrary metadata types.

## Entity Graph canvas

У секції `#osint` реалізовано read-only local graph canvas на native browser
SVG. Він не завантажує CDN, не додає React Flow/Tailwind і не виконує
third-party JavaScript. Native SVG обрано як прозорий local-first renderer:
DOM nodes доступні keyboard/focus, а graph лишається deterministic та auditable
без окремого asset pipeline.

Життєвий цикл UI:

1. Після вибору active Project `#osint-graph-select` завантажує лише графи
   цього Project.
2. `Create graph` створює versioned graph через CSRF-protected API; `Add entity`
   додає bounded custom entity через idempotent upsert.
3. `#osint-graph-canvas` показує entity nodes, relations, type colors і risk
   score. `Auto-layout` перемикає deterministic grid/radial layout.
4. `#osint-graph-filter` фільтрує type, identity, risk і bounded properties;
   relations показуються лише коли обидва endpoints видимі.
5. Click або keyboard Enter відкриває details drawer з identity, type, risk,
   `observed_at`, properties і redacted provenance.
6. Context menu right-click показує лише transforms, сумісні з entity type.
   Local transforms виконуються одразу; `subdomains` і `github_recon` вимагають
   окремого confirmation dialog. Жоден transform не запускається з пасивного
   OSINT result автоматично.

Canvas має browser budget до 1000 visible entities за один render; 500+ node
сценарій перевірено Firefox E2E. Для більшого graph UI показує bounded
`rendered/total` stat і не виконує unbounded DOM expansion. Graph selection,
filter, layout і selected entity зберігаються в OSINT workspace state та
відновлюються після reload; серверний graph лишається project-scoped source of
truth. Усі user-controlled labels виводяться через DOM `textContent`/escaped
markup, а POST UI додає CSRF token.

Native SVG canvas не є physics engine: positions детерміновані, а drag/zoom,
force-directed layout і live passive-to-graph ingestion залишаються окремими
наступними ітераціями.

## Local transform registry

Graph API exposes a bounded transform catalog at `GET /api/osint/transforms` and
runs one explicitly selected transform at
`POST /api/osint/graphs/<id>/transform`.

Available transforms:

- `email_recon` — local email normalization and domain expansion; no mass
  social-profile requests;
- `username_enum` — local username canonicalization; external platform mass
  enumeration is disabled;
- `ip_geo` — local IP normalization with optional environment-only
  `OSINT_GEOIP_JSON` lookup; no database download;
- `subdomains` — bounded crt.sh plus DNS guesses, only with
  `confirm_network=true`;
- `github_recon` — bounded public GitHub profile lookup, only with
  `confirm_network=true`; commit/email extraction is not performed.

Every transform is bounded, uses the Go engine, returns explicit warnings, and
its entities/relations are persisted through the same idempotent graph upsert.
Network transforms require a separate confirmation and never run implicitly as
part of passive discovery.

## UI-схема

Розмітка знаходиться в `web/templates/lab/index.html`, секція `#osint`.
Поле `#osint-url` приймає абсолютну адресу цілі.
Checkbox `#osint-waf-check` керує benign WAF canary.
Кнопка `#osint-run` запускає перевірку.
Кнопка `#osint-clear` перериває активний запит і скидає форму.
`#osint-export` завантажує повний результат як JSON.
`#osint-export-csv` flatten-ить результат у CSV.
`#osint-send-ai` передає явно вибраний результат AI-вкладці.
Graph controls: `#osint-graph-create`, `#osint-graph-add`,
`#osint-graph-refresh`, `#osint-graph-layout`, `#osint-graph-filter`,
`#osint-graph-canvas`, `#osint-graph-details` та `#osint-graph-menu`.

UI відображає `#osint-summary`, `#osint-dns`, `#osint-http`,
`#osint-security`, `#osint-tech`, `#osint-discovery` і `#osint-cookies`.
`runOSINT` бере `value.trim()` і відхиляє порожній URL до fetch.
Для browser request створюється `AbortController`.
Timeout UI дорівнює 30000 ms.
При зміні URL поточний controller abort-иться і старий результат скидається.

## Payload gateway

Запит UI має точну форму:

```json
{"url":"https://example.test/","waf_check":true}
```

UI надсилає `POST /api/osint` з `Content-Type: application/json`.
`web/core/urls.py` маршрутизує endpoint до `views.osint`.
Django приймає тільки POST.
JSON мусить бути object, а `url` — непорожнім після trim.
Gateway нормалізує payload до `url` та boolean `waf_check`.
До engine виконується `call_engine('/proxy/osint', payload)`.
Gateway не додає History-запис і не модифікує Traffic.

## Go endpoint і валідація

`engine/main.go` реєструє `POST /proxy/osint`.
Handler декодує `osintInput` з полями `URL` і `WAFCheck`.
Невалідний JSON дає `400` з кодом `INVALID_JSON`.
URL без host або не `http`/`https` дає `400 INVALID_TARGET_URL`.
Помилка верхнього збору дає `502 OSINT_CHECK_FAILED`.
Успішний результат повертається як JSON з HTTP 200.

## Послідовність engine

Handler trim-ить URL і парсить його через `url.Parse`.
Далі викликається `runOSINT(parsed, input.WAFCheck)`.
Спочатку визначається hostname і створюється базовий result.
`lookupHostWithRetry` робить до двох DNS спроб.
Кожна DNS спроба має context timeout 2 секунди.
Між спробами є пауза 250 ms.
DNS section містить `host`, `mx`, `ns`, `txt`.

Потім `fetchOSINTPage` робить HTTP GET через OSINT client.
User-Agent встановлюється як `RequestRider-OSINT/1.0`.
Redirects обробляються вручну, щоб зберегти всі hops.
Ліміт redirect loop — вісім кроків.
Результат записує фінальний HTTP metadata та `redirect_chain`.

## Схема результату

Базові поля: `url`, `host`, `checked_at`, `errors`.
`checked_at` — UTC RFC3339 timestamp.
`http` містить status, headers та аналіз відповіді.
`technologies` — список fingerprint-ів.
`security_headers` — результати header checks.
`cookies` — атрибути Set-Cookie.
`discovery` — знайдені публічні resource references.
`waf` містить `detected`, `vendors`, `confidence`,
`confidence_percent` та `evidence`.
`waf_check` додається лише при `waf_check=true`.

Якщо DNS не вдався, IP list залишається порожнім,
а текст помилки додається до `errors`.
Якщо HTTP не вдався, engine повертає partial result зі статусом 200.
У такому partial result HTTP має error, а залежні секції порожні.
Це навмисно не success-shaped fallback: помилка явно присутня в `errors`.

## State, export і помилки UI

Останній result тримається у browser variable `currentOSINT`.
Export JSON серіалізує весь result без скорочення body metadata.
CSV рекурсивно flatten-ить sections у `section`, `path`, `value`.
Ім'я файлу має timestamp і не використовує server storage.
Успішний render активує export buttons.
Abort при clear або input change не показується як помилка.
Інші exceptions відображаються у `#osint-status` з error class.

Graph result не додається до `currentOSINT` і не виконує transform автоматично.
Canvas читає durable graph через project-scoped API; custom entity, refresh,
filter, layout і selection зберігаються у browser workspace state. Після reload
UI відновлює вибраний graph, але сервер залишається єдиним source of truth для
entities, relations, provenance та versioning.

## Обмеження і пов'язані symbols

OSINT не виконує форми, JS або активне fuzzing.
WAF canary є окремою opt-in операцією і не є exploit.
Mass email/username enumeration, GitHub commit scraping и automatic MaxMind
downloads не виконуються; network adapters мають bounded confirmation boundary.
Canvas не виконує drag/zoom, force-directed layout або passive-to-graph
ingestion; custom graph changes require explicit UI/API action. Результат
зберігається в session workspace лише для browser state, а durable graph
потрібує server API. Основні symbols: `runOSINT`, `renderOSINT`,
`downloadOSINT`, `downloadOSINTCSV`, `loadOsintGraphs`, `renderOsintGraph`,
`selectOsintGraphEntity`, `runOsintGraphTransform`, `fetchOSINTPage`,
`lookupHostWithRetry`,
`detectTechnologies`, `securityHeaderChecks`, `discoverOSINTResources`,
`detectWAF`, `runWAFCanary`.
Пов'язані файли: `index.html`, `web/lab/views.py`, `web/lab/osint_graph.py`,
`web/lab/models.py`, `web/core/urls.py`, `engine/main.go`, `engine/routing.go`.

## Додатковий literal walkthrough

### Entity Graph canvas

`osint-graph-create click` -> CSRF `POST /api/osint/graphs` -> select graph ->
`GET /api/osint/graphs/<id>` -> `renderOsintGraph` -> SVG nodes/relations.
`osint-graph-add click` -> local dialog -> CSRF graph upsert -> reload selected
graph. Node click або Enter відкриває `#osint-graph-details`; right-click
відкриває `#osint-graph-menu`. Context-menu transform виконує лише після
`requestConfirmDialog` для network adapter, а після response граф перечитується
з API. `#osint-graph-refresh` не запускає network transform і не змінює
server data. Workspace capture зберігає `graphId`, `graphFilter`,
`graphLayout` та `graphSelectedId`.

### Кнопки і DOM

OSINT Run читає `#osint-url` і `#osint-waf-check`.
Перед fetch викликається `resetOSINTResult` і встановлюється status.
Після fetch викликається `renderOSINT`.
Clear викликає `AbortController.abort`, очищає поля та `queueWorkspacePersistence`.
Export JSON викликає `downloadOSINT`.
Export CSV викликає `downloadOSINTCSV`.
Send AI використовує current result як explicit evidence.

### Call chain і transitions

`osint-run click` -> controller -> `fetch('/api/osint')` -> `readJSON`.
`readJSON` або повертає object, або кидає помилку HTTP.
Django `osint` -> `call_engine` -> Go `server.osint`.
Go `server.osint` -> `runOSINT` -> DNS helpers -> `fetchOSINTPage`.
Далі йдуть technology/header/cookie/discovery/WAF helpers.
Result -> gateway JsonResponse -> `renderOSINT` -> DOM/currentOSINT.

### Exact output paths

Успіх зберігається тільки в currentOSINT/workspace state.
Engine events для OSINT не публікуються автоматично в Traffic.
Partial DNS/HTTP error живе в JSON `errors`, не в Traffic.
Browser timeout дає AbortError і не робить retry.
HTTP 400/502 проходить UI catch і показується у status.

## Трасування повного lifecycle

1. Input change або Clear abort-ить попередній `AbortController`, щоб
   повільний старий response не перезаписав нову ціль.
2. Run створює один bounded request із URL і `waf_check`; browser timeout
   30 s є окремим від engine/DNS timeouts.
3. Django перевіряє payload і передає його в Go. Engine спочатку готує host,
   DNS retries, потім HTTP redirect chain і тільки після цього похідні
   technology/security/discovery checks.
4. DNS failure не зупиняє весь result: `errors` і порожні DNS fields
   повертаються разом із доступним HTTP evidence. Верхня engine failure
   повертається як explicit 502.
5. Redirects зберігаються по hops, щоб оператор бачив не лише фінальний URL.
   WAF canary запускається тільки коли прапорець opt-in встановлений.
6. `renderOSINT` розкладає result по секціях і встановлює `currentOSINT`.
   Export і Send AI працюють із цим snapshot без повторного network call.
7. Clear відміняє запит, скидає DOM/current result і ставить empty state.
   Workspace autosave може відновити останню локальну форму, але engine не
   має server-side OSINT job для resume.

### Контрольні точки

`input abort → payload → Django validation → DNS → HTTP/redirects →
fingerprints/headers/cookies/discovery/WAF → render → export/AI/clear`.
Для повної діагностики зберігайте URL, timestamp, redirect_chain, DNS errors,
HTTP status і секції, які були свідомо пропущені через failure.
