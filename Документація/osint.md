# OSINT

> Актуально на 2026-09-25. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).
> Детальний перелік зняття application-level обмежень — у
> [звіті про видалені обмеження](видалені-обмеження.md).

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
Technology, Port, Cloud asset. Relations мають фіксований schema allow-list
типів; це валідація типу, а не обмеження кількості.

API:

```text
GET/POST /api/osint/graphs
GET      /api/osint/graphs/<id>
POST     /api/osint/graphs/<id>/upsert
```

`POST /api/osint/graphs` вимагає explicit `project_id`; `?project_id` лише
фільтрує list і не змінює active Project session. Upsert приймає повний
graph payload, canonicalizes URL без query credentials, redacts common
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
   додає custom entity через idempotent upsert.
3. `#osint-graph-canvas` показує entity nodes, relations, type colors і risk
   score. `Auto-layout` перемикає deterministic grid/radial, force-directed,
   concentric і circle розкладки.
4. `#osint-graph-filter` фільтрує type, identity, risk і properties;
   relations показуються лише коли обидва endpoints видимі.
5. Click або keyboard Enter відкриває details drawer з identity, type, risk,
   `observed_at`, properties і redacted provenance.
6. Context menu right-click показує лише transforms, сумісні з entity type.
   Local transforms виконуються одразу; `subdomains` і `github_recon` вимагають
   окремого confirmation dialog. Жоден transform не запускається з пасивного
   OSINT result автоматично.

Canvas не застосовує application count/render budget: graph відображається
повністю у native SVG; viewBox `1000×520` є лише координатною системою, а не
cap на кількість entities. 500+ node сценарій перевірено Firefox E2E. Graph
selection, filter, layout і selected entity зберігаються в OSINT workspace
state та відновлюються після reload; серверний graph лишається project-scoped
source of truth. Усі user-controlled labels виводяться через DOM
`textContent`/escaped markup, а POST UI додає CSRF token.

Native SVG canvas не є повноцінним physics engine: positions детерміновані,
drag/zoom та live passive-to-graph ingestion залишаються окремими наступними
ітераціями. Cytoscape.js, Monaco, Alpine.js і Tailwind CDN свідомо не
додаються: canvas лишається залежністю-free за поточним asset pipeline.

## Local transform registry

Graph API exposes a transform catalog at `GET /api/osint/transforms` and
runs one explicitly selected transform at
`POST /api/osint/graphs/<id>/transform`.

Available transforms (`engine/osint_transforms.go`, registry 13 items):

- `email_recon` — local normalization plus social-profile HTTP
  probes, only with `confirm_network=true`;
- `username_enum` — local username canonicalization; external platform mass
  enumeration is disabled;
- `ip_geo` — local IP normalization with optional environment-only
  `OSINT_GEOIP_JSON` lookup; no database download;
- `email_domain` — normalized domain extraction from a plain address;
- `username_normalize` — username normalization for graph correlation;
- `domain_normalize` — domain identity normalization without network;
- `url_host` — host entity extraction from an absolute HTTP(S) URL;
- `reverse_dns` — PTR lookup, only with `confirm_network=true`;
- `dns_records` — A/AAAA lookup, only with `confirm_network=true`;
- `subdomains` — п'ять паралельних індексів Certificate Transparency плюс
  sublist3r-style DNS brute force (embedded default wordlist, коли caller не
  передає `words`; обов'язкове виявлення wildcard DNS, що пропускає
  brute-force імена як ненадійні), лише з `confirm_network=true`;
- `github_recon` — public GitHub profile lookup plus public commit
  email extraction, only with `confirm_network=true`;
- `wayback_urls` — public archive index lookup, only with
  `confirm_network=true`;
- `s3_buckets` — AWS S3 / GCP / Azure Blob checks over an explicit
  user-supplied candidate list, only with `confirm_network=true`.

Every transform uses the Go engine, returns explicit warnings, and persists
its entities/relations through the same idempotent graph upsert. Network
transforms require a separate confirmation and never run implicitly as part
of passive discovery; application count/body ceilings are not applied.

## Transform як background-job: Pause / Continue / Cancel

Розвідка по великій зоні триває хвилинами, тому transform — це **background-job**,
а не один блокуючий запит. API повторює патерн nuclei jobs:

```text
POST /api/osint/graphs/<id>/transform/jobs            → job_id
GET  /api/osint/graphs/<id>/transform/jobs/<job_id>   → state + progress + result
POST /api/osint/graphs/<id>/transform/jobs/<job_id>/pause|resume|cancel
```

`POST /api/osint/graphs/<id>/transform` лишається доступним для сумісності.

`state`: `queued` / `running` / `paused` / `completed` / `failed` / `cancelled`.
`progress`: реальні лічильники — `names`, `relations`, `indexes`,
`indexes_total`, `current_index`, `elapsed_ms`. Жодного відсотка, який ніхто не
вміє обчислити: `partial_percent` дорівнює `-1`, бо сертифікатні індекси не
публікують totals.

Job прив'язаний до **generation** route, а не до контексту HTTP-запиту, тому
переживає запит, але скасовується `Apply route`.

### Пауза тут кооперативна, а не SIGSTOP

Nuclei паузиться через `SIGSTOP` на дочірньому процесі. Transform не має
процесу — це HTTP-стрім, тому пауза призупиняє **збиральник між іменами**:
вже зібрані імена лишаються, відкриті з'єднання добудовуються. `pauseGate`
зроблений на каналі, а не на `sync.Cond`, бо паузований transform має
закінчуватися при скасуванні: cond var прокидається тільки на broadcast, і
transform, зупинений зміною route, чекав би на resume, якого не буде.

- `pause` наступного checkpoint-у зупиняє збір; `resume` знімає.
- `cancel` спершу **`resume()`**, інакше зупинений збирач ніколи не побачив би
  скасування.
- Скасований transform повертає `cancelled` **і не віддає частковий результат**:
  це заборонений success-shaped fallback.
- **DNS-фаза — теж pause point.** Після індексів `subdomains` перевіряє
  wildcard DNS і резолвить словник. Кожен кандидат проходить `checkpoint`, а
  фаза працює через обмежений пул `bruteForceWorkerCount = 8` робітників. Без
  пулу один goroutine на кандидат запускав би весь словник до того, як пауза
  встигла б побачитися, тобто `Pause` був би недійсним на половині transform-у.
  Обмеження — це конкурентність, а не cap: повний словник однаково резолвиться,
  а `resume` продовжує його з того ж місця.

`indexes_total` — це реальна кількість запитів до сертифікатних індексів, яку
зробить цей запуск: індекси × довжина ланцюга зон. Для transform, який індекси
не читає (`wayback_urls`, локальні transform-и), він дорівнює `0`, і UI не
показує лічильник індексів узагалі.

### Локальний таймер не переписує стан job-а

Панель статусу малюють двоє: poll job-а (раз на 700 ms, авторитетний стан від
engine) і локальний таймер-elapsed (10 разів на секунду, щоб лічильник не
стрибав). Локальний таймер **не має права вигадувати стан**: він перемальовує
панель лише з тим станом, який останнім віддала poll-а. Без цієї умови пауза
виглядала б як `running`, бо таймер перезаписував би `paused` десять разів на
секунду.

Тривалість показується в реальних одиницях (`3.6 s`, `1 min 14 s`), а не в
мілісекундах: `transform_result.duration_ms` для background-job береться з
`progress.elapsed_ms` engine-а, а не з нульового заглушкового значення.

### Великий результат — файл, а не 176 936 вузлів

Велика зона — це нормальні докази, а не помилка. Результат понад
`FILE_ENTITY_ROWS = 2000` рядків **повністю** записується у файл, а граф
зберігає одну entity, що вказує на нього.

- `data/osint-exports/graph-<id>/<transform>-<value>.csv` і `.jsonl` — **усі**
  рядки, без обрізання.
- `GET /api/osint/graphs/<id>/files/<name>` — відкрити в новій вкладці;
  `?download=1` — завантажити як вкладення.
- Ім'я файлу генерується сервером; при читанні перевіряється суворим
  regex-ом і `resolve()`-ом, що resolved-path лежить у каталозі графа, тому
  traversal неможливий.
- Перемикання **явно показане** у `transform_result.delivered_as_file`,
  `metadata.result_file` і warning-і — файл не читається як «скорочена
  відповідь».

Це спосіб доставки, а не ліміт: зрізаних даних немає, повний список
відкривається і завантажується.

## Стійкість зовнішніх джерел

Публічні джерела OSINT (crt.sh, Internet Archive) повертають помилки й
обривають відповідь, тому adapters не падають на першій невдачі.

### Certificate Transparency

`certificateTransparencyNames` опитує **п'ять незалежних індексів
Certificate Transparency паралельно** і зливає їхні відповіді в одну множину
імен. Це не п'ять постачальників даних: усі читають ті самі публічні CT-логи,
і кожен має власний формат відповіді та власні збої.

| Індекс | Формат відповіді | Ключ |
|---|---|---|
| `crt.sh` | JSON масив `name_value` | — |
| `crt.name` | один hostname на рядок | — |
| `certspotter` (SSLMate) | сторінки `issuances` з `dns_names` | `CERTSPOTTER_API_TOKEN` |
| `shodan-ctl` | JSON масив hostname | — |
| `ctlogs.dev` | конверт `hosts[]` | `CTLOGS_API_KEY` |

Чому саме так:

- **crt.sh** — публічний фронтенд на спільному PostgreSQL-кластері. За
  вимірами ctlogs.dev його 30-денний uptime — **38.68%**, а на один великий
  запит зони він відповідає 502. Одного індексу недостатньо.
- **crt.name** — незалежний індекс, читає Argon / Sectigo / Cloudflare CT.
  Найбільший практичний внесок: 176 936 імен для `yandex.ru` за 8.4 s.
- **certspotter** — пагінований індекс SSLMate.
- **shodan-ctl** — індекс CT Shodan, відповідає масивом hostname.
- **ctlogs.dev** — незалежний пошуковик CT; його `/v1/hosts` не потребує
  wildcard-синтаксису, тому відповідає й на субдомен, який apex-only індекси
  відкидають.

Правила, які код дотримується:

- **Паралельно, а не послідовно.** Вартість transform дорівнює найповільнішому
  індексу, а не сумі. Мертвий індекс не затримує решту.
- **Злиття, а не ланцюг «перший відповів».** Об'єднання і є доказом: індекс,
  який відповів, не витрачає metered-бюджет інших.
- **Запит іде до зони, а не до голого хоста.** CT-індекси індексовані за
  зоною, а не за хостом: `crt.name` відкидає хост, який не є apex
  (`400 invalid apex: not an apex (eTLD+1 is lafann.ru)`), а індекси, які такий
  запит приймають, відповідають самим хостом — тобто нулем subdomain'ів.
  Тому `certificateQueryZones` будує ланцюг зон від найближчої до найвіддаленішої
  (`www.lafann.ru` → `lafann.ru`), і обхід зупиняється на першій зоні, що дала
  ім'я, якого transform ще не знав. Ланцюг ніколи не доходить до однолітерного
  публічного суфікса, а кожна зона запитується власним запитом індексу.
- **Підміна зони проголошується.** Якщо запит пішов до батьківської зони, у
  `warnings` і в `metadata.cert_zone` / `cert_input` / `cert_zones_queried`
  видно, що саме запитано. Імена стають `subdomain` саме цієї зони, а сам
  запитаний хост лишається окремою `domain`-сутністю, тож напрям зв'язку
  `subdomain_of` ніколи не стає зворотним.
- **Відмова індексу не повторюється.** `certificateStatusError` розрізняє
  тимчасовий збій (`408`, `425`, `429`, `5xx` — повторюється до
  `crtLookupAttempts`) і відмову самої відповіді (`4xx` крім `429`, зокрема
  `crt.name` на не-apex — повторюється один раз і більше не витрачає часу).
  Індекс, який повідомив `X-RateLimit-Remaining: 0`, до наступної зони більше
  не запитується.
- **Пагінація йде за курсором індексу і його власним бюджетом.**
  `certspotter` анонімно віддає `x-ratelimit-limit: 10`; обхід іде, поки сам
  індекс не повідомляє `X-RateLimit-Remaining: 0`, і зупинка чесно
  показується: `was read for 7 page(s); stopped where the index reported 0 of
  10 requests left`. Жодного ліміту сторінок не вигадано.
- **Ключі лише з оточення.** `CERTSPOTTER_API_TOKEN` і `CTLOGS_API_KEY`
  читаються з env; у коді немає жодного credential, а індекс без ключа
  працює анонімно. Ключ не надсилається туди, де його не існує.
- **Відповідь індексу — це attacker-controllable input.** `addCertificateName`
  + `storableHostname` відкидають порожні лейбли (`..example.test`), роздільники,
  пробіли та name з `@`; apex не дублюється. Кожен лейбл перевіряється за тими
  самими правилами, що й gateway identity validation.
- **Metadata:** `cert_indexes` (скільки імен дав кожен індекс) і
  `cert_names` (разом). Покриття видно без повторного запиту.
- **Provenance** розділяє доказ: `certificate_transparency` для імені з індексу
  та `dns_guess` для імені, знайденої brute-force резолвом.

Перевірено на живому `yandex.ru`: 5 індексів, 43.7 s, **176 937 subdomain**,
`cert_indexes = {crt.sh: 1300, crt.name: 176936, certspotter: 843,
shodan-ctl: 781, ctlogs.dev: 92}`, 0 імен відхилено правилами gateway.

Перевірено на живому `www.lafann.ru` ( subdomain-вхід): `indexes_total: 10`
(5 індексів × 2 зони), `crt.name` відмовив першій зоні, решта відповіли на
`lafann.ru` — **9 імен з індексів + 1 з DNS** (`ftp.lafann.ru`), 13 сутностей і
11 зв'язків у графі, `cert_zone: lafann.ru`, і видиме попередження про підміну
зони. До цієї зміни той самий запит давав 0 імен.

### Internet Archive

`wayback_urls` читає два індекси в ланцюжку: `cdx`
(`/cdx/search/cdx`, `collapse=urlkey`, один рядок на URL) і `timemap`
(`/web/timemap/json`, один рядок на capture). Індекси живуть на різних
backend-ах архіву: CDX indexer rate limit-ить і йде offline незалежно від
timemap, тому відповідь CDX не визначає доступність timemap.

- Третій endpoint не додається: наявні два — це два різні backend-и одного
  публічного архіву, а не додатковий постачальник даних.
- Archive відхиляє default HTTP-клієнтів: за вимогами
  [archive.org/developers/bots.html](https://archive.org/developers/bots.html)
  **кожен** автоматизований запит має містити описувальний `User-Agent` з
  назвою інструмента та версією. Тому `User-Agent:
  RequestRider-OSINT-Transform/1.0` і `Accept: application/json` — частина
  контракту adapter-а, а не деталь. Анонімний клієнт отримує rate-limit
  статус замість відповіді.
- Той самий документ вимагає шанувати `429` і заголовок `Retry-After`.
  `retryAfterNote` додає його до тексту помилки (`HTTP 429 (retry after 37s)`),
  щоб обмеження пояснювало себе, а не виглядало як твердий збій.
- Індекс великого хоста — довгий потік, який архів regularly обриває посеред
  масиву. `streamArchiveIndex` споживає його через `streamJSONArray` рядок за
  рядком і не буферизує тіло. Обриваний хвіст не викидає вже прочитані
  рядки: результат лишається корисним, а `the <index> archive index stream
  ended early after N rows; the collected URLs are a partial view` явно
  повідомляє, що view частковий.
- Повний індекс і справді порожній (`[]`) — не помилка: перший індекс, який
  відповів, завершує ланцюг, а порожня відповідь дає warning `holds no
  captures for <domain>`. Fallback запускається лише коли індекс узагалі не
  відповів, тому answered-but-empty не витрачає другий запит.
- Коли жоден індекс не відповів, помилка `WAYBACK_LOOKUP_FAILED` перелічує
  кожну спробу (`cdx index: archive returned HTTP 429; timemap index: ...`),
  замість одного незрозумілого коду.

Metadata результату: `archive_index`, `archive_rows`, `archive_urls`,
`archive_stream_complete`. Це робить частковий архівний view видимим у
graph metadata.

### Канонізація архівних URL

Архів — це attacker-controllable input: він зберігає перехоплені URL з
credentials (`https://user@yandex.ru/`) і fragment-only варіанти.
`archiveURLTarget`:

- приймає лише абсолютні `http`/`https`;
- відкидає `userinfo`, query і fragment, щоб жоден захоплений секрет не став
  identity;
- знімає default port (`:80` для http, `:443` для https), щоб один ресурс не
  роздвоювався на дві identity;
- нормалізує host до ASCII через `idna.Lookup` і перевіряє кожен label за тими
  самими правилами, що й `normalize_entity_identity` у gateway — тобто кожен
  URL, який engine прийняв, gateway гарантовано збереже;
- відкидає шлях із `.`/`..` сегментами (traversal у чужому dataset) і
  некоректний порт;
- береться з escapeden path, тому non-ASCII шлях не втрачається.

Один отруєний рядок не провалює весь transform — він просто не стає entity.
Дублікати capture того самого URL зводяться до однієї identity через `seen`,
тому timemap-індекс не роздуває граф.

Перевірено на реальному `yandex.ru`: 1 660 046 рядків → 124 152 унікальні
URL, 33 135 рядків із credentials відкинуто канонізацією, 0 entity
відхилено правилами gateway, 0 traversal identities.

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
Для browser request створюється `AbortController`; автоматичний UI deadline не
застосовується. При зміні URL поточний controller abort-иться і старий результат скидається.

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
downloads не запускаються автоматично; network adapters мають explicit
confirmation boundary.
Canvas не виконує passive-to-graph
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
2. Run створює один request із URL і `waf_check`; browser abort/timeout
   залишається явним UI-flow, а engine/DNS timeouts не мають прихованого
   application ceiling.
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
