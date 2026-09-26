# Roadmap RequestRider

## Статус roadmap

Цей файл містить лише невиконаний backlog (`[ ]`). Виконані пункти видалено
для читабельності; історія виконаних робіт зберігається в
`DEVELOPMENT_LOG.md`. Кожен пункт backlog вважається нереалізованим до повного
проходження targeted/regression тестів і browser smoke-test.

Під кожним пунктом курсивом додано коротке пояснення запланованої фічі.

## Automation / Workflows

Поточний runtime є process-local і не є distributed queue; Redis/Celery,
multi-main HA, webhook signing та proxy-trigger можуть бути окремими майбутніми
ітераціями.

### Наступні ітерації

- [ ] Додати сумісність із self-hosted Interactsh API та DNS/HTTPS/SMTP
  provider fixtures після локального HTTP contract.

  > Пояснення: планується підтримка зовнішнього OAST-провайдера типу Interactsh як альтернативи вбудованому loopback-лістенеру, з фістурами для кожного протоколу.

- [ ] Додати server-backed `WorkflowTemplate` CRUD, community manifests,
  schema signing та import preview.

  > Пояснення: планується серверне сховище шаблонів workflows з підписом схем і попереднім переглядом імпорту, замість лише локального каталогу.

- [ ] Додати Nuclei/Postman converters лише після canonical graph validation.

  > Пояснення: планується конвертація Nuclei/Postman у канонічний граф RequestRider, але тільки після готової серверної валідації графа.

## Session/workspace

- [ ] Забезпечити наскрізну project-isolation для звичайних Repeater/Intruder,
  proxy snapshots, OSINT/Scanner, Traffic sessions, History filters і reports;
  не прив’язувати весь proxy traffic до одного глобального active Project.

  > Пояснення: планується повна ізоляція даних між проєктами в усіх інструментах і звітах, без привʼязки всього proxy-трафіку до одного активного проєкту.

- [ ] Додати versioned browser `uiPreferences` із migration/validation для
  layout, split ratios, shortcut profile та per-workspace view modes.

  > Пояснення: планується версіоноване сховище UI-налаштувань у браузері з міграціями, щоб розкладка і шорткати не ламалися між версіями.

## Accessibility

- [ ] Видалити повторно введений `window.prompt` у Request Inspector і
  відновити accessible dialog regression.

  > Пояснення: планується прибрати блокуючий системний `prompt` і повернути власний доступний діалог з клавіатурною навігацією.

## Scanner та Findings

- [ ] Зробити profiles behaviorally different: окремі read-only checks,
  explicit per-profile budgets і targeted tests; зараз профіль лише
  metadata.

  > Пояснення: планується, щоб кожен профіль сканера реально виконував свій набір read-only перевірок з окремим бюджетом, а не був лише підписом.

- [ ] Додати server-side escaping HTML export і allow-list validation
  severity/status/confidence.

  > Пояснення: планується безпечний HTML-експорт findings з серверним екрануванням і перевіркою довідникових полів за allow-list.

- [ ] Замінити truncating fingerprint на stable evidence-aware identity та
  idempotent upsert для повторного Save.

  > Пояснення: планується стабільний ідентифікатор finding за evidence, щоб повторне збереження оновлювало запис, а не створювало дублікат.

## Стратегічний backlog, узгоджений 2026-09-24

Цей backlog виникає з аудиту поточного коду, а не з припущень про наявність
функцій. Він виконується залежно від security/data foundation; один пункт за
раз проходить targeted tests, regression suite та live browser smoke-test.

### P0. Project Hub, scope і ізоляція даних

- [ ] Додати Project dashboard із Overview, Assets, Endpoint map,
  Findings, Workflows та local Markdown notes; зберегти поточний Projects tab
  як основний entry point.

  > Пояснення: планується зведений дашборд проєкту з активами, ендпоінтами, findings і нотатками, а вкладка Projects лишиться точкою входу.

### P1. OSINT Entity Graph та local transforms

- [ ] Першими graph entities зробити Domain, Subdomain, IP, URL, Email,
  Username, ASN/CIDR, Certificate, Technology, Port та Cloud asset.

  > Пояснення: планується базовий набір типів сутностей графа для покриття доменів, адрес, сертифікатів і хмарних активів.

- [ ] Додати subdomain transform через crt.sh і bounded DNS brute force;
  `SecurityTrails`, `OTX`, `Shodan` і `Censys` додавати окремими adapters із
  environment-only credentials та provider-specific quotas.

  > Пояснення: планується пошук піддоменів через crt.sh і обмежений DNS-брут, а комерційні джерела — окремими адаптерами з ключами лише з ENV.

- [ ] Додати DNS records A/AAAA/CNAME/MX/NS/TXT/SOA/CAA з explicit errors;
  wildcard DNS detection і cancellation мають бути обов’язковими.

  > Пояснення: планується повний збір DNS-записів з явними помилками, детектом wildcard і обовʼязковим скасуванням довгих задач.


- [ ] Додати email/username recon, paste/breach lookup, GHDB link generator
  та GitHub public metadata як окремі bounded transforms з redaction.

  > Пояснення: планується розвідка за email/username, перевірка витоків і GitHub-метадані окремими обмеженими трансформами з маскуванням.


**Референси архітектури:** [Argus](https://github.com/cotcollective/argus) (MIT,
local-first modules), [Flowsint](https://github.com/reconurge/flowsint)
(Apache-2.0, graph/enricher ideas), [Osiris](https://github.com/simplifaisoul/osiris)
(MIT, live activity/UI ideas). Argus не робить запити приватними: локальним є
виконання, але public endpoints/websites всё одно бачать запит. Код сторонніх
проєктів не копіювати без окремого license/NOTICE audit.

Canvas реалізовано без стороннього bundle: native browser SVG дає
local-first rendering, keyboard-accessible DOM nodes, deterministic layout і
bounded 1000-node budget. Drag/zoom, force-directed layout та live ingestion
залишаються окремими backlog пунктами.

### P1. OSINT → Scanner pipeline

- [ ] Додати durable OSINT/Scanner runs, evidence envelope, cancellation,
  progress і retention; замінити синхронні calls лише після persistence.

  > Пояснення: планується персистентний життєвий цикл запусків OSINT/Scanner з конвертом evidence, прогресом і скасуванням.

-
-
- [ ] Додати data-only scanner template schema до YAML preview. Виняток
  sanctioned 2026-09-25 власником: дозволено bounded HTTP-only виконання
  Nuclei-подібних шаблонів (request + matchers status/words/regex, без коду і
  shell) з; див. `engine/pkg/scanner`,


  `DEVELOPMENT_LOG.md`.

  > Пояснення: планується data-only схема шаблонів сканера без коду і shell; виняток — обмежене HTTP-виконання Nuclei-подібних matchers за ENV-бюджетами.

- [ ] Додати context-aware mutations після baseline/response clustering;
  bounded OAST, adaptive 429/503 backoff і browser-rendered evidence.

  > Пояснення: планується мутаційне сканування після кластеризації базових відповідей, з адаптивними паузами і браузерними доказами.


### P1. Automation, SessionMacro та API security

- [ ] Додати AttackChain/AttackStep/evidence provenance після stable IDs;
  не перевикористовувати execution DAG як semantic security graph.

  > Пояснення: планується семантичний граф ланцюжка атаки з provenance evidence, окремо від технічного DAG виконання.

### P1. Protocols, client-side та API security

- [ ] Додати protocol metadata і local H2 fixture/TLS tests до WebSocket,
  gRPC/Protobuf, H3/QUIC та frame-level features.

  > Пояснення: планується метадані протоколів і локальні фікстури для WebSocket, gRPC, H3/QUIC з тестами TLS.

- [ ] Додати WebSocket capture/replay, gRPC `.proto`/`.desc` introspection і
  bounded binary mutations; raw bytes і metadata мають залишатися
  розрізнюваними.

  > Пояснення: планується захоплення і повтор WebSocket, інтроспекція gRPC-схем і обмежені бінарні мутації без змішування байтів і метаданих.

- [ ] Додати JavaScript source-map/AST analysis, local taint evidence та
  browser WebSocket events; extracted secrets 

  > Пояснення: планується аналіз JS source-map/AST з локальними taint-доказами
  
- [ ] Додати OpenAPI/Postman import, GraphQL introspection/schema inspection,
  BOLA role matrix і JWT allowlist/signature verification fixtures.

  > Пояснення: планується імпорт API-специфікацій, інтроспекція GraphQL, матриця BOLA-ролей і фікстури перевірки JWT.

- [ ] Додати TLS/H2/WAF differential evidence 

- [ ] Додати H2 single-packet лише як manual-only best-efffork experiment з
  low-level `x/net/http2.ClientConn`, blocking body gates та PING barrier;
  не гарантувати і не тестувати deterministic one-TCP-packet semantics.

  > Пояснення: планується ручний експеримент відправки H2 одним пакетом без гарантії детермінованої TCP-семантики.

### P1. UI/UX та interaction primitives

- [ ] Спершу додати semantic status/tag tokens, accessible progress,
  toast service та versioned `uiPreferences`; не вводити docking раніше.

  > Пояснення: планується базова дизайн-система статусів, доступних прогресів і тостів перед будь-яким докуванням панелей.

- [ ] Додати shared action registry, right-click/keyboard context menu,
  conflict-free command palette і shortcut profiles.

  > Пояснення: планується єдиний реєстр дій з контекстним меню, палітрою команд і профілями шорткатів.

- [ ] Додати resizable Repeater split, Pretty/Raw/Hex, escaped syntax/JWT
  rendering, persistent visual diff і safe allow-listed DSL search.

  > Пояснення: планується регульований спліт Repeater, режими перегляду, підсвітка JWT і безпечний пошук за DSL.

- [ ] Додати OSINT graph/Findings Kanban, live activity bar та localization
  усіх dynamic states без color-only meaning.

  > Пояснення: планується Kanban для графа і findings зі стрічкою активності і повною локалізацією динамічних станів.

- [ ] Додати browser tests для layout persistence, keyboard operation,
  language switch, XSS/binary/malformed input, console та failed requests.

  > Пояснення: планується набір браузерних тестів на розкладку, клавіатуру, мови, биті входи і помилки запитів.

### P2. Collaboration, integrations та CLI/CI


- [ ] Додати fixture-only CI для checks/tests/E2E/SARIF validation; CI не
  запускає зовнішні active targets без isolated explicit configuration.

  > Пояснення: планується CI лише на фістурах без звернень до зовнішніх цілей, окрім явно ізольованої конфігурації.

