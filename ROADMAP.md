# Roadmap RequestRider

## Статус roadmap

Станом на 2026-09-24 завершені пункти позначені `[x]`; після кожного пункту
виконувалися застосовні targeted/regression тести, а browser-facing зміни
перевірялися через живий браузер. Додатково узгоджено стратегічний backlog для
OSINT, Scanner, Project Hub, Target Knowledge Base, Automation, протоколів,
UI/UX та reporting. Пункти `[ ]` є backlog і не вважаються реалізованими до
повного проходження відповідних тестів і browser smoke-test.

Локалізаційний аудит Ukrainian/English завершено для статичних, динамічних,
збережених і відновлених станів основних вкладок. Останні виправлення
стосувалися Scanner та Comparer empty states після reload і зміни мови.

## Automation / Workflows

- [x] Додати окрему вкладку Automation з canvas, palette вузлів, connections,
  інспектором і журналом виконань.
- [x] Додати SQLite persistence для workflow graphs і project-scoped execution
  history.
- [x] Додати Manual, Schedule та Webhook triggers, Condition/Branch, Set,
  Template, Merge, Delay, Output та інструментальні вузли.
- [x] Додати process-local DAG runner, pause/resume/cancel, cron scheduler,
  webhook endpoint, live SSE stream і JSON/Markdown export.
- [x] Додати n8n-style graph normalization, scope validation для active tools
  та explicit confirmation для Intruder/browser actions.
- [x] Зафіксувати поточний UX/UI-варіант Automation: меню в одну стрічку,
  окрема іконка AI попереднього розміру та компактна palette без внутрішнього
  скролу на основному desktop viewport.
- [x] Додати передачу налаштованого workspace з інструментів в Automation,
  schema-driven inspector та round-trip `Open in tool` / `Use current workspace`.
- [x] Додати local-only Firefox E2E matrix для DAG, tools, evidence → AI →
  follow-up workflow, export/import, persistence та lifecycle controls.
- [x] Додати MVP Template Store: локальний API-каталог, категорії, preview,
  required variables, scope confirmation та імпорт у новий Automation canvas.
- [x] Розширити Template Store безпечними read-only playbooks для perimeter,
  API headers, schema endpoint discovery, asset inventory та advisory AI triage.

Поточний runtime є process-local і не є distributed queue; Redis/Celery,
multi-main HA, webhook signing та proxy-trigger можуть бути окремими майбутніми
ітераціями.

### Наступні ітерації

- [x] Додати self-hosted/local OAST Listener у дві фази: start/registration →
  payload URL, окремий collect/wait для bounded polling, cancellation та
  explicit evidence; перший fixture є local loopback.
- [ ] Додати сумісність із self-hosted Interactsh API та DNS/HTTPS/SMTP
  provider fixtures після локального HTTP contract.
- [x] Додати bounded `Repeater Burst` node з Go job lifecycle, exact Project
  scope, manual-only confirmation, cancellation, TLS verification,
  iteration/concurrency budget, response limits і History persistence; raw
  Last-Byte sync не вбудовувати в baseline Repeater.
- [x] Додати experimental raw Last-Byte TCP/TLS contract з TLS verification,
  окремим confirmation, bounded hold, cancellation, loopback-first policy та
  локальним raw fixture.
- [x] Додати manual-only high-risk canary templates для BOLA/IDOR differential,
  race timing, WAF rules, synthetic JWT claims, XXE → local OAST та read-only
  CI/CD exposure review; без реальних credentials та external execution.
- [ ] Додати server-backed `WorkflowTemplate` CRUD, community manifests,
  schema signing та import preview.
- [ ] Додати Nuclei/Postman converters лише після canonical graph validation.


- [x] Додати повний UI для збережених Traffic sessions:
  - list;
  - load;
  - rename;
  - delete;
  - restore конкретної Traffic session.

## Session/workspace

- [x] Додати Project-сутність і session metadata з
  `target`/`environment`/`route_profile`.
- [x] Додати nullable зв’язки Project із History, Traffic sessions, Intruder,
  Target, Findings і Workflows.
- [ ] Забезпечити наскрізну project-isolation для звичайних Repeater/Intruder,
  proxy snapshots, OSINT/Scanner, Traffic sessions, History filters і reports;
  не прив’язувати весь proxy traffic до одного глобального active Project.
- [x] Додати versioning і migration для session bundle schema.
- [x] Перенести великі workspace/session snapshots із `localStorage` до
  IndexedDB.
- [ ] Додати versioned browser `uiPreferences` із migration/validation для
  layout, split ratios, shortcut profile та per-workspace view modes.

## Engine gateway та error handling


- [x] Додати єдиний error mapping.
- [x] Додати стабільний `ENGINE_HTTP_ERROR`.
- [x] Додати загальну обробку malformed responses.
- [x] Створити єдиний Django `EngineClient`.

## Accessibility

- [x] Додати повну ARIA-модель вкладок із `role="tablist"`, `role="tab"` і
  `role="tabpanel"`.
- [x] Додати зв’язок tab/panel через `aria-controls` і `aria-labelledby`.
- [x] Замінити `window.prompt` на локальний accessible dialog.
- [x] Замінити `window.confirm` на локальний accessible dialog.
- [x] Додати keyboard-only smoke tests.
- [ ] Видалити повторно введений `window.prompt` у Request Inspector і
  відновити accessible dialog regression.

## Browser-driven Target

- [x] Додати явний form mode.
- [x] Додати локальні fixtures.
- [x] Додати окреме підтвердження state-changing actions.
- [x] Додати повні E2E lifecycle tests.

## Scanner та Findings

- [x] Додати selectable Scanner profiles `Generic Web`, `CMS`, `API`,
  `Security Headers`.
- [ ] Зробити profiles behaviorally different: окремі read-only checks,
  explicit per-profile budgets і targeted tests; зараз профіль лише
  metadata.
- [x] Додати `confidence` і `verification_status` до кожного finding.
- [x] Додати повторну перевірку finding із порівнянням evidence до/після.
- [x] Додати єдину Findings-модель.
- [x] Додати стани `New`, `Confirmed`, `False positive`, `Accepted risk`,
  `Fixed`.
- [x] Створити Findings Center.
- [x] Додати Markdown/HTML export.
- [ ] Додати server-side escaping HTML export і allow-list validation
  severity/status/confidence.
- [ ] Замінити truncating fingerprint на stable evidence-aware identity та
  idempotent upsert для повторного Save.

## Стратегічний backlog, узгоджений 2026-09-24

Цей backlog виникає з аудиту поточного коду, а не з припущень про наявність
функцій. Він виконується заЛЕжно від security/data foundation; один пункт за
раз проходить targeted tests, regression suite та live browser smoke-test.

### P0. Project Hub, scope і ізоляція даних

- [x] Додати `Project Scope Foundation`: структуровані `scope_in`/`scope_out`,
  exact host, wildcard domain, IP/CIDR та URL origin/path rules; out-of-scope
  має пріоритет, regex не підтримуються.
- [x] Додати server-side scope parser/validator із межами кількості rules,
  довжини та URL; active workflow calls fail-closed без Project, а
  `?project_id` не використовується як спосіб зміни контексту.
- [x] Зробити Project context явним browser action із CSRF/server validation;
  selector записує validated Django session, `?project_id` ігнорується, а
  browser-local draft/localStorage не вважаються authorization boundary.
- [x] Прив’язувати passive Traffic через явний proxy-session/capture context,
  а не через глобальний active Project; out-of-scope evidence за
  замовчуванням не видаляти, а класифікувати.
- [ ] Зробити Project scope обов’язковим для active workflow nodes; окремий
  unscoped local mode має бути явним і не мати schedule/webhook trigger.
- [x] Додати `ProjectContextBuilder` із bounded project-scoped aggregation:
  scope, tech, endpoints, findings, workflows, TargetJobs і secret references;
  raw bodies, cookies, Authorization, CSRF, URL query credentials та plaintext
  secrets не включаються.
- [x] Додати explicit one-shot AI opt-in для Project context; server бере
  validated active Project, redacted/compact context і provenance, а consent
  скидається після success/error.
- [ ] Додати Project dashboard із Overview/Scope, Assets, Endpoint map,
  Findings, Workflows та local Markdown notes; зберегти поточний Projects tab
  як основний entry point.

### P0. Secrets, evidence, reporting та AI boundary

- [ ] Додати `SecretRef`/local secret lifecycle замість `ProjectSecret.value`;
  не зберігати password/JWT/API key у SQLite, browser state, exports чи logs.
- [ ] Додати stable evidence references, redaction policy, retention metadata
  та evidence-aware Finding identity/upsert.
- [ ] Додати SARIF 2.1.0 і redacted HTML/Markdown report snapshots; raw
  evidence export повинен бути окремим підтверджуваним режимом.
- [ ] Посилити AI provider boundary: private-IP/redirect blocking, response
  cap, timeout/rate limits, remote-provider consent і workflow AI opt-in.
- [ ] До shared/external mode додати authentication, project membership,
  object-level authorization, audit events і CSRF/service-auth boundary.

### P1. OSINT Entity Graph та local transforms

- [x] Додати versioned `OsintGraph`, `OsintEntity`, `OsintRelation` із
  project-scoped identity, provenance, observed_at та idempotent upsert.
- [x] Додати read-only canvas на основі local native browser SVG renderer;
  не додавати React Flow/Tailwind або CDN-залежності паралельно з поточним
  single-template UI без окремого asset pipeline.
- [ ] Першими graph entities зробити Domain, Subdomain, IP, URL, Email,
  Username, ASN/CIDR, Certificate, Technology, Port та Cloud asset.
- [ ] Додати read-only transform registry з preview, progress, cancellation,
  provenance, redaction та local fixtures; transforms не виконують shell,
  arbitrary code або network actions поза явними bounds.
- [ ] Додати subdomain transform через crt.sh і bounded DNS brute force;
  `SecurityTrails`, `OTX`, `Shodan` і `Censys` додавати окремими adapters із
  environment-only credentials та provider-specific quotas.
- [ ] Додати DNS records A/AAAA/CNAME/MX/NS/TXT/SOA/CAA з explicit errors;
  wildcard DNS detection і cancellation мають бути обов’язковими.
- [ ] Додати локальні GeoLite2/ASN enrichment, WHOIS та passive archive
  adapters; MaxMind/інші DB не комітити, лише перевіряти signature/license.
- [ ] Додати email/username recon, paste/breach lookup, GHDB link generator
  та GitHub public metadata як окремі bounded transforms з redaction.
- [ ] Додати live activity/pagination/cache/provenance inspired by OSIRIS,
  але не переносити unrelated global feeds у поточний cyber-scope без
  окремого узгодження.
- [x] Додати Web-Maltego-style details drawer, context-menu transforms,
  auto-layout, filters і 500+ node performance budget.

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
- [ ] Додати approval-based candidate queue зі станами
  `discovered/pending_review/approved/queued/scanned/completed/rejected/expired`.
- [ ] Дозволити Scanner лише approved candidates; passive discovery не має
  автоматично запускати active checks.
- [ ] Додати real behavioral Scanner profiles, distinct budgets і evidence
  hashes; не називати profile selective, якщо checks не відрізняються.
- [ ] Додати data-only scanner template schema до YAML preview; code
  templates, executors, shell та arbitrary scripts не підтримувати.
- [ ] Додати context-aware mutations після baseline/response clustering;
  bounded OAST, adaptive 429/503 backoff і browser-rendered evidence.
- [ ] Додати optional authenticated Tor control circuit rotation з перевіркою
  exit IP; не називати SOCKS5 route switch circuit rotation.

### P1. Automation, SessionMacro та API security

- [ ] Додати versioned canonical workflow schema, server-side typed parameter
  validation, node evidence references та import preview.
- [ ] Додати local-only `SessionMacro` execution з Go-owned cookie jar,
  target-site CSRF extraction, origin pinning, TTL, redaction та fixture.
- [ ] Додати auto-reauth лише після SessionMacro: bounded manual predicate,
  safe-method retry за замовчуванням, no replay для ambiguous writes,
  lockout/403 stop; жодних credentials у workflow/browser state.
- [ ] Додати Nuclei/Postman preview-only import із safe subset, unsupported
  feature diagnostics і забороною execution scripts.
- [ ] Додати AttackChain/AttackStep/evidence provenance після stable IDs;
  не перевикористовувати execution DAG як semantic security graph.

### P1. Protocols, client-side та API security

- [ ] Додати protocol metadata і local H2 fixture/TLS tests до WebSocket,
  gRPC/Protobuf, H3/QUIC та frame-level features.
- [ ] Додати WebSocket capture/replay, gRPC `.proto`/`.desc` introspection і
  bounded binary mutations; raw bytes і metadata мають залишатися
  розрізнюваними.
- [ ] Додати JavaScript source-map/AST analysis, local taint evidence та
  browser WebSocket events; extracted secrets не потрапляють у persistence/AI.
- [ ] Додати OpenAPI/Postman import, GraphQL introspection/schema inspection,
  BOLA role matrix і JWT allowlist/signature verification fixtures.
- [ ] Додати TLS/H2/WAF differential evidence до окремого read-only mode;
  fingerprint spoofing і WAF bypass не входять у baseline execution.
- [ ] Додати H2 single-packet лише як manual-only best-effork experiment з
  low-level `x/net/http2.ClientConn`, blocking body gates та PING barrier;
  не гарантувати і не тестувати deterministic one-TCP-packet semantics.

### P1. UI/UX та interaction primitives

- [ ] Спершу додати semantic status/tag tokens, accessible progress,
  toast service та versioned `uiPreferences`; не вводити docking раніше.
- [ ] Додати shared action registry, right-click/keyboard context menu,
  conflict-free command palette і shortcut profiles.
- [ ] Додати resizable Repeater split, Pretty/Raw/Hex, escaped syntax/JWT
  rendering, persistent visual diff і safe allow-listed DSL search.
- [ ] Додати OSINT graph/Findings Kanban, live activity bar та localization
  усіх dynamic states без color-only meaning.
- [ ] Додати browser tests для layout persistence, keyboard operation,
  language switch, XSS/binary/malformed input, console та failed requests.

### P2. Collaboration, integrations та CLI/CI

- [ ] Додати shared Project workspaces/comments лише після auth, ACL, audit,
  optimistic locking і redaction foundation.
- [ ] Додати redacted notification outbox із HMAC, idempotency, bounded retry,
  dead-letter, rotation/revocation; external integrations не синхронні.
- [ ] Додати read-only CLI поверх versioned Django API: health, projects,
  findings, SARIF, workflow validate/dry-run; active commands require scope,
  service auth і explicit confirmation.
- [ ] Додати fixture-only CI для checks/tests/E2E/SARIF validation; CI не
  запускає зовнішні active targets без isolated explicit configuration.

### Технічні межі

- HTTP/2 `Write` не гарантує один TCP packet.
- Public OSINT endpoint не є анонімним і не повинен обіцяти zero-egress.
- Secrets не зберігаються plaintext і не передаються AI без explicit consent.
- Scope не використовує arbitrary regex; out-of-scope має precedence.
- Passive findings не запускають active Scanner автоматично.
- Shared Workspaces, remote webhooks та зовнішні integrations неможливі до
  authentication, authorization, audit і redaction foundation.
