# Журнал розробки RequestRider

Цей файл містить детальний хронологічний опис змін, виправлень, перевірок і
операцій запуску, виконаних у репозиторії. Git залишається джерелом точного
diff і авторства змін, а цей журнал пояснює мету, контекст і результат кожної
операції.

## Правила ведення журналу

- Додавати новий запис після кожної завершеної зміни або окремої діагностичної
  операції, що вплинула на стан проєкту.
- Для кожного запису вказувати дату, область, причину, змінені файли, результат
  перевірки та важливі обмеження.
- Не записувати секрети, токени, cookies, приватний ключ CA, повні тіла
  запитів або інші чутливі дані.
- Не замінювати цим журналом Git: коміти, diff і статус робочого дерева
  залишаються технічним джерелом істини.
- Нові записи додавати зверху, одразу після цього розділу.

## 2026-09-24 — Стабілізовано відновлення графа та великі layout-и

Відновлення OSINT graph більше не довіряє застарілому `graphId` із локального
workspace: ID спочатку звіряється зі списком графів активного проєкту, а при
видаленні або race під час оновлення вибирається доступний граф без помилки
`Project load error: OSINT graph not found`. Стан вибраного графа оновлюється
після fallback.

Force-directed layout тепер використовує bounded локальну симуляцію відштовхування
та притягання за relations, а для графів без зв'язків застосовує рознесені кільця
з достатньою мінімальною відстанню. Concentric layout також розкладає вузли по
великих кільцях, зберігає позиції перетягнутих вузлів і правильно масштабує
viewport за фактичними межами графа.

Перевірки: `node --check`, Django tests (60 тестів), `python manage.py check`,
`makemigrations --check --dry-run`; у браузері перевірено 106-node граф у режимах
Force-directed і Concentric, відсутність помилки завантаження та статус `Saved
locally`.

## 2026-09-24 — Автономний інтерактивний HTML-експорт OSINT graph

Попередній HTML-експорт переносив SVG без стилів і без runtime-обробників
основного UI, через що у збереженій сторінці з'являлися чорні квадрати та не
працювали переміщення, zoom і перегляд entity. Експорт тепер містить власні
стилі SVG, панель деталей entity, drag вузлів, pan полотна, wheel zoom, Fit,
перемикач підписів, фільтрацію, таблицю та JSON download. Сторінка повністю
автономна й не потребує RequestRider, Django або зовнішніх бібліотек.

Перевірки: новий HTML відкрито через локальний HTTP fixture server; перевірено
106 SVG-вузлів, відкриття деталей entity після click і зміну viewport transform
після wheel zoom.

## 2026-09-24 — HTML-експорт OSINT graph та повторне enrichment

OSINT graph отримав автономний HTML-експорт у стилі Target map: сторінка
містить вбудований SVG-граф, пошук і фільтрацію entities, таблицю сутностей,
перемикач підписів, zoom, Fit/JSON download і повний raw graph snapshot.
Експорт не залежить від RequestRider або CDN і може відкриватися локально.

У Project Hub додано перелік project-scoped OSINT graphs із кількістю entities
та relations і кнопкою `Open in OSINT`, яка повертає користувача до потрібного
графа. У drawer entity додано `Run transform on this value`, `Copy value` та
`Use in OSINT checks`. Діалог дозволяє змінити значення URL, domain, IP,
email або username перед повторним запуском transform; контекстне меню
показує локальні нормалізатори й network enrichment окремо.

Перевірки: inline `node --check`, Django graph/project tests (60 тестів),
Django check і migrations check — passed; у браузері перевірено Project Hub,
106-node graph, HTML payload (108 KB, controls + embedded graph) і dialog
повторної трансформації.

## 2026-09-24 — Покращено навігацію та читабельність OSINT graph

Native SVG canvas OSINT-графа перероблено для практичної роботи з великими
наборами вузлів: додано масштабування колесом і кнопками, панорамування фону,
перетягування окремих вузлів, `Fit` і `Reset`. Вузли тепер мають кольорові
типи, підписи в окремих контрастних картках і видимі підписи зв’язків.

Layout-режими отримали зрозумілі назви та різну геометрію: рівномірна сітка,
force-directed-подібне радіальне розкладання, концентричні кільця та
breadth-first рівні за типом сутності. Додано легенду, коротку підказку
керування та автоматичне припасування графа після завантаження.

Перевірки: inline `node --check`, OSINT graph API tests (10 тестів) і жива
перевірка DOM canvas з 106 вузлами та робочим zoom viewport — passed.

## 2026-09-24 — Інтерактивний OSINT graph і локальні transforms

Розширено native SVG Entity Graph без підключення CDN або стороннього runtime:
правий клік по вузлу показує доступні transforms для його типу, результати
зберігаються через наявний graph upsert API, а панель деталей показує
властивості та provenance. Додано layout-перемикачі Grid, Force-directed,
Concentric і Breadthfirst.

Go engine тепер публікує 13 transform entries: локальні нормалізатори email,
username, domain і URL, локальний GeoIP, а також explicit-confirm network
трансформи DNS records, reverse DNS, subdomains, GitHub profile, Wayback URLs
і S3 candidate checks. Network transforms не запускаються пасивно та
повертають явну помилку без confirmation; результати залишаються project-scoped
через наявний graph endpoint. Бюджети відповідей і кількість результатів
читаються з `RR_OSINT_*` environment variables.

Project AI context доповнено bounded adjacency list і DOT-представленням
поточного OSINT graph. У graph context не додаються raw headers, bodies,
credentials або secret values.

Перевірки: `go test ./... -count=1`, Django tests, OSINT graph tests, Django
check, migrations check і inline `node --check` — passed.

## 2026-09-24 — Наскрізний active Project для інструментів і ручне прикріплення Findings

Intruder-запуски тепер зберігають зв’язок із Project через
`IntruderAttack.engine_attack_id`, тому пізній polling не втрачає Project і не
прив’язує результати до випадково вибраного пізніше workspace. Нові збережені
Intruder-конфігурації також отримують active Project.

Workflow, створений без явного `project_id`, успадковує server-side active
Project. Ручний запуск незв’язаного workflow записує Project у `WorkflowRun`,
а вузли Repeater, Repeater Burst, Last-Byte Sync, Target, Intruder, OSINT і
Scanner використовують цей самий run context для збереження результатів.

Додано `POST /api/findings/<id>/attach`: кнопка `Add to active Project` у
Findings Center прикріплює вже знайдену, але ще не пов’язану Finding до
активного Project без довіри до довільного ID з браузера.

Перевірки: regression tests для active Project, Intruder mapping, Workflow
inheritance і manual Finding attach, Django check, migrations check та inline
JavaScript syntax — passed.

## 2026-09-24 — Project Knowledge Hub та безпечний ingestion

Додано `ProjectEndpoint` для накопичення методів, шляхів, параметрів і статусів
спостережуваних HTTP-обмінів. Signal для нових `TrafficRecord` автоматично
реєструє endpoint, технологічні заголовки та metadata-посилання на JWT,
Bearer/API-key і cookie спостереження. Plaintext значення секретів не
зберігаються; `ProjectSecret` залишається reference-only.

Додано `GET /api/projects/<id>/hub` і багатопанельний Project Hub у наявній
SPA-вкладці Projects: Overview, Asset map, Secret references, Findings,
Workflows та AI snapshot. Scope-поля не використовуються для виконання або
блокування запитів.

Перевірки: `python manage.py check`, `makemigrations --check --dry-run`,
Project Hub regression test, `lab.tests` та inline `node --check` — passed.

## 2026-09-24 — Desktop Project Hub UI та fixture-перевірка

Project Hub перероблено з горизонтального технічного блоку на desktop-first
workspace: окремий header активного проєкту, вертикальна навігація панелей,
метричні картки, списки evidence і адаптивне звуження лише для малих екранів.
Створено локальний `Project Hub Demo` з fixture traffic, endpoint metadata,
технологіями, findings, OSINT entities, workflow і reference-only secret
observations для повторюваного browser smoke-test.

Перевірено в живому Chromium viewport: вибір demo Project, 4 traffic records,
4 endpoints, 2 findings, 1 open port, technology summary, secret references,
workflow list і AI snapshot. Усі п’ять Hub-панелей перемикаються та показують
відповідний DOM-контент.

## 2026-09-24 — Автоматичне наповнення активного Project інструментами

Target, OSINT і Scanner тепер використовують перевірений server-side
`request.active_project`, якщо користувач вибрав Project у header. Завершений
Target map індексує сторінки як endpoint metadata та URL entities в OSINT graph.
OSINT зберігає domain/IP/technology observations, а Scanner автоматично
зберігає findings і technology metadata; окрема кнопка `Save findings` більше
не є необхідною для збереження результату.

UI автоматично підставляє Project target у поля Target/OSINT/Scanner, показує
статус `Saved to active Project` та оновлює Hub після завершення інструмента.
При відкритті Hub завершені Target jobs також повторно індексуються, тому
результати, створені до цього виправлення, можуть відновити endpoint metadata.

Перевірки: 98 Django tests, 17 targeted Project/ingestion tests, Django check,
migrations check і inline JavaScript syntax — passed.

## 2026-09-24 — Видалення дубльованих Traffic sessions і стабілізація Automation

Видалено окремий функціонал збережених Traffic sessions: кнопки `Save session`
і `Sessions`, браузерну панель Load/Restore/Rename/Delete, Django endpoint,
`TrafficSession` model та пов’язані тести. Traffic залишається доступним у live
таблиці, а повний набір даних експортується наявною функцією `Export all`.
Додано міграцію `0034_remove_trafficsession`, яка видаляє застарілу таблицю.

В Automation вибір workflow тепер повторно завантажує вибраний запис через
`GET /api/workflows/<id>` і оновлює локальний каталог перед відображенням.
Це запобігає зникненню workflow через застарілий або неповний browser snapshot.

Перевірки: `python manage.py check`, `makemigrations --check --dry-run`,
targeted Django tests (**67 passed**), inline `node --check` — passed.
Browser smoke-test підтвердив відсутність Traffic session controls і збереження
workflow у списку після вибору.

## 2026-09-24 — Local OSINT Entity Graph canvas

Додано read-only OSINT Entity Graph canvas у вкладці `#osint` на основі
local native browser SVG, без CDN, React Flow/Tailwind або стороннього runtime.
Реалізовано project-scoped graph selection/create, bounded custom entity upsert,
type/risk/provenance details drawer, filter, deterministic grid/radial auto-layout
і right-click context menu з local/network transforms. Network adapters
(`subdomains`, `github_recon`) залишаються за explicit confirmation; passive
OSINT discovery не запускає transform автоматично. Canvas обмежено 1000 visible
nodes за render, а Firefox E2E перевіряє 502-node budget, filter, details,
context menu, workspace persistence, console та network cleanup.

Змінені файли: `web/templates/lab/index.html`,
`tests/e2e/test_automation_ui.py`, `tests/e2e/README.md`, `README.md`,
`AGENTS.md`, `ROADMAP.md`, `документация/osint.md`, `DEVELOPMENT_LOG.md`.

Перевірки: targeted OSINT graph/transform — **10 passed**; повний Django suite —
**103 passed**; Go full suite — **passed**; `python manage.py check`,
`node --check`, `git diff --check` — passed; повний Firefox Automation E2E —
**37 passed**. Початкові targeted запуски виявили number/string mismatch у
graph positions, click hit-area та CSRF-safe browser bulk fixture; усі три
аспекти виправлено й regression reruns пройшли. Відомі межі: native SVG має
deterministic layout без drag/zoom/force-directed physics; passive OSINT-to-graph
live ingestion і transform preview/progress/cancellation залишаються окремими
наступними ітераціями.

## 2026-09-24 — Bounded local OSINT transforms

Додано Go transform registry та gateway API:

- `GET /api/osint/transforms`;
- `POST /api/osint/graphs/<id>/transform`.

`email_recon`, `username_enum` і `ip_geo` працюють локально; `subdomains` і
`github_recon` вимагають explicit `confirm_network=true`, мають bounded
timeouts/response limits і не запускаються автоматично. Email/username mass
enumeration, GitHub commit email extraction і GeoIP database downloads не
виконуються. Результати transforms проходять bounded redaction, canonicalization
та idempotent `OsintGraph` upsert.

Змінені файли: `engine/osint_transforms.go`,
`engine/osint_transforms_test.go`, `engine/main.go`, `web/lab/views.py`,
`web/core/urls.py`, `web/lab/test_osint_graph.py`, `README.md`, `AGENTS.md`,
`документация/osint.md`, `DEVELOPMENT_LOG.md`.

Перевірки: targeted OSINT graph/transform — **10 passed**; повний Django suite —
**103 passed**; Go full suite — **passed**; Django system check, migration drift,
`node --check`, `py_compile` і `git diff --check` — passed. Canvas/Cytoscape та
automatic live OSINT-to-graph wiring залишаються наступними backlog пунктами.

## 2026-09-24 — OSINT Entity Graph foundation

Додано versioned `OsintGraph`, `OsintEntity` та `OsintRelation` з explicit
project-scoped identity, current/archived graph versions, bounded name/risk/
properties/provenance, `observed_at` і `first_observed_at`. Додано idempotent upsert API з
canonicalization доменів/IP/CIDR/URL/ASN/port, allow-listed entity/relation
types, URL query stripping та redaction common secret markers. Duplicate entity
or relation payloads не створюють нові rows; relations можуть посилатися лише на
entities свого graph.

Змінені файли: `web/lab/models.py`,
`web/lab/migrations/0031_osint_entity_graph.py`,
`web/lab/migrations/0032_osint_graph_risk_and_name.py`, `web/lab/osint_graph.py`,
`web/lab/test_osint_graph.py`, `web/lab/views.py`, `web/core/urls.py`,
`README.md`, `AGENTS.md`, `ROADMAP.md`, `документация/osint.md`,
`DEVELOPMENT_LOG.md`.

Перевірки: targeted OSINT graph — **7 passed**; повний Django suite — **100
passed**; Go suite, Django system check, migration drift, `node --check`,
`py_compile` і `git diff --check` — passed. Existing OSINT handoff Firefox
regression — **passed**. Canvas, Cytoscape/local bundle, transform execution
і live OSINT-to-graph wiring ще не реалізовані та залишаються окремими
наступними ітераціями.

## 2026-09-24 — Explicit passive Traffic capture context

Додано `TrafficCaptureContext` із явним `project_id` або `null`, opaque token і
soft deactivation. Django API не читає active Project session: context створюється
окремою CSRF-protected операцією. Go passive proxy читає
`X-RequestRider-Capture-Context`, видаляє internal header перед upstream
forwarding і публікує token лише у correlation event; gateway приховує token у
snapshot/SSE. Browser-driven Target і workflow Target browser передають
validated context ID через worker; server підставляє token і worker додає
internal header лише для local proxy route.

`TrafficRecord` зберігає `capture_context` та `scope_status`. `in_scope` records
приписуются explicit Project; `out_of_scope`, `unscoped` і `invalid_context`
залишаються durable і не видаляються. Traffic table показує scope badge, а
capture token не потрапляє в UI metadata чи captured request headers.

Змінені файли: `web/lab/models.py`,
`web/lab/migrations/0030_traffic_capture_context.py`,
`web/lab/test_traffic_capture_context.py`, `web/lab/views.py`,
`web/lab/workflow_engine.py`, `web/core/urls.py`, `engine/pkg/passive/passive.go`,
`engine/pkg/passive/passive_test.go`, `browser-worker/worker.py`,
`browser-worker/test_worker.py`, `web/templates/lab/index.html`,
`tests/e2e/test_automation_ui.py`, `tests/e2e/README.md`, `README.md`,
`AGENTS.md`, `ROADMAP.md`, `документация/pasivnyi-trafik.md`,
`DEVELOPMENT_LOG.md`.

Перевірки: targeted Django capture context — **6 passed**; browser worker —
**3 passed**; Go passive (including real proxy-handler correlation test) та full
Go suite — **passed**; Django system check,
migration drift, `node --check`, `py_compile` і `git diff --check` — passed.
Повний Django suite — **93 passed**; Firefox Automation E2E — **36 passed**;
comprehensive UI QA — passed. E2E перевіряє явний Project/no-Project вибір,
browser Target forwarding, workspace state, browser/static mode transition та
cleanup. Перший targeted E2E виявив string-vs-number `capture_context_id`; UI
виправлено на numeric payload, повторний тест і full suite пройшли.

Поточні межі: token є local correlation identifier, не authorization credential;
manual browser traffic має передавати internal header через proxy, а shared
auth/ACL/audit retention залишаються окремими backlog ітераціями. Перший full E2E
після додавання context мав transient Firefox reload timeout у Template Store;
test harness тепер повторює лише reload timeout із перевіркою bootstrap DOM.
Targeted rerun і наступний повний Firefox E2E — **36 passed**; comprehensive
UI QA — **passed**.

## 2026-09-24 — Explicit one-shot AI Project context

Додано безпечний opt-in для AI Assistant: checkbox у вкладці AI передає лише
boolean `include_project_context: true` і скидається після кожного success або
error. Без validated active Project checkbox disabled, а API повертає явну
`PROJECT_CONTEXT_REQUIRED` помилку. Server бере `request.active_project`,
формує `ProjectContextBuilder` summary з notes default-off, compact-ить його разом
з attached evidence до `CHAT_TOTAL_CONTEXT_LIMIT` і передає provider-у як
untrusted evidence з project ID provenance. Workflow AI, notes та remote-provider
consent автоматично не вмикаються.

Змінені файли: `web/lab/views.py`, `web/lab/agent_services.py`,
`web/lab/models.py`, `web/lab/migrations/0029_tighten_project_secret_reference.py`,
`web/lab/test_project_context_builder.py`, `web/lab/tests.py`,
`web/templates/lab/index.html`, `tests/e2e/test_automation_ui.py`,
`tests/e2e/README.md`, `README.md`, `AGENTS.md`, `ROADMAP.md`,
`документация/ai-asystent.md`, `документация/project-hub.md`,
`DEVELOPMENT_LOG.md`.

Перевірки: targeted AgentChat — **20 passed**; повний Django suite — **87 passed**;
Go suite, Django system check, migration drift, inline `node --check`,
`py_compile` і `git diff --check` — passed. Повний Firefox Automation E2E —
**35 passed**; AI one-shot checkbox, active Project provenance, redacted
provider payload, consent reset і disabled state без active Project перевірені
реальним browser flow. Comprehensive
UI QA — passed. Тимчасові E2E Project/workflow rows видалено.

Поточні межі: consent не зберігається у workspace snapshot; workflow AI не має
Project context opt-in; shared authentication/ACL, audit retention і окремий
remote-provider consent залишаються наступними backlog ітераціями. Builder
також перетворює invalid legacy scope metadata на explicit `ProjectContextError`,
замість непомітного 500. Перший full-suite прогін після tightening міграції мав
один transient SQLite `database table is locked` у webhook worker; targeted test
і повний повторний Django suite пройшли без помилки.

## 2026-09-24 — Target Knowledge Base foundation

Додано `Project.tech_stack`, bounded `Project.notes` та `ProjectSecret` metadata
model. `ProjectSecret` навмисно не має plaintext `value`: DB дозволяє лише
portable `env:` reference або metadata-only row. Створено
`ProjectContextBuilder(project_id)`, який формує bounded project-scoped Markdown
summary/AI prompt: technology, unique method+URL aggregates, status/content-type
counters, Findings, Workflows, TargetJobs і secret references. Raw headers/bodies,
URL query credentials, cookies, Authorization/CSRF та secret values не
потрапляють у context; notes default-off, prompt delimiters екрануються, evidence
маркується untrusted.

`POST`/`PATCH /api/projects` валідують tech stack nesting/keys/list limits і notes
до 20 000 символів. List endpoint не повертає notes; detail/mutation response
повертає їх лише оператору. Project API error boundary — `INVALID_PROJECT_CONTEXT`.
UI dashboard ще не реалізовано; AI Project context opt-in з’явлений у наступній
ітерації нижче.

Змінені файли: `web/lab/project_context.py`,
`web/lab/test_project_context_builder.py`,
`web/lab/migrations/0028_project_knowledge_base.py`, `web/lab/models.py`,
`web/lab/views.py`, `README.md`, `AGENTS.md`, `ROADMAP.md`,
`документация/project-hub.md`, `DEVELOPMENT_LOG.md`.

Перевірки: targeted Knowledge Base — **5 passed**; повний Django suite —
**84 passed**; Go suite, system check, migration drift, inline `node --check`,
`py_compile`, Markdown links і `git diff --check` — passed. Live Firefox
server-context regression — **2 passed**; повний Automation E2E — **33 passed**;
comprehensive UI QA — passed. Тимчасові E2E Project/workflow rows видалено.

## 2026-09-24 — Server-backed active Project context

Додано `ActiveProjectMiddleware`, який читає лише validated Django session,
прив'язує `request.active_project` та очищає missing/deleted ID. Новий
CSRF-protected `POST /api/project-context` встановлює або очищає Project;
`?project_id` не змінює server context. Index bootstrap передає лише
server-validated ID, а selector синхронізує session і залишає
`requestrider-project` у `localStorage` лише як mirror.

Project create/delete/card selection тепер проходять server context endpoint;
invalid/missing selector відновлює попереджене значення та показує error. E2E
scenario перевіряє CSRF enforcement, deleted-session cleanup, spoofed
`?project_id`, reload, tampered localStorage і projectless active workflow.
Session залишається local single-user context, не object authorization boundary.

Змінені файли: `web/lab/middleware.py`, `web/lab/test_project_context.py`,
`web/lab/views.py`, `web/core/urls.py`, `web/core/settings.py`,
`web/templates/lab/index.html`, `tests/e2e/test_automation_ui.py`,
`tests/e2e/README.md`, `README.md`, `AGENTS.md`, `ROADMAP.md`,
`документация/robochi-prostory-sesii.md`, `DEVELOPMENT_LOG.md`.

Перевірки: targeted context/scope — **11 passed**; повний Django suite —
**79 passed**; Go suite, system check, migration drift, `node --check`,
`py_compile` і `git diff --check` — passed. Live Firefox selector → server
session → reload та clear-context сценарії пройшли без console/page/network
errors. Повний Automation E2E — **33 passed**; comprehensive UI QA — passed.
Два перші full-suite запуски виявили E2E race під час async project load та
transient OAST timeout; helper тепер очікує завершення project-scoped workflow
load, OAST fixture budget збільшено, після чого targeted та два послідовні
full-suite перевірки пройшли.

## 2026-09-24 — Project Scope Foundation

Додано `Project.scope_in`/`scope_out` та окремий deterministic parser без
arbitrary regex. Підтримуються exact host, domain/wildcard, IPv4/IPv6 CIDR і
HTTP(S) URL origin/path rules; rules каноналізуються й дедуплікуються, мають
bounded count/length, а credentials/query/fragment/ambiguous path
відхиляються. `scope_out`
перевіряється перед include. Якщо `scope_in` порожній, workflow використовує
exact `Project.target` scheme/host/effective port/path; відсутній Project або
target тепер fail-closed.

`/api/projects` повертає й canonicalize scope fields та відхиляє invalid
target/rules з `INVALID_PROJECT_SCOPE`. Active Repeater/Target/OSINT/Scanner/
Intruder workflow calls перевіряються перед engine call. UI додає локалізоване
повідомлення, якщо active tool node запускається без Project; E2E harness
створює окремий local Project для кожного сценарію. Це не змінює глобальний
browser-local active Project і не прив’язує весь passive Traffic до нього.

Змінені файли: `web/lab/project_scope.py`,
`web/lab/migrations/0027_project_scope.py`, `web/lab/models.py`,
`web/lab/views.py`, `web/lab/test_project_scope.py`,
`web/lab/test_workflows.py`, `web/templates/lab/index.html`,
`tests/e2e/test_automation_ui.py`, `tests/e2e/README.md`, `README.md`,
`AGENTS.md`, `ROADMAP.md`, `DEVELOPMENT_LOG.md`.

Перевірки: targeted Project scope — **9 passed**; повний Django suite —
**75 passed**; Go suite — passed; Django system check, migration drift,
inline `node --check`, `py_compile`, Markdown links і `git diff --check` —
passed. Live Firefox Project create/manage/scope persistence/reload/delete не
мав console/page/network errors; тимчасовий Project видалено. Повний Automation
Firefox E2E після первинного fail-closed regression й виправлення test harness
— **32 passed**; comprehensive UI QA — passed. Один transient OAST timeout у
першому повному прогоні не повторився у targeted та наступному повному прогоні.
Поточний UI ще не має полів редагування scope; API contract готовий до
наступного browser-facing slice.

## 2026-09-24 — Аудит стратегічного roadmap і Web-Maltego OSINT

Проведено read-only аудит OSINT/Scanner, Automation/AI/session, protocols та
UI/UX. Roadmap виправлено відповідно до фактичного коду: nullable Project
relations ще не забезпечують наскрізну isolation, Scanner profiles поки не
змінюють checks, Finding fingerprint не є deduplication key, а OSINT/Scanner
не мають durable job lifecycle. Додано пріоритетні P0/P1/P2 backlog для Project
Hub, Target Knowledge Base, OSINT Entity Graph, local transforms, Scanner,
SessionMacro, protocols, UI та reporting.

Окремо додано Web-Maltego-style graph напрям із посиланнями на Argus (MIT),
Flowsint (Apache-2.0) та Osiris (MIT). Зафіксовано, що local execution Argus
не означає відсутність egress: public endpoints/websites бачать запити. Сторонні
кодові бази не копіювати без license/NOTICE audit; UI/library та entity/transform
contract мають бути власними й проходити fixtures/redaction/bounds.

Змінені файли: `ROADMAP.md`, `DEVELOPMENT_LOG.md`.

Перевірки: `git diff --check` — passed; browser smoke-test не застосовний,
оскільки browser-facing код не змінювався. Наступна ітерація — `Project Scope
Foundation`, а не simultaneous implementation усіх backlog-пунктів.

## 2026-09-24 — Відновлення перевірки після крашнутої сесії

Відновлено незавершену локальну верифікацію пакета Repeater Burst,
Last-Byte Sync, OAST, Template Store та high-risk canary templates. Жодні
зміни попередньої сесії не відкачено або перезаписано.

Перевірки: `go test ./... -count=1` та race suite — passed; `go vet ./...` —
passed; Django system check і повний suite — **68 passed**; browser-worker
Playwright tests — **2 passed**; OAST fixture — **2 passed**; Last-Byte fixture
— **1 passed**; inline JavaScript `node --check`, `py_compile`,
`makemigrations --check --dry-run` та `git diff --check` — passed. Повний
local-only Firefox E2E — **31 passed** за 258.811 с; comprehensive UI QA —
passed. Поточного тестового Project після smoke-test не залишено; раніше
наявні локальні записи не змінювалися.

## 2026-09-24 — Raw Last-Byte та manual-only high-risk canary package

Реалізовано окремий `Last-Byte Sync` node і Go job: raw HTTP/1.1
POST/PUT/PATCH із затримкою фінального body byte, bounded hold/timeout,
iteration/concurrency budget, cancellation, TLS verification без
`InsecureSkipVerify`, response caps, loopback-first policy та History
traffic. Зовнішній raw target дозволяється лише через явний
`LAST_BYTE_ALLOW_EXTERNAL=1`; baseline Repeater не змінено.

Додано сім manual-only high-risk canary templates: BOLA/IDOR differential,
bounded race timing, WAF rule differential, synthetic JWT claims, XXE → local
OAST callback, read-only CI/CD exposure review та Last-Byte timing review.
Усі активні manifests мають Project scope confirmation і reserved
`__requires_confirmation` marker, тому confirmation не залежить лише від
типу ноди. Credentials, реальні authorization bypass та external execution не
додаються; XXE callback fixture дозволяє лише loopback URL.

Змінені файли: `engine/main.go`, `engine/last_byte.go`,
`engine/last_byte_test.go`, `tools/last_byte_fixture.py`,
`tools/test_last_byte_fixture.py`, `tools/target_fixture.py`,
`web/lab/models.py`, `web/lab/migrations/0026_trafficrecord_last_byte_source.py`,
`web/lab/views.py`, `web/lab/workflow_engine.py`,
`web/lab/workflow_templates.py`, `web/lab/test_workflows.py`,
`web/templates/lab/index.html`, `tests/e2e/test_automation_ui.py`,
`tests/e2e/README.md`, `README.md`, `ROADMAP.md`,
`документация/template-store.md`.

Перевірки на поточній ітерації: Go suite — passed; Django workflow suite —
**25 passed**; raw fixture unit — passed; live Firefox Last-Byte — passed;
live Firefox high-risk canary Template Store import/run — **6 scenarios passed**;
Template Store preview/search — passed. Фінальний повний browser regression —
**31 passed**; усі загальні й targeted перевірки та `git diff --check` —
passed, див. запис про відновлення після крашнутої сесії.


## 2026-09-24 — Безпечний пакет Template Store playbooks

Додано шість read-only/interactive baseline manifests на існуючих вузлах:
API headers, JavaScript asset inventory, debug surface check, schema endpoint
discovery, perimeter asset inventory та advisory request-evidence AI triage.
Усі нові шаблони вимагають manual import, Project scope confirmation і не містять
Intruder, browser actions, OAST, raw sockets чи Last-Byte sync.

Змінені файли: `web/lab/workflow_templates.py`,
`web/lab/test_workflows.py`, `tests/e2e/test_automation_ui.py`,
`документация/template-store.md`, `README.md`, `ROADMAP.md`.

Перевірки: Django workflow suite — **21 passed**; live Template Store browser
smoke — passed; повний Firefox E2E — **29 passed**; `node --check`,
`py_compile` та `git diff --check` — passed.


## 2026-09-24 — Адаптація comprehensive QA smoke-test

`tests/e2e/comprehensive_qa_test.py` синхронізовано з новим інтерфейсом:
header status badges, raw editors, response metadata, OSINT/Scanner/Comparer/
Decoder/AI selectors, Target status, Template Store close button та History/
Traffic selectors. Тест використовує лише локальний fixture і створює
тимчасовий Project після перевірки; результат пишеться у git-ignored
`tests/e2e/qa_results.json`.

Змінені файли: `tests/e2e/comprehensive_qa_test.py`,
`tests/e2e/README.md`, `.gitignore`.

Перевірки: live Firefox comprehensive QA — passed; перевірено header status,
усі основні вкладки, local fixture, History/Traffic та Template Store;
`node --check`, `py_compile` та `git diff --check` — passed.


## 2026-09-24 — Bounded Repeater Burst node

Додано окремий `Repeater Burst` node для small parallel request review. Він
передає bounded job у Go через `/proxy/repeater-burst`, має confirmation,
жорсткі iteration/concurrency limits, delay між waves, cancellation і History
entries.
Це не raw Last-Byte TCP/TLS mode: TLS verification, redirects і реальна
last-byte semantics залишені для окремого experimental contract.

Додано built-in Template Store playbook `Bounded parallel request review`,
Django adapter test і live Firefox fixture scenario. Targeted burst E2E
перевіряє 3 local `/health` exchanges, count/mode та History.

Threat model і mitigations: недовічений workflow input не може розширити
Project origin; schedule/webhook автоматично не запускають burst; активний job
 має global budget, read-only method allowlist, fixed TLS verification, redirect
 rejection, timeout, response/aggregate caps, cancellation cleanup і
 retention cleanup. Engine не логрує body, headers чи credentials; результат
містить лише negotiated metadata та truncation markers.

Змінені файли: `engine/main.go`, `engine/routing.go`, `engine/main_test.go`,
`engine/burst.go`, `engine/burst_test.go`,
`web/lab/workflow_engine.py`, `web/lab/views.py`,
`web/templates/lab/index.html`, `web/lab/test_workflows.py`,
`web/lab/workflow_templates.py`, `tests/e2e/test_automation_ui.py`,
`README.md`, `AGENTS.md`, `документация/automation-сценарії.md`, `ROADMAP.md`.

Перевірки: targeted Django burst test — passed; live Firefox burst success/scope
сценарії — passed; Go burst lifecycle/TLS/cancellation/global-budget tests —
passed; `go test ./... -count=1` і `go test ./... -count=1 -race` — passed;
Django workflow suite — **21 passed**; загальний Django suite — **63 passed**;
повний Firefox E2E — **29 passed**; OAST fixture — **2 passed**; browser-worker
— **2 passed**; `node --check`, `py_compile`, `go vet` та `git diff --check` — passed. Перший
повний E2E прогін мав transient timeout під час browser `setUp`; E2E harness
тепер очікує DOM commit і selector `#workflow-new` та має один retry для
Firefox connection saturation; після цього targeted test і два повні прогони
після перезапуску/engine reload завершилися **`29 passed`**. Після cleanup
workflow API містить `0` test workflows; один порожній проєкт `Новий проєкт`
залишено без видалення, оскільки його походження не підтверджене.


## 2026-09-24 — Local OAST Listener vertical slice

Додано безпечний loopback-first OAST contract: Go engine реєструє provider
session, повертає payload URL, фоново polling-ить callback events і підтримує
cancel/status. Django workflow має дві фази: `OAST Listener` (start) і
`OAST Collect` (wait); shared workflow context дозволяє collect знайти listener
після проміжного Repeater/Target вузла. Public/remote provider заборонений без
`OAST_ALLOW_EXTERNAL=1`, TLS verification не вимикається, auth token не
потрапляє у збережені workflow params.

Додано `tools/oast_fixture.py` з локальними `/register`, `/poll`, `/hit` та
`/listener` endpoints і fixture unit test. Go OAST adapter поки що використовує
явний provider contract, а не прикидається повним Interactsh crypto client.

Змінені файли: `engine/oast.go`, `engine/oast_test.go`, `engine/main.go`,
`tools/oast_fixture.py`, `tools/test_oast_fixture.py`,
`web/lab/workflow_engine.py`, `web/lab/views.py`,
`web/templates/lab/index.html`, `web/lab/test_workflows.py`,
`tests/e2e/test_automation_ui.py`, `ROADMAP.md`,
`документация/automation-сценарії.md`, `документация/oast.md`.

Перевірки: Go tests — passed; OAST fixture test — passed; Django workflow
tests — **17 passed**; live Firefox OAST start → Repeater callback → Collect —
passed; повний E2E — **28 tests passed**; загальний Django suite — **60 tests
passed**; fixture tests — **2 passed**.


## 2026-09-24 — Template Store MVP для Automation

Додано локальний каталог готових workflow-шаблонів без автоматичного виконання:
`GET /api/workflow-templates`, категорії, пошук, preview, required variables,
risk/execution badges і scope confirmation. Import створює окремий локальний
Automation workspace і не записує workflow у SQLite до окремого `Save`; активні
шаблони не bypass-ять поточний confirmation flow. `Save as template` зберігає
redacted custom graph у browser-local catalog.

Змінені файли: `web/lab/workflow_templates.py`, `web/lab/views.py`,
`web/core/urls.py`, `web/lab/test_workflows.py`,
`web/templates/lab/index.html`, `tests/e2e/test_automation_ui.py`,
`tests/e2e/README.md`, `документация/template-store.md`, `README.md`,
`ROADMAP.md`, `AGENTS.md`.

Перевірки: Django catalog/API tests — passed; Django workflow — **18 tests
passed**; live Firefox Template Store scenario — passed; повний E2E — **28 tests
passed**; загальний Django suite — **60 tests passed**; Go tests,
browser-worker tests (2), system check,
`makemigrations --check`, inline `node --check`, `py_compile` і `git diff --check`
— passed. Каталог не містить public OAST, fixed credentials, Last-Byte burst
або автономних active actions.


## 2026-09-24 — Automation UI E2E та evidence → AI сценарії

Створено відтворювану local-only browser matrix у
`tests/e2e/test_automation_ui.py` та `tests/e2e/README.md`. Тести працюють
через Firefox UI з випадковим loopback fixture і local OpenAI-compatible LLM
stub; зовнішніх цілей, credentials і persistent test workflows немає.

Перевірені сценарії:

- canvas connections та Manual → Set → Output;
- Repeater transfer, multi-URL loop, History;
- Target selected URL → Repeater workspace → follow-up Automation;
- Condition true/false → Merge, Decoder/Comparer та failed Decoder;
- static/browser Target, browser confirmation та network evidence;
- Intruder dictionary, cancel/confirm dialog та export;
- Project scope rejection без engine call;
- pause/resume/cancel, webhook/schedule activation;
- export/import/rerun, reload/persistence, dirty draft auto-save;
- Repeater/Intruder/Target/OSINT/Scanner evidence → explicit AI attachment →
  local AI recommendation → operator-created follow-up workflow;
- Repeater evidence → AI Agent node → Output.

Під час UI regression виправлено:

- відновлення attached AI evidence з workspace (`Object.fromEntries` отримував
  вже object, а не entries);
- `data-i18n` на Scanner label з nested `<select>` видаляв profile control;
- Intruder workspace відновлювався без жодного dictionary;
- inactive Condition branch більше не запускав downstream Set перед Merge;
- `Run`, `Export` і `Activate` тепер зберігають dirty draft перед дією;
- workspace autosave більше не перетирає explicit validation/error status;
- run log UI показує `WorkflowRun.output`.

Змінені файли: `tests/e2e/test_automation_ui.py`, `tests/e2e/README.md`,
`web/templates/lab/index.html`, `web/lab/workflow_engine.py`,
`web/lab/test_workflows.py`, `README.md`, `ROADMAP.md`,
`документация/automation-сценарії.md`, `документация/ai-asystent.md`.

Перевірки: E2E Firefox — **28 tests passed**; Django workflow — **18 tests
passed**, загальний Django suite — **60 tests passed**; Go tests, browser-worker
tests (2), system check, `makemigrations --check`, inline `node --check`,
`py_compile` і `git diff --check` — passed. Поточний runtime залишається process-local; AI не виконує активні
дії автоматично, а follow-up workflow запускає оператор.


## 2026-09-24 — Перенесення налаштованих tool workspaces у Automation

Завершено вертикальний зріз для роботи з налаштованими вкладками інструментів:

- додано `Send to Automation` для Repeater, Intruder, Target, OSINT, Scanner,
  Decoder, Comparer та AI; передача зберігає поточний workflow, додає trigger
  для нового draft і перемикає на вибраний вузол;
- `Use current workspace` і `Open in tool` дозволяють оновлюти вузол із
  відкритої вкладки або відкрити serialized node params у відповідному інструменті;
- inspector переведено на schema-driven поля з `/api/workflows/node-types`:
  Repeater, Target, Intruder, Decoder, Comparer, AI та логічні вузли мають
  типізовані select/number/boolean/JSON controls, а не лише загальний JSON
  редактор; невідомі параметри зберігаються окремо;
- workspace persistence доповнено для Target engine/browser/mode/actions,
  Decoder operation, Comparer mode та AI provider/endpoint/model;
- виправлено вибір вузла на canvas: pointer drag більше не перериває click
  selection after render.

Змінені файли: `web/templates/lab/index.html`,
`web/lab/workflow_engine.py`, `web/lab/test_workflows.py`, `README.md`,
`документация/povtoryuvach.md`, `документация/robochi-prostory-sesii.md`.

Перевірки: `node --check` для inline JavaScript, `git diff --check`,
`python manage.py check`, `python manage.py makemigrations --check --dry-run`,
Django `54` tests, Go `go test ./... -count=1`, targeted workflow tests і
Playwright Firefox smoke-test для Repeater → Automation, reload/persistence,
`Open in tool`, `Use current workspace`, browser Target actions, Comparer bytes
та Decoder transfer; окремо перевірено запуск перенесеного Repeater через
`tools/target_fixture.py` (HTTP 200, response `ok`). Smoke-test не виявив console
errors або failed requests.
Поточний runtime залишається process-local; Redis/Celery, distributed queue та
multi-main HA не входять у цю ітерацію.


## 2026-09-24 — Workflow runtime: scope, export/import, SSE та UX-фікс

Розширено Automation runtime після фіксації UX/UI-бази:

- додано n8n-style normalization для `nodes`, `edges`, `parameters` і позицій;
- активні Repeater URL перевіряються межами Project scope, а Repeater може
  виконувати обмежений список requests із `delay_ms`/`rate_limit_ms`;
- додано JWT decode без перевірки signature, Markdown/HTML/JSON Output;
- додано workflow export/import та run export у JSON/Markdown;
- додано SSE endpoint для live node events з UI polling fallback;
- додано canvas zoom, pan, minimap і auto-layout controls;
- Intruder і browser actions залишаються за explicit confirmation.

Архітектурні концепти (`nodes`, `edges`, активне виконання, реєстрація trigger,
SSE) звірено з публічним репозиторієм n8n; код n8n не копіювався, а його
Sustainable Use License не залучається до цього локального runtime.

Перевірено: Django `53` tests, targeted workflow tests, Go tests, inline
JavaScript syntax, `git diff --check`, Playwright Firefox smoke-test і
повний Repeater lifecycle через локальний `tools/target_fixture.py` fixture. Поточний
runtime process-local; Redis/Celery, multi-main HA і proxy-trigger не входять у
цей реліз.


## 2026-09-24 — зафіксовано UX/UI-базу Automation

Зафіксовано поточний зовнішній варіант редактора Automation, який є основою
подальшого workflow runtime:

- додана окрема вкладка `Automation` з canvas, palette вузлів, інспектором і
  журналом виконань;
- меню інструментів залишається в одному ряду; на вузьких екранах використовується
  горизонтальна прокрутка меню без перенесення пунктів;
- іконка AI зберегла попередній розмір, а окремі компактні правила застосовуються
  лише до palette кнопок вузлів;
- кнопки `Triggers`, `Tools` і `Logic` у лівій панелі зменшено так, щоб список
  функцій був видимий без внутрішнього вертикального скролу на основному desktop
  viewport;
- Automation-редактор не змінює масштаб браузера: розміри перевірено у Firefox при
  ширині 1366, 1024, 800 та 560 px.

Змінені файли: `web/templates/lab/index.html`, `web/lab/workflow_engine.py`,
`web/lab/models.py`, `web/lab/apps.py`, `web/lab/views.py`, `web/core/urls.py`,
`web/lab/tests.py`, `web/lab/migrations/0025_workflow_automation.py`,
`web/lab/test_workflows.py`, `README.md`, `ROADMAP.md`, `AGENTS.md`.

Перевірки для цієї UX/UI-ітерації: `node --check` для inline JavaScript,
`git diff --check`, Django system check, targeted workflow tests і Playwright
Firefox smoke-test canvas/palette/navigation. Поточна версія зафіксована як
базовий UX/UI-варіант; подальші зміни мають бути окремими ітераціями.


Розширено всі 13 документів у [документация/](./документация/). Для кожної
функції додано трасування повного циклу:

- вхідні дані та дії оператора;
- browser handlers і локальний state;
- Django gateway validation/normalization;
- Go engine, worker, route або browser-worker flow;
- проміжні стани, progress, SSE/polling і cancellation;
- успішне завершення та explicit error paths;
- SQLite/Traffic/workspace persistence;
- export, reload, language switch та інтеграції з іншими вкладками;
- контрольні точки для діагностики й regression smoke-test.

Особливо деталізовано Repeater, Intruder, Target static/browser-driven,
Scanner, OSINT, Passive Traffic, History, Proxy/Tor, workspace/session,
AI, Decoder і Comparer. Browser-facing код не змінювався, тому окремий
браузерний smoke-test для цієї документаційної ітерації не потрібен.

## 2026-09-22 — фінальна перевірка документації

Після синхронізації документації повторно перевірено:

- усі відносні Markdown-посилання — битих посилань немає;
- `git diff --check`;
- inline JavaScript через `node --check`;
- `python manage.py check`;
- `python manage.py test -v 1` — 42 тести пройшли;
- `go test ./... -count=1` — усі пакети пройшли.

Оскільки ця ітерація змінювала лише документацію, окремий browser smoke-test
не потрібен; browser-facing код не змінювався.

## 2026-09-22 — синхронізація документації з актуальним станом

Оновлено документацію проєкту:

- [AGENTS.md](./AGENTS.md) тепер містить актуальні посилання, завершений
  browser-driven Target і єдиний алгоритм ітерацій;
- [README.md](./README.md) отримав зведення реалізованих можливостей,
  Projects/cascade deletion, Findings Center і завершеного аудиту
  Ukrainian/English;
- [ROADMAP.md](./ROADMAP.md) позначає всі поточні пункти як виконані та не
  містить неузгодженого незавершеного backlog;
- `NEXT_AGENT_PROMPT.md` переведено в режим
  підтримки завершеного roadmap: нові функції додаються лише за окремим
  запитом, а робота починається з `AGENTS.md`;
- [AGENT_USER_GUIDE.md](./AGENT_USER_GUIDE.md) доповнено правилами перевірки
  локалізованих і відновлених AI evidence states;
- довідники в `документация/` перевірені на відповідність поточним назвам
  вкладок, route modes, Target режимам і API.

Перевірено:

- `git diff --check`;
- пошук битих посилань на відсутні документи та неіснуючий roadmap backlog;
- актуальність описів через поточні моделі, migrations, API та UI.

## 2026-09-22 — алгоритм роботи за todo/roadmap

До [AGENTS.md](./AGENTS.md) додано обов'язковий алгоритм ітерацій:

- одна ітерація — одне конкретне завдання;
- перед початком перечитується `AGENTS.md` і перевіряється актуальний обсяг;
- після реалізації запускаються всі застосовні перевірки: inline JavaScript,
  `git diff --check`, Django check, Django tests, Go tests і targeted
  regression-тести;
- browser-facing зміни додатково перевіряються через живий браузер із
  перевіркою DOM, persistence, console і network;
- документація та журнал оновлюються до переходу до наступного пункту;
- якщо будь-яка перевірка не пройшла, наступна ітерація не починається.

## 2026-09-22 — нормалізація Proxy workspace після зміни мови

Під час відновлення Proxy workspace збережені українські та англійські
порожні стани маршруту тепер нормалізуються через поточний словник. Це
стосується статусу прямого підключення, сводки маршруту та підказки перевірки,
тому відкриття вкладки одразу відповідає активній мові.

## 2026-09-22 — локалізація порожньої відповіді Repeater

Порожній стан відповіді Repeater нормалізується через поточний словник навіть
після відновлення робочого простору. Український текст більше не залишається
в англійській локалізації після перемикання мови або перезавантаження сторінки.

## 2026-09-22 — оновлення порожнього стану Scanner під час зміни мови

Порожній стан Scanner тепер оновлюється при кожному перемиканні мови, навіть
якщо в робочому просторі збережено попередній текст іншою мовою. Український
текст більше не залишається після переходу на English.

## 2026-09-22 — повторна перевірка локалізації Intruder

Повторно перевірено весь розділ Intruder через живий браузер. Локалізовано
динамічні кнопки `Видалити`, назву словника, вибір файлу, поле payload,
підписи збережених атак і повідомлення статусу. Під час перемикання мови
словники, трансформації та список збережених атак тепер перерисовуються з
поточними перекладами.

## 2026-09-22 — локалізація меню Target

У блоці керування картою Target локалізовано заголовок сортування, фільтр
мережевих доказів браузера та кнопку порівняння статичної й браузерної карт.
Пункти сортування й мережевого фільтра тепер не залишають англомовних підписів
в українському режимі.

## 2026-09-22 — локалізація порожнього стану Proxy

Fallback під час відновлення Proxy workspace тепер використовує поточний
словник для стану завантаження маршруту замість жорстко заданого
`Loading route...`. Переклад підказки перевірки маршруту також зберігається
під час перемикання української та англійської мов, а статус прямого
підключення більше не містить англійського тексту в українському режимі.

## 2026-09-22 — локалізація порожнього стану інспектора Intruder

Український текст порожнього стану інспекторів запиту та відповіді Intruder
змінено на `Виберіть результат Інтрудера`. Очищення результатів також тепер
використовує поточний словник замість жорстко заданого англійського тексту.

## 2026-09-22 — локалізація огляду Intruder

Перекладено динамічний блок огляду Intruder: підписи цілі, маршруту, режиму,
затримки, паралельності та орієнтовної кількості завдань тепер беруться з
поточного словника. Огляд також перерисовується під час перемикання між
українською та англійською мовами.

## 2026-09-22 — переклад порожнього стану Scanner

Виправлено український переклад порожнього стану Scanner: англомовний текст
`Enter an authorized URL and run Safe CMS Recon.` замінено на
`Введіть дозволений URL і запустіть безпечну CMS-розвідку.` Перевірено через
живий браузер після очищення Scanner, перемикання мови та без console errors.

## 2026-09-22 — індикатор активного Project у шапці

Індикатор активного Project перенесено в ліву верхню частину шапки. Логотип
залишається по центру, а глобальні дії сесії — праворуч; перевірка в живому
браузері підтвердила відсутність перекриття елементів і переповнення.

## 2026-09-22 — перевірка локалізації UI

Перевірено перемикання української та англійської мов через живий браузер на
всіх основних вкладках. Для української локалізації додано переклади меню
Projects, активного Project, Target controls, Scanner і Agent empty state.
Кнопки Traffic sessions, підказки сортування та доступні назви запису трафіку
тепер також локалізуються.

Індикатор запису Traffic більше не має фіксованої ширини, що спричиняла
переповнення для довшого українського тексту: ширина адаптивна, текст може
переноситися. Перевірено DOM, ARIA labels, переповнення контролів і console
errors у двох мовах.

## 2026-09-22 — керування Project у UI

У Project-панелі додано керування вибраним проєктом: редагування назви,
target, environment і route profile через доступний HTML-діалог, а також
видалення з явним підтвердженням. Після видалення selector повертається до
`No project`, а пов’язані записи видаляються разом із Project каскадно.

Перевірено `python manage.py test` (42 тести), перевірку синтаксису inline
JavaScript, `git diff --check` і живий браузерний цикл створення, редагування
та видалення тимчасового Project без console errors.

## 2026-09-22 — окрема вкладка Projects

Керування workspace перенесено з верхньої панелі в окрему доступну вкладку
`Projects`. Вкладка показує активний Project, список усіх проєктів, створення,
вибір, редагування та каскадне видалення. У шапці залишено компактний індикатор
активного Project, щоб не перекривати логотип і не змішувати керування
workspace з глобальними діями сесії.

Перевірено syntax check, Django suite, живий browser-сценарій вкладки,
оновлення project label, відсутність console errors і очищення тимчасового
проєкту після тесту.

## 2026-09-22 — Project workspace і Findings Center

Додано `Project` із target/environment/route profile, metadata та
`schema_version`. History, Traffic sessions, Intruder attacks, Target jobs і
Findings мають nullable зв’язок із Project. Session bundle додатково
дзеркалюється в IndexedDB з fallback на наявний localStorage для сумісності.

Scanner отримав профілі `Generic Web`, `CMS`, `API` і `Security Headers`.
Додано єдину модель Findings із confidence, verification status, lifecycle
статусами та evidence до/після. Findings Center підтримує збереження scanner
результатів, Markdown/HTML export і endpoint повторної перевірки evidence.
Перевірено Django suite, Go suite, JavaScript syntax та живий браузерний
workflow Project, Scanner і Findings Center.

## 2026-09-22 — завершено Browser-driven Target lifecycle

Додано локальний fixture у `tools/target_fixture.py` з HTML-навігацією,
формою, JS `fetch` і окремими сторінками для перевірки same-origin обходу.
`browser-worker/test_worker.py` запускає реальний Firefox через Playwright,
виконує `fill` і `click`, перевіряє network evidence, перехід на `/next` та
завершення job зі статусом `completed`. Form actions застосовуються лише до
стартової сторінки, щоб знайдені дочірні документи не отримували непридатні
для них селектори.

Живий browser smoke-test через Django UI завершив 3 сторінки fixture зі
статусом `200`, показав `/api/data` у network evidence і не зафіксував
помилок у console. Worker тепер за замовчуванням слухає лише `127.0.0.1`.

## 2026-09-22 — чистий запуск міграцій і Playwright

Створено міграцію `web/lab/migrations/0020_alter_trafficrecord_source.py`
для актуального набору джерел `TrafficRecord`. `run-engine.sh` використовує
вже кешований Playwright Firefox і не запускає перевірку/завантаження
Chromium/WebKit при кожному старті. Якщо кешу немає, Firefox встановлюється
лише один раз. Попередження про Ubuntu fallback build на Kali стосується
первинної установки сумісного runtime та не є помилкою застосунку.

## 2026-09-22 — browser network workflow для Target

Target отримав таблицю network evidence з фільтрами API/XHR/fetch, документів,
скриптів та інших ресурсів, а знайдені endpoint-и можна передати в Repeater,
Intruder або Scanner. Для JS-heavy сторінок додано явний список browser actions
`click` і `fill` за CSS-селекторами. Worker після дії очікує коротку паузу замість
`networkidle`, щоб не зависати на сторінках із постійним фоновим трафіком.
Кнопка порівняння показує різницю між останніми static і browser картами.

## 2026-09-22 — прискорено browser-driven crawl

Послідовний обхід однією вкладкою замінено на worker pool до чотирьох
паралельних Playwright-вкладок. Значення `Delay ms` у Target за замовчуванням
змінено зі 100 на 0, а коротке очікування після `domcontentloaded` зменшено до
50 мс. Ліміти `max_pages`, `max_depth`, `same_origin` і явний delay збережено.
Живий Firefox-тест на локальній fixture завершив 9 сторінок зі статусом
`completed`.

## 2026-09-22 — вилучено непотрібний генератор payload

З Intruder вилучено слабкий генератор чисел, дат, UUID і загальних значень:
оператору достатньо ручного редагування словників або завантаження `.txt`
файлів. Основний workflow словників, маркерів і режимів атаки не змінено.

## 2026-09-22 — виправлено тайм-аут browser-driven Target для Yandex

Browser-driven Target використовував `wait_until="networkidle"`. Сайти з
постійними фоновими запитами, зокрема Yandex, не досягали стану `networkidle`
до ліміту 30 секунд, тому UI показував `ERROR` і час близько `30000 ms`,
хоча сторінка була доступна.

Змінено:

- `browser-worker/worker.py` — навігація тепер очікує
  `domcontentloaded`, а коротка додаткова пауза зберігає час для
  JS-rendered контенту без очікування завершення фонового трафіку;
- `web/templates/lab/index.html` — після фіксації висоти Target-контролів
  дочірні елементи панелі знову приймають pointer events, щоб кнопки
  `Build map`, `Cancel` та експорту були доступні для ручного керування.

Перевірено реальним Firefox через Django gateway і UI:

- `https://yandex.ru` завершився як `completed`;
- знайдений redirect на Yandex SSO повернув HTTP 200;
- час навігації — близько 2–3 секунд замість `30009 ms`;
- browser worker `/health`, Python syntax check і `git diff --check` — OK.

Під час перевірки повільного обходу знайдено накопичення `page.on("request")`
listener-ів: worker додавав новий callback для кожної сторінки й не знімав
попередній. Це збільшувало CPU та обсяг обробки мережевих подій на довгих
картах. Listener тепер знімається після кожної сторінки, а зображення, шрифти
й медіа блокуються як непотрібні для пошуку URL. UI polling Target збільшено з
250 до 500 мс, щоб не перемальовувати велику таблицю надмірно часто.

Для зрозумілого відображення redirect у browser-driven результат додано
`requested_url`: таблиця показує і URL, який crawler запитував, і фінальний URL
після HTTP redirect. Значення `Max pages=1` та `Max depth=0` залишаються
навмисним режимом одного стартового документа; для обходу посилань потрібно
збільшити їх у Target controls.

## 2026-09-21 — виправлено порожній Firefox Push proxy event

Службовий Firefox Push-запит міг відображатися як `proxy | - | - | - | 204 |
- B`. `blockFirefoxPush` повертав синтетичну відповідь до `captureRequest`, тому
`captureResponse` створював fallback-подію без методу й URL. Нульовий розмір
відповіді також губився через `omitempty` та truthy-перевірку в Django.

Змінено:

- `engine/pkg/passive/passive.go` — `captureRequest` тепер виконується перед
  блокувальником Firefox Push, а `response_size: 0` серіалізується явно;
- `web/lab/views.py` — значення `0` зберігається в SQLite як валідний розмір;
- `web/templates/lab/index.html` — History і Traffic показують `0 B` для
  порожньої, але успішної відповіді, а `-` лише коли розмір невідомий;
- `engine/pkg/passive/passive_test.go` і `web/lab/tests.py` — додано
  регресійні перевірки нульового розміру.

Статус `204 No Content` не змінювався: це очікувана локальна відповідь для
Firefox Push, але тепер proxy event має повні метадані запиту.

## 2026-09-21 — додано browser-driven Target worker

Для JS-rendered маршрутів додано окремий `browser-worker` на
Firefox/Playwright. Статичний Go crawler не змінювався та має окремий
lifecycle.

Змінено:

- `browser-worker/worker.py` — асинхронні jobs, polling, cancel, обходи
  сторінок у браузері та network evidence;
- `browser-worker/Dockerfile` і `browser-worker/requirements.txt` —
  ізольований Playwright runtime;
- `web/lab/views.py` і `web/core/urls.py` — browser-facing gateway API;
- `web/templates/lab/index.html` — вибір Static HTTP або Browser-driven
  Firefox;
- `docker-compose.yml` — окремий локальний сервіс worker.

State-changing actions не виконуються без явного
`allow_state_changing_actions`; режим форм із fixtures залишається окремою
наступною роботою.

Після smoke-перевірки виправлено запуск у локальному режимі: `run-engine.sh`
раніше не запускав browser worker, через що UI отримував `Connection refused`.
Тепер worker стартує автоматично, має `/health`, а gateway передає йому
активний SOCKS5/Tor route як `proxy_server`.

Окремо sync Playwright API замінено на async API, оскільки sync API не може
працювати у фонового thread. Worker тепер перевіряє реальний запуск Firefox
до відкриття health endpoint; відсутній або пошкоджений browser runtime
виявляється під час запуску, а не як job із `0 pages`.

Browser runtime за замовчуванням — Firefox, оскільки це основний браузер
оператора, але browser-driven Target розширено вибором runtime: Firefox, Chromium, Chrome,
Edge або WebKit. Worker не підключається до вже відкритого профілю браузера:
для стабільності та ізоляції він запускає окремий automation context обраного
браузера з активним Direct або SOCKS5/Tor proxy. Playwright-managed Firefox,
Chromium і WebKit встановлюються launcher-ом; Chrome та Edge використовують
відповідний встановлений browser channel.

Під час обов’язкового живого UI smoke-тесту через Firefox знайдено та виправлено
два runtime-баги, які не ловили скриптові тести:

- async `response.header_value()` не мав `await`, через що worker падав під час
  JSON serialization і gateway отримував `RemoteDisconnected`;
- `asyncio` не був доступний у browser crawl loop, через що job відкривав
  сторінку з HTTP 200, але завершувався як `failed`.

Після виправлень фактичний сценарій через UI завершився як `completed`,
відкрив локальний fixture через Firefox, зібрав 2 сторінки (`/` і `/next`) та
показав їх у Target table.

Перевірено також robots-поведінку: `Allow`/`Disallow` не застосовуються як
фільтр URL. Static crawler бере з `robots.txt` лише sitemap references, а
browser-driven crawler не читає robots directives.

Перевірено:

- Python compilation: OK;
- Go engine tests: OK;
- Django browser-worker gateway tests додані.
- browser-worker `/health` smoke check: OK.
- живий Firefox UI smoke test Target: OK.

## 2026-09-21 — додано review summary для Intruder

Для підвищення операційної прозорості в UI додано компактну панель review перед запуском Intruder. Панель показує:

- активну ціль;
- поточний маршрут (Direct або SOCKS5/Tor);
- режим Intruder;
- delay, concurrency та оцінку кількості jobs.

Змінено [web/templates/lab/index.html](./web/templates/lab/index.html):

- вставлено `operation-review` блок для Intruder;
- обчислення review-summary прив’язано до актуального route і введених параметрів;
- block є інформативним, а не обмежувальним: він додає audit context і visual confirmation, але не блокує повноцінний pentest workflow.

Review-блок для Target вилучено, оскільки його значення повністю дублювали
видимі поля налаштувань обходу.

Перевірено:

- JS syntax check для inline script: OK;
- `git diff --check`: OK.

## 2026-09-21 — виправлення refresh traffic без активного engine

Після запуску Django-тестів виявлено, що `DELETE /api/traffic` повертав `502` у
сценарії без запущеного Go engine, хоча UI описує цю операцію як локальне
`Refresh traffic` і має повертати успіх для очищення in-memory snapshot навіть
при відсутньому upstream.

Змінено [web/lab/views.py](./web/lab/views.py):

- `traffic(request)` тепер перехоплює `ENGINE_UNAVAILABLE` для `DELETE /events`;
- у такому випадку відповідь повертається як `{ "ok": true }` зі статусом 200
  замість propagation 502;
- інші engine-related routes залишаються незмінними, щоб не маскувати реальні
  помилки в інструментальних операціях.

Перевірено:

- `cd /home/kali/Desktop/Request-Rider/web && python manage.py test -v 2` — OK;
- `cd /home/kali/Desktop/Request-Rider/engine && go test ./... -count=1` — OK;
- `git diff --check` — без помилок.

## 2026-09-21 — створення окремої документації функцій

Створено папку `документация` для детального опису функцій RequestRider
окремими файлами.

Додано файл [документация/прокси.md](./документация/прокси.md), який описує:

- налаштування Direct і SOCKS5/Tor через UI;
- маршрут `Browser -> Django -> Go engine -> transport -> target`;
- спільний `http.Transport` і `routeManager`;
- Repeater, Intruder, Target, OSINT і Scanner;
- перевірку маршруту через Tor Project API;
- автоматичний Source IP;
- passive HTTP/HTTPS MITM proxy на `127.0.0.1:8080`;
- lifecycle pending/complete Traffic events;
- потрапляння даних у Traffic і History;
- обмеження поточної реалізації та API endpoints.

У [README.md](./README.md) додано посилання на каталог функціональної
документації. Наступні великі функції слід описувати окремими файлами цієї
папки, не об'єднуючи різні функції в один документ.

## 2026-09-21 — створення повного комплекту документації функцій

На уточнений запит користувача створено окремий файл для кожної великої
функції проєкту:

- `povtoryuvach.md` — Repeater;
- `intruder.md` — Intruder;
- `karta-cili.md` — Target;
- `osint.md` — OSINT;
- `scanner-pro.md` — Scanner Pro;
- `porivniuvach.md` — Comparer;
- `dekoder.md` — Decoder;
- `tor-proksi.md` — Tor/Proxy workflow;
- `pasivnyi-trafik.md` — passive Traffic;
- `istoriia.md` — History;
- `ai-asystent.md` — AI Assistant;
- `robochi-prostory-sesii.md` — Workspaces і Session.

Разом із раніше створеним `прокси.md` папка `документация` тепер містить
окремі документи для всіх основних вкладок і мережевих функцій, визначених у
UI, Django URL map і Go engine. [README.md](./README.md) оновлено таблицею
навігації по всіх документах.

## 2026-09-21 — поглиблення документації за фактичним кодом

Після уточнення користувача короткі довідкові описи замінено на code-trace
документацію. Для Repeater, Intruder, Target, Passive Traffic, History та AI
додано:

- повні маршрути Browser → Django → Go → transport → target;
- конкретні handler-и та послідовність викликів;
- фактичні JSON payload і response/state fields;
- pending/completed lifecycle, polling, SSE та deduplication;
- зберігання у memory/SQLite/localStorage;
- явні помилки, binary encoding, cancel/pause і межі функцій;
- links на точні файли реалізації.

Такий самий рівень завершено для OSINT, Scanner, Comparer, Decoder, Tor/Proxy
operator workflow та Workspaces/Session. Для кожного з 13 файлів перевірено
локальні посилання на файли реалізації та відповідність опису фактичним
browser handlers, Django views і Go symbols. Мета документації — відтворити
фактичну поведінку коду, а не лише описати призначення вкладки.

Перевірено:

- 13 Markdown-файлів у `документация`;
- 2339 рядків code-trace документації;
- усі локальні посилання з документації існують;
- `git diff --check` пройшов без помилок;
- код застосунку не змінювався в межах цього documentation-only етапу.

## 2026-09-21 — повноекранне розгортання таблиці

Після перевірки UI виявлено, що збільшена висота таблиці виходила за межі
контейнера вкладки, тому нижня частина списку ставала невидимою.

Змінено [web/templates/lab/index.html](./web/templates/lab/index.html):

- додано повноекранний режим таблиці при перетягуванні роздільника до верхньої
  межі viewport;
- таблиця закріплюється під хедером і розтягується до нижнього краю екрана;
- усунуто проміжок між handle та таблицею, щоб під час розгортання не можна
  було натискати елементи навігації через щілину;
- у повноекранному режимі таблиця має власну вертикальну прокрутку;
- звичайний режим зміни висоти збережено;
- оброблено pointer capture так, щоб синтетичні та реальні pointer events не
  спричиняли помилки браузера.

Перевірено:

- повноекранний режим фактично додає клас `table-expanded`;
- таблиця займає область від верхньої межі під хедером до низу viewport;
- JavaScript syntax check, `git diff --check` і HTTP `200` для UI пройшли.

## 2026-09-21 — перенесення перевірки Source IP на Tor Project

На запит користувача джерело визначення IP змінено з ipify на Tor Project.

Змінено [engine/main.go](./engine/main.go):

- активні запити та passive proxy тепер визначають IP через
  `https://check.torproject.org/api/ip`;
- ручний `POST /route/check` використовує той самий endpoint;
- з відповіді використовується поле `IP`, а значення додатково перевіряється
  через `net.ParseIP`;
- таблиці History і Traffic продовжують отримувати те саме поле `source_ip`,
  але тепер воно походить із Tor Project API через поточний Direct або
  SOCKS5/Tor transport.

Змінено [README.md](./README.md):

- оновлено опис джерела IP;
- у списку ручних перевірок додано Tor Project API та прибрано ipify.

Змінено [web/templates/lab/index.html](./web/templates/lab/index.html):

- прибрано окреме посилання ipify з блоку ручних IP-перевірок, щоб не
  пропонувати інше джерело поруч із canonical Tor Project check.

Перевірено:

- `https://check.torproject.org/api/ip` повертає JSON з полями `IsTor` та `IP`;
- engine перезапущено через [run-engine.sh](./run-engine.sh);
- `POST /proxy/request` після перезапуску повернув непорожній `source_ip`,
  отриманий через новий Tor Project endpoint;
- `GET /health` повернув `{"ok":true}`, UI повернув HTTP `200`;
- `go test ./... -count=1` і `git diff --check` пройшли успішно.

## 2026-09-21 — створення журналу

- Створено цей файл як додатковий до Git журнал технічних дій.
- Зафіксовано попередній аналіз кодової бази, запуск локального режиму,
  відновлення колонок Intruder та автоматичне визначення Source IP.
- До [README.md](./README.md) додано посилання на цей журнал у розділі
  пов’язаних документів.

## 2026-09-21 — запуск і відновлення колонок Intruder

### Аналіз проєкту

- Переглянуто [AGENTS.md](./AGENTS.md), [README.md](./README.md) і ключові
  компоненти Go engine, Django gateway, моделей History та passive Store.
- Підтверджено архітектурний поділ: Django володіє browser-facing API та
  SQLite History, Go виконує outbound HTTP, Intruder, Target і passive MITM.
- Перевірено доступні API-маршрути, локальні порти, правила запуску,
  маршрутизацію Direct/SOCKS5/Tor і lifecycle Traffic через SSE.

### Запуск локального режиму

- Запущено [run-engine.sh](./run-engine.sh).
- Engine піднято на `127.0.0.1:8081`.
- Django UI піднято на `127.0.0.1:8000`.
- Passive proxy працює на `127.0.0.1:8080`.
- Створено або використано `web/.venv`, встановлено Python-залежності.
- Django migrations застосовано успішно.
- Перевірки:
  - `GET http://127.0.0.1:8081/health` повернув `{"ok":true}`.
  - `GET http://127.0.0.1:8000/` повернув HTTP `200`.
  - UI відкрито в локальному браузері.

### Відновлення Method і URL у таблиці Intruder

Причина: engine уже повертав у кожному результаті об’єкт `request` з полями
`method` і `url`, але UI таблиця їх не відображала.

Змінено [web/templates/lab/index.html](./web/templates/lab/index.html):

- додано колонки `Method` і `URL` до таблиці Intruder;
- збережено колонки `Payload`, `Status`, `Length`, `Time` та `Actions`;
- оновлено ширини `colgroup`;
- виправлено `colspan` для порожнього стану та virtualized spacer rows;
- фільтр Intruder розширено пошуком за методом і URL;
- CSV export уже містив method і URL, тому API експорту не змінювався.

Перевірки:

- inline JavaScript перевірено через `node --check`;
- `git diff --check` пройшов без помилок;
- UI після reload показав заголовки `# Method URL Payload Status Length Time
  Actions`.

## 2026-09-21 — автоматичний Source IP для History і Traffic

### Проблема

Поле `source_ip` існувало в моделі та UI History/Traffic, але для активних
запитів воно заповнювалося лише після ручної дії `Check connection`. Через це
Direct, SOCKS5/Tor, Repeater, Intruder і passive proxy не мали гарантовано
узгодженого значення.

### Реалізація

Змінено [engine/main.go](./engine/main.go):

- на попередньому етапі було помилково додано потокобезпечний кеш source IP;
- перед активним запитом engine автоматично виконує перевірку через
  `https://api.ipify.org?format=json` з поточним transport;
- через спільний transport перевіряється саме поточний Direct або SOCKS5/Tor
  маршрут;
- IP валідовується через `net.ParseIP`;
- після зміни маршруту наявний кеш очищається вже наявною логікою route manager;
- `source_ip` додано до результатів Repeater/Intruder;
- Repeater та Intruder Traffic events отримують source IP;
- для помилкових/неповних результатів збережено коректний fallback на кешоване
  значення.

### 2025-02-14 — виправлення кешування Source IP

Під час перевірки сценарію зі зміною Tor circuit виявлено, що `ensureSourceIP`
повертав попереднє значення з полів `server.sourceIP` і не звертався до
`check.torproject.org` повторно, доки маршрут не змінювався через UI. Це
порушувало вимогу бачити реальну адресу кожного нового вихідного exchange.

Виправлення:

- видалено process-wide стан кешу Source IP і no-op методи, що його імітували;
- `ensureSourceIP` виконує свіжий запит через поточний shared transport для
  кожної операції;
- fallback на старий IP після помилки нового lookup не використовується;
- Intruder Traffic більше не підставляє застаріле значення з кешу;
- додано тест із двома послідовними відповідями API (`198.51.100.10` і
  `198.51.100.11`), який перевіряє два окремі виклики endpoint;
- оновлено README та документацію Proxy/Tor із описом актуальної поведінки й
  latency/availability trade-off.

Змінені файли: `engine/main.go`, `engine/main_test.go`, `README.md`,
`документація/прокси.md`, `документація/tor-proksi.md`,
`DEVELOPMENT_LOG.md`.

Змінено [engine/pkg/passive/passive.go](./engine/pkg/passive/passive.go):

- passive proxy отримав callback визначення source IP;
- кожен proxy event записує source IP до публікації pending event.

Змінено [web/lab/views.py](./web/lab/views.py):

- Repeater зберігає `result["source_ip"]` у `TrafficRecord`.

Змінено [README.md](./README.md):

- документовано автоматичне визначення source IP перед активними та passive
  запитами.

### Перевірки

- `cd engine && gofmt -w main.go pkg/passive/passive.go`
- `cd engine && go test ./... -count=1` — успішно.
- `cd web && python manage.py check` — успішно.
- `git diff --check` — успішно.

## 2026-09-21 — перевірка цілісності маршруту Direct/SOCKS5/Tor

### Причина

Під час security-аудиту Tor/Proxy потрібно було підтвердити, що DNS-запити
OSINT не обходять активний маршрут, а конкурентний запит не використовує
старе keep-alive-з'єднання після зміни route.

### Реалізація

Змінено [engine/routing.go](./engine/routing.go):

- route manager створює окремий `http.Transport` для кожного покоління
  конфігурації маршруту;
- після зміни Direct/SOCKS5 старий transport закриває idle-з'єднання;
- route-aware `net.Resolver` передає DNS-запити через поточний dialer;
- для SOCKS5 DNS використовується TCP-шлях через налаштований проксі, а не
  системний UDP resolver;
- round tripper вибирає transport актуального покоління для кожного запиту.

Змінено [engine/main.go](./engine/main.go):

- OSINT використовує resolver і transport поточного route manager;
- активні запити, route check і визначення source IP використовують актуальний
  transport;
- прихований fallback із SOCKS5 у Direct не доданий: помилка dial повертається
  як помилка запиту;
- TLS certificate validation не відключається.

Змінено [engine/main_test.go](./engine/main_test.go):

- додано тест, який перевіряє виклик налаштованого route dialer під час DNS
  lookup;
- додано тест перемикання route, створення нового transport і закриття
  старого idle-з'єднання;
- збережено перевірки свіжого source IP для послідовних запитів.

### Перевірки

- `cd engine && go test ./... -count=1` — успішно.
- `cd engine && go test -race ./... -count=1` — успішно.
- `git diff --check` — успішно.

UI та інші зміни, не пов'язані з цим виправленням маршрутизації, у межах
цього етапу не змінювалися й не відкатувалися.
- Engine Repeater API повернув непорожній `source_ip`.
- Django Repeater API повернув непорожній `source_ip`.
- History API зберіг source IP у записі Repeater.
- Traffic API показав source IP у live exchange.
- У перевіреному Direct-маршруті engine повернув зовнішню адресу
  `149.88.27.132`; значення наведено лише як результат тесту, а не як
  конфігураційний секрет.

### Поточний стан після зміни

- Проєкт перезапущено через [run-engine.sh](./run-engine.sh).
- UI доступний на `http://127.0.0.1:8000/`.
- Engine health доступний на `http://127.0.0.1:8081/health`.
- Активний маршрут — Direct.
- У startup output Django повідомив, що в моделях є зміни без нової міграції.
  Ця сесія не змінювала моделі Django, тому нову міграцію навмисно не
  створювали; ситуацію потрібно перевірити окремо перед наступною зміною
  моделей.

## 2026-09-21 — збільшення кількості видимих рядків у таблицях

### Проблема

При масштабі браузера 90% у таблицях Intruder, Target, History і Traffic було
видно лише приблизно один-два рядки. Причиною були великі вертикальні резерви:
інспектори запиту/відповіді займали значну частину viewport, а Target
резервував до `52vh` під preview.

### Зміни

Змінено [web/templates/lab/index.html](./web/templates/lab/index.html):

- для History і Traffic зменшено висоту інспекторів до компактного preview;
- для Intruder зменшено інспектори та збільшено допустиму висоту таблиці;
- для Target зменшено висоту preview до `min(300px, 36vh)`, щоб таблиця
  отримувала більше простору;
- висоту робочих областей History, Traffic, Intruder і Target скориговано під
  viewport;
- інспектори History, Traffic та Intruder залишено у двох колонках навіть у
  вузькому responsive-режимі, щоб вони не складалися вертикально та не
  приховували таблицю.

Поведінка, сортування, фільтри, virtualized rendering і прокрутка таблиць не
змінювалися.

Перевірено:

- inline JavaScript через `node --check`;
- `git diff --check`;
- локальний UI відкривається з HTTP `200`;
- у DOM таблиці Target та заголовки всіх змінених секцій присутні після
  перезавантаження.

## 2026-09-21 — баланс висоти інспекторів і таблиць

Після попереднього збільшення таблиць інспектори request/response стали
занадто малими для комфортного читання. В [web/templates/lab/index.html](./web/templates/lab/index.html)
їхню висоту збільшено з `min-height:90px; max-height:16vh` до
`min-height:150px; max-height:24vh` для History, Traffic та Intruder.

Інспектори залишаються у двох колонках, а таблиці зберігають власну прокрутку.
Таким чином збережено компроміс між читабельністю повного exchange та
кількістю видимих рядків.

Перевірено:

- inline JavaScript через `node --check`;
- `git diff --check`;
- UI після reload доступний з HTTP `200`.

## 2026-09-21 — повернення початкового layout

На запит користувача скасовано останні зміни, що змінювали висоту таблиць,
preview Target та інспекторів request/response. [web/templates/lab/index.html](./web/templates/lab/index.html)
повернуто до початкових значень layout:

- History і Traffic: `height:calc(100vh - 92px)`;
- Intruder: `max-height:42vh`;
- Target preview: `min(430px,52vh)`;
- стандартні responsive-правила інспекторів відновлено.

Попередні функціональні зміни (колонки Intruder, автоматичний Source IP через
Tor Project API та цей журнал) не скасовувалися.

## 2026-09-21 — збільшення тільки області таблиць

Уточнений запит вимагав показувати більше рядків в Intruder, Target, History і
Traffic, не змінюючи верхні блоки з кнопками, пошуком, сортуванням та
інспекторами.

Змінено лише CSS-контейнери таблиць у
[web/templates/lab/index.html](./web/templates/lab/index.html):

- Intruder: `.exchange-list` має `height:58vh` і власну прокрутку;
- Target: `.exchange-list` має `height:48vh` і власну прокрутку;
- History і Traffic: `.exchange-list` мають `height:48vh` і власну прокрутку;
- висота и позиції верхніх toolbar, search, sort та inspector не змінювалися;
- `overflow:visible` на вкладках використовується лише для того, щоб
  збільшений table container не обрізався батьківським viewport.

Перевірено:

- inline JavaScript через `node --check`;
- `git diff --check`;
- UI завантажується з HTTP `200`;
- таблиці залишаються окремими прокручуваними областями.

## 2026-09-21 — інтерактивний розмір таблиць

На запит користувача додано вертикальний інтерактивний роздільник над
таблицями Intruder, Target, History і Traffic.

Змінено [web/templates/lab/index.html](./web/templates/lab/index.html):

- кожен `.exchange-list` отримує handle `.table-resizer`;
- висота змінюється перетягуванням handle вгору або вниз;
- верхні toolbar, кнопки, пошук, сортування та інспектори не змінюються;
- таблиця має мінімальну висоту `180px` і може бути розтягнута до `100vh`,
  щоб показати максимально великий список;
- якщо роздільник перетягнути до верхньої межі вікна, таблиця переходить у
  повноекранний режим під хедером і займає простір до нижнього краю viewport;
- таблиця зберігає власну прокрутку;
- вибрана висота зберігається в `localStorage` для кожної таблиці;
- підтримуються pointer events, тому handle працює мишею та на touch-пристроях;
- додано ARIA role `separator` та горизонтальну орієнтацію для доступності.

Перевірено:

- inline JavaScript через `node --check`;
- `git diff --check`;
- UI завантажується з HTTP `200`;
- handle створюється окремо перед кожним контейнером `.exchange-list`.

## Подальші записи

## 2026-09-21 — нормалізація порожніх станів Scanner і Comparer

Змінено [web/templates/lab/index.html](./web/templates/lab/index.html):

- під час відновлення робочого простору Scanner збережені український та
  англійський варіанти порожнього стану нормалізуються до поточної мови;
- під час відновлення Comparer так само нормалізується порожній результат;
- додано локалізацію підписів дій Target, назв робочих просторів та їхніх
  ARIA-підписів;
- після зміни мови робочі простори перемальовуються без повернення тексту
  попередньої локалі.

Перевірено:

- inline JavaScript через `node --check`;
- `python manage.py check`;
- `git diff --check`;
- живий браузер: Scanner і Comparer перемикаються між українською та
  англійською без змішаних порожніх станів і помилок консолі.

Усі наступні зміни, виправлення, запуски, перевірки та відомі обмеження
додавати в цей файл із датою, короткою назвою, переліком файлів і результатами
валідації. Не редагувати попередні записи заднім числом, окрім виправлення
фактичної помилки з явним поясненням.
