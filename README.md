<img width="2912" height="1440" alt="Gemini_Generated_Image_s92k5ts92k5ts92k" src="https://github.com/user-attachments/assets/94771d81-1972-418f-ba69-71e64743a44a" />

# RequestRider

RequestRider — локальний інструмент для ручного QA, аналізу HTTP-трафіку та
дозволеного тестування власних систем. Проєкт об’єднує Django UI, Go engine,
SQLite History, passive MITM proxy і явний маршрут Direct або SOCKS5/Tor.

> Використовуйте інструмент лише проти систем, якими ви володієте або на
> тестування яких маєте явний дозвіл. Tor, VPN, Docker і віртуальна машина не
> роблять несанкціоноване тестування дозволеним.

## Зміст

- [Архітектура](#архітектура)
- [Можливості](#можливості)
- [Швидкий локальний запуск](#швидкий-локальний-запуск)
- [Docker Compose](#docker-compose)
- [Маршрутизація через Direct або SOCKS5/Tor](#маршрутизація-через-direct-або-socks5tor)
- [Passive MITM і локальний CA](#passive-mitm-і-локальний-ca)
- [Основний workflow](#основний-workflow)
- [API](#api)
- [Перевірка та діагностика](#перевірка-та-діагностика)
- [Безпека](#безпека)
- [Документація функцій](#документація-функцій)
- [Пов’язані документи](#повязані-документи)

## Актуальний стан проєкту

Станом на 2026-09-22 основні пункти поточного roadmap реалізовані та
перевірені targeted/regression-тестами й живим браузером:

- Projects: створення, редагування, вибір і каскадне видалення пов'язаних
  History, Traffic, Intruder та Target записів;
- session metadata, schema versioning і IndexedDB для великих workspace
  snapshots;
- єдиний Django `EngineClient`, стабільні engine errors і malformed-response
  handling;
- ARIA tabs, accessible prompt/confirm dialogs та keyboard smoke coverage;
- static і browser-driven Target із fixtures, form confirmation, network
  evidence і exports;
- Scanner profiles із read-only checks;
- повна двомовна UI-локалізація Ukrainian/English для статичних, динамічних,
  збережених і відновлених станів Scanner, Intruder, Proxy, Repeater,
  Target і Comparer.

Перелік виконаних елементів зберігається в [ROADMAP.md](./ROADMAP.md), а
детальні зміни та результати перевірок — у
[DEVELOPMENT_LOG.md](./DEVELOPMENT_LOG.md). Нові завдання виконуються лише
за ітераційним алгоритмом з [AGENTS.md](./AGENTS.md): одне завдання,
повний набір застосовних тестів, browser smoke-test для UI і лише потім
наступний пункт.

## Архітектура

### Локальний режим

```text
Browser :8000
    -> Django web gateway + SQLite History
    -> Go engine :8081
         -> outbound HTTP execution
         -> Intruder / Target / OSINT / Scanner
         -> passive MITM proxy :8080
         -> Direct або SOCKS5/Tor
     -> AI provider transport (окремий cancelable backend socket)
```

### Docker Compose

```text
Browser :8000
    -> web container
         -> engine:8081
              -> tor:9050
              -> passive proxy :8080
```

`web` відповідає за UI, workspace і browser-facing API. `engine` виконує
HTTP-операції, Intruder, Target, OSINT, Scanner і passive capture; AI provider
socket залишається backend-операцією з окремим cancelable transport. `tor` —
окремий SOCKS5 upstream у Compose-мережі. SQLite зберігається у web-контейнері
та залежить від його filesystem/volume-конфігурації.

Локальні сервіси за замовчуванням використовують loopback:

```text
127.0.0.1:8000  Django UI
127.0.0.1:8080  passive HTTP MITM proxy
127.0.0.1:8081  Go engine API
127.0.0.1:9050  локальний SOCKS5 Tor
```

Не запускайте локальний і Docker-режим одночасно: вони використовують однакові
порти. У Docker web передає browser-worker `PASSIVE_PROXY_URL=http://engine:8080`,
а локально за замовчуванням використовується `http://127.0.0.1:8080`.

### Структура репозиторію

У корені лежить лише те, що потрібно для роботи застосунку. Обслуговуючі
агента файли (зовнішні тести, fixtures, бібліотека skills) винесені в
`agent-workspace/`, а конфіг OpenCode лишається в корені — саме звідти OpenCode
його читає.

```text
Request-Rider/
├── web/                  Django UI + gateway (Python 3.12, Django 5)
├── engine/               Go engine, passive proxy, Intruder/Target/Scanner
├── browser-worker/       Python + Playwright headless Firefox worker
├── data/                 локальний CA, OSINT-експорти (gitignored)
├── tor/                  SOCKS5-контейнер
├── bin/                  runtime-бінарники, зокрема nuclei (gitignored)
├── документация/         довідники окремих інструментів
├── .opencode/            OpenCode: встановлені skills + skills-assets
├── opencode.json         OpenCode permission.skill
├── AGENTS.md             правила роботи агента в цьому репозиторії
├── agent-workspace/      тести й обслуговуючі скрипти, не потрібні для запуску
│   ├── SKILLS-AI-MD/     бібліотека SKILL.md (джерело для .opencode/skills)
│   ├── tests/e2e/        live Firefox сценарії Automation UI
│   └── tools/            fixtures, smoke, loadtest, інсталятор skills
└── run-engine.sh, docker-compose.yml, Dockerfile, *.md
```

Деталі `agent-workspace/` — у його власному
[README.md](./agent-workspace/README.md).

## Можливості

- **Repeater** — raw HTTP editor, повторне надсилання, перегляд відповіді,
  збереження exchange у History.
- **Intruder** — Sniper, Battering Ram, Pitchfork, Cluster Bomb, dictionaries,
  transformations, parallel workers, pause/resume/cancel, polling,
  JSON/CSV export і review summary перед запуском із target, route,
  delay/concurrency та оцінкою jobs. Великі словники редагуються у textarea
  без inline preview, щоб не розтягувати панель.
- **Target** — асинхронна статична карта сайту та окремий browser-driven режим
  із вибором Firefox, Chromium, Chrome, Edge або WebKit для JS-rendered маршрутів
  і network evidence; обидва режими мають
  pages/depth/delay, same-origin, cancel і JSON/CSV/HTML export. Browser-driven
  режим передається через локальний generation-aware passive proxy, тому browser
  exchanges мають той самий Direct/SOCKS5/Tor route і `source_ip`, що й Repeater.
  Його network
  evidence можна відфільтрувати за API/XHR/fetch, документами, скриптами або
  іншими ресурсами та передати endpoint у Repeater, Intruder чи Scanner.
  Для SPA можна додати послідовність `click`/`fill` actions за CSS-селекторами,
  а `Compare static/browser` показує URL, які знайдені лише одним із режимів.
  Navigation mode виконує лише read-only навігацію. Form mode вимагає
  щонайменше одну `click` або `fill` action і окреме підтвердження перед
  запуском, оскільки такі дії можуть змінювати стан цілі. Для повторюваних
  локальних перевірок доступний fixture-сервер:
  `python agent-workspace/tools/target_fixture.py`.
  Browser crawl використовує паралельні вкладки, не додає
  штучної затримки за замовчуванням і блокує image/font/media ресурси; `Delay
  ms` можна збільшити вручну для обережнішого темпу.

Target не використовує `robots.txt` як обмеження доступу: `Allow`/`Disallow`
є рекомендаціями для пошукових роботів, а не механізмом авторизації. Static
crawler читає з `robots.txt` лише `Sitemap:`-посилання; browser-driven режим
не застосовує robots directives. Використовуйте це лише для дозволених цілей.
- **OSINT** — DNS/IP, MX/NS/TXT, HTTP metadata, redirects, technologies,
  cookies, security headers, robots/sitemap і пасивні WAF-сигнали; окремий
  project-scoped Entity Graph canvas показує durable entities/relations,
  details drawer, filters, deterministic layout і explicit transforms.
  Зовнішні джерела не обвалюють transform: `subdomains` опитує **п'ять
  паралельних індексів Certificate Transparency** (crt.sh, crt.name,
  certspotter, shodan-ctl, ctlogs.dev) і зливає їхні відповіді, тому недоступність
  crt.sh не зупиняє розвідку, а `wayback_urls` читає два індекси Internet
  Archive (CDX → timemap) потоково, зберігаючи вже прочитані рядки, якщо архів
  обриває відповідь. Частковий результат позначається явно — у warnings і в
  metadata (`cert_indexes`, `archive_*`). Опціональні ключі до індексів
  (`CERTSPOTTER_API_TOKEN`, `CTLOGS_API_KEY`) читаються лише з оточення.
  Архівні URL канонізуються: credentials, fragments, default ports і
  traversal-шляхи не стають ідентифікаторами графа. Transform виконується як
  **background-job** з кнопками **Pause / Continue / Cancel** і живими
  лічильниками прогресу; результат понад 2000 рядків записується **повністю**
  у CSV/JSONL файл, який відкривається в новій вкладці або завантажується, а
  граф зберігає одну entity-вказівку — жоден рядок не відкидається.

  **Хост, а не зона.** CT-індекси індексовані за зоною: запит
  `crt.name?apex=www.lafann.ru` повертає `400 not an apex`, а індекси, які
  запит приймають, відповідають самим хостом. Тому `subdomains` на
  subdomain-вході будує ланцюг зон (`www.lafann.ru` → `lafann.ru`), запитує
  кожну власним запитом і зупиняється на першій, що дала нові імена; публічний
  суфікс запитом не йде. Підміна **проголошується**: імена стають `subdomain`
  саме цієї зони, зона й запитаний хост лишаються окремими `domain`-сутностями,
  а `warnings` і `metadata.cert_zone` / `cert_input` / `cert_zones_queried`
  показують, що саме запитано (в UI — чіп `zone: <host>`). Відмова індексу
  (`4xx`) не повторюється, на відміну від тимчасового `5xx`/`429`.

  **Керування існуючими entities.** Обраний entity (клік по вузлу) або relation
  (клік по ребру) відкриває drawer з деталями та діями: `Edit`, `Delete entity`,
  `Run transform on this value`, `Copy value`, `Use in OSINT checks`, а для
  relation — `Delete relation` і перехід до його endpoint entities. Ті самі дії
  `Edit` / `Delete entity` доступні з контекстного меню (ПКМ по вузлу).
  Кнопка `Clear graph` очищає entities і relations поточного графа після
  підтвердження, і контейнер графа лишається — новий entity можна додати
  одразу після очищення. Усі операції CSRF-protected і суворо scoped до
  власного `graph_id`: entity чи relation з іншого графа дає `404`.

  **Статус transform.** Кожен запуск показує явний стан замість порожнього
  результату: `running` (з таймером, що відлічує секунди), `completed`,
  `empty` (transform завершився, але нічого не знайшов) або `failed` (з
  текстом помилки движка). Панель показує `local only` / `network`, тривалість у
  мс і список warnings. `transform_result.status`, `stored_entity_count`,
  `stored_relation_count`, `rejected_count`, `rejected[]` і `duration_ms`
  приходять у відповіді API.

  **Часткові результати.** Зовнішні адаптери legitимно повертають identities,
  які граф не може зберігти (наприклад certificate wildcard `*.*.example.com`
  або label з підкресленням `_dmarc.example.com`). Під час ingestion transform
  такі рядки **відкидаються поодинці** і перелічуються в `rejected` та warnings,
  а не знищують весь batch: `subdomains` для великого домену міг знайти 1308
  entities і втратити всі через одну wildcard-identity. Ручний
  `/api/osint/graphs/<id>/upsert` лишається атомарним, щоб помилка введення
  залишалася явною.
- **Scanner Pro** — read-only перевірки CMS/public paths, TLS,
  cookies, methods, headers і configuration exposure signals. Завантажені
  Nuclei-шаблони виконуються справжнім бінарником одним batch-запуском, а
  звіт показує **результат по кожному YAML-файлу**: назва файлу, template id,
  CVE/CWE, статус `matched` / `not_matched` / `invalid` і причину для
  відхиленого файлу. Одне вікно завантаження приймає файли або цілу папку
  (drag & drop з обходом каталогів), великі папки йдуть чанками, панель
  `Scan options` замінює інтерактивні прапорці nuclei. Вкладка має дві
  внутрішні сторінки — **CMS scan** і **Nuclei scan** — з окремим результатом
  та окремим експортом на кожну. Експорт — меню `Export ▾` з форматами
  JSON / CSV і **інтерактивним HTML-звітом у фірмовому стилі** (живий пошук,
  фільтри статусу, сортування; самодостатний, без зовнішніх ресурсів).
- **Comparer** — Words і Bytes.
- **Decoder** — URL, Base64, Base64 URL-safe, HTML, Hex, byte, JSON і SHA-256.
- **Traffic** — live SSE-потік passive proxy, Repeater і Intruder.
- **History** — SQLite-записи завершених exchange, tags/notes, export/import.
- **AI** — аналіз лише явно прикріплених оператором evidence; автономного
  виконання дій немає.
- **Automation** — візуальний редактор workflow із canvas, вузлами Repeater,
  Target, OSINT, Scanner, Intruder, Decoder, Comparer, AI, умовами, розкладом і
  webhook-тригерами; workflow зберігається в SQLite разом із Project.
  Поточний runtime process-local: scheduler, webhook activation, pause/resume,
  SSE-події та export/import працюють у межах одного Django-процесу; Redis/Celery,
  distributed queue і multi-main HA поки не реалізовані. Active URL-вузли
  використовують URL, переданий оператором, а Intruder і browser actions вимагають
  explicit confirmation; `Repeater Burst` додатково є manual-only і не може
  входити до schedule/webhook graph.
  У вкладках інструментів доступна кнопка `Send to Automation`: вона читає
  поточний workspace, додає або оновлює відповідний типовий вузол, зберігає
  workflow і перемикає на Automation. В inspector можна також використати
  `Use current workspace`, відкрити вузол у відповідному інструменті та
  редагувати типові поля (Repeater method/URL/headers/body, Target parameters,
  Intruder mode/dictionaries/transformations, Decoder/Comparer operations тощо).
  API-каталог `/api/workflows/node-types` повертає ці поля разом із defaults,
  тому canvas не залежить від окремого списку параметрів. У toolbar Automation
   доступний `Template Store`: локальний каталог `/api/workflow-templates` із
   категоріями, preview, required variables та import у новий canvas. Import
   сам по собі не створює активний job і не запускає граф; workflow зберігається
   лише після окремого `Save`. `Save as template` зберігає лише граф і
   metadata у browser-local catalog, не змішуючи їх із workflow snapshot.
   Template Store також містить baseline-пакет із read-only reconnaissance,
   API headers, schema endpoint discovery, asset inventory та advisory AI
   triage playbooks, а також manual-only high-risk canary templates для
   BOLA/IDOR differential, race timing, WAF rules, synthetic JWT claims,
   XXE → local OAST та read-only CI/CD exposure review. Це не реальні
   credential/authorization attacks: payloads, tokens і callbacks можуть
   бути лише local fixture canary, а кожен active template має explicit
   confirmation перед запуском.
   Automation також має окремий `Repeater Burst` для manual, parallel
   review: Django передає user-controlled iterations/concurrency/delay/timeout,
   Go виконує job із cancellation, TLS verification та History persistence.
   Burst заборонений у schedule/webhook graphs і не є raw Last-Byte sync.
   `Last-Byte Sync` — окремий manual-only raw HTTP/1.1 POST/PUT/PATCH job:
   Go надсилає всі bytes крім фінального, утримує останній byte за явним
   hold, перевіряє TLS certificate chain і не використовує redirects або
   automatic retries.
   Automation також має `OAST Listener` → payload URL → `OAST Collect`
   contract; provider endpoint і timeout задаються користувачем.
- **Workspace** — окремі вкладки інструментів, autosave і session JSON.

Scanner та інші активні інструменти не замінюють дозвіл на тестування і не
призначені для реального exploit, brute force, fuzzing або access-control bypass.
High-risk Automation templates — це лише local/synthetic canary
scenarios з explicit confirmation; вони не містять реальних credentials,
external OAST providers або автоматичного destructive action.

## Швидкий локальний запуск

Потрібні Go, Python 3, `curl` і `venv` або `virtualenv`.

Із кореня репозиторію:

```bash
./run-engine.sh
```

Для browser-driven Target цей скрипт також запускає локальний
Firefox/Playwright worker на `127.0.0.1:8090`. Перший запуск встановлює
Playwright і керований Playwright Firefox у `browser-worker/.venv`; наступні запуски використовують
збережене середовище.

Скрипт:

1. запускає Go engine, якщо `/health` ще недоступний;
2. створює `web/.venv` і встановлює Python-залежності;
3. застосовує Django migrations;
4. запускає UI на `127.0.0.1:8000`.

Перевірка:

```bash
curl http://127.0.0.1:8081/health
curl -I http://127.0.0.1:8000/
```

Очікувано:

```json
{"ok":true}
```

Якщо engine або UI вже працюють, не запускайте другий екземпляр. Для
нестандартного CA або engine:

```bash
CA_DIR=/path/to/ca ./run-engine.sh
ENGINE_URL=http://127.0.0.1:8081 ./run-engine.sh
```

### Ручний запуск компонентів

Термінал 1:

```bash
cd engine
go run .
```

Термінал 2:

```bash
cd web
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
ENGINE_URL=http://127.0.0.1:8081 python manage.py runserver 127.0.0.1:8000
```

Локальний `runserver` працює через WSGI та не підтримує WebSocket project live
stream. UI спочатку перевіряє `GET /api/project-events/status`; при відповіді
`{"websocket": false}` він не створює помилкове з’єднання. Для ASGI-розгортання
через `core.asgi` endpoint повертає `true`, і live project events залишаються
доступними.

## Docker Compose

Переконайтеся, що Docker daemon доступний:

```bash
docker ps
```

Якщо користувач щойно доданий до групи `docker`, застосуйте нову групу без
перезавантаження:

```bash
newgrp docker
```

Збірка і запуск:

```bash
docker compose build
docker compose up -d
docker compose ps
```

Compose створює три сервіси:

| Сервіс | Роль | Внутрішня адреса |
|---|---|---|
| `tor` | SOCKS5 Tor upstream | `tor:9050` |
| `engine` | Go API і passive proxy | `engine:8081`, `engine:8080` |
| `web` | Django UI і gateway | `web:8000` |

У `docker-compose.yml` engine отримує:

```text
ROUTE_ADDRESS=tor:9050
PROXY_LISTEN_ADDR=0.0.0.0:8080
ENGINE_LISTEN_ADDR=0.0.0.0:8081
```

`0.0.0.0` тут потрібен лише всередині контейнера, щоб Docker network могла
доставити трафік до сервісу. На host порти публікуються тільки на
`127.0.0.1`.

Перевірка:

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/route
docker compose logs --no-color tor
```

У логах Tor має з’явитися:

```text
Bootstrapped 100% (done)
```

Зупинка:

```bash
docker compose stop
```

Видалення контейнерів і мережі:

```bash
docker compose down
```

Видалення образів цього Compose-проєкту:

```bash
docker compose down --rmi all
```

Не використовуйте `docker system prune`, якщо не хочете видалити ресурси
інших проєктів.

## Маршрутизація через SOCKS5/Tor

Маршрут налаштовується у вкладці **Tor/Proxy**.

- Порожня адреса — **Direct**.
- `127.0.0.1:9050` — локальний Tor при локальному запуску.
- `tor:9050` — Tor-контейнер для engine у Docker Compose.
- Будь-який інший доступний SOCKS5 `host:port` — віддалений або локальний
  SOCKS5-проксі.

Після введення адреси натисніть **Apply route**. **Cancel route** очищає
адресу і повертає Direct. Обидві дії виконують route-generation drain:
скасовують активні Repeater/Intruder/Target/OSINT/Scanner/Burst/Last-Byte/OAST,
AI та workflow-операції старого покоління, закривають browser-worker jobs
і не допускають змішування старого та нового маршруту. **Check connection**
перевіряє ціль, latency, HTTP status, зовнішню IP-адресу через
`https://check.torproject.org/api/ip` і показує `IsTor`; типове поле перевірки
за замовчуванням — `https://check.torproject.org/`.

Для ручної перевірки у браузері можна використовувати:

| Сервіс | URL | Призначення |
|---|---|---|
| Tor Project | <https://check.torproject.org/> | Перевірка, чи визначається браузер як підключений через Tor |
| Tor Project API | <https://check.torproject.org/api/ip> | JSON із зовнішньою IP та прапорцем `IsTor` |
| ifconfig.me | <https://ifconfig.me/ip> | Зовнішня IP у plain text |
| icanhazip | <https://icanhazip.com/> | Зовнішня IP у plain text |
| ipinfo.io | <https://ipinfo.io/json> | IP та базова інформація у JSON |

Щоб ручна перевірка показувала Tor-маршрут, браузер має використовувати
`127.0.0.1:8080` як HTTP/HTTPS proxy для RequestRider або `127.0.0.1:9050`
як SOCKS5. Посилання в UI саме по собі не змінює маршрут браузера. Не
надсилайте через сторонні IP-сервіси секретні дані й враховуйте, що кожен
сервіс бачить IP-адресу та час запиту.

### Як проходить трафік

Для активних інструментів:

```text
Repeater / Intruder / Target / OSINT / Scanner
    -> Go engine transport
    -> Direct або SOCKS5/Tor
    -> target
```

Для браузерного трафіку:

```text
Browser
    -> HTTP proxy 127.0.0.1:8080
    -> passive MITM
    -> той самий outbound transport
    -> Direct або SOCKS5/Tor
    -> target
```

Repeater, Intruder, static Target, OSINT і Scanner не проходять повторно через
`:8080`; вони використовують той самий route manager без подвійного MITM.
Browser-driven Target навпаки свідомо проходить через локальний passive proxy,
щоб network evidence мали route generation і `source_ip`. Усі події публікуються
у спільний Traffic Store.

У Docker engine не може використовувати `127.0.0.1:9050` для Tor-контейнера:
це loopback самого engine-контейнера. Використовуйте саме `tor:9050`.

Source IP metadata запускає **один свіжий lookup для кожного логічного outbound
exchange** через `https://check.torproject.org/api/ip` і той самий активний
Direct/SOCKS5 route. Process-wide кеш відсутній: наступний exchange бачить
нову IP-адресу, навіть якщо API змінюється щосекунди; помилка lookup дає
порожнє значення, але ніколи не повертає старий IP. Для довгих job і passive
browser traffic lookup не витрачає budget цільового запиту; поки lookup не
завершився, результат має явний `source_ip_pending`, а Traffic/History row
backfill-иться після свіжого значення. Значення потрапляє в
повний Traffic/History evidence для Repeater, Intruder, Burst, Last-Byte,
passive proxy та route check; уже збережені historical rows не переписуються
після наступного route switch. Якщо SOCKS5 недоступний, outbound-запит має
завершитися явною помилкою, а не непомітним fallback у Direct.

## Passive MITM і локальний CA

Engine автоматично створює:

```text
data/ca/ca.crt
data/ca/ca.key
```

Для HTTPS імпортуйте `data/ca/ca.crt` лише в окремий тестовий профіль
браузера. `data/ca/ca.key` — приватний ключ і не повинен потрапляти до Git,
логів або сторонніх систем.

Налаштування браузера:

```text
HTTP proxy:  127.0.0.1
HTTP port:   8080
HTTPS proxy:  127.0.0.1
HTTPS port:  8080
```

Traffic є in-memory Store engine. Pending exchange спочатку показується зі
статусом `pending`, після відповіді оновлюється тим самим ID. Перезапуск engine
або очищення Traffic видаляє незбережені live events. **Save row** переносить
вибраний exchange у Django History/SQLite.

Системні запити браузера, наприклад Firefox Push Service, можуть потрапляти у
Traffic. Це не обов’язково трафік тестованого сайту; використовуйте окремий
профіль браузера і не відкривайте особисті сесії через MITM.

## Основний workflow

1. Визначте письмовий scope і дозвіл на тестування.
2. Запустіть локальний або Docker Compose режим, але не обидва одночасно.
3. Перевірте `/health`, активний route і зовнішню IP.
4. Якщо потрібен браузерний Traffic, імпортуйте CA в тестовий профіль і
   встановіть proxy `127.0.0.1:8080`.
5. Почніть із Repeater, потім використовуйте Target/OSINT/Scanner для
   read-only аналізу.
6. Для Intruder задайте мінімальні dictionaries, concurrency і delay.
7. Зберігайте лише потрібні записи, очищайте cookies, tokens і exports після
   завершення.
8. Для повторюваної автоматизації відкрийте `Automation`, зберіть workflow з
   trigger-вузлом і інструментами, збережіть його в активному Project та запускайте
   вручну або активуйте webhook/розклад.
9. Щоб перенести вже налаштований інструмент, заповніть його вкладку та
   натисніть `Send to Automation`; після переходу перевірте вибраний вузол у
   canvas і за потреби скористайтеся `Open in tool` або `Use current workspace`.

## API

### Django gateway

| Method | Endpoint | Призначення |
|---|---|---|
| `GET` | `/` | UI |
| `POST` | `/api/execute` | Repeater |
| `POST` | `/api/intruder` | Запуск Intruder |
| `GET` | `/api/intruder?attack_id=<id>` | Статус і результати |
| `DELETE` | `/api/intruder?attack_id=<id>` | Cancel Intruder |
| `GET/POST` | `/api/intruder/saved` | Saved configurations |
| `POST` | `/api/target-map` | Target map |
| `GET/DELETE` | `/api/target-map?map_id=<id>` | Статус або cancel |
| `POST` | `/api/target-browser` | Запуск browser-driven Target |
| `GET/DELETE` | `/api/target-browser?job_id=<id>` | Статус або cancel browser job |
| `GET/POST` | `/api/projects` | Список або створення Project/workspace |
| `GET/PATCH/DELETE` | `/api/projects/<id>` | Перегляд, зміна або видалення Project |
| `POST` | `/api/project-context` | Встановлення або очищення server-backed active Project |
| `GET` | `/api/project-events/status` | Capability live project WebSocket для WSGI/ASGI |

Вкладка `Projects` містить окреме меню керування workspace: вибір активного
Project, створення, редагування назви, target, environment і route profile,
а також видалення через підтвердження. Видалення Project є каскадним:
пов’язані History, Intruder, Target jobs і Workflows
також видаляються. Операція незворотна. У шапці залишається лише індикатор активного
Project.

Активний Project зберігається у валідованому Django session і встановлюється
лише через CSRF-protected `POST /api/project-context`. `?project_id` ігнорується,
а `localStorage` залишається лише browser mirror; reload читає server value.
Middleware надає `request.active_project`, очищає deleted/invalid ID і не робить
цей session context authorization boundary для shared/multi-user deployment.

`POST`/`PATCH /api/projects` зберігають `scope_in` та `scope_out` як legacy
metadata, але вони не є execution policy і не блокують інструменти. active
workflow tools використовують URL, переданий оператором.

`Project` приймає необмежені `tech_stack` та `notes`. `ProjectSecret` не має
окремого plaintext `value`; зберігаються лише type, key name, reference та
source metadata. `ProjectContextBuilder` формує project-scoped Markdown/AI
context із endpoints, Workflows, TargetJobs і secret references, але без raw
headers/bodies, query credentials, cookies чи secret values. Детальний контракт
— у [`документация/project-hub.md`](./документация/project-hub.md). AI Assistant
додає цей context лише за one-shot checkbox активного Project; після запиту
consent скидається, а відсутність active Project повертає explicit error.

Passive Traffic має явний `TrafficCaptureContext`: оператор вказує
`project_id` або `null`, а сервер підставляє opaque token у browser-driven Target
через `X-RequestRider-Capture-Context` лише через local proxy route. Token не
повертається browser API; proxy не пересилає цей internal header upstream;
Django класифікує evidence як `in_scope`, `out_of_scope`, `unscoped` або
`invalid_context`. Out-of-scope exchange зберігається і не видаляється. Token
не є authorization credential і не замінює shared-mode auth/ACL.

| `POST` | `/api/osint` | OSINT |
OSINT transforms є explicit: network adapters запускаються лише з
`confirm_network=true`, а їхні результати не обмежуються application
count/body budget. Output redact-иться і upsert-иться у вибраний graph. Жоден
transform не запускається неявно з passive OSINT discovery.

У OSINT workspace граф створюється й редагується через CSRF-protected API.
Local native SVG canvas не має CDN/third-party runtime: selection, details,
right-click transform menu, filter, grid/radial auto-layout і повне
відображення graph. 500+ node Firefox smoke, persistence після reload,
console та network cleanup входять у
`agent-workspace/tests/e2e/test_automation_ui.py`.

| `GET/POST` | `/api/osint/graphs` | Versioned project-scoped OSINT graphs |
| `GET` | `/api/osint/graphs/<id>` | Entities, relations and provenance |
| `POST` | `/api/osint/graphs/<id>/upsert` | Idempotent graph upsert (атомарний: одна некоректна identity відхиляє весь batch) |
| `PATCH/DELETE` | `/api/osint/graphs/<id>/entities/<entity_id>` | Редагування `risk_score`/`display_value`/`properties`/`provenance` або видалення entity разом із її relations |
| `DELETE` | `/api/osint/graphs/<id>/relations/<relation_id>` | Видалення одного relation без видалення його endpoint entities |
| `POST` | `/api/osint/graphs/<id>/clear` | Очищення графа (`{"confirm": true}`); контейнер графа зберігається |
| `GET` | `/api/osint/transforms` | Transform registry |
| `POST` | `/api/osint/graphs/<id>/transform` | Explicit transform run з graph persistence і `transform_result.status` |
| `POST` | `/api/scanner` | Scanner Pro |
| `POST` | `/api/scanner/nuclei` | Запуск завантажених Nuclei-шаблонів із per-file звітом |
| `POST` | `/api/scanner/nuclei/upload` | Один чанк завантажених шаблонів → `upload_id` |
| `POST` | `/api/scanner/nuclei/run` | Запуск staged-шаблонів із `Scan options` |
| `POST` | `/api/scanner/nuclei/jobs` | Background-job запуску → `job_id` і живий прогрес |
| `GET` | `/api/scanner/nuclei/jobs/<id>` | `state` + `progress` (лічильники nuclei) + фінальний `result` |
| `GET` | `/api/scanner/nuclei/jobs/<id>/stream` | SSE: `progress`, `template` (live-рядок на файл), `done` |
| `POST` | `/api/scanner/nuclei/jobs/<id>/pause` | Пауза запуску (`SIGSTOP`), стан `paused` |
| `POST` | `/api/scanner/nuclei/jobs/<id>/resume` | Продовження з того ж місця, стан `running` |
| `POST` | `/api/scanner/nuclei/jobs/<id>/cancel` | Скасування запуску |
| `GET/PUT` | `/api/route` | Читання або зміна маршруту |
| `POST` | `/api/route/check` | Перевірка route і source IP |
| `GET` | `/api/history` | History |
| `GET` | `/api/history/export` | Export History |
| `DELETE` | `/api/history/<id>` | Видалення запису |
| `POST` | `/api/history/bulk` | Масове видалення |
| `GET/DELETE` | `/api/traffic` | Traffic або очищення |
| `GET` | `/api/traffic/stream` | Traffic SSE |
| `POST` | `/api/traffic/save` | Save Traffic row |
| `POST` | `/api/traffic/annotate` | Tags/notes |
| `GET/POST` | `/api/traffic/capture-contexts` | Явні passive capture contexts |
| `GET/PATCH/DELETE` | `/api/traffic/capture-contexts/<id>` | Перегляд, rename/activate або deactivate context |
| `POST` | `/api/agent/chat` | Один AI chat turn; `include_project_context` лише за explicit one-shot opt-in |
| `GET` | `/api/workflows/node-types` | Каталог типів вузлів Automation |
| `GET/POST` | `/api/workflows` | Список або створення workflow |
| `GET/PATCH/DELETE` | `/api/workflows/<id>` | Перегляд, редагування або видалення workflow |
| `GET` | `/api/workflows/<id>/export` | Export workflow JSON |
| `POST` | `/api/workflows/import` | Import workflow JSON |
| `POST` | `/api/workflows/<id>/run` | Запуск workflow вручну |
| `POST` | `/api/workflows/<id>/activate` | Активація webhook/розкладу |
| `POST` | `/api/workflows/<id>/deactivate` | Деактивація workflow |
| `GET` | `/api/workflows/runs` | Історія виконань workflow |
| `GET` | `/api/workflows/runs/<id>` | Статус, результат і журнал вузлів |
| `GET` | `/api/workflows/runs/<id>/stream` | SSE live node events |
| `GET` | `/api/workflows/runs/<id>/export` | Export run JSON/Markdown |
| `POST` | `/api/workflows/runs/<id>/<action>` | `pause`, `resume` або `cancel` запуску |
| `ALL` | `/api/workflows/hooks/<slug>` | Webhook-тригер workflow |

### Помилки engine gateway

Django gateway повертає явні структуровані помилки від Go engine. Основні
значення `reason`:

- `ENGINE_UNAVAILABLE` — engine недоступний на рівні з'єднання;
- `ENGINE_HTTP_ERROR` — engine відповів HTTP-помилкою; поле `status` містить
  upstream status;
- `ENGINE_INVALID_RESPONSE` — відповідь engine порожня, не є коректним JSON
  або має непідтримувану форму.

Malformed responses і помилки transport не перетворюються на успішні відповіді.

UI-вкладки мають WAI-ARIA зв'язки `tablist`/`tab`/`tabpanel`, підтримують
клавіатурне перемикання стрілками та використовують локальні dialogs для
введення і підтвердження дій.

### Go engine

```text
GET  /health
GET  /route
PUT  /route
POST /route/check
POST /proxy/request
POST /proxy/intruder
GET  /proxy/intruder/<attack_id>
DELETE /proxy/intruder/<attack_id>
POST /proxy/repeater-burst
GET  /proxy/repeater-burst/<burst_id>
DELETE /proxy/repeater-burst/<burst_id>
POST /proxy/repeater-burst/<burst_id>  {"action":"pause|resume"}
POST /proxy/last-byte
GET  /proxy/last-byte/<last_byte_id>
DELETE /proxy/last-byte/<last_byte_id>
POST /proxy/last-byte/<last_byte_id>  {"action":"pause|resume"}
POST /proxy/oast
GET  /proxy/oast/<listener_id>
DELETE /proxy/oast/<listener_id>
GET  /events
GET  /events/stream
```

## Перевірка та діагностика

З кореня репозиторію:

```bash
cd engine && go test ./... -count=1
cd ../web && python manage.py check
cd web && python manage.py test -v 2
```

Зовнішні browser-сценарії й тести обслуговуючих скриптів живуть у
`agent-workspace/` і запускаються з кореня:

```bash
browser-worker/.venv/bin/python agent-workspace/tests/e2e/test_automation_ui.py
python agent-workspace/tools/test_oast_fixture.py -v
python agent-workspace/tools/test_last_byte_fixture.py -v
python agent-workspace/tools/skills/test_install_opencode_skills.py -v
./agent-workspace/tools/skills/bootstrap.sh --verify
```

Перевірка inline JavaScript:

```bash
python3 - <<'PY'
from pathlib import Path
import re
import subprocess
import tempfile

html = Path("web/templates/lab/index.html").read_text()
script = re.search(r"<script>(.*)</script>", html, re.S).group(1)
with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
    handle.write(script)
    path = handle.name
result = subprocess.run(["node", "--check", path], capture_output=True, text=True)
print(result.stderr, end="")
raise SystemExit(result.returncode)
PY
```

Docker-диагностика:

```bash
docker compose ps
docker compose logs --no-color --tail=100 tor engine web
docker system df
df -h /
```

Типові проблеми:

| Симптом | Причина | Дія |
|---|---|---|
| `permission denied /var/run/docker.sock` | користувач не в групі Docker | `newgrp docker` або новий login |
| `address already in use` | локальний режим уже займає порт | зупинити один режим перед запуском іншого |
| Tor не працює | bootstrap ще не завершився | дочекатися `Bootstrapped 100% (done)` |
| Docker Tor не доступний з engine | використано `127.0.0.1` замість service DNS | у Compose використовувати `tor:9050` |
| `no space left on device` | переповнений host або Docker cache | звільнити місце і перевірити `docker system df` |
| HTTPS certificate error | CA не імпортований у тестовий профіль | імпортувати `data/ca/ca.crt` |

## Безпека

Розширені рекомендації щодо LUKS, VPN/kill switch, firewall, VM, Docker,
секретів, CA і безпечного scope зберігаються в [`SECURITY.md`](SECURITY.md).
Це практична пам’ятка, а не гарантія абсолютної анонімності або безпеки.

## Документація функцій

Кожна велика функція описана окремим файлом у папці
[документация](./документация):

| Функція | Документ |
|---|---|
| Proxy, маршрутизація і passive MITM | [прокси.md](./документация/прокси.md) |
| Repeater | [povtoryuvach.md](./документация/povtoryuvach.md) |
| Intruder | [intruder.md](./документация/intruder.md) |
| Target карта цілі | [karta-cili.md](./документация/karta-cili.md) |
| OSINT | [osint.md](./документация/osint.md) |
| Scanner Pro | [scanner-pro.md](./документация/scanner-pro.md) |
| Comparer | [porivniuvach.md](./документация/porivniuvach.md) |
| Decoder | [dekoder.md](./документация/dekoder.md) |
| Tor/Proxy operator workflow | [tor-proksi.md](./документация/tor-proksi.md) |
| Passive Traffic | [pasivnyi-trafik.md](./документация/pasivnyi-trafik.md) |
| History | [istoriia.md](./документация/istoriia.md) |
| AI Assistant | [ai-asystent.md](./документация/ai-asystent.md) |
| Template Store Automation | [template-store.md](./документация/template-store.md) |
| OAST Listener | [oast.md](./документация/oast.md) |
| Automation UI E2E | [tests/e2e/README.md](./agent-workspace/tests/e2e/README.md) |
| Практичні сценарії Automation | [automation-сценарії.md](./документация/automation-сценарії.md) |
| Workspaces і Session | [robochi-prostory-sesii.md](./документация/robochi-prostory-sesii.md) |
| Project Hub і Target Knowledge Base | [project-hub.md](./документация/project-hub.md) |
| Звіт про видалені обмеження рівня застосунку | [видалені-обмеження.md](./документация/видалені-обмеження.md) |

## Пов’язані документи

- [`SECURITY.md`](SECURITY.md) — операційна безпека та checklist.
- [`ROADMAP.md`](ROADMAP.md) — короткий актуальний план розвитку.
- [`AGENT_USER_GUIDE.md`](AGENT_USER_GUIDE.md) — окрема інструкція AI-вкладки.
- [`LLM.md`](LLM.md) — межі та модель AI runtime.
- [`DEVELOPMENT_LOG.md`](DEVELOPMENT_LOG.md) — хронологічний журнал змін,
  виправлень, запусків і перевірок.
- [`документация/`](документация/) — актуальні довідники Repeater, Intruder,
  Target, Scanner, Proxy, Traffic, History, Decoder, Comparer, OSINT, AI та
  workspace/session.
