# Project Hub і Target Knowledge Base

> Документація центру керування проєктами (Project Hub), бази знань та автоматичного інжесту спостережень.
> Архітектура системи: [arkhitektura-ta-api.md](./arkhitektura-ta-api.md).

## Призначення

Project Hub поєднує durable metadata цілі та повний project-scoped context для
QA/report/AI. Він не копіює сирі HTTP exchanges у LLM prompt і не зберігає
паролі, JWT чи API keys у PostgreSQL.

## Автоматична інтеграція знахідок (Observations Ingest)

Це штатна та ключова можливість (**feature**) проєкту, а не помилка чи витік даних:

Коли оператор працює з вибраним активним проєктом (`Project`), результати роботи розвідувальних інструментів автоматично перетворюються на структуру знань цілі та зберігаються у відповідних графах `OsintGraph`. Це усуває необхідність вручну переносити адреси, домени та пошти між вкладками.

### 1. Знахідки краулера Target (`Target observations`)
Після успішного завершення побудови карти сайту (`TargetJob`) система одноразово індексує виявлені компоненти у граф `"Target observations"` (`source: target`):
- **`url`** — кожна знайдена сторінка та цікавий файл (`notable_files`: скрипти, бекенд-точки, конфіги, адмінки);
- **`subdomain`** — піддомени, виявлені у структурі посилань та коді;
- **`domain`** — зовнішні домени, трекери та CDN (`properties.kind = "external"`);
- **`email`** — контактні e-mail адреси, знайдені в HTML;
- **`ProjectEndpoint`** — реєстрація ендпоїнтів з HTTP-методами та статусами для подальшого тестування в Repeater/Intruder;
- **`ProjectSecret`** — знайдені у вихідному коді або відповідях API-ключі та витоки.

### 2. Знахідки пасивного OSINT (`Passive OSINT observations`)
При виконанні пасивної розвідки цілі результати автоматично зберігаються у граф `"Passive OSINT observations"` (`source: osint`):
- **`url`** — цільова адреса;
- **`domain`** — цільовий домен;
- **`ip`** — IP-адреси, отримані з DNS-записів;
- **`technology`** — виявлений стек технологій (сервери, CMS, фреймворки).

### Перевірка походження (Provenance)
Будь-яку сутність можна перевірити у вкладці **OSINT** або **Projects**:
- У картці сутності вказано `properties.source` (`target`, `osint` або `manual`), що дозволяє чітко бачити, який саме інструмент створив цей вузол.

---

## Scanner runs

Вкладка Scanner показує журнал запусків (`ScannerRun`: engine
builtin/active/corpus, URL, час, кількість і severity знахідок, самі
знахідки компактно). Кожен скан з активним Project автоматично дописується
сюди — як Repeater/Target пишуть своє. Тріажу/верифікації/статусів немає
свідомо (Findings Center видалено 2026-09-25): це evidence-лог, а не черга
задач. API віддає повний список `scanner_runs` разом із метрикою `scans`.

Для `engine: active` та `engine: corpus` у `findings` та `summary` зберігається
детальний звіт: назва перевірки/модуля, статус підтвердження (`verified` / `potential`),
виявлена поверхня або шлях, докази та cURL для відтворення.
Деталі — у [scanner-pro.md](scanner-pro.md) та [aktivnyi-skanner.md](aktivnyi-skanner.md).

## Project metadata

`Project` має:

- `target`, `environment`, `route_profile`:
  - `target` — базовий URL або адреса цілі проєкту;
  - `environment` — необов'язковий текстовий маркер контуру або стадії розгортання цільового застосунку (наприклад, `local`, `dev`, `qa`, `staging`, `prod`). Використовується як організаційна мітка у зведеннях для AI-асистента (`ProjectContextBuilder`), звітах (`fusion_report`) та при експорті/імпорті проєкту; **не** змінює мережеву маршрутизацію, **не** блокує інструменти та **не** читає змінні оточення процесу;
  - `route_profile` — профіль мережевого маршруту для проєкту;
- `scope_in` / `scope_out` — legacy metadata, не execution policy;
- `tech_stack` — JSON object із перевіреними technology metadata;
- `notes` — Markdown/local notes без верхньої межі;
- `metadata` — restricted service compatibility field.

`POST`/`PATCH /api/projects` перевіряють JSON-типи та required fields, але
не встановлюють application-level length/count ceilings. Invalid context
повертає `INVALID_PROJECT_CONTEXT`; invalid scope/target — `INVALID_PROJECT_SCOPE`.

## Secrets

`ProjectSecret` зберігає знайдений секрет **повністю**:

- type (`JWT`, `API key`, `Password`, `Leak reference`);
- stable `key_name`;
- `value_ref` — **повне значення** credential'а таким, як він ішов;
- optional `source_url`;
- timestamps.

Окремого поля `value` у моделі немає саме тому, що `value_ref` і є значенням:
поле з'явилося як вказівник, але ingest ніколи не збирав credential, тож усі
поверхні могли показати лише «тут був секрет». Тепер значення збирається при
захопі й показується без маскування, обрізання та fingerprint — у вкладці
«Секрети», у розділі `## Secrets` звіту, в `## Notes` та в експортному bundle.

Це стосується перехопленого оператором трафіку і знайдених при скануванні
креденшелів однаково. Дедуплікація при цьому **лишається за fingerprint**: той
самий ключ у 50 комітах — одне розкриття, а не п'ятдесят. Fingerprint тут ключ
згортки, а не заміна значення.

DB constraint, який вимагав `env:` prefix, видалено разом із загальними
обмеженнями. Browser/AI ніколи не читають process environment для secret.

## ProjectContextBuilder

`web/lab/project_context.py` містить `ProjectContextBuilder(project_id)`:

```python
builder = ProjectContextBuilder(project.id)
summary = builder.build_summary_markdown()
prompt = builder.build_ai_prompt("Summarize the attack surface")
```

Summary включає тільки project-scoped:

- target/scope/technology metadata;
- унікальні method + URL aggregates із History;
- status/content-type counters;
- Workflow names/active state/run count;
- TargetJob status metadata;
- secret reference types/key names/env references;
- notes лише за explicit `include_notes=True`.

URL query/fragment, credentials, raw headers та raw bodies не включаються.
Context включає повні project-scoped lists без count/length budget. Evidence
позначається як untrusted; prompt-delimiter characters екрануються, а operator
query передається окремим JSON payload.

## AI boundary

`build_ai_prompt()` лише формує повний text і нічого не виконує.
`/api/agent/chat` додає Project summary лише коли browser checkbox передає
explicit `include_project_context: true`; consent є one-shot і скидається після
success/error. Без active Project API повертає `PROJECT_CONTEXT_REQUIRED`.
Workflow AI не отримує Project context автоматично.

## Project context session

Selector у вкладці `Projects` зберігає active Project через CSRF-protected
`POST /api/project-context`. Django session є server authority; `?project_id`
ігнорується, `localStorage` є лише mirror. Детально — у
[робочих просторах](robochi-prostory-sesii.md).

## Обмеження

- Browser-local OSINT/Scanner results не входять до durable summary.
- Raw OAST/workflow output не реконструюється у secret-bearing context.
- `include_notes=True` використовує common-pattern redaction, але notes можуть
  містити нестандартний секрет; для AI краще залишати notes вимкненими.
- Shared/multi-user authorization, retention та audit ще не реалізовані.
- UI dashboard/editing для `tech_stack`, notes і secret references ще не доданий.

## Перевірки

Обов'язкові сценарії:

- project isolation і відсутність чужих rows у summary;
- query stripping та відсутність raw headers/bodies у самому summary;
- **повне значення** кожного секрета у вкладці, звіті й bundle — без
  `[REDACTED]`, `[metadata only]`, fingerprint і обрізання;
- `## Notes` у context за замовчуванням;
- відсутність окремого поля `ProjectSecret.value`: `value_ref` і є значенням;
- prompt delimiter escaping;
- invalid tech stack/notes;
- live create/reload/delete Projects без console/network errors.

---

## Двосторонній обмін із Metasploit та XML-експорт/імпорт

У вкладці **Projects** підтримується обмін даними з Metasploit Framework (`msfconsole` / `msfdb`) та XML-форматами:

1. **Експорт проєкту у XML та Metasploit XML**:
   - `GET /api/projects/<id>/export?format=xml` — структурований XML-бандл проєкту (`<project_bundle>`).
   - `GET /api/projects/<id>/export?format=msf-xml` — експорт у форматі `<MetasploitV4>` (сумісному з парсером `msfconsole db_import`, включно з обов'язковими тегами `<host>`, `<service>`, `<vuln>`, `<note>`, `<web_site>`, `<web_vuln>`).
2. **Пряме відправлення в локальну базу Metasploit (`Send to Metasploit`)**:
   - `POST /api/projects/<id>/metasploit-import` — генерує `<MetasploitV4>` XML і запускає `msfconsole -q -x "workspace -a <workspace>; db_import <tmp.xml>; exit"` (`shell=False`, без шел-інтерпретації).
   - Дані **додаються (мерджаться)** у вибраний workspace Metasploit, не перезаписуючи існуючі записи.
   - При запуску через `start.sh` функція `ensure_msfdb()` автоматично перевіряє наявність `~/.msf4/database.yml` і, якщо конфіг створений лише з правами `root` у `/usr/share/metasploit-framework/config/database.yml` або `/root/.msf4/database.yml`, копіює його у `~/.msf4/database.yml` з правами `600` для поточного користувача.
3. **Імпорт бази Metasploit у Request-Rider (`Projects → Import → Metasploit XML`)**:
   - Вивантажте потрібний workspace із `msfconsole`:
     ```text
     msfconsole -q -x "workspace default; db_export -f xml /tmp/msf_export.xml; exit"
     ```
   - Завантажте файл через **Projects → Import → Metasploit XML**:
     - якщо вибрано активний проєкт (`POST /api/projects/<id>/import-metasploit-xml`) — хости, сервіси/ендпоїнти (`ProjectEndpoint`) та знахідки (`ScannerRun`) **додаються в поточний проєкт**;
     - якщо активний проєкт не вибрано (`POST /api/projects/import-metasploit-xml`) — автоматично створюється **новий проєкт** `Metasploit (<host>)`.
   - XML-парсер захищений від XXE (відхиляє `DOCTYPE`/`ENTITY`).

---

## Live Dashboard, Hosts & Services, Attack Surface Drift та налаштування (`⚙️`)

Розмітка вкладки розташована у `web/templates/lab/tabs/_projects.html` (історично була в `index.html`). Вкладка **Projects** містить 4 підвкладки (`data-hub-tab`):

1. **`⚡ Live Dashboard` (`#project-hub-dashboard`, активна за замовчуванням)**:
   - **HUD-панель**: `#hub-engine-status` (`ONLINE (8081)`), `#hub-egress-route` (`DIRECT`), `#hub-ping-latency`, `#hub-target-url`.
   - **Швидкі дії**: `#hub-btn-active-scan` (`Quick Active Scan`), `#hub-btn-crawler` (`Crawl Target`), `#hub-btn-fusion-report` (`Fusion Report`).
   - **5 KPI-карток**: `#hub-kpi-hosts`, `#hub-kpi-endpoints`, `#hub-kpi-traffic`, `#hub-kpi-vulns` (з лічильниками `#hub-cnt-crit`, `#hub-cnt-high`, `#hub-cnt-med`, `#hub-cnt-low`), `#hub-kpi-tasks`.
   - **Active Tasks & Scan Orchestrator**: `#hub-active-tasks-list` (автооновлення кожні 3 с за замовчуванням), `#hub-empty-scan-btn`.
   - **Security Findings Stream**: `#hub-findings-feed-list`, фільтри severity `[data-hub-filter]` (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), пагінація `#hub-findings-more-btn` та модальне вікно деталей знахідки (`#hub-finding-drawer` з PoC cURL та evidence).
2. **`🖥️ Hosts & Services` (`#project-hub-hosts`)**:
   - Пошук `#hub-hosts-search` (IP, хост, порт, сервіс, CVE), фільтр портів `#hub-hosts-filter-port` (`""`, `web`, `ssh`, `ftp`, `db`), фільтр знахідок `#hub-hosts-filter-vulns` (`""`, `vulns_only`, `critical`), кнопка `#hub-btn-import-scan-xml` (`Import XML Scan`).
3. **`Overview` (`#project-hub-overview`) та `Attack Surface Drift & Shadow API Radar` (`#surface-drift-panel`)**:
   - `#sd-capture-btn` (`Capture Snapshot`), селекти базового та цільового знімків `#sd-snap-s1` / `#sd-snap-s2`, `#sd-diff-btn` (`Compare Drift`), `#sd-scan-delta-btn` (`Scan Delta`), вивід `#sd-diff-output`.
4. **`AI snapshot` (`#project-hub-ai`)**:
   - `<pre id="project-hub-ai-snapshot">` — текстове зведення проєкту для передачі AI-асистенту.

### Експорт, імпорт та керування проєктом
- **Меню експорту (`#project-export`)** підтримує 8 форматів: `fusion-html` (Unified Fusion Report), `sarif` (SARIF 2.1.0), `msf-xml` (Metasploit XML), `msf-db` (Send to Metasploit), `xml` (Full project XML), `json` (Re-importable bundle), `html` (Interactive report), `csv` (One row per record).
- **Меню імпорту (`#project-import`)** підтримує `json-file` (`.json` bundle) та `msf-xml-file` (`.xml` Metasploit).
- **Модалка редагування проєкту (`#project-manage`)** редагує поля `name`, `target`, `environment`, `route_profile`.
- **Налаштування (`⚙️` → `#tool-pane-projects`)**: `#setting-projects-refresh` (інтервал автооновлення Dashboard: `3` с за замовчуванням, `5`, `10`, `30`) та `#setting-projects-scope-strict` (`checked`, сувора фільтрація Knowledge Hub і Dashboard за scope активного проєкту).
- **Кутові дії вкладки**: `.tab-faq-trigger` (`❓ FAQ`) та `.tab-settings-trigger` (`⚙️`).
