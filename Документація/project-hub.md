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
- **`ProjectEndpoint`** — реєстрація ендпоінтів з HTTP-методами та статусами для подальшого тестування в Repeater/Intruder;
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

- `target`, `environment`, `route_profile`;
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
