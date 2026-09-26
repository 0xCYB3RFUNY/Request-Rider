# Project Hub і Target Knowledge Base

> Актуально на 2026-09-25. Загальні правила ітерацій і перевірок див. у
> [AGENTS.md](../AGENTS.md), API та загальний статус — у [README.md](../README.md).
> Детальний перелік зняття application-level обмежень — у
> [звіті про видалені обмеження](видалені-обмеження.md).

## Призначення

Project Hub поєднує durable metadata цілі та повний project-scoped context для
QA/report/AI. Він не копіює сирі HTTP exchanges у LLM prompt і не зберігає
паролі, JWT чи API keys у SQLite.

## Scanner runs

Вкладка Scanner показує журнал запусків (`ScannerRun`: engine
builtin/templates/nuclei, URL, час, кількість і severity знахідок, самі
знахідки компактно). Кожен скан з активним Project автоматично дописується
сюди — як Repeater/Target пишуть своє. Тріажу/верифікації/статусів немає
свідомо (Findings Center видалено 2026-09-25): це evidence-лог, а не черга
задач. API віддає повний список `scanner_runs` разом із метрикою `scans`.

Для `engine: nuclei` у `summary.templates` зберігається окремий per-file
звіт журналу: `name`, `template_id`, `severity`, `status`
(`matched` / `not_matched` / `invalid`), `reason`, `cve`, `matches`.
Знахідки додатково несуть `cve` (з `info.classification.cve-id` шаблону).
Деталі — у [scanner-pro.md](scanner-pro.md#результат-по-кожному-yaml-файлу).

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

## Secret references

`ProjectSecret` зберігає лише:

- type (`JWT`, `API key`, `Password`, `Leak reference`);
- stable `key_name`;
- `value_ref` — reference або metadata-only значення;
- optional `source_url`;
- timestamps.

Поля `value` у моделі немає. Password, bearer token, cookie, CSRF value та raw
API key не можна записувати через цю модель. DB constraint, який вимагав
`env:` prefix, видалено разом із загальними обмеженнями. Browser/AI ніколи
не читають process environment для secret reference.

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
- query stripping та відсутність raw headers/bodies;
- redaction notes/technology labels;
- no plaintext `ProjectSecret.value` field;
- explicit notes opt-in;
- prompt delimiter escaping;
- invalid tech stack/notes;
- live create/reload/delete Projects без console/network errors.
