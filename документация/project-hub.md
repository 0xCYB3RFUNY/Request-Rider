# Project Hub і Target Knowledge Base

> Актуально на 2026-09-24. Загальні правила ітерацій і перевірок див. у
> [AGENTS.md](../AGENTS.md), API та загальний статус — у [README.md](../README.md).

## Призначення

Project Hub поєднує durable metadata цілі та безпечний compact context для
QA/report/AI. Він не копіює сирі HTTP exchanges у LLM prompt і не зберігає
паролі, JWT чи API keys у SQLite.

## Project metadata

`Project` має:

- `target`, `environment`, `route_profile`;
- `scope_in` / `scope_out`;
- `tech_stack` — bounded JSON object із перевіреними technology metadata;
- `notes` — Markdown/local notes, максимум 20 000 символів;
- `metadata` — restricted service compatibility field.

`POST`/`PATCH /api/projects` валідують `tech_stack` та `notes`. Invalid context
повертає `INVALID_PROJECT_CONTEXT`; invalid scope/target — `INVALID_PROJECT_SCOPE`.

## Secret references

`ProjectSecret` зберігає лише:

- type (`JWT`, `API key`, `Password`, `Leak reference`);
- stable `key_name`;
- `value_ref` виду `env:NAME` з дозволеними `[A-Za-z_][A-Za-z0-9_]*`
  символами або порожнє metadata-only значення;
- optional `source_url`;
- timestamps.

Поля `value` у моделі немає. Password, bearer token, cookie, CSRF value та raw
API key не можна записувати через цю модель. DB constraint дозволяє лише
`value_ref` з `env:` prefix. Browser/AI ніколи не читають process environment
для secret reference.

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
- Findings totals і bounded list;
- Workflow names/active state/run count;
- TargetJob status metadata;
- secret reference types/key names/env references;
- notes лише за explicit `include_notes=True`.

URL query/fragment, credentials, raw headers та raw bodies не включаються.
Context має bounds для endpoint, finding, workflow, TargetJob і secret-reference
lists. Evidence позначається як untrusted; prompt-delimiter characters екрануються,
а operator query передається окремим JSON payload.

## AI boundary

`build_ai_prompt()` лише формує bounded text і нічого не виконує.
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
