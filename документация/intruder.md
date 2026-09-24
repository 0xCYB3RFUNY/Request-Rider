# Функція Intruder: повний шлях атаки і результатів

> Актуально на 2026-09-22. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).

Intruder — асинхронний генератор і виконавець HTTP jobs. UI формує одну
базову raw request із marker-ами, Django передає attack definition, Go
генерує jobs, виконує їх worker pool-ом і повертає результати частинами.

## Повна схема

```text
UI raw request + markers + dictionaries
    -> POST /api/intruder
    -> Django intruder()
    -> POST /proxy/intruder
    -> attack ID
    -> marker parsing + transformations
    -> Generate(mode)
    -> worker pool
    -> executeContext() per job
    -> GET /proxy/intruder/<id>
    -> Django persist_intruder_results()
    -> Intruder table + Traffic + History
```

## 1. Формування definition

UI надсилає:

```json
{
  "base_request": {
    "method": "GET",
    "url": "https://example.test/search?q=§term§",
    "headers": {},
    "body": ""
  },
  "mode": "sniper",
  "payloads": [["admin", "test"]],
  "dictionaries": {},
  "transformations": [],
  "delay_ms": 150,
  "concurrency": 4
}
```

Marker-и підтримують `§name§`, `{{name}}` і `%name%`. Parser проходить URL,
headers і body у wire order; глобальний offset означає, що positions
замінюються в єдиній послідовності.

## 2. Django lifecycle

`views.intruder()` розділяє операції:

- `POST` — передати definition і запустити attack;
- `GET` — прочитати status/results;
- `POST action=pause|resume` — керувати lifecycle;
- `DELETE` — cancel engine attack.

Django може зберегти `IntruderAttack` для повторного запуску, але оперативний
progress і result slice живуть у Go process memory.

## 3. Генерація jobs

`intruder.Generate()` відхиляє definition без marker або payload set:

- **Sniper** створює job для кожного marker окремо, решта values порожні;
- **Battering Ram** повторює один payload у всі marked positions;
- **Pitchfork** бере однаковий index у dictionaries до shortest;
- **Cluster Bomb** рекурсивно будує Cartesian product.

Перед replacement кожен payload проходить `TransformPayload()` зліва направо:

```text
urlEncode -> prepend -> base64Encode -> append
```

Невідома transformation або malformed decode зупиняє generation з explicit
error. Binary bytes не відкидаються через відсутність UTF-8.

## 4. Worker execution

Go створює `attack` із cancel context, `resumeCh`, counters і result slice.
Worker pool бере jobs із channel. `delay_ms > 0` серіалізує запити з паузою;
`concurrency` визначає кількість workers.

Кожен job:

1. замінює markers у URL, headers і body;
2. викликає `executeContext()`;
3. зберігає HTTP result або explicit error;
4. публікує exchange у Traffic як `source=intruder`;
5. збільшує completed/failed.

Окремі job start/complete logs не пишуться, щоб великі атаки не перевантажували
terminal і disk; залишаються aggregate lifecycle logs.

## 5. Polling і deduplication

`GET /proxy/intruder/<id>` повертає `status`, counters, `result_offset` і
порцію `results`. UI запитує наступну порцію через offset і додає лише нові
virtualized rows.

Django передає `proxy_session` та `proxy_event_id`, тому повторний polling не
створює дублікати History. Result має generated request поруч із response:
method, URL, payload, status, size, time, headers, body і source IP.

## 6. Pause, resume, cancel

Pause блокує видачу нових jobs через `resumeCh`, але не обриває поточний
outbound exchange. Resume відкриває канал. DELETE викликає context cancel і
переводить attack у `cancelled`.

`pagehide` не скасовує атаку. Cancel можливий тільки явною кнопкою.

## 7. API і файли

```text
POST   /api/intruder
GET    /api/intruder?attack_id=<id>
POST   /api/intruder?attack_id=<id>&action=pause|resume
DELETE /api/intruder?attack_id=<id>
GET/POST /api/intruder/saved
POST   /api/intruder/saved/<id>/run
POST   /proxy/intruder
GET    /proxy/intruder/<id>
DELETE /proxy/intruder/<id>
```

- [web/templates/lab/index.html](../web/templates/lab/index.html)
- [web/lab/views.py](../web/lab/views.py)
- [engine/main.go](../engine/main.go)
- [engine/pkg/intruder/intruder.go](../engine/pkg/intruder/intruder.go)
- [web/lab/models.py](../web/lab/models.py)


## Code walkthrough: Intruder

### UI handlers

The UI reads raw request editor, marker selection, mode, dictionaries,
transformations, concurrency and delay controls.
Run builds a `base_request` and payload sets.
Save calls `/api/intruder/saved`; load calls GET saved configurations.
Pause/resume uses action query; Cancel uses DELETE.
Polling updates the compact result table incrementally.
Each result can open full request/response inspector or Comparer.

### Exact request/state

The logical POST contains `base_request`, `mode`, `payloads` or `dictionaries`,
`transformations`, `delay_ms`, and `concurrency`.
`POST /api/intruder` returns `attack_id` and initial state.
`GET /api/intruder?attack_id=id&since=n&limit=m` returns result batches,
`result_offset`, progress and lifecycle status.
`POST ...?attack_id=id&action=pause|resume` changes lifecycle state.
`DELETE /api/intruder?attack_id=id` cancels the attack.

### Django chain

`views.intruder` branches GET, DELETE, action POST, or start POST.
Start parses JSON and normalizes `base_request`.
It calls `call_engine('/proxy/intruder', payload)`.
GET calls `call_engine_get` and `persist_intruder_history` using offset.
DELETE calls `call_engine_delete`; action calls `call_engine_action`.
Saved config view stores `IntruderAttack` in SQLite and can rerun it.

### Go chain

`server.intruder` -> marker position extraction -> `intruder.Generate`.
Transformations run left-to-right before job creation.
`runAttack` executes generated jobs with worker pool or sequential delay mode.
Each job replaces markers in URL, headers and body.
`executeContext` performs the outbound request through route transport.
`publishIntruderTraffic` emits pending/completed Traffic events.
`intruderStatus` -> `attackSnapshot` returns incremental results.

### Branches and storage

Sniper, Battering Ram, Pitchfork and Cluster Bomb select different generators.
HTTP 4xx/5xx with a response are valid results; no-response is `error`.
Pause/resume changes scheduling, cancel closes context.
Django persists each new result once using proxy session/event IDs.
Go attack state is in memory and disappears after restart.
SQLite History remains after restart; Traffic is memory-only unless saved.

### Buttons and symbols

Run starts; Save stores; Load hydrates; Pause/Resume controls lifecycle.
Cancel is the only destructive attack action and requires explicit click.
Clear removes displayed result state but does not cancel unless specified by UI.
Symbols: `runIntruder`, polling/render functions, `persist_intruder_history`,
`intruder_saved`, `server.intruder`, `runAttack`, `intruderStatus`,
`attackSnapshot`, `intruder.Generate`; files `index.html`, `views.py`,
`main.go`, `pkg/intruder/intruder.go`, `models.py`.

## Трасування повного lifecycle

1. UI спочатку показує review: target, method, route, mode, delay,
   concurrency і estimated jobs. Запуск до перевірки definition не вважається
   початком атаки.
2. Raw request розбирається в marker positions у wire order. Dictionary,
   payload sets і transformations перевіряються до POST; відсутній marker або
   payload дає explicit validation error.
3. Django нормалізує definition і створює/повертає attack context лише після
   успішного виклику engine. Невдалий engine response не маскується під
   запущену атаку.
4. Go materializes jobs згідно з mode, після чого worker pool бере jobs із
   bounded queue. `delay_ms` регулює старт наступного job, `concurrency`
   регулює одночасно активні workers.
5. Кожен job отримує власний generated request, проходить transformations,
   route transport і `executeContext`. HTTP 4xx/5xx є нормальним результатом,
   а відсутність response — окремим error.
6. Для кожного exchange Go публікує pending/completed Traffic events. Polling
   через `since`/`result_offset` забирає лише нову порцію, тому повторний
   запит не дублює таблицю або History.
7. Pause зупиняє видачу нових jobs, resume продовжує той самий attack context,
   Cancel закриває context. Поточний низькорівневий request може завершитися
   перед фінальним `cancelled`.
8. Після completion UI залишає результати доступними для inspect, Compare,
   Repeater, AI та JSON/CSV export. Saved attack зберігає definition, але не
   гарантує збереження runtime progress після restart Go.
9. Після reload відновлюються локальні settings/result view, а durable
   Intruder/History records залишаються в SQLite незалежно від engine memory.

### Контрольні точки

Перевіряйте послідовно: marker parser → job estimate → `POST /api/intruder`
→ `attack_id` → incremental polling → pause/resume/cancel → deduplicated
History → final export. На кожній точці помилка має залишатися видимою, а
часткові результати — доступними для аналізу.
