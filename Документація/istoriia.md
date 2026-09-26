# Функція History: повний шлях збереження і повторного використання

> Актуально на 2026-09-25. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).
> Детальний перелік зняття application-level обмежень — у
> [звіті про видалені обмеження](видалені-обмеження.md).

History — Django/SQLite шар довготривалих завершених exchange. Він відрізняється
від memory-only Traffic Store: engine може перезапуститися, а History
залишається у базі web.

## Повна схема

```text
Repeater completed response
    -> views.execute()
    -> TrafficRecord.objects.create()
    -> SQLite
    -> GET /api/history
    -> filters + sort + full list
    -> history_item()
    -> History table
```

Для passive event:

```text
Traffic row
    -> POST /api/traffic/save
    -> validate event
    -> TrafficRecord.objects.create(source=proxy)
    -> History
```

## 1. Модель

`TrafficRecord` зберігає:

```text
timestamp, source, method, url, host, source_ip
proxy_event_id, proxy_session
request_headers, request_body, request_body_encoding, request_body_base64
response_headers, response_body, response_body_encoding, response_body_base64
response_content_type, status_code, latency_ms, response_size
tags, notes
```

`source` розрізняє repeater, intruder, proxy і route-check. Binary data не
втрачається: text і base64 fields зберігаються окремо.

## 2. Запис Repeater

`views.execute()` приймає `/api/execute`, викликає engine і створює row лише
якщо status engine 200 і result має HTTP `status`. Це означає:

- HTTP 404/500 із відповіддю зберігається;
- engine unavailable/transport failure не створює фальшивий успішний row;
- source IP береться з result, отриманого через поточний route.

## 3. Запис Intruder

Під час polling `persist_intruder_results()` проходить нову порцію за
`result_offset`. Для deduplication використовуються `proxy_session` і
`proxy_event_id`. В generated request зберігаються URL/method/headers/body
кожного job, а не лише base request.

## 4. API read/filter

`GET /api/history` спочатку обмежує sources repeater/intruder, потім додає:

```text
q       URL/body/response/host/tags/notes
host    host contains
path    URL contains
method  case-insensitive
status  exact status
mime    content type contains
body    response body contains
size_min/size_max
latency_min/latency_max
```

Дозволене сортування: timestamp, host, method, URL, status і response size.
Browser response повертає повний список без application row cap.

## 5. UI actions

History row тримає дві швидкі іконки (Inspect, Repeater); решта дій схована у
плавуче меню `⋯` (`#ctx-menu`, тригер `data-ctx-history`): Intruder, Comparer
запит/відповідь, Decoder запит/відповідь, Tag/note, Copy cURL/JSON, Copy,
Delete, Send to Automation. Повторний клік по `⋯` закриває меню; шапка меню
показує `#id · METHOD host` рядка. Клік по `⋯` рядок не виділяє.

History row можна:

- відкрити у повному request/response inspector;
- відправити в Repeater;
- відправити у Intruder;
- передати в Comparer;
- змінити tags/notes;
- видалити один row;
- видалити вибрані rows bulk.

## 6. Export/import

`GET /api/history/export` серіалізує durable rows у portable JSON із headers,
body, encoding, status, timing, source IP, tags і notes. Legacy
`POST /api/history/import` валідовує кожен item, вимагає URL і створює нові
rows без довіри до старого database ID.

## 7. API і код

```text
GET    /api/history
GET    /api/history/export
POST   /api/history/import
DELETE /api/history/<id>
POST   /api/history/bulk
```

- [web/lab/models.py](../web/lab/models.py)
- [web/lab/views.py](../web/lab/views.py)
- [web/core/urls.py](../web/core/urls.py)
- [web/templates/lab/index.html](../web/templates/lab/index.html)


## Code walkthrough: History

### UI and controls

History loads with `GET /api/history`.
Host search filters rows locally; sort is host/method/URL/time.
View opens request/response inspectors.
Copy copies the selected exchange.
Repeater/Intruder buttons transfer stored request data to workspaces.
Comparer/Decoder/AI buttons transfer explicit evidence.
Delete row uses `DELETE /api/history/<id>`.
Bulk delete posts selected IDs to `/api/history/bulk`.
Clear deletes all applicable History records.
Export downloads JSON from `/api/history/export`.

### Django/storage chain

`views.history` queries `TrafficRecord` sources repeater/intruder.
`history_item` serializes complete headers/body and encoding metadata.
`execute` creates repeater records after completed HTTP responses.
`persist_intruder_history` uses attack offset and proxy IDs for deduplication.
`history_export` returns format `intruder-lab-history` and all items.
`history_import` validates items and creates SQLite records.
`history_detail` returns one record or 404.

### Branches and errors

Invalid JSON/import shape returns 400 explicit error.
Unknown ID returns 404.
Bulk action validates IDs/action before deletion.
HTTP 4xx/5xx responses with bodies remain valid records.
A request with no HTTP response is not falsely stored as successful exchange.
History is durable SQLite, unlike live Go Traffic memory.

### Symbols/files

UI symbols include `loadHistory`, `renderHistory`, row action handlers,
`loadItem`, `historyExport`, bulk/delete helpers.
Backend symbols: `history`, `history_detail`, `history_item`,
`history_export`, `history_import`, `history_bulk`,
`persist_intruder_history`, `persist_proxy_history`.
Files: `index.html`, `web/lab/views.py`, `web/lab/models.py`,
`web/core/urls.py`.

## Трасування повного lifecycle

1. Exchange з'являється в History лише з завершеного Repeater/Intruder
   response або після explicit Save proxy Traffic event.
2. Gateway нормалізує headers/body/encoding, визначає source і перевіряє
   deduplication metadata. HTTP 4xx/5xx з body зберігаються як valid evidence.
3. Django serializer формує `history_item` для таблиці й inspector. Binary
   поля передаються окремими base64 attributes, тому UI не втрачає bytes.
4. Browser load виконує GET, після чого застосовує search/filter/sort локально
   або через query parameters. Selected row стає джерелом для action chain.
5. Send to Repeater/Intruder/Comparer/Decoder/AI переносить копію даних у
   workspace/context; оригінальний row не змінюється без окремої edit action.
6. Annotation оновлює tags/notes окремим запитом. Delete one і bulk delete
   перевіряють IDs/action та видаляють durable rows; clear не зачіпає live
   engine Traffic.
7. Export serializes portable JSON без довіри до database IDs. Import
   валідовує shape/URL і створює нові rows, щоб не перезаписувати існуючі.
8. Project cascade deletion видаляє пов'язані History records разом із
   Project; після цього UI оновлює project list і active context.

### Контрольні точки

`source exchange → normalize → SQLite create → GET/serialize → inspect/action
→ annotate/delete/export/import` — canonical durable trace. При діагностиці
порівнюйте `proxy_session/proxy_event_id`, source, status, body encoding і
кількість створених rows, щоб відрізнити дублікати від нових exchange.
