# Функція Target: повний шлях побудови карти

> Актуально на 2026-09-22. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).

Target — асинхронний read-only crawler. Django не чекає завершення crawl:
створює job у Go, повертає `map_id`, а UI окремо опитує status.

## Повна схема

```text
Target form
    -> POST /api/target-map
    -> Django target_map()
    -> POST /proxy/target-map
    -> 202 + map_id
    -> Go runTargetMap() goroutine
    -> shared transport -> pages/resources
    -> GET polling
    -> preview + JSON/CSV/tree export
```

## 1. Validation і state

Payload:

```json
{
  "url": "https://example.test/",
  "max_pages": 100,
  "max_depth": 3,
  "delay_ms": 100,
  "same_origin": true
}
```

Engine перевіряє absolute `http/https` URL, pages 1..10000, depth 0..50 і
non-negative delay. `targetMapStart()` створює cancel context і memory state:

```text
status=running
startURL
maxPages
visited=0
pages=[]
```

Після збереження state background goroutine викликає `runTargetMap`.

## 2. Crawl loop

Crawler підтримує queue URL/depth і visited set. Для кожної URL:

1. перевіряє page/depth/origin limits;
2. очікує `delay_ms`;
3. робить GET через shared transport;
4. читає status, content type і body;
5. додає URL, depth, status, type і kind у pages;
6. HTML parser знаходить links і forms;
7. static extraction знаходить JS/CSS/JSON references;
8. `robots.txt` обробляється лише як джерело `Sitemap:`-посилань; директиви
   `Allow`/`Disallow` не є policy-фільтром і не блокують crawl. Sitemap і XML
   `<loc>` додаються до queue;
9. нові URL фільтруються через same-origin і visited.

JavaScript не виконується, форми не submit-яться, payload не генерується.

## 3. Progress і cancel

```text
running -> completed
        -> cancelled
        -> error
```

`GET /proxy/target-map/<id>` повертає progress snapshot і pages. `DELETE`
викликає cancel context; поточний низькорівневий request може завершитись, але
нові queue items не запускаються.

## 4. UI export

UI не повторює crawl для export. Він бере pages snapshot і будує:

- JSON із повною структурою;
- CSV URL/depth/status/content type/kind;
- text tree за depth.

Target results не додаються автоматично до History або Traffic.

## 5. API і файли

```text
POST        /api/target-map
GET/DELETE  /api/target-map?map_id=<id>
POST        /proxy/target-map
GET         /proxy/target-map/<id>
```

- [web/templates/lab/index.html](../web/templates/lab/index.html)
- [web/lab/views.py](../web/lab/views.py)
- [engine/main.go](../engine/main.go)


## Code walkthrough: Target

### UI and payload

Target controls read URL, max pages, max depth, delay and same-origin.
Run click builds `{url,max_pages,max_depth,delay_ms,same_origin}`.
It sends `POST /api/target-map`; response returns `map_id`.
UI polls `GET /api/target-map?map_id=id` for progress/pages.
Cancel sends `DELETE /api/target-map?map_id=id`.
Export buttons serialize JSON, CSV or tree HTML locally.

### Django chain

`views.target_map` branches GET, DELETE and POST.
GET/DELETE require numeric `map_id` and call engine GET/DELETE.
POST parses JSON and calls `call_engine('/proxy/target-map', payload)`.
Malformed JSON is 400; engine errors are not hidden.
No Target result is automatically inserted into History or Traffic.

### Go chain

`targetMapStart` validates input and creates in-memory `targetMap` job.
A goroutine runs `runTargetMap` with context cancellation.
Crawler fetches pages through route transport and parses HTML links/forms,
JS/CSS/JSON references, `robots.txt` only for Sitemap references, and sitemap
XML locations. `Allow` and `Disallow` directives are intentionally ignored
because robots.txt is advisory, not an access-control mechanism.
`targetMapStatus` returns status, progress and pages.
DELETE cancels context and status becomes cancelled.

### State and outputs

Each page has URL, depth, status, content_type and kind.
UI stores `currentTargetMap`, filters/sorts visible rows and retains original indexes.
Tree renderer uses page indexes for action buttons after filtering.
Completed map is browser state plus Go memory until export.
Network errors become page/error state or top-level explicit failure.
Same-origin and limits are enforced by crawler, not browser JavaScript.
Symbols/files: `renderTargetMap`, export helpers and polling in `index.html`,
`target_map` in `views.py`, `targetMapStart`, `runTargetMap`,
`targetMapStatus` in `engine/main.go`.

## Деталі cancellation

Start stores the returned `map_id` in active target state.
Polling stops when status is completed, failed or cancelled.
Cancel is explicit and does not imply browser navigation.
A partial pages array remains inspectable after cancellation.
Export uses the last `currentTargetMap`, not a new engine request.
No SQLite or SSE persistence is performed for target pages.

## Трасування повного lifecycle

1. Оператор обирає static або browser-driven engine, navigation/form mode,
   browser runtime, URL, limits і optional click/fill actions.
2. UI будує payload і показує review перед запуском. Form mode без action або
   без окремого підтвердження не повинен стартувати.
3. Django перевіряє JSON і передає job у Go. Відповідь `202` із `map_id` є
   прийняттям job, а не завершенням crawl.
4. Go створює context, cancel function, queue, visited set і in-memory status.
   Static crawler читає HTML/resources; browser worker відкриває fixture/target,
   виконує дозволену navigation або form sequence і збирає network evidence.
5. UI poll-ить status, progress, pages/network evidence. Поки job running,
   cancel працює через DELETE і залишає вже зібрані сторінки inspectable.
6. Фінальний стан — completed, cancelled або error. Невдалий page request
   записується як page error, а не перетворюється на вигаданий успіх.
7. Renderer застосовує filter/sort, зберігає original indexes для action
   buttons і формує JSON/CSV/HTML/tree локально без нового crawl.
8. Передача endpoint у Repeater/Intruder/Scanner — це явна browser action;
   Target сам не створює History/Traffic record автоматично.
9. Workspace зберігає inputs і останній snapshot локально, але Go job memory
   зникає після restart, тому завершений результат треба експортувати.

### Lifecycle checkpoints

`review → POST → map_id → poll → evidence/pages → cancel/complete → export`
є canonical trace. Для browser-driven режиму додатково фіксуйте обраний
runtime, режим навігації, fixture URL, state-changing confirmation і фактичні
network rows.

The Go crawler keeps cancellation in the job context.
Status reads the same in-memory map object on every poll.
Gateway does not convert a cancelled job into completed success.
