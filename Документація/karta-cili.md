# Функція Target: повний шлях побудови карти

> Документація інструмента побудови карти цілі (Target Site Map & Crawler).
> Архітектура системи: [arkhitektura-ta-api.md](./arkhitektura-ta-api.md).

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
  "max_pages": 0,
  "max_depth": -1,
  "delay_ms": 100,
  "same_origin": true
}
```

Engine перевіряє absolute `http/https` URL та non-negative delay. Значення
`max_pages <= 0` і `max_depth < 0` означають необмежений crawl; позитивні
значення залишаються явними user parameters без верхньої межі. `targetMapStart()`
створює cancel context і memory state:

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

1. перевіряє page/depth/origin parameters;
2. очікує `delay_ms`;
3. робить GET через shared transport (`newCrawlerClient` із увімкненим ALPN `ForceAttemptHTTP2: true` — для HTTPS-цілей краулер автоматично здійснює обхід через HTTP/2);
4. читає status, content type і body;
5. додає URL, depth, status, type і kind у pages;
6. HTML parser знаходить links і forms;
7. static extraction знаходить JS/CSS/JSON references;
8. `robots.txt` обробляється лише як джерело `Sitemap:`-посилань; директиви
   `Allow`/`Disallow` не є policy-фільтром і не блокують crawl. Sitemap і XML
   `<loc>` додаються до queue;
9. нові URL фільтруються через same-origin і visited.

> **Підтримка HTTP/2 у краулерах:**
> - **Статичний краулер:** Завдяки `ForceAttemptHTTP2: true` на вихідному транспорті Go, запити до підтримуваних серверів надсилаються по протоколу HTTP/2 з мультиплексуванням.
> - **Browser-driven краулер (Browser-Worker):** Headless Chromium за замовчуванням нативно використовує протоколи HTTP/2 та HTTP/3 при завантаженні ресурсів, скриптів та виконанні AJAX/Fetch запитів.

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

## 4. UI: керування, експорт та передача карти

Панель керування Цілі розділена на два чіткі логічні рівні:

1. **Панель виконання краулера (`.target-run-toolbar`):**
   - **Побудувати карту** (`#target-start`) — запуск статичного або browser-driven обходу.
   - **Пауза** (`#target-pause`) та **Продовжити** (`#target-resume`) — призупинення та поновлення поточного обходу.
   - **Скасувати** (`#target-cancel`) — негайне скасування роботи через `DELETE /api/target-map`.
   - **Перевідправити недоставлені сторінки** (`#target-resend-failed`) — повторний запуск опитування для виявлених ресурсів, що завершилися мережевими збоями.

2. **Смуга експорту та передачі (`.target-transfer-bar`):**
   - **Єдине випадне меню «Експорт ▾»:** об'єднує формати експорту (JSON, CSV, HTML-звіт) в одному компактному меню, аналогічно до інших вкладок (Intruder, Scanner, OSINT). Експорт генерується локально з поточного `currentTargetMap` без повторного обходу мережі.
   - **Кнопки швидкої передачі (праворуч):**
     - `🤖 Надіслати карту до AI` (`#target-send-ai`) — прикріплює знімок поточної карти цілі (структуру URL, ендпоінти, виявлені статуси й JS-знахідки) до контексту AI-Агента та перемикає на вкладку Агента для комплексного аналізу поверхні атаки.
     - `🚀 Надіслати до Automation` (`#target-send-automation`) — передає зібрані URL цілі як стартовий датасет у вузли конструктора сценаріїв автоматизації.

Target results не додаються автоматично до History або Traffic, щоб не засмічувати лог сирих запитів. Проте за наявності активного проєкту (`Project`) завершене завдання автоматично індексується у базу знань: ендпоінти потрапляють у `ProjectEndpoint`, а виявлені сторінки, піддомени, сторонні домени та e-mail адреси автоматично додаються як сутності до графу `"Target observations"` у вкладці OSINT. Детальніше див. у [project-hub.md](project-hub.md#автоматична-інтеграція-знахідок-observations-ingest).

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
The export dropdown serializes JSON, CSV or tree HTML locally. Quick transfer buttons (`#target-send-ai` and `#target-send-automation`) pass the map payload to AI Agent or Automation workflows.

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
Same-origin та явні max-параметри перевіряє crawler, а не browser JavaScript.
Symbols/files: `renderTargetMap`, export helpers and polling in `index.html`,
`target_map` in `views.py`, `targetMapStart`, `runTargetMap`,
`targetMapStatus` in `engine/main.go`.

## Деталі cancellation

Start stores the returned `map_id` in active target state.
Polling stops when status is completed, failed or cancelled.
Cancel is explicit and does not imply browser navigation.
A partial pages array remains inspectable after cancellation.
Export uses the last `currentTargetMap`, not a new engine request.
Target pages are not persisted to PostgreSQL or SSE history.

## Трасування повного lifecycle

1. Оператор обирає static або browser-driven engine, navigation/form mode,
   browser runtime, URL, explicit max parameters і optional click/fill actions.
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
   у рядках таблиці лишено швидку іконку Repeater, решта ховається у плавуче
   меню `⋯` (`#ctx-menu`, тригери `data-ctx-target`/`data-ctx-network`):
   Intruder, Scanner (network rows), Send to Automation. Повторний клік по
   `⋯` закриває меню; шапка показує `#індекс · URL` рядка.
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

## 4. Аналіз JavaScript Source Maps та AST

Краулер Target автоматично перевіряє виявлені JavaScript-ресурси на наявність карт вихідного коду (Source Maps v3):
- **Виявлення директив**: шукає `//# sourceMappingURL=` та `//@ sourceMappingURL=` (у формі однорядкових та блочних коментарів `/*# ... */`), а також прямі `.map` файли;
- **Інлайнові Data URI**: декодує `data:application/json;base64,...` та URL-encoded джерела без додаткових мережевих запитів;
- **Розкриття структури проєкту**: витягує `sources`, очищує префікси збирачів (`webpack:///`, `vite://`, `turbopack:///`), сигналізує про виявлення чутливих файлів (`.env`, `admin`, `secret`, `auth`, `token`, `config`);
- **AST та синтаксичний видобуток ендпоінтів (`sourcesContent`)**:
  - Маршрути роутерів: Express, Koa, Fastify (`app.get('/api/...')`, `router.post(...)`);
  - Клієнтська навігація: React Router (`<Route path="..." />`, `path: "..."`), Vue, Angular;
  - HTTP-клієнти: `fetch('/...')`, `axios.get(...)`, `axios.post(...)`, `$.ajax(...)`;
  - Файлова конвенція Next.js: `pages/admin/users.tsx` → `/admin/users`, `app/api/.../route.ts` → `/api/...`;
  - Параметри запитів: виділяє параметри шляху (`:id`, `[id]`) та query-параметри;
- **Інтеграція у фронтир обходу**: чисті відносні та same-origin маршрути без невизначених динамічних виразів автоматично додаються до черги краулера (`analysis.links`);
- **Відображення у UI та експорті**: бейдж `JS` на карті Target відображає кількість оригінальних джерел (`sources`), знайдені ендпоінти маркуються типом `sourcemap`, а у вікні знахідок виводяться розкриті чутливі файли проєкту.
