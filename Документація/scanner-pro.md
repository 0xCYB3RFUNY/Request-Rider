# Scanner Pro

> Актуально на 2026-09-25. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).
> Детальний перелік зняття application-level обмежень — у
> [звіті про видалені обмеження](видалені-обмеження.md).

## Призначення

Scanner Pro — read-only reconnaissance для HTTP(S) цілі.
UI прямо визначає межі: без exploit, fuzzing, brute force або access-control bypass.
Сканер збирає evidence, а не виконує активну атаку.
Результат не записується автоматично в History або Traffic.

## UI

Секція `#scanner` описана в `web/templates/lab/index.html`.

### Дві внутрішні сторінки

`#scanner-view-switch` перемикає **CMS scan** і **Nuclei scan**:

| view | панель | що робить |
|---|---|---|
| `cms` | `#scanner-panel-cms` | Safe CMS Recon через `POST /api/scanner` |
| `nuclei` | `#scanner-panel-nuclei` | реальний бінарник nuclei на завантажених шаблонах |

Спільні для обох view: смуга workspace-вкладок `#workspace-tabs-scanner`,
поле цілі `#scanner-url`, рядок стану `#scanner-status` і текстовий звіт
`#scanner-findings`. Кожен view має **власний** результат
(`scannerViews.cms.current`, `scannerViews.nuclei.current`) і **власний**
dropdown експорту (`#scanner-export-cms`, `#scanner-export-nuclei`), тому CMS
розвідка ніколи не перезаписує nuclei-звіт і навпаки.

Кожен workspace запам'ятовує, на якому view він залишився
(`captureWorkspaceState('scanner').view`), і повертається на нього при
перемиканні workspace.

> Рішення щодо однієї смуги workspace-вкладок, а не двох: `activeWorkspaceId`
> у спільному workspace-механізмі — одне глобальне значення, а
> `closeWorkspace` забороняє закрити останній workspace kind. Другий kind
> означав би правку ядра, яким користуються ще 10 інструментів. Split на view
> дає ту саму ізоляцію (кожен workspace присвячений одному виду скану) без
> зміни спільного коду.

### CMS scan

`#scanner-url` приймає адресу цілі, `#scanner-run` запускає Safe CMS Recon,
`#scanner-clear` очищає URL і результат CMS, `#scanner-send-ai` прикріплює
result до AI context, `#scanner-send-automation` передає його в Automation.

### Nuclei scan

Одне вікно завантаження приймає файли або папку; далі — опції, Run і
**таблиця результату по кожному YAML-файлу** `#scanner-tpl-body`
(File / Template / CVE·CWE / Status / Details). Лічильники —
`#scanner-tpl-perfile-stats`, фільтри — `#scanner-tpl-filter` (назва файлу, id
шаблону, CVE, CWE, теги), `#scanner-tpl-status`
(matched / not_matched / invalid) і `#scanner-tpl-only-matched`.

`runScanner` trim-ить URL і створює JSON payload:

```json
{"url":"https://example.test/"}
```

Fetch іде як `POST /api/scanner` з JSON content type.
Успішна відповідь кладеться у `currentScanner`.
`renderScanner` читає `summary`, `findings`, `details`.
Export buttons стають enabled після render.

## Django gateway

`web/core/urls.py` веде `/api/scanner` до `views.scanner`.
`views.scanner` дозволяє тільки POST.
JSON має бути object з непорожнім `url`.
Порожній або malformed payload дає HTTP 400.
Формат помилки gateway: `invalid scanner request: ...`.
Після validation викликається `call_engine('/proxy/scanner', {'url': ...})`.
Engine response status і JSON повертаються без прихованого успіху.

## Go endpoint

`engine/main.go` реєструє `POST /proxy/scanner`.
Handler декодує `scannerInput`.
Malformed JSON дає `400 INVALID_JSON`.
Не absolute HTTP(S) URL дає `400 INVALID_TARGET_URL`.
Помилка scan дає `502 SCANNER_CHECK_FAILED`.
Успіх — JSON HTTP 200.

Поруч зареєстровано `POST /proxy/scanner/nuclei`: приймає
`{url, files: [{name, path?, content}], tags?, severity?, options?}`, валідує
кожен файл, розкладає придатні у temp-dir одного запуску (з cleanup) і виконує
справжній Nuclei одним batch-запуском. Для великих папок є окремі
`POST /proxy/scanner/nuclei/stage` і `POST /proxy/scanner/nuclei/run`.
Помилка запиту — `400 INVALID_TEMPLATE`, помилка виконання —
`502 SCANNER_NUCLEI_FAILED`.

## Результат по кожному YAML-файлу

Відповідь `POST /api/scanner/nuclei` (і `POST /proxy/scanner/nuclei`) містить
три блоки:

- `findings` — плоский список знахідок у спільному scanner schema
  (`title`, `severity`, `evidence`, `template_id`, `matched_at`, а також
  `matcher_name`, `curl_command`, `extracted`, `description`, `cve`, `cwe`,
  `tags`, `author`, `references`, `type`, `ip`, `timestamp`);
- `templates` — **по одному рядку на кожен завантажений файл**:
  `name`, `template_id`, `title`, `severity`, `status`, `reason`, `cve`, `cwe`,
  `tags`, `author`, `matches`, `findings`;
- `stats` — `files`, `matched`, `not_matched`, `invalid`, `findings`,
  `exit_code`, `exit_status`, `binary`, `url`, `stderr`.

`status` має рівно три значення:

| status | значення |
|---|---|
| `matched` | файл завантажено і спрацював щонайменше один matcher |
| `not_matched` | файл відпрацьовано, збігів немає |
| `invalid` | файл не дійшов до scanner, `reason` пояснює чому |

Атрибуція знахідки до файлу робиться за `template-path`, який nuclei повертає
в JSONL для кожного запису. Тому один batch-запуск дає повну картину по кожному
файлу, а `cve` береться з `info.classification.cve-id` шаблону.

### Статуси HTTP

| ситуація | відповідь |
|---|---|
| є хоча б один придатний файл | `200` + `templates` для всіх файлів, де непридатні мають `status: invalid` |
| усі файли відхилено до запуску | `400` + `reason: SCANNER_NUCLEI_NO_VALID_TEMPLATES` + тим самим `templates` |
| бінарник не стартував / ctx скасовано | `502 SCANNER_NUCLEI_FAILED` |
| nuclei завершився з ненульовим кодом | `200`, у `stats.exit_status: failed`, `stats.exit_code`, `stats.stdout`/`stats.stderr` |

Останній рядок важливий: ненульовий exit не губить зібраний звіт. Раніше
ненульовий код із порожнім JSONL перетворювався на безлике
`nuclei failed: exit status 1`; тепер stderr бінарника захоплюється, ANSI
послідовності знімаються і причина показується в `stats.stderr` та в
`title` лічильника `#scanner-tpl-perfile-stats`.

## Завантаження: одне вікно для файлів і папок

`#scanner-upload-zone` — єдине вікно завантаження. Воно приймає і перетягнуті
файли, і перетягнуту папку (`DataTransferItem.webkitGetAsEntry()` з
рекурсивним обходом каталогів), а кнопки `Choose files` / `Choose folder`
відкривають відповідний picker. Реальні інпути `#scanner-yaml-file` і
`#scanner-yaml-dir` лишаються в DOM (приховані), тому ними можна керувати
програмно і з тестів.

`nuclei-templates/http/cves/2020` — це 316 файлів (0.71 МБ), а вся папка
`nuclei-templates` — 14021 файл / 34 МБ YAML. Django відхиляє POST понад
2.5 МБ, тому завантаження йде **чанками**.

## Чанкове завантаження і запуск

| крок | endpoint | роль |
|---|---|---|
| 1..N | `POST /api/scanner/nuclei/upload` | один чанк файлів → `upload_id` |
| фінал | `POST /api/scanner/nuclei/run` | запуск staged-шаблонів → per-file звіт |

Перший чанк надсилає порожній `upload_id` і отримує новий; кожен наступний
повторно використовує той самий `upload_id`, тому всі чанки потрапляють в
**один** staging-каталог. Розмір чанка — лише транспортна деталь
(`SCANNER_CHUNK_BYTES`, 900 КБ): ні кількість файлів, ні кількість байтів не
обмежені, число чанків просто росте.

Staging-каталог живе в engine (`POST /proxy/scanner/nuclei/stage`), тому браузер
ніколи не передає серверні шляхи. `run` забирає сесію, видаляє каталог і
повторно використати `upload_id` неможливо (`400 INVALID_UPLOAD`). Сесії, які
залишилися без запуску, прибираються sweep-ом через 2 години.

Перевірено: `cves/2020` (316 файлів) одним запитом і штучно розбитий на
16 чанків по 48 КБ — обидва випадки повертають 316 рядків per-file.

## Живий прогрес запуску

Довгий запуск більше не є одним блокуючим запитом: він виконується як
background-job, а браузер бачить реальні лічильники.

| крок | endpoint | роль |
|---|---|---|
| 1..N | `POST /api/scanner/nuclei/upload` | чанки файлів → `upload_id` |
| старт | `POST /api/scanner/nuclei/jobs` | `202` + `job_id` |
| опитування | `GET /api/scanner/nuclei/jobs/<id>` | `state`, `progress`, у кінці `result` |
| пауза | `POST /api/scanner/nuclei/jobs/<id>/pause` | `state: paused` |
| продовження | `POST /api/scanner/nuclei/jobs/<id>/resume` | `state: running` |
| скасування | `POST /api/scanner/nuclei/jobs/<id>/cancel` | `state: cancelled` |

`progress` — це лічильники самого бінарника, а не оцінка інтерфейсу:

```json
{
  "state": "running",
  "progress": {
    "phase": "running", "elapsed_seconds": 9.7,
    "templates": 315, "hosts": 1, "rps": 7,
    "matched": 2, "errors": 58,
    "requests_done": 68, "requests_total": 602,
    "percent": 11.3
  }
}
```

Джерело — рядки статистики nuclei, які бінарник пише у **stderr**. Формат
залежить від режиму, тому парсер приймає обидва:

- pipe-формат (без `-silent`):
  `[0:00:01] | Templates: 41 | Hosts: 1 | RPS: 23 | Matched: 0 | Errors: 0 | Requests: 29/60 (48%)`
- JSON (у JSONL-режимі, разом із знахідками в потоці):
  `{"duration":"0:00:01","templates":"80","requests":"27","total":"126","percent":"21", ...}`

Знахідка (`template-id`) ніколи не читається як статистика: JSON-статистика
відрізняється наявністю `templates` + `requests` + `total` і відсутністю
`template-id`. Будь-який інший рядок stderr (банер, `[INF]`, помилки прапорців)
просто потрапляє у діагностику.

`percent` дорівнює `-1`, поки nuclei ще не знає загальної кількості запитів —
тоді панель показує індикатор невизначеної довжини, а не вигаданий відсоток.

Перевірено на `cves/2020` (316 шаблонів): 315 завантажено, 68/602 запитів,
RPS 7, 58 помилок, 11%, завершення зі 316 рядками per-file.

### Панель прогресу в UI

`#scanner-progress` показує фазу, відсоток, таймер, лічильники та кнопки
`Pause` / `Cancel`. Стани:

| стан | вигляд |
|---|---|
| `queued` | підготовка або завантаження чанків, невизначений індикатор |
| `running` | реальний відсоток, лічильники, кнопка `Pause` |
| `paused` | бурштиновий акцент, не рухається, кнопка `Resume` |
| `completed` / `failed` / `cancelled` | без `Pause` і `Cancel` |

## Live-результати: SSE замість очікування кінця

Результати приходять **під час** сканування, як passive Traffic: одна подія на
файл, який nuclei вже обробив.

```
GET /api/scanner/nuclei/jobs/<id>/stream      (text/event-stream)
```

Події:

| `event` | `data` | що робить браузер |
|---|---|---|
| `progress` | `progress` з лічильниками nuclei | оновлює панель прогресу |
| `template` | один файл: `name`, `template_id`, `status`, `cve`, `evidence` | **додає один рядок** у таблицю |
| `done` | `state` і фінальний `result` | замінює потік на повний звіт і показує діагностику |

Кожна подія має монотонний `cursor` і `id`, тому перепідключення з
`Last-Event-ID` не дублює і не втрачає рядки.

### Чому це працює

Nuclei **дописує** JSONL-запис у файл `-o` щойно закінчив шаблон. Engine
читає цей файл у фоні (`watchOutput`) і перетворює записи на події. Тому:

- жодних змін у способі виконання шаблонів не потрібно;
- `-ms` дає запис і для шаблонів без збігів, тому live-подія приходить для
  кожного виконаного файлу, а «виконався» відрізняється від «не виконався»;
- підв'язка до конкретного файлу — та сама, що в фінальному звіті, за
  `template-path`.

Фінальна подія `done` несе авторитетний `result`: клієнт, який слухав лише
потік, все одно отримує всі файли, лічильники та повний висновок бінарника.

## Великий звіт: DOM не виростає до 14000 рядків

Папка `nuclei-templates` — це 14021 файл. Малювати по одному вузлу DOM на файл
заливало сторінку, а вкладка згодом падала — разом із результатами. Тепер:

- таблиця показує вікно в **200 рядків** і росте на вимогу;
- кнопка **«Показати ще · N з M»** живе поза таблицею, бо рядки верстуються
  ліниво (`content-visibility:auto; contain-intrinsic-size:auto 42px`) і кнопка
  всередині останнього рядка була б неклікабельною;
- `thead` прилипає до верху, тож колонки лишаються читабельними;
- **жоден файл не губиться**: повний звіт лишається в пам'яті, лічильники в
  рядку стану — справжні, а фільтр шукає по всіх файлах, а не по видимих.

Перевірено на 14000 файлів: 200 рядків на екрані, клік додає ще 200 за ~0.6 с,
пошук по 14000 рядків — 0.7 с, помилок у консолі немає.

## Пауза і продовження

Nuclei не має прапорця паузи, тому запуск зупиняється сигналом `SIGSTOP` і
продовжується `SIGCONT`. Це справжня пауза: процес зупинено цілком, тому
зберігаються всі запити, з'єднання та лічильники, і продовження починається
з того самого місця.

- Пауза можлива лише коли бінарник уже стартував; стан `queued` повертає
  помилку, а не прикидається, що сканування зупинено.
- Подвійна пауза не помилка, повторний `resume` для активного запуску повертає
  помилку.
- Скасування працює і на паузі: спочатку надсилається `SIGCONT`, інакше
  зупинений процес ніколи не побачив би скасування.
- `Apply route` скасовує паузу запуску: job живе в generation-контексті route, а
  не в контексті HTTP-запиту, який його запустив, тому він переживає запит, але
  не переживає зміну route.
- На платформах без `SIGSTOP` (`//go:build !unix`) пауза повертає
  `501 PAUSE_UNSUPPORTED`, а не імітує її.

## Опції сканування

Панель `Scan options` (`#scanner-options-wrap`) замінює інтерактивний набір
прапорців nuclei. Кожна опція відповідає **рівно одному** прапорцю; браузер
ніколи не надсилає сирий командний рядок.

**Завжди видимий рядок** (базовий web-скан): фільтри severity, темп і
редиректи.

| UI | flag |
|---|---|
| Severity (chips) | `-severity` |
| Exclude severity (chips) | `-es` |
| Concurrency | `-c` |
| Rate limit | `-rl` |
| Request timeout | `-timeout` |
| Follow redirects | `-fr` |

**Advanced options** (`#scanner-options-advanced`, згорнутий за замовчуванням):

| UI | flag |
|---|---|
| Template IDs | `-id` |
| Retries | `-retries` |
| Payload / Probe concurrency | `-pc` / `-prc` |
| Max redirects / Max host errors | `-mr` / `-mhe` |
| Exclude matchers | `-em` |
| Follow same-host redirects | `-fhr` |
| Headless | `-headless` |
| Use interactsh (OAST) | `-ni` коли вимкнено |
| Store request/response | `-sresp` |
| Omit raw request/response | `-or` (типово увімкнено) |
| Disable ANSI colours | `-nc` |
| Show matcher status | `-ms` |

### Severity — chips, а не список

`Severity` і `Exclude severity` — це групи перемикачів
(`.scanner-chip`, `aria-pressed`), а не багаторядковий `<select multiple>`.
Кілька рівнів обираються одночасно одним кліком, при цьому панель лишається
низькою. Значення — рівно ті, що приймає nuclei: `info`, `low`, `medium`,
`high`, `critical`, `unknown`.

### Прибрані з UI опції

`Tags` (`-tags`), `Exclude tags` (`-etags`), `Always include tags` (`-itags`),
`Protocol type` (`-pt`) і `Exclude template paths` (`-et`) **прибрано з
інтерфейсу**: для базового web-скану вони не дають практичної користі, а
`-pt` ще й має неприйнятний набір значень (`network`, `multipart` завершують
бінарник кодом 2). Вони **лишаються в API** движка
(`NucleiOptions.ExcludeTags`, `.IncludeTags`, `.Types`, `.ExcludeTemplates`) і
покриті тестами, тож ними можна скористатися скриптом.

### Правила валідації

- порожнє поле **не** додає жодного прапорця;
- явне значення опції має пріоритет над ENV-fallback
  (`RR_NUCLEI_RATE_LIMIT`, `RR_NUCLEI_EXEC_TIMEOUT_MS`), який діє лише коли
  опція не задана;
- `severity` і `exclude_severity` валідуються за набором nuclei;
- від'ємні числові значення відхиляються.

### `-ms` і хибні спрацювання

`-ms` (`matcher-status`) змушує nuclei писати в JSONL **запис для кожного
виконаного шаблону**, включно з провалами matcher, які мають
`"matcher-status": false`. Такі записи — **не знахідки**. `parseNucleiJSONL`
відкидає їх (`nucleiFinding.isFinding`), інакше звіт показував би кожен
запущений шаблон як вразливість. Поле `matcher-status` розбирається як
`*bool`, щоб відрізнити `false` від відсутності поля.

### Діагностика запуску

Nuclei пише помилки прапорців у **stdout**, а логи — у **stderr**, тому
захоплюються обидва потоки. При ненульовому коді `stats` містить
`exit_status`, `exit_code`, `stdout` і `stderr` (ANSI знято), а UI показує
хвіст діагностики в `#scanner-upload-progress` і в статусі.

## Export: меню з JSON / HTML / CSV

Експорт — це **меню**, а не нативний select і не окремі кнопки:

```text
[Export ▾]  →  JSON    Full report as-is
                HTML    Interactive report
                CSV     One row per file
```

`#scanner-export-cms` експортує результат CMS-розвідки,
`#scanner-export-nuclei` — nuclei-звіт. Тригер блокується, доки
відповідний view не має результату.

| формат | nuclei | CMS |
|---|---|---|
| `json` | повний звіт як є: `engine`, `templates[]`, `findings[]`, `stats`, `source_ip` | звіт `POST /api/scanner` як є |
| `csv` | таблиця `section, file, template_id, title, severity, status, cve, cwe, tags, matches, reason, matched_at, matcher, evidence`: `template` — рядок на кожен файл, `finding` — на кожну знахідку, `stats` — на кожен параметр | узагальнена `section, field, value` |
| `html` | інтерактивний звіт (див. нижче) | звіт без блоку шаблонів |

Поведінка меню (`initializeExportMenu`): клік по тригеру відкриває список і
передає фокус на перший пункт; `ArrowUp`/`ArrowDown` перемикають пункти;
`Escape` закриває список і повертає фокус на тригер; клік поза меню закриває
його; після вибору меню закривається, а тригер на 1.8 с показує підтвердження
`✓ JSON|HTML|CSV`. Тригер має `aria-haspopup="menu"`, `aria-expanded` і
`role="menu"`/`role="menuitem"`.

## Інтерактивний HTML-звіт

`scannerHtmlReport()` будує самодостатній документ у фірмовому стилі
RequestRider — ті самі токени (`--accent:#43d9a3`, `--purple:#a970ff`,
`--panel`, `--line`, `--radius`), той самий градієнт фону, ті самі форма chip
і моноширинні блоки, що й в застосунку.

Склад звіту:

- шапка з логотипом (inline SVG), назвою view і ціллю;
- картки-показники: файлів / спрацьвало / не спрацювало / некоректних /
  знахідок / найвища severity;
- таблиця **по кожному YAML-файлу** з фільтром-пошуком, табами статусів
  (All / Matched / Not matched / Invalid) і сортуванням по колонках
  File, Template, Severity;
- таблиця знахідок із `matched-at`, evidence, extracted і curl-командою;
- сітка статистики запуску.

Інтерактивність (`SCANNER_REPORT_JS`) працює поверх уже відрендерених рядків:
читання лише з `data-status`, `data-hay`, `data-name`, `data-title`, `data-sev`
та `textContent`. Жодного JSON-блаба і жодної вставки розMarkup із значення.

**Самодостатність і безпека**

- жодного зовнішнього ресурсу: немає `<link>`, `<img>`, `<iframe>` і CDN;
- усе значення проходить через `escapeHTML`: назви файлів, `evidence`,
  `curl-command`, CVE походять із цілі, шаблонів і виводу nuclei;
- теги `<script>` звіту збираються з частин (`'<' + 'script>'`), бо
  HTML-парсер завершує інлайн-блок на першому ж закриваючому тезі, навіть
  усередині JS-рядка або коментаря. Помилка тут зламала б **всю** сторінку
  застосунку, а не лише звіт.

## Файли, які nuclei не запустив: `skipped`

Nuclei завантажує **один файл на `template-id`**. Якщо два завантажених файли
оголошують однаковий id, перший виконується, а другий мовчки відкидається:
бінарник нічого не пише про нього, і старий звіт називав його
`not matched` з текстом «Template ran, no matches».

Відтворено на 9 файлах з 7 унікальними id: `executed=7 skipped=2`, а сам
бінарник у статистиці показує `templates: 7`. Таблиця тепер каже те саме, що
і лічильник, і в ній видно, який файл утримав id.

| статус | значення |
|---|---|
| `matched` | файл виконався і спрацював хоча б один matcher |
| `not_matched` | файл виконався, але ні один matcher не спрацював |
| `skipped` | **файл не виконувався**, у `reason` — конкретна причина |
| `invalid` | файл не дійшов до бінарника, у `reason` — причина відхилення |

`reason` для `skipped` називає файл, який зберіг той самий id:

```text
Not run: template id "smb-default-login" is already provided by smb.yaml,
and Nuclei loads one file per id.
```

Якщо причина не в дублікаті, `reason` не вигадує її, а наводить факти:

```text
Not run: Nuclei returned no record for template id "...". It loaded N
template(s) for these files and the active options were: <повний список прапорців>.
Full binary output is in the run diagnostics.
```

### Чим це доведено

Рух **завжди** запускається з `-ms` (`matcher_status`). Тільки цей прапорт змушує
nuclei писати JSONL-запис для кожного **виконаного** шаблона, тому множина
`template-path` у JSONL і є доказом того, що реально запускалося. Записи з
`matcher-status: false` знахідками не є — `isFinding()` їх відкидає, але сам факт
запису лишається доказом виконання.

Без `-ms` різниці «виконався без збігів» / «не виконувався» не існує: бінарник
не пише нічого. Тому `-ms` частина руху, а не опція, яку можна зняти.

Перевірено на справжньому бінарнику: 9 файлів / 7 унікальних id →
`executed=7 skipped=2 not_matched=7`, лічильник `templates: 7` збігається з
таблицею.

### Повний висновок бінарника

`stats` завжди містить `args`, `stdout` і `stderr` — не лише при помилці. Це
доказ для пропущеного файлу і для будь-якої помилки, тому нічого не обрізається
до «хвоста» і не підсумовується. UI показує їх у блоці
`#scanner-tpl-diagnostics` («Команда nuclei та весь її висновок»).

## Валідація шаблонів перед запуском

`parseTemplateDocument` повторює перевірки самого nuclei, щоб файл, який
nuclei мовчки відкине, не губився. Nuclei v3.x відкидає шаблон як
`invalid_template`, якщо немає `info.author`; коли це стосується всіх файлів,
бінарник завершується з `no templates provided for scan` і кодом 1.

Перевірки перед запуском (кожна причина пишеться у `reason`):

- розширення `.yaml` / `.yml`;
- непорожній вміст;
- валідний YAML;
- наявність кореневого `id`;
- наявність блоку `info` з `info.name` та `info.severity` із відомим значенням;
- наявність `info.author`;
- наявність хоча б одного request-блоку (`http`, `dns`, `network`, `file`,
  `headless`, `ssl`, `websocket`, `whois`, `code`, `javascript`, `multipart`).

Файл з `reason` не пишеться у temp-dir і не запускається. Нічого не
автовиправляється — движок не модифікує завантажені шаблони мовчки.

## Заливка файлів і структура папки

`UploadFile.Path` зберігає відносний шлях завантаження, а `StageUploads`
відтворює його в temp-dir. Це обов'язково: у пакунку templates різні
каталоги містять файли з однаковим basename (`CVE-2022-22965.yaml`,
`cloudflare.yaml`, `gradio-lfi.yaml`), і плоске розкладання за basename
перезаписувало б їх. Traversal (`..`) відхиляється запитом, а не
переписується. Колаізії однакового **відносного** шляху розводяться
суфіксом `-2`, `-3`.

Браузер передає `path` для кожного файлу: окремий файл — `rel || name`,
папка — `webkitRelativePath`.

## Зовнішній Nuclei engine (справжній бінарник)

`engine/pkg/scanner/nuclei_exec.go` запускає Nuclei як subprocess БЕЗ shell:
бінарник збирається в проект скриптом `run-engine.sh` (`bin/nuclei`,
pin v3.11.1) або береться системний, якщо вже стоїть; шлях перевизначається
`RR_NUCLEI_BINARY`. Базовий набір прапорів (`-u`, `-t <temp-dir>`, `-jsonl`,
`-duc`, `-silent`, `-o` у temp-файл) плюс валідовані опції з панелі
`Scan options`; жодних користувацьких прапорців. Optional ENV-параметри
`RR_NUCLEI_TIMEOUT_SEC`, `RR_NUCLEI_RATE_LIMIT` і
`RR_NUCLEI_EXEC_TIMEOUT_MS` додають відповідні flags лише при явному заданні
та лише коли опція не перекрита; upload byte/file ceilings відсутні. stdout і
stderr захоплюються; ненульовий exit не скасовує вже зібраний звіт. Відсутній
бінарник або скасований контекст — явна помилка, а не порожній успіх.
Endpoint `POST /proxy/scanner/nuclei`, `.../stage`, `.../run`; gateway
`POST /api/scanner/nuclei`, `.../upload`, `.../run`.
Покриття: stub-бінарник у тестах (герметично, справжній nuclei не потрібен).
