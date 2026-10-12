# Сесія 2026-10-09 — ECC-скіли, History-дефект, порожні комірки Scanner

## 🎯 Поточна задача
- [x] **[HIST-1]** nuclei-скан потрапляє в Traffic, але не в History — **ЗАКРИТО**
  - Причина: `/events` віддає список, `/events?detail=summary` — конверт
    `{"bodies_omitted":…,"events":[…]}`; `persist_proxy_history` приймає лише список.
  - Правка: `web/lab/views.py` view `traffic` — розгортає конверт перед персистенцією,
    сирі події в архів / очищені в браузер.
  - Тест: `TrafficSummarySnapshotArchiveTests` (3), файл 9/9 OK.
  - Наживо: той самий запит 0 → **1469** рядків, усі з `capture_context`, History
    повертає `nuclei · https://yandex.ru`.
  - Розділ у `DEVELOPMENT_LOG.md` записано.

## 📥 Беклог (від оператора)
- [x] **[TABLE-1]** «15 матчес, але в таблиці в деяких колонках的信息 порожня»
  - Скриншот: таблиця per-file Nuclei, колонки FILE | TEMPLATE | CVE/CWE | STATUS | DETAILS.
    У всіх рядків **DETAILS = «—»**, при тому що рядки мають MATCHED.
    Рядки — це згорнуті ГРУПИ по папках (`http/credential-stuffing/cloud [5]` і т.д.),
    знахідки лежать усередині `<details>` і в колонках не показані.
  - Супутньо: оператор каже «15 матчес», у шапці видно MATCHED 14, у баджах 5+1+1+5+1+1=14.
    Розбіжність 15 vs 14 не звірена — треба виміряти.
  - **Виміряно 2026-10-09 у Firefox (1356×652, реальний `webkitdirectory`-прогін):**
    `templates 1 requests 1 / 1 matches 1`, рядок `tpl1` має
    FILE `1 findings in the folder`, STATUS `MATCHED · 1`, **DETAILS `—`**,
    console чистий, `details_empty_count: 1`.
  - Причина встановлена читанням коду: комірка DETAILS у рядку-зведенні папки
    (`index.html:7095-7100`) малює лише `summary.reason`, а `reason` буває тільки
    у `invalid`/`skipped`/`duplicate` (`scannerTemplateTallyAdd`, 6854-6860).
    Для MATCHED його немає → «—». У зведенні немає й імен матчерів (`matchers` —
    0 збігів), тож показати знахідку там нема звідки, окрім як додати облік.
  - **Спірне питання, яке лишилося:** файловий рядок (`scannerTemplateRow`,
    7188-7201) читає правильні ключі — рушій `toMap()` дає `evidence`,
    `matched_at`, `matcher_name`, `curl_command`, `extracted`. Тобто розкриття
    папки може показувати знахідку правильно, і тоді дефект лише у рядку-зведенні.
    Перевіряється кліком по рядку (механізм — `row.addEventListener` →
    `toggleScannerTemplateFolder`, `index.html:7057`, а не `<details>`).
    Виміряно у Firefox: після кліку по рядку дочірній файловий рядок існує
    і його DETAILS **заповнена** — `https://yandex.ru` + `Matched yandex.ru at
    https://yandex.ru. Extracted: is_gdpr=1; …`. Отже файловий рядок правильний,
    а дефект лише у рядку-зведенні. (Механізм розкриття — клік по рядку,
    `row.addEventListener` → `toggleScannerTemplateFolder`, а не `<details>`;
    поперсняня `<details>` у моєму записі було помилковим.)
  - **Гіпотеза, яку я сам зняв виміром:** «неправильні імена полів у розгортці».
    Не підтвердилась — рушій `toMap()` віддає `evidence`, `matched_at`,
    `matcher_name`, `curl_command`, `extracted`, і UI читає саме їх. Не пишу її
    як причину.
  - **ВИПРАВЛЕНО (код).** `web/templates/lab/index.html`:
    1. `scannerTemplateTally()` отримав `matchers: new Set()`;
    2. `scannerTemplateTallyAdd()` збирає `finding.matcher_name` (приходить разом
       із фінальним звітом, тож рядок і файловий рядок наповнюються одночасно);
    3. новий `scannerFolderMatcherText(summary)` — спільне джерело тексту для
       таблиці й експортованого звіту: до 4 імен + `+N` (лише дані, без
       i18n-ключів; константа `SCANNER_FOLDER_MATCHERS_SHOWN`);
    4. комірка DETAILS зведення: `reason` → імена матчерів → «—»;
    5. той самий текст у **експортованому звіті** (`rr-folder-row`), де остання
       комірка мала ту саму прогалину;
    6. CSS: `td.scanner-folder-matchers` — моно-гарнітура (імена ідентифікаторів)
       і `word-break`, довгий список переноситься в клітинці.
    `node --check` rc=0 після кожної з правок.
  - **Перевірка в Firefox** (ui на 1356×652 і 1920×1080 + експортований HTML,
    твердження замість огляду): pid 546728, лог
    `/tmp/opencode/details_check.log`, скриншоти `/tmp/opencode/details-*.png`.
    Статус — чекає завершення.

## ✅ Виконано
- [x] **[ECC-1]** встановлення 302 скілів ECC + плагін у `.opencode/`
- [x] **[REV-1]** огляд коду за `owasp-security-code-review`: підтверджених вразливостей 0

## 📥 Беклог (від оператора, сесія 2026-10-09)

- [x] **[REV-2]** огляд Go на горутини/воркери/конкурентність/async/оптимізацію
  - 154 файли / 79 157 рядків, 43 точки запуску горутин. `go-review` skill
    непридатний (відсутні `scripts/prepare_review.py`,
    `prompts/clusters/manifest.json`, `skills-assets/skills-SpecterOps/`) —
    за його ж інструкцією прогін зупиняється, а не імітується.
  - **Знахідка 1, виправлено:** `source_ip` робив один зовнішній lookup на кожен
    логічний обмін, кожен через **новий** `http.Transport` (`DisableKeepAlives`),
    без жодної межі. Виміряно: 443 події з `source_ip`, усі з однаковим
    `149.34.244.140`.
  - **Уточнення власного вимірювання:** спершу записав «до 102 одночасних
    TLS-з'єднань» як доказ. Неточно: знімок показував з'єднання движунка
    **загалом**, і вони йшли переважно до цілі (`95.163.218.220`,
    `93.158.134.144`, `77.88.55.88`), а не до `check.torproject.org`
    (`116.202.120.181`). Правильний доказ — 443 запити + код.
  - Правка: семафор `sourceIPLookupSlots` (`RR_SOURCE_IP_LOOKUP_CONCURRENCY`,
    дефолт 8), **два шляхи** — асинхронний чекає до своєї межі, `ensureSourceIP`
    (операторські дії) не чекає взагалі; значення в видимому блоці `bound`.
  - Наживо після правки: пік до `check.torproject.org` = **6**, межа 8 у відповіді
    движунка. Django: 958 тестів OK. Тести Go: 6 нових + 2 наявні про
    `ensureSourceIP` — 8/8.
  - **Знахідка 2 (моя регресія, виправлено):** розділення `lookupSourceIP` на
    дві функції перенесло обмежене читання тіла, і
    `http_bounds_test.go` (`TestTargetResponsesAreStillReadWhole`) це зловив:
    його реєстр іменує функцію, де читання має бути. Реєстр оновлено на
    `lookupSourceIPWithSlot`; тест зелений.
  - Категорії без дефектів: таймери (13/13 зі `Stop`), `wg.Add` у горутині (0),
    замок під I/O (1 — `cond.Wait()`, канонічний `sync.Cond`), надсилання без
    `select` (0), `panic` у горутині (0).

- [x] **[ЧУЖЕ, не чіпаю — виявилося transient]** `engine/subfinder_reconciliation_test.go`
  (`TestTheSourceCountIsMeasuredNotGuessed`, `TestEveryKeyedSourceIsCounted`) двічі
  впав із `source submd has no readable KeyRequirement()`. Після того, як сусідня
  сесія дописала свій файл, **повний `go test .` зелений** (`ok 125.770 s`), тож
  падіння були transієнтними, а не стабільними. Нічого не чіпав.

- [ ] **[ПОТРЕБУЄ РІШЕННЯ ОПЕРАТОРА]** У dev-БД `requestrider` **4293 рядки
  `TrafficRecord`** від моїх діагностичних прогонів проти `yandex.ru`
  (proxy 2419 + tool 1874). Це сміття діагностики в робочій базі. Не чищу
  самостійно — це дані оператора; команда, якщо треба:
  `POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=55433 POSTGRES_USER=$(id -un) POSTGRES_DB=requestrider .venv/bin/python -c "…TrafficRecord.objects.all().delete()"`
  або кнопкою `Clear` у вкладці Traffic (вона доходить до сховища).


## 📥 Беклог (від оператора, сесія 2026-10-10)

- [ ] **[REC-1]** Звірка движунка з оригіналом на живій цілі: прогнати **весь
  корпус** шаблонів через продукт і порівняти з прямим запуском nuclei.
  Перевірити: (1) що знахідки повні; (2) що дані рядка збігаються з тим, що
  дав nuclei; (3) розбіжність лічильників (пункт «15 проти 14») і механізм
  `dedupeFindings`.
  Мета — не «скільки знайшло», а **де наш звіт розходиться з оригіналом** і
  де втрачається.

## ✅ Виконано (закрито)

- [x] **[HIST-1]** History не заповнювався — виправлено, доведено наживо (0 → 1469, потім 4293).
- [x] **[TABLE-1]** порожня комірка DETAILS — виправлено, Firefox PASS 8/8 на обох розмірах + звіт.
- [x] **[REV-2]** огляд конкурентності Go — 1 реальна знахідка (`source_ip` без межі), виправлено й виміряно.
- [x] **[REV-1]** огляд безпеки — підтверджених вразливостей 0.
- [x] **[ECC-1]** 302 скіли ECC + плагін у `.opencode/`.

### Фінальні перевірки

`go test . -count=1` ok 125.770 s · `go test . -count=1 -race` ok 168.926 s ·
`go test ./... -count=1` усі пакети ok (`pkg/active` 547.405 s) · `go vet ./` rc=0 ·
Django 958 тестів OK (skipped=1) · `manage.py check` 0 · `git diff --check` чисто ·
`node --check` rc=0 · Firefox 1356×652 і 1920×1080 PASS 8/8 ·
History наживо 4293 рядки з контекстом.

## 📥 Бэклог (Pending Tasks) — зауваження оператора 2026-10-10 ~04:40

- [x] **[SCAN-404]** Scanner/nuclei: «Run failed: 404» на вкладці Scanner (Checks: 6521, unique paths: 5832, in corpus: 6521).
      Симптом: прогон падає з HTTP 404, находок немає. engine і Django живі (health 200,
      POST /api/target-map 202). Треба знайти, який запит дає 404 (ймовірно job, втрачений
      через рестарт engine) і що саме показує UI.
- [x] **[SCAN-SSE]** Scanner: находки не приходять у реальному часі через SSE
      (`GET /api/scanner/nuclei/jobs/<id>/stream` за контрактом є — перевірити, чи працює).
- [x] **[SCAN-CANCEL]** Scanner: немає кнопки скасування прогону (контракт: `POST .../<id>/cancel`).
- [ ] **[SCAN-PERSIST]** Scanner: стан не переживає перезавантаження сторінки.
- [ ] **[PROXY-PERF]** Заміряти ефект пулу апстрім-сокетів на живій цілі (завдання попереднього кроку).

## Статус на 2026-10-10 ~07:0x

- **[SCAN-404]** закрито частково. Причина: двигунок тримає corpus-job у пам'яті, а я
  перезапускав його тричі під час роботи над проксі — прогон оператора з 404 був
  втрачений разом із процесом. Тепер UI каже про це прямо (`scanner.corpusLost`),
  а не «Run failed: 404».
- **[SCAN-SSE]** закрито. `GET /api/scanner/corpus/jobs/<id>/stream`: `snapshot` →
  `progress`/`finding` → `done`. Виміряно крізь Django: 140 кадрів `progress` за прогін.
- **[SCAN-CANCEL]** закрито. Дві причини, обидві виміряні: (1) у розмітці кнопки не було
  взагалі; (2) `run()` замінював `job.cancel` на no-op, тому `DELETE` доходив до порожньої
  функції. Жива перевірка: `running → cancelled` за 4 с.
- **[SCAN-PERSIST]** відкрито: не перевірено в Firefox після reload. `requestriderCorpusState`
  і `requestriderRestoreCorpus` у коді є, але доказу в браузері ще немає.
- Знайдено й виправлено два дефекси за скриншотами оператора: усі находки злипалися в один
  рядок (ключ читав camelCase, а `CorpusFinding` без JSON-тегів) і рядок не розкривався.
