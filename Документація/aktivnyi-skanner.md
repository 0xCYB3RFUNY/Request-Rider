# Активний сканер

> Актуально на 2026-10-02. Загальні правила ітерацій і перевірок — у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).
> Чинне правило — жодних прихованих application-level обмежень у коді; явні
> технічні межі дозволені — у [AGENTS.md](../AGENTS.md).

## Що це

Активний скан обходить ціль і перевіряє кандидатів уразливостей дев'ятьма
модулями виявлення. Кожна знахідка отримує **рівень** — `verified` або
`potential` — ендпоінт і доказове поле, а коли модуль це дозволяє, окремий
**доказ впливу**: другий запит, який має спрацювати, щоб оператор побачив не
реакцію сервера, а наслідок.

Це `Scanner → Active & Corpus Scanner`, view вкладки Scanner. Він доповнює безпечну
CMS-розвідку, має власний результат, власний стан і власний експорт.

> **Межі роботи.** Сканер збирає доказ, а не виконує атаку: exploit, fuzzing,
> brute force і access-control bypass поза межами. Доказ впливу — це окремий
> запит із доведеним очікуваним наслідком, а не зміна стану цілі. Всі запити
> йдуть через той самий generation-aware passive proxy, що й Repeater, тому
> вони мають той самий route (Direct або SOCKS5/Tor) і `source_ip`, і видно в
> Traffic та History.

## Модулі виявлення

Реєстр і фіксований порядок прогону — `AllModulesWithMarker` у
`engine/pkg/active/scan.go`.

| Модуль | Рівень | Що перевіряє |
|---|---|---|
| `exposure` | endpoint | 13 патернів кредів у тілі відповіді: AWS AKIA, PEM `PRIVATE KEY`, GitHub токени, Stripe `sk_live_`, Slack `xoxb-`, connection string з паролем, JWT, Google `AIza`, Mailgun, Twilio. Привілейований сигнал має бути **структурним** (JSON-ключ у позиції значення або `input value=`), а не англійським словом у тексті |
| `misconfig` | endpoint | CORS (віддзеркалення `Origin`, medium без credentials, high з `Access-Control-Allow-Credentials`), відсутність CSP / `X-Content-Type-Options` / `X-Frame-Options` / HSTS / `Referrer-Policy`, directory listing |
| `redirect` | param | Open redirect через 12 векторів (plain, protocol-relative, backslash, userinfo confusion, encoded `@`, tab after scheme тощо) плюс клієнтський redirect через віддзеркалення маркера + навігаційний примітив |
| `ssrf` | param | 5 внутрішніх цілей: `127.0.0.1`, `localhost`, cloud metadata `169.254.169.254` і GCP `metadata.google.internal` (обидва critical), IPv6 `[::1]`. Правило: fingerprint є **і** payload не віддзеркалено verbatim — інакше нічого |
| `sqli` | param | Три техніки: error fingerprint (11 підписів СУБД × 12 breakout-probe), boolean-диференціал (7 пар, три умови одночасно), UNION (лише для числового baseline, з обов'язковою умовою, що відповідь довша за baseline і додана область порожня) |
| `xss` | param | Reflected XSS за контекстом. Крок 1 — canary віддзеркалено; крок 2 — HTML Content-Type; крок 3 — окремий запит `canary<`; крок 4 — ескалація під конкретний контекст (`html-body`, `attribute`, `script-string`). Підтвердження вимагає payload **всередині того самого тегу** з event-handler'ом |
| `lfi` | param | 6 технік: абсолютний шлях, traversal, змішаний `....//`, `/etc/shadow`, Windows `win.ini`, PHP-wrapper (fingerprint шукається в **декодованому** тілі) |
| `cmdi` | param | Ехо-техніка з 11 shell-синтаксисів і виразом `echo $((19*23))` = 437; сліпа техніка з 4 синтаксисами `sleep N` і порівнянням інкремента над baseline |
| `ssti` | param | 6 сімейств движків × 4 пари операндів. Умова: продукт свіжий, вираз **зник** із відповіді, є фрагмент |

Спільні примітиви — `engine/pkg/active/detect.go`: `Fresh`, `FreshFold`,
`Changed`, `Snippet`, `Divergence`.

## Рівні знахідки

| Рівень | Що означає |
|---|---|
| `verified` | Є fingerprint або другий запит, який підтвердив очікуваний наслідок. Це реальна знахідка |
| `potential` | Реакція відрізняється, але підтвердити не вдалося. Потребує ручної перевірки |

Доказ впливу має право підняти рядок до `verified` і дописає в evidence
`Confirmed by proof of impact: …` (`applyProofUpgrades`,
`engine/pkg/active/scan.go`).

## Доказ впливу

`Run` у `engine/pkg/active/exploit.go` будує `Proof` для доведених рядків.
Чотири генератори:

| Модуль | `kind` | Що робить |
|---|---|---|
| `sqli` | `data-extraction` | `UNION SELECT '<canary>',NULL…` з доведеним числом колонок, і перевірка, що маркер повернувся |
| `ssti` | `expression-evaluation` | `{{ '<canary>' ~ A*B }}`, де A і B виводяться з довжини canary |
| `cmdi` | `command-execution` | `; echo <canary>`, маркер має бути надрукований окремим рядком |
| `lfi` | `file-read` | Traversal глибиною, виведеною з глибини URL + 4 (мінімум 6), і читання `/etc/os-release` |

Рядок `potential` без доведеного числа колонок отримує proof лише тоді, коли
це можливо, і позначається `Upgrades = true`; решта лишається `potential`.
Рядки модуля `chain` proof не отримують узагалі.

## Ланцюжки

Сім правил у `engine/pkg/active/chain.go`. Ланцюжок, який не вдалося довести
сам, позначається `Potential … (unverified)` і обмежується рівнем medium.

`xss-to-account-takeover`, `lfi-to-rce` (log poisoning),
`sqli-to-auth-bypass`, `ssti-to-rce`, `cors-with-xss`,
`redirect-token-theft`, `ssrf-to-config-exposure`.

## Контроли в UI

Панель `#scanner-panel-active`, значення збирає `activeScanRequest`
(`web/templates/lab/index.html`).

| Поле | Тип | За замовчуванням | Що означає |
|---|---|---|---|
| `Max pages` | number | `0` | `0` = без межі |
| `Link depth` | number | `2` | `-1` = без обмеження глибини |
| `Workers` | number | `8` | Розмір пулу одночасних запитів |
| `Delay between probes` (ms) | number | `0` | Пауза між пробами |
| `Request timeout` (ms) | number | `15000` | Таймаут одного запиту |
| `Stay on the same host` | checkbox | увімкнено | `same_origin` |
| `Follow redirects` | checkbox | вимкнено | `follow_redirects` |

Межі не мають верхнього cap: `0` або `-1` означає «без межі», а будь-яке
введене число передається як є. Поле цілі — спільне з іншими view Scanner.

Життєвий цикл: `Start active scan` → `job_id` у `localStorage` → підписка на
`/stream` прогону → **рендер знахідок під час прогону** і прогресу. Після reload
прогін відновлюється: підписка без курсора отримує відтворений backlog, тож
таблиця знову має вже доведені рядки, а не порожню.

## Життєвий цикл і сховище

`POST /api/scanner/active/jobs` → `job_id`; `GET .../jobs/<id>` → стан, прогрес
і фінальний звіт; `POST .../jobs/<id>/<action>` (`cancel`, `pause`, `resume`) →
керування життєвим циклом (вивільнення сокетів на паузі, збереження точного часу
та безшовне відновлення); `GET .../jobs/<id>/stream` → SSE (`progress`,
**`finding`**, `pause`, `resend`, `done`). Також підтримується механізм повторної
відправки невдалих запитів (`resend`). Невідомий action повертає `400`.

### Живі рядки

`finding` несе **один доведений рядок у момент, коли його доведено**: рушій
публікує його з поверхні, яка його довела (`engine/pkg/active/scan.go`,
`Scan.announce`), а не з готового звіту. Подія ділить монотонний курсор із
`progress`, тому перепідключення не втрачає рядок і не показує його двічі, а
сторінка, що підпишелася після reload, отримує відтворений backlog.

Три межі, які варто знати перед покладанням на «живі» рядки:

| що | який стан у рядка |
|---|---|
| порядок живих рядків | порядок завершення поверхонь, а не канонічний порядок звіту; на `done` таблиця перемальовується звітом і порядок стає канонічним |
| `tier` | той, який дав детектор; `proof` може підняти його до кінця прогону, і підняття приходить разом із `done` |
| ланцюги | теж оголошуються (`Chains` завершився) — але після детекторів |

`done` несе фінальний звіт (із `proofs` і піднятими `tier`) і **замінює** живi
рядки цілком, а не дописує їх. Export під час прогону вимкнений: на екрані рядки
без proofs, а половина звіту, що скачалась би як звіт, гірша за відсутність
експорту до кінця прогону.

Запасний шлях — `GET .../jobs/<id>` раз на секунду — лишається для браузера без
`EventSource` і для обриву потоку. Він малює лічильники, а рядки — наприкінці.

Результат один раз записується в `ScannerRun` з `engine="active"`
(`web/lab/models.py`) і потрапляє в project bundle. Зберігаються рядки знахідок
і лічильники `stats`; `proofs` зберігається **лише як число**, а самі артефакти
доказу живуть у браузері та в експорті.

Прив'язка job → Project живе в `ActiveScanJob` (`web/lab/models.py`), тому
перезапуск gateway її не втрачає. Прогін, який завершився, поки ніхто не
опитував, підбирає `sweep_active_scan_jobs`.

## Експорт

`Export ▾` → JSON / HTML / CSV. HTML рендериться у браузері у фірмовому стилі,
самодостатний, без зовнішніх ресурсів; окрема гілка для `active` показує
картки verified / potential / сторінок / поверхонь / запитів і окрему таблицю
знахідок.

## Що варто знати перед покладанням на інструмент

Ці межі читаються з коду, а не з коментарів:

- `marker_host` і `interesting_paths` **не налаштовуються з UI**. Скан сам
  генерує canary-хост і використовує єдиний список цікавих шляхів; замінити
  його з браузера неможливо.
- Сліпа техніка `cmdi` завжди працює з `DefaultBlindDelay = 2s` — поля для
  нього в UI немає.
- `Missing Security Headers` приходить **окремим рядком на кожен ендпоїнт**:
  агрегований site-wide рядок існує в коді, але оркестрація його не викликає.
- PoC-скрипт повторного відтворення (`replay.go`) не доступний ані через
  engine-ендпоїнт, ані в UI — код існує, викликів і тестів немає.

## Код

- [engine/pkg/active/](../engine/pkg/active) — детектори, оркестрація,
  ланцюжки і доказ впливу
- [engine/scanner_active.go](../engine/scanner_active.go) — job рушія, SSE,
  retention
- [web/lab/active_scanner_views.py](../web/lab/active_scanner_views.py) —
  ендпоїнти шлюзу
- [engine/pkg/active/vexor_reconciliation.md](../engine/pkg/active/vexor_reconciliation.md)
  — звірка з upstream `github.com/0xamirdev/vexor`
