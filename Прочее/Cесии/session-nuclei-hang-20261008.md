# Сесія: Nuclei — виправлення помилок сканера (продовження)

**Session ID:** ses_nuclei_hang_20261008
**Created:** 2026-10-08
**Продовження:** `session-ses_eece.md` (NUCLEI-JOB-HANG, NUCLEI-JAVASCRIPT-REPORT,
NUCLEI-CODE-FLAG)

---

## 🎯 Поточне завдання

- [ ] **NUCLEI-JOB-HANG-2** Продовжити виправлення помилок функції Nuclei.
      Оператор: «UI-скан триває 15 хвилин і не завершується, тоді як запуск тієї
      самої папки з терміналу завершується за кілька секунд» + дав еталонні команди
      запуску по кожному виду папок.

## Вхідні дані оператора (канонічні команди запуску)

```text
nuclei -target https://sberbank.ru -t code      --сode -esc -o code.txt
nuclei -target https://sberbank.ru -t dast      -dast  -esc -o code.txt
nuclei -target https://sberbank.ru -t dns              -esc -o code.txt
nuclei -target https://sberbank.ru -t file     -file   -esc -o code.txt
nuclei -target https://sberbank.ru -t headless -headless -esc -o code.txt
nuclei -target https://sberbank.ru -t helpers          -esc -o code.txt
nuclei -target https://sberbank.ru -t http             -esc -o code.txt
nuclei -target https://sberbank.ru -t javascript       -esc -o code.txt
nuclei -target https://sberbank.ru -t network          -esc -o code.txt
nuclei -target https://sberbank.ru -t nuclei-wordfence-cve -esc -o code.txt
nuclei -target https://sberbank.ru -t ssl              -esc -o code.txt
nuclei -target https://sberbank.ru -t cloud    -code   -esc -as -o code.txt
```

**Що з цього випливає для рушія (ще не реалізовано):**

| папка | capability-прапорець за командою оператора |
|---|---|
| `code` | `-code` |
| `cloud` | `-code` (+ `-as`) |
| `dast` | `-dast` |
| `file` | `-file` |
| `headless` | `-headless` |
| `dns`, `helpers`, `http`, `javascript`, `network`, `ssl`, `nuclei-wordfence-cve` | без додаткового прапорця |

Тобто **прапорець визначається видом вибраної папки**, а не вмістом кожного
документа. Це прямо суперечить поточній реалізації, яка читає capability з
кожного документа окремо.

---

## Виміряні дефекти (2026-10-08)

Корпус: `/home/kali/Desktop/DevBackUp-vecher07101/nuclei-templates/javascript`
(131 документ), nuclei v3.11.1, ціль — локальний `httptest`-сервер.

### 1. Рушій витрачає 340 с там, де термінал витрачає 14–79 с

| замір | час | записів |
|---|---:|---:|
| Рушій, `RunNucleiDir` (повний) | **364.6 с** | 131 |
| Рушій, тільки бінарник (`Transport: nil`) | **362.5 с** | 131 |
| Термінал, та сама папка, ті самі прапорці | **79.3 с** | 131 |
| Локальний копія папки, жива ціль, ті самі прапорці | **294.7 с** | 131 |

Локальний копія дає 294.7 с, рушій — 364.6 с. **Вартість локального runner-а
виміряна окремо: 2.1 с** — вона не є причиною.

Розподіл по батчах:

| батч | файлів | capability | час | exit |
|---|---:|---|---:|---:|
| 1 | 123 | (немає) | **337.7 с** | 0 |
| 2–9 | 1 кожен | `-dast` + id шаблону | 0.3 с кожен | **1** |

### 2. Вісім батчів	exit 1 — вони не виконують нічого

У 8 з 131 документів `BlockKeys` порожні, `Capabilities` порожні, але
`BlocksWithoutDeadline()` істинно (вони мають `payloads:` з `attack: clusterbomb`).
`groupByCapability` ставить їх у ключ `dast+<template-id>`, а `executeBatch`
бачить `Key.isolated()` → додає `-dast` і запускає на папці з **одним** файлом, де
немає fuzzing-шаблонів. nuclei v3.11.1 відповідає `[FTL] no templates provided for
scan`, exit 1, 0 записів.

Це рівно та причина, яку вже описано в `AGENTS.md` для `-dast`, але вона
застосувалася до `-dast`, виведеного з **синтетичного** capability, а не з
документа. Ключ `dast+<id>` — це не capability: `capabilityFlag["ldap-default-login"]`
не існує, і `capabilityFlagArgs` це мовчки пропускає.

### 3. Прогрес, який бачить оператор, нічого не повідомляє

Усі 371 рядок статистики за 364 с:

```text
phase=running percent=-1 templates=0 requests=0/0 matched=0
```

`percent=-1` + `templates=0` — це індикатор невизначеної довжини без жодного
числа. Оператор бачить «скан триває 15 хвилин», бо **протягом усієї роботи
рахівок не змінюється**. nuclei не має stats для `javascript`-протоколу, які
рахували б Documents, тому прогрес для цієї папки не з чого узяти.

Це пояснює `data-report-state="running"` при
`Matched: 4 · Not matched: 18 · No URL checked: 105 · Findings: 0` у знімку
оператора: 4 + 18 + 105 = 127 ≈ 131, тобто **батчі переважно відпрацювали**, а
завис саме *відлік*.

### 4. `-dast` неIsolation, а Capability-мисль

`BlocksWithoutDeadline()` правильно каже «цей документ не дає дедлайну» і
правильно вимагає окремий батч. Але групування реалізує це *у ключі
capability*, і键 `dast+<id>` потім читається як «потрібен `-dast`». Ізоляція
потрібна; прапорця — ні.

### 5. Уточнення оператора та перевірка через реальний Firefox

Оператор: «нет не грузит и запросы не идут — делать тесты только через реальное
открытие фаерфокс и загрузки папки», «бинарник в терминале и у меня работает».
На скриншоті: **`Uploading 0 of 131 · request 1 of 1`, таймер 1:57**, `templates 0`.

Firefox-прогін (`/tmp/opencode/firefox_upload_probe.py`, Playwright Firefox,
справжній `webkitdirectory` через `set_input_files`):

| папка | файлів | upload | jobs | stream |
|---|---:|---|---|---|
| `javascript` | 131 | **200 за 2.2 с** | 202 | 200 |

Тобто через Firefox з `javascript` завантаження **проходить**. Отже зависання на
скриншоті — не в 131 файлі і не в самому коді завантаження для цієї папки.

Лог оператора (`23:30:40`) показує той самий успішний upload:
`POST /api/scanner/nuclei/upload 200 57648` → `POST /api/scanner/nuclei/jobs 202 248`.
Тобто перший запуск **`javascript` стартував**. На скриншоті зависла друга,
`http`-спроба, або той самий стан після попереднього скана.

### 6. Що встановлено про «зависання» на живому стенді

Відтворення через gateway (131 файл, `https://yandex.ru`):

```
t=  3.0s running percent=0  templates=131 req=3/869
t= 60.0s running percent=60 templates=131 req=529/869
t=150.5s running percent=61 templates=131 req=535/869   <- 1-2 запити на 30 с
```

Останній запис у `data/logs/engine.log` — **16:43:36**; на момент перевірки
**16:46:35**, тобто три хвилини без жодного запиту при `state=running`.

Причина виміряна на процесі (`/proc/<pid>/fd`, `ss -tnp`):

```
ESTAB 10.0.2.15:59300 -> 77.88.44.55:445  users:(("nuclei",pid=181963,fd=18))
ESTAB 10.0.2.15:59378 -> 77.88.44.55:445  users:(("nuclei",pid=181963,fd=20))
ESTAB 10.0.2.15:44284 -> 77.88.44.55:445  users:(("nuclei",pid=181963,fd=23))
```

Це `javascript/misconfiguration/smb/*` і `default-logins/smb-*` з корпусу.
Три з'єднання SMB **не проходять через пасивний проксі** (у `ss` для
`127.0.0.1:8080` їх немає), тому вони **не пишуться в History** — і оператор
бачить «запити не ідуть», поки вони йдуть. nuclei спить, дочірніх процесів немає.

Це не зависання нашого коду: це те, що робить nuclei з SMB-шаблонами проти
хоста, який на 445 відповідає.

---

## Виправлені дефекти (усі виміряні)

### D1. SSE-кадри не мали роздільника — браузер не отримував НІЧОГО

`web/lab/views.py`, `scanner_nuclei_job_stream`: цикл проксі читав рядки і
передавав далі лише `if chunk.strip(): yield chunk`. **Порожній рядок — це
роздільник SSE-кадру**, і він ковтався. Усі кадри злипалися в один.

Виміряно до/після на одному job (`javascript/`, 131 документ, yandex.ru):

| | кадрів у потоці | байт |
|---|---:|---:|
| до | **1** | 23 670 |
| після | **73** | 23 670 |

Backlog другого підключення: `progress: 30, template: 54`.

У Firefox до правки: `events received: 0`, панель `Preparing`. Після:
`events received: 100` (`template: 58, progress: 42`), панель `Scanning`.

Зразок, який у тому ж файлі працює правильно — `traffic_stream`: `else: yield chunk`.

### D2. Панель не оновлювалася після останнього чанка — «Uploading 0 of 131»

`setScanProgress` усередині циклу виконується **перед** кожним `fetch`, і після
циклу оновлення немає. Для 131 файлу це один чанк, тому єдине оновлення панелі
описувало стан **до** останнього запиту.

Виміряно у Firefox: `Uploading 0 of 131 · request 1 of 1` → `Preparing` /
`templates 131`, статус `Scanning`.

Те саме з рядком стану: він ставився один раз перед першим чанком і більше не
мінявся.

### D3. Cancel не відпускав SSE — наступний upload стояв у черзі

`EventSource` тримає одне з 6 з'єднань браузера до хоста, поки він відкритий.
Cancel чекав `done`-кадру від job. Вихлів у двох місцях:

- Cancel: тепер закриває потік одразу після `200 {"state":"cancelled"}`;
- `runScannerTemplates`: попередній прогін звільняється **до** першого upload, а не
  після (`followScannerJob` робив це вже після запиту, який стояв у черзі).

Виміряно у Firefox: після Cancel `phase='Cancelled'`, кнопка Run **увімкнена**,
`stream closed: true`.

### D4. History не оновлювалася під час Nuclei-скану

History перезавантажувалася лише з трьох місць: Repeater, поллінг Intruder,
перемикання вкладки. Nuclei — у жодному.

Обміряно, що дані приходять: `total` 603 → 631 за 30 с прогону. Правка —
`refreshHistoryDuringScan()` з тротлінгом 4 с, лише коли вкладка History відкрита.

Firefox: `history GETs while scanning: 14` (було 0). Новітні рядки у History
підтверджено напряму через API:

```
2026-10-09 00:42:38 | proxy | https://yandex.ru/api/about
2026-10-09 00:42:38 | proxy | https://yandex.ru/api/home
total: 631
```

### D5. `-dast` давався 8 документам, які його не просили

`groupByCapability` кодував ізоляцію як capability-ключ `dast+<template-id>`, а
`executeBatch` читав перший токен як capability. Розділено на `needsReservedFlag`
(прапорець) і `runsAlone` (ізоляція).

Виміряно на живому бінарнику, копія одного документа корпусу:

```
nuclei -t <copy> -esc -nss        -> Templates loaded for current scan: 1
nuclei -t <copy> -esc -nss -dast  -> [FTL] no templates provided for scan
```

До правки: 8 інвакацій з `javascript/`, усі exit 1, 0 записів.

---

## Що НЕ закрито: застрягання на 62%

Виміряно на живому процесі (`ss -tnp`, pid 243268, 4:49):

```
1  5.255.255.77:445
1  5.255.255.77:80
```

Тримається **SMB на 445**. `javascript/misconfiguration/smb/*` і
`default-logins/smb-*` роблять `nuclei/smb`; yandex.ru приймає TCP на 445 і не
говорить SMB, тому клієнт чекає. `RPS` падає до 2.

Чи це поведінка нашого коду — перевіряється еталонним запуском оператора
(`nuclei -target https://yandex.ru -t javascript -esc`) на тому самому корпусі;
замір виконується, лог `/tmp/opencode/term-js.log`.

---

## Перевірки коду

| рівень | команда | результат |
|---|---|---|
| gofmt | `gofmt -l pkg/scanner/` | порожньо |
| build | `go build ./...` | rc=0 |
| vet | `go vet ./...` | rc=0 |
| тести | `go test ./pkg/scanner/ -count=1` | **ok 77.410s** |
| гонки | `go test ./pkg/scanner/ -count=1 -race` | **ok 90.489s** |
| все | `go test ./... -count=1` | rc=0, падінь немає |
| Python | `python -m py_compile web/lab/views.py` | rc=0 |
| inline JS | `node --check` (рецепт з `start.sh`) | rc=0, 1 029 135 байт |

---

## Файли, змінені цією сесією

- `engine/pkg/scanner/nuclei_document.go` — `parts`, `parseCapabilities`,
  `isolated`/`needsReservedFlag`/`runsAlone`
- `engine/pkg/scanner/nuclei_plan.go` — ключ ізоляції, `Describe()`-причина
- `engine/pkg/scanner/nuclei_exec.go` — пра星系ць читається як `needsReservedFlag`
- `engine/pkg/scanner/nuclei_isolation_flag_test.go` — **новий**, 7 тестів
- `web/lab/views.py` — SSE-кадри
- `web/templates/lab/index.html` — панель, Cancel, звільнення потоку, History


| команда | результат |
|---|---|
| `go build ./...` (engine) | rc=0 |
| `go vet ./pkg/scanner/` | rc=0 |
| `go test ./pkg/scanner/ -count=1` | **ok 14.712s** (до моїх правок) |
| `nuclei -validate -t javascript/` | All templates validated successfully |

Корпус `nuclei-templates/` у корені репозиторію встановлений сьогодні
(`nuclei -validate` сам встановив у `~/.local/nuclei-templates`, потім
`start.sh` поклав копію в корінь).

---

## Обмеження цієї ітерації

- `Cесии/SESSION-CLAIMS.md`, `DEVELOPMENT_LOG.md`, `ЗВІРЯННЯ_ІНСТРУМЕНТІВ.md`,
  `РЕЄСТР_ІНСТРУМЕНТІВ.md` тримає сесія `ses_integrations_20261008`
  (записи 15:1x–15:5x) — правити локально, не перезаписувати.
- `engine/nuclei_reconciliation.md` + `nuclei_reconciliation_test.go` створено
  тією ж сесією, `готово` — не чіпати.
