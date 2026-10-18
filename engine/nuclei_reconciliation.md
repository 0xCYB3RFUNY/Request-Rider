# nuclei — реєстр звірки

Реєстр перенесення `projectdiscovery/nuclei/v3` у рушій сканування RequestRider
(`engine/pkg/scanner/`).

**Upstream-коміт, звірка проти якого зроблена: `v3.11.1`**
(`github.com/projectdiscovery/nuclei/v3`, ліцензія MIT, версія з `go.mod:11`).

## Чому реєстр для nuclei з'явився саме зараз

`АУДИТ_ІНТЕГРАЦІЙ.md` назвав nuclei **головним інструментом проєкту, для якого
реєстру немає взагалі**, і поставив його першим пунктом. Виміряно: до 2026-10-08
файлів `*nuclei*reconcil*` у дереві не було жодного. Сім інших реєстрів у проєкті
існують, правило «сверка з оригіналом» вимагає рядок на кожну здатність оригіналу,
і nuclei був єдиним з чотирьох зовнішніх пакетів, хто його не мав.

## Підсумок вимірювання

| що | число |
|---|---:|
| прапорців у `nuclei -h` v3.11.1 | **229** |
| прапорців, які цей проєкт передає | **39** |
| протоколів у `pkg/protocols/` | **13** плюс `offlinehttp`, `common`, `utils` |
| секцій документа, які `parseTemplateDocument` приймає | **20** |
| рядків у цьому реєстрі | **58** |
| `не перенесено` | **12** |

Числа різні й не додаються: 229 — це прапорці командного рядка, 13 — це протоколи,
20 — секції YAML. «39 з 229» — це частка **інтерфейсу**, а не частка здатностей,
і нижче це пояснено.

## Три речі, які треба сказати перед таблицею

**1. Nuclei запускається зовнішнім процесом, а не вбудовується.** Тому «перенесення
здатності» для nuclei означає не переписану функцію, а **присутність потрібного
прапорця у векторі аргументів, або присутність потрібного поля у розборі JSONL**.
Реєстр фіксує саме це, і це перевірювано: `buildNucleiArgs` і `nucleiFinding`
лежать у дереві, а тест шукає їх.

**2. 39 передаваних прапорців — це не 39 з 229 «здатностей».** Upstream має 229
прапорців, але більшість з них — це або шлях передавання даних (`-o`, `-l`, `-u`,
`-sfv`), або режими роботи з самим собою (`-validate`, `-update`, `-reset`,
`-project`), або діагностика (`-stats`, `-vv`, `-elog`). Для оператора цінність має
не кількість, а те, чи може він цим керувати. Тому нижче capabilities розбито на
**три групи** і кожна має власну оцінку.

**3. Verdict `не перенесено` ≠ «зламано».** Nuclei — це зрілий інструмент, і
більшість того, чого тут немає, не бракує: або це контроль над самим nuclei
(його власний `-project`, `-resume`, `-stats`), який ми свідомо замінили власним
обліком, або це формат виводу для чужого споживача (SARIF, markdown, ES, Splunk,
Mongo), який не має сенсу всередині веб-інструмента.

## Група A — секції документа (протоколи)

Перелік знято з `pkg/protocols/protocols.go` і з `protocolBlocks` нашого
`nuclei_document.go`.

| # | здатність оригіналу | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---:|---|---|---|---|---|---|
| 1 | `http` протокол | `pkg/protocols/http` | `супадає` | `protocolBlocks[http]` | секція приймається, документ планується, рядок звіту має `type: http` | `protocolBlocks` |
| 2 | `requests` (застаріле написання) | `pkg/protocols/http` | `супадає` | `protocolBlocks[requests]` | nuclei v3.11.1 ще розбирає; тип звіту — `http`, тому що саме так бинар пише | `protocolBlocks` |
| 3 | `dns` протокол | `pkg/protocols/dns` | `супадає` | `protocolBlocks[dns]` | те саме | `protocolBlocks` |
| 4 | `ssl` протокол | `pkg/protocols/ssl` | `супадає` | `protocolBlocks[ssl]` | те саме | `protocolBlocks` |
| 5 | `websocket` протокол | `pkg/protocols/websocket` | `супадає` | `protocolBlocks[websocket]` | те саме | `protocolBlocks` |
| 6 | `whois` протокол | `pkg/protocols/whois` | `супадає` | `protocolBlocks[whois]` | те саме | `protocolBlocks` |
| 7 | `tcp` / `network` протокол | `pkg/protocols/network` | `супадає` | `protocolBlocks[tcp]`, `protocolBlocks[network]` | обидва написання приймаються: `network` — застаріле, `tcp` — поточне, і nuclei звіряє їх із типом `tcp` | `protocolBlocks` |
| 8 | `headless` протокол | `pkg/protocols/headless` | `супадає` | `protocolBlocks[headless]` + `CapabilityHeadless` | праорець `-headless` додається за наявності документа; браузер у нас окремий сервіс, але рух шаблону — nuclei | `capabilityFlag` |
| 9 | `javascript` протокол | `pkg/protocols/javascript` | `улучшено` | `javascriptAddressesTarget` | **Класифікація змінилася 2026-10-06.** Усі `javascript`-блоки раніше вважалися локальними (`Requestless()` → `no_request`), через що 105 з 131 шаблон показували «No URL checked: 105». Тепер документ читається: `nuclei/net`, `nuclei/ssh`, будь-який невідомий модуль і виклики `isPortOpen(`/`isUDPPortOpen(` вважаються адресними; локальними лишаються лише `nuclei/bytes` і `nuclei/fs` | `javascriptAddressesTarget` |
| 10 | `code` протокол | `pkg/protocols/code` | `супадає` | `protocolBlocks[code]` + `CapabilityCode` | праорець `-code` обов'язковий для документа, і `-code` приходить саме з цієї здатності | `capabilityFlag` |
| 11 | `file` протокол | `pkg/protocols/file` | `супадає` | `protocolBlocks[file]` + `CapabilityFile` | те саме з `-file` | `capabilityFlag` |
| 12 | `fuzzing` (DAST) протокол | `pkg/fuzz` | `улучшено` | `CapabilityDAST` | `-dast` винесено в **ізольований** виклик. Виміряно 2026-10-02: `-dast` у спільному виклику на змішаній папці друкує `[FTL] Could not run nuclei: no templates provided for scan` і виходить 1, тобто скасовує весь виклик — 54 файли корпусу були втрачені при коректному плані | `capabilityFlag` |
| 13 | `workflows` секція | `pkg/workflows` | `супадає` | `protocolBlocks[workflows]`, `IsWorkflow`, `WorkflowReason`, `-w` | `-w <dir>` передається поруч із `-t`, і вердикт `workflow` має власну причину, бо workflow не знаходить сам по собі | `IsWorkflow` |
| 14 | `flow:` верхнього рівня | `pkg/workflows` | `улучшено` | `IsFlow`, `FlowReason`, вердикт `flow` | Виміряно: `flow: http(1) && http(2)` **виконується** без додаткового прапорця, тому статус не «не виконується», а «цей прогін не дав запису» | `IsFlow` |
| 15 | `offlinehttp` | `pkg/protocols/offlinehttp` | `не перенесено` | — | причина: причина: `offlinehttp` читає локальний HTTP-файл замість мережевого запиту; у нас такий шаблон проходить як `file`, а окремий протокол дав би два рядки на одне й те саме читання | `protocolBlocks` |
| 16 | `multi`, `ssl-request`, `jarm`, `asn`, `port` | `pkg/templates` (секції) | `улучшено` | `protocolBlocks` | nuclei v3.11.1 розбирає ці секції; ми їх **приймаємо в парсері**, щоб документ не потрапляв у `invalid`, інакше бінарник не отримав би його | `protocolBlocks` |

## Група B — можливості движка

| # | здатність оригіналу | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---:|---|---|---|---|---|---|
| 17 | Capability `code` | `pkg/templates/templates.go` | `супадає` | `CapabilityCode` → `-code` | праорець додається за наявності `code:`-документа | `capabilityFlag` |
| 18 | Capability `file` | там само | `супадає` | `CapabilityFile` → `-file` | те саме | `capabilityFlag` |
| 19 | Capability `headless` | там само | `супадає` | `CapabilityHeadless` → `-headless` | те саме | `capabilityFlag` |
| 20 | Capability `dast` | там само | `улучшено` | `CapabilityDAST` → `-dast` | рядок 12: ізольований виклик замість спільного | `capabilityFlag` |
| 21 | Capability `global-matchers` | `pkg/templates`, `-egm` | `не перенесено` | — | причина: `global-matchers` — це шаблони, які **не виконуються**, а лише оголошують спільні matcher-и для інших. Наш звіт вимагає одного вердикту на файл, а такий файл не має нічого перевіряти; він прийнятий парсером і приходить без запису | `protocolBlocks` |
| 22 | Capability `self-contained` | `-esc` | `супадає` | `CapabilitySelfContained` → `-esc` | `-esc` обов'язковий у кожному виклику, як вимагає правило оператора 2026-10-05 | `capabilityFlag` |
| 23 | `-ms` (`matcher-status`) | `cmd/nuclei/main.go` | `супадає` | `-ms` | обов'язковий: без нього nuclei не пише JSONL-запис для виконаного шаблону, і «виконався, нічого не знайшов» не відрізняється від «не виконався» | `buildNucleiArgs` |
| 24 | `-nss` (`-no-strict-syntax`) | там само | `супадає` | `-nss` | обов'язковий: `-validate` приймав документ, а `-t` відмовлявся від нього (`no templates provided for scan`) | `buildNucleiArgs` |
| 25 | `-it` (ігнорувати `.nuclei-ignore`) | `pkg/catalog/disk` | `улучшено` | `-it <dir>` | Виміряно 2026-10-06 на корпусі 13 764 файлів: 91 файл приходив `skipped` без причини, бо nuclei власним списком ігнорування не запускав їх. Оператор ці файли завантажив сам | `buildNucleiArgs` |
| 26 | Розкладка по `template-id` | `cmd/nuclei/main.go` | `улучшено` | `nucleiPlan` | Бінарник завантажує **один** файл на id. На корпусі 76 731 id несуть більше одного документа, тож без розкладки мовчки втрачалося не менше 76 731 шаблонів | `BuildPlan` |
| 27 | Дедуплікація за вмістом (SHA-256) | `pkg/reporting/dedupe` | `улучшено` | `DedupeStaged` | Копія не видаляється, а отримує власний рядок зі статусом `duplicate` і причиною — це `не перенесено` з боку оригіналу, але не втрата доказу | `DedupeStaged` |
| 28 | Пауза/продовження як `SIGSTOP`/`SIGCONT` | `cmd/nuclei` | `супадає` | `PauseNucleiJob` | відсутнього в nuclei прапорця немає; пауза зроблена сигналами, тому запити, з'єднання і лічильники зберігаються | `PauseNucleiJob` |
| 29 | Живий потік результатів | `pkg/output`, `-o` | `улучшено` | `nuclei_events.go`, SSE | nuclei дописує JSONL у `-o` лише завершивши шаблон, тому engine читає файл у фоні і віддає події через SSE з `id`/`cursor` | `TemplateEvent` |
| 30 | `-rate-limit` | `cmd/nuclei/main.go` | `супадає` | `-rl` | **Виміряно 2026-10-08: праорець вже передається** (`nuclei_options.go`, `RateLimit`). `АУДИТ_ІНТЕГРАЦІЙ.md` писав «не передаємо» — це було правильно для його дати і неправильно зараз | `buildNucleiArgs` |
| 31 | `-rld` (вікно rate-limit) | там само | `супадає` | `-rld` | окреме поле `RateLimitDuration`, бо «5 на секунду» і «300 на хвилину» — різні твердження | `buildNucleiArgs` |
| 32 | `-per-host-rate-limit` | там само | `не перенесено` | — | причина: обмеження на хост, а не на процес. Наш контроль — на процес; для нашого сценарію (одна ціль за прогін) різниця не спостерігається, а другий праорець без першого не має сенсу | `NucleiOptions` |
| 33 | `-exclude-severity` | `-es` | `супадає` | `-es` | **Виміряно 2026-10-08: вже передається.** Аудит писав «не передаємо» | `buildNucleiArgs` |
| 34 | `-exclude-tags` | `-etags` | `супадає` | `-etags` | **Виміряно 2026-10-08: вже передається.** Аудит писав «не передаємо» | `buildNucleiArgs` |
| 35 | `-exclude-id`, `-exclude-matchers`, `-exclude-type` | `-et`, `-em`, `-pt` | `улучшено` | `-et`, `-em` | `-pt` **не** передається ніколи: виміряно, що він **замінює** перелік типів, а не додає до нього, тому на змішаній папці він дає 0 шаблонів | `buildNucleiArgs` |
| 36 | `-crawl` | `cmd/nuclei/main.go` | `не перенесено` | — | причина: обхід виявлених шляхів у nuclei й обхід у `pkg/active`/`target` — дві різні речі з різним обліком; у нас краулер уже є окремою фічею Target, і друга копія тут була б паралельним шляхом | `BuildPlan` |
| 37 | `-resume` | `pkg/types/resume.go` | `не перенесено` | — | причина: `types.ResumeScan` відновлює прогін у процесі nuclei, а у нас прогін live-job у PostgreSQL і переживає перезапуск сам; два механізми відновлення дали б два джерела правди | `sweepFinishedJobs` |
| 38 | `-automatic-scan`, `-preflight-portscan` | `cmd/nuclei/main.go` | `не перенесено` | — | причина: обидва роблять **вибір цілей** замість оператора. Оператор обирає сам — це правило проєкту, і автоматичний вибір цілей у ньому прямо заборонений | `NucleiRequest` |
| 39 | `-project` / `-project-path` | `pkg/projectfile` | `не перенесено` | — | причина: сховище прогонів nuclei дублює `ScannerRun` у PostgreSQL; два сховища одного прогону дають розходження | `nucleiJobs` |
| 40 | Експорт звіту: SARIF / markdown / ES / Splunk / Mongo | `pkg/reporting/exporters` | `не перенесено` | — | причина: це споживачі для чужого конвеєра. У нас звіт іде в UI, HTML/JSON/CSV, які вже є; SARIF має сенс у CI, якого в проєкті немає | `nucleiFinding` |

## Група C — дані результату

Знято з `pkg/output/output.go`, `ResultEvent`.

| # | поле оригіналу | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---:|---|---|---|---|---|---|
| 41 | `info` (name, author, tags, severity, description, reference, classification) | `pkg/output/output.go` |`супадає`| `nucleiFinding.Info` | розбирається повністю; `cve-id`/`cwe-id` дають CVE/CWE у звіті | `nucleiFinding` |
| 42 | `template-id`, `template-path` | `pkg/output/output.go` |`супадає`| `nucleiFinding.TemplateID/TemplatePath` | атрибуція рядка до файлу йде саме через них | `nucleiFinding` |
| 43 | `type`, `host`, `port`, `scheme`, `url`, `path`, `ip` | `pkg/output/output.go` |`супадає`| `nucleiFinding` | усі сім полів присутні | `nucleiFinding` |
| 44 | `matched-at`, `matcher-name` | `pkg/output/output.go` |`супадає`| `nucleiFinding.MatchedAt/MatcherName` | те саме | `nucleiFinding` |
| 45 | `extracted-results` | `pkg/output/output.go` |`супадає`| `nucleiFinding.ExtractedResults` | те саме | `nucleiFinding` |
| 46 | `curl-command` | `pkg/output/output.go` |`супадає`| `nucleiFinding.CurlCommand` | команда відтворення потрапляє у звіт | `nucleiFinding` |
| 47 | `timestamp` | `pkg/output/output.go` |`супадає`| `nucleiFinding.Timestamp` | те саме | `nucleiFinding` |
| 48 | `request`, `response` | `pkg/output/output.go` |`супадає`| `TemplateEvent`, доказ у звіті | сирий обмін шаблону показується в рядку | `evidenceText` |
| 49 | `interaction` (interactsh) | `pkg/output/output.go` |`улучшено`| `OASTSource` | OAST-слухач у нас окремий і власний; взаємодії з nuclei приймаються і прив'язуються до тієї ж сутності | `OASTSource` |
| 50 | `matched-line` | `pkg/output/output.go` |`не перенесено`| — | причина: номери рядків збігу мають сенс лише разом із самим тілом відповіді, а ми показуємо доказ повністю; окремий список номерів без тіла — це друковане число без доказу | `nucleiFinding` |
| 51 | `global-matchers` | `pkg/output/output.go` |`не перенесено`| — | причина: те саме, що рядок 21, з боку **результату**: збіг global-matcher-а приходить без власного запису шаблону | `nucleiFinding` |
| 52 | `meta` | `pkg/output/output.go` |`не перенесено`| — | причина: довільна мета-карта від шаблону; показувати її в звіті без правила формату означало б показати довільні ключі користувача як наші колонки | `nucleiFinding` |
| 53 | `template-encoded` | `pkg/output/output.go` |`не перенесено`| — | причина: байт-в-байт копія документа в звіті дублює те, що вже можна відкрити з `template-path` | `nucleiFinding` |

## Група D — облік і вердикти, які **добавили ми**

Це рядки, яких в оригіналі немає взагалі. Вони в реєстрі, бо правило вимагає рядок
на кожну здатність, а здатність нашого шару — теж наша.

| # | здатність | де в оригіналі | вердикт | у нас | підстава | символ |
|---:|---|---|---|---|---|---|
| 54 | Вердикт на кожен файл, а не тільки на збіг | — | `улучшено` | `matched`, `not_matched`, `no_request`, `skipped`, `invalid`, `flow`, `workflow`, `uncompiled`, `duplicate` | nuclei мовчить про те, що **не** знайшов; оператор бачить лише збіги, тому «виконано 11 656 шаблонів, знайдено 2» неможливо відрізнити від «виконано 2» | `applyBatchOutcome` |
| 55 | Причина для кожного невиконання | — | `улучшено` | `reason` на `skipped`/`invalid`/`no_request`/`flow`/`workflow`/`uncompiled` | вердикт без причини — це «не працює», а AGENTS.md забороняє такий статус | `applyBatchOutcome` |
| 56 | Живий облік по файлу під час прогону | — | `улучшено` | SSE `template` + `progress` зі справжніми лічильниками | nuclei пише JSONL після завершення шаблону; на великій папці до кінця прогону не видно нічого | `TemplateEvent` |
| 57 | Локальний відкат для ignored-файлів | — | `улучшено` | `nuclei_local_fallback.go` | файл, який бінарник не запустив, ми виконуємо самі через `pkg/operators`, щоб рядок не лишався без вердикту | `applyLocalFallback` |
| 58 | Чесна класифікація JavaScript | — | `улучшено` | `javascriptAddressesTarget` | рядок 9 | `javascriptAddressesTarget` |

## Що це означає для оператора

**Головне: nuclei в цьому проєкті не «перенесений» і не «недоперенесений» — він
запускається.** Усе, що робить nuclei з шаблоном, робить сам nuclei; наш код —
це планування, облік, класифікація і доказ. Тому `не перенесено` тут має інший
зміст, ніж у httpx або katana: це переважно контроль над самим nuclei або формати
виводу для чужого конвеєра, а не втрачені можливості сканування.

**Найцінніше, що залишилось не зробленим:** нічого з Групи A/B/C не є прогалиною
в обліку. Реально відкриті речі — три:

1. `-per-host-rate-limit` (рядок 32) — обмеження на хост, а не на процес;
2. `matched-line`, `global-matchers`, `meta`, `template-encoded` (рядки 50–53) —
   поля, які не мають сенсу без формату, якого в нас немає;
3. `nuclei-templates-labs` (див. `КУДИ_ІНТЕГРУВАТИ.md`, розділ 5) — єдине, що
   дало б доказ правильності на **відомому** результаті. Це не інтеграція, а стенд.