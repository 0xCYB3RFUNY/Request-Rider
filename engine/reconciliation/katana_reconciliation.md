# Звірка з оригіналом: katana (projectdiscovery) → RequestRider Target

Цей реєстр існує тому, що при порті активного сканера з VEXOR три здібності
були втрачені **мовчки**: кожен рядок реєстру існував, набір тестів був
зелений, а здібність, яку ніхто не портував, не могла з'явитися у списку,
упорядкованому за принципом «звіряй те, що в нас є».

Перелік нижче знято **по файлах upstream**, а не з пам'яті: пам'ять і
породила ту втрату. Тест `katana_reconciliation_test.go` тримає список
справжніх імен парсерів і вимагає, щоб кожне з них було присутнє в цьому
файлі, тому пропущений парсер — це падіння тесту, а не тиша.

## Предмет порівняння

| | |
|---|---|
| upstream | `github.com/projectdiscovery/katana` |
| клон | `~/katana` |
| **коміт** | **`04a51b8`** (`v1.6.1-225-g04a51b8`) |
| версія в банері | `v1.7.0` (`internal/runner/banner.go:15`) |
| ліцензія | MIT |
| go | 1.26.0 |
| зібраний бінарник | `bin/katana` — 84 562 685 байт, перевірено `-version`; використовувався для порівняльного вимірювання |
| наша сторона | `engine/main.go` (`runTargetMap`), `engine/anti_detect.go`, `engine/target_javascript.go`, `engine/target_js_findings.go`, `engine/osint_transform_entities.go` |
| дата звірки | 2026-10-03 |

**Хто саме бере katana — рушій чи звірка.** *Розділ переписано 2026-10-03:
попередня редакція стверджувала, що бінарник «керується exec-ом» нашим
движком. Це було не так.*

Виміряно: рушій exec'ить рівно три зовнішні речі — `httpx`
(`osint_http_probe.go:137`), `nuclei` (`nuclei_exec.go:1053`,
`nuclei_validate.go:221`) та code interpreter (`nuclei_code.go:102`). Пошук по
`engine/` дав **0** збігів на `"katana"` як аргумент команди, **0** на
`os.StartProcess` і **0** на `syscall.Exec`.

Тобто **рушій бере katana бібліотекою**: `pdtools_katana_parsers.go:58-59`
імпортує `katana/pkg/engine/parser` та `pkg/navigation`, а `main.go:2774,2863`
викликає готові парсери. Exec-варіант, який дає 38 у таблиці нижче, — це
**звірка**, а не продукт:
`REPO/bin/katana` і запускає його по одному прогону на сторінку фікстури.

Тому `ensure_pdtools` збирає `bin/katana` **не для рухія**, а для інструмента
звірки. Аудит 2026-10-03 спершу оголосив цю збірку мертвою — рушій її справді
не виконує — і прибрав би її, зламавши звірку; це виправлено того ж дня, а
споживач названий у `start.sh` і в `test_runtime_binaries.py`.

Аргумент «katana не має сигналів, тому exec безпечніший» зберігає силу для
**майбутнього** exec-варіанта в рухії, але не описує того, що є. Якщо такий
exec знадобиться, його додає тот, хто додає, і цей розділ переписується разом
із ним.

**Атрибуція здібностей за файлами upstream** (порядок таблиці йде за ним):

```
cmd/katana/main.go
internal/runner/{runner,options,executer,banner,healthcheck}.go
pkg/engine/standard/{standard,crawl}.go
pkg/engine/common/{base,http}.go
pkg/engine/parser/parser.go
pkg/engine/parser/files/{robotstxt,sitemapxml}.go
pkg/engine/hybrid/{hybrid,crawl,hijack,hooks}.go
pkg/engine/headless/{headless,crawler,debugger}.go + headless/{auth,captcha,graph,browser,js}
pkg/navigation/{request,response}.go
pkg/output/{output,format_json,fields,custom_field,responses,error}.go
pkg/knowledgebase/{extractor,extractors/secrets,extractors/endpoints}
pkg/similarity/{index,simhash,lexical,normalize}.go
pkg/types/{options,crawler_options,default}.go
pkg/utils/{utils,regex,jsluice,urlfingerprint,pathtrie,formfields,formfill}.go
pkg/utils/{scope,filters,queue,extensions}
```

## Таблиця здібностей

| здатність upstream | символ / де в оригіналі | вердикт | підстава / причина |
|---|---|---|---|
| версія, банер, самоновичення | `internal/runner/banner.go:24` | не перенесено | самоновичення зовнішнього інструменту не має сенсу: версію тримає `go.mod` та реєстр, а `-update` у чужому бінарнику тягне його в чужу версію. Замість — пінована версія в реєстрі |
| health-check діагностика | `internal/runner/healthcheck.go:16` | не перенесено | діагностика середовища, а не можливість обходу; наш стенд має `./start.sh --check` і `start.sh --status` |
| pprof-сервер | `cmd/katana/main.go:81` | не перенесено | наш engine уже має власний профіль; друге джерело дампа в спільному стенді шкідливе |
| YAML-конфіг прапорців | `cmd/katana/main.go:260` | не перенесено | конфіг прапорців дублює наші явні поля запиту; правило «пред явний уведення — джерело істини» |
| обмеження розміру тіла 4 Мб | `cmd/katana/main.go:107` `defaultBodyReadSize` | не перенесено | **свідомо не переносимо**: наш `readAnalysisBody` — `io.ReadAll` без межі, і це зафіксовано тестом `engine/http_bounds_test.go:391`. Менша межа — це прихований звужуючий предел |
| стандартний HTTP-обхід BFS/DFS | `runTargetMap` | улучшено | upstream `Crawl` (`pkg/engine/standard/standard.go:30`). наш `runTargetMap` (`engine/main.go:2586`) — рукописний BFS, який додає те, чого в katana немає: `Referer` і `Sec-Fetch-*` як у браузера (`anti_detect.go:140`), cookie jar, `detectChallenge`, ланцюг редиректів і джерельний аналіз JS. katana не задає свій frontier для парсерів JS — він окремо |
| повтор запиту + `Retry-After` | `crawlOnce` | совпадає | upstream `-retry` (`pkg/engine/common/http.go:26`). `crawlOnce` / `retryDelayFor` (`anti_detect.go:474`, `:410`) читають `Retry-After` і з секунд, і з дати, і повторюють лише тоді, коли оператор дозволив (`target_javascript_test.go`, `anti_detect_test.go:282`) |
| ланцюг редиректів як доказ | `crawlRedirectChain` | совпадає | upstream `RedirectCallback` (`pkg/engine/common/base.go:354`). `crawlRedirectChain` (`anti_detect.go:202`) пише `redirects` і `final_url` у запис сторінки, а не лише фінальний URL |
| читання тіла без межі | `readAnalysisBody` | совпадає | upstream `io.LimitReader` (`pkg/engine/standard/crawl.go:95`). `readAnalysisBody` (`main.go:369`) читає `io.ReadAll` |
| cookie jar на весь обхід | `newCrawlerClient` | совпадає | upstream `httputil.CookieJar` (`pkg/engine/standard/crawl.go:57`). `newCrawlerClient` (`anti_detect.go:174`), перевірено `anti_detect_test.go:126` |
| TLS-клон інструменту не перевіряє сертифікат | `pkg/engine/common/http.go:40` `InsecureSkipVerify` | не перенесено | свідомо: наш краулер і так працює через локальний MITM, але **відключати перевірку для прямого виходу — це втрата контролю**; замість — довіра CA движка |
| імітація TLS ClientHello (JA3) | `pkg/engine/common/http.go:31` `-tlsi` | не перенесено | у нас немає шару TLS-відпечатків; наш `navigatorHeaders` (`anti_detect.go:61`) імітує метадані навігації, а не TLS. Замість — `-tlsi` лишається доступним оператору через прапорець у розширені |
| затискання TLS за Burp | `pkg/engine/common/http.go:47` | не перенесено | стосується стороннього проксі; наш проксі самотужно тримає MITM |
| адаптивний backoff за хостом | `pkg/engine/common/base.go:262` | не перенесено | наш краулер чекає `Retry-After`, але не має експоненціального відступу з джитером за хостом. Замість — видиме поле `retry_attempts` + `retry_delay_ms` |
| детекція тротлінгу 429/503 | `pkg/engine/common/base.go:292` `IsThrottled` | не перенесено | частково перекривається `rateLimited` (`anti_detect.go:463`), але стан тротлінгу не ведеться між сторінками |
| глобальний і per-host rate limit | `pkg/types/crawler_options.go:175` | не перенесено | наш краулер одногорутинний і має лише `delay_ms` між запитами. Замість — `delay_ms`, видимий у UI |
| ліміт сторінок на домен | `pkg/engine/common/base.go:136` `-mdp` | не перенесено | дублює наш `max_pages` (`main.go:2769`), який вже не має верхньої межі |
| max depth зі звітом «досягнуто» | `pkg/engine/common/base.go:131` | не перенесено | наш `max_depth < 0` означає необмежено (`main.go:2745`). **УВАГА:** katana `-d 0` означає «обходу немає» — виміряно 0 подій, тому стан «без обмеження» треба задавати явно, а не нулем |
| дедуплікація URL | `normalizeMapURL` | улучшено | upstream `UniqueURL` (`pkg/utils/filters/simple.go:37`). наша `seen` мапа (`main.go:2603`) дедуплікує нормалізованим URL (`normalizeMapURL`), а katana — сирим рядком. Наш варіант не об'єднує різні форми одного адреси |
| дедуплікація контенту MD5 | `pkg/utils/filters/simple.go:47` | не перенесено | наш краулер не відкидає сторінку з дублем тіла; вона просто дублюється в карті. Замість — `seen` + фільтр на UI |
| детекція редирект-циклу | `pkg/utils/filters/simple.go:65` `IsCycle` | не перенесено | наш краулер обмежує редиректи 10 переходами в `newCrawlerClient`; це стеля, а не виявлення циклу |
| BFS з пріоритетом глибини | `runTargetMap` | совпадає | upstream `priorityQueue` (`pkg/utils/queue/priority_queue.go:20`). наша черга BFS зі значенням `depth` у кожному елементі (`main.go:2604`) |
| DFS через стек | `pkg/utils/queue/stack.go:16` | не перенесено | наш краулер однопрядковий BFS; вибір стратегії не передбачений. Замість — порядок черги |
| черга з виходом по context | `runTargetMap` | совпадає | upstream `PopWithContext` (`pkg/utils/queue/queue.go:80`). `runTargetMap` перевіряє `ctx.Err()` на кожній ітерації (`main.go:2636`) |
| відновлення після зупинки `-resume` | `internal/runner/runner.go:43` | не перенесено | наш стан живе в PostgreSQL як `TargetJob` (`web/lab/models.py:293`), а не у файлі поруч із бінарником |
| фільтр розширень (76 типово) | `pkg/utils/extensions/extensions.go:65` | не перенесено | наш `classifyMapURL` (`main.go:2877`) класифікує, але не відсікає; відсікання розширень зробило б карту неповною без прохання оператора |
| фільтр URL за regex | `pkg/output/output.go:374` | не перенесено | немає; замість — фільтр і сортування в UI (`index.html:12985`) поверх повної карти |
| фільтр за DSL-умовою | `pkg/output/output.go:411` | не перенесено | немає DSL-рушія; власний рушій — це паралельна підсистема, а не потреба |
| фільтр за типом сторінки | `pkg/output/output.go:202` `-fpt` | не перенесено | залежить від зовнішнього ML-класифікатора `dit`; без моделі `classifyPage` мовчки повертає лише `pHash` (`runner.go:662`). Див. R3 |
| власні regex-поля з YAML | `pkg/output/custom_field.go:62` | не перенесено | дублює наш `secret_scan` і аналіз JS; друга мова описувачів — паралельний шлях |
| вбудоване поле `email` | `pkg/output/custom_field.go:71` | не перенесено | дублює `email_recon` і `collectEmails` (`target_js_findings.go:916`) |
| 14 вбудованих полів URL | `pkg/output/fields.go:18` | не перенесено | наш краулер зберігає `url` і `content_type`; решта полів не мають читача в нашому UI |
| шаблон виводу `{{field}}` | `pkg/output/format_template.go:12` | не перенесено | наш експорт JSON/CSV/HTML (`index.html:13253`) і так серверний і самодостатній; шаблони виводу — це друге джерело правди про формат |
| сховище сирих обмінів на диску | `pkg/output/output.go:214` `-sr` | не перенесено | наші обміни вже пишуться в PostgreSQL через пасивний проксі; дисковий дубль — мертвий артефакт |
| лічильник результатів | `targetMapSnapshot` | совпадає | upstream `GetResultCount` (`pkg/output/output.go:322`). наш `job.visited = len(job.pages)` (`main.go:2728`) у режимі реального часу |
| помилковий потік JSONL | `pkg/output/error.go:5` | не перенесено | наш краулер пише помилку в саму сторінку (`page["error"]`, `main.go:2706`), тому окремий потім не потрібен |
| визначення технологій wappalyzer | `pkg/types/crawler_options.go:185` `-td` | не перенесено | у нас є Scanner CMS і `technology_probe`, але не повний wappalyzer. Замість — Scanner CMS і доказ маркера в `technologyEvidence` |
| база знань про тип сторінки | `pkg/types/crawler_options.go:270` `-kb` | не перенесено | та сама залежність від `dit` |
| видобуток секретів | `collectJSSecrets` | улучшено | наш `collectJSSecrets` (`target_javascript.go:658`) працює на тому самому дереві-AST, що й ендпоінти, і повертає fingerprint, а не значення в звіт. Але наш витяг є з JS-файлів, katana — з будь-якого тіла |
| жива валідація секретів | `pkg/knowledgebase/extractors/secrets/secrets.go:27` | не перенесено | свідомо: це надсилає справжні виклики API стороннім провайдерам із доказами оператора. Замість — `ProjectSecret` зі значенням лише за посиланням |
| класифікація ендпоінтів | `mergeJSEndpoints` | улучшено | наш `analyzeJavaScript` дає ендпоинти з методом, типом, query і body-параметрами, розв'язаними **проти файлу, у якому вони написані** (`target_javascript_test.go:147`), і з поділом методів за місцем виклику. katana не прив'язує ендпоінт до його файлу |
| фільтр схожості simhash | `pkg/similarity/index.go:111` | не перенесено | дублює дедуплікацію контенту, якої в нас немає; замість — відсутність фільтра (карта повна) |
| фільтр схожості TF-IDF / BM25 | `pkg/similarity/lexical.go:90` | не перенесено | лексичний фільтр, який ми не маємо; дублює відсутній у нас фільтр схожості контенту. Замість — карта без фільтра, повна за замовчуванням |
| кластеризація сторінок | `pkg/similarity/index.go:129` | не перенесено | обмеження на сторінки в кластері — прихований предел обсягу |
| нормалізація тексту для схожості | `pkg/similarity/normalize.go:37` | не перенесено | обслуговує лише фільтр схожості |
| robots.txt | `runTargetMap` | улучшено | upstream `robotstxtCrawler` (`pkg/engine/parser/files/robotstxt.go:23`). наш краулер сіє `/robots.txt` **завжди** і бере з нього посилання; katana робить це лише за `-kf`. Різниця: наш не шанує `Disallow` (перевірено `main_test.go:131`) — це навмисно, `Disallow` є порадою, а наш інструмент має бачити те, що сервер віддає |
| sitemap.xml | `extractSitemapReferences` | улучшено | upstream `sitemapXmlCrawler` (`pkg/engine/parser/files/sitemapxml.go:23`). наш `extractSitemapReferences` (`main.go:2894`) бере і `Sitemap:`, і вкладені `<loc>` (`main_test.go:123`) |
| парсер заголовка `Content-Location` | `pkg/engine/parser/parser.go:122` `headerContentLocationParser` | не перенесено | наш `extractMapLinks` не читає цей заголовок; джерело рідкісне, окремий рядок потрібен, щоб пропуск не був тихим |
| парсер заголовка `Link` | `pkg/engine/parser/parser.go:132` `headerLinkParser` | не перенесено | наш краулер не читає HTTP-заголовок `Link`; це реальне джерело посилань (RFC 8288), тож це відома діра, а не «немає» |
| парсер заголовка `Refresh` | `pkg/engine/parser/parser.go:155` `headerRefreshParser` | не перенесено | наш краулер не читає `Refresh` у заголовку; решту `Refresh` (у meta) він не читає теж |
| парсер заголовка `Location` | `crawlRedirectChain` | совпадає | upstream `headerLocationParser` (`pkg/engine/parser/parser.go:145`). редиректи ми не просто йдемо, а **записуємо ланцюг** (`main.go:2702`), тому атрибуція кожного кроку збережена |
| парсер `<a href\|ping>` | `extractMapLinks` | совпадає | upstream `bodyATagParser` (`pkg/engine/parser/parser.go:173`). `extractMapLinks` читає `a[href]`; `ping` — ні, це окремий атрибут |
| парсер `<link href>` | `extractMapLinks` | совпадає | upstream `bodyLinkHrefTagParser` (`pkg/engine/parser/parser.go:188`). наш регулярний витяг бере `link[href]` |
| парсер `<body background>` | `pkg/engine/parser/parser.go:272` `bodyBackgroundTagParser` | не перенесено | рідкісний атрибут, наш витяг його не читає |
| парсер `<audio>/<source src\|srcset>` | `pkg/engine/parser/parser.go:283` `bodyAudioTagParser` | не перенесено | наш витяг не читає `audio` і `source`; `srcset` не читається ніде в нас |
| парсер `<applet archive\|codebase>` | `pkg/engine/parser/parser.go:306` `bodyAppletTagParser` | не перенесено | застарілий тег; окремий рядок, щоб пропуск був помітним |
| парсер `<img dynsrc\|longdesc\|lowsrc\|src\|srcset>` | `pkg/engine/parser/parser.go:321` `bodyImgTagParser` | не перенесено | наш витяг не бере атрибути зображень як джерела обходу; це архівні URL, які в реальних сайтах трапляються |
| парсер `<object>/<param>` | `pkg/engine/parser/parser.go:354` `bodyObjectTagParser` | не перенесено | наш витяг не читає `object`; вбудовані об'єкти — реальне джерело ендпоінтів |
| парсер `<svg><image href>\|<script href>` | `pkg/engine/parser/parser.go:375` `bodySvgTagParser` | не перенесено | SVG часто несе вбудовані скрипти; наш витяг їх не бачить |
| парсер `<table>/<td background>` | `pkg/engine/parser/parser.go:394` `bodyTableTagParser` | не перенесено | застарілий атрибут, окремий рядок заради повноти переліку |
| парсер `<video src\|poster>/<track src>` | `pkg/engine/parser/parser.go:411` `bodyVideoTagParser` | не перенесено | наш витяг не читає відео-джерела |
| парсер `<button formaction>` | `pkg/engine/parser/parser.go:480` `bodyButtonFormactionTagParser` | не перенесено | наш витяг не читає `formaction`; це URL, який браузер реально запросить |
| парсер `<blockquote cite>` | `pkg/engine/parser/parser.go:432` `bodyBlockquoteCiteTagParser` | не перенесено | рідкісний атрибут |
| парсер `<area href\|ping>` | `pkg/engine/parser/parser.go:443` `bodyMapAreaTagParser` | не перенесено | наш витяг не читає `area` |
| парсер `<base href>` | `extractMapLinks` | улучшено | upstream `bodyBaseHrefTagParser` (`pkg/engine/parser/parser.go:458`). наш витяг вирішує відносні посилання через `url.Parse` від поточної сторінки, але **не читає `<base>`**; зато ми не ламаємось на сайтах, які декларують `<base>`, помилково йдучи з кореня |
| парсер `<import implementation>` | `pkg/engine/parser/parser.go:469` `bodyImportImplementationTagParser` | не перенесено | застарілий HTML, окремий рядок заради повноти |
| парсер `<embed src>` | `pkg/engine/parser/parser.go:199` `bodyEmbedTagParser` | не перенесено | наш витяг не читає `embed` |
| парсер `<frame src>` | `pkg/engine/parser/parser.go:210` `bodyFrameTagParser` | не перенесено | наш витяг не читає `frame`; застарілі фрейми трапляються на старих CMS |
| парсер `<iframe src\|srcdoc>` | `pkg/engine/parser/parser.go:221` `bodyIframeTagParser` | не перенесено | **`<iframe src>` — це не перенесено, і це відчутно**: вкладені документи є окремими сторінками. `srcdoc` (інлайн-HTML) ми також не аналізуємо |
| парсер `<input type=image src>` | `pkg/engine/parser/parser.go:239` `bodyInputSrcTagParser` | не перенесено | рідкісний випадок |
| парсер `<isindex action>` | `pkg/engine/parser/parser.go:250` `bodyIsindexActionTagParser` | не перенесено | застарілий тег, окремий рядок заради повноти |
| парсер `<script src>` | `analyzeJavaScript` | улучшено | upstream `bodyScriptSrcTagParser` (`pkg/engine/parser/parser.go:261`). наш `isJavaScriptResource` (`main.go:2869`) бере скрипт і **аналізує його тіло** (`analyzeJavaScript`, `main.go:2719`) — ендпоинти, секрети, findings, змінні. katana лише додає URL у чергу |
| парсер `<meta content>` (refresh) | `pkg/engine/parser/parser.go:613` `bodyMetaContentTagParser` | не перенесено | наш витяг не читає `meta refresh` |
| парсер `<html manifest>` | `pkg/engine/parser/parser.go:491` `bodyHtmlManifestTagParser` | не перенесено | застарілий атрибут, окремий рядок заради повноти |
| парсер doctype `system` | `pkg/engine/parser/parser.go:502` `bodyHtmlDoctypeTagParser` | не перенесено | не є джерелом URL; рядок існує, щоб перелік парсерів був повним, а не «цікавими» |
| парсер htmx-атрибутів | `pkg/engine/parser/parser.go:627` `bodyHtmxAttrParser` | не перенесено | **найважливіша прогалина**: katana будує справжні запити з `hx-get/post/put/patch`. Наш витяг про htmx не знає, тому htmx-застосунки в нас дають порожню карту. `hx-delete` свідомо опущений і в upstream |
| власне regex-поле | `pkg/engine/parser/parser.go:781` `customFieldRegexParser` | не перенесено | дублює `secret_scan`; друга мова описувачів |
| збереження JS-аналізу на тілі сторінки | `jsAnalysis` | улучшено | katana віддає `Extra` виклику й нічого з ним не робить (`pkg/navigation/response.go:48`). Наш `jsAnalysis` (`target_javascript.go:93`) живий і зливається в UI, CSV, HTML-експорт і `ProjectEndpoint` |
| інлайн-аналіз тексту `<script>` | `mergeJSEndpoints` | улучшено | upstream `ExtractRelativeEndpoints` (`pkg/engine/parser/parser.go:670`). наш `mergeJSEndpoints` (`target_javascript.go:278`) робить це на дереві-AST і **утримує** посилання з виразами поза чергою (`containsJSExpression`, `target_javascript_test.go:162`), щоб краулер не пішов у неіснуючий URL |
| видобуток ендпоінтів з JS/CSS | `analyzeJavaScript` | улучшено | наш аналіз дає метод, тип, параметри й(call-site)-розв'язку; katana дає лише URL |
| видобуток з довільного текстового тіла | `extractMapLinks` | улучшено | upstream `pageBodyRegex` (`pkg/engine/parser/parser.go:756`). те саме, плюс наш `extractMapLinks` для JSON і CSS зберігається регулярним виразом (`target_javascript_test.go:937`) — JSON не має дерева-AST |
| захист від бінарного тіла | `pkg/engine/parser/parser.go:730` | не перенесено | наш витяг не перевіряє, чи тіло текстове, перед regex; для JSON/CSS тип заданий і ризик інший |
| jsluice AST | `mergeJSEndpoints` | совпадає | upstream `scriptContentJsluiceParser` (`pkg/engine/parser/parser_generic.go:41`). вже є `BishopFox/jsluice` в `engine/go.mod:6` і `mergeJSEndpoints` |
| пропуск бібліотек JS | `pkg/utils/jsluice.go:18` | не перенесено | наш аналізатор парсить кожен скрипт; список ~300 назв економив би час на вендорних бандлах |
| гібридний рушій (CDP + HTTP) | `analyzeJavaScript` | улучшено | browser-driven Target уже дає реальні XHR і мережеві докази (`index.html:13020`) через browser-worker на нашому стенді upstream `hybrid.Crawler` (`pkg/engine/hybrid/crawl.go:30`). |
| XHR-відловлення | `analyzeJavaScript` | улучшено | browser-worker збирає реальні запити XHR і fetch з браузера і пише їх у карту як мережеві докази (`index.html:13020`), тоді як katana віддає їх лише як поле відповіді. Наш шлях дає ще й атрибуцію до пасивного проксі та джерельний IP за кожен обмін. upstream `-xhr` (`pkg/engine/hybrid/crawl.go:156`). |
| обхід shadow DOM | `pkg/engine/hybrid/crawl.go:485` | не перенесено | наш browser-worker не будує псевдо-документ; тіньовий DOM не обходиться |
| симуляція `onclick` | `pkg/engine/hybrid/crawl.go:302` | не перенесено | browser-worker має `auto_click`, але не «клікнути посилання з inline-обробником, щоб побачити JS-редирект» |
| відстеження навігації з JS | `analyzeJavaScript` | улучшено | browser-worker збирає `network` з реальної навігації upstream `Page.frameNavigated` (`pkg/engine/hybrid/crawl.go:223`). |
| стратегії завантаження сторінки | `pkg/engine/hybrid/crawl.go:235` | не перенесено | browser-worker має `navigation_timeout_ms` і `auto_wait_timeout_ms`, але не `heuristic/networkidle` |
| гачки гібрида | `pkg/engine/hybrid/hooks.go:32` | не перенесено | наш browser-worker не має BeforeNavigate/AfterLoad; це розширення точки входу для стороннього коду |
| обхід CDP-вузла власного сокета | `pkg/engine/hybrid/hybrid.go:92` | не перенесено | внутрішня деталь katana; наш browser-worker керує своїм браузером інакше |
| чисто-headless рушій | `pkg/engine/headless/headless.go:100` | не перенесено | наш browser-driven Target — це Playwright із прямими діями, а не граф станів з відновленням |
| граф обходу | `pkg/engine/headless/graph/graph.go:24` | не перенесено | наш Target не будує граф станів; `map_id` — плоский список сторінок |
| відбиток стану сторінки | `pkg/engine/headless/crawler/state.go:97` | не перенесено | SHA-256 нормалізованого DOM, який обслуговує порівняння станів; наш Target не будує граф станів, а має плоский список сторінок. Замість — ідентичність за URL |
| відновлення стану в три етапи | `pkg/engine/headless/crawler/state.go:132` | не перенесено | повернення до попереднього стану через ідентифікатор елемента, історію браузера або найкоротший шлях у графі; жодного з цих трьох механізмів у нас немає. Замість — browser-worker зберігає власний контекст |
| нормалізатор DOM | `pkg/engine/headless/crawler/normalizer/dom_utils.go:11` | не перенесено | обслуговує порівняння станів, якого в нас немає |
| прискорення таймерів у браузері | `pkg/engine/headless/js/page-init.js:114` | не перенесено | наш browser-worker чекає реальні таймери; прискорення змінює поведінку сторінки, тому це не переносимо свідомо |
| перехоплення навігаційних джерел | `pkg/engine/headless/js/page-init.js:24` | не перенесено | **і це dormant upstream:** `__katanaHooksOptions.hooked` ніде не встановлюється, тому гачки не встановлюються. Наш browser-worker має власний `network` |
| зняття подій DOM | `pkg/engine/headless/js/page-init.js:128` | не перенесено | та сама причина: гачки не встановлюються, `GetEventListeners()` повертає порожньо |
| stealth-ін'єкція | `detectChallenge` | улучшено | upstream `stealth.JS` (`pkg/engine/headless/browser/stealth/assets.go:5`). наш browser-worker має `anti_detect` і власний профіль (`worker.py`), плюс `engine/anti_detect.go` |
| блокування cookie-згоди | `pkg/engine/headless/browser/cookie/cookie.go:48` | не перенесено | наш browser-worker не блокує трекери; це змінює те, що сервер бачить |
| автозаповнення форм у браузері | `detectChallenge` | улучшено | upstream `processForm` (`pkg/engine/headless/crawler/formfill.go:60`). browser-worker має `auto_fill`/`auto_click` і вимагає `allow_state_changing_actions` (`worker.py:282`) — явний дозвіл оператора, якого в katana немає |
| автологін | `pkg/engine/headless/crawler/crawler.go:406` `-al` | не перенесено | наш browser-worker не автологіниться; це стан-зміна без явного рішення оператора |
| відтворення записаного флоу | `pkg/engine/headless/crawler/crawler.go:571` `-rf` | не перенесено | browser-worker приймає явні `actions` (`views.py:2359`), але не відтворює запис Chrome Recorder |
| перевірка успіху автентифікації | `pkg/engine/headless/crawler/crawler.go:617` | не перенесено | немає стану «увійшли / не увійшли» |
| захоплення стану сесії | `detectChallenge` | улучшено | upstream `CaptureSessionState` (`pkg/engine/headless/auth/session.go:62`). наш профіль browser-worker персистентний, тому сесія переживає job; явного знімка немає |
| уникнення logout | `pkg/engine/common/base.go:241` | не перенесено | наш краулер може вийти з сесії і втратити її; це небезпека для карти |
| CAPTCHA-виявлення | `detectChallenge` | улучшено | upstream `HandleIfCaptcha` (`pkg/engine/headless/captcha/captcha.go:29`). наш `detectChallenge` (`anti_detect.go:320`) називає постачальника і маркер, розрізняє `gate` і `widget`, і **зупиняє обхід на gate** (`challengeIsGate`, `main.go:2739`) — виміряно, що без цього читання `g-recaptcha` на новинній сторінці спорожнювало карту |
| ідентифікація CAPTCHA | `challengeVendors` | улучшено | upstream `Identify` (`pkg/engine/headless/captcha/identify.go:26`). наша таблиця `challengeVendors` (`anti_detect.go:276`) — 24 рядки, з маркерами та поділом gate/widget |
| розв'язання CAPTCHA | `pkg/engine/headless/captcha/solver.go:17` | не перенесено | свідомо: розв'язання CAPTCHA вимагає зовнішнього платного сервісу, передає йому сторінку цілі й живі сесії оператора |
| інтеграція CapSolver | `pkg/engine/headless/captcha/capsolver/capsolver.go:53` | не перенесено | те саме + третій сторони отримує вміст цілі |
| ін'єкція токена CAPTCHA | `pkg/engine/headless/captcha/captcha.go:63` | не перенесено | обслуговує розв'язання |
| дамп діагностики обходу | `pkg/engine/headless/crawler/diagnostics/diagnostics.go:55` | не перенесено | наші логи в `data/logs/`; другий дамп із DOM і скриншотами — дубль |
| живий дебагер обходу | `pkg/engine/headless/debugger.go:27` | не перенесено | другий HTTP-сервер на `127.0.0.1:8089` у спільному стенді — займий порт |
| класифікація помилок дій | `pkg/engine/headless/crawler/crawler.go:293` | не перенесено | обслуговує лічильник падінь дій, якого в нас немає |
| запобіжник серії помилок | `pkg/engine/headless/crawler/crawler.go:256` `-mfc` | не перенесено | наш `runTargetMap` не має лічильника помилок; обрив обходу після N помилок — неявний предел |
| парсинг відповідей браузера | `analyzeJavaScript` | улучшено | upstream `performAdditionalAnalysis` (`pkg/engine/headless/headless.go:253`). browser-worker пише мережеві докази з реального перехоплення |
| витяг елементів сторінки | `pkg/engine/headless/browser/element.go:59` | не перенесено | наш browser-worker не будує список елементів як джерело обходу |
| пропуск неактивних елементів | `pkg/engine/headless/browser/element.go:20` | не перенесено | відсікання disabled, aria-disabled і pointer-events-none, щоб не натискати те, чим не можна натиснути; наш browser-worker такого фільтра не має. Замість — обмеження на `allow_state_changing_actions` |

## Виміряно на спільній фікстурі (2026-10-03)

Цей розділ існує, бо реєстр вище — це твердження. Твердження, яке ніхто не
міряв, — це припущення, і саме на припущеннях народилися три мовчки втрачені
здібності vexor-порту.

Спільна фікстура й маніфест (index `sha256:8db6cbcd…`), 48 витягуваних
здібностей + 2 окремі ресурси (`robots.txt`, `sitemap.xml`), які запитуються
прямо. **Обидва інструменти отримали ті самі байти**, перевірено `sha256sum`
сервера проти маніфесту.

### Числа

<!-- measurement-table: числа, а не здібності. Парсер реєстру цей рядок
     пропускає: у ньому немає вердикту, бо вердикт тут не ставиться. -->

<!--MEASUREMENT-TABLE-->
| інструмент | досягнуто | з | примітка |
|---|---:|---:|---|
| наш краулер (цілісний) | 52 | 52 | `extractMapLinks` + парсери katana + наш шар |
| набір парсерів katana | 42 | 52 | `NewResponseParser`, викликаний напряму |
| краулер katana (бінарник) | 38 | 52 | чотири парсери він читає, але не ставить у чергу |
| **ОБ'ЄДНАННЯ** | **52** | **52** | **мета досягнута** |
<!--/MEASUREMENT-TABLE-->

Три числа, а не одне, і кожне виміряне окремо. Причина трьох — те, що в katana
**два різні речі**, які попередня версія цього реєстру називала одним числом.

- **42** — скільки читає `NewResponseParser`, тобто набір парсерів. Це те, що
  ми викликаємо зі свого краулера (`pdtools_katana_parsers.go`); це число
  зафіксовано в цьому вимірюванні.
- **38** — скільки katana **сам** ставить у чергу, виміряно бінарником по одному
  прогону на кожну сторінку фікстури. Різниця `42 − 38 = 4` — це
  `img_lowsrc`, `param_value`, `applet_codebase`, `video_poster`: усі чотири
  парсери в upstream **є** (перевірено читанням `bodyImgTagParser`,
  `bodyObjectTagParser`, `bodyAppletTagParser`, `bodyVideoTagParser`), але
  краулер katana їх не ставить у чергу.

Тому вбудовування парсерів дає більше, ніж запуск katana другим процесом:
плюс чотири здібності, які katana витягає і відкидає.

### Де було «52 із 52» у katana, і чому це було неправдою

Попередня версія цього розділу писала «katana 52 з 52». Вимірювання, яке це
дало, шукало маркер здібності **в усьому JSON-записі** katana, включно з
`response.body` — а це тіло тієї сторінки, на якій маркер і лежить. Katana
приходила на `/cap/source_src`, її відповідь ехо маркер, лічильник зростав, і
здібність, яку інструмент не витягнув, рахувалася знайденою.

Виправлено двома правками, обидві в
у порівняльному вимірюванні:

1. **`marker in blob_line` → `marker in endpoint`.** Рахується лише те, до чого
   інструмент **дійшов** як до сторінки.
2. **Один виклик на 52 цілі → окремий прогін на кожну сторінку.** Виміряно:
   список із 52 цілей через `-u` дає **0 записів** JSONL, список із 2 — 56
   записів, і жоден прапорець (`-d`, `-c`, `-rl`, `-kf`, `-jc`) це не міняє.
   Мовчаливий нуль виглядав би як «katana не читає нічого».

Той самий дефект був у **нашій** мірці (`our crawler: 0`), але там він був
видимий — число нульове, а не правдоподібне.

### Об'єднання, а не змагання

Мета інтеграції — **доповнення**: наш краулер дає свідчення, Project і власний
аналіз JS, katana дає тридцять парсерів. Тому число, яке має значення, — не
«скільки знайшов кожен», а `|ours ∪ katana|` проти `|усі|`.

**52 із 52: кожна здібність фіксстури закрита, і цю цифру дає наш краулер сам.**

Розподіл на 52, а не лише число:

Розподіл такий:

- **лише наш власний видобувач — 10.** `a[href]`, `a[ping]`, `link[href]`,
  `script[src]`, `form[action]` (збір `extractMapLinks`), `robots.txt`,
  `sitemap.xml` і вкладений `<sitemap><loc>` (сіяння та
  `extractSitemapReferences`), спільний JS-ресурс (`isJavaScriptResource`) і
  ланцюг редиректів для `Location` (`crawlRedirectChain`).
- **лише набір парсерів katana — 37.** Решта здібностей розмітки; їх дає
  `katanaReferences`.
- **лише наш шар поверх katana — 4.** `<source src>`, `<source srcset>`,
  `meta refresh`, `iframe srcdoc`; їх дає `frontierLayerReferences`.
- **перекривається одна — `hdr_link`.** Вона і в `link[href]`, і в парсері
  заголовків.

10 + 37 + 4 + 1 = 52.

Множина була зафіксована під час порівняльного вимірювання; наведені числа є
результатом того прогона.

### Жодної нашої здібності katana не має

Ми дісталися до десяти власних, katana — до жодної з них, крім `<form action>`,
який він бере лише за `-aff` (явне заповнення форм). Тобто ми не втрачаємо
нічого свого.

### Тридцять сім здібностей, яких немає в нас

Найважчі за впливом на аналіз:

| здібність | наслідок |
|---|---|
| htmx `hx-get`/`hx-post`/`hx-put`/`hx-patch` | htmx-застосунок дає **порожню карту**: його ендпоинти не в розмітці посилань |
| `<iframe src>` | вкладений документ не обходиться — а це часто окрема сторінка з власними ендпоинтами |
| `<img src>` / `<video src>` / `<audio src>` | мультимедіа-URL не обходяться; на них бувають історічно забуті шляхи |
| `<base href>` | ми вирішуємо відносні посилання від поточної сторінки, а не від `<base>` |
| `<object data>` / `<embed src>` / `<param value>` | вбудовані об'єкти — реальне джерело ендпоінтів |
| заголовок `Refresh` | редирект, який ми не бачимо |
| заголовок `Content-Location` | те саме, другим способом |
| `<button formaction>` | URL, який браузер реально запитає, нам невідомий |
| doctype `SYSTEM` | зовнішній DTD, який ми не читаємо |

### Десять здібностей, яких не дає набір парсерів katana

Це виміряно, а не виведено з коду: `NewResponseParser` запускали на кожному
документі фікстури й записували, що він повернув.

- **`<source src>`** — парсера `<source>` не існує: `NewResponseParser`
  реєструє `audio`, `video`, `img`, `embed`, `frame`, `object` і жодного
  `source`. Закриває наш шар, `pdtools_katana_parsers.go`.
- **`<source srcset>`** — те саме, що й `src`. Той самий файл.
- **`meta refresh`** — `bodyMetaContentTagParser` не читає `http-equiv` і
  віддає значення в `utils.ExtractRelativeEndpoints`; виміряно, що той
  повертає порожньо і для шляху без розширення, і для шляху у лапках без
  розширення. Закриває наш шар.
- **`iframe srcdoc`** — `bodyIframeTagParser` читає `srcdoc`, але тим самим
  regex'ом, тому шлях у лапках без розширення зникає. Закриває наш шар, який
  розпарсений як документ.
- **`Location`** — парсер читає `Content-Location`, а не `Location`; редирект
  обробляє сам клієнт. Закриває `crawlRedirectChain` (`anti_detect.go`).
- **`<form action>`** — лише за `-aff`, тобто за явного заповнення форм. Закриває
  `extractMapLinks`.
- **`robots.txt`, `sitemap.xml`, вкладений `<sitemap><loc>`** — не HTML, тому
  жоден HTML-парсер їх не читає. Закриває наше сіяння та
  `extractSitemapReferences`.
- **JS-ресурс** — не парсер, а окремий аналізатор `analyzeJavaScript`.

Важливо для чесності для чесності: `extractSitemapReferences` **читав** лише
`Sitemap:` і `<loc>`, а `Allow:`/`Disallow:` з robots.txt ігнорував. Виміряно на
фікстурі: з ними здібність `robots` з'являється, без них — ні.

### Знайдений дефект продукту — НЕ виправлено

**`kind` має два різні значення для `/sitemap.xml`.** Сіяння пише
`strings.TrimPrefix(suffix, "/")` (`main.go:2648`), тобто `"sitemap.xml"`, а
`classifyMapURL` для того ж URL повертає `"sitemap"` (`main.go:2971`).

Не виправлено свідомо: `kind` — публічне поле сторінки, документоване в
AGENTS.md, а зміна його значення без запиту власника порушила б контракт.
Зафіксовано під час вимірювання, яке перевіряло, що ресурс було **запитано**
(це і є здібність), а не прив'язувалося до тексту, який треба узгодити.

### Два дефекти самого вимірювання, знайдені мутацією

1. **Індекс спочатку посилався на всі probe-шляхи.** Число вийшло 47 з 49, і
   воно **нічого не міряло**: краулер брав сторінку посиланням, а не витягом
   атрибута. Перероблено — тепер індекс містить самі атрибути.
2. **Початковий тест друкував число, але не стверджував його.** Мутація, що вимикає
   `<form action>`, змінювала 5 на 4 — і тест лишався зеленим. Це було виправлено
   в harness вимірюванням із зафіксованою множиною очікувань.

Це той самий патерн, що дав «3 = 3», тільки на рівень глибше: підмножина була
неявною, у компіляторі, а не в реєстрі — і реєстр нічого не міг виявити.

## Наші власні здібності, яких немає в katana

Ці рядки потрібні, щоб реєстр фіксував не лише втрати. Кожна з них має бути
присутня, інакше здібність приєдналася б до сканера без рішення.

| здібність | символ | вердикт | підстава |
|---|---|---|---|
| повний сирий обмін у History | `crawlRedirectChain` | улучшено | katana не пише нічого в нашу БД; ми пишемо через пасивний проксі, тому доказ у `TrafficRecord` і `ProjectExchange` |
| джерельний IP за обміном | `startSourceIPLookup` | улучшено | katana не атрибутує вихідний IP; наш проксі робить це на обмін, без процесного кеша |
| бар'єр generation | `bindRouteContext` | улучшено | `Apply route` скасовує роботи попереднього generation; katana про route не знає |
| виявлення gate і зупинка обходу | `challengeIsGate` | улучшено | katana має CAPTCHA-виявлення, але не розрізняє «цей відповідь — не сайт» |
| аналіз JS на тілі сторінки | `jsAnalysis` | улучшено | результат зливається в UI, CSV, HTML і `ProjectEndpoint` |
| нумерація ID за вмістом | `FindingID` | улучшено | стабільний ідентифікатор доказу, якого в katana немає |

## Що register не може перевірити

Тест не може знайти здібність upstream, якої **немає ні в реєстрі, ні в
нашому дереві** — йому немає чого назвати. Це ловить перелік файлів у
шапці, узятий з upstream, і `TestEveryUpstreamParserIsNamed` у тесті, який
тримає список справжніх імен парсерів: пропущений парсер змінює той список
і падіння стає механічним, а не «хтось пам'ятає».

Ще не перевіряється і має бути перевірено до Фази 4: **фактичне покриття
нашого `extractMapLinks`**. Реєстр фіксує, яких атрибутів ми не читаємо, але
не вимірює, скільки з них трапляється на живих сторінках. Вимірювання — це
Фаза 2 (фікстура), а не цей файл.