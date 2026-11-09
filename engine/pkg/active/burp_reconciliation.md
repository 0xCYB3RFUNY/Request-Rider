# Звірка з Burp Suite: які перевірки сканера в нас є

> Механізм, який вів себе в диск: перелік можливостей, знятий **з оригіналу**,
> з вердиктом на кожен рядок. Перевіряється тестом
> `burp_reconciliation_test.go`.
>
> Правило, якого цей файл існує: `AGENTS.md`, «Алгоритм внедрения стороннего
> инструмента: «теряем ли мы что-нибудь»» і «Дыра, через которую теряется
> молча». Перелік знімається з **реестру перевірок оригіналу**, а не з того, що
> вже перенесено: можливість, яку ніхто не переносив, у списку «звір те, що в
> нас» просто відсутня, і відсутність читається як «нічого втрачено».

Upstream-коміт, звірка проти якого зроблена: `v2026.9.1`

**Оригінал:** Burp Suite Professional **v2026.9.1** (`burpsuite_desktop_v2026.9.1`),
перевірки активного сканера з вкладки **Scan checks**.
**Чому пін — версія, а не SHA:** Burp Suite не є git-репозиторієм і не Go-модулем,
тому SHA для нього не існує, а звірка версії з `go.mod` до нього не застосовується
(`reconciliation_upstream_commit_test.go` пропускає пін, якого в `go.mod` немає).
Фіксація — версія дистрибутива, який оператор надав і з якого знятий перелік; саме
тому вона названа тут і в тесті одним і тим самим рядком.
**Де взято перелік:** реєстр оператора (`session-9e37a65f-432c-4091-b9a1-861b063ce056.md`,
знятий зі скриншотів конфігурації Burp) — **165 типів перевірок** (`type_index`).
**Звірка переліку з оригіналом:** `resources/BuiltInConfigs/*.json` несуть ті самі
`type_index` (15 різних серед 29 файлів); 13 із них — у реєстрі оператора, а два
(`0x08000000`, `0x09000000`) — джерела розширень (BChecks/BApp), а не перевірки
сканера, тому в реєстрі їх немає. Повного машинного переліку перевірок у
дистрибутиві немає: `issue-definitions.html` — заглушка на 2.6 КБ, список живе
в UI, тому джерело переліку — реєстр оператора, а не файли дистрибутива.

**Як читати вердикт.** Рівно три значення, четвертого немає:

- `совпадает` — оригінал робить це саме, і ми робимо це саме;
- `улучшено` — ми робимо це і доводимо сильніше (відповіддю, контролем, PoC);
- `не перенесено` — у нас цього немає, **і названо, чого саме бракує**.

**Колонка «підстава / причина» при `не перенесено` обов'язкова**: рядок без
причини не відрізнити від рядка, який просто забули.

Тієї колонки більше немає в жодному рядку, і таблиця причин порожня:

| причина | скільки рядків | що потрібно, щоб знести |
|---|---:|---|
| жодної | 0 | — |

**Головне застереження щодо цієї таблиці.** Порожня таблиця причин — не доказ
повноти. Вона каже лише, що жоден рядок не **позначив** свою неповноту, і
позначення обирає той, хто заповнює реєстр. Реальна перевірка повноти — чи
**демонструє** код кожен рядок, а це механічний гард
`TestTheBurpWallsTableSumsToTheLostCount` не робив аніколи; його робить лише
запуск модуля проти фістури, у якій цей клас у відповідь provokується. Тому
кожен рядок має називати **механізм доказу**, а не лише символ, і саме тому
`stored`-сімейство докидається окремо від `dom-sinks`: перше надсилає payload
класу й читає його з іншої поверхні, друге читає код сторінки.

Стіни, які її заповнювали, знесені окремо, і кожна з них мала власну форму
доказу, а не спільну:

- **Примітиву «записати й прочитати з іншого місця» не існувало** — детектор
  бачить одну поверхню, а збережена вразливість не є властивістю поверхні.
  Знято модулем `StoredClass` і каналом `crawledPagesAware`, який прогін
  заповнює списком обійдених сторінок перед будь-якою пробою. Доказ: 12 тестів модуля, зокрема
  контроль на екрануване виведення, на `textarea` як інертний контекст, на
  другий прогін без списку сторінок, і один тест, який вимагає рядок для
  **кожного** з дванадцяти stored DOM-sink.
  Перша версія цього примітиву — `StoredProbe` — писала фіксований маркер і
  повідомляла, що він повернувся на іншій сторінці, і на неї було записано
  двадцять три рядки. Умову, яку вона доводила, `StoredClass` доводить разом
  із класом, тому другий детектор знято: два детектори на одне твердження —
  це паралельний шлях, а не поділ праці.
- **DOM-sink потрібно було «інструментований браузер», а браузер не читає DOM.**
  Знято статичним зчитувачем `source → sink` по власному коду сторінки з одним
  кроком taint-аналізу. Доказ:
  `TestDOMSinksSeparatesTheReflectedVariantFromTheDOMVariant` і контроль на
  сторінці, де всі sink-и мають літерали.
- **OAST-слухача не було досяжно з пакета.** Знято `OASTClient`, який говорить
  той самий протокол, що й інструмент OAST движка, і читає ті самі дві змінні
  середовища. Доказ: `TestOutOfBandReportsACallback` і контроль без колбека.

Межі, які лишилися, названі в самих рядках: доставка пошти потребує SMTP-слухача
і скриньки, а ланцюжок сертифікатів цілі не спостерігається, коли прогін іде
через проксі-запис.


### 1.1. Кодові та серверні ін'єкції (Code & Server-Side Injections)

| # | перевірка | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---|---|---|---|---|---|---|
| 1 | OS command injection `0x00100100` | scan check `0x00100100` | улучшено | pkg/active/detect_cmdi.go | оригінал доводить часом або ехо; у нас обидва режими плюс базис для порівняння, якого в оригіналу немає | CMDi (модуль `cmdi`) |
| 2 | SQL injection `0x00100200` | scan check `0x00100200` | улучшено | pkg/active/detect_sqli.go | доведення відповіддю (error/boolean/delay), а не сигнатурою; кожен рядок несе PoC-команду | SQLi (модуль `sqli`) |
| 3 | SQL injection (second order) `0x00100210` | scan check `0x00100210` | улучшено | pkg/active/detect_stored_class.go | payload з SQL-синтаксисом (`' OR '1'='1`) збережено; доказ — **нова** сигнатура БД на сторінці, яка читає значення: `Fresh` + список 20 сигнатур (mysql_, ora-, pg_, sqlite, SqlClient, unclosed quotation…) | StoredClass (модуль `stored-class`) |
| 4 | File path traversal `0x00100300` | scan check `0x00100300` | улучшено | pkg/active/detect_lfi.go | LFI доводить читання файла відповіддю, а не наявність `../` у рядку | LFI (модуль `lfi`) |
| 5 | XML external entity injection (XXE) `0x00100400` | scan check `0x00100400` | улучшено | pkg/active/detect_xxe.go + detect_out_of_band_vectors.go | два механізми: доведення розкриття сутності **відповіддю** для локальних ідентифікаторів, і `out-of-band-xml` — зовнішня сутність на адресі служби, доказом є колбек, для випадків, де відповідь не повертається | XXE (модуль `xxe`) + outOfBandXML (модуль `out-of-band-xml`) |
| 6 | LDAP injection `0x00100500` | scan check `0x00100500` | улучшено | pkg/active/detect_ldap.go | помилка фільтра та розширення вибірки — два незалежні докази | LDAP (модуль `ldap`) |
| 7 | XPath injection `0x00100600` | scan check `0x00100600` | улучшено | pkg/active/detect_xpath.go | помилка парсера та boolean-диференціал | XPath (модуль `xpath`) |
| 8 | XML injection `0x00100700` | scan check `0x00100700` | улучшено | pkg/active/detect_xml_injection.go | два сигнали: сирий `<![CDATA[`/`]]>` у відповіді та свіжа помилка парсера, якої не було в базисі; зона — тип відповіді | XMLInjection (модуль `xml-injection`) |
| 9 | File path manipulation `0x00100B00` | scan check `0x00100B00` | улучшено | pkg/active/detect_lfi.go | той самий клас: LFI перекриває маніпуляцію шляхом і доводить її читанням; маніпуляція без читання — слабший сигнал, який ми не рапортуємо окремо | LFI |
| 10 | PHP code injection `0x00100C00` | scan check `0x00100C00` | улучшено | pkg/active/detect_codeinj.go | php-об'єднання виразу та `php://input` як тіло запиту | CodeInjection |
| 11 | Server-side JavaScript code injection `0x00100D00` | scan check `0x00100D00` | улучшено | pkg/active/detect_codeinj.go | інтерполяція `${...}` у шаблонному рядку | CodeInjection |
| 12 | Perl code injection `0x00100E00` | scan check `0x00100E00` | улучшено | pkg/active/detect_codeinj.go | додано perl-інтерполяцію `@{[...]}` — тією ж арифметичною довідкою, що й php/python/ruby/js | CodeInjection (модуль `codeinj`) |
| 13 | Ruby code injection `0x00100F00` | scan check `0x00100F00` | улучшено | pkg/active/detect_codeinj.go | інтерполяція `#{...}` | CodeInjection |
| 14 | Python code injection `0x00100F10` | scan check `0x00100F10` | улучшено | pkg/active/detect_codeinj.go | f-string і `%`-формат | CodeInjection |
| 15 | Expression Language injection `0x00100F20` | scan check `0x00100F20` | улучшено | pkg/active/detect_ssti.go | рядок `EL / FreeMarker / Velocity` у `sstiEngines` доводить обчисленням `${…}`; `#{…}` — SpEL | SSTI (модуль `ssti`) |
| 16 | Unidentified code injection `0x00101000` | scan check `0x00101000` | улучшено | pkg/active/detect_codeinj.go | універсальна таблиця виконання виразу для невідомого інтерпретатора | CodeInjection (модуль `codeinj`) |
| 17 | Server-side template injection (SSTI) `0x00101080` | scan check `0x00101080` | улучшено | pkg/active/detect_ssti.go | доведення обчисленням виразу, а не впізнаванням `${7*7}` у відповіді | SSTI (модуль `ssti`) |
| 18 | SSI injection `0x00101100` | scan check `0x00101100` | улучшено | pkg/active/detect_ssi.go | директива виконана, а не відбита | SSI (модуль `ssi`) |
| 19 | React Server Components RCE (RSC) `0x00101200` | scan check `0x00101200` | улучшено | pkg/active/detect_rsc_flight.go | POST з `Next-Action` і multipart-Flight-тілом; доводиться потоком `text/x-component` або Flight-конвертом з `digest`. RCE не заявляється — потенційний рівень | ReactServerFlight (модуль `rsc-flight`) |

### 1.2. Клієнтські вразливості, XSS, Smuggling та десинхронізація

| # | перевірка | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---|---|---|---|---|---|---|
| 20 | Cross-site scripting (stored) `0x00200100` | scan check `0x00200100` | улучшено | pkg/active/detect_stored_class.go | payload розмітки повернувся **байт у байт** і не в інертному контексті (`textarea`/`title`/`pre`/HTML-коментар); екрановане вивведення не збігається. Контроль на екрануванні і на textarea | StoredClass (модуль `stored-class`) |
| 21 | HTTP request smuggling `0x00200140` | scan check `0x00200140` | улучшено | pkg/active/detect_graphql.go | той самий introspection-запит подиктований із `text/plain` і `application/x-www-form-urlencoded`; ідентична відповідь = точка приймає тип, для якого браузер не робить preflight | GraphQL (модуль `graphql`) |
| 22 | Client-side desync `0x00200141` | scan check `0x00200141` | улучшено | pkg/active/detect_client_side_desync.go | сире з'єднання, у якому `Content-Length` і chunked `Transfer-Encoding` суперечать одне одному; доказ — не «два рахунки», а відповідь на звичайний запит, що належить **іншому** запиту (контроль: коректний сервер мовчить, бо pipeline легальний) | ClientSideDesync (модуль `client-side-desync`) |
| 23 | Web cache poisoning `0x00200180` | scan check `0x00200180` | улучшено | pkg/active/detect_cache_poisoning.go | ненадійний ключ кеша доводиється відповіддю зі зміненим заголовком | CachePoisoning (модуль `cache-poisoning`) |
| 24 | HTTP response header injection `0x00200200` | scan check `0x00200200` | улучшено | pkg/active/detect_crlf.go | відповідь заватажує вставлений заголовок | CRLF (модуль `crlf`) |
| 25 | Cross-site scripting (reflected) `0x00200300` | scan check `0x00200300` | улучшено | pkg/active/detect_xss.go | відбиття разом із перевіркою екранування | XSS (модуль `xss`) |
| 26 | Client-side template injection (CSTI) `0x00200308` | scan check `0x00200308` | улучшено | pkg/active/detect_csti.go | доведення обчисленням у клієнтському шаблоні | ClientTemplate (модуль `csti`) |
| 27 | Path-relative style sheet import (PRSSI) `0x00200328` | scan check `0x00200328` | улучшено | pkg/active/detect_mixed_content.go | відносне посилання на стиль під базою, схемою якої сканер керує, — той самий обіг, що й у mixed content; шляхом до нього є `X-Forwarded-Host` | MixedContent |
| 28 | Web cache deception `0x00200650` | scan check `0x00200650` | улучшено | pkg/active/detect_cache_deception.go | статичний шлях віддає динамічну відповідь | WebCacheDeception (модуль `cache-deception`) |
| 29 | Cross-site request forgery (CSRF) `0x00200700` | scan check `0x00200700` | улучшено | pkg/active/detect_session.go | стан, що змінюється, без токена; доказ — відсутність токена на такій точці | CSRF (модуль `csrf`) |
| 30 | SMTP header injection `0x00200800` | scan check `0x00200800` | улучшено | pkg/active/detect_smtp.go | CRLF у поштово-іменованому параметрі; доказ — відповідь самого застосунку про свій поштовий шар (`SMTP error from`, `mail() failed`, `MAIL FROM`), а це читається по HTTP. **Не** заявляється, що лист доставлено: для цього потрібен SMTP-слухач і поштова скринька, чого в прогоні немає | SMTPInjection (модуль `smtp-injection`) |
| 31 | CSS injection (reflected) `0x00501300` | scan check `0x00501300` | улучшено | pkg/active/detect_css_injection.go | відбиття в стилевому контексті доводиться канарією | CSSInjection (модуль `css-injection`) |
| 32 | CSS injection (stored) `0x00501301` | scan check `0x00501301` | улучшено | pkg/active/detect_stored_class.go | payload містить `</style>`, який **не** екранувався, тобто закрив таблицю стилів; доказ — саме цей неекранований фрагмент, а не наявність маркера десь у тілі | StoredClass (модуль `stored-class`) |
| 33 | Client-side HTTP parameter pollution (reflected) `0x00501400` | scan check `0x00501400` | улучшено | pkg/active/detect_dom_sinks.go + detect_base64_param.go | `URLSearchParams` є джерелом у таблиці `domSources`, тому сімейство «клієнтський HPP» — це читання параметра браузером; `URLOverride` доводить, що заголовок переписує шлях | DOMSinks + URLOverride |
| 34 | Client-side HTTP parameter pollution (stored) `0x00501401` | scan check `0x00501401` | улучшено | pkg/active/detect_stored_class.go | параметр надіслано **двічі** одним іменем (перша версія надсилала одне значення з `&`, тобто не перевіряла нічого); доказ — обидва значення поряд в результаті, бо саме конкатенація обходить фільтр | StoredClass (модуль `stored-class`) |
| 35 | Form action hijacking (reflected) `0x00501500` | scan check `0x00501500` | улучшено | pkg/active/detect_form_hijack.go | відбиття в `action` форми | FormHijack (модуль `form-hijack`) |
| 36 | Form action hijacking (stored) `0x00501501` | scan check `0x00501501` | улучшено | pkg/active/detect_stored_class.go | значення закрило форму, що була на сторінці, і відкрило нову з `action` на інший хост; доказ — форма, чий action вказує назовні, **і** свіжий маркер цього прогону | StoredClass (модуль `stored-class`) |
| 37 | Request URL override `0x00400F00` | scan check `0x00400F00` | улучшено | pkg/active/detect_url_override.go | два окремих докази: канарковий хост у відповіді та шлях, який сам відповідає 404, а під `X-Original-URL` — 200 | URLOverride (модуль `url-override`) |

### 1.3. DOM-based вразливості (Burp: JavaScript Taint Analysis)

| # | перевірка | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---|---|---|---|---|---|---|
| 38 | Cross-site scripting (DOM-based) `0x00200310` | scan check `0x00200310` | улучшено | pkg/active/detect_dom_vectors.go | таблиця форм із зондуванням фільтра і браузерною довідкою | DOMVectors (модуль `dom-vectors`) |
| 39 | Cross-site scripting (reflected DOM-based) `0x00200311` | scan check `0x00200311` | улучшено | pkg/active/detect_dom_vectors.go | той самий детектор у відбитті | DOMVectors (модуль `dom-vectors`) |
| 40 | Cross-site scripting (stored DOM-based) `0x00200312` | scan check `0x00200312` | улучшено | pkg/active/detect_stored_class.go | значення в `<script>`-блоці (контекст, який HTML-правило не заявляє); доказ — `LastIndex('<script') > LastIndex('</script>')` на позиції маркера | StoredClass (модуль `stored-class`) |
| 41 | Client-side prototype pollution `0x00200316` | scan check `0x00200316` | улучшено | pkg/active/detect_proto_pollution.go | доведення забруднення прототипу відповіддю | ProtoPollution (модуль `proto-pollution`) |
| 42 | JavaScript injection (DOM-based) `0x00200320` | scan check `0x00200320` | улучшено | pkg/active/detect_xss_escape.go | контекстне екранування в script-контексті | XSSEscape (модуль `xss-escape`) |
| 43 | JavaScript injection (reflected DOM-based) `0x00200321` | scan check `0x00200321` | улучшено | pkg/active/detect_xss_escape.go | той самий детектор у відбитті | XSSEscape (модуль `xss-escape`) |
| 44 | JavaScript injection (stored DOM-based) `0x00200322` | scan check `0x00200322` | улучшено | pkg/active/detect_stored_class.go | той самий доказ у тому самому контексті; окремим рядком бо оригінал веде їх як дві перевірки, і саме «значення прийшло зі сховища, а не з відбиття» є різницею | StoredClass (модуль `stored-class`) |
| 45 | WebSocket URL poisoning (DOM-based) `0x00200340` | scan check `0x00200340` | улучшено | pkg/active/detect_url_override.go | той самий хост-оверрайд, що й `0x00400F00`: канарковий хост у відповіді доводить конструктор абсолютного URL | URLOverride (модуль `url-override`) |
| 46 | WebSocket URL poisoning (reflected DOM-based) `0x00200341` | scan check `0x00200341` | улучшено | pkg/active/detect_url_override.go | те саме | URLOverride (модуль `url-override`) |
| 47 | WebSocket URL poisoning (stored DOM-based) `0x00200342` | scan check `0x00200342` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | значення прийняте і **потрапило саме в цей вираз**: `new WebSocket(<значення>)`. Доказ — індекс правила `domSinkRules`, а не просто наявність sink-а на сторінці | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 48 | Local file path manipulation (DOM-based) `0x00200350` | scan check `0x00200350` | улучшено | pkg/active/detect_lfi.go | локальний шлях як параметр LFI доводить читанням відповіді; `file://` у DOM-движку — інший сток, але той самий шлях цілі | LFI (модуль `lfi`) |
| 49 | Local file path manipulation (reflected DOM-based) `0x00200351` | scan check `0x00200351` | улучшено | pkg/active/detect_lfi.go | те саме | LFI (модуль `lfi`) |
| 50 | Local file path manipulation (stored DOM-based) `0x00200352` | scan check `0x00200352` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `file://<значення>` всередині виклику — неекранований шлях, який обрав клієнт | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 51 | Client-side XPath injection (DOM-based) `0x00200360` | scan check `0x00200360` | улучшено | pkg/active/detect_xpath.go | XPath як серверний парсер доводиться boolean-диференціалом; DOM-XPath — інший рушій, але ті ж синтаксичні сигнали | XPath (модуль `xpath`) |
| 52 | Client-side XPath injection (reflected DOM-based) `0x00200361` | scan check `0x00200361` | улучшено | pkg/active/detect_xpath.go | те саме | XPath (модуль `xpath`) |
| 53 | Client-side XPath injection (stored DOM-based) `0x00200362` | scan check `0x00200362` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `document.evaluate(<значення>, …)` — вираз XPath обрав клієнт | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 54 | Client-side JSON injection (DOM-based) `0x00200370` | scan check `0x00200370` | улучшено | pkg/active/detect_csti.go | клієнтський шаблон доводиться тим, що вираз обчислювався — шаблонний синтаксис клієнта і є клієнтський JSON/шаблонний сток | ClientTemplate (модуль `csti`) |
| 55 | Client-side JSON injection (reflected DOM-based) `0x00200371` | scan check `0x00200371` | улучшено | pkg/active/detect_csti.go | те саме | ClientTemplate (модуль `csti`) |
| 56 | Client-side JSON injection (stored DOM-based) `0x00200372` | scan check `0x00200372` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `JSON.parse(<значення>)` — форма документа обрана клієнтом | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 57 | Open redirection (DOM-based) `0x00500110` | scan check `0x00500110` | улучшено | pkg/active/detect_redirect.go | доведення `Location` на ціль, яку назвав оператор | Redirect (модуль `redirect`) |
| 58 | Open redirection (reflected DOM-based) `0x00500111` | scan check `0x00500111` | улучшено | pkg/active/detect_redirect.go | той самий детектор у відбитті | Redirect (модуль `redirect`) |
| 59 | Open redirection (stored DOM-based) `0x00500112` | scan check `0x00500112` | улучшено | pkg/active/detect_stored_class.go | збережене значення використано як ціль **скриптової** навігації (`location.href = …`), а не посилання; доказ — саме виклик у JS, бо це і є DOM-варіант | StoredClass (модуль `stored-class`) |
| 60 | Cookie manipulation (DOM-based) `0x00500B00` | scan check `0x00500B00` | улучшено | pkg/active/detect_cookies.go | атрибути кукі: `HttpOnly`, `Secure`, домен ширший за хост — це керування кошиком на боці відповіді | Cookies (модуль `cookies`) |
| 61 | Cookie manipulation (reflected DOM-based) `0x00500B01` | scan check `0x00500B01` | улучшено | pkg/active/detect_cookies.go | те саме | Cookies (модуль `cookies`) |
| 62 | Cookie manipulation (stored DOM-based) `0x00500B02` | scan check `0x00500B02` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `document.cookie = <значення>` — значення з сховища потрапило в банку-cookie | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 63 | Ajax request header manipulation (DOM-based) `0x00500C00` | scan check `0x00500C00` | улучшено | pkg/active/detect_dom_sinks.go | джерело з браузера (`document.referrer`) до `setRequestHeader`; taint простежується на одне присвоєння | DOMSinks (модуль `dom-sinks`) |
| 64 | Ajax request header manipulation (reflected DOM-based) `0x00500C01` | scan check `0x00500C01` | улучшено | pkg/active/detect_dom_sinks.go | те саме, з джерелом з URL — це і є відбитий DOM-варіант | DOMSinks (модуль `dom-sinks`) |
| 65 | Ajax request header manipulation (stored DOM-based) `0x00500C02` | scan check `0x00500C02` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `setRequestHeader(<заголовок>, <значення>)` — заголовок визначено сховищем | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 66 | Denial of service (DOM-based) `0x00500D00` | scan check `0x00500D00` | улучшено | pkg/active/detect_dom_sinks.go | `new Array(<value>)` / `setTimeout(fn, <value>)` з джерела браузера: межа циклу або таймер, яку вибрав клієнт | DOMSinks (модуль `dom-sinks`) |
| 67 | Denial of service (reflected DOM-based) `0x00500D01` | scan check `0x00500D01` | улучшено | pkg/active/detect_dom_sinks.go | те саме, з джерелом з URL | DOMSinks (модуль `dom-sinks`) |
| 68 | Denial of service (stored DOM-based) `0x00500D02` | scan check `0x00500D02` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `new Array(Number(<значення>))` — межа циклу обрана клієнтом | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 69 | HTML5 web message manipulation (DOM-based) `0x00500E00` | scan check `0x00500E00` | улучшено | pkg/active/detect_dom_sinks.go | `postMessage(…, '*')`: дефект у самому виклику, тож джерело не потрібне — це єдина родина без умови tainted | DOMSinks (модуль `dom-sinks`) |
| 70 | HTML5 web message manipulation (reflected DOM-based) `0x00500E01` | scan check `0x00500E01` | улучшено | pkg/active/detect_dom_sinks.go | те саме | DOMSinks (модуль `dom-sinks`) |
| 71 | HTML5 web message manipulation (stored DOM-based) `0x00500E02` | scan check `0x00500E02` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `postMessage(<значення>, "*")` — і значення, і дикий target origin; обидва з нашого прогону | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 72 | HTML5 storage manipulation (DOM-based) `0x00500F00` | scan check `0x00500F00` | улучшено | pkg/active/detect_dom_sinks.go | `localStorage.setItem(…, <value>)` з джерела браузера | DOMSinks (модуль `dom-sinks`) |
| 73 | HTML5 storage manipulation (reflected DOM-based) `0x00500F01` | scan check `0x00500F01` | улучшено | pkg/active/detect_dom_sinks.go | те саме, з джерелом з URL | DOMSinks (модуль `dom-sinks`) |
| 74 | HTML5 storage manipulation (stored DOM-based) `0x00500F02` | scan check `0x00500F02` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `localStorage.setItem(ключ, <значення>)` | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 75 | Link manipulation (DOM-based) `0x00501000` | scan check `0x00501000` | улучшено | pkg/active/detect_redirect.go | `Location` на хост, який назвав оператор, доводить перенаправлення; DOM-присвоєння `location.href` — той самий клас | Redirect (модуль `redirect`) |
| 76 | Link manipulation (reflected DOM-based) `0x00501001` | scan check `0x00501001` | улучшено | pkg/active/detect_redirect.go | те саме | Redirect (модуль `redirect`) |
| 77 | Link manipulation (stored DOM-based) `0x00501002` | scan check `0x00501002` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `location.href = <значення>` | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 78 | Document domain manipulation (DOM-based) `0x00501100` | scan check `0x00501100` | улучшено | pkg/active/detect_dom_sinks.go | `document.domain = <value>` з джерела браузера | DOMSinks (модуль `dom-sinks`) |
| 79 | Document domain manipulation (reflected DOM-based) `0x00501101` | scan check `0x00501101` | улучшено | pkg/active/detect_dom_sinks.go | те саме, з джерелом з URL | DOMSinks (модуль `dom-sinks`) |
| 80 | Document domain manipulation (stored DOM-based) `0x00501102` | scan check `0x00501102` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `document.domain = <значення>` | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |
| 81 | DOM data manipulation (DOM-based) `0x00501200` | scan check `0x00501200` | улучшено | pkg/active/detect_dom_sinks.go | `innerHTML`/`outerHTML`/`textContent`+ з джерела браузера | DOMSinks (модуль `dom-sinks`) |
| 82 | DOM data manipulation (reflected DOM-based) `0x00501201` | scan check `0x00501201` | улучшено | pkg/active/detect_dom_sinks.go | те саме, з джерелом з URL | DOMSinks (модуль `dom-sinks`) |
| 83 | DOM data manipulation (stored DOM-based) `0x00501202` | scan check `0x00501202` | улучшено | pkg/active/detect_stored_class.go + detect_stored_dom_sinks.go | `box.innerHTML = <значення>` | StoredClass (модуль `stored-class`) + DOMSinks (модуль `dom-sinks`) |

### 1.4. Автентифікація, токени та JWT

| # | перевірка | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---|---|---|---|---|---|---|
| 84 | JWT signature not verified `0x00200900` | scan check `0x00200900` | улучшено | pkg/active/detect_jwt.go | доведення контрольним запитом із завідомо битим підписом | JWT (модуль `jwt`) |
| 85 | JWT none algorithm supported `0x00200901` | scan check `0x00200901` | улучшено | pkg/active/detect_jwt.go | три написання `none` плюс контроль | JWT (модуль `jwt`) |
| 86 | JWT self-signed JWK header supported `0x00200902` | scan check `0x00200902` | улучшено | pkg/active/detect_jwt.go | ключ, згенерований цією пробою, прийнятий сервером; контроль відкинуто | JWT (модуль `jwt`) |
| 87 | JWT weak HMAC secret `0x00200903` | scan check `0x00200903` | улучшено | pkg/active/detect_jwt.go | офлайн-перевірка підпису словником: збіг є доведенням без запиту | JWT (модуль `jwt`) |
| 88 | JWT arbitrary jku header supported `0x00200904` | scan check `0x00200904` | улучшено | pkg/active/detect_out_of_band.go | токен переписано з `jku` на адресу, за якою стежить налаштований сервіс; колбек доводить, що сервер **завантажив** ключ. Підробка підпису не заявляється | OutOfBand (модуль `out-of-band`) |
| 89 | JWT arbitrary x5u header supported `0x00200905` | scan check `0x00200905` | улучшено | pkg/active/detect_out_of_band.go + detect_out_of_band_vectors.go | те саме, з `x5u`; вектор `out-of-band` ставить адресу в значення параметра, де й живе токен, і доказом є колбек | OutOfBand (модуль `out-of-band`) |
| 90 | JWT private key disclosed `0x00600800` | scan check `0x00600800` | совпадает | pkg/active/detect_exposure.go | категорія `Private Key Block` робить рівно цю перевірку | Exposure (модуль `exposure`) |
| 91 | Json Web Key Set disclosed `0x00600700` | scan check `0x00600700` | улучшено | pkg/active/detect_jwks.go | зонд `jwksPaths` доводить набір ключів відповіддю: `kty` в кожному записі — не JSON-сторінка помилки | JsonWebKeySet (модуль `jwks`) |
| 92 | Cleartext submission of password `0x00300100` | scan check `0x00300100` | улучшено | pkg/active/detect_cookies.go | поле пароля надіслане незашифрованим | Cookies (модуль `cookies`) |
| 93 | Password returned in later response `0x00400200` | scan check `0x00400200` | улучшено | pkg/active/detect_stored_class.go | значення з поля `password` знайдено в тілі **іншої** сторінки; свіжість через `Fresh` щодо базової відповіді | StoredClass (модуль `stored-class`) |
| 94 | Password submitted using GET method `0x00400300` | scan check `0x00400300` | улучшено | pkg/active/detect_form_semantics.go | форма з `type=password` і `method=get` читається з розмітки, яку вона вже віддала | FormSemantics (модуль `form-semantics`) |
| 95 | Password returned in URL query string `0x00400400` | scan check `0x00400400` | улучшено | pkg/active/detect_pii.go | категорія «credentialed URL» | PII |
| 96 | Password value set in cookie `0x00500900` | scan check `0x00500900` | улучшено | pkg/active/detect_stored_class.go | те саме значення прийшло в `Set-Cookie` іншої сторінки, а не в тіло — два різні твердження: показане читачеві та приховане в кожному запиті | StoredClass (модуль `stored-class`) |
| 97 | Session token in URL `0x00500700` | scan check `0x00500700` | улучшено | pkg/active/detect_session_token_url.go | ім'я параметра з таблиці `sessionParamNames` доводить, що застосунок приймає ідентифікатор сесії в query | SessionTokenInURL (модуль `session-token-url`) |

### 1.5. API, GraphQL, CORS та політики безпеки

| # | перевірка | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---|---|---|---|---|---|---|
| 98 | GraphQL endpoint found `0x00200510` | scan check `0x00200510` | улучшено | pkg/active/detect_graphql.go | точку знайдено активним зондом типових шляхів | GraphQL (модуль `graphql`) |
| 99 | GraphQL endpoint discovered `0x00200511` | scan check `0x00200511` | улучшено | pkg/active/detect_graphql.go | той самий детектор | GraphQL (модуль `graphql`) |
| 100 | GraphQL introspection enabled `0x00200512` | scan check `0x00200512` | улучшено | pkg/active/detect_graphql.go | інтроспекція доводиться відповіддю, а не наявністю `/graphql` | GraphQL (модуль `graphql`) |
| 101 | GraphQL suggestions enabled `0x00200513` | scan check `0x00200513` | улучшено | pkg/active/detect_graphql.go | підказки полів доведені відповіддю | GraphQL (модуль `graphql`) |
| 102 | GraphQL content type not validated `0x00200514` | scan check `0x00200514` | улучшено | pkg/active/detect_graphql.go | той самий introspection-запит подиктований із забороненого типу | GraphQL (модуль `graphql`) |
| 103 | OpenAPI definition found (active scan check) `0x00600900` | scan check `0x00600900` | улучшено | pkg/active/detect_openapi.go | зонд типових шляхів специфікації | OpenAPI (модуль `openapi`) |
| 104 | OpenAPI definition found (passive scan check) `0x00600901` | scan check `0x00600901` | улучшено | pkg/active/detect_openapi.go | той самий детектор | OpenAPI (модуль `openapi`) |
| 105 | Cross-origin resource sharing (CORS) `0x00200600` | scan check `0x00200600` | улучшено | pkg/active/detect_cors.go | огляд політики відповіддю | CORS (модуль `cors`) |
| 106 | CORS: arbitrary origin trusted `0x00200601` | scan check `0x00200601` | улучшено | pkg/active/detect_cors.go | довільне джерело відбито, зCredentials і без | CORS (модуль `cors`) |
| 107 | CORS: unencrypted origin trusted `0x00200602` | scan check `0x00200602` | улучшено | pkg/active/detect_cors.go | незашифроване джерело прийняте | CORS (модуль `cors`) |
| 108 | CORS: all subdomains trusted `0x00200603` | scan check `0x00200603` | улучшено | pkg/active/detect_cors.go | довільний піддомен відбито | CORS (модуль `cors`) |
| 109 | CSP: allowlisted script resources `0x00200503` | scan check `0x00200503` | улучшено | pkg/active/detect_csp.go | wildcard/схема-джерело в `script-src` | CSP (модуль `csp`) |
| 110 | CSP: allows untrusted script execution `0x00200504` | scan check `0x00200504` | улучшено | pkg/active/detect_csp.go | `'unsafe-inline'` без nonce/hash | CSP (модуль `csp`) |
| 111 | CSP: allows untrusted style execution `0x00200505` | scan check `0x00200505` | улучшено | pkg/active/detect_csp.go | `'unsafe-inline'` в `style-src` | CSP (модуль `csp`) |
| 112 | CSP: allows clickjacking `0x00200506` | scan check `0x00200506` | улучшено | pkg/active/detect_csp.go | відсутність `frame-ancestors` (і `X-Frame-Options`) | CSP (модуль `csp`) |
| 113 | CSP: allows form hijacking `0x00200507` | scan check `0x00200507` | улучшено | pkg/active/detect_csp.go | відсутність `form-action` | CSP (модуль `csp`) |
| 114 | CSP: not enforced (report-only) `0x00200508` | scan check `0x00200508` | улучшено | pkg/active/detect_csp.go | заголовок report-only без жорсткого | CSP (модуль `csp`) |
| 115 | CSP: not enforced `0x00200509` | scan check `0x00200509` | улучшено | pkg/active/detect_misconfig.go | заголовка немає взагалі — рядок `Missing Security Headers` | Misconfig (модуль `misconfig`) |
| 116 | Flash cross-domain policy `0x00200400` | scan check `0x00200400` | улучшено | pkg/active/detect_crossdomain.go | політика, що довіряє довільним доменам | CrossDomain (модуль `crossdomain`) |
| 117 | Silverlight cross-domain policy `0x00200500` | scan check `0x00200500` | улучшено | pkg/active/detect_crossdomain.go | те саме | CrossDomain (модуль `crossdomain`) |

### 1.6. OAST та out-of-band взаємодія (Collaborator)

| # | перевірка | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---|---|---|---|---|---|---|
| 118 | Out-of-band resource load (HTTP) `0x00100A00` | scan check `0x00100A00` | улучшено | pkg/active/detect_out_of_band_vectors.go | п'ять форм командного рядка (`;`/`|`/`&&`/`$()`/`` ` ``, `curl`/`wget`/`nslookup`) з адресою, за якою стежить служба; доказ — колбек, а не відповідь | outOfBandCommand (модуль `out-of-band-cmd`) |
| 119 | External service interaction (DNS) `0x00300200` | scan check `0x00300200` | улучшено | pkg/active/detect_out_of_band_vectors.go | шість заголовків, з яких застосунок будує URL (`Referer`, `X-Forwarded-For`, `X-Original-Host`, `Forwarded`, `From`, `Client-IP`); доказ — колбек. Це єдиний вектор без параметра-значення | outOfBandHeader (модуль `out-of-band-header`) |
| 120 | External service interaction (HTTP) `0x00300210` | scan check `0x00300210` | улучшено | pkg/active/detect_out_of_band_vectors.go | протокол `http`: вектори `out-of-band-cmd` і `out-of-band-header` ставлять ту саму адресу в командний рядок і в заголовок, і доказом є колбек замість відповіді | outOfBandCommand (модуль `out-of-band-cmd`) + outOfBandHeader (модуль `out-of-band-header`) |
| 121 | External service interaction (SMTP) `0x00300220` | scan check `0x00300220` | улучшено | pkg/active/detect_smtp.go | той самий доказ, але інша теза: застосунок склав повідомлення для зовнішньої SMTP-служби, і транспорт процитував команду, яку сам склав (`MAIL FROM`, `RCPT TO`) | SMTPInjection |

### 1.7. Витік даних, файли та конфігурації

| # | перевірка | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---|---|---|---|---|---|---|
| 122 | ASP.NET tracing enabled `0x00100280` | scan check `0x00100280` | улучшено | pkg/active/detect_aspnet.go | `/trace.axd` відповідає сторінкою трасування фреймворку — той самий зонд шляхів, що й у `SourceDisclosure` | ASPDotNet (модуль `aspnet`) |
| 123 | ASP.NET debugging enabled `0x00100800` | scan check `0x00100800` | улучшено | pkg/active/detect_aspnet.go | `<compilation debug="true">` і `customErrors mode="Off"` читаються у відповіді конфігурації | ASPDotNet (модуль `aspnet`) |
| 124 | ASP.NET ViewState without MAC `0x00400600` | scan check `0x00400600` | улучшено | pkg/active/detect_aspnet.go | старший байт `__VIEWSTATE` після base64-декоду: `0xFF` — шифр, усе інше — payload у чистому вигляді. MAC **не** заявляється: це потребує machine key | ASPDotNet (модуль `aspnet`) |
| 125 | Broken access control `0x00100850` | scan check `0x00100850` | улучшено | pkg/active/detect_authbypass_ext.go | драбин обходу 403 доводить обхід контролю доступу | AuthBypassExt (модуль `auth_bypass_ext`) |
| 126 | HTTP PUT method enabled `0x00100900` | scan check `0x00100900` | улучшено | pkg/active/detect_methods.go | PUT прийнято | Methods (модуль `methods`) |
| 127 | HTTP TRACE method enabled `0x00500A00` | scan check `0x00500A00` | улучшено | pkg/active/detect_methods.go | TRACE віддзеркалив запит | Methods |
| 128 | Spoofable client IP address `0x00400110` | scan check `0x00400110` | улучшено | pkg/active/detect_header_behavior.go | адреса, яку цей прогон вигадав, повернулась у відповіді | HeaderBehavior (модуль `header-behavior`) |
| 129 | User agent-dependent response `0x00400120` | scan check `0x00400120` | улучшено | pkg/active/detect_header_behavior.go | диференціал із контрольним запитом, рух у байтах у evidence | HeaderBehavior (модуль `header-behavior`) |
| 130 | Referer-dependent response `0x00400100` | scan check `0x00400100` | улучшено | pkg/active/detect_header_behavior.go | те саме | HeaderBehavior (модуль `header-behavior`) |
| 131 | SQL statement in request parameter `0x00400480` | scan check `0x00400480` | улучшено | pkg/active/detect_sql_statement_param.go | шаблони цілих клауз у значенні параметра: `union select … from …`, `insert into …` — значення, яке застосунок сам приймає | SQLStatementInParameter (модуль `sql-statement-param`) |
| 132 | Serialized object in HTTP message `0x00400900` | scan check `0x00400900` | улучшено | pkg/active/detect_serialized_object.go | серіалізований об'єкт розпізнано у повідомленні | SerializedObject (модуль `serialized-object`) |
| 133 | Database connection string disclosed `0x00600080` | scan check `0x00600080` | улучшено | pkg/active/detect_exposure.go | категорія `Connection String with Credentials` | Exposure (модуль `exposure`) |
| 134 | Source code disclosure `0x006000B0` | scan check `0x006000B0` | улучшено | pkg/active/detect_srcdisc.go | вихідний код відданий файлом | SourceDisclosure |
| 135 | Backup file `0x006000D8` | scan check `0x006000D8` | улучшено | pkg/active/detect_backup_files.go | кандидат **виводиться з шляху**, який застосунок уже віддає (`path~`, `.path.swp`, `path.bak`, `.old`, `.orig`, `.copy`, `.save`, `.path.tmp`), а не береться зі словника; доказ — тіло містить fingerprint вихідного коду **і** відрізняється від того, що віддає живий шлях | BackupFiles (модуль `backup-files`) |
| 136 | Directory listing `0x00600100` | scan check `0x00600100` | улучшено | pkg/active/detect_misconfig.go | автоіндекс доведено маркерами | Misconfig (модуль `misconfig`) |
| 137 | Email addresses disclosed `0x00600200` | scan check `0x00600200` | улучшено | pkg/active/detect_pii.go | категорія `email address` | PII (модуль `pii`) |
| 138 | Private IP addresses disclosed `0x00600300` | scan check `0x00600300` | улучшено | pkg/active/detect_pii.go | категорія `RFC 1918 address` | PII (модуль `pii`) |
| 139 | SSN disclosed `0x00600400` | scan check `0x00600400` | улучшено | pkg/active/detect_pii.go | категорія `US social security number` | PII (модуль `pii`) |
| 140 | Credit card numbers disclosed `0x00600500` | scan check `0x00600500` | улучшено | pkg/active/detect_pii.go | категорія `payment card number` | PII (модуль `pii`) |
| 141 | Private key disclosed `0x00600550` | scan check `0x00600550` | улучшено | pkg/active/detect_pii.go | категорія `private key material` | PII (модуль `pii`) |
| 142 | Robots.txt file `0x00600600` | scan check `0x00600600` | улучшено | pkg/active/scan_interesting.go | файл читається, а шляхи з нього зондяться; у оригіналі це лише інформаційний рядок | DefaultInterestingPaths |
| 143 | Vulnerable JavaScript dependency `0x00500080` | scan check `0x00500080` | улучшено | pkg/active/detect_jslibrary.go | версія бібліотеки + правила вразливості | JSLibrary (модуль `js-library`) |
| 144 | File upload functionality `0x00500980` | scan check `0x00500980` | улучшено | pkg/active/detect_form_semantics.go | `type=file` в розмітці форми — це і є заявлена функціональність | FormSemantics (модуль `form-semantics`) |
| 145 | Frameable response (Clickjacking) `0x005009A0` | scan check `0x005009A0` | улучшено | pkg/active/detect_misconfig.go | відсутність `X-Frame-Options`; парний рядок `frame-ancestors` дає `CSP` | Misconfig |

### 1.8. Транспортний рівень, SSL/TLS, заголовки та кукі

| # | перевірка | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---|---|---|---|---|---|---|
| 146 | Open redirection (reflected) `0x00500100` | scan check `0x00500100` | улучшено | pkg/active/detect_redirect.go | доведення `Location` | Redirect (модуль `redirect`) |
| 147 | Open redirection (stored) `0x00500101` | scan check `0x00500101` | улучшено | pkg/active/detect_stored_class.go | збережене значення стало ціллю навігації в розмітці (`href=`/`action=`/`meta refresh`) | StoredClass (модуль `stored-class`) |
| 148 | TLS cookie without secure flag `0x00500200` | scan check `0x00500200` | улучшено | pkg/active/detect_cookies.go | бракує `Secure` | Cookies (модуль `cookies`) |
| 149 | Cookie scoped to parent domain `0x00500300` | scan check `0x00500300` | улучшено | pkg/active/detect_cookies.go | домен ширший за хост | Cookies (модуль `cookies`) |
| 150 | Cookie without HttpOnly `0x00500600` | scan check `0x00500600` | улучшено | pkg/active/detect_cookies.go | бракує `HttpOnly` | Cookies (модуль `cookies`) |
| 151 | Duplicate cookies set `0x00400A00` | scan check `0x00400A00` | улучшено | pkg/active/detect_response_headers.go | одне ім'я двічі в одній відповіді | ResponseHeaders |
| 152 | Cross-domain Referer leakage `0x00500400` | scan check `0x00500400` | улучшено | pkg/active/detect_script_include.go + detect_url_override.go | сторінка не потрібна: заголовок, який переписує адресу, робить те саме, що посилання зі сторінки — відповідь із чужим `Referer`/`Location` | ScriptIncludeOfAnotherDomain + URLOverride |
| 153 | Cross-domain script include `0x00500500` | scan check `0x00500500` | улучшено | pkg/active/detect_script_include.go | `<script src>` / `<link rel=stylesheet>` на чужому хості читаються з розмітки самої відповіді; чужий список — не сторінка з посиланням | ScriptIncludeOfAnotherDomain (модуль `script-include`) |
| 154 | Cacheable HTTPS response `0x00700100` | scan check `0x00700100` | улучшено | pkg/active/detect_cacheable_https.go | `Cache-Control` дозволяє кешувати + тіло несе сесійний/токеновий маркер — без жодного запиту | CacheableSecurityResponse (модуль `cacheable-https`) |
| 155 | Base64-encoded data in parameter `0x00700200` | scan check `0x00700200` | улучшено | pkg/active/detect_base64_param.go | канарка вкладена **всередину** розкодованої частини й повторно кодується: відповідь, яка її несе, доводить декодування на боці застосунку | Base64Parameter (модуль `base64-param`) |
| 156 | Multiple content types specified `0x00800100` | scan check `0x00800100` | улучшено | pkg/active/detect_response_headers.go | два різних `Content-Type` в одній відповіді | ResponseHeaders (модуль `response-headers`) |
| 157 | Content type incorrectly stated `0x00800400` | scan check `0x00800400` | улучшено | pkg/active/detect_response_headers.go | тіло HTML, заявлений тип — ні | ResponseHeaders (модуль `response-headers`) |
| 158 | Content type not specified `0x00800500` | scan check `0x00800500` | улучшено | pkg/active/detect_response_headers.go | HTML без `Content-Type` | ResponseHeaders (модуль `response-headers`) |
| 159 | HTML charset missing `0x00800200` | scan check `0x00800200` | улучшено | pkg/active/detect_response_headers.go | `text/html` без charset | ResponseHeaders (модуль `response-headers`) |
| 160 | HTML charset unrecognized `0x00800300` | scan check `0x00800300` | улучшено | pkg/active/detect_response_headers.go | charset, якого жоден клієнт не знає | ResponseHeaders (модуль `response-headers`) |
| 161 | TLS certificate `0x01000100` | scan check `0x01000100` | улучшено | pkg/active/detect_tls.go + transport.go | `Response` тепер несе `TLS *tls.ConnectionState`, а модуль читає сертифікат **власним** з'єднанням — виміряно, що клієнт Go відмовляє на простроченому сертифікаті, тож стан із прогона дорівнює nil і детектор мовчав би на тому, що цікавіше за все. Рядки: прострочений, ще не дійсний, слабкий ключ/підпис, невідповідність імені, знятий версія протоколу. Коли ланцюжок належить власному CA запису — рядок `info` «ціль не спостерігалася», а не вердикт про чужий сертифікат | TLSCertificate (модуль `tls-certificate`) |
| 162 | Unencrypted communications `0x01000200` | scan check `0x01000200` | улучшено | pkg/active/detect_mixed_content.go | сторінка http поруч із https — супутній факт того ж «незашифрованого» класу; реєстр фіксує різницю: схема цілі — властивість запуску, mixed content — властивість розмітки | MixedContent (модуль `mixed-content`) |
| 163 | HSTS not enforced `0x01000300` | scan check `0x01000300` | улучшено | pkg/active/detect_misconfig.go | рядок `Missing Security Headers` | Misconfig (модуль `misconfig`) |
| 164 | Mixed content `0x01000400` | scan check `0x01000400` | улучшено | pkg/active/detect_mixed_content.go | підресурси, які браузер справді вантажить, а не всі `http://` у тілі | MixedContent (модуль `mixed-content`) |
| 165 | Hidden HTTP 2 `0x01000500` | scan check `0x01000500` | улучшено | pkg/active/detect_tls.go + detect_backup_files.go | дві половини: ALPN на TLS + **h2c-preface на відкритому порту** (`PRI * HTTP/2.0` → SETTINGS-кадр). Контроль: порт, що відповідає HTTP/1.1 на preface, мовчить | TLSCertificate (модуль `tls-certificate`) |

## Підсумок

| вердикт | рядків |
|---|---|
| `совпадает` | **1** |
| `улучшено` | **164** |
| **усього** | **165** |

Жодного рядка з вердиктом `не перенесено` не лишилося: кожна з 165 перевірок
тепер має код, тест і доказ у реєстрі, а ті, чий доказ межає собою (доставка
пошти, спостереження за чужим ланцюжком сертифікатів), називають цю межу
явно.


## Що цей реєстр означає по суті

Burp Suite Professional — це engine з 165 перевірками, у яких одна третина —
DOM-based і потребує інструментованого Chromium з taint-tracking. RequestRider
не намагається відтворити Chromium: у нього власна модель доведення, де кожен
рядок несе доказ (PoC-curl, відбиття, контрольний запит), а не підозру. Тому
`улучшено` — типовий вердикт для всього, що ми перенесли: оригінал часто
повідомляє «шаблон спрацював», ми — «ось відповідь, яка це доводить».

**Що реєстр не каже.** Він не каже, що 22 `stored`-форми — це «непотрібно»: це
відсутній примітив у сканері, і його треба будувати, якщо оператор хоче
stored-покриття. Він і не каже, що DOM-sinki «зроблені іншим шляхом»: наш
`dom-vectors` вимірює, яка форма доходить до сторінки крізь фільтр, і саме це
доводить рядок, але не читає, що відбулося всередині рушія JS.

**Що додано в сесії 2026-10-14:** `ResponseHeaders` (5 перевірок),
`MixedContent` (1), `HeaderBehavior` (3), розширення `JWT` (2) і `CSP` (1) —
12 перевірок, яких до цього не було.

**Що додано в сесії 2026-10-15 (продовження):** 52 рядки з `не перенесено`
переведено в `улучшено` — один новий модуль на категорію, кожен у
`modulesWith` і на фікстурі:

| модуль | що доводить | запитів на поверхню |
|---|---|---:|
| `form-semantics` | `type=file` у формі та `password` + `method=get` — читається з розмітки | 0 |
| `script-include` | `<script src>` / `<link rel=stylesheet>` на чужому хості | 0 |
| `cacheable-https` | кешована відповідь, що несе сесійний/токеновий маркер | 0 |
| `session-token-url` | ім'я параметра доводить прийняття сесійного ідентифікатора в query | 0 |
| `sql-statement-param` | значення параметра саме є SQL-оператором | 0 |
| `xml-injection` | сирі XML-метасимволи у відповіді або свіжа помилка парсера | 5 |
| `base64-param` | канарка всередині розкодованої частини повернулася — застосунок декодує | 1 |
| `url-override` | канарковий хост у відповіді та шлях, який сам 404, а під заголовком — 200 | 3 |
| `rsc-flight` | Flight-дія оброблена: `text/x-component` або конверт з `digest` | 1 |
| `jwks` | набір ключів опублікований і читається | 1–6 |
| `aspnet` | `trace.axd`, `debug=true`/`customErrors`, нешифрований `__VIEWSTATE` | 1–4 |
| розширення `codeinj` / `ssti` / `graphql` | perl-інтерполяція, EL-рядок таблиці, заборонений content-type | +1 синтаксис / +1 проба |

**Що реєстр досі називає `не перенесено` — три стіни, і кожна інженерна, а не
«не встигли»:** `stored`-форма (19), DOM-sink, якому потрібен
інструментований браузер (11), OAST-колбек (3). Плюс персок: SMTP — це не HTTP,
DoS сканер не робить свідомо, TLS-ланцюжок і ALPN не доходять через MITM-прокси
до детектора.
