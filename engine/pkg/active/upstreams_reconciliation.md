# Звірка активного сканера з шістьма зовнішніми інструментами

> Механізм той самий, що в `vexor_reconciliation.md`: перелік здатностей
> знято **з файлових дерев** кожного upstream, з вердиктом на кожен рядок.
> Перевіряється тестом `upstreams_reconciliation_test.go`, який падає на
> вилученому рядку, порожньому або невідомому вердикті, заявленому символі,
> якого немає в дереві, `не перенесено` без причини, нашій здатності без рядка
> та відсутньому коміті upstream.
>
> Шість інструментів, а не один, тому що це шість різних джерел здатностей, і
> одна таблиця на всі — щоб правило «некласифіковане вважається втратою»
> застосовувалось до кожного з них однаково.

## Коміти upstream

Таблиця проти незафіксованого коміту — це таблиця про інший предмет. Коміт
зафіксовано, і тест вимагає, щоб він був.

| інструмент | репозиторій | коміт | дата коміту |
|---|---|---|---|
| Arachni | `https://github.com/Arachni/arachni` | `9cd73f2541ef57814312b0aefe079ad428722b84` | 2026-04-22 |
| Jaeles | `https://github.com/jaeles-project/jaeles` | `d40305ffe42a831b2b144e48d0428de4def4270a` | 2026-06-20 |
| flan | `https://github.com/cloudflare/flan` | `6588b07751f14180ba151842458b97510490fa58` | 2024-09-19 |
| BlackWidow | `https://github.com/1N3/BlackWidow` | `c9eb24e238c390b03897a04c79e55cb17ec35b8c` | 2026-04-17 |
| backslash-powered-scanner | `https://github.com/PortSwigger/backslash-powered-scanner` | `1194cf8651aec69f79e22bf4100f18ec9685d8c5` | 2025-04-30 |
| Eagle | `https://github.com/BitTheByte/Eagle` | `bde6c28af7736ec88edbab51828e3c080791eaa6` | 2021-01-28 |

## Вердикти

Рівно три, четвертого немає: `совпадает`, `улучшено`, `не перенесено`. Стани
«в процесі», «частково», `TODO` і порожній вердикт не допускаються — саме ними
прикривається втрата.

---

## 1. Arachni — `components/checks/active` (36 файлів) і `components/checks/passive` (25 файлів)

### Активні перевірки

| здатність upstream | символ у нас | вердикт | підстава |
|---|---|---|---|
| SQLi: помилки та boolean | `SQLi` | совпадает | `detect_sqli.go`; VEXOR-рядок |
| SQLi: диференціал | `SQLi` | совпадает | `detect_sqli.go` |
| SQLi: часова сліпа | `timeProbe` | совпадает | `detect_sqli.go`; upstream `sql_injection_timing/` має `mssql.txt`, `mysql.txt`, `pgsql.txt` |
| **NoSQL: сліпий диференціал** | `NoSQL`, `nosqlDifferentialPairs` | улучшено | upstream `no_sql_injection_differential.rb` будує 6 пар із трьох видів лапок; у нас пари будуються з шаблонів, а не вписані, і до них додано ще три техніки — операторні документи |
| **NoSQL: відбитки помилки** | `nosqlErrorSignatures` | совпадает | upstream `no_sql_injection/substrings/`: `mongodb`, `Uncaught exception 'MongoCursorException'` |
| **XPath: помилки парсера** | `xpathErrorSignatures` | улучшено | 24 рядки upstream `xpath_injection/errors.txt` перенесено дослівно й **згруповано за стеком**; наш рядок називає реалізацію (libxml2 / SimpleXML / Xalan / MSXML / COM) |
| **XPath: boolean-диференціал** | `xpathBooleanProbes` | улучшено | upstream має лише помилки; наші два раунди побудовані на `count(//*)`, тож не залежать від форми документа |
| **LDAP: помилки каталогу** | `ldapErrorSignatures` | совпадает | усі 29 рядків upstream `ldap_injection/errors.txt`, без вигаданих |
| **LDAP: розширення фільтра** | `ldapWildcardProbes` | улучшено | upstream має лише помилки; наші чотири проби — це спостережувана зміна результату, а не повідомлення сервера |
| **XXE: зовнішній сутнісний документ** | `XXE`, `xxeTargets` | улучшено | upstream `xxe.rb` мусить **переписати документ** (`transform_xml`) і не вміє працювати через параметр; ми вбудовуємо DOCTYPE у значення, і список шляхів unix/windows той самий |
| **XXE: платформа-розрізнення** | `xxeTargets` | совпадает | upstream `self.payloads`: unix `/proc/self/environ`, `/etc/passwd`; windows `%SYSTEMDRIVE%\boot.ini`, `%WINDIR%\win.ini` |
| **Code injection: помилка інтерпретатора** | `CodeInjection`, `codeInjectionSyntaxes` | улучшено | upstream `code_injection.rb` шукає помилку парсера; наші п'ять синтаксисів (PHP, Python ×2, Ruby, JavaScript) вимірюють **обчислення** і вимагають свіжості |
| **Code injection: `php://input`** | `phpWrapperProbe` | улучшено | upstream `code_injection_php_input_wrapper.rb` окремою перевіркою; у нас обгорнуто в той самий модуль і **перевіряється змістом розпакованого** файлу |
| **Code injection: часова** | — | не перенесено | upstream `code_injection_timing.rb` робить інтерпретатор зачекати; наш пакет уже має два часових детектори (`SQLi.BlindDelay`, `CMDi.BlindDelay`) з видимою оператору ціною, і третій додав би витрату без нового виду доказу — затримка інтерпретатора не відрізняється від затримки бази даних у тому самому рядку доказу |
| **CSRF** | `CSRF`, `tokenPresent` | улучшено | upstream `csrf.rb` дивиться на поле токена; наша перевірка також вимагає відсутності `SameSite`, і приймає токен за **формою значення**, а не за ім'ям |
| **Session fixation** | `SessionFixation` | не перенесено | upstream `session_fixation.rb` повідомляє про прийнятий ідентифікатор; довести фіксцію треба увійти під чужими обліковими даними, чого сканер не робить і не проситиме — наш рядок каже **передумову** і не приписує демонстрації |
| **Source code disclosure** | `SourceDisclosure` | улучшено | upstream `source_code_disclosure.rb` спирається на код у відповіді; наш шляховий детектор вимагає ще й **відмінності від м'якого 404** |
| **Response splitting** | `CRLF` | улучшено | upstream `response_splitting.rb`; наш детектор перевіряє і заголовок (планований канар у відповідних заголовках), і тіло, і бере overlong-форми з Eagle |
| **XSS: DOM / події / шлях / script-контекст / тег** | `XSS`, `classifyContext` | улучшено | п'ять активних XSS-перевірок upstream зведено в одну, яка класифікує контекст HTML і ескалює лише виконуваний |
| **RFI** | `LFI` | совпадает | `rfi.rb` шукає `http://` у параметрі; наш `LFI` не робить цього окремо — див. рядок нижче |
| **RFI: окрема перевірка** | — | не перенесено | upstream має `rfi.rb` як окремий модуль, наш — ні: `LFI` доведено файловим вмістом, а RFI потребує callback, якийого в цьому пакеті немає. Рядок про SSRF нижче пояснює, чому callback відсутній |
| **Unvalidated redirect (Location)** | `Redirect`, `redirectVectors` | совпадает | `unvalidated_redirect.rb` |
| **Unvalidated redirect (DOM)** | `Redirect`, `reflectClientRedirect` | улучшено | `unvalidated_redirect_dom.rb`; наш детектор вимагає і віддзеркалення, і навігаційного примітиву |
| **Trainer** | — | не перенесено | `trainer.rb` — це навчальний модуль Arachni, який збирає зразки для його власного движка; у нашому пакеті єдине джерело схем — фістура й тести |
| **Path traversal** | `LFI`, `lfiTechniques` | улучшено | `path_traversal.rb`; шість технік, з PHP-обгорткою, яка не потребує обходу взагалі |
| **OS command injection** | `CMDi` | совпадает | `os_cmd_injection.rb` |
| **OS command injection (timing)** | `CMDi`, `cmdSleepSyntaxes` | совпадает | `os_cmd_injection_timing.rb` |

### Пасивні перевірки

| здатність upstream | символ у нас | вердикт | підстава |
|---|---|---|---|
| **Sensitive files / backups / dirs / admin panels** | `SourceDisclosure`, `sensitiveFiles` | улучшено | Arachni несе ці родини файлів: `passive/common_directories` (499 директорій), `passive/common_admin_interfaces` (50 admin-шляхів), `passive/common_files` і **`passive/backup_directories`**, **`passive/backup_files`** (24 файли), плюс 20 рядків Eagle `senstivefiles.txt`; **жоден** не має відбитка, тому перенесено лише 12 шляхів, у яких тіло відповіді саме визначає файл. Решта лишається доступною оператору через `ScanRequest.InterestingPaths`, бо список без відбитка не можна переносити без хибних спрацювань |
| **Common files (`robots.txt`, `phpinfo.php`, `.git/HEAD`, `web.xml`)** | `sensitiveFiles` | улучшено | перенесено з відбитками; зокрема `.git/HEAD` шукає `ref:`, `phpinfo.php` — `phpinfo()` |
| **Directory listing** | `Misconfig`, `directoryListingMarkers` | совпадает | `passive/directory_listing.rb` |
| **CORS / security headers / htaccess_limit** | `Misconfig` | совпадает | `grep/hsts.rb`, `grep/x_frame_options.rb`, `grep/insecure_cors_policy.rb`, `passive/htaccess_limit.rb` |
| **Emails / SSN / credit cards / private IP** | `PII`, `piiCategories` | улучшено | `grep/{emails,ssn,credit_card,private_ip}.rb` — чотири з дев'яти; кожен вимагає **контексту** поруч із значенням, бо самі по собі номери збігаються з тестовими даними |
| **CVS / SVN users** | `SourceDisclosure` | не перенесено | `grep/cvs_svn_users.rb` шукає список користувачів у CVS-розшифровці; наш детектор уже читає `.svn/entries` і `.git/*` як файли, але **не** парсить CVS-формат — це окремий парсер, а не регулярний вираз |
| **HTML objects / mixed resources / captcha** | — | не перенесено | `grep/{html_objects,mixed_resource,captcha}.rb` — це поради якості сторінки (доступність, змішане вміст, наявність CAPTCHA), а не вразливості; жодна з трьох не має атаки, яку сканер може довести |
| **Password autocomplete / unencrypted password forms** | `Cookies`, `cleartextPasswordFinding` | улучшено | `grep/{password_autocomplete,unencrypted_password_forms}.rb`; з двох перенесено безпечний (форма з паролем на `http://`), а `autocomplete` — це ergonomics, а не доказ |
| **Insecure cookies / HttpOnly / parent domain** | `Cookies` | улучшено | `grep/{insecure_cookies,http_only_cookies,cookie_set_for_parent_domain}.rb`; розділено на два модулі за місцем: прапорці сесійного cookie — це передумова фіксації (`SessionFixation`), решта — тут |
| **Form upload** | — | не перенесено | `grep/form_upload.rb` шукає наявність форми завантаження; вивантаження файлу — це не вразливість без доказу виконання, а наш детектор `Methods` уже доводить запис через PUT |
| **Allowed methods / HTTP PUT / WebDAV / TRACE** | `Methods` | улучшено | `passive/{allowed_methods,http_put,webdav,xst}.rb` — п'ять перевірок зведено в одну; PUT **доводиться** завантаженням і читанням назад, DELETE не перевіряється взагалі (бо підтвердження видалило б дані оператора) |
| **Insecure client access policy / origin spoof** | — | не перенесено | `passive/{insecure_client_access_policy,origin_spoof_access_restriction_bypass}.rb` перевіряють обхід обмеження за IP; щоб довести обхід треба прикинутися іншою адресою, а `Session` не має і не може мати чужої IP-адреси — підміна адреси на транспорті означала б, що сканер надсилає запити від імені чужої машини |
| **Cross-domain policy** | — | не перенесено | `passive/insecure_cross_domain_policy_{access,headers}.rb` перевіряють `crossdomain.xml`, формат Adobe Flash, який вилучений з усіх сучасних браузерів; здатність мертва у своєму предметі |
| **Backdoors** | — | не перенесено | `passive/backdoors/filenames.txt` — це перелік імен файлів, а не доказ; перенесений список без механізму відтворив би увесь `не перенесено` з VEXOR у вигляді, де нічого не перевіряється |
| **Localstart ASP** | — | не перенесено | `passive/localstart_asp.rb` шукає один конкретний артефакт IIS; це один рядок у списку шляхів, а `SourceDisclosure` не має для нього відбитка й тому не може його підтвердити |

---

## 2. Jaeles — `core/`, `libs/`, `database/`

Jaeles — не набір перевірок, а **движок підписів**: правила живуть в окремому
репозиторії, а в цьому дереві лежить механіка, яка їх виконує. Тому перелік
знято з `core/*.go`, а не з правил.

| здатність upstream | символ у нас | вердикт | підстава |
|---|---|---|---|
| Підпис як окремий артефакт (YAML) | — | не перенесено | `core/signature.go`, `core/template.go`: правило — зовнішній YAML, який рунтайм читає з каталогу. Тримати здатності в репозиторії означало б додати чужий підпис-движок з YAML-парсером і завантажувачем — другий спосіб описати детектор поруч із нашим першим, а `AGENTS.md` називає це паралельним шляхом |
| Генератор payloads | `codeInjectionSyntaxes`, `redirectVectors`, `cmdSyntaxes` | совпадает | `core/generator.go`: підпис розмножує запит по генератору; наші таблиці технік роблять те саме, але таблицями, а не інтерпретатором рядка |
| Passive-підписи (grep по відповіді) | `Misconfig`, `PII`, `SourceDisclosure` | улучшено | `core/passive.go`, `libs/passive.go`: passive-правило дивиться на вже зроблений обмін. У нас passive-читачі — `Misconfig`, `PII`, `Cookies`, `SourceDisclosure` — і кожен має обов'язкову свіжість |
| Змінна `[[...]]` у запиті | `Point.Values`, `Transport.Fire` | совпадает | `core/signature.go`, `AltResolveRequest`: підпис підставляє значення у запит; `Fire` робить те саме для одного параметра |
| Фільтри рівня / risk / confidence | `SeverityFor`, `tierCeiling` | улучшено | `core/config.go`, `core/filter.go`: підпис має Risk/Confidence/Level. У нас схема жорсткіша — детектор **не може** назвати severity, лише tier, а кеп визначає `SeverityFor` |
| Конкурентний надсилач | `Scan.probe` | совпадает | `core/sending.go`, `core/runner.go`: пул воркерів; наш `probe` — те саме, з `Concurrency` оператора як шириною |
| Прогрес і завершення | `Progress`, `Scan.emit` | совпадает | `core/conclusions.go`, `core/report.go` |
| Співпрацювальник (OAST / DNS) | `ScanRequest.MarkerHost` | не перенесено | `database/collaborator.go`, `core/dns.go`: Jaeles має власний Collaborator і надсилає callback. У нашому пакеті є лише `MarkerHost` для редиректу; DNS-слухача тут немає, а OAST-слухачі проєкту живуть в engine — дублювати їх у сканері означало б два способи отримати один callback |
| **Бібліотека підписів (signature library)** | `test-signatures/` | не перенесено | Upstream на коміті `d40305ff` **не має** бібліотеки підписів: усі 11 yaml лежать у `test-signatures/` і є фікстурами тестів (`test-sign`, `common-error-01`, `local-analyze`), а каталогу `resources/signatures` у дереві немає. Тож переносити нічого: здатностей на перенос тут нуль, і заявляти їх було б вигадкою. Ядро Jaeles — генератор payloads, підстави `[[…]]`, рівні, паралельний надсилач — класифіковано рядками вище |

---

## 3. flan — `shared/`, `Dockerfile`, `Makefile`

**flan не веб-сканер.** Це обгортка над nmap: сканує TCP-порти, визначає
версії сервісів і звіряє їх із CVE через `vulners.nse`. Його предмет — мережевий
периметр, а предмет `pkg/active` — HTTP-поверхня одного хоста. Рядки нижче
не «втрачені здатності», а розмежування предметів, і воно має бути записане,
бо мовчки пропущене `не перенесено` не відрізняється від «немає чого брати».

| здатність upstream | символ у нас | вердикт | підстава |
|---|---|---|---|
| Сканування TCP-портів | — | не перенесено | `README`: `nmap -sV ... $@ --script=vulners/vulners.nse`. Порти — це інший протокол і інша модель загрози; `pkg/active` має HTTP-транспорт і не відкриває TCP-сокетів |
| Визначення версії сервісу | `Session.Version`, `VersionSource`, `PatchState` | совпадает | Поля версії в нашому `Spec`/`Finding` існують саме для цього і вже використовуються `enumerate.go` |
| Матчинг CVE за версією | — | не перенесено | Матчинг CVE у нас — не робота сканера, а робота корпусу: 98 636 шаблонів nuclei, які і є нашим джерелом CVE. Друга копія цієї бази в сканері розійшлася б з корпусом і ніколи не оновлювалася б |
| Звіти LaTeX / HTML / MD / JSON | — | не перенесено | `Makefile`-цілі `latex`, `html`. Звіт про сканування в проєкті вже є: серверний звіт сканера та експорт у браузері |
| Вивантаження в GCS / S3 | — | не перенесено | `upload` змінна в `README`: вивантаження результатів у хмару. Сканер не має ні сховища, ні облікових даних стороннього сервісу, і не повинен їх мати |
| Розгортання в Kubernetes | — | не перенесено | `README`: деплой у k8s. Це операційна оболонка стороннього сервісу, а не здатність сканування |

---

## 4. BlackWidow — `blackwidow`, `injectx.py`

| здатність upstream | символ у нас | вердикт | підстава |
|---|---|---|---|
| Збір URL з сайту | `harvestAll`, `linksFrom` | совпадает | `scan_crawl.go` |
| Збір динамічних параметрів | `Point`, `Harvest` | совпадает | `points.go`; VEXOR-рядок |
| Збір форм | `formPoints` | совпадает | `points.go` |
| Збір субдоменів | — | не перенесено | `blackwidow` краде DNS-резолв. Збір DNS у проєкті належить OSINT-графу (`engine/osint_sources.go`), а не сканеру: дублювати його тут означало б два способи додати той самий ентіті |
| Збір email-адрес | `PII`, `piiCategories` | улучшено | `blackwidow` їх збирає; наш рядок їх **знаходить з доказом і severity**, тобто робить те, що павук робить, і каже оператору, що з цим робити |
| Збір телефонів | `PII` | совпадает | те саме |
| Fuzz: Open Redirect | `Redirect` | улучшено | `injectx.py` шукає `<title>Google</title>` — тобто надсилає Google як dest і перевіряє, що прийшли саме вони; наш детектор маркує власний хост і порівнює хост **точно** |
| Fuzz: XSS | `XSS` | улучшено | `injectx.py` шукає `alert(1)` у тілі; наш вимагає класифікації HTML-контексту й підтвердження виконання |
| Fuzz: SQLi | `SQLi` | улучшено | `injectx.py` надсилає `'` і `\\` і порівнює довжину; наш вимірює помилку, boolean-диференціал, час і число колонок |
| Fuzz: Directory Traversal | `LFI` | улучшено | 6 форм обходу в `injectx.py` проти 6 технік у `lfiTechniques`, включно з PHP-обгорткою, якої в BlackWidow немає |
| Fuzz: LFI | `LFI` | улучшено | чотири форми в `injectx.py` |
| Fuzz: RFI | — | не перенесено | `injectx.py` шукає `/etc/passwd` у **відповіді на `GET /etc/passwd`** — тобто це не RFI, а перевірка локального читання; вона дублює `LFI`, а справжній RFI потребує callback, якого в пакеті немає |
| Fuzz: SSTI | `SSTI` | улучшено | `injectx.py` надсилає `{{7*7}}`; наш вимагає, щоб продукт був відсутній у baseline |
| Fuzz: Command Execution | `CMDi` | улучшено | `injectx.py` надсилає `;id`; наш має 11 синтаксисів і обов'язкову свіжість |
| Fuzz: IDOR | — | не перенесено | секція `# IDOR Check` у `injectx.py:522` **закоментована повністю** (змінна `idor_list` розкоментована), тож це мертвий код upstream, а не здатність. Переносити нема чого; наш `IDOR`-вектор працює за `Project`-контекстом, а не за перебором сусідніх ідентифікаторів |
| Fuzz: Buffer Overflow | — | не перенесено | секція `# Buffer Overflow Check` у `injectx.py:547` **закоментована повністю**, разом із `print` без дужок, тож навіть розкоментована вона не є Python. Мертвий код upstream; наш пакет має обмеження довжини запиту на рівні виконання, а не детект "на 4000 символів" |

---

## 5. backslash-powered-scanner — `src/burp/*.java`, `resources/`

Це єдиний з шести, чия здатність — **не детекція, а вимірювання**: він визначає
стек екранування між параметром і стоком, щоб інші детектори знали, який payload
писати. Тому це окремий модуль, а не ще один ін'єкційний тест.

| здатність upstream | символ у нас | вердикт | підстава |
|---|---|---|---|
| **Аналіз трансформації через `\`** | `Escaping`, `transformationStack` | улучшено | `TransformationScan.java`: базовий запит `leftAnchor` + `\` + `rightAnchor`, і `backslashConsumed` визначається наближенням «`\zz` повернувся як `zz`». Наш вимір той самий, але з **випадковими** якорями (сталі — це рядок, який сторінка може легітимно містити) і з перевіркою контрольного запиту перед висновком |
| Набір 19 спецсимволів | `transformationSyntaxes` | совпадает | `TransformationScan.java`: `'` `"` `{` `}` `(` `)` `[` `]` `$` `` ` `` `/` `@` `#` `;` `%` `&` `|` `;` `^` `?` — перенесено в тому самому порядку |
| Decode-based payloads | `transformationDecodeProbes` | совпадает | `decodeBasedPayloads` = `101`, `x41`, `u0041`, `0`, `1`, `x0` |
| Визначення мови екранування | `transformationStack` | улучшено | upstream повертає рядки виду `\` + символ + `=>` трансформація; наш повертає **названий шар** (unwrap / один шар / два шари / shell) з доказом у рядку — це відповідь на питання «який payload писати», а не перелік спостережень |
| Bulk scan по точці вставлення | `Point`, `probeSurface` | совпадает | `BulkUtilities.buildTransformationAttack` |
| Diffing-скан (SQLi через екранування) | `SQLi` | улучшено | `WsDiffingScan.java`; наш SQLi вимірює boolean-диференціал і час, а не порівнює екранування |

---

## 6. Eagle — `plugins/*.py`

| здатність upstream | символ у нас | вердикт | підстава |
|---|---|---|---|
| **CRLF-ін'єкція** | `CRLF`, `crlfEncodings` | улучшено | `plugins/crlf.py` надсилає `%0D%0A` і дві overlong-форми; наш бере цей набір **і** перевіряє доказ у відповідних заголовках, де він доказовий, а не в тілі, де він безглуздий |
| Sensitive files | `SourceDisclosure` | улучшено | `plugins/files/senstivefiles.txt` (20 рядків); перенесено лише ті, у яких тіло відповіді ідентифікує файл |
| Сумісність Spider: секрети в JS і HTML | `PII`, `Exposure` | улучшено | `plugins/spider.py:get_secrets` — 20 іменованих регулярних виразів. Ті, що є credentials, належать `Exposure` (який **перевіряє** їх відтворенням), решта — `PII` |
| Сумісність Spider: перелік джерел | `linksFrom` | совпадает | `plugins/spider.py:sources` |
| HTTP Request Smuggling | — | не перенесено | `plugins/sumggler.py` (606 рядків) будує сирі байти з конфліктом `Content-Length` і `Transfer-Encoding`. Наш транспорт — `net/http` через проксі-рекордер, і він **не може** виставити обидва заголовки framing: виразити smuggle можна лише сирим сокетом, а сирий сокет пішов би в обхід проксі-рекордера, тобто втратив би єдину властивість, заради якої сканер існує — атрибутивність трафіку. Це записано, а не промовчано |
| Subdomain takeover | — | не перенесено | `plugins/subtakeover.py` потребує `dns.resolver.query(host, 'CNAME')`. У пакеті немає DNS-резолвера, і додавати другий резолвер заради одного детектора — паралельний шлях; DNS-шари в проєкті належать OSINT |
| Anonymous FTP | — | не перенесено | `plugins/ftp.py` — інший протокол; `pkg/active` відкриває HTTP-з'єднання |
| S3 bucket misconfiguration / takeover / upload | — | не перенесено | `plugins/s3.py` — сторооннє сховище, не ціль сканування |
| Firebase misconfiguration | — | не перенесено | `plugins/firebase.py` — те саме стосовно чужого сервісу реального часу |
| Відсутній SPF-запис | — | не перенесено | `plugins/spf.py` надсилає POST на `spf.myisp.ch` — **сторонній** сервіс. Детектор, який відправляє ціль оператора сторонньому сайту, робить те, чого оператор не просив |
| Path Traversal | `LFI` | улучшено | `plugins/traversal.py`: шість форм, з подвійним URL-енкодуванням; наші `lfiTechniques` містять `....//` і PHP-обгортку |
| CVE-2012-1823 (PHP-CGI) | — | не перенесено | Один CVE — nuclei-шаблон, а не детектор сканера; корпус nuclei виконує його проти будь-якої цілі |
| CVE-2014-6271 (Shellshock) | — | не перенесено | Один CVE — це nuclei-шаблон, а не детектор сканера; корпус nuclei виконує його проти будь-якої цілі й уміє довести відповідь сервісу |
| CVE-2018-11776 (Struts) | — | не перенесено | Один CVE — nuclei-шаблон; окремий детектор у сканері продублював би один рядок корпусу й розійшовся б з ним при наступному оновленні |
| CVE-2019-2725 (WebLogic) | — | не перенесено | Один CVE — nuclei-шаблон; його виконання і доказ належать корпусу, який оновлюється разом із шаблоном, а не разом із кодом сканера |
| CVE-2019-3396 (Confluence LFI) | — | не перенесено | Один CVE — nuclei-шаблон; наш `LFI` уже доводить читання файлу доказом, а конкретний продукт визначає корпус |
| CVE-2019-5418 (Rails LFI) | — | не перенесено | Один CVE — nuclei-шаблон; доказ читання файлу дає `LFI`, а прив'язку до версії продукту дає корпус |
| CVE-2019-8451 (Atlassian SSRF) | — | не перенесено | Один CVE — nuclei-шаблон; наш `SSRF` уже має розрізнення reflection/fetch, версійний гейт дає корпус |
| CVE-2019-10098 (Apache mod_rewrite) | — | не перенесено | Один CVE — nuclei-шаблон; окремий детектор у сканері не додав би доказу понад те, що корпус уже надсилає цей шаблон |

---

## Наші власні здатності, додані цим портом

Правило вимагає рядок на кожну нашу здатність, а не лише на кожну theirs.

| наша здатність | символ | вердикт | підстава |
|---|---|---|---|
| Сліпий NoSQL-диференціал з операторними формами | `NoSQL`, `nosqlOperatorPayloads` | улучшено | Жоден із шести upstream не має операторних форм: Arachni має лише диференціал і помилки, BlackWidow — довжину відповіді |
| Свіжість на fingerprint з помилкою парсера | `FreshFold` у `xpathErrorProbe`, `ldapErrorProbe` | улучшено | Arachni шукає свої 24/29 рядків безперевіркою; наш кожен проходить через базовий контроль |
| Розрізнення «м'який 404» від реального файлу | `softNotFoundPath`, `endpointOrigin` | улучшено | Жоден з чотирьох інструментів зі списками шляхів (Arachni, Eagle, BlackWidow, flan) не порівнює відповідь із відповіддю на неіснуючий шлях, тому список із 499 шляхів дає на сучасному сайті 499 хибних спрацювань |
| Доказ запису через PUT із читанням назад | `methodsPutFinding` | улучшено | Arachni `http_put.rb` і Eagle повідомляють про `Allow`; ми пишемо файл і читаємо його |
| Аналіз стеку екранування з випадковими якорями | `Escaping` | улучшено | Поряд зі значенням upstream, але з випадковими якорями — інакше міряється те, чи містить сторінка рядок, а не те, що робить стек |
| Арифметика з простих для детектора коду | `codeInjectionFactorA`, `codeInjectionFactorB` | улучшено | `7*7=49` є на звичайних сторінках; `11*13=143` — ні, тому очікуване значення обчислюється з факторів, а не пишеться окремо |
| Реєстр звірки як механізм | `upstreams_reconciliation_test.go` | улучшено | Жоден із шести не має механізму, який заважає втратити здатність мовчки |

## Модулі цього порту: назва в звіті → тип у коді

Таблиця існує, щоб динамічна перевірка `TestEveryDetectorOfThisPortIsClassified`
була здатна знайти детектор за його **назвою**, а не за текстом міркування. Без
неї перевірка шукала б рядок, який називає `SourceDisclosure`, у стовпці «підстава»,
і детектор, перейменований без запису в реєстр, проходив би непомітно.

| детектор у звіті | тип у коді | вердикт | підстава |
|---|---|---|---|
| `nosql` | `NoSQL` | улучшено | Arachni `no_sql_injection_differential.rb` + операторні документи, яких в upstream немає |
| `xpath` | `XPath` | улучшено | Arachni `xpath_injection/errors.txt` (24 рядки) + boolean-раунд, якого в upstream немає |
| `ldap` | `LDAP` | улучшено | Arachni `ldap_injection/errors.txt` (29 рядків) + проби розширення фільтра |
| `xxe` | `XXE` | улучшено | Arachni `xxe.rb`, перенесений у форму параметра замість переписування документа |
| `codeinj` | `CodeInjection` | улучшено | Arachni `code_injection*.rb` (3 файли), зведені в один модуль |
| `crlf` | `CRLF` | улучшено | Eagle `plugins/crlf.py` + Arachni `response_splitting.rb` |
| `methods` | `Methods` | улучшено | Arachni `allowed_methods` / `http_put` / `webdav` / `xst` (4 файли), зведені в один модуль |
| `escaping` | `Escaping` | улучшено | backslash-powered-scanner `TransformationScan.java` — єдиний з шести, чия здатність є вимірюванням |
| `csrf` | `CSRF` | улучшено | Arachni `csrf.rb` |
| `sessionfixation` | `SessionFixation` | не перенесено | Arachni `session_fixation.rb`; причина — у розділі Arachni, тут лише відповідність назв |
| `srcdisc` | `SourceDisclosure` | улучшено | Arachni `common_files` / `common_directories` / `common_admin_interfaces` + Eagle `senstivefiles.txt` |
| `pii` | `PII` | улучшено | Arachni `grep/{emails,ssn,credit_card,private_ip}.rb` + BlackWidow збір email/телефонів |
| `cookies` | `Cookies` | улучшено | Arachni `grep/{insecure_cookies,http_only_cookies,cookie_set_for_parent_domain,unencrypted_password_forms}.rb` |
| `hidden_params` | `HiddenParams` | улучшено | Жоден із шести upstream не має словника прихованих параметрів з імен змінних: їхні краулери йдуть за посиланнями сторінки. Словник приходить з аналізатора JavaScript (`js.ParamCandidates`), детектор надсилає два різні значення й розрізняє «сервер читає присутність» та «значення дійшло до виводу». Рядки повторюють зміст VEXOR-реєстру, бо доказ той самий |
| `auth_bypass_ext` | `AuthBypassExt` | улучшено | Жоден із шести не має усікання розширення як окремої техніки: усі дивляться на `;` як на небезпечний символ у запиті, а не як на спосіб дістатися того самого файлу. П'ять форм на кожен серверний шлях, доказ — «baseline просив пароль, проба ні» |
| `vite_fs_read` | `ViteFSRead` | улучшено | Жоден із шести не читає файли через міст файлу Vite: Nikto має `/@fs/` у своєму словнику шляхів як звичайний шлях і не доводить жодного читання. Тут кожна ціль має підпис contents-рядка і `Fresh` проти baseline |
| `hidden_paths` | `HiddenPaths` | улучшено | Усі шість мають словники, але жоден не вимірює власну відповідь 404 і не порівнює за формою: їхні фільтри — за статусом і за довжиною, а довжиною керує сервер. Тут м'який 404, що малює шлях у тілі, не дає жодного рядка |

## Змінена контрактна поведінка

Це не таблиця здатностей, тому вона списком, а не таблицею: таблиця з трьома
колонками в цьому файлі — це помилка парсера, і помилку парсера не можна
виправити тим, що вона лежить у зручному місці.

- **`AllModules()` тепер містить 22 детектори** — `scan.go`, `modulesFor`.
  Кількість не є метою, а є наслідком; вона перевіряється тестом `scan_test.go`
  проти `len(AllModules())`, тому зміна числа без зміни списку падає.
- **`ScanRequest.InterestingPaths` лишається єдиним способом додати шлях.**
  Списки Arachni на 499 директорій і 50 admin-шляхів не додані в
  `DefaultInterestingPaths`: жоден із них не має відбитка тіла, тому додавання
  перетворило б мовний список на 499 запитів, які повертають або відповідь, або
  м'який 404, і другий випадок переважний на сучасному сайті.
---

## 7. Список здатностей оператора — п'ять джерел, які не є сканерами

Цей розділ існує тому, що п'ять позицій зі списку оператора **не є інструментами
сканування**, і перша їх обробка у відповіді була «це не наш предмет» без
перевірки. Перевірка показала, що для трьох із п'яти це була помилка: Electron
розбірливий у бандлі, а зіставлення версій із CVE уже є. Розділ записано, щоб
помилка не повторилась мовчки.

### Коміти upstream

| інструмент | репозиторій | коміт | дата коміту |
|---|---|---|---|
| Fuzzilli | `https://github.com/googleprojectzero/fuzzilli` | `281729bfc79f3bc9af398e4dce44933d6ea01dc4` | 2026-09-24 |
| eslinter | `https://github.com/parsiya/eslinter` | `f2b58eaee43cd724678e04c602f3844a67a69558` | 2021-03-06 |
| Vulners | `https://github.com/vulnersCom/burp-vulners-scanner` | `77dd024597da5fcf4ac07e6e6d50b76fda27aa62` | 2025-10-01 |
| awesome-electronjs-hacking | `https://github.com/doyensec/awesome-electronjs-hacking` | `d7a1f2e4c97c32896e5126510f09e3ae8a494564` | 2025-05-14 |
| MSSQLHound | `https://github.com/SpecterOps/MSSQLHound` | `92efaeb892cd3e43dbdd5b4308dbf55383db1453` | 2026-06-29 |

### Другий список оператора: три джерела, прочитані після першої сесії

Ці три з'явилися в розширеному списку оператора після того, як реєстр вище був
закритий, тому вони мають окремий перелік і окремі коміти.

| інструмент | репозиторій | коміт | дата коміту |
|---|---|---|---|
| SecretFinder | `https://github.com/m4ll0k/SecretFinder` | `d06119dedd9c1505137d1ec4792d5d5b65c7425d` | 2025-10-03 |
| GAP (GetAllParam) | `https://github.com/xnl-h4ck3r/GAP-Burp-Extension` | `f223016fa347776aff59dd610da8f1e2ffee3260` | 2025-10-01 |
| dirsearch | `https://github.com/maurosoria/dirsearch` | `13b3cc8baf0771e867e72b81cf29c58ae1232da9` | 2026-09-30 |

### Вердикти по здатностях другого списку

| здатність джерела | символ у нас | вердикт | підстава |
|---|---|---|---|
| SecretFinder: словник регулярних виразів для секретів | `secretRules` (16 → 21) | улучшено | Прочитано `SecretFinder.py` за комітом вище: у ньому ~25 патернів, у нас було 16. Додано 5 — `google_oauth_token`, `google_captcha_site_key`, `amazon_mws_auth_token`, `facebook_access_token`, `square_access_token`. Решта — або вже є (`twilio_api_key` приходить з Pinkerton), або надто шумні для списку, який сам себе обмежує |
| SecretFinder: `-r` свій регулярний вираз, `-e` витягування JS з сторінки | — | не перенесено | Своє регулярне вираз — це спосіб сказати «усі наші 21 патерн плюс твій», тобто користувачеві потрібен лише спосіб додати патерн. Його немає: правило живе в коді, а не в запиті. Це зміна контракту списку, а не здатність аналізу |
| GAP: параметри з JS, запитів і відповідей | `jsAnalysis.Params`, `collectJSCapabilities` | совпадает | Ті самі імена з тих самих місць виклику. Параметри з **запитів і відповідей** GAP бере з Burp, у нас їх бере обхід і Traffic — це інший шлях до тих самих даних |
| GAP: **ціль-специфічний словник** для фаззингу | `collectTargetSpecificWordlist`, `jsAnalysis.ProbeWords` | улучшено | GAP з'єднує параметр із посиланням, де його можна спробувати. У нас те саме, але шлях береться **sendable**-формою: аналізатор тримає `/api/v1/users/EXPR` як доказ, а словник отримує `/api/v1/users/1` — надіслати можна лише друге |
| GAP: обмеження і «що відкинуто» | `jsProbeWordsLimit`, `ProbeWordsTruncated` | улучшено | GAP обмежує обсяг мовчки. Обмеження тут видиме двома числами: скільки слів і скільки відкинуто. Підвищення межі — зміна константи, але тест пише число, а не читає константу, тому зміна межі падає в перевірці |
| dirsearch: `-e` маски, `-r` рекурсія, `--include-status` | `ScanRequest.PathWordlist`, `moduleOptions` | не перенесено | Маска розширень — це спосіб написати більший словник, а словник і так операторський, і рекурсія обходу вже є в Target. Фільтр за статусом замінено на **виміряне** порівняння з власним 404, яке не дає хибних спрацювань на м'якому 404 |


| здатність джерела | символ у нас | вердикт | підстава |
|---|---|---|---|
| Fuzzilli: генерація програм для движка JS і пошук падінь у ньому | — | не перенесено | Фазер V8/JavaScriptCore шукає баг у **рушії**, а не у чужому сайті. Предмет — процес движка, а не HTTP-поверхня; перенесення означало б розгорнути фазер движка всередині сканера |
| eslinter: пошук XSS у скриптах сторінніх сторінок під час перегляду | `jsFindingSink` | совпадает | Ми читаємо ті самі байти й називаємо ті самі sinks: `innerHTML`, `document.write`, `eval`. Різниця не в здатності, а в тому, що eslinter працює як розширення Burp, а ми — як уже наявний аналізатор у `target_javascript.go` |
| Vulners: зіставлення знайденої версії з CVE | `retirejsRepository` (веридкти по бібліотеках), корпус nuclei | улучшено | Здатність «знайдена версія → CVE» у нас двічі: `engine/retirejs.go` для бібліотек у бандлі та 98 636 шаблонів nuclei для вразливостей на цілі. Обидва джерела оновлюються зовні, як у upstream, а не вбудованою базою |
| awesome-electronjs-hacking: прапорці Electron, які перетворюють ін\'екцію в RCE | `jsFindingElectronExposure`, `jsElectronMarkers` | улучшено | Категорію `electron_exposure` прочитано з цього списку: 20 маркерів (`nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, `shell.openExternal`, `asar.unpack`, `readFileSync`, protocol-обробники). Половина список — статті, а половина — саме ці прапорці, тобто об\'єкт аналізу в ньому є |
| MSSQLHound: збір MSSQL-шляхів атаки в Active Directory | — | не перенесено | `SpecterOps/MSSQLHound` — Go-колектор, який додає до BloodHound шляхи атаки через MSSQL. Предмет — служба MSSQL у домені Windows, а не HTTP-поверхня: у сканері немає ні з'єднання з Active Directory, ні здатності читати домен. Перенесення потребувало б іншого транспорту й іншої моделі загрози |
