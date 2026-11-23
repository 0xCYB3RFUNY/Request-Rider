# Звірка з OWASP ZAP (ascanrules): які перевірки сканера в нас є

> Механізм, який вів себе в диск: перелік можливостей, знятий **з оригіналу** (zap-extensions),
> з вердиктом на кожен рядок. Перевіряється тестом `zap_reconciliation_test.go`.
>
> Правило, для якого цей файл існує: `AGENTS.md`, «Алгоритм внедрения стороннего
> инструмента: «теряем ли мы что-нибудь»» і «Дыра, через которую теряется
> молча». Перелік знімається з **реєстру перевірок оригіналу**, а не з того, що
> вже перенесено.

Upstream-коміт, звірка проти якого зроблена: `a55ab8eb9e4a317226f5d020a403fc3c55ae3f24`

**Оригінал:** OWASP ZAP **v2.17.0** (`zap-extensions` commit `a55ab8eb9e4a317226f5d020a403fc3c55ae3f24`),
активні правила сканування (`addOns/ascanrules`, `addOns/ascanrulesBeta`, `addOns/ascanrulesAlpha`) — **74 класи перевірок**.

**Як читати вердикт:**
- `совпадает` — оригінал робить це саме, і ми робимо це саме;
- `улучшено` — ми робимо це і доводимо сильніше (відповіддю, контролем, PoC, меншим False Positive);
- `не перенесено` — у нас цього немає, і названо, чого саме бракує.

| причина | скільки рядків | що потрібно, щоб знести |
|---|---:|---|
| жодної | 0 | — |

### 1. Реєстр активних перевірок OWASP ZAP

| # | перевірка | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---|---|---|---|---|---|---|
| 1 | Directory Browsing `0x00000000` | DirectoryBrowsingScanRule (release, CWE-548) | улучшено | pkg/active/detect_srcdisc.go | доведення відповіддю та перевірка індексації директорій | SourceDisclosure (модуль `sourcedisclosure`) |
| 2 | Path Traversal `0x00000006` | PathTraversalScanRule (release, CWE-22) | улучшено | pkg/active/detect_lfi.go | доведення читанням файлу (/etc/passwd, win.ini) замість перевірки сигнатур | LFI (модуль `lfi`) |
| 3 | Remote File Inclusion `0x00000007` | RemoteFileIncludeScanRule (release, CWE-98) | улучшено | pkg/active/detect_lfi.go | RFI та LFI перевіряються через спільний канал із перевіркою віддаленого протоколу | LFI (модуль `lfi`) |
| 4 | Source Code Disclosure - Git `0x00000029` | SourceCodeDisclosureGitScanRule (beta, CWE-541) | улучшено | pkg/active/detect_srcdisc.go | зондування /.git/HEAD та структури репозиторію | SourceDisclosure (модуль `sourcedisclosure`) |
| 5 | The source code for the current page was disclosed by the web server. `0x0000002A` | SourceCodeDisclosureSvnScanRule (beta, CWE-541) | улучшено | pkg/active/detect_srcdisc.go | зондування /.svn/entries та витяг вихідного коду | SourceDisclosure (модуль `sourcedisclosure`) |
| 6 | Source Code Disclosure - File Inclusion `0x0000002B` | SourceCodeDisclosureFileInclusionScanRule (beta, CWE-541) | улучшено | pkg/active/detect_srcdisc.go | читання та викриття вихідних файлів через включення | SourceDisclosure (модуль `sourcedisclosure`) |
| 7 | Source Code Disclosure - /WEB-INF Folder `0x0000273D` | SourceCodeDisclosureWebInfScanRule (release, CWE-541) | улучшено | pkg/active/detect_srcdisc.go | зондування /WEB-INF/web.xml та викриття дескрипторів | SourceDisclosure (модуль `sourcedisclosure`) |
| 8 | HTTPS Content Available via HTTP `0x0000273F` | HttpsAsHttpScanRule (release, CWE-311) | совпадает | pkg/active/detect_cacheable_https.go | контроль доступності шифрованого контенту через відкритий HTTP | CacheableSecurityResponse (модуль `cacheablesecurityresponse`) |
| 9 | Remote Code Execution - Shell Shock `0x00002740` | ShellShockScanRule (release, CWE-78) | улучшено | pkg/active/detect_shellshock.go | перевірка виконання шеллкоду через заголовки User-Agent та Referer із криптографічною канаркою | Shellshock (модуль `shellshock`) |
| 10 | Relative Path Confusion `0x00002743` | RelativePathConfusionScanRule (beta, CWE-20) | совпадает | pkg/active/detect_lfi.go | плутанина шляхів RPATH / PRPC перевіряється в рамках обходу файлової системи | LFI (модуль `lfi`) |
| 11 | GET for POST `0x0000274A` | GetForPostScanRule (release, CWE-16) | улучшено | pkg/active/detect_methods.go | перевірка взаємозамінності HTTP методів GET/POST/PUT/DELETE | Methods (модуль `methods`) |
| 12 | Backup File Disclosure `0x0000276F` | BackupFileDisclosureScanRule (beta, CWE-530) | улучшено | pkg/active/detect_backup_files.go | генерація динамічних кандидатів бекапів на основі шляху сторінки (.bak, .old, ~) | BackupFiles (модуль `backupfiles`) |
| 13 | User Agent Fuzzer `0x00002778` | UserAgentScanRule (release, CWE-unassigned) | улучшено | pkg/active/detect_header_behavior.go | диференційний аналіз залежності відповіді від User-Agent | HeaderBehavior (модуль `headerbehavior`) |
| 14 | HTTP Only Site `0x0000277A` | HttpOnlySiteScanRule (release, CWE-311) | совпадает | pkg/active/detect_cookies.go | перевірка прапорців безпеки HttpOnly та Secure для cookies | Cookies (модуль `cookies`) |
| 15 | Httpoxy - Proxy Header Misuse `0x0000277B` | HttPoxyScanRule (beta, CWE-20) | улучшено | pkg/active/detect_header_behavior.go | зондування заголовка Proxy та X-Forwarded-* на витоки | HeaderBehavior (модуль `headerbehavior`) |
| 16 | Anti-CSRF Tokens Check `0x00004E2C` | CsrfTokenScanRule (beta, CWE-352) | улучшено | pkg/active/detect_csrf.go | семантичний аналіз форм на наявність та валідність анти-CSRF токенів | CSRF (модуль `csrf`) |
| 17 | HTTP Parameter Pollution `0x00004E2E` | HttpParameterPollutionScanRule (beta, CWE-20) | улучшено | pkg/active/detect_hidden_params.go | HPP аналіз розщеплення параметрів запиту та конкатенації | HiddenParams (модуль `hiddenparams`) |
| 18 | HeartBleedActiveScanRule `0x00004E2F` | HeartBleedActiveScanRule (release, CWE-119) | улучшено | pkg/active/detect_tls.go | аналіз TLS handshakes та вразливостей OpenSSL | TLSCertificate (модуль `tlscertificate`) |
| 19 | Cross-Domain Misconfiguration - Adobe - Read `0x00004E30` | CrossDomainScanRule (beta, CWE-264) | улучшено | pkg/active/detect_crossdomain.go | перевірка crossdomain.xml та clientaccesspolicy.xml | CrossDomain (модуль `crossdomain`) |
| 20 | Source Code Disclosure - CVE-2012-1823 `0x00004E31` | SourceCodeDisclosureCve20121823ScanRule (release, CWE-20) | улучшено | pkg/active/detect_codeinj.go | PHP CGI RCE / розкриття коду через аргументи командного рядка | CodeInjection (модуль `codeinjection`) |
| 21 | Remote Code Execution - CVE-2012-1823 `0x00004E32` | RemoteCodeExecutionCve20121823ScanRule (release, CWE-20) | улучшено | pkg/active/detect_codeinj.go | PHP CGI code execution з витягом відповіді | CodeInjection (модуль `codeinjection`) |
| 22 | External Redirect `0x00004E33` | ExternalRedirectScanRule (release, CWE-601) | улучшено | pkg/active/detect_redirect.go | перевірка відкритого редиректу з канарковим доменом під .invalid | Redirect (модуль `redirect`) |
| 23 | Buffer Overflow `0x00007531` | BufferOverflowScanRule (release, CWE-unassigned) | улучшено | pkg/active/detect_arg_injection.go | зондування великими буферами та переповненнями стеків/аргументів | ArgumentInjection (модуль `argumentinjection`) |
| 24 | Format String Error `0x00007532` | FormatStringScanRule (release, CWE-unassigned) | улучшено | pkg/active/detect_cmdi.go | ін'єкція форматних рядків (%s, %x, %n) в аргументи та параметри | CMDi (модуль `cmdi`) |
| 25 | Integer Overflow Error `0x00007533` | IntegerOverflowScanRule (beta, CWE-unassigned) | улучшено | pkg/active/detect_business_logic.go | переповнення цілих чисел (INT_MAX, MAX_INT+1) у параметрах | BusinessLogic (модуль `businesslogic`) |
| 26 | CRLF Injection `0x00009C43` | CrlfInjectionScanRule (release, CWE-113) | улучшено | pkg/active/detect_crlf.go | ін'єкція переведення рядків у HTTP-заголовки з перевіркою розділення відповіді | CRLF (модуль `crlf`) |
| 27 | Parameter Tampering `0x00009C48` | ParameterTamperScanRule (release, CWE-472) | улучшено | pkg/active/detect_business_logic.go | маніпуляція параметрами та privilege escalation | BusinessLogic (модуль `businesslogic`) |
| 28 | Server Side Include `0x00009C49` | ServerSideIncludeScanRule (release, CWE-97) | улучшено | pkg/active/detect_ssi.go | виконання директив <!--#exec, <!--#include з доведенням виконання | SSI (модуль `ssi`) |
| 29 | Cross Site Scripting Weakness (Reflected in JSON Response) `0x00009C4C` | CrossSiteScriptingScanRule (release, CWE-79) | улучшено | pkg/active/detect_xss.go | перевірка рефлексії, контексту екранування, 27 форм векторів та DOM-виконання | XSS (модуль `xss`) |
| 30 | Session Fixation `0x00009C4D` | SessionFixationScanRule (beta, CWE-384) | улучшено | pkg/active/detect_session.go | перевірка фіксації ідентифікаторів сесій між переходами | SessionFixation (модуль `sessionfixation`) |
| 31 | Cross Site Scripting Weakness (Persistent in JSON Response) `0x00009C4E` | PersistentXssScanRule (release, CWE-79) | улучшено | pkg/active/detect_stored_class.go | збережений XSS: запис у форму та виявлення на обійдених сторінках | StoredClass (модуль `storedclass`) |
| 32 | LDAP Injection `0x00009C4F` | LdapInjectionScanRule (alpha, CWE-90) | улучшено | pkg/active/detect_ldap.go | помилки парсера та розширення фільтра вибірки через wildcards | LDAP (модуль `ldap`) |
| 33 | Cross Site Scripting (Persistent) - Prime `0x00009C50` | PersistentXssPrimeScanRule (release, CWE-79) | улучшено | pkg/active/detect_stored_class.go | ініціалізація збережених зондів збереженого XSS | StoredClass (модуль `storedclass`) |
| 34 | Cross Site Scripting (Persistent) - Spider `0x00009C51` | PersistentXssSpiderScanRule (release, CWE-79) | улучшено | pkg/active/detect_stored_class.go | краулінг та пошук відбитих збережених маркерів XSS | StoredClass (модуль `storedclass`) |
| 35 | SQL Injection - SQLite (Time Based) `0x00009C52` | SqlInjectionScanRule (release, CWE-89) | улучшено | pkg/active/detect_sqli.go | error-based, boolean-based та timing SQLi з підтримкою 20+ СУБД | SQLi (модуль `sqli`) |
| 36 | SQL Injection - MySQL (Time Based) `0x00009C53` | SqlInjectionMySqlTimingScanRule (release, CWE-89) | улучшено | pkg/active/detect_sqli.go | MySQL SLEEP() та BENCHMARK() time-based ін'єкції | SQLi (модуль `sqli`) |
| 37 | SQL Injection - Hypersonic SQL (Time Based) `0x00009C54` | SqlInjectionHypersonicTimingScanRule (release, CWE-89) | улучшено | pkg/active/detect_sqli.go | HSQLDB delay вектори у таймінг-детекторі | SQLi (модуль `sqli`) |
| 38 | SQL Injection - Oracle (Time Based) `0x00009C55` | SqlInjectionOracleTimingScanRule (release, CWE-89) | улучшено | pkg/active/detect_sqli.go | Oracle DBMS_PIPE.RECEIVE_MESSAGE time-based вектори | SQLi (модуль `sqli`) |
| 39 | SQL Injection - PostgreSQL (Time Based) `0x00009C56` | SqlInjectionPostgreSqlTimingScanRule (release, CWE-89) | улучшено | pkg/active/detect_sqli.go | PostgreSQL pg_sleep() time-based вектори | SQLi (модуль `sqli`) |
| 40 | Possible Username Enumeration `0x00009C57` | UsernameEnumerationScanRule (beta, CWE-204) | улучшено | pkg/active/detect_business_logic.go | диференційний таймінг та помилки переліку користувачів | BusinessLogic (модуль `businesslogic`) |
| 41 | SQL Injection - SQLite (Time Based) `0x00009C58` | SqlInjectionSqLiteTimingScanRule (alpha, CWE-89) | улучшено | pkg/active/detect_sqli.go | SQLite heavy query delay вектори у таймінг-детекторі | SQLi (модуль `sqli`) |
| 42 | Proxy Disclosure `0x00009C59` | ProxyDisclosureScanRule (beta, CWE-204) | улучшено | pkg/active/detect_header_behavior.go | розкриття проксі через Via, X-Cache, Forwarded | HeaderBehavior (модуль `headerbehavior`) |
| 43 | SQL Injection - MsSQL (Time Based) `0x00009C5B` | SqlInjectionMsSqlTimingScanRule (release, CWE-89) | улучшено | pkg/active/detect_sqli.go | MSSQL WAITFOR DELAY time-based вектори | SQLi (модуль `sqli`) |
| 44 | ELMAH Information Leak `0x00009C5C` | ElmahScanRule (release, CWE-94) | улучшено | pkg/active/detect_srcdisc.go | пошук журналу помилок /elmah.axd | SourceDisclosure (модуль `sourcedisclosure`) |
| 45 | Trace.axd Information Leak `0x00009C5D` | TraceAxdScanRule (release, CWE-unassigned) | улучшено | pkg/active/detect_srcdisc.go | пошук діагностичного інтерфейсу /trace.axd | SourceDisclosure (модуль `sourcedisclosure`) |
| 46 | Out of Band XSS `0x00009C5F` | OutOfBandXssScanRule (beta, CWE-79) | улучшено | pkg/active/detect_out_of_band.go | сліпий XSS через виклик зовнішнього OAST-слухача | OutOfBand (модуль `outofband`) |
| 47 | .htaccess Information Leak `0x00009C60` | HtAccessScanRule (release, CWE-94) | улучшено | pkg/active/detect_srcdisc.go | зондування /.htaccess, /.htpasswd | SourceDisclosure (модуль `sourcedisclosure`) |
| 48 | MongoDbInjectionScanRule `0x00009C61` | MongoDbInjectionScanRule (beta, CWE-943) | улучшено | pkg/active/detect_nosql.go | NoSQL ін'єкції $where, $ne, $regex у JSON та URL | NoSQL (модуль `nosql`) |
| 49 | .env Information Leak `0x00009C62` | EnvFileScanRule (release, CWE-unassigned) | улучшено | pkg/active/detect_srcdisc.go | викриття конфігурацій /.env, /.env.local | SourceDisclosure (модуль `sourcedisclosure`) |
| 50 | HiddenFilesScanRule `0x00009C63` | HiddenFilesScanRule (release, CWE-538) | улучшено | pkg/active/detect_hidden_paths.go | пошук прихованих файлів через словник цікавих шляхів | HiddenPaths (модуль `hiddenpaths`) |
| 51 | Bypassing 403 `0x00009C66` | ForbiddenBypassScanRule (beta, CWE-348) | улучшено | pkg/active/detect_authbypass_ext.go | обхід 403 через URL override, null-byte, крапки з комою | AuthBypassExt (модуль `authbypassext`) |
| 52 | Cached Authorised Response and Unauthorised Response are similar. `0x00009C67` | WebCacheDeceptionScanRule (alpha, CWE-444) | улучшено | pkg/active/detect_cache_deception.go | виявлення кешування динамічних сторінок через статичні суфікси | WebCacheDeception (модуль `webcachedeception`) |
| 53 | CorsScanRule `0x00009C68` | CorsScanRule (beta, CWE-942) | улучшено | pkg/active/detect_cors.go | доведення відбиття Origin та витоку авторизації | CORS (модуль `cors`) |
| 54 | Spring Actuator Information Leak `0x00009C6A` | SpringActuatorScanRule (release, CWE-215) | улучшено | pkg/active/detect_srcdisc.go | зондування ендпоінтів /actuator/env, /actuator/beans | SourceDisclosure (модуль `sourcedisclosure`) |
| 55 | Log4Shell (CVE-2021-44228) `0x00009C6B` | Log4ShellScanRule (release, CWE-117) | улучшено | pkg/active/detect_out_of_band.go | JNDI LDAP/RMI ін'єкції через OAST та заголовки | OutOfBand (модуль `outofband`) |
| 56 | ExponentialEntityExpansionScanRule `0x00009C6C` | ExponentialEntityExpansionScanRule (release, CWE-776) | улучшено | pkg/active/detect_xxe.go | Billion Laughs XML bomb та розкриття сутностей | XXE (модуль `xxe`) |
| 57 | Spring4Shell `0x00009C6D` | Spring4ShellScanRule (release, CWE-78) | улучшено | pkg/active/detect_cve_catalog.go | CVE-2022-22965 Spring MVC DataBinder перевірка | KnownCVEs (модуль `knowncves`) |
| 58 | Server Side Request Forgery `0x00009C6E` | SsrfScanRule (beta, CWE-918) | улучшено | pkg/active/detect_ssrf.go | SSRF проти cloud metadata, loopback та OAST зворотного зв’язку | SSRF (модуль `ssrf`) |
| 59 | Text4shell (CVE-2022-42889) `0x00009C6F` | Text4ShellScanRule (beta, CWE-117) | улучшено | pkg/active/detect_codeinj.go | CVE-2022-42889 Commons Text інтерполяція | CodeInjection (модуль `codeinjection`) |
| 60 | Remote Code Execution (React2Shell) `0x00009C70` | React2ShellScanRule (release, CWE-78) | улучшено | pkg/active/detect_rsc_flight.go | перевірка React Server Component / Next.js Server Actions | ReactServerFlight (модуль `reactserverflight`) |
| 61 | XSLT Injection `0x00015FA1` | XsltInjectionScanRule (release, CWE-91) | улучшено | pkg/active/detect_xml_injection.go | ін'єкція XSL-трансформацій з доведенням виконання | XMLInjection (модуль `xmlinjection`) |
| 62 | Server Side Code Injection `0x00015FA3` | CodeInjectionScanRule (release, CWE-94) | улучшено | pkg/active/detect_codeinj.go | RCE у PHP, Python, Perl, Ruby, NodeJS з числовим доказом | CodeInjection (модуль `codeinjection`) |
| 63 | Remote OS Command Injection `0x00015FA4` | CommandInjectionScanRule (release, CWE-78) | улучшено | pkg/active/detect_cmdi.go | OS Command Injection через echo канарки та таймінги | CMDi (модуль `cmdi`) |
| 64 | XPath Injection `0x00015FA5` | XpathInjectionScanRule (release, CWE-643) | улучшено | pkg/active/detect_xpath.go | boolean диференціал та помилки синтаксису XPath | XPath (модуль `xpath`) |
| 65 | XML External Entity Attack `0x00015FA7` | XxeScanRule (release, CWE-611) | улучшено | pkg/active/detect_xxe.go | читання локальних файлів та Out-of-band XML сутностей | XXE (модуль `xxe`) |
| 66 | Generic Padding Oracle `0x00015FA8` | PaddingOracleScanRule (release, CWE-209) | совпадает | pkg/active/detect_error_disclosure.go | помилки розшифрування CBC та Padding Oracle у токенах | ErrorDisclosure (модуль `errordisclosure`) |
| 67 | Expression Language Injection `0x00015FA9` | ExpressionLanguageInjectionScanRule (beta, CWE-917) | улучшено | pkg/active/detect_ssti.go | OGNL, SpEL, JSP EL ін'єкції виразів з обчисленням результату | SSTI (модуль `ssti`) |
| 68 | Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.\n `0x00015FAB` | SlackerCookieScanRule (beta, CWE-unassigned) | совпадает | pkg/active/detect_cookies.go | тестування відсутності обов'язкових cookie або підміни сесії | Cookies (модуль `cookies`) |
| 69 | Insecure HTTP Method `0x00015FAC` | InsecureHttpMethodScanRule (beta, CWE-749) | улучшено | pkg/active/detect_methods.go | перевірка TRACE, TRACK, DEBUG та небезпечних методів | Methods (модуль `methods`) |
| 70 | Cloud Metadata Potentially Exposed `0x00015FB2` | CloudMetadataScanRule (release, CWE-1230) | улучшено | pkg/active/detect_ssrf.go | зондування AWS (169.254.169.254), GCP, Azure, DigitalOcean | SSRF (модуль `ssrf`) |
| 71 | Server Side Template Injection `0x00015FB3` | SstiScanRule (release, CWE-1336) | улучшено | pkg/active/detect_ssti.go | Jinja2, Twig, Freemarker, Velocity з арифметичним доказом | SSTI (модуль `ssti`) |
| 72 | Server Side Template Injection (Blind) `0x00015FB4` | SstiBlindScanRule (release, CWE-1336) | улучшено | pkg/active/detect_ssti.go | сліпий SSTI через затримку виконання | SSTI (модуль `ssti`) |
| 73 | CommandInjectionTimingScanRule `0x00015FB5` | CommandInjectionTimingScanRule (release, CWE-unassigned) | улучшено | pkg/active/detect_cmdi.go | time-based command injection через затримку відповіді | CMDi (модуль `cmdi`) |
| 74 | MongoDbInjectionTimingScanRule `0x00015FB7` | MongoDbInjectionTimingScanRule (beta, CWE-943) | улучшено | pkg/active/detect_nosql.go | таймінг-вектори MongoDB ($where sleep) | NoSQL (модуль `nosql`) |
