# gosearch — реєстр звірки

Реєстр порту `ibnaleem/gosearch` у OSINT-рушій RequestRider.

**Upstream-коміт, звірка проти якого зроблена: `687f9ed`**
(`ibnaleem/gosearch`, v2.0.2).

Ліцензія оригіналу — **GPL-3.0**. Тому **жодного рядка його коду не скопійовано**:
перенесено контракти HTTP і семантику відповідей, а реалізація написана заново в
стилі `engine/osint_transforms.go`. Крім того, оригінал **фізично не імпортується**:
увесь код лежить у `internal/`, тож зовнішній модуль не дістане жодного пакета.

## Як звірялося

Один клон, один коміт, один список здібностей. Перелік знято **з файлів
оригіналу** (`ls internal/modules/`, `grep '^func [A-Z]' internal/ main.go`), а не
з власної пам'яті — інакше здатність, яку ще ніхто не переносив, просто
відсутня без рядка.

Порядок рядків — **за файлами оригіналу**, алфавітно, як вимагає алгоритм.

Одиниця звірки — **одна експортована функція оригіналу**. У оригіналі їх 24
(без `theme` — це вивід, а не здатність). Кожна має рядок нижче.

Що **неможливо** перенести принципово, і це не втрата, а різниця середовища:

| що | чому не переноситься |
|---|---|
| `theme.*` (19 функцій кольору) | вивід у термінал; у нас JSON → Django → UI |
| `tablewriter`, `screen.Clear()` | таблиці в stdout і `\033[2J`; у нас граф |
| `utils.WriteToFile`, `WriteEmailToFile` | запис у файл з `os.ModePerm` (0777); у нас PostgreSQL |
| `flag.*` на глобальному `CommandLine` | CLI прапорці; у нас HTTP-контракт |
| `os.Exit`, `log.Fatal` | убивають процес хоста |

## Здатності, які перенесено цього разу

Одна ітерація — три джерела, з яких `breach_exposure` складається. Вони
обрані разом, бо це один ланцюг: ProxyNova і BreachDirectory дають хеші, а
weakpass їх розбиває. Розбиття ланцюга означало б або втрату пароля, або
transform, який читає себе неповно.

### 1. ProxyNova — компрометовані паролі за email/username

Оригінал: `internal/modules/proxynova/proxynova.go:24`.

Контракт: `GET https://api.proxynova.com/comb?query=<value>` →
`{"count":N,"lines":["email:password", …]}`.

**Знайдені дефекти оригіналу, зафіксовані в тестах:**

| дефект | де | наслідок |
|---|---|---|
| `strings.Split(line, ":")` і `len(parts) == 2` | `proxynova.go:57` | пароль, що містить `:`, **втрачався** — `Split` дає 3 частини |
| `count` не звірено з `len(lines)` | `proxynova.go:55` | розбіжність невидима |
| `&http.Client{}` без таймауту | `proxynova.go:29` | завислий upstream = завислий процес |

У нас: `SplitN` по першому `:`, тому `p:a:ss:word` читається як пароль
(`TestBreachExposureReadsAllThreeAnswers`); `count` і довжина `lines` звіряються, і
кожен рядок парситься, а розбіжність потрапляє в попередження
(`TestBreachExposureReportsEveryLineWhenTheCountDisagrees`); таймаут на запит.

### 2. BreachDirectory — пошук компрометацій за email/username

Оригінал: `internal/modules/breachdirectory/breachdirectory.go:14` +
`github.com/ibnaleem/gobreach` (`gobreach.go:26-84`).

Контракт: `GET https://breachdirectory.p.rapidapi.com/?func=auto&term=<value>` з
заголовками `x-rapidapi-key` і `x-rapidapi-host` → `{"found":N,"result":[{email,
password, sha1, sources}]}`.

**Знайдені дефекти оригіналу:**

| дефект | де | наслідок |
|---|---|---|
| `log.Fatal` усередині горутини | `breachdirectory.go:23,28` | помилка третьої сторони **вбиває процес хоста** |
| `NewBreachDirectoryClient` повертає `error`, коли ключ порожній → `log.Fatal` | `breachdirectory.go:22` | без ключа оригінал не працює взагалі, навіть ProxyNova |
| `entry.Password` не виводиться, якщо weakpass дав пароль | `breachdirectory.go:45-51` | **втрачається** пароль, який уже був у відповіді |
| `CrackHash(entry.Hash)` — по `Hash`, а не по `Sha1` | `breachdirectory.go:44` | запит не за тим полем, яке відповідь реально містить |
| один виклик weakpass на кожен запис | `breachdirectory.go:44` | одна_credentials у 40 джерелах = 40 однакових запитів |
| `entry.Email` не виводиться | — | оригінал мав поле і не показував його |

У нас: помилка → попередження, процес живий (`TestBreachExposureRefusesWithoutTheDirectoryKey`
окремо доводить, що без ключа **вимкнена лише ця** сторінка, а ProxyNova працює);
**обидва** паролі збережено — і власний `password` запису, і розбитий weakpass, з
полем `password_from_weakpass`, що розрізняє їх
(`TestBreachExposureKeepsBothPasswords`, `TestBreachExposureFillsAnEmptyPasswordFromTheCrack`);
weakpass запитано **раз на унікальний хеш**
(`TestBreachExposureAsksWeakpassOncePerDistinctHash`: 12 записів, 1 запит).

### 3. weakpass — розбиття SHA-1

Оригінал: `internal/modules/weakpass/weakpass.go:18`.

Контракт: `GET https://weakpass.com/api/v1/search/<sha1>.json` →
`{"type","hash","pass"}`.

У оригіналі це **не самостійний пошук**, а ланцюг: його викликає лише
BreachDirectory. Той самий ланцюг тут — і він збережений, бо розбиття ланцюга
означало б «повертаємо хеш там, де оригінал повертав пароль».

## Рядки реєстру

| # | здатність оригіналу | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---:|---|---|---|---|---|---|
| 1 | Пошук юзернейма по 306 платформах, `errorType: status_code` | `internal/search/search.go:192` | `улучшено` | `username_search` | наш каталог — злиті Sherlock+Maigret (5897 платформ) проти 306 у `data.json`; критерій той самий `status_code`, але ми не рахуємо `403` за знахідку | `identitySite` |
| 2 | Те саме, `errorType: errorMsg` | `internal/search/search.go:219` | `улучшено` | `username_search` | маркер у тілі відповіді; у нас це модель `message`, застосована до каталогу, а не до 306 рядків | `identitySite` |
| 3 | Те саме, `errorType: profilePresence` | `internal/search/search.go:258` | `улучшено` | `username_search` | наявність профілю в розмітці; злита з двома попередніми моделями в одну перевірку з доказом | `identitySite` |
| 4 | Те саме, `errorType: response_url` | `internal/search/search.go:164` | `улучшено` | `username_search` | переадресація на login читається як відсутність профілю; у нас це окрема модель, бо це найбільше джерело хибних спрацювань | `identitySite` |
| 5 | Те саме, невідомий `errorType` → жовта «не перевірено» | `internal/search/search.go:337` | `улучшено` | `username_search` | оригінал на 24 платформах із 306 віддавав «не зміг перевірити» і рахував їх у звіт; у нас невідома модель перевірки не потрапляє в каталог узагалі | `identityCatalogue` |
| 6 | Каталог платформ `data.json` (306 записів, з `errorMsg`/`errorCode`/`response_url`/`cookies`) | `data.json`, `internal/models/models.go:5` | `супадає` | `identityCatalogue` | здатність «список платформ для пошуку імені» покрита: `identityCatalogue` несе злиті каталоги Sherlock+Maigret на 5897 плаформ, які містять усі чотири моделі виявлення з `data.json` і на 5591 платформ більше. Сам **файл** не перенесено: `utils.UnmarshalJSON` (`utils.go:97`) щоразу видаляє локальний `data.json` і робить обов'язковий запит на `raw.githubusercontent.com` | `identityCatalogue` |
| 7 | `SearchDomains` — 26 TLD через `http://<user><tld>` | `internal/search/search.go:30`, `utils.BuildDomains` | `улучшено` | `identity_graph` → `identityGraphDomainPass` | список з 26 TLD збігається з оригіналом **байт у байт** (тест читає `utils.go`), але пас **не рахує** нічого, що лише відповіло: оригінал зараховував будь-який не-error статус, тобто `404` і `403` теж, і паркований сайт рахувався «знайденим». Тут рахується лише те, що відповіло і не сказало «тут нічого», а статус пишеться на вузол — обидві відповіді лишаються. Пас **вимкнений за замовчуванням** і це видно в `check_domains` | `identityGraphDomainPass` |
| 8 | Профіль GitHub (`/users/<u>`) | `internal/modules/github/github.go:41` | `улучшено` | `github_recon` | наш профіль читає ті самі поля плюс `html_url` і `account_type`; `GITHUB_TOKEN` з env у нас, і ми **не** друкуємо сам токен у жодному рядку результату | `transformGitHubRecon` |
| 9 | Email з публічних комітів | `internal/modules/github/email-from-commits.go:25` | `улучшено` | `github_recon` | оригінал звіряв лише `PushEvent` і брав адресу з `commits/<sha>`. У нас два проходи — публічний стрім подій **і** скан комітів власних репозиторіїв — і кожна адреса фільтрується тим самим правилом, що відсікає `noreply` GitHub. Причина `улучшено`: стрім подій покриває лише ~90 днів, тож сам по собі він не знайшов би адресу, яку акаунт комітить давно | `githubScanCommits` |
| 10 | GPG-ключі акаунта (`/users/<u>/gpg_keys`) | `internal/modules/github/gpg-keys.go:28` | `улучшено` | `github_recon` → `githubReconPassGPGKeys` | ключ стає вузлом за `key_id`, а кожна адреса на ключі — вузлом `email` з `verified` на ребрі. Оригінал друкував адреси у файл (`gpg-keys.go:104`) і **ніколи не з'єднував** їх із ключем | `githubReconPassGPGKeys` |
| 11 | SSH-ключі акаунта (`/users/<u>/keys`) | `internal/modules/github/ssh-keys.go:20` | `улучшено` | `github_recon` → `githubReconPassSSHKeys` | оригінал друкував лише тип і цифровий `id` (`ssh-keys.go:69`) — жоден із них не ідентифікує ключ поза GitHub, і два ключі одного типу ставали невідрізнюваними. У нас identity = SHA-256 від опублікованої лінії | `githubReconPassSSHKeys` |
| 12 | Соціальні акаунти (`/users/<u>/social_accounts`) | `internal/modules/github/social-accounts.go:19` | `улучшено` | `github_recon` → `githubReconPassSocialAccounts` | це **не** дубль `username_search`: там каталог питає кожну платформу, тут GitHub сам каже, які акаунти належать людині. На вузлі й на ребрі `verified_by: github` | `githubReconPassSocialAccounts` |
| 13 | Mutual followers (`/users/<u>/followers` + `/following/<login>`) | `internal/modules/github/mutual-followers.go:18,53` | `улучшено` | `github_recon` → `githubReconPassMutualFollowers` | та сама семантика (лише `204` — це «взаємний»), але обидві межі видимі: `max_followers` і `max_follower_checks`, і **обидві** публікуються в metadata. Оригінал при 100 фоловерах робив 101 запит, а без ключа GitHub дає 60/год — пас не завершувався взагалі | `githubReconPassMutualFollowers` |
| 14 | Gravatar — профіль, email-хеш, пов'язані акаунти | `internal/modules/gravatar/gravatar.go:37` | `улучшено` | `identity_graph` → `identityGraphGravatar` | JSON-ендпоінт замість HTML. Різниця не в силі, а в **питанні**: HTML відповідає «сторінка існує», а обидва сервіси дають `200` і для порожнього профілю. JSON відповідає «що сервіс тримає» — публіковані адреси й пов'язані акаунти | `identityGraphGravatar` |
| 15 | Keybase — lookup + профіль + криптоадреси + пристрої | `internal/modules/keybase/keybase.go:87` | `улучшено` | `identity_graph` → `identityGraphKeybase` | дві зміни проти оригіналу: ненульовий `status.code` **не** перетворюється на «профілю немає» (оригінал повертав нульову структуру, а його ж код друкував «No Keybase profile found» — відмова сервісу і відсутність людини стали одним реченням); пристрої й криптоадреси їдуть на профіль, бо для них немає виду вузла | `identityGraphKeybase` |
| 16 | HudsonRock — злитий лог інфостілера | `internal/modules/hudsonrock/hudsonrock.go:70` | `улучшено` | `identity_graph` → `identityGraphStealerLog` | **не злито** з тим HudsonRock, що вже читає `subdomains`: там `urls-by-domain` дає імена заражених машин, модуль оригіналу — `search-by-username`/`stealersbyemail` і дає людину. Найважливіше: оригінал вирішує «нічого не знайдено» порівнянням 140-символьної прози (`hudsonrock.go:99`) — переформулювання речення перетворює «немає компрометації» на «компрометація», єдиний напрямок помилки, що звинувачує невинну людину. У нас вирішує **відсутність `stealers`** | `identityGraphStealerLog` |
| 17 | BreachDirectory — компрометації за email/username | `internal/modules/breachdirectory/breachdirectory.go:14` | `улучшено` | `breach_exposure` | 3 дефекти оригіналу виправлені й зафіксовані тестами: `log.Fatal` у горутині, втрата `entry.Password` за наявності розбитого, і 40 дубльованих запитів до weakpass | `transformBreachExposure` |
| 18 | ProxyNova — `email:password` за компрометацією | `internal/modules/proxynova/proxynova.go:24` | `улучшено` | `breach_exposure` | `Split` → `SplitN`, тому пароль із `:` більше не втрачається | `breachExposureParseProxyNova` |
| 19 | weakpass — SHA-1 → пароль | `internal/modules/weakpass/weakpass.go:18` | `улучшено` | `breach_exposure` | ланцюг збережено; запити дедупліковано за унікальним хешем, межа запитів видима в попередженні | `breachExposureCrackHashes` |
| 20 | Запис результатів у файл (`WriteToFile`) | `internal/utils/utils.go:25` | `улучшено` | `identity_graph` → `identityGraphDumpFile` | три відмінності, усі виміряні: оригінал писав файл на **кожному** прогоні (тобто creds лягали на диск, хто б не просив), і робив це з `os.ModePerm` — **0777, читається будь-ким акаунтом на машині**. Тут файл пишеться лише за `dump_file: true`, режим `0640`; назва та розширення оригіналу збережені | `identityGraphDumpFile` |
| 21 | Окремий файл адрес (`WriteEmailToFile`) | `internal/utils/utils.go:52` | `улучшено` | `identity_graph` → `identityGraphDumpFile` | окремий файл, але **та сама гонка** оригіналу ліквідована: `WriteToFile` має `mu.Lock()` (`:27`), а `WriteEmailToFile` — **ні** (`:56`), і обидва викликалися з паралельних горутин. Тут звіт збирається в пам'яті й пишеться один раз; адреси — окремою секцією того ж файлу | `identityGraphDumpFile` |
| 22 | Прапорці `-u`, `-b`, `-o`, `--no-false-positives` | `main.go:38-48` | `супадає` | контракт `osintTransformInput` | роля перейшла на контракт запиту: `-u` → `value`, `-b` → `confirm_network` + `BREACHDIRECTORY_API_KEY`, `--no-false-positives` → модель виявлення в каталозі, `-o` → `dump_path`. Прапорців у HTTP-контракті бути не може, але кожен їхній **зміст** є | `osintTransformInput` |
| 23 | `UnmarshalJSON` — завантаження `data.json` з GitHub | `internal/utils/utils.go:97` | `супадає` | `identityCatalogue` | оригінал **видаляв** локальний `data.json` і робив обов'язковий запит на `raw.githubusercontent.com` при кожному запуску — без мережі інструмент не стартував. У нас каталог убудований у бінарник, тому прогін детермінований; сам каталог покриває всі чотири моделі виявлення з `data.json` і на 5591 платформ більше | `identityCatalogue` |
| 24 | Лічильник знайдених профілів і підсумок часу | `main.go:172-179`, `config.Count` | `улучшено` | `username_search` | наш `transformCollector` рахує відповіді **під час** прогону, а не після нього — оператор бачить `0 / 5897` не як мертвий інтерфейс | `transformCollector` |

## Що лишилося

Чотири рядки — 10, 11, 12, 13 (GitHub SSH/GPG/social/mutual-followers) і три —
14, 15 (Gravatar, Keybase), 16 (HudsonRock). Це наступна ітерація: чотири
GitHub-ендпоінти через `githubAPIGet` і один новий transform `identity_graph`
(Gravatar + Keybase + HudsonRock) дадуть усі вісім.

Що вже є в цій сесії й **не** входить у цей список: `email_recon` у нас читає
Gravatar і Keybase як HTML-профілі, і це не змінювалося — змінювався лише
`breach_exposure`.

## Де ми кращі за оригінал

| оригінал | у нас |
|---|---|
| `log.Fatal` у горутинах (`search.go:305,321`, `breachdirectory.go:23,28`, `mutual-followers.go:64,72`) | помилка → попередження в результаті |
| `&http.Client{}` без таймауту в **9** модулях | `timeout_ms` на кожен запит, publishes у metadata |
| `context.Context` немає ніде | `ctx` від HTTP-запиту до кожної горутини |
| 306 горутин без ліміту, кожна зі своїм `http.Transport` | пул `concurrency`/`delay` |
| `TLSConfig.NextProtos = ["http/1.1"]` вимикає HTTP/2 | дефолтний транспорт |
| `utils.UnmarshalJSON` видаляє файл і тягне його з GitHub | каталог у бінарнику |
| `os.ModePerm` (0777) на файли з паролями | нічого не пишеться на диск |
| `WriteEmailToFile` без mutex | один запис, немає спільного стану |
| CI ламається: `.github/workflows/go.yml` ставить Go 1.22.5, `go.mod` вимагає 1.25 | Go 1.26.7, CI зелений |
| `screen.Clear()` друкує `\033[2J` без перевірки `isatty` | JSON-відповідь, без ANSI |

## Живий прогін 2026-10-07 — що він показав

Прогін через живий рушій на ізольованому стенді (`ENGINE_LISTEN_ADDR=127.0.0.1:8281`,
окремий `CA_DIR`), запит **`noreply@pravda.ru`**, `max_bytes: 65536`,
`timeout_ms: 15000`. ProxyNova і weakpass реальні; BreachDirectory без ключа.

| що | число |
|---|---:|
| HTTP | 200 за **2.41 s** |
| рядків від ProxyNova | 20 (сервер каже `count: 3458`) |
| адрес у знахідках | **18** |
| кредів | **19** |
| вузлів-дублікатів | **0** |
| ребер `exposed_in_breach` | 18 |

**Три числа, які не збігаються, — і це не помилка, а факт про джерело.**
`count: 3458` — це розмір збігу за підрядком усієї відповіді ProxyNova, а
`lines` обрізаний до 20. Обидва поля присутні в його відповіді, і ми беремо
більше з них та пишемо розбіжність у попередження: зрізати до `count` означало б
кинути 3438 знахідок мовчки.

**Дефект, знайдений цим прогоном, а не читанням коду.** ProxyNova відповів
`al3xis@pravda.ru` **двома** рядками з різними паролями (`200804` і
`200804al3xis`) і `akkord@pravda.ru` двома рядками з однаковим. Реалізація, що
писала один вузол на знахідку, поклала б два вузли на одну адресу, а
`identity` + `kind` — це ключ графа: пара збереглася б як один вузол, і один
пароль зник би без жодного рядка про це. Тому:

- один вузел на адресу;
- **усі** креди й хеші у списку `credentials` — два різні паролі живуть там оба;
- однаковий повтор **зливається**: два рядки, що збігаються в усьому, — це одна
  знахідка, і рахувати її двічі означало б написати оператору «цей акаунт
  перевикористано в 4 витоках» з даних, які цього не кажуть;
- скалярні `password`/`sha1`/`source` **завжди** присутні й називають перший за
  сортуванням кред — щоб читач бачив пароль і хеш без відкриття списку, а
  `credential_count` поруч каже, що це перший із кількох.

Це рішення змінило форму звіту після того, як прогін її показав; тест
`TestBreachExposureKeepsEveryPasswordForOneAddress` фіксує саме цю форму.

**Другий дефект, знайдений тим самим прогоном.** Тип сутності визначається з
**самої знахідки**, а не з того, що запитали: запит юзернейма повернув адреси, і
типізація за запитом записала б двадцять адрес як `username`-вузли. Замість цього
`breachExposureIdentity` бере вид з identity — і хеш без адреси типізується як
`username` з префіксом `sha1:`, бо SHA-1 не є адресою.

## Сверка з оригіналом — обидва запущені окремо, на тих самих датах

Оригінал зібрано з клону (`go build`, Go 1.26.8) і запущено **окремою командою**,
вивід збережено у файл:

```
/tmp/opencode/gosearch-orig -u noreply@pravda.ru -o /tmp/opencode/gs-run
```

Наш рушій — окремий процес на окремому порту `8281`. Жодного спільного процесу не
зупинено.

| що | оригінал | у нас | вердикт |
|---|---:|---:|---|
| знахідок надруковано | **20** рядків | **20** (`findings`) | збіг |
| унікальних кредів | 18 | 19 (`distinct_findings`) | наше число рахує рядки джерела, оригінал рахує рядки таблиці |
| адрес | 18 | 18 (`identities`) | збіг |
| ключ `count` від ProxyNova | 3458 | 3458, у попередженні | збіг |
| доменів `<user><tld>` | **3** (`.biz`, `.co`, `.io`, усі 200) | **3**, ті самі, ті самі статуси | збіг |
| профілів по 306 платформах | 61 | — | `username_search`, окремий transform |
| права файлу звіту | **775** | **640** | наше виправлення, див. нижче |
| витків кожного пароля | **не рахує** | рахує | наше розширення |
| компрометованість пароля | не перевіряє | `password_breach_count` | наше розширення |

**Чому лічильник зливів, а оригінал його не має.** Оригінал розбиває хеш у
пароль (`weakpass.go:18`) і на цьому зупиняється. Живий вимір 2026-10-07:

| пароль | витків (Pwned Passwords) |
|---|---:|
| `123456` | **210 461 208** |
| `123qwe` | 3 973 136 |
| `9081726354` | 41 807 |
| `01096262jm` | 117 |
| `19701941` | 0 |
| `69d67e` | 0 |

Пароль у 210 мільйонах витків і пароль у ста — різні знахідки, а оригінал показує
обидва однаково. Запит іде k-anonімно: назові йде лише 5 символів SHA-1, решта
порівнюється локально.

**Файл звіту: 775 проти 640.** Оригінал відкриває файл з `os.ModePerm`
(`utils.go:45`) — виміряно `775`, тобто пароль читає будь-який акаунт на машині.
Тут `0640`. Це єдина свідома відмінність у поведінці, і вона в бік відсутності
втрати: здатність та сама, але без розкриття.

## Межі

- `gosearch/` у дереві — клон оригіналу, доказ контрактів. Не редагувався.
- `web/templates/lab/index.html` — спільний файл: змінено рівно 4 рядки (2 ключі ×
  2 мови). Жодної іншої розмітки не торкався.
- `engine/osint_transforms.go` — змінено 2 рядки: один у `transformRegistry`, один
  `case` у диспетчері.