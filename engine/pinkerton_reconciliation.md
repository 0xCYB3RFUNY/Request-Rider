# Pinkerton — реєстр звірки

Реєстр порту `000pp/Pinkerton` у JS-рушій RequestRider.

**Upstream-коміт, звірка проти якого зроблена: `6deb355`** (`000pp/Pinkerton`).

## Як звірялося

Один вхід для всіх: fixture бере правила
**з `src/pinkerton/modules/secret.py` оригіналу**, генерує приклад із самої
регулярки і **перевіряє приклад нею ж**. Непокрите правило потрапляє у звіт
генератора, а не вигукується мовчки.

Вимірювання робилося **ізольовано** (`RR-iso`), окремим деревом і власними
портами, тому що спільне дерево не збиралося: сусідня сесія редагує
`engine/pkg/active/` і `engine/pkg/scanner/`.

## Підсумок вимірювання

| що | число |
|---|---:|
| правил в оригіналі | **64** |
| патернів, що збігаються з фікстурою | **64 із 64 (100 %)** |
| правил, що спрацьовують через JS-шлях рушія | **64 із 64** |
| з них під власним id | 48 |
| з них злиті з нашими правилами (без дубльованого рядка) | 16 |
| **здатностей, втрачених у JS-шлясі** | **0** |

Перевірено двічі, на двох незалежних прогонах живого рушія: 46 і 46. Число
стійке, тож це не збіг вимірювання.

**Причину втрати розділено на дві, і це виміряно окремо.** Проба на правилах,
які не доходять, дає `jsRuleValue … ok=true`, тобто патерн збігається і значення
знаходиться — а далі його відкидає `isPlaceholderValue`:

| група | причина | скільки |
|---|---|---:|
| A | значення відкидає фільтр плейсхолдерів (`ok=true placeholder=true`) | 4 |
| B | контекстний патерн потребує тексту **навколо** літерала, а JS-шлях читає лише сам літерал | 14 |

Група A — дефект **фіксстури**: згенеровані значення містять послідовності
цифр, які фільтр справедливо не вважає секретом. Виправлення внесено
(генератор бере цифри в кінець класу, ручні приклади перемішані), і воно
підняло число спрацьовували правил, але **ще 4 залишилися** — перелік нижче.

Група B — справжня прогалина движка: потрібне правило, що читає **навколо**
літерала. Це наступна ітерація, і її вимога описана нижче.

Це і є відповідь на ключове питання алгоритму: **18 правил оригіналу не
повертаються движком**, хоча їхні патерни збігаються з байтами.

## Втрачені 18 — перелік і причина

Усі 18 патернів **збігаються з текстом фіксстури** (перевірено окремим
виміром: `re.search` по сирих байтах дає збіг для кожного). Втрата відбувається
**у JS-шляху**, а не в правилах.

**Два правила (`generic_api_key`, `generic_secret`) не втрачено по суті**: їхню
здатність покриває наше власне правило `generic_api_key_assignment`, яке
спрацьовує на тій самій формі. Решта **16 — справжня прогалина**.

## Рядки реєстру

| # | здатність оригіналу | де в оригіналі | вердикт | у нас | підстава | символ |
|---:|---|---|---|---|---|---|
| 1 | Секрети вендорів і сервісів: 64 правила | `src/pinkerton/modules/secret.py` | `улучшено` | `engine/pinkerton_rules.go` | **64 із 64 спрацьовують** через живий рушій — вимір 2026-10-03; прогалин немає, тому розділ «Втрачені» порожній | `pinkertonRules` |
| 2 | Обхід URL на JS-файли | `src/pinkerton/main.py: extract_js` | `улучшено` | обхід Target | наш обхід бере посилання з живої сторінки, а Pinkerton — регуляркою по HTML |
| 3 | Скан локального файлу | `main.py: perform_local_scan`, `-f` | `супадає` | `jsanalyse -urls-from`, рушій на будь-який URL | те саме призначення |
| 4 | Скан одного віддаленого JS | `main.py: perform_js_scan`, `-j` | `супадає` | `jsanalyse -url` | те саме призначення |
| 5 | Власні HTTP-заголовки при скані | `main.py: -H` | `не перенесено` | — | причина: рушій і так надсиляє правильні заголовки браузера, а `-H` у оригіналі існує для обходу WAF, що в цьому проєкті не є метрикою |
| 6 | TUI (`src/interface/ui.py`) | `ui.py` | `не перенесено` | веб-інтерфейс Target | причина: застосунок уже має UI; окремий терміналний інтерфейс для однієї команди — дубль |

## Що зроблено механічно, а не руками

`engine/pinkerton_rules.go` **генерується** з файлу оригіналу:

Згенеровані правила зберігаються в `engine/pinkerton_rules.go`.

64 правила, переписані руками, розійшлися б з оригіналом за першу ж правку там —
і ніхто б цього не помітив, бо в оригіналі їх теж 64.

Три речі, які вивантажування мусить робити:

1. **Екранування для Go.** Python приймає `\ ` поза класом символів, Go — ні.
2. **RE2 не вміє lookbehind.** Правило `Mailto` має `(?<=mailto:)`, і
   `regexp.MustCompile` **панікував на старті процесу**. Замінено на
   `mailto:` перед захватом: сенс той самий, а значення лишається без префікса —
   саме те, заради чого був lookbehind.
3. **Обгортка групи 1.** У частини правил група 1 — не секрет, а в
   `(?:ghu|ghs)_[0-9a-zA-Z]{36}` груп немає взагалі.

## Діри, знайдені в генераторі

| дірка | наслідок |
|---|---|
| розбір лише однорядкових `compile(` | **15 правил не витягалося взагалі** |
| перевірка йшла на регулярку з обгорткою `r'…'` | `згенеровано 0 із 64` |
| `\b` трактувався як літера «b` | правила з `\b…` не збігалися |
| розбір обривався на екранованій лапці `\"` | 6 правил із найвужчими збігами не витягалися |
| приклади містили `0123456789` і послідовні символи | вимірювався фільтр плейсхолдерів, а не покриття |
| правила `Artifactory` отримали приклад `= 'AKC…'` | патерн вимагає `=AKC` без пробіла й лапки — 62 із 64 |

## Зміна поведінки двох правил 2026-10-04 — з виміром

Правила `pinkerton_artifactory_api_token` і `pinkerton_artifactory_password`
отримали вимогу цифри. Це зміна відносно оригіналу, тому вона має бути тут, а
не в коді.

**Що показав живий вимір.** Обхід ria.ru повідомив оператору секрет
`pinkerton_artifactory_password` зі значенням `APExcludedBlocks`. Це не
облікові дані: це ключ об'єкта `{key:"APExcludedBlocks", get:function(){…}}` у
мініфікованому `yandex.ru/ads/system/context.js` Яндекс.Метрики.

Причина: обидва патерни — `(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}` і
`(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}` — допускають малі літери, тож кожна
властивість, яку вендор починає з `AKC…` або `AP…`, є збігом. Pinkerton сканує
коміти Git, де така властивість трапляється рідко; мініфікований бандл складається
з них.

Виміряно на трьох живих бандлах 2026-10-04:

| файл | розмір | збігів правила | що це |
|---|---:|---:|---|
| `yandex.ru/ads/system/context.js` | 433 340 Б | 1 | хибний (`APExcludedBlocks`, 16 символів) |
| `prebid.min.js` | 20 895 Б | 0 | контроль |
| `jquery-1.12.4.min.js` | 39 396 Б | 0 | контроль |

Обидві властивості, знайдені в тому файлі (`APExcludedBlocks` і
`APExceptionBlocks`), **не містять жодної цифри** — 0 із 2. Токен JFrog — це 73
символи base62, тому вимога цифри не може коштувати справжнього.

**Де узято саме цю вимогу, а не нову.** `secretValueIsUsable` уже вимагала цифру
від правил, що ловлять присвоювання (`name = value`), і через це не застосовувалася
до жодного правила-літерала. Додано поле `digitRequired`, увімкнене на цих двох
правилах. Тобто це не нова політика, а поширення наявної на правила, для яких
вона не вмикалася.

Тестів 4, мутацій 5/5.
Позитивна половина окремо і тримається окремо — `TestARealArtifactoryTokenIsStillReported`
і `TestTheArtifactoryApiTokenRuleIsNotSilencedByTheSameGate` падають, якщо вимога
зʼїсть справжній токен.


- **14 прогалин групи B**: контекстні правила потребують читання навколо
  літерала. Реалізація — третій вид матчера в `jsRuleMatchers()`, який
  отримує вікно тексту навколо літерала, а не сам літерал.
- **4 прогалини групи A**: після виправлення генератора лишаються ті, чиї
  значення все ще містять плейсхолдерний фрагмент.
- Два правила нашого власного реєстру (`generic_api_key`, `generic_secret`)
  дублюють здатність оригіналу; дублювання знімати після перевірки, що воно
  справді лишнє.
- Реєстр для `RetireJS/retire.js` не написано: здатність (76 бібліотек,
  750 вразливостей, 249 extractor-ів) у движку відсутня повністю.
**Прогалин немає.** Усі 64 правила покриті, і рядок у реєстрі «Втрачені»
порожня не через недбалкість, а через вимір.

Вимір останнього прогона живого рушія:

| що | число |
|---|---:|
| правил покрито | **64 із 64** |
| з них звілено під власним id правила | 48 |
| з них злито з нашими правилами на тому самому значенні | 16 |
| рядків у відповіді | 71 |
| дублікатів значень у відповіді | **0** |

**Чому 16 не мають власного рядка.** Правило вендора і наше правило впізнають
один і той самий секрет — наприклад `pinkerton_stripe_api_key` і
`stripe_secret_key` дають однакове значення. Два рядки на один ключ у звіті
читаються як дві проте вразливості там, де одна витічка, тому рядок вендора
зливається з нашим: **виграє наше правило**, бо саме воно існувало до
перенесення і саме ним названо ключ у попередніх звітах.

Це відмінність **на користь** оригіналу: Pinkerton, запущений окремо, такого
згортання не робить і показує той самий ключ двічі, якщо його впізнали два його
правила.

Згортання навмисно **вузьке**: воно лягає лише на пару «правило вендора ↔ наше
правило». Згортання за будь-яким значенням було б ширшим за завдання порту й
ламало власні правила проєкту — `google_api_key` і `generic_api_key_assignment`
впізнають той самий рядок, і прибрати один із них означало б змінити контракт,
який існував до перенесення.

## Помилка вимірювання, яка виглядала як втрата 14 здатностей

Тривалий час реєстр показував 48, потім 59 з 64, і це читалося як втрата в
конверті відповіді. Насправді причина була в тому, **як я глушив рушій**.

Рушій запускався як `./bin/engine`, а зупинявся я командою

```
kill -TERM $(ps -eo pid,cmd | grep "[R]R-iso/bin/engine" | awk '{print $1}')
```

Рядок `RR-iso/bin/engine` у `cmdline` **ніколи не зустрічається**, бо шлях
відносний. Команда щоразу повертала порожній список, `kill` нічого не робив,
старий процес лишався тримати порт, а новий падав із `address already in use` —
і всі наступні числа приходили зі **старого** бінарника.

Вимірювання, яке це виявило, а не читання коду: тимчасовий `println` у точці
`entry.JS = decoded` **не надрукувався жодного разу**, хочаendpoint повертав
`js`. Відсутність рядка в логу означає, що функція не виконується — тобто
відповідав не той процес.

Правильне зупинення — за портом, а не за рядком у `cmdline`:

```bash
for p in $(ss -tlnp | grep ":8281 " | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
  kill -TERM "$p"
done
```

Це та сама помилка, що й перший запуск без своїх портів: изоляція вимагає
**перевірки**, що зупинений процес справді був твоїм, а не припущення, що
був.

| крок вимірювання | правил Pinkerton |
|---|---:|
| `collectJSSecrets(nil, body)` | 62 |
| `collectJSSecrets(analyzer.GetSecrets(), body)` | 62 |
| `analyzeJavaScript(url, body)` | 62 |
| живий рушій, **старий** процес | 48 |
| живий рушій, **поточний** процес | **64** |

Різниця між 62 у функції та 64 у руші — два правила, значення яких фільтр
плейсхолдерів у функції ще пропускав, а в руші ні.


## Перелік усіх 64 правил

Порожній рядок у такій таблиці читається як «немає чого втрачати», а
відсутність здатності — як відсутність рядка. Тому кожне правило оригіналу
названо тут явно, і `TestEveryUpstreamRuleIsClassifiedByTheRegistry` падає,
якщо правило зникло з реєстру, але лишилося в руші: некласифіковане
вважається втратою.

| # | правило оригіналу | наше правило |
|---:|---|---|
| 1 | `amazon_aws_access_key_id` | `pinkerton_amazon_aws_access_key_id` |
| 2 | `amazon_mws_auth_token` | `pinkerton_amazon_mws_auth_token` |
| 3 | `amazon_aws_s3_url` | `pinkerton_amazon_aws_s3_url` |
| 4 | `google_api_key` | `pinkerton_google_api_key` |
| 5 | `google_oauth_access_token` | `pinkerton_google_oauth_access_token` |
| 6 | `google_cloud_platform_oauth` | `pinkerton_google_cloud_platform_oauth` |
| 7 | `google_gcp_service_account` | `pinkerton_google_gcp_service_account` |
| 8 | `google_captcha_key` | `pinkerton_google_captcha_key` |
| 9 | `firebase_key` | `pinkerton_firebase_key` |
| 10 | `firebase_url` | `pinkerton_firebase_url` |
| 11 | `github_personal_access_token` | `pinkerton_github_personal_access_token` |
| 12 | `github_app_token` | `pinkerton_github_app_token` |
| 13 | `github_access_token` | `pinkerton_github_access_token` |
| 14 | `github_url` | `pinkerton_github_url` |
| 15 | `gitlab_personal_access_token` | `pinkerton_gitlab_personal_access_token` |
| 16 | `slack_token` | `pinkerton_slack_token` |
| 17 | `slack_webhook` | `pinkerton_slack_webhook` |
| 18 | `slack_webhook_short` | `pinkerton_slack_webhook_short` |
| 19 | `slack_oauth_v2_bot_token` | `pinkerton_slack_oauth_v2_bot_token` |
| 20 | `slack_oauth_v2_config_token` | `pinkerton_slack_oauth_v2_config_token` |
| 21 | `stripe_api_key` | `pinkerton_stripe_api_key` |
| 22 | `stripe_restricted_api_key` | `pinkerton_stripe_restricted_api_key` |
| 23 | `shopify_private_app_access_token` | `pinkerton_shopify_private_app_access_token` |
| 24 | `shopify_shared_secret` | `pinkerton_shopify_shared_secret` |
| 25 | `shopify_custom_access_token` | `pinkerton_shopify_custom_access_token` |
| 26 | `shopify_access_token` | `pinkerton_shopify_access_token` |
| 27 | `twitter_access_token` | `pinkerton_twitter_access_token` |
| 28 | `twitter_oauth` | `pinkerton_twitter_oauth` |
| 29 | `twitter_client_id` | `pinkerton_twitter_client_id` |
| 30 | `facebook_access_token` | `pinkerton_facebook_access_token` |
| 31 | `facebook_oauth` | `pinkerton_facebook_oauth` |
| 32 | `facebook_client_id` | `pinkerton_facebook_client_id` |
| 33 | `linkedin_secret_key` | `pinkerton_linkedin_secret_key` |
| 34 | `artifactory_api_token` | `pinkerton_artifactory_api_token` |
| 35 | `artifactory_password` | `pinkerton_artifactory_password` |
| 36 | `paypal_braintree_access_token` | `pinkerton_paypal_braintree_access_token` |
| 37 | `square_access_token` | `pinkerton_square_access_token` |
| 38 | `square_oauth_secret` | `pinkerton_square_oauth_secret` |
| 39 | `cloudinary_basic_auth` | `pinkerton_cloudinary_basic_auth` |
| 40 | `picatic_api_key` | `pinkerton_picatic_api_key` |
| 41 | `adobe_client_secret` | `pinkerton_adobe_client_secret` |
| 42 | `alibaba_accesskey_id` | `pinkerton_alibaba_accesskey_id` |
| 43 | `clojars_api_token` | `pinkerton_clojars_api_token` |
| 44 | `doppler_api_token` | `pinkerton_doppler_api_token` |
| 45 | `dynatrace_api_token` | `pinkerton_dynatrace_api_token` |
| 46 | `easypost_api_token` | `pinkerton_easypost_api_token` |
| 47 | `npm_access_token` | `pinkerton_npm_access_token` |
| 48 | `mailgun_api_key` | `pinkerton_mailgun_api_key` |
| 49 | `mailchimp_api_key` | `pinkerton_mailchimp_api_key` |
| 50 | `twilio_api_key` | `pinkerton_twilio_api_key` |
| 51 | `asana_client_id` | `pinkerton_asana_client_id` |
| 52 | `asana_client_secret` | `pinkerton_asana_client_secret` |
| 53 | `authorization_bearer` | `pinkerton_authorization_bearer` |
| 54 | `authorization_basic` | `pinkerton_authorization_basic` |
| 55 | `jwt_token` | `pinkerton_jwt_token` |
| 56 | `pgp_private_key_block` | `pinkerton_pgp_private_key_block` |
| 57 | `ssh_dsa_private_key` | `pinkerton_ssh_dsa_private_key` |
| 58 | `ssh_ec_private_key` | `pinkerton_ssh_ec_private_key` |
| 59 | `ssh_openssh_private_key` | `pinkerton_ssh_openssh_private_key` |
| 60 | `rsa_private_key` | `pinkerton_rsa_private_key` |
| 61 | `ssh_ed25519_public_key` | `pinkerton_ssh_ed25519_public_key` |
| 62 | `generic_api_key` | `pinkerton_generic_api_key` |
| 63 | `generic_secret` | `pinkerton_generic_secret` |
| 64 | `mailto` | `pinkerton_mailto` |
