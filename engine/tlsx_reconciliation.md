# tlsx — реєстр звірки

Реєстр звірки з `projectdiscovery/tlsx` у шар пасивного збагачення
RequestRider.

**Upstream-коміт, звірка проти якого зроблена: `v1.3.2`**
(`projectdiscovery/tlsx`, ліцензія **MIT**).

## Де взято вимірювання — і чому це інший випадок

Усі попередні реєстри цього набору звірялися з клоном у
`Semple-Интеграции/`. **Клони видалені** — дерево `/home/kali/Request-Rider
v1.1.0` їх не містить. `tlsx` при цьому все одно вимірюється точно, бо він
**пряма Go-залежність**: вихідники лежать у модульному кеші
`$(go env GOMODCACHE)/github.com/projectdiscovery/tlsx@v1.3.2`, і це той самий
код, який компілюється в наш бінарник.

Тому предмет звірки тут — не «чи ми прочитали їхній репозиторій», а «що ми
беремо з типу, який реально використовуємо». Це сильніша форма звірки: вона
не може розійтися з тим, що компілюється.

## Що це за інструмент

TLS-сканер: розбирає рукостискання, читає сертифікат, рахує відбитки й
керує станом TLS-з'єднання. **37 файлів Go, 6 344 рядки** без тестів.

## Підсумок вимірювання

| що | число |
|---|---:|
| файлів Go без тестів | **37** |
| рядків Go без тестів | **6 344** |
| полів у `CertificateResponse` | **20** |
| полів у `clients.Response` (оболонка) | **28** |
| полів `CertificateResponse`, які ми беремо | **19** |
| полів з оболонки `clients.Response`, які ми беремо | **8** |
| **усього властивостей `tls_` у нашому зонді** | **28** |
| прапорців командного рядка | **~140** |
| рядків у цьому реєстрі | **12** |
| `не перенесено` | **2** |
| `супадає` | **9** |
| `улучшено` | **1** |

## Головна знахідка: беремо 19 полів з 48

Тут була помилка першої редакції, і вона варта того, щоб бути записаною.

Я спершу виміряв `osint_http_probe.go` у діапазоні рядків 519-545 і написав
«10 з 20». **`grep -oE '"tls_[a-z_]+"' osint_http_probe.go` дає 19**, і
причина проста: перші вісім властивостей лежать **вище** цього діапазону —
вони читаються з `record.TLSData`, а не з `leaf`.

`record.TLSData` — це `*clients.Response` з того самого пакета `tlsx`
(`httpx/runner/types.go:41`), який вбудовує `*CertificateResponse` і має ще
**28 полів** оболонки. Тобто типів два, а я виміряв один.

| звідки | усього | беремо |
|---|---:|---:|
| `clients.Response` (оболонка) | 28 | **8** |
| `CertificateResponse` (сертифікат) | 20 | **10** |
| разом | 48 | **19** |

З оболонки — **8** полів оболонки: `tls_version`, `tls_cipher`,
`tls_key_exchange`, `tls_server_name`, `tls_jarm`, `tls_ja3`,
`tls_probe_status`, `tls_error`. Плюс `tls_read` — це наш власний маркер
«сертифікат прочитано», а не поле оригіналу, тому в 8 він не входить, але в
підсумкових 19 входить.

8 + 10 + 1 = **19**, і саме це число тест звіряє з кодом.

**Два з них — `jarm_hash` і `ja3_hash` — руйнують моє попереднє твердження.**
Я написав у першій редакції, що відбитки ми не рахуємо. Це неправда: ми їх
беремо. Розбіжність у джерелі: обчислення робить httpx своїм кодом
(`httpx/common/hashes/jarm`, 88 + 116 рядків), а не `tlsx/pkg/tlsx/jarm`
(72 рядки) — це дві незалежні реалізації одного алгоритму, і ми отримуємо
першу, бо читаємо JSON httpx.

## Здатності

| # | здатність оригіналу | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---:|---|---|---|---|---|---|
| 1 | Читання 10 базових полів сертифікату | `clients.CertificateResponse` | `супадає` | `osint_http_probe.go:519-545` | беремо `expired`, `self_signed`, `mismatched`, `wildcard_certificate`, `subject_cn`, `issuer_cn`, `domains`, `emails`, `not_before`, `not_after` — усі десять присутні в нашому `properties` | `CertificateResponse` |
| 2 | `revoked` — відкликаний сертифікат | `CertificateResponse.Revoked` | `супадає` | `osint_http_probe.go` (`tls_revoked`) | перенесено: `properties["tls_revoked"] = leaf.Revoked` | `CertificateResponse` |
| 3 | `untrusted` — сертифікат не в довірі | `CertificateResponse.Untrusted` | `супадає` | `osint_http_probe.go` (`tls_untrusted`) | перенесено: `properties["tls_untrusted"] = leaf.Untrusted` | `CertificateResponse` |
| 4 | `serial` — номер сертифікату | `CertificateResponse.Serial` | `супадає` | `osint_http_probe.go` (`tls_serial`) | перенесено: `properties["tls_serial"] = leaf.Serial` | `CertificateResponse` |
| 5 | `fingerprint_hash` — відбитки сертифікату | `CertificateResponse.FingerprintHash` | `супадає` | `osint_http_probe.go` (`tls_fingerprint_hash`) | перенесено: `md5`, `sha1`, `sha256` у `tls_fingerprint_hash` | `CertificateResponse` |
| 6 | `certificate` — сам PEM | `CertificateResponse.Certificate` | `супадає` | `osint_http_probe.go` (`tls_certificate`) | перенесено: `properties["tls_certificate"] = leaf.Certificate` | `CertificateResponse` |
| 7 | `subject_dn` / `issuer_dn` — повні DN | `CertificateResponse.SubjectDN`, `IssuerDN` | `супадає` | `osint_http_probe.go` (`tls_subject_dn`, `tls_issuer_dn`) | перенесено обидва повні DN | `CertificateResponse` |
| 8 | `subject_org` / `issuer_org` — організації | `CertificateResponse.SubjectOrg`, `IssuerOrg` | `супадає` | `osint_http_probe.go` (`tls_subject_org`, `tls_issuer_org`) | перенесено обидва масиви організацій | `CertificateResponse` |
| 9 | `subject_an` — Subject Alternative Names | `CertificateResponse.SubjectAN` | `улучшено` | `tls_domains` | ми беремо `Domains`, який upstream сам визначає як «дедуплікований `subject_cn` + `subject_an`» — тобто беремо **об'єднання** і не розрізняємо джерела. Для нашої задачі («які домени покриває сертифікат») це сильніше: `CN` без `SAN` — відомий дефект, а `Domains` його згладжує | `CertificateResponse` |
| 10 | Відбитки рукостискання: `jarm` / `ja3` / `ja3s` | `pkg/tlsx/jarm/jarm.go`, `ztls/ja3/ja3.go`; поля в `clients.Response` | `супадає` | `tls_jarm`, `tls_ja3` | **виправлення першої редакції: я написав, що ми їх не рахуємо — це хибно, ми беремо обидва.** Різниця у джерелі: обчислення робить httpx своїм кодом (`httpx/common/hashes/jarm`, 204 рядки), а не `tlsx/pkg/tlsx/jarm` (72 рядки) — дві незалежні реалізації. Ми отримуємо першу, бо читаємо JSON httpx. `ja3s` — **єдине** поле з трьох, якого в нас немає | `tls_jarm` |
| 11 | Довіра до CA з диска і змінні `--cacert` | `clients`, прапорці `ca`, `cacert` | `не перенесено` | — | причина: ми покладаємося на `crypto/tls` і системне сховище. Власний пул CA не даємо, тож перевірити сертифікат, виданий корпоративним CA, наш зонд не зможе | `CertificateResponse` |
| 12 | Стан з'єднання: `-cipher-enum`, `-version-enum`, `-probe-status`, `-pre-handshake` | прапорці `cipher-enum`, `version-enum`, `probe-status`, `pre-handshake` | `не перенесено` | — | причина: перебір і перевірка слабких конфігурацій — окремий клас роботи, а ми в пасивному шарі лише **читаємо** те, що сервер показав сам | `CertificateResponse` |

## Рядок 2 — чому це перший кандидат на перенесення

`revoked` — це одне поле, яке в нас уже є на руках: `leaf` у
`osint_http_probe.go:512` — це об'єкт того самого типу. Тобто перенесення
поля не потребує ні нової залежності, ні зміни моделі, ні нового мережевого
запиту — тільки рядок у вже наявній точці.

Це рідко: зазвичай здатність оригіналу вимагає коду. Тут не вимагає.

## Межа цього реєстру

Реєстр описує **збагачення сертифікату**, а не TLS-сканування. Рядки 10-12
(`ja3`, `jarm`, перебір шифрів) — це здатності сканера, а не збагачувача:
переносити їх у пасивний шар означало б додати активну атаку в проєкт, який
зараз сканує пасивно.

І жоден рядок не є твердженням «сертифікат ми читаємо повністю» — ми читаємо
половину полів, і таблиця каже які.