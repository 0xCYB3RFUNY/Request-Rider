# OAST Listener у Request Rider

> Станом на 2026-09-25 жорсткі event/body/poll ceilings та provider-specific
> fallback caps прибрано. Чинне правило — жодних прихованих application-level обмежень у
> коді; явні технічні межі дозволені — у [AGENTS.md](../AGENTS.md#заборонено-на-рівні-проєкту).

## Поточний вертикальний зріз

Реалізовано provider contract для blind callback evidence:

```text
OAST Listener (start)
    -> payload_url + listener_id
    -> Repeater/Target/Intruder з {{payload_url}}
    -> OAST Collect (wait)
    -> events / triggered / timed_out
```

Go engine володіє provider registration, polling, cancellation і in-memory
job state. Django workflow runtime зберігає graph/run state, передає shared
OAST context між вузлами та cleanup-є listener навіть якщо collect не дійшов.

Внутрішні engine routes:

```text
POST   /proxy/oast
GET    /proxy/oast/<listener_id>
DELETE /proxy/oast/<listener_id>
```

Browser-facing `/api/oast` приймає вхідні OAST-колбеки (GET/POST) і публікує
live project event через `emit_project_event` у канал активного Project
(`ws/project/<id>/events`, див. `web/core/asgi.py`); фронтенд показує
вспливаюче toast-повідомлення. Покриття: `OastCallbackTests` у
`web/lab/tests.py` (POST/GET без Project, еміт події `oast` для активного
Project). Interactsh-сумісність лишається backlog після локального HTTP
contract і не реалізована.

## Fixture

Локальний fixture-сервер підтримує:

```text
POST   /register
GET    /poll?listener_id=<id>
GET    /hit/<id>
DELETE /listener/<id>
```

Він не є повним Interactsh emulator і не виконує криптографію. Повернена
`payload_url` перевіряється щодо origin provider; TLS verification не
вимикається. Provider endpoint приймає absolute HTTP(S) URL без userinfo,
query або fragment.

## Безпека

- provider URL задається користувачем і проходить лише синтаксичну перевірку
  absolute HTTP(S) URL;
- `OAST_AUTH_TOKEN` читається лише з environment і не повертається snapshot;
- workflow `auth_token` не persists;
- redirects rejected;
- callback events require stable `event_id`, deduplicate and redact sensitive
  headers/query values;
- events, strings і provider responses не обмежуються application count/body
  budget;
- provider failures стають `failed`, clean timeout — `completed`,
  `triggered: false`, `timed_out: true`;
- listener cancellation is idempotent and attempts provider cleanup.

## Workflow UI

`OAST Listener` і `OAST Collect` доступні в palette Automation. Listener має
explicit confirmation. `Collect` отримує listener ID із shared context того
самого run; arbitrary external job ID не приймається як достатній авторизаційний
токен.

Для Intruder/Target callback URL вставляється через `{{payload_url}}`, а сам
OAST provider URL не вважається target URL. Фактичний Repeater/Intruder
request запускається окремою операторською дією.

## Активний сканер (2026-10-15)

`engine/pkg/active` теж читає цей сервіс. `active.ScanRequest.OAST` несе
`ServerURL`/`AuthToken`; порожні значення читаються з **`OAST_SERVER_URL`** і
**`OAST_AUTH_TOKEN`** — тих самих змінних, що й інструмент OAST, тож оператор
налаштовує їх один раз.

Налаштований сервіс → `OutOfBand` (модуль `out-of-band`) реєструє **один**
слухача на прогін і читає доказ, якого немає в HTTP-обміні: застосунок сам
звернувся на адресу, яку назвав прогін.

**Чотири вектори, чотири модулі** — і ділка між ними не у форматі, а в тому,
*куди* кладе адресу прогін:

| модуль | адреса потрапляє | рядки |
|---|---|---|
| `out-of-band` | у **значення параметра**, і застосунок його завантажує | `0x00100A00`, `0x00300210`, `0x00200904`/`0x00200905` (JWT `jku`/`x5u`) |
| `out-of-band-xml` | у `SYSTEM`-ідентифікатор зовнішньої сутності надісланого документа | blind XXE (`0x00100400`) |
| `out-of-band-cmd` | у командний рядок: `;`/`|`/`&&`/`$()`/`` ` `` × `curl`/`wget`/`nslookup` | blind command execution (`0x00300210`) |
| `out-of-band-header` | у **заголовок**, який застосунок перетворює на URL | `0x00300200` |

Доказ у всіх чотирьох один: колбек, а не відповідь. `out-of-band-header` —
єдиний, у якому значення параметра немає взагалі: параметр не задіяний, а
застосунок будує URL із заголовка, який надіслав клієнт. Це форма
password-reset-посилання, абсолютного редиректа та referer-beacon.

Без налаштованого сервісу модулі **мовчать**, і це названий стан, а не тихе
зниження: `report.Warnings` містить рядок про недоступність сервісу, якщо адресу
задано, а сервіс не відповів. Вигадувати доказ у цій сім'ї не можна — «не
прийшов колбек» і «ціль нічого не робила» дають однаковий рядок, тому
детектор, який не бачить колбека, змушений мовчати.

Межі цього каналу:

- підтримані протоколи — `http` і `dns`. SMTP-рядки (`0x00200800`,
  `0x00300220`) закриває модуль `smtp-injection`, але **не** через цей канал:
  він доводить відповідь поштового сервера на ін'єктований адресі, а не колбек
  на нашій адресі;
- `jku`/`x5u` доводяться тим, що сервер **завантажив** ключ; підробка підпису
  не доводиться і не заявляється;
- колбек доводить **звернення**, а не наслідок — що саме зроблено з відповіддю,
  читає оператор. Тому кожен рядок цієї сім'ї має в описі окреме речення
  «Not proven»: що саме не доведено.

## Обмеження

- fixture використовує local HTTP provider contract; endpoint також приймає
  зовнішній absolute HTTP(S) provider URL без application policy gate;
- Interactsh registration/crypto compatibility, DNS/HTTPS/SMTP events і
  durable encrypted evidence залишені наступними ітераціями;
- runtime process-local; provider TTL/lease є додатковим safety net.

Перевірки:

```bash
go test ./... -count=1
```
