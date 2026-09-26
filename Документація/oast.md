# OAST Listener у Request Rider

> Станом на 2026-09-25 жорсткі event/body/poll ceilings та provider-specific
> fallback caps прибрано. Деталі — у
> [звіті про видалені обмеження](видалені-обмеження.md).

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

`agent-workspace/tools/oast_fixture.py` підтримує:

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

## Обмеження

- fixture використовує local HTTP provider contract; endpoint також приймає
  зовнішній absolute HTTP(S) provider URL без application policy gate;
- Interactsh registration/crypto compatibility, DNS/HTTPS/SMTP events і
  durable encrypted evidence залишені наступними ітераціями;
- runtime process-local; provider TTL/lease є додатковим safety net.

Перевірки:

```bash
go test ./... -count=1
python agent-workspace/tools/test_oast_fixture.py -v
browser-worker/.venv/bin/python agent-workspace/tests/e2e/test_automation_ui.py -k oast_listener
```
