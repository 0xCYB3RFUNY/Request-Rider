# OAST Listener у Request Rider

## Поточний вертикальний зріз

Реалізовано loopback-first provider contract для blind callback evidence:

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

Browser-facing `/api/oast` не додано: workflow run вже є достатнім API для UI,
SSE, pause/resume/cancel.

## Fixture

`tools/oast_fixture.py` підтримує:

```text
POST   /register
GET    /poll?listener_id=<id>
GET    /hit/<id>
DELETE /listener/<id>
```

Він не є повним Interactsh emulator і не виконує криптографію. Повернена
`payload_url` перевіряється щодо origin provider; TLS verification не
вимикається. Поточна версія приймає лише `http` protocol.

## Безпека

- external provider disabled unless `OAST_ALLOW_EXTERNAL=1`;
- optional `OAST_PROVIDER_URL` pins the configured provider origin;
- `OAST_AUTH_TOKEN` читається лише з environment і не повертається snapshot;
- workflow `auth_token` не persists;
- redirects rejected;
- callback events require stable `event_id`, deduplicate and redact sensitive
  headers/query values;
- event count and event string sizes are bounded;
- provider failures become `failed`, clean timeout becomes
  `completed`, `triggered: false`, `timed_out: true`;
- listener cancellation is idempotent and attempts provider cleanup.

## Workflow UI

`OAST Listener` і `OAST Collect` доступні в palette Automation. Listener має
explicit confirmation. `Collect` отримує listener ID із shared context того
самого run; arbitrary external job ID не приймається як достатній авторизаційний
токен.

Для Intruder/Target callback URL вставляється через `{{payload_url}}`, а сам
OAST provider URL не вважається target URL і не проходить target scope як
endpoint. Scope перевіряється для фактичного Repeater/Intruder request.

## Обмеження

- поки підтримується лише local HTTP provider contract;
- Interactsh registration/crypto compatibility, DNS/HTTPS/SMTP events і
  durable encrypted evidence залишені наступними ітераціями;
- runtime process-local; provider TTL/lease є додатковим safety net.

Перевірки:

```bash
go test ./... -count=1
python -m unittest tools.test_oast_fixture -v
browser-worker/.venv/bin/python tests/e2e/test_automation_ui.py -k oast_listener
```
