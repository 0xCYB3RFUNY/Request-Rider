# Automation UI E2E

Локальні browser-сценарії Automation перевіряються через Firefox UI, Django gateway,
Go engine та browser-worker. Тести не використовують зовнішні цілі: fixture
запускається на випадковому loopback-порту, а AI-провайдером є локальний
OpenAI-compatible stub.

## Запуск

З корня репозиторію, коли вже працюють `web :8000`, `engine :8081` і
`browser-worker :8090`:

```bash
browser-worker/.venv/bin/python tests/e2e/test_automation_ui.py
```

Один окремий сценарій можна запустити через unittest-фільтр, наприклад:

```bash
browser-worker/.venv/bin/python tests/e2e/test_automation_ui.py -k handoff
```

Для повного smoke-аудиту зміненого інтерфейсу використовуйте:

```bash
browser-worker/.venv/bin/python tests/e2e/comprehensive_qa_test.py
```

Скрипт перевіряє header status, основні вкладки, локальний fixture, History,
Traffic, Automation і Template Store, а результат записує у
`tests/e2e/qa_results.json` (файл ігнорується Git).

## Матриця сценаріїв

- Manual trigger → Set → Output: canvas, connections, запуск і журнал.
- Repeater transfer та loop: один raw request, кілька URL, History.
- Target selected URL: рядок карти → Repeater workspace → Automation workflow.
- Condition true/false → Merge: активна гілка без виконання inactive branch.
- Decoder/Comparer: typed fields, JSON/object values, failed decoder path.
- Static Target і Browser Target: fixture lifecycle, browser confirmation,
  network evidence.
- Passive capture context: explicit Project/no-Project selection, opaque token,
  browser Target forwarding, workspace state та live UI classification.
- OSINT graph canvas: local SVG 500+ node budget, details drawer, filter,
  auto-layout, custom entity та context-menu transforms.
- Intruder: fixture dictionary, cancel/confirm dialog, generated results.
- Scope rejection: Project target блокує Repeater до engine call; active
  tool workflow без Project зупиняється до run.
- Project context: selector записує CSRF-protected server session, reload не
  приймає spoofed localStorage або `?project_id`.
- Pause/resume/cancel: Delay node та окремі execution controls.
- Webhook/schedule activation: UI activation, webhook trigger, deactivation.
- Export/import: download, JSON schema, import through file input, rerun.
- Persistence: reload, node params, connections і run history.
- Evidence handoff: Repeater/Intruder/Target/OSINT/Scanner → explicit AI
  attachment → local AI response → operator-created follow-up workflow.
- AI Project context: explicit one-shot opt-in, active Project provenance,
  redacted bounded context та automatic reset після запиту; без active Project
  control disabled.
- Workflow AI node: Repeater evidence → AI Agent node → Output.
- Template Store: category/search, preview, required variables, active-template
  confirmation, local `Save as template` та import у новий canvas.
- OAST Listener: local provider registration, Repeater callback, Collect та
  explicit no-callback timeout.
- Repeater Burst: bounded parallel fixture requests, confirmation, History та
  відмова поза exact Project origin.
- Last-Byte Sync: real raw HTTP/1.1 executor, local TCP fixture, final-byte hold,
  TLS verification, cancellation та History evidence.
- High-risk canary templates: BOLA/IDOR differential, bounded race observation,
  WAF rule differential, synthetic JWT claims, XXE → local OAST callback та
  read-only CI/CD exposure review; усі импорти/запуски manual-confirmed.

## Перевірка й cleanup

Кожен тест має унікальне ім'я workflow і видаляє створені workflow у
`tearDown`. Capture contexts deactivate, а fixture-specific `TargetJob` та
`TrafficRecord` видаляються через `web/.venv/bin/python manage.py shell`, а
локальні fixture і fake LLM процеси зупиняються. Скрипт спостерігає console errors і failed browser requests;
винятком є лише очікувані `ERR_ABORTED`/`NS_ERROR_ABORT` під час закриття SSE.
Поточна матриця
містить 37 browser-тести.

AI не виконує активні дії автоматично: у сценаріях handoff recommendation лише
перевіряється, а наступний Target/Repeater/Scanner workflow запускає оператор
через окрему UI-дію та підтвердження.
