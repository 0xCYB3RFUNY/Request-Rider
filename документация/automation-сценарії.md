# Практичні сценарії Automation

## Мета

Сценарії показують реальний операторський workflow: результат одного
інструменту не передається як «магічний AI action», а спочатку стає явним
evidence. AI аналізує лише прикріплений результат, після чого оператор сам
вибирає наступний інструмент, URL, параметри та підтвердження.

Усі приклади нижче виконуються на локальному fixture
`tools/target_fixture.py` і не використовують зовнішню ціль.

## 1. Від fuzzing до наступного crawl

```text
Intruder: GET /search?q={{payload}}
    -> Intruder results (status/body/length/payload)
    -> Send results to AI
    -> AI: FACT / HYPOTHESIS / next safe check
    -> оператор обирає URL
    -> Target або Repeater workflow
    -> окремий Run / confirmation
```

Перевірка:

1. Відкрити `Intruder`, ввести paired marker і малий словник.
2. Дочекатися `completed` і натиснути `Send results to AI`.
3. Перевірити `Attached to chat`: має бути `Intruder results`.
4. Надіслати запит до локального AI provider і перевірити, що відповідь
   містить рекомендацію, а не виконаний tool call.
5. За потреби створити Target/ Repeater workflow через `Send to Automation`
   або вручну в canvas. AI не запускає активний запит автоматично.

Автоматизований regression: `test_intruder_results_handoff_to_ai_and_operator_approved_target_followup`.

## 2. Repeater exchange → AI → Target

```text
Repeater baseline exchange
    -> Send exchange to AI
    -> AI аналізує status/body/headers
    -> оператор обирає URL для наступної перевірки
    -> Target workflow
```

Перевірка: `test_repeater_exchange_handoff_to_ai_and_target_followup`.

## 3. Target map → AI → Repeater

```text
Target static/browser map
    -> page URLs, network evidence, JS/API requests
    -> Send map to AI
    -> AI групує URLs і пропонує baseline
    -> оператор обирає один URL
    -> Repeater baseline
    -> Comparer/Decoder/AI evidence за потреби
```

Важливо: browser network evidence не означає, що URL підтверджений як
endpoint. AI має відокремлювати `FACT`, `HYPOTHESIS` та `UNKNOWN`.

Перевірка: `test_target_map_handoff_to_ai_and_repeater_followup` і
`test_target_browser_fixture_requires_confirmation_and_collects_network`.

## 4. OSINT → AI → Scanner/Target

```text
OSINT DNS/HTTP/TLS/redirects
    -> Send OSINT to AI
    -> AI формує read-only hypotheses
    -> Scanner bounded read-only pass
    -> Target map лише після вибору hostname/URL
```

Не передавати в AI повний secret set без потреби; evidence обмежується
контекстом і явним вибором оператора.

Перевірка: `test_osint_handoff_to_ai_and_scanner_followup`.

## 5. Scanner findings → AI → Target

```text
Scanner findings + evidence
    -> Send scan to AI
    -> AI пріоритезує перевірки
    -> оператор створює Target/Scanner workflow
    -> findings зберігаються з evidence_before/after
```

Scanner не виконує fuzzing, brute force або exploit. AI може лише
запропонувати наступний read-only крок.

Перевірка: `test_scanner_handoff_to_ai_and_target_followup`.

## 6. Workflow AI node

```text
Manual trigger
    -> Repeater / інструментальний вузол
    -> AI Agent
    -> Output
```

AI node отримує результат попереднього вузла як bounded workflow input.
Це не замінює явне прикріплення evidence у вкладці AI: для production-like
аналізу краще використовувати `Send ... to AI` і перевірити вкладений
контекст перед запуском.

Перевірка: `test_workflow_ai_node_receives_repeater_evidence`.

## Загальні правила безпеки

- Діяти Intruder і Browser Target потребують explicit confirmation.
- URL активних вузлів перевіряється межами активного Project.
- AI не має shell, arbitrary filesystem або arbitrary HTTP tools.
- Після AI-рекомендації оператор перевіряє URL, method, dictionary, delay,
  concurrency і budget перед запуском.
- Export/import workflow не є дозволом на запуск; активний workflow запускається
  окремою кнопкою.
- Runtime залишається process-local; Redis/Celery/distributed queue не є
  частиною цих сценаріїв.

## Автоматизована перевірка

```bash
browser-worker/.venv/bin/python tests/e2e/test_automation_ui.py
```

Тестовий runner піднімає випадковий local fixture і local fake LLM, перевіряє
canvas, інспектор, підтвердження, persistence, branch/merge, pause/resume/cancel,
webhook/schedule, export/import, Template Store та evidence handoffs. Після
завершення він видаляє створені workflow і fixture-specific записи.

## Backlog розширених playbooks

Запропоновані у реальних програмах Bug Bounty сценарії — ESI, XXE/OAST,
WebAuthn challenge replay, CI/CD webhook poisoning, HMAC mobile signing,
inventory exhaustion, RAG poisoning, WAF mutation та Last-Byte race — не
вмикаються в MVP автоматично. Їхній пріоритетний порядок:

1. **Read-only baseline:** exposed `.git`, security headers, CORS, GraphQL
   schema, JS assets, response diff.
2. **Bounded active fuzzing:** Intruder із confirmation, локальні словники,
   timeout, budget і Project scope.
3. **OAST/self-hosted adapter:** local loopback contract уже реалізовано;
   наступний крок — сумісність із self-hosted Interactsh API та окремі
   DNS/HTTPS/SMTP provider fixtures. Public endpoint не є default.
4. **Race/Last-Byte node:** окремий node type з обмеженням burst, cancel,
   fixed TLS verification і ручним запуском; не вбудовувати його в звичайний
   Repeater без окремого modal.
5. **Community templates:** server-backed validation і підписи manifests перед
   імпортом.

## Безпечний контракт OAST у DAG

Щоб payload можна було передати в Intruder/Target **до** появи callback,
OAST flow не повинен блокувати весь граф на register. Для наступної ітерації
використовується дві фази:

```text
OAST Listener (start) -> payload_url + listener_id
    -> Intruder / Target / Repeater з payload_url
    -> OAST Collect (wait) -> events / correlation evidence
```

`start` реєструє fixture/self-hosted session і повертає URL майже миттєво.
`wait` має окремий timeout, cancellation і read-only polling. Якщо callback не
прийшов, workflow завершується `completed` з `triggered: false`, а не
підміняє результат success-подібним event. Public Interactsh, fixed token і
відкритий outbound callback не є defaults; перший fixture є local loopback.

## Bounded Repeater Burst

`Repeater Burst` — окремий confirmation-gated node для small parallel review:

```text
Manual Trigger -> Repeater Burst -> Comparer -> Output
```

Django перевіряє точний Project origin (scheme, host і port) і запускає
bounded job у Go через `POST /proxy/repeater-burst`; loopback fixture допускається
лише якщо він явно збережений у Project і підтверджений оператором, без
implicit request-only target. Далі використовує
`GET /proxy/repeater-burst/<id>`, а cancellation викликає `DELETE`. Дозволені
лише read-only методи `GET`, `HEAD`, `OPTIONS`; межі job — `iterations <= 20`,
`concurrency <= 4`, `delay_ms <= 5000`, `timeout_ms` від `1000` до `15000`.
Go не виконує redirect, не робить окремий source-IP lookup для кожної
iteration, не повторює запити і зберігає TLS verification. Відповідь обмежена
1 MiB, а aggregate результат — 8 MiB; truncation позначається в результаті.
Кожен успішний exchange записується у History; snapshot містить `status`,
`total`, `completed`, `failed` і впорядковані `results`.

Node є manual-only: schedule/webhook triggers заборонені, а active workflow
потребує explicit confirmation. Це orchestration contract, а не raw
Last-Byte TCP/TLS attack; режим raw burst залишається experimental і не має
default execution path.
