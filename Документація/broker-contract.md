# Контракт брокера Django ↔ Go Engine

Цей документ визначає версіонований формат повідомлень між Django/Celery та
Go Engine. Він не змінює наявні HTTP API й не переносить виконання на чергу:
поточні шляхи залишаються чинними, доки producer, consumer та result handler
не пройдуть окремі інтеграційні перевірки.

## Транспорт: Redis

Redis — єдиний брокер. Транспорт не обирається: `CELERY_BROKER_URL` і
`ENGINE_BROKER_URL` мають бути `redis://`, `rediss://` або `unix://`, а будь-яка
інша схема падає з помилкою, що називає заміну. Тиша була б найгіршим станом
для черги: engine з чужим URL виглядав би здоровим, не споживаючи нічого.

| Роль | Реалізація | Команди |
|---|---|---|
| Django publish | власний RESP-клієнт (`lab/broker_transport.py`) | `LPUSH` |
| Django result consumer | власний RESP-клієнт | `BLMOVE`, `LREM`, `LMOVE`, `INFO` |
| Go consumer | `go-redis v9` (`engine/redis_consumer.go`) | `BLMOVE`, `LPUSH`, `LREM`, `LMOVE`, `SET`/`GET` |

Повідомлення — **байт у байт** JSON із `contracts/engine-task-v1.json` і
`contracts/engine-result-v1.json`. Kombu на Redis обгортає повідомлення власним
envelope (base64-тіло, headers, properties, delivery tag) і тримає unacked-стан у
власних ключах, тому транспорт свідомо не йде через kombu: інакше Go залежав би
від фреймінгу чужого проєкту. Celery при цьому лишається на kombu — йому
`redis`-пакет потрібен, engine-транспорту ні.

Жодна з черг не має обмежень розміру. Назви: `rr.engine.tasks.v1` (Django → Go)
та `rr.engine.results.v1` (Go → Django); додаткові списки —
`rr.engine.*.inflight` і `rr.engine.*.dead`.

### Надійність

Redis не має підтвердження публікації, але має атомарні блокуючі переміщення, тому
надійність виражена явно:

- повідомлення забирається одним `BLMOVE <queue> <queue>.inflight RIGHT LEFT`,
  тобто воно одразу переходить у «в роботі», і обрив між pop та ack не втрачає
  його;
- `ack` вилучає його з `.inflight`, `requeue` повертає в голову черги, `reject`
  переносить у `<queue>.dead`, тож некоректне повідомлення лишається доказом, а
  не зникає;
- на старті consumer повертає все, що залишилося в `.inflight`, у чергу — це
  відновлення роботи процесу, померлого під час обробки;
- результат, який engine уже віддав, зберігається в broker
  (`rr.engine.outcome.<task_id>`, TTL `ENGINE_BROKER_OUTCOME_TTL`, типово 1 год,
  `0` вимикає), тому перезапущений engine не виконує той самий зовнішній запит
  удруге, а відтворює записаний результат разом із його `event_id`.

Django result consumer перевіряє `INFO server` на старті й відмовляється
запускатися на сервері нижче 6.2, називаючи його версію: без блокуючого
переміщення обрив між читанням і commit втрачає повідомлення, а помилка
«unknown command» прийшла б усередині доставки. Сервер, який приховує `INFO`,
не відкидається.

## Власність черг

- Черга Celery належить Python-задачам, яким потрібні Django ORM, scheduler та
  подальша orchestration; `lab.publish_engine_task` публікує вже збережену
  задачу до Go через власний RESP-клієнт.
- `rr.engine.tasks.v1` призначена для команд Go Engine; Go не запускається як
  Celery worker і не читає внутрішній протокол Celery.
- `rr.engine.results.v1` призначена для результатів Go, які Django
  персистить перед ack через `consume_engine_results`. `EngineTask` зберігає
  кореляцію й останній стан, а `EngineTaskEvent` — дедуплікаційний журнал
  результатів за `event_id`.
- Черги мають бути durable (Compose вмикає AOF); message delivery —
  at-least-once. Дублікати очікувані й обробляються ідемпотентно за `task_id`
  та `event_id`.

## Команда Engine

Приклад: [engine-task-v1.json](../contracts/engine-task-v1.json).

| Поле | Тип | Вимога |
|---|---|---|
| `schema_version` | integer | Рівно `1` |
| `task_id` | UUID string | Ідемпотентний ID логічної задачі |
| `task_type` | string | Нижній регістр; наприклад `target.crawl` |
| `workflow_run_id` | positive integer | Опційне посилання на `WorkflowRun` |
| `workflow_node_id` | string | Опційне ID вузла графа |
| `project_id` | positive integer | Опційне посилання на `Project` |
| `route_generation` | non-negative integer | Опційний generation для збереження route barrier |
| `created_at` | RFC 3339 string | Час створення з timezone |
| `payload` | object | Параметри конкретного типу задачі |

`task_type` визначає версіонований handler і shape `payload`; невідомий тип не
можна перетворювати на успішний результат. Секрети не включаються до логів.
Поточний Go consumer реалізує `request.execute` і `target.crawl`; інші типи
завершуються явною помилкою `UNSUPPORTED_TASK_TYPE`. Внутрішній тип
`engine.task.cancel` приймає `payload.task_id` і скасовує активну задачу того
самого Go consumer process. Django може broker-dispatch static Target і
Repeater workflow nodes лише за `WORKFLOW_ENGINE_BROKER_ENABLED=1`; browser
Target та інші вузли лишаються на наявному шляху.

## Подія результату

Приклад завершення: [engine-result-v1.json](../contracts/engine-result-v1.json).

| Поле | Тип | Вимога |
|---|---|---|
| `schema_version` | integer | Рівно `1` |
| `task_id` | UUID string | Має відповідати команді |
| `event_id` | UUID string | Унікальний ID події для дедуплікації |
| `state` | string | `accepted`, `progress`, `completed`, `failed` або `cancelled` |
| `occurred_at` | RFC 3339 string | Час створення події з timezone |
| `progress` | object | Опційний поточний стан виконання |
| `result` | object | Обов’язковий лише для `completed` |
| `error` | object | Для `failed`: `code`, `message`, `retryable` |

`accepted` і `progress` не є термінальними та не містять `result`/`error`.
`completed` не містить `error`; `failed` не містить `result` і має явну
помилку; `cancelled` не містить ані результату, ані помилки.

## Delivery та відновлення

1. Producer фіксує task correlation у Django до publish, публікує persistent
   JSON і підтверджує publish broker-ом.
2. Go перевіряє schema/version/type, виконує лише зареєстрований handler і
   публікує відповідну event у durable result queue.
3. Go ack-ить task після підтвердження publish результату; transient broker
   failure лишає task доступною для повторної доставки. Повторна delivery
   використовує terminal outcome, який живе в самому broker, тому він переживає
   restart engine: зовнішня дія не виконується вдруге, а відтворюється записана
   відповідь разом із її `event_id`. Crash між зовнішнім side effect і записом
   outcome все ще може повторити дію — це межа at-least-once, а не гарантія
   exactly-once.
4. Django перевіряє `task_id`/`event_id`, атомарно записує event і оновлює
   workflow state; лише після commit надсилає ack.
5. Duplicate event не повторює побічні ефекти; malformed/unsupported payload
   переходить у явний terminal error із причиною, а не в success-shaped
   fallback.
6. Connection loss не скасовує задачу; process shutdown припиняє приймання,
   завершує/відкладає поточну delivery за protocol semantics і закриває канал.

Спільні fixture та валідатори: [contracts/](../contracts/),
[engine_task_contract.py](../web/lab/engine_task_contract.py) і
[taskcontract](../engine/pkg/taskcontract/contract.go).

## Стан інтеграції

Redis — єдиний брокер: у Compose сервіс `redis` з AOF, залежність
`github.com/redis/go-redis/v9` з боку Go і `redis` з боку Python (останній
потрібен лише Celery). Celery app/task publisher, PostgreSQL-моделі стану,
Django result consumer і Go consumer через `ENGINE_BROKER_URL` реалізовані. Go надсилає `accepted` перед запуском і terminal
result перед ack; route generation передається до engine handler, а cancellation
надсилається окремою task-командою. Broker dispatch static Target і Repeater
workflow nodes є opt-in; інші nodes лишаються на HTTP-шляху.

Живий lifecycle перевірено end-to-end — Django → Celery → Redis → Go → Redis →
Django persistence — сценаріями success, idempotent redelivery, error, restart
recovery, cancel і malformed (dead-letter).

Delivery лишається at-least-once; межа — crash між зовнішнім side effect і
записом outcome.
Workflow graph checkpoint/recovery після рестарту процесу реалізовані частково:
queued/running відновлюються між завершеними вузлами, невизначені checkpoint-и
переводяться в `interrupted`.
