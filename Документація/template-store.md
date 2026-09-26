# Template Store Automation

> Станом на 2026-09-25 жорсткі application-level ceilings у шаблонах та
> execution engine прибрано. Параметри `iterations`, `concurrency`, timeout,
> `max_pages` і `max_depth` є явними полями шаблону, а не прихованими cap.
> Детальний перелік — у [звіті про видалені обмеження](видалені-обмеження.md).
> Target-шаблони за замовчуванням використовують `max_pages=0` і
> `max_depth=-1` (необмежені sentinels).

## Поточний MVP

Template Store — локальний каталог готових workflow-шаблонів у вкладці
Automation. Він не виконує вузли автоматично: картка показує структуру,
змінні, ризик і preview, а імпортує граф у окремий Automation workspace.

Каталог доступний через:

```text
GET /api/workflow-templates
```

Відповідь має форму:

```json
{
  "items": [
    {
      "template_id": "logic-baseline",
      "version": "1.0.0",
      "meta": {
        "category": "compliance_devsecops",
        "risk_level": "info",
        "execution": "passive",
        "requires_confirmation": false
      },
      "required_variables": [],
      "workflow": {
        "nodes": [],
        "connections": []
      }
    }
  ]
}
```

## UX

1. Натиснути `Templates` у toolbar Automation.
2. Вибрати категорію або знайти шаблон за назвою, описом, тегом, типом вузла.
3. Відкрити `Preview` і перевірити mini-graph та risk badge.
4. Заповнити required variables, наприклад `Target URL`.
5. Для active/browser шаблонів підтвердити попередній запуск і перевірити параметри шаблону перед імпортом.
6. Натиснути `Import` — створюється новий локальний Automation workspace,
   який ще не записується в Django SQLite.
7. Оператор перевіряє canvas і окремо натискає `Save` та `Run`.

## Категорії

- `recon_asset_discovery` — Target, OSINT, JavaScript asset inventory, debug surface
  check, perimeter inventory, browser evidence;
- `api_microservices` — Repeater, API status triage, headers baseline, schema
  endpoint discovery;
- `fuzzing_injection` — Intruder із confirmation;
- `ai_llm_security` — evidence → AI triage;
- `compliance_devsecops` — baseline, response diff, scheduled read-only scan;
- `oast_security` — local OAST start → payload callback → collect;
- `business_logic` — BOLA/IDOR differential, race observation та
  parallel request review;
- `auth_sessions` — synthetic JWT claim differential без реальних токенів.

Постачальник каталогу — `web/lab/workflow_templates.py`. Django віддає
після копіювання manifests, тому browser не може змінити серверний registry
через випадковий mutable object.

## Безпечний пакет read-only playbooks

У поточній версії додано шість baseline-шаблонів, які використовують лише
manual trigger, Repeater, Target, OSINT, Scanner, Decoder, AI Agent та Output:

- `Read-only API headers baseline`;
- `JavaScript asset inventory`;
- `Read-only debug surface check`;
- `Schema endpoint discovery`;
- `Perimeter asset inventory`;
- `Request evidence to AI triage`.

Вони не містять Intruder, browser actions, OAST, raw sockets чи Last-Byte
sync. Debug/API paths перевіряються лише read-only GET запитами; AI залишається
advisory-only. Для імпорту всі нові шаблони вимагають явного повторного перегляду
параметрів перед запуском, а фактичний запуск workflow залишається
окремою операторською дією.

## Manual-only high-risk canary package

Каталог також містить сім окремих high-risk manifest templates. Вони не є
інструментами для реального exploit і не містять credentials, destructive
commands або automatic external execution:

- `Last-Byte Sync timing review` — real raw HTTP/1.1 loopback fixture із
  explicit final-byte hold; зовнішній target не блокується application policy
  gate;
- `BOLA/IDOR differential evidence` — два authorized GET records і comparer;
- `Race-condition timing observation` — parallel GET timing evidence;
- `WAF rule differential` — baseline/canary header differential без bypass payload;
- `JWT claim mutation differential` — synthetic unsigned `alg:none` claims;
- `XXE/OAST local canary chain` — XML entity лише через local OAST provider;
- `CI/CD exposure review` — read-only перевірка стандартних manifest paths.

Усі seven templates мають `execution: active`, `requires_confirmation: true` і
manual-only trigger. Django marker `__requires_confirmation` зберігається у
графі, тому UI run confirmation не залежить лише від типу ноди. E2E проганяє
кожен manifest через Firefox, локальні fixtures, явне review-before-run,
реальний Django → Go lifecycle і cleanup. Для XXE callback дозволено лише
loopback URL,
а JWT/IDOR/WAF payloads не містять реальних токенів або обходу authorization.

## Безпека

- Import ніколи не виконує workflow і не активує його.
- `active`, webhook/slug, project ID та runs не переносяться із manifest.
- Активні шаблони зберігають `requires_confirmation` і не обходять
  узгоджений review flow перед запуском.
- Каталог не містить public OAST endpoint, fixed credentials або автоматичного
  Last-Byte burst.
- User-created templates зберігаються окремо в browser-local
  `requestrider-workflow-templates-v1`; секретні ключі параметрів redact-яться
  перед локальним збереженням. Це не SQLite-реєстр і не спільний community store.
- Наступна ітерація може додати server-backed CRUD/import community registry,
  не змішуючи його з workspace snapshots.

## Перевірка

```bash
python manage.py test lab.test_workflows -v 1
browser-worker/.venv/bin/python agent-workspace/tests/e2e/test_automation_ui.py -k template_store
```

E2E перевіряє пошук, category filter, preview, active-template confirmation,
import у новий canvas, відсутність DB workflow до `Save` та запуск імпортованого
графа після явного збереження.
