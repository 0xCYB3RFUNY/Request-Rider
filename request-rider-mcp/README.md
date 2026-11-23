# Request-Rider Model Context Protocol (MCP) Server

Повноцінний автономний MCP-сервер для двостороннього підключення платформи **Request-Rider** та її каталогу інженерних навичок тестування до сучасних агентських середовищ та IDE:
- **Antigravity IDE**
- **Claude Desktop**
- **Cursor IDE**
- **Windsurf / Codex**
- **OpenCode**
- **VS Code (Cline / Roo Code / Continue)**

Сервер працює через стандартний протокол **MCP (JSON-RPC 2.0 over stdio)**, надає прямий доступ до **79 інструментів аудиту безпеки** (повне покриття 15 воркспейсів, усіх сканерів, налаштувань та Live Browser View платформи) та каталогу з понад **550+ відібраних технічних навичок** (тестування, безпека, рекон, розробка, фазинг, DevSecOps).

---

## 📋 Зміст

1. [Вимоги та архітектура](#-вимоги-та-архітектура)
2. [Покрокова інструкція зі встановлення та підключення](#-покрокова-інструкція-зі-встановлення-та-підключення)
3. [Робота з каталогом технічних навичок (Skills System)](#-робота-з-каталогом-технічних-навичок-skills-system)
4. [Доступні інструменти (79 Tools)](#-доступні-інструменти-79-tools--повний-паритет)
5. [Тестування та перевірка через консоль (CLI Smoke Test)](#-тестування-та-перевірка-через-консоль-cli-smoke-test)
6. [Змінні середовища та конфігурація](#-змінні-середовища-та-конфігурація)
7. [Діагностика та усунення несправностей (Troubleshooting)](#-діагностика-та-усунення-несправностей-troubleshooting)

---

## 🏗️ Трирівнева архітектура виконання агентів

У проєкті реалізовано інтегровану трирівневу модель агентського середовища:

```
[1. Базовий шар (Основа)] : Request-Rider MCP (інструменти перехоплення, проксі, сканування, OSINT, OOB)
         ↓
[2. Шар гартування]       : Request-Rider Harness (Action Space, Observation Contract, Scope Guard)
                            + Google Research Harness² (рекурсивне Propose-Probe-Compose гартування)
         ↓
[3. Арсенал експертизи]   : 550+ технічних скілів (.agents/skills/*)
```

### Додаткові інструменти гартування (Group 7):
- `harness2_status`: Перевірка статусу оточення Google Research Harness², версії та 8 компонентів.
- `harness2_run_demo`: Запуск детермінованого циклу рекурсивного гартування (Propose-Probe-Compose) без викликів зовнішніх моделей.
- `harness_pipeline_info`: Огляд топології та зв'язку між MCP, харнесами та каталогом скілів.

---

## ⚙️ Вимоги та архітектура

- **Python 3.10+** та віртуальне середовище `request-rider-mcp/.venv` із пакетами з `requirements.txt` (`mcp[cli]>=1.2.0` (`MCPServer`) та `httpx>=0.27.0` для високошвидкісного асинхронного HTTP-клієнта зі збереженням cookie-сесій активного проєкту).
- **Запущений стенд Request-Rider**:
  - Django шлюз: `http://127.0.0.1:8000`
  - Go engine: `http://127.0.0.1:8081`
- **Каталог навичок**:
  - Каталог `skills/` всередині папки сервера або `.agents/skills/` у корені проєкту Request-Rider (546+ перевірених і структурованих методологій).

---

## 🚀 Покрокова інструкція зі встановлення та підключення

### 1. Підключення до Claude Desktop

1. Відкрийте файл конфігурації Claude Desktop для вашої операційної системи:
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

2. Додайте секцію `request-rider` у блок `mcpServers`:

```json
{
  "mcpServers": {
    "request-rider": {
      "command": "/usr/bin/python3",
      "args": [
        "/home/kali/Desktop/DevBackUp-29.10/request-rider-mcp/server.py"
      ],
      "env": {
        "REQUEST_RIDER_URL": "http://127.0.0.1:8000"
      }
    }
  }
}
```

> **Примітка**: Замініть `/usr/bin/python3` та шлях до `server.py` на актуальні абсолютні шляхи у вашій системі.

3. Повністю перезапустіть Claude Desktop. У діалоговому вікні з'явиться іконка молотка 🔨 з 62 інструментами Request-Rider.

---

### 2. Підключення до Antigravity IDE

1. У робочій директорії або конфігурації агента (`~/.gemini/antigravity-ide/` або `.agents/`) перевірте наявність секції MCP.
2. Додайте конфігурацію сервера в `mcp_config.json`:

```json
{
  "mcpServers": {
    "request-rider-mcp": {
      "command": "python3",
      "args": [
        "/home/kali/Downloads/Request-Rider v1.2/request-rider-mcp/server.py"
      ],
      "env": {
        "REQUEST_RIDER_URL": "http://127.0.0.1:8000"
      }
    }
  }
}
```

3. Інструменти та скіли стануть доступними моделі безпосередньо через агентські виклики `request_rider_*`.

---

### 3. Підключення до Cursor IDE

1. Відкрийте **Cursor Settings** (`Ctrl + Shift + J` або `Cmd + Shift + J`).
2. Перейдіть у розділ **Features** → **MCP**.
3. Натисніть кнопку **+ Add New MCP Server**.
4. Заповніть поля:
   - **Name**: `request-rider`
   - **Type**: `command`
   - **Command**: `python3 "/home/kali/Desktop/DevBackUp-29.10/request-rider-mcp/server.py"`
5. Натисніть **Save**. Індикатор стану має стати зеленим (`Connected`).

---

### 4. Підключення до Windsurf

1. Відкрийте файл конфігурації MCP у домашній директорії:
   - `~/.codeium/windsurf/mcp_config.json`
2. Додайте сервер:

```json
{
  "mcpServers": {
    "request-rider": {
      "command": "python3",
      "args": [
        "/home/kali/Desktop/DevBackUp-29.10/request-rider-mcp/server.py"
      ],
      "env": {
        "REQUEST_RIDER_URL": "http://127.0.0.1:8000"
      }
    }
  }
}
```
3. Перезапустіть Windsurf Cascade.

---

### 5. Підключення до VS Code (Cline / Roo Code / Continue)

1. Відкрийте налаштування розширення Cline або Roo Code у VS Code.
2. Перейдіть до **MCP Servers** → **Edit MCP Settings** (`cline_mcp_settings.json`).
3. Вставте конфігурацію:

```json
{
  "mcpServers": {
    "request-rider": {
      "command": "python3",
      "args": [
        "/home/kali/Desktop/DevBackUp-29.10/request-rider-mcp/server.py"
      ],
      "env": {
        "REQUEST_RIDER_URL": "http://127.0.0.1:8000"
      },
      "disabled": false,
      "autoApprove": [
        "request_rider_status",
        "request_rider_skills_list",
        "request_rider_skills_read",
        "request_rider_url_encode",
        "request_rider_url_decode"
      ]
    }
  }
}
```

---

### 6. Підключення до OpenCode

У конфігураційному файлі агента OpenCode додайте блок запуску процесу stdio:

```json
{
  "mcp": {
    "servers": {
      "request_rider": {
        "type": "stdio",
        "command": "python3",
        "args": ["/home/kali/Desktop/DevBackUp-29.10/request-rider-mcp/server.py"],
        "env": {
          "REQUEST_RIDER_URL": "http://127.0.0.1:8000"
        }
      }
    }
  }
}
```

---

## 🧠 Робота з каталогом технічних навичок (Skills System)

Сервер містить вбудовану базу з **546 відібраних технічних навичок** безпеки, тестування та програмування. Усі сторонні нерелевантні навички (маркетинг, продажі, HR, менеджмент) повністю відсіяні.

### Категорії навичок:
1. **Безпека та пентест**: `burp-suite`, `burpsuite-expert`, `cloud-pentest`, `red-team`, `semgrep`, `codeql`, `yara-rule-authoring`, `llm-redteam`, `smart-contracts` (Solidity, EVM, Solana), `osint-investigation`, `reverse-engineering`.
2. **Тестування та QA**: `api-test-suite-builder`, `playwright-cli`, `playwright-pro`, `cargo-fuzz`, `libfuzzer`, `ossfuzz`, `atheris`, `aflpp`, `property-based-testing`, `mutation-testing`, `address-sanitizer`.
3. **Програмування та архітектура**: `golang-patterns`, `golang-testing`, `modern-python`, `python-patterns`, `rust-patterns`, `cpp-testing`, `django-patterns`, `fastapi-patterns`, `springboot-patterns`, `react-patterns`, `vue-patterns`.
4. **DevSecOps та інфраструктура**: `docker-development`, `kubernetes-patterns`, `terraform-patterns`, `database-designer`, `postgres-patterns`, `ci-cd-pipeline-builder`.
5. **Агентні інструменти Request-Rider**: `request-rider-harness`, `mcp-server-audit`, `zero-hallucination-coder`.

### Як агент використовує навички:

1. **Пошук скілів за категорією**:
   ```json
   {
     "name": "request_rider_skills_list",
     "arguments": {
       "category": "fuzz"
     }
   }
   ```
   *Відповідь містить перелік точних скілів: `cargo-fuzz`, `fuzzing-dictionary`, `fuzzing-obstacles`, `libfuzzer`, `ossfuzz`.*

2. **Зчитування покрокової інструкції**:
   ```json
   {
     "name": "request_rider_skills_read",
     "arguments": {
       "name": "burp-suite"
     }
   }
   ```
   *Повертає повний Markdown-документ `SKILL.md` з методологією тестування, командами та кращими практиками.*

---

## 🛠️ Доступні інструменти (79 Tools — Повний паритет)

Сервер надає 79 інструментів, розділених на 9 взаємопов'язаних груп:

### Група 1: Платформа та Проєкти (Core & Projects)
- `platform_status`: Перевірка стану Django шлюзу та Go рушія.
- `project_list`, `project_create`, `project_switch_active`, `project_get_knowledge_hub`.
- `project_update`, `project_delete`, `project_export`, `project_import`, `project_fusion_report`, `project_hub_task_action`.
- `project_hosts_manage`, `project_snapshots_manage`, `project_metasploit_import`, `project_events_status`.

### Група 2: Проксі, Трафік та Історія (Proxy & History)
- `history_get_records`, `history_get_transaction_raw`.
- `history_manage` (позначки, теги, видалення, масове видалення, експорт, імпорт).
- `traffic_control` (перемикання стану перехоплення), `traffic_capture_contexts`.
- `kebab_send_to_tool` (контекстна передача транзакцій у Repeater, Intruder, Scanner, Decoder).

### Група 3: Карта цілі, Краулер та Live Browser Control (Target & Sitemap)
- `target_get_sitemap`, `target_run_crawl` (з підтримкою `browser_mode`, `live_view`, `cookies`, `custom_headers`, `capture_context_id`, `extra_options`).
- `target_browser_live` (живі кадри viewport та телеметрія дій браузерного краулера).
- `target_browser_control` (ручне керування вкладкою: `take_control`, `release_control`, `click`, `drag`, `wheel`, `type`, `key`, `reload`, `back`).
- `target_job_action` (скасування та опитування фонових завдань краулера).
- `target_browsers_list` (список підтримуваних браузерів: `firefox`, `chromium`, `webkit`).
- `target_js_analyze` (витяг ендпоінтів, DOM-sink та секретів із JS-файлів цілі).
- `bypass_forms_list` (список форм і технік для 403 Bypass).

### Група 4: Повторювач, Автентифікація, JWT та PoC (Repeater & Auth)
- `repeater_send_raw_http` (відправка запиту через рушій).
- `repeater_burst_test` (паралельний пакетний запуск запитів для тестування race condition).
- `repeater_last_byte_sync` (синхронізація відправки останнього байта за стандартом HTTP/1.1 і HTTP/2).
- `repeater_burst_status`, `repeater_last_byte_status`.
- `auth_profiles_manage` (CRUD профілів автентифікації для Auth Matrix та сканування).
- `repeater_auth_matrix` (матрична перевірка прав доступу / IDOR по ролях).
- `jwt_manage` (інспекція контексту та формування/підпис JWT-токенів).
- `poc_generate` (генерація PoC-експлойтів у форматах curl / Python / HTML).

### Група 5: Фазер (Intruder)
- `intruder_start_attack`, `intruder_get_attack_results`.
- `intruder_attack_action` (пауза, відновлення, скасування атаки).
- `intruder_saved_attacks` (список та запуск збережених конфігурацій атак).

### Група 6: Сканери вразливостей (Active, OpenVAS/GVM, Nuclei, Corpus)
- `scanner_cms_recon` (розвідка CMS та технологічного стеку цілі).
- `scanner_active_start` (з профілями `full`, `fast`, `api`, `llm`, `stealth`, `failure_pause`, `project_id`), `scanner_job_status`, `scanner_get_findings`, `scanner_active_action`.
- `scanner_preset` (збереження/завантаження/редагування/видалення пресетів з усіма 11 Advanced параметрами: `max_pages`, `max_depth`, `concurrency`, `delay_ms`, `blind_delay_ms`, `timeout_ms`, `failure_pause`, `recorded_failures`, `same_origin`, `follow_redirects`, `params`, `path_wordlist`).
- `scanner_openvas` (повне керування OpenVAS/GVM через GMP: `status`, `options`, `scan`, `poll`, `task_action`, `sync_list`, `sync_import`, `create_port_list`, `create_credential`, `import_xml`).
- `scanner_nuclei` (керування Nuclei та каталогами шаблонів: `dirs`, `inspect`, `upload`, `run_job`, `run_dir_job`, `run_sync`, `run_local`, `run_inline`, `poll`, `pause`, `resume`, `cancel`).
- `scanner_corpus_stats`, `scanner_corpus_start`, `scanner_corpus_action`, `scanner_corpus_run_sync`.
- `scanner_report_generate` (генерація зведеного звіту за проєктом).

### Група 7: OSINT, OAST та Трансформації
- `data_transform` (Base64, URL, Hex, JWT, MD5, SHA256, Gzip тощо).
- `osint_transform_list`, `osint_run_transform`.
- `osint_recon`, `osint_graphs` (включно з `delete_entity` / `delete_relation`), `osint_transform_job`.
- `oob_generate`, `oob_poll`, `oast_listener`.

### Група 8: Автоматизація, Маршрутизація, Звіти та Скіли
- `workflow_catalog`, `workflow_manage` (включно з `export`, `import`, `convert`, `auto_chain`, `preview_template`), `workflow_execute` (включно з `export_run`).
- `route_manage`, `dns_manage` (включно з `tls_fingerprint`).
- `report_ingest`, `agent_run`, `agent_chat`.
- `skills_list`, `skills_read`.
- `harness2_status`, `harness2_run_demo`, `harness_pipeline_info`.

### Група 9: Ланцюжки атак, API-специфікації та Інспектор протоколів
- `attack_chains_manage` (CRUD ланцюжків атак та MITRE-технік).
- `api_spec_import` (імпорт OpenAPI/Swagger, GraphQL, Postman).
- `protocol_inspect` (інспекція та мутація HTTP/2, gRPC, WebSocket, Protobuf).

---

## 🧪 Тестування та перевірка через консоль (CLI Smoke Test)

Швидка перевірка працездатності MCP-сервера напряму через термінал:

### 1. Перевірка списку доступних інструментів:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | request-rider-mcp/.venv/bin/python request-rider-mcp/server.py
```
*У відповіді повинен прийти JSON-RPC об'єкт із масивом 79 інструментів.*

### 2. Перевірка статусу шлюзу:
```bash
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"platform_status","arguments":{}}}' | request-rider-mcp/.venv/bin/python request-rider-mcp/server.py
```

### 3. Перевірка каталогу скілів:
```bash
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"skills_list","arguments":{"category":"security"}}}' | request-rider-mcp/.venv/bin/python request-rider-mcp/server.py
```

---

## 🔧 Змінні середовища та конфігурація

| Змінна | За замовчуванням | Опис |
|---|---|---|
| `REQUEST_RIDER_URL` | `http://127.0.0.1:8000` | Адреса шлюзу Django Request-Rider |
| `REQUEST_RIDER_LOG` | `/tmp/request-rider-mcp.log` | Файл журналу операцій MCP-сервера |
| `POSTGRES_HOST` | `127.0.0.1` | Хост бази даних PostgreSQL (для прямих інструментів знахідок) |
| `POSTGRES_PORT` | `55433` | Порт PostgreSQL стенду Request-Rider |
| `POSTGRES_USER` | `kali` | Користувач бази даних |
| `POSTGRES_DB` | `requestrider` | Назва бази даних |

---

## 🔍 Діагностика та усунення несправностей (Troubleshooting)

### Помилка: `Connection refused` до `127.0.0.1:8000`
- **Причина**: Request-Rider не запущено.
- **Вирішення**: Запустіть стенд командою `./start.sh` у корені проєкту. Перевірте працездатність: `curl -I http://127.0.0.1:8000/`.

### Помилка: `Папка зі скілами не знайдена`
- **Причина**: Некоректний робочий каталог або переміщена папка навичок.
- **Вирішення**: Сервер автоматично шукає скіли у `request-rider-mcp/skills` та `.agents/skills`. Переконайтеся, що один із цих каталогів присутній та містить файли `SKILL.md`.

### Логи порожні або сервер завершується без виводу
- Перевірте файл журналу:
  ```bash
  tail -n 50 /tmp/request-rider-mcp.log
  ```
- Переконайтеся, що права на виконання надано:
  ```bash
  chmod +x request-rider-mcp/server.py
  ```
