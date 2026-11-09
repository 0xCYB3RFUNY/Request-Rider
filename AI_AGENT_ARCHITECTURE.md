# Архітектура Автономного AI Агента Request-Rider (MCP & ReAct Engine)

> Документ визначає архітектуру, протоколи та специфікацію інструментів для автономного AI-агента в Request-Rider.
> Мова документації: Українська (згідно з [AGENTS.md](AGENTS.md)).

---

## 1. Загальне бачення

Замість написання закритого пропрієтарного рушія, автономний агент Request-Rider базується на перевірених відкритих стандартах:
1. **MCP (Model Context Protocol)** / **OpenAI Tool Calling standard** — для визначення та виклику інструментів.
2. **ReAct Loop (Reasoning + Acting)** — цикл прийняття рішень моделлю з обробкою результатів ітерацій.
3. **Human-in-the-Loop** — захисний бар'єр підтвердження оператором критичних та деструктивних дій.

Агент працює як всередині веб-інтерфейсу Request-Rider, так і може експортувати свої інструменти зовнішнім сумісним клієнтам (Claude Desktop, Cursor, OpenCode, Goose) за стандартом MCP.

---

## 2. Загальна діаграма потоків

```text
┌─────────────────────────────────────────────────────────────┐
│                 Веб-інтерфейс Request-Rider                 │
│  - Інтерактивний чат (вкладка AI)                           │
│  - Стрімінг кроків (Dumping Thought -> Action -> Result)    │
│  - Картки згоди оператора для деструктивних атак            │
└──────────────────────────────▲──────────────────────────────┘
                               │ Event-Stream / JSON
┌──────────────────────────────▼──────────────────────────────┐
│           ReAct Agent Runner (web/lab/agent_loop.py)        │
│                                                             │
│   1. Формування контексту (History, Traffic, Project state) │
│   2. Підключення схем інструментів (tools schema)           │
│   3. Запит до LLM (OpenAI / Claude / Ollama / OpenRouter)   │
│   4. Якщо виявлено tool_call:                               │
│      - Перевірка безпеки / дозволу                          │
│      - Виклик відповідного tool із реєстру                  │
│      - Отримання спостереження (Observation)                │
│      - Наступна ітерація циклу                              │
│   5. Формування фінального висновку оператору               │
└──────────────────────────────▲──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│       Request-Rider Tool Registry (web/lab/agent_tools.py)   │
│                                                             │
│  - request_send: надсилання HTTP через рушій проксі         │
│  - history_search: повнотекстовий пошук перехоплених запитів│
│  - intruder_fuzz: запуск атак підбору та фазингу            │
│  - osint_lookup: розвідка доменів, піддоменів і портів      │
│  - finding_record: фіксація вразливості в Project Hub       │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Реєстр інструментів (Tool Registry Specification)

Кожен інструмент описується стандартизованою схемою JSON Schema.

### 3.1. `request_send`
* **Призначення:** Відправка сирого HTTP-запиту через рушій Request-Rider із підтримкою проксі.
* **Параметри:**
  - `raw_request` (string, required): Повний сирий HTTP-запит (метод, шлях, заголовки, тіло).
  - `target_host` (string, required): Цільовий хост/IP.
  - `target_port` (integer, optional, default: 80/443).
  - `use_tls` (boolean, optional, default: true).
  - `proxy` (string, optional): Опціональний апстрім-проксі.
* **Результат:** HTTP статус-код, час відповіді, заголовки та скорочене/повне тіло відповіді.

### 3.2. `history_search`
* **Призначення:** Пошук запитів та відповідей у базі історії трафіку проекту.
* **Параметри:**
  - `query` (string, optional): Рядок для пошуку в URL, заголовках або тілі.
  - `method` (string, optional): Фільтр за методом (GET, POST, PUT тощо).
  - `status_code` (integer, optional): Фільтр за кодом статусу.
  - `limit` (integer, optional, default: 10, max: 50).
* **Результат:** Список знайдених запитів (ID, URL, метод, статус, розмір, таймстемп).

### 3.3. `intruder_fuzz`
* **Призначення:** Запуск автоматизованого фазингу за списком пейлоадів.
* **Рівень безпеки:** **Requires Approval** (вимагає підтвердження оператора).
* **Параметри:**
  - `template_request` (string, required): Шаблон запиту з маркером `§payload§`.
  - `attack_type` (string, required): `sniper`, `battering_ram`, `pitchfork`.
  - `wordlist` (array of strings, required): Набір перевірочних значень.
* **Результат:** Зведена таблиця відповідей зі змінами в довжині, кодах статусу та аномаліях.

### 3.4. `osint_lookup`
* **Призначення:** Збір пасивної та напівактивної інформації про ціль.
* **Параметри:**
  - `domain` (string, required): Доменне ім'я цілі.
  - `check_subdomains` (boolean, optional, default: true).
  - `check_ports` (boolean, optional, default: false).
* **Результат:** Список виявлених хостів, IP-адрес, відкритих портів та DNS-записів.

### 3.5. `finding_record`
* **Призначення:** Збереження підтвердженої проблеми безпеки у звіті проекту.
* **Параметри:**
  - `title` (string, required): Назва вразливості.
  - `severity` (string, required): `info`, `low`, `medium`, `high`, `critical`.
  - `description` (string, required): Опис проблеми та вектор атаки.
  - `evidence_exchange_id` (string/int, optional): ID запиту-доказу з історії.
  - `remediation` (string, optional): Рекомендація з виправлення.
* **Результат:** ID збереженої знахідки в Project Hub.

---

## 4. Захисні бар'єри (Guardrails)

1. **Max Iteration Limit:** Не більше 6 ітерацій (Tool Calling turns) на один запит оператора, щоб уникнути нескінченних циклів або надмірних витрат токенів.
2. **Action Classification:**
   - **Safe (Read-Only):** `history_search`, `finding_record`, `osint_lookup` (пасивний). Виконуються автоматично.
   - **Sensitive (Active/Fuzzing):** `request_send` (якщо змінює стан), `intruder_fuzz`. Повертають статус `AWAITING_APPROVAL` у UI з відображенням деталей запиту перед фактичним виконанням.
3. **Data Redaction:** Будь-які чутливі маркери (Cookie сесії, токени Authorization, внутрішні ключі) проходять маскування перед передачею стороннім провайдерам LLM.

---

## 5. Повний спектр інструментів агента (All Tools Coverage)

Станом на листопад 2026 року агент Request-Rider підтримує **повне охоплення всіх 15 воркспейсів та функціональних модулів проєкту**:

### 5.1. Реєстр вбудованого агента (`web/lab/agent_tools.py` — 71 інструмент):
1. **Базові інструменти ReAct (Legacy & Core):**
   - `request_send`, `history_search`, `intruder_fuzz`, `osint_lookup`, `finding_record`.
2. **P1 Паритетні інструменти (`agent_tools_p1.py` — 26 інструментів):**
   - **Platform & Project:** `platform_status`, `project_list`, `project_create`, `project_switch_active`, `project_get_knowledge_hub`.
   - **Proxy & History:** `history_get_records`, `history_get_transaction_raw`, `kebab_send_to_tool`.
   - **Target & Sitemap:** `target_get_sitemap`, `target_run_crawl`.
   - **Repeater:** `repeater_send_raw_http`, `repeater_burst_test`, `repeater_last_byte_sync`.
   - **Intruder:** `intruder_start_attack`, `intruder_get_attack_results`.
   - **Scanner:** `scanner_cms_recon`, `scanner_active_start`, `scanner_job_status`, `scanner_get_findings`.
   - **Transform & OSINT:** `data_transform`, `osint_transform_list`, `osint_run_transform`.
   - **OOB / OAST:** `oob_generate`, `oob_poll`.
   - **Reports & Harness:** `report_ingest`, `harness2_status`, `harness2_run_demo`, `harness_pipeline_info`.
3. **Розширені інструменти (`agent_tools_ext.py` — 31 інструмент):**
   - **Projects Extended:** `project_update`, `project_delete`, `project_export`, `project_import`, `project_fusion_report`.
   - **Traffic Control:** `traffic_control`, `traffic_capture_contexts`.
   - **History Manage:** `history_record_action`, `history_export_records`.
   - **Target Extended:** `target_job_action`, `target_js_analyze`, `target_bypass_403`.
   - **Repeater Extended:** `repeater_burst_status`, `repeater_burst_cancel`, `repeater_last_byte_status`, `repeater_last_byte_cancel`.
   - **Intruder Extended:** `intruder_action`, `intruder_saved_attacks`.
   - **Scanner Extended:** `scanner_active_action`, `scanner_corpus_stats`, `scanner_corpus_start`, `scanner_corpus_action`, `scanner_report_generate`.
   - **OSINT Extended:** `osint_recon_action`, `osint_graph_manage`, `osint_job_action`, `osint_file_manage`.
   - **OAST Extended:** `oast_listener_manage`.
   - **Workflows (DAG):** `workflow_catalog`, `workflow_manage`, `workflow_execute`.
   - **Route & DNS:** `route_manage`, `route_check`, `dns_manage`.

### 5.2. FastMCP Сервер (`request-rider-mcp/server.py` — 62 інструменти):
Експортує повну множину інструментів для зовнішніх агентів (Claude Desktop, Cursor, OpenCode runtime, Google Harness 2) та інтегрує бібліотеку з 550+ скілів через `skills_list` і `skills_read`.

---

## 6. Дорожня карта впровадження (Статус реалізації)

- [x] **Етап 1: Опис схем та обробників інструментів (`web/lab/agent_tools.py`, `agent_tools_p1.py`, `agent_tools_ext.py`)** — ЗАВЕРШЕНО (71 інструмент).
- [x] **Етап 2: ReAct Runner (`web/lab/agent_loop.py`)** — ЗАВЕРШЕНО (цикл із системним промптом, валідацією схем та Guardrails).
- [x] **Етап 3: API ендпоінти (`POST /lab/agent/run`, `/lab/agent/approve`)** — ЗАВЕРШЕНО.
- [x] **Етап 4: FastMCP Сервер (`request-rider-mcp/server.py`)** — ЗАВЕРШЕНО (62 інструменти, 550+ скілів, повний паритет).
- [x] **Етап 5: Повний набір юніт-тестів та верифікація Agent Harness** — ЗАВЕРШЕНО (28 тестів Django, 95 тестів MCP, Harness runner verify PASS).
