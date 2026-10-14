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

## 5. Дорожня карта впровадження (Етапи)

- [ ] **Етап 1: Опис схем та обробників інструментів (`web/lab/agent_tools.py`)**.
  Реалізація Python-функцій для виконання `history_search`, `request_send`, `finding_record`.
- [ ] **Етап 2: ReAct Runner (`web/lab/agent_loop.py`)**.
  Побудова циклу автономної взаємодії з моделлю з обробкою `tool_calls` та поверненням структурних кроків.
- [ ] **Етап 3: API ендпоінт (`POST /api/agent/run`)**.
  Ендпоінт для запуску циклу з можливістю передачі схвалення дій (`POST /api/agent/approve`).
- [ ] **Етап 4: Оновлення UI вкладки AI**.
  Відображення ланцюжка дій (Thought -> Action -> Result) та інтерактивних карток підтвердження в чаті.
- [ ] **Етап 5: Експорт MCP Server**.
  Можливість підключення зовнішніх агентів (Claude Desktop, OpenCode тощо) до Request-Rider через MCP endpoint.
