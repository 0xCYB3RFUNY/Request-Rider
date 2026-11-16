# Візуалізація та Архітектура Ланцюжка Взаємодії Агента в Request-Rider

Цей документ детально розкриває, як автономний агент (OpenCode, Codex, Claude Code, Antigravity) взаємодіє з інтегрованою екосистемою **Request-Rider**:
1. **Request-Rider MCP** (базове ядро інструментів платформи)
2. **Request-Rider Harness** (детермінований Action Space, Observation Contract, Scope Guard)
3. **Google Research Harness²** (рекурсивне Propose-Probe-Compose гартування та оптимізація оточення)
4. **Арсенал скілів** (553 структуровані інженерні методології)

---

## 1. Загальна Топологія та Потоки Даних

```mermaid
flowchart TD
    subgraph S0["0. Ініціація та Вхід"]
        User["Оператор / Нове Завдання"] --> Agent["Автономний AI Агент (OpenCode / LLM)"]
        Agent --> Preflight["Preflight / Auto-Bootstrap<br/>harness_runner.py verify"]
    end

    subgraph S1["1. Шар Рекурсивного Гартування (Google Research Harness²)"]
        Preflight --> H2["Google Research Harness² Engine"]
        H2 --> Comp["8 Компонентів Оточення:<br/>1. System Prompt<br/>2. Guardrails (Scope)<br/>3. Memory (Ledger)<br/>4. Tool Guidance<br/>5. Subagents<br/>6. Skills Filter<br/>7. Scripts (Tests)<br/>8. Plugins (Middleware)"]
        Comp --> PPC["Propose -> Probe -> Compose Loop"]
    end

    subgraph S2["2. Шар Детермінованого Виконання (Request-Rider Harness)"]
        PPC --> RRH["Request-Rider Agent Harness"]
        RRH --> ActionSpace["Structured Action Space:<br/>• probe<br/>• search-history<br/>• check-scope<br/>• run-tests"]
        RRH --> ObsContract["Deterministic Observation Contract:<br/>{status, summary, details, root_cause_hint, safe_retry_instruction}"]
    end

    subgraph S3["3. Ядро Інструментів Платформи (Request-Rider FastMCP)"]
        RRH --> MCP["Request-Rider MCP Server (:stdio)"]
        MCP --> Pxy["Proxy & Traffic History<br/>(:8000 Gateway, SQLite WAL)"]
        MCP --> Eng["Live MITM Engine & Intruder<br/>(:8081 Go Engine)"]
        MCP --> Scn["Active Scanners & Probes<br/>(Nuclei, Sqlmap, DAST)"]
        MCP --> Wrk["Browser Worker<br/>(:8001 Playwright)"]
        MCP --> OOB["Out-Of-Band Collateral<br/>(DNS/HTTP/SMTP Callbacks)"]
    end

    subgraph S4["4. Арсенал Експертизи (550+ Skills)"]
        MCP --> SkillList["skills_list(category='...')"]
        SkillList --> SkillRead["skills_read(name='burp-suite')"]
        SkillRead --> SkillFS[".agents/skills/* & skills.json"]
    end

    subgraph S5["5. Завершення та Рефлексія"]
        ObsContract --> ScopeVerify["check-scope (AGENTS.md Compliance)"]
        ScopeVerify --> RecordFinding["record-finding -> ScannerRun DB"]
        RecordFinding --> LedgerUpdate["Harness² Experience Ledger Update"]
        LedgerUpdate --> Report["Фінальний Звіт Оператору"]
    end
```

---

## 2. Sequence-Діаграма Повного Життєвого Циклу Завдання

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Оператор / Користувач
    participant Agent as AI Агент (OpenCode)
    participant Boot as Auto-Bootstrap Script
    participant H2 as Google Harness²
    participant RRH as Request-Rider Harness
    participant MCP as Request-Rider MCP Server
    participant Skills as Каталог 550+ Скілів
    participant Platform as Request-Rider Core (Gateway/Engine)

    Operator->>Agent: "Дослідити авторизацію на цільовому вузлі"
    
    rect rgb(240, 248, 255)
        Note over Agent, Boot: ЕТАП 1: Автоматичний Preflight & Bootstrap
        Agent->>Boot: python3 harness_runner.py verify
        Boot-->>Agent: JSON: status="success", MCP/Harnesses/553 skills OK
    end

    rect rgb(255, 250, 240)
        Note over Agent, H2: ЕТАП 2: Адаптація оточення (Google Harness²)
        Agent->>H2: harness2_status() & вибір компонента Tool Guidance
        H2-->>Agent: Конфігурація 8 компонентів (guardrails, prompt, memory)
    end

    rect rgb(245, 255, 245)
        Note over Agent, Skills: ЕТАП 3: Підтягування спеціалізованих знань
        Agent->>MCP: skills_list(category="auth")
        MCP-->>Agent: ["burp-suite", "jwt-tool", "oauth-pentest", ...]
        Agent->>MCP: skills_read(name="jwt-tool")
        MCP->>Skills: читання .agents/skills/jwt-tool/SKILL.md
        Skills-->>MCP: вміст інструкції та методології
        MCP-->>Agent: структурована методологія тестування токенів
    end

    rect rgb(255, 245, 245)
        Note over Agent, Platform: ЕТАП 4: Виконання дій через MCP та Harness
        Agent->>RRH: probe(url="http://target/api/login", method="POST")
        RRH->>MCP: repeater_send_raw_http(...)
        MCP->>Platform: відправка запиту через Go Engine
        Platform-->>MCP: HTTP 401 з заголовком Bearer
        MCP-->>RRH: сирий обмін
        RRH-->>Agent: Observation Contract: status="warning", details={status: 401}
    end

    rect rgb(240, 255, 255)
        Note over Agent, Platform: ЕТАП 5: Фіксація знахідки та верифікація Scope
        Agent->>RRH: check-scope(allowed="web/lab/views.py")
        RRH-->>Agent: Scope Check: PASS
        Agent->>RRH: record-finding(title="Broken Auth", severity="HIGH")
        RRH->>Platform: Запис у проєктну базу SQLite WAL / Postgres
        Platform-->>RRH: Finding ID #42 зареєстровано
        RRH-->>Agent: status="success"
    end

    rect rgb(248, 248, 255)
        Note over Agent, H2: ЕТАП 6: Рефлексія та формування звіту
        Agent->>H2: Оновлення Improvement Ledger новими уроками
        Agent-->>Operator: Фінальний структурований звіт (§16 AGENTS.md)
    end
```

---

## 3. Як Функціонує Кожен Компонент у Цілісному Ланцюжку

### 1. Ядро: Request-Rider MCP Server (`request-rider-mcp`)
- **Роль**: Головний фасад платформи. Надає агентському середовищу 97+ прямих безпекових та діагностичних методів:
  - Робота з HTTP/HTTPS перехопленим трафіком (`history_get_records`, `history_get_transaction_raw`).
  - Ручне надсилання та повторення запитів (`repeater_send_raw_http`).
  - Високошвидкісний фаззінг маркерів (`intruder_start_attack`).
  - Запуск вбудованих сканерів (`scanner_active_start`).
  - Розвідка та OSINT граф (`osint_run_transform`).
  - Out-of-band підтвердження вразливостей (`oob_generate`, `oob_poll`).
  - Керування навичками (`skills_list`, `skills_read`).

### 2. Детермінований Action Space: Request-Rider Harness
- **Роль**: Захист від хаотичного виконання неконтрольованих shell-команд.
- Забезпечує контракт **Observation Contract**:
  - `status`: `"success"` | `"warning"` | `"error"`
  - `summary`: стислий зміст результату в одне речення
  - `details`: технічні деталі (метрики, статус-код, час)
  - `root_cause_hint`: підказка щодо першопричини збою
  - `safe_retry_instruction`: безпечна дія для виправлення ситуації
  - `explicit_stop_condition`: критерій, за якого агент зобов'язаний зупинитися
- Контролює межі змін за допомогою `check-scope` (перевірка несанкціонованого редагування файлів).

### 3. Рекурсивне Гартування: Google Research Harness²
- **Роль**: Адаптивне налаштування оточення моделі для складних відкритих завдань.
- Керує 8 компонентами:
  1. `system_prompt` — контекстні системні директиви.
  2. `guardrails` — жорсткі інваріанти безпеки.
  3. `memory` — персистентний журнал успішних патернів (`Improvement Ledger`).
  4. `tool_guidance` — контекстні підказки щодо правильного виклику інструментів.
  5. `subagents` — делегування підзадач субагентам.
  6. `skills` — динамічна фільтрація релевантних навичок.
  7. `scripts` — автоматичні перевірочні скрипти.
  8. `plugins` — підключення додаткових обробників.
- Забезпечує цикл **Propose-Probe-Compose**: агент пропонує зміни в оточення, зондує їх вплив і компонує найефективніше робоче середовище.

### 4. Бібліотека Знань: 550+ Скілів (`.agents/skills/*`)
- **Роль**: Глибока інженерна база знань на всі випадки (від аудиту смарт-контрактів та Burp Suite до аналізу хмарної безпеки AWS/GCP).
- Агент не тримає всі 550 скілів у системному промпті (що призвело б до переповнення контексту), а шукає їх на вимогу через `skills_list` та зчитує лише потрібний `SKILL.md` через `skills_read`.

---

## 4. Стратегічні Точки Покращення Взаємодії (Optimization Roadmap)

| Точка ланцюжка | Поточний стан | Пропоноване покращення | Очікуваний ефект |
|---|---|---|---|
| **1. Вибір скіла (Skills Discovery)** | Агент шукає скіл за текстовим пошуком підрядка (`category`) | **Семантичний підбір скілів через індекс**: інтеграція локального роутера, що за запитом завдання повертає топ-3 найбільш релевантні скіли автоматично | Зменшення зайвих ітерацій пошуку з 2 кроків до 0 |
| **2. Скорочення навантаження на контекст (Observation Compression)** | Сирі дампи відповідей можуть перевищувати ліміти контексту | **Автоматичний Smart-Trimming**: стиснення HTML/JS відповідей до семантичних маркерів (форми, заголовки, параметри) | Економія до 70% контекстного вікна під час сканування |
| **3. Зворотний зв'язок з UI (UI Sync State)** | Агент фіксує результати в БД, а користувач бачить їх після ручного оновлення | **Live WebSocket Broadcast**: сповіщення UI про кожну знахідку або дію агента в реальному часі через Gateway WebSocket | Оператор миттєво бачить дії агента на живому дашборді |
| **4. Автоматична рефлексія Harness² (Auto-Reflection)** | Рефлексія запускається окремим викликом демо або свіпу | **Zero-overhead background reflection**: після фіксації знахідки або проходження тестів короткий дельта-урок автоматично записується в `harness2 improvement ledger` | Постійне самонавчання агента від завдання до завдання |
