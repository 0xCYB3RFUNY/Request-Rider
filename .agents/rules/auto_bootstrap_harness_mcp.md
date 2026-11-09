# Автоматичне Підключення та Ініціалізація Агентського Оточення (MCP + Harnesses + Skills)

> **ОБОВ'ЯЗКОВЕ ПРАВИЛО**: Будь-який автономний агент (OpenCode, Codex, Antigravity, Claude Code, Cursor), який починає роботу в репозиторії Request-Rider, зобов'язаний гарантувати активність та автоматичне підключення трирівневого агентського оточення.

---

## 1. Трирівнева Модель Робочого Оточення Агента

При взаємодії з проєктом агент автоматично оперує через наступні рівні:

1. **Базовий шар (Основа) — Request-Rider FastMCP Server**:
   - Надає 97+ інструментів безпеки (Proxy, Repeater, Intruder, Scanner, OSINT, OOB).
   - Запускається через віртуальне середовище `request-rider-mcp/.venv`.
   - Налаштований у `opencode.json` та `.agents/mcp_config.json`.

2. **Шар гартування — Request-Rider Harness + Google Research Harness²**:
   - `request-rider-harness` (`.agents/skills/request-rider-harness`): забезпечує детермінований Action Space, Observation Contract, валідацію дозволених файлів (Scope Guard) та запуск ізольованих тестів.
   - `google-harness2` (`.agents/skills/google-harness2` та `.agents/harness2`): забезпечує оптимізацію оточення моделей (Propose-Probe-Compose рекурсія), управління 8 компонентами (промпт, guardrails, пам'ять, підказки інструментів, субагенти, скіли, скрипти, плагіни).

3. **Арсенал експертизи — 550+ Скілів**:
   - Розташовані в `.agents/skills/*` та проіндексовані в `.agents/skills.json`.
   - Автоматично дозволені для агентів через `opencode.json` (`"skill": { "*": "allow" }`).
   - Доступні через FastMCP інструменти `skills_list` та `skills_read`.

---

## 2. Автоматичний Bootstrap та Preflight (Перевірка перед початком)

Перед виконанням або на початку нової сесії агент виконує автоматичну верифікацію:

```bash
# Швидка перевірка готовності (повертає JSON Observation Contract)
python3 .agents/skills/request-rider-harness/scripts/harness_runner.py verify

# Або повний автобутстрап (автоматично створює venv, встановлює пакети, конфігурує mcp)
python3 scripts/bootstrap_agents_env.py
```

Якщо будь-який компонент відсутній, скрипт `scripts/bootstrap_agents_env.py` автоматично:
1. Створює віртуальне оточення `request-rider-mcp/.venv` (якщо відсутнє).
2. Встановлює обов'язкові бібліотеки `mcp`, `httpx`.
3. Встановлює `harness2` у режимі editable (`pip install -e .agents/harness2`).
4. Синхронізує навички та конфігурації `opencode.json` і `.agents/mcp_config.json`.
