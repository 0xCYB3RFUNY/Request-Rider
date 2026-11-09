---
name: google-harness2
description: "Google Research Recursive Agent Harnessing Framework (Harness²). Provides task-level and harnessing-level recursion (Propose-Probe-Compose), 8 editable harness components (system prompt, guardrails, memory, tool guidance, subagents, skills, scripts, plugins), and benchmark evaluation for OpenCode and Codex models. Integrated into Request-Rider as the permanent recursive hardening environment for request-rider-mcp."
license: Apache-2.0
compatibility: opencode
metadata:
    source: "https://github.com/google-research/harness2"
    integration: "Request-Rider v1.2"
---

# Google Research Harness² (Recursive Agent Harnessing)

**Harness²** — це фреймворк рекурсивного гартування агентів від Google Research, інтегрований у проєкт **Request-Rider** як постійне аналітично-валідаційне оточення для `request-rider-mcp`.

## Трирівнева архітектура гартування Request-Rider

```
+------------------------------------------------------------------------+
|                          AUTONOMOUS AI AGENT                           |
+------------------------------------------------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
+-----------------------------+             +-----------------------------+
|    REQUEST-RIDER MCP        |             |    REQUEST-RIDER HARNESS    |
| (97+ інструментів безпеки)  |             | (Action Space + ObsContract)|
| - proxy, repeater, intruder |             | - probe, search-history     |
| - active scanner, osint     |             | - check-scope, run-tests    |
+-----------------------------+             +-----------------------------+
                                   |
                                   v
+------------------------------------------------------------------------+
|                     GOOGLE RESEARCH HARNESS²                           |
|       (Recursive Agent Harnessing for Open World Operations)           |
|  - 8 компонентів: prompt, guardrails, memory, tools, subagents, skills |
|  - Task-level recursion: Propose -> Probe -> Compose                   |
|  - Harnessing-level recursion: Experience Reflection & Improvement     |
|  - Підтримка виконавців OpenCode & Codex                               |
+------------------------------------------------------------------------+
                                   |
                                   v
+------------------------------------------------------------------------+
|                       АРСЕНАЛ ІЗ 550+ СКІЛІВ                           |
|      (.agents/skills/*: burp-suite, semgrep, red-team, osint, ...)     |
+------------------------------------------------------------------------+
```

## Основні компоненти Harness²

Harness² надає 8 керованих компонентів оточення моделі:
1. **System Prompt**: структуроване системне ядро інструкцій.
2. **Guardrails**: безпекові інваріанти, обмеження на виконання, перевірка меж scope.
3. **Memory**: довгострокова пам'ять та журнал уроків попередніх запусків.
4. **Tool Guidance**: специфікація виклику та безпечних параметрів MCP-інструментів.
5. **Subagents**: декларація та оркестрація вузькоспеціалізованих субагентів.
6. **Skills**: каталог скілів із `.agents/skills/`.
7. **Scripts**: автоматизовані сценарії перевірки та валідації.
8. **Plugins**: інтеграція з розширеннями та middleware.

## Швидкий запуск через оточення MCP

Пакет `harness2` встановлено у віртуальне оточення `request-rider-mcp/.venv` і доступний як через CLI, так і через MCP-інструменти:

### 1. Перевірка статусу оточення
```bash
/home/kali/Desktop/DevBackUp-29.10/request-rider-mcp/.venv/bin/harness2-check
```

### 2. Запуск локального детермінованого демо (2 ітерації рекурсії)
```bash
/home/kali/Desktop/DevBackUp-29.10/request-rider-mcp/.venv/bin/harness2-demo --output /tmp/harness2_runs/demo --k 2
```

### 3. Запуск через скіл-раннер
```bash
python3 .agents/skills/google-harness2/scripts/run_harness2.py status
python3 .agents/skills/google-harness2/scripts/run_harness2.py demo --k 2
```

### 4. Виклик через FastMCP інструменти
З будь-якого клієнта MCP (`request-rider-mcp`):
- `harness2_status()`: повертає інформацію про оточення Harness², версію, компоненти та конфігурацію.
- `harness2_run_demo(k=2, mode="parallel")`: виконує локальне детерміноване гартування та повертає структурований звіт.
- `harness_pipeline_info()`: повертає огляд повного ланцюжка `Request-Rider MCP -> Harnesses -> Skills`.
