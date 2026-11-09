---
trigger: always_on
description: Постійна обов'язкова інструкція Request-Rider — повний контракт AGENTS.md (пункти 0–17, Частини I–XXVII) та архітектурні інваріанти документації проєкту без усічення.
---

# ПОСТІЙНА ІНСТРУКЦІЯ ПРОЄКТУ REQUEST-RIDER (AGENTS.MD + ДОКУМЕНТАЦІЯ)

> **АБСОЛЮТНИЙ ПРІОРИТЕТ**: Цей файл закріплює правила `/home/kali/Desktop/DevBackUp-29.10/AGENTS.md` (4742 рядки) та всієї проєктної документації (`Документація/*.md`, кореневі `.md`, `Прочее/*.md`) у форматі `always_on` (< 24 КБ, без усічення контекстного вікна). При будь-якій колізії `AGENTS.md` є єдиним джерелом істини.

---

## I. СИСТЕМНА ДИРЕКТИВА ТА ОБОВ'ЯЗКОВИЙ ФОРМАТ ВІДПОВІДІ

1. **Початок кожної відповіді**:
   - Перший рядок: `EXEC_MODE=AGENTS_MD_STRICT`
   - Підтвердження завантаження: `"AGENTS.md загружен, 17 пунктов приняты к исполнению"`
2. **Мова**:
   - Спілкування з користувачем у чаті та ведення всієї документації — **виключно українською мовою**.
   - Коментарі в коді та `AGENTS.md` можуть залишатися російською/українською відповідно до наявного стилю файлу.
3. **Пріоритет правил**:
   - Агент — детермінований виконавець специфікації `AGENTS.md`.
   - Заборонено ігнорувати, послаблювати або частково виконувати правила `AGENTS.md`.
   - Якщо запит суперечить `AGENTS.md` — зупинитися, вивести `CONFLICT_DETECTED` та `"Данное действие противоречит AGENTS.md, пункт N"`, діяти за правилом.
4. **Обов'язкові блоки у відповіді**:
   - Зафіксований план (§7): `ЦЕЛЬ`, `РАЗРЕШЁННЫЕ ФАЙЛЫ`, `ЗАПРЕЩЁННЫЕ ФАЙЛЫ`, `ПЛАН`, `ОБЯЗАТЕЛЬНЫЕ ПРОВЕРКИ`, `ОЖИДАЕМЫЙ РЕЗУЛЬТАТ`, `ОГРАНИЧЕНИЯ`.
   - Фінальний звіт (§16): `ЗАДАЧА`, `ПЛАН`, `ВЫПОЛНЕННЫЕ ИЗМЕНЕНИЯ`, `ПРОВЕРКИ`, `ИЗМЕНЁННЫЕ ФАЙЛЫ`, `COMPLIANCE: PASS / FAIL`, `ИЗМЕНЕНИЯ ВНЕ ПЛАНА: НЕТ / <описание>`, `ПРОБЛЕМЫ`.
   - Блок застосованих пунктів: `"AGENTS.md: применены пункты [...]"`
   - Блок трикрокової самоперевірки наприкінці:
     - `Шаг 1: какие пункты AGENTS.md применимы.`
     - `Шаг 2: как каждый из них влияет на ответ.`
     - `Шаг 3: итоговый ответ, удовлетворяющий всем пунктам.`

---

## II. ЖОРСТКИЙ ПРОТОКОЛ ВИКОНАННЯ (ПУНКТИ 0–17 AGENTS.MD)

- **§0 Статус**: Усі вимоги обов'язкові. Заборонено змінювати `AGENTS.md` без явного дозволу користувача.
- **§1 Порядок етапів (незмінний)**:
  `1. ПРОЧИТАТЬ ИНСТРУКЦИИ → 2. ПРОАНАЛИЗИРОВАТЬ ЗАДАЧУ → 3. СОСТАВИТЬ ПЛАН → 4. ЗАФИКСИРОВАТЬ ПЛАН → 5. ВЫПОЛНИТЬ ПЛАН → 6. ПРОВЕРЯТЬ КАЖДОЕ ИЗМЕНЕНИЕ → 7. ПРОВЕСТИ ФИНАЛЬНУЮ ПРОВЕРКУ → 8. СФОРМИРОВАТЬ ОТЧЁТ`
- **§2 Етап 1 (Читання інструкцій)**: До будь-яких змін прочитати `AGENTS.md`, `SESSION-CLAIMS.md`, релевантні файли `Документація/` та код (Правило «Прочитай тричі, пиши один раз»).
- **§3 Етап 2 (Аналіз задачі)**: Визначити мету, дозволені/заборонені файли, обов'язкові перевірки, обмеження. При неоднозначності — зупинитися і запитати уточнення.
- **§4–§5 Етап 3–4 (План як жорстка межа)**: До зміни першого файлу зафіксувати план та створити файл сесії у `~/.ai-sessions/Request-Rider/session-YYYYMMDD-<опис>.md`. Вихід за межі плану заборонений.
- **§6 Зміна плану**: Якщо плану недостатньо — `СТОП → пояснити причину → оновити план → зафіксувати нові дозволені дії → продовжити`.
- **§8 Перевірка перед кожною зміною**:
  `[ ] Файл дозволений? [ ] Зміна в плані? [ ] Відповідає AGENTS.md? [ ] Не порушує обмежень? [ ] Справді необхідна?`
- **§9 Заборона непов'язаних змін**: Заборонено рефакторинг «заодно», форматування сторонніх файлів, оновлення залежностей або видалення файлів поза планом.
- **§10–§12 Контроль області змін, обов'язкові тести та Compliance-Check**:
  - Порівняти `РАЗРЕШЁННЫЕ ФАЙЛЫ` vs фактично змінені файли.
  - Заборонено заявляти «тести пройдені» без їх фактичного запуску.
  - Якщо хоча б один пункт не виконано — `COMPLIANCE: FAIL`.
- **§13–§15 Принцип «Зупинитися, а не порушити»**: Жодних самовільних винятків чи прихованої зміни стратегії.

---

## III. АРХІТЕКТУРА ТА ІНВАРІАНТИ REQUEST-RIDER (ЧАСТИНИ I–XXVII AGENTS.MD + ДОКУМЕНТАЦІЯ)

### 1. Трирівнева модель виконання та порти
| Шар | Стек та розташування | Порт за замовчуванням | Відповідальність |
|---|---|---|---|
| **UI (`apps/ui`)** | React 18 + TypeScript + Vite (`src/features/*`, `src/widgets/*`, `src/shared/*`) | `:5173` | 15 воркспейсів (TopNav, SplitPane, Evidence Rail), локальний стан, рендеринг |
| **Gateway (`apps/gateway`)** | FastAPI + Python 3.12 (`app/routers/*`, `app/services/*`, `app/broker/*`) | `:8000` | Проєктне сховище (SQLite WAL `data/gateway.db`), API-фасад, оркестрація сканів/AI/OSINT/Automation, управляючий сокет брокера (`data/broker.sock`) |
| **Engine (`services/engine`)** | Go 1.24 (`cmd/engine/main.go`, `internal/proxy`, `internal/intruder`, `internal/crawler`) | `:8080` (проксі), `:8081` (internal API) | MITM HTTP/HTTPS/WS перехоплення, Upstream/Tor SOCKS5h, високошвидкісний Intruder, Go-краулер |
| **Worker (`services/worker`)** | Python FastAPI (`app/main.py`, `app/browser_worker.py`) | `:8001` | Ізольовані задачі, Playwright headless-браузер, скрінкаст, перевірка залежностей |
| **MCP Server (`request-rider-mcp`)** | Python FastMCP (`server.py`, `.venv`, `skills/`) | `stdio` | 97 MCP-інструментів для зовнішніх та внутрішніх AI-агентів + доступ до 546+ скілів |
| **Agent Harness** | `.agents/skills/request-rider-harness/scripts/harness_runner.py` | CLI | Детермінований раннер життєвого циклу задачі (`init`, `preflight`, `verify`, `check-scope`, `report`) |

### 2. Карта 15 воркспейсів UI та документації (`Документація/*.md`)
1. **`project-hub`** ([project-hub.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/project-hub.md)): Проєкти, Scope (In-Scope/Out-of-Scope), бекапи, імпорт/експорт, глобальна конфігурація.
2. **`proxy`** ([proxy.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/proxy.md), [pasivnyi-trafik.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/pasivnyi-trafik.md), [istoriia.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/istoriia.md)): Живий перехоплювач (Intercept Queue, Forward/Drop/Send to Repeater), HTTP/WS історія, пасивні перевірки.
3. **`browser-profile` / `screencast`** ([browser-profile.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/browser-profile.md), [screencast-manual.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/screencast-manual.md)): Вбудований Chromium через проксі `:8080`, ізоляція профілів, автоматичний довірений CA, інтерактивний канвас.
4. **`target-site-map`** ([karta-cili.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/karta-cili.md)): Ієрархічне дерево хостів/шляхів/параметрів, інтеграція з краулером (`crawl.py`, `katana`, Go-crawler).
5. **`repeater`** ([povtoryuvach.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/povtoryuvach.md)): Ручна модифікація та повторна відправка запитів, вкладки сесій, таймінги.
6. **`intruder`** ([intruder.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/intruder.md)): Фаззинг маркерів `§...§`, режими Sniper / Battering Ram / Pitchfork / Cluster Bomb, генератори пейлоадів, `ffuf`.
7. **`active-scanner` & `scanner-pro`** ([aktivnyi-skanner.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/aktivnyi-skanner.md), [scanner-pro.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/scanner-pro.md)): Вбудований пайплайн DAST + 28 зовнішніх сканерів (`nuclei`, `sqlmap`, `dalfox`, `nikto`, `zap`, `wapiti`, `kxss`, `crlfuzz`, `corsy`, `ssrfmap`, `xsstrike`, `commix`, `fenjing`, `sstimap`, `nosqlmap`, `graphql-cop`, `jwt-tool`, `arjun`, `x8`, `interactsh`, `subzy`, `testssl`, `sslyze`, `nmap`, `naabu`, `httpx`, `gowitness`, `feroxbuster`), дедуплікація та верифікація знахідок.
8. **`osint`** ([osint.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/osint.md)): 33 інструменти розвідки через `osint_runner.py` (`subfinder`, `amass`, `assetfinder`, `findomain`, `chaos`, `dnsx`, `massdns`, `puredns`, `shuffledns`, `alterx`, `tlsx`, `uncover`, `shodan`, `censys`, `zoomeye`, `fofa`, `theHarvester`, `spiderfoot`, `recon-ng`, `sherlock`, `maigret`, `holehe`, `h8mail`, `ghunt`, `gitdorker`, `trufflehog`, `gitleaks`, `waybackurls`, `gau`, `urlfinder`, `hakrawler`, `gospider`, `exiftool`), граф сутностей.
9. **`oast`** ([oast.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/oast.md)): Out-of-Band взаємодії (DNS/HTTP/SMTP колбеки, `interactsh-client`, кореляція токенів).
10. **`decoder` & `comparer`** ([dekoder.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/dekoder.md), [porivniuvach.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/porivniuvach.md), [yak-korystuvatysya-transformamy.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/yak-korystuvatysya-transformamy.md)): Трансформації (Base64, URL, Hex, JWT, Gzip, Хеші) та побайтовий/порядковий diff.
11. **`template-store` & `automation`** ([template-store.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/template-store.md), [automation-сценарії.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/automation-сценарії.md)): Бібліотека YAML-шаблонів перевiрок та графовий DAG-конструктор пайплайнів (`automation_runner.py`).
12. **`tor-proxy`** ([tor-proksi.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/tor-proksi.md)): Керування Tor (`SOCKS5h` без DNS-витоків, `NEWNYM` ротація ланцюжків, перевірка вихідного IP).
13. **`ai-assistant`** ([ai-asystent.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/ai-asystent.md), [AI_AGENT_ARCHITECTURE.md](file:///home/kali/Desktop/DevBackUp-29.10/AI_AGENT_ARCHITECTURE.md), [agent-harness-specification.md](file:///home/kali/Desktop/DevBackUp-29.10/Документація/agent-harness-specification.md)): AI-чат, OpenCode runtime, MCP-сервер (`request-rider-mcp`), 552 скіли, автономні цикли верифікації.

### 3. Жорсткі технічні та безпекові інваріанти (`AGENTS.md` Частини I–XXVII + `SECURITY.md` + `broker-contract.md`)
1. **Заборона `shell=True`**: Усі зовнішні CLI-інструменти викликаються виключно через масив аргументів `subprocess.run([bin, ...], shell=False)` або `asyncio.create_subprocess_exec` з явним `timeout`.
2. **Broker Contract (`apps/gateway/app/broker/`)**:
   - Непривілейований Gateway спілкується з привілейованим брокером (`scripts/rr_privileged_broker.py`) лише через Unix domain socket `data/broker.sock` (`0660`) з NDJSON-протоколом та білим списком capability (`net_raw_scan`, `service_tor`, `namespace_exec`).
   - Жодних `sudo` з паролем у відкритому тексті або довільних shell-команд через брокер.
3. **Захист таємниць та Redaction**:
   - API-ключі AI/OSINT провайдерів зберігаються в системному Keyring або зашифрованому сховищі й ніколи не повертаються у відкритому вигляді в API/UI/логах (`***REDACTED***`).
   - Перед відправкою запитів у хмарні LLM-провайдери обов'язково працює pipeline маскування чутливих заголовків (`Authorization`, `Cookie`, `X-API-Key`).
4. **База даних SQLite (`apps/gateway/app/db.py`)**:
   - Обов'язковий режим `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`.
   - Ідемпотентні міграції при старті Gateway без втрати існуючих таблиць.
5. **Контракти API та типів**:
   - Зміна схеми відповіді в `apps/gateway/app/routers/*.py` вимагає синхронної перевірки клієнта в `apps/ui/src/` та інструментів у `request-rider-mcp/server.py`.
6. **Гігієна процесів та Playwright (`AGENTS.md` Частина V, VII)**:
   - Після завершення e2e/browser перевірок не повинно залишатися осиротілих процесів `ms-playwright`, `playwright/driver`, `headless_shell`.
   - Заборонено вбивати живий `services/worker` або робочий браузер користувача широким `pkill -f chromium`.
7. **Виконання CLI-інструментів безпеки (`.agents/rules/tools_execution.md`)**:
   - Зовнішні утиліти (`nmap`, `nuclei`, `sqlmap`, `ffuf`, `subfinder` тощо) запускати через MCP-сервер `request-rider-mcp` (наприклад, `request_rider_scanner_pro_launch`, `request_rider_osint_run`), щоб результати автоматично зберігалися у БД проєкту та відображалися в UI.

---

## IV. ДОВІДНИК ОБОВ'ЯЗКОВИХ ПЕРЕВІРОК ПЕРЕД ЗДАЧЕЮ ЗАДАЧІ

Залежно від зміненого шару агент зобов'язаний виконати:
- **Gateway (`apps/gateway`)**: `pytest apps/gateway/tests`
- **UI (`apps/ui`)**: `npm --prefix apps/ui run typecheck && npm --prefix apps/ui run test && npm --prefix apps/ui run build`
- **Engine (`services/engine`)**: `cd services/engine && go test ./...`
- **Worker (`services/worker`)**: `pytest services/worker/tests`
- **MCP Server (`request-rider-mcp`)**: `/home/kali/Desktop/DevBackUp-29.10/request-rider-mcp/.venv/bin/python -m unittest discover -s /home/kali/Desktop/DevBackUp-29.10/request-rider-mcp -p "test_*.py"`
- **Agent Harness**: `python3 /home/kali/Desktop/DevBackUp-29.10/.agents/skills/request-rider-harness/scripts/harness_runner.py verify`
- **Перевірка процесів**: `ps -eo pid,etime,cmd | grep -E "ms-playwright|playwright/driver|headless" | grep -v grep`
