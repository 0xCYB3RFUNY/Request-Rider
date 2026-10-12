# Сесія: встановлення сторонніх skills і плагінів OpenCode

Дата: 2026-10-09
Проєкт: `/home/kali/Desktop/Request-Rider`
Мета: встановити сторонні agent-skills у `.opencode/skills/` і плагін у
`.opencode/plugins/`, потім зробити бекап на робочий стіл з інструкцією
імпорту.

## ✅ Виконано

- [x] **[CR-01]** Встановлено Claude-Red (0xamirdev/claude-red) — 79 skills,
      каталог `.opencode/skills/offensive-*`. 28 без YAML frontmatter
      конвертовано з `## Metadata` / `## Description` (як у upstream
      `convert_skills.py`), ім'я з `**Folder**`.
- [x] **[CR-02]** Написано `.opencode/plugins/claude-red.js` — інструменти
      `claude_red_catalog`, `claude_red_verify`. `node --check` rc=0.
      Виправлено експорт: прибрано іменований `export const ClaudeRedPlugin`
      (лоадер OpenCode реєструє **кожен** експорт як окремий плагін —
      плагін реєструвався двічі). Лишився тільки `export default`.
- [x] **[SRC]** Склоновано й звірено 13 репозиторіїв + VoltAgent (каталог
      посилань, `SKILL.md` немає — встановлювати нічого).
- [x] **[INS]** Встановлено 538 skills із 7 джерел:
      Alireza 422, Trail of Bits 85, mattpocock 10, Claude-OSINT 9,
      humanlayer 7, shuvonsec 4, claude-reflect 1.
- [x] **[VAL]** Валідація 919 каталогів проєкту: 0 невалідних імен,
      0 проблем з описом, 0 порожніх тіл, 0 без `SKILL.md`.
- [x] **[DUP]** Прибрано 43 власні тіні імені (shuvonsec + mattpocock),
      дублікати батьківського каталогу `/home/kali/Desktop/.opencode/skills/`.
- [x] **[JUNK]** Прибрано 2 каталоги-сміття `readme` і `agent-name`,
      створені інсталятором із `.gemini/skills/{README,TEMPLATE}`.
      `readme` — порожнє тіло, `agent-name` — шаблон `name: Agent Name`.
- [x] **[BAK]** Бекап на робочий стіл:
      `~/Desktop/Request-Rider-opencode-skills-backup-2026-10-09/`
      + `.tar.gz` (3.5 МБ, 2252 файли). Перевірено `install.sh` на чистій
      приманці: 538 skills, 1 плагін, `opencode.json` створено;
      другий запуск — 0 імпортовано, 538 пропущено (ідемпотентно);
      сторонні поля `opencode.json` збережено, створено `.bak`.
- [x] **[REF]** Виправлено цифру в README бекапу: ECC — не «302»,
      а **222** каталоги з `origin: ECC` (див. відкриті питання).

## ❌ Не зроблено (з причиною)

- [ ] **[HOOKS]** claude-reflect: 4 hooks (`UserPromptSubmit`, `PreCompact`,
      `PostToolUse`, `SessionStart`) **не портовано**. Причина виміряна:
      API плагінів OpenCode v2 (`@opencode-ai/plugin`) має тільки
      `transform`-хуки на `agent`/`catalog`/`skill`/`command`/`integration`/
      `reference`. Аналога цих чотирьох подій немає, а `hooks.json`
      використовує формат Claude Code з `${CLAUDE_PLUGIN_ROOT}`.
      Skill встановлено разом із `scripts/*.py` — викликаються вручну,
      автоматичного спрацювання не буде.

## 🔎 Відкриті питання (не виправляв — не моя задача)

- **Живі браузери не мої.** `ps` показує `playwright/driver` pid 416808
  (etime 40:54) і pid 487923 (04:53) з `firefox-1490` pid 487967 + 6
  `contentproc`, усі з вендором
  `/home/kali/Desktop/Request-Rider/browser-worker/.venv/`.
  У цій сесії браузер не запускався жодного разу. Не чіпав: за
  «Находка рядом — не поручання» і «Живий мусор» (зупиняється тільки
  своє).
- **6 дублікатів імені з батьківським каталогом** (`brand-discovery`,
  `brand-voice`, `design-system`, `git-workflow`, `hipaa-compliance`,
  `security-review`) існували **до** сесії. Не чіпав.
- **`.opencode/plugins/ecc.js` та `.opencode/ecc/` не торкався.** mtime
  `18:01`/`18:02` — до початку моїх правок (`18:28+`).

## 🧠 Виявлені пастки (записано, бо повторяться)

1. **Конфлікти треба рахувати по ДВОХ каталогах.** OpenCode підвантажує
   і `/home/kali/Desktop/Request-Rider/.opencode/skills/`, і
   `/home/kali/Desktop/.opencode/skills/`. Перевірка лише по каталозі
   призначення створює тіні імені (43 випадки).
2. **`.gemini/skills/` — плоске дзеркало всього репо** і сортується
   першим (`.*` < літери), тому `rglob`+`sorted` бере саме його.
   Виміряно: у 369 парах «дзеркало ↔ канонічний» 367 байт-у-байт
   ідентичні, у 2-х дзеркало повніше. Втрат немає, але інсталятор
   повинен віддавати перевагу не-dot каталогам.
3. **Manifest без фінального переводу рядка** обрізає останній запис
   при `while read` — втрачено `zeroize-audit`, поки не додано `|| [ -n "$name" ]`.
4. **Лоадер плагінів OpenCode реєструє кожен експорт.** Іменований
   `export const X` поряд із `export default X` = подвійна реєстрація.