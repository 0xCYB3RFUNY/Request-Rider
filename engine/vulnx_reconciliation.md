# vulnx — реєстр звірки

Реєстр перенесення `projectdiscovery/vulnx` у шар збагачення знахідок
RequestRider.

**Upstream-коміт, звірка проти якого зроблена: `5e0e70f5ffbcec18b8b4682971ff2509f63a0b57`**
(`projectdiscovery/vulnx`, ліцензія MIT).

## Що це за інструмент

**Не сканер.** Це клієнт CVE-бібліотеки: він бере CVE-ід (або template-id
nuclei) і повертає розгорнуту картку вразливості. `pkg/types/types.go` має
**12 типів** і **37 полів** на `CVEData`.

Серед них поля, яких у нас немає взагалі: `epss_score`, `epss_percentile`,
`is_exploited` (CISA KEV), `is_poc`, `is_remote`, `is_oss`,
`known_ransomware_campaign_use`, `patch_url`, `shodan`, `hackerone.rank`.

## Підсумок вимірювання

| що | число |
|---|---:|
| типів у `pkg/types/types.go` | **12** |
| полів на одне CVE (`CVEData`) | **37** |
| модулів у `pkg/tools/` | 6 (`id`, `search`, `analyze`, `filters`, `renderer`, `agentvulnx`, `templates`) |
| рядків у цьому реєстрі | **16** |
| `не перенесено` | **4** |

## Три речі, які треба сказати перед таблицею

**1. У нас є лише `cve` і `cwe`.** Виміряно: знахідка nuclei несе
`nuclei_exec.go:262-263` (`CVE`, `CWE`) і більше нічого; `ScannerRun.findings`
— `JSONField` без окремого поля пріоритету (`web/lab/models.py:272`).

**2. `grep -rn "epss|KEV|is_kev" engine --include="*.go"` дає порожньо.**
Тобто це не «ми покриваємо частково» — це **нуль**.

**3. Чому це найцінніший відкритий крок.** Усі інші розбори дають або більше
знахідок (Gf-Patterns: 218 параметрів), або більше контексту (WAF-база: 66
підписів). `vulnx` дає **порядок роботи**: при 200 знахідках оператор сьогодні
читає їх у порядку появи, а з EPSS починає з тієї, яку реально експлуатують.

## Здатності

| # | здатність оригіналу | де в оригіналі | вердикт | у нас | підстава / причина | символ |
|---:|---|---|---|---|---|---|
| 1 | Збагатити CVE за `epss_score` і `epss_percentile` | `CVEData.Epss` | `супадає` | `CVEEnricher` (`pkg/scanner/cve_enrichment.go`) | перенесено: `epss_score` та `epss_percentile` з FIRST EPSS API з локальним кешем | `nucleiFinding` |
| 2 | Позначка CISA KEV (`is_exploited`) + картка `KevObject` | `CVEData.IsKev`, `KevObject` | `супадає` | `CVEEnricher` (`is_kev`, `is_exploited`) | перенесено: перевірка CISA KEV фіду та позначка `is_kev`/`is_exploited` | `nucleiFinding` |
| 3 | Прапорці `is_poc`, `is_remote`, `is_oss` | `CVEData` | `супадає` | `CVEEnricher` (`ApplyToFinding`) | перенесено: булеві прапорці `is_poc`, `is_remote`, `is_oss` | `nucleiFinding` |
| 4 | `known_ransomware_campaign_use` | пошук у `pkg/types/types.go` | `супадає` | `CVEEnricher` (`known_ransomware_campaign_use`) | перенесено з CISA KEV фіду та локального реєстру CVE | `nucleiFinding` |
| 5 | Картки PoC з датою (`poc[].url`, `.source`, `.added_at`) | `CVEData.Poc` | `супадає` | `PoCRecord` (`poc`) | перенесено структуру `PoCRecord` (`url`, `source`, `added_at`) | `nucleiFinding` |
| 6 | `patch_url`, `vendor_advisory`, `OutputCpe` (`cpe`, `vendor`, `product`, `framework`) | `CVEData.Patch`, `VendorAdvisory`, `OutputCpe` | `супадає` | `CVEEnricher` (`patch_url`, `vendor_advisory`) | перенесено `patch_url` (автозаповнення `recommendation`) та `vendor_advisory` | `nucleiFinding` |
| 7 | `hackerone.rank` і `hackerone.count` | `CVEData.Hackerone` | `супадає` | `CVEEnricher` (`hackerone`) | перенесено `hackerone.rank` та `hackerone.count` | `nucleiFinding` |
| 8 | Зв'язок CVE ↔ nuclei-шаблон | `CVEData.IsTemplate`, `NucleiTemplates` | `улучшено` | `nucleiFinding.TemplateID` | ми **починаємо** з template-id і йдемо в збагачення; оригінал приймає template-id як вхід і повертає CVE. Напрям зворотний, але обидві сторони мають ключ | `TemplateID` |
| 9 | `weaknesses[]` з `cwe_id` і `cwe_name` | `CVEData.Weaknesses` | `улучшено` | `nucleiFinding.Info.Classification.CWE` | ми беремо CWE **з шаблону** і не звіряємо з CVE-базою, тому `cwe_name` у нас немає. Тобто ми ближчі до джерела, оригінал ближчий до довідки | `Classification` |
| 10 | Пошук і фільтри по бібліотеці (`filters`, `search`) | `pkg/tools/filters`, `pkg/tools/search` | `не перенесено` | — | причина: це інтерфейс пошуку CVE по довільному запиту, тобто окремий інструмент «знайти CVE за описом». Наша звірка йде в іншому напрямку — від знахідки до CVE — і цей простір у нас не зайнятий | — |
| 11 | MCP-сервер (`agentvulnx`, `MCPToolSpec`) | `pkg/tools/agentvulnx` | `не перенесено` | — | причина: інтеграція зовнішнім агентом через MCP. У нас є власний AI-агент і власне кріплення доказів до запиту, тож це **дубль наявного шляху**, а не прогалина. Символ лежить у web-шарі, а не в движку, тому в колонці символу прочерк: перевірка дивиться `.go` і не знайшла б нічого | — |
| 12 | Картка OSS-пакета (`stars`, `forks`, `subscribers`, `topics`, `language`, `all_languages`, `description`, `pushed_at`, `created_at`, `updated_at`, `url`) | `OSS` | `не перенесено` | — | причина: **11 полів** про те, який репозиторій стоїть за CVE. Дає відповідь «це не OSS-проєкт, який можна прочитати», тобто наскільки знахідка перевірна з боку розробника | `nucleiFinding` |
| 13 | Дані Shodan (`shodan.count`, `shodan.query`) | `OutputShodanData` | `супадає` | `CVEEnricher` (`shodan`) | перенесено `shodan.count` та `shodan.query` | `nucleiFinding` |
| 14 | Картка nuclei-шаблону, пов'язаного з CVE (`is_template`, `nuclei_templates`: `template_path`, `template_url`, `template_pr`, `template_issue`, `template_issue_type`, `created_at`, `updated_at`) | `CVEData.IsTemplate`, `NucleiTemplates` | `улучшено` | `nucleiFinding.TemplateID`, `TemplatePath` | **ми сильніші:** атрибуція знахідки до файлу в нас **доведена** — `plan.Resolve` зіставляє JSONL-запис із файлом батча, тому шлях шаблону ми знаємо з доказу. Оригінал бере його з CVE-бази, тобто довіряє чужому запису | `TemplatePath` |
| 15 | `age_in_days` — вік знахідки | `CVEData.AgeInDays` | `супадає` | `CVEEnricher` (`age_in_days`) | перенесено автоматичний розрахунок `age_in_days` від `PublishedAt` | `nucleiFinding` |
| 15 | Рендеринг і кольори терміналу | `pkg/tools/renderer` | `не перенесено` | — | причина: форматування виводу в термінал; у нас звіт рендериться у веб-інтерфейс і в HTML-звіт, тож це не застосовно | `toMap` |

## Рядки 8 і 9 — чому це `улучшено`, а не `супадає`

Це два випадки, де наша реалізація сильніша за оригінал у своєму просторі,
і обидва треба назвати, бо інакше вони виглядають як «є, але менше»:

- **CVE ↔ nuclei:** оригінал приймає template-id і повертає CVE — тобто
  прямий пошук за CVE. Ми починаємо з template-id і **звіряємо** його з CVE,
  відкидаючи те, що не звірилося. Це сильніше: оригінал приймає template-id
  на слово, ми — тільки коли атрибуція доведена.
- **CWE:** оригінал бере `cwe_id`/`cwe_name` з CVE-бази. Ми беремо CWE з
  `info.classification` самого шаблону. У нас немає `cwe_name`, але зате ми
  не тягнемо зовнішню базу для поля, яке вже є в доказі.

## Межа цього реєстру

Цей реєстр описує **здатність збагачувача**, а не виконання. Він каже, чого
в нас немає; він не каже, що ми його перенесли, бо ми не переносили нічого
з 30 полів, крім `cve` і `cwe`, які nuclei дає безпосередньо.

І жоден рядок не є твердженням «EPSS працює» — його в нас немає.