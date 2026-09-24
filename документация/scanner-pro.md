# Scanner Pro

> Актуально на 2026-09-22. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).

## Призначення

Scanner Pro — bounded read-only reconnaissance для дозволеної HTTP(S) цілі.
UI прямо визначає межі: без exploit, fuzzing, brute force або access-control bypass.
Сканер збирає evidence, а не виконує активну атаку.
Результат не записується автоматично в History або Traffic.

## UI

Секція `#scanner` описана в `web/templates/lab/index.html`.
`#scanner-url` приймає адресу цілі.
`#scanner-run` запускає Safe CMS Recon.
`#scanner-clear` очищає URL, status і findings.
`#scanner-export` завантажує JSON.
`#scanner-export-csv` завантажує CSV.
`#scanner-send-ai` прикріплює result до AI context.
`#scanner-status` показує lifecycle/error.
`#scanner-findings` показує summary та findings.

`runScanner` trim-ить URL і створює JSON payload:

```json
{"url":"https://example.test/"}
```

Fetch іде як `POST /api/scanner` з JSON content type.
Успішна відповідь кладеться у `currentScanner`.
`renderScanner` читає `summary`, `findings`, `details`.
Export buttons стають enabled після render.

## Django gateway

`web/core/urls.py` веде `/api/scanner` до `views.scanner`.
`views.scanner` дозволяє тільки POST.
JSON має бути object з непорожнім `url`.
Порожній або malformed payload дає HTTP 400.
Формат помилки gateway: `invalid scanner request: ...`.
Після validation викликається `call_engine('/proxy/scanner', {'url': ...})`.
Engine response status і JSON повертаються без прихованого успіху.

## Go endpoint

`engine/main.go` реєструє `POST /proxy/scanner`.
Handler декодує `scannerInput`.
Malformed JSON дає `400 INVALID_JSON`.
Не absolute HTTP(S) URL дає `400 INVALID_TARGET_URL`.
Помилка scan дає `502 SCANNER_CHECK_FAILED`.
Успіх — JSON HTTP 200.

## Послідовність scan

`runSafeScanner` спочатку викликає `runOSINT(target, true)`.
Тому Scanner успадковує DNS, HTTP, redirects, technologies,
cookies, security headers, discovery та WAF data.
Визначається baseline response fingerprint.
Потім формуються security findings.
Перевіряються HSTS, CSP і X-Frame-Options.
Перевіряється TLS 1.0/1.1.
Перевіряються Secure, HttpOnly та SameSite cookie flags.
WAF signal перетворюється на informational finding.
`Allow` header перевіряється через OPTIONS-related logic.

## Fixed probes

Список CMS paths включає `/wp-admin/`, `/wp-login.php`, `/wp-json/`
та `/xmlrpc.php`.
Joomla path — `/administrator/`.
API/admin paths — `/api/`, `/admin/`, `/phpmyadmin/`.
Misconfiguration paths — `/.env`, `/.git/HEAD`, `/backup.zip`, `/db.sql`.
Debug paths — `/server-status`, `/debug/`.
Кожен probe є read-only HTTP request.
Body аналізується обмежено і не зберігається.
Probe записує path, category, status, content type і fingerprint.
`same_as_baseline` відсікає fallback/default pages.
`body_truncated` описує analysis limit.

## Output schema

Top-level result має `url`, `summary`, `details`, `findings`.
Summary містить `highest_severity`, `findings_count`, `status_code`.
Details містить technologies, probes і inherited OSINT sections.
Finding має `severity`, `title`, `category`, `evidence`, `recommendation`.
Severity використовується як INFO, LOW, MEDIUM або HIGH.
Недоступна ціль створює HIGH `Target unreachable`.
Missing headers зазвичай дають MEDIUM.
Cookie policy findings дають LOW/MEDIUM.
HTTP 200 для misconfiguration exposure дає HIGH.

## State, errors, limitations

`currentScanner` — тільки browser memory/workspace state.
JSON/CSV export виконується через `downloadTarget`.
При network error status показує текст exception.
Немає polling: один gateway request чекає завершення probes.
Немає автоматичного History/Traffic persistence.
Scanner не гарантує повний inventory і не виконує JS.

Symbols/files: `runScanner`, `renderScanner`, export handlers у `index.html`;
`scanner` у `web/lab/views.py`; routes у `web/core/urls.py`;
`server.scanner`, `runSafeScanner`, `scannerOptions`, `probeScannerPath`
та `runOSINT` у `engine/main.go`.

## Додатковий literal walkthrough

### Handlers і call chain

`scanner-run click` -> `runScanner` -> `fetch('/api/scanner')`.
Payload створюється з одного trimmed URL.
Response проходить `readJSON`, потім `renderScanner`.
`renderScanner` читає summary/findings/details і формує text output.
Export buttons використовують currentScanner без нового fetch.
Clear скидає currentScanner і disabled export state.

### Backend chain

Django `scanner` перевіряє method, JSON type і URL.
Після нормалізації викликає `call_engine('/proxy/scanner', payload)`.
Go `server.scanner` декодує `scannerInput` і парсить target.
`runSafeScanner` -> `runOSINT(target,true)` -> fingerprints/header/cookie checks.
Потім `probeScannerPath` проходить fixed paths.
`scannerOptions` додає finding про Allow methods.
Summary формується перед JSON response.

### Error/cancel/output

Scanner не має cancel endpoint і не є SSE job.
Abort можливий лише на рівні browser request, якщо handler його використовує.
Go probe errors окремих paths пропускаються, але верхня помилка явна.
Result не пишеться в SQLite/Traffic автоматично.
AI отримує його лише через explicit Send scan to AI.

## Трасування повного lifecycle

1. UI trim-ить URL, визначає profile і показує оператору read-only scope.
   Scanner не приймає payload dictionary і не має прихованого attack mode.
2. `POST /api/scanner` проходить JSON/method/URL validation у Django; при
   malformed input engine не викликається.
3. Go перевіряє absolute HTTP(S) target, запускає `runSafeScanner` і спочатку
   отримує OSINT baseline. Це дозволяє відрізняти реальну exposure від SPA
   fallback/default response.
4. Фіксовані probes виконуються послідовно як bounded read-only requests.
   Кожен probe аналізує status/content type/fingerprint, але не зберігає
   необмежене тіло і не виконує знайдений код.
5. Security checks додають findings із severity, evidence,
   recommendation, confidence і verification state. Недоступна ціль
   залишається explicit finding/error, а не порожнім success.
6. Summary агрегує highest severity, count і HTTP status; details містить
   technologies, probes і inherited OSINT. Django повертає цей JSON без
   прихованого перетворення status.
7. UI записує result у `currentScanner`, будує readable output, вмикає
   export і дозволяє explicit Send to AI. Автоматичної History/Traffic
   persistence немає.
8. Clear скидає URL/status/result/export state. Workspace persistence може
   відновити URL та result; відомий empty state нормалізується до поточної
   локалі після reload або language switch.
9. Export працює з останнім `currentScanner` локально. Повторна перевірка —
   новий повний scan, а не replay старої відповіді.

### Контрольні точки

`URL/profile review → Django validation → OSINT baseline → fixed probes →
finding aggregation → render → export/AI` — повний trace Scanner. Для
діагностики окремо фіксуйте target URL, profile, HTTP status, probe count,
highest severity і explicit error text.
