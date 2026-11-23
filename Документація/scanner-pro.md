# Scanner Pro — Об'єднаний сканер безпеки

> Документація об'єднаного сканера вразливостей проєкту Request Rider.
> Загальна архітектура системи: [arkhitektura-ta-api.md](./arkhitektura-ta-api.md).
> Детальний довідник детекторів: [aktivnyi-skanner.md](./aktivnyi-skanner.md).

---

## 1. Концепція та архітектура

Scanner Pro об'єднує **Active Scanner** (евристичне виявлення вразливостей веб-застосунків та API **79 спеціалізованими модулями** з 5 профілями: `full`, `fast`, `api`, `llm`, `stealth`), **Corpus Scanner** (глибоке сигнатурне сканування за базою **6521 перевірки**) та інтеграцію **OpenVAS (GVM)** (детальніше у [aktivnyi-skanner.md](./aktivnyi-skanner.md)) в **єдиний цілісний інструмент аудиту**.

### Ключові можливості:
1. **Єдиний інтерфейс аудиту**: активний евристичний сканер поверхні атаки (SQLi, XSS, SSRF, BOLA/IDOR, бізнес-логіка, Open Redirect, чутливі шляхи та заголовки) та структурований корпус **6521** перевірки цільових шляхів і сигнатур.
2. **SPA / API Discovery**: автоматичний аналіз клієнтських JavaScript-файлів для виявлення API-маршрутів та генерація точок атаки (`CandidatePointsForURL`) для безформних REST/JSON ендпоінтів.
3. **Миттєве потокове оновлення (SSE)**: знахідки передаються оператору в реальному часі через Server-Sent Events (`event: finding`), щойно вони виявлені.
4. **Пряма інтеграція з Live Dashboard**: кожна нова знахідка миттєво потрапляє у таблицю та лічильники Live Dashboard з дедуплікацією за фінгерпринтами без перезавантаження сторінки.
5. **Постійний антидетект та ротація User-Agent**: усунено будь-які дефолтні підписи `Request Rider` — сканер здійснює підміну відбитків браузерів за реалістичним пулом відбитків з `UserAgent.txt` для всіх запитів.
6. **Повний контроль життєвого циклу завдань**: асинхронний запуск завдань, пауза (`pause`), продовження (`resume`), безпечне скасування (`cancel`), автоматична зупинка на серії збоїв (`Streak`), перевідправка невдалих запитів (`resend`) та збереження чекпоінтів.
7. **Експорт звітів**: єдине меню `#scanner-export-active` із групами `Active Scan` (`JSON`, `HTML`, `CSV`, `XML`, `Metasploit XML`), `Corpus Scan` (`JSON`, `HTML`, `CSV`, `XML`) та `All Combined`.

---

## 2. Складові частини об'єднаного сканера

### 2.1. Active Scanner Engine
- **Евристичний аналіз поверхонь**: дослідження форм, параметрів запиту, шляхів URL, заголовків відповіді.
- **5 профілів сканування (`#scanner-active-profile`)**: `full` (дефолт, 79 модулів), `fast` (22), `api` (25 + `MassAssignment`), `llm` (7), `stealth` (12 пасивних).
- **Детекція класів вразливостей OWASP Top-10 (79 модулів)**:
  - Ін'єкції (SQLi з глибокими векторами SQLite/ORM, Command Injection, Template Injection, NoSQL, XPath, LDAP, XXE).
  - Cross-Site Scripting (Reflected, DOM) та ін'єкції клієнтських шаблонів (CSTI).
  - Server-Side Request Forgery (SSRF) з підтримкою OAST-валідації (DNS/HTTP зворотні виклики).
  - Багатоетапна бізнес-логіка (модуль `BusinessLogic`): BOLA / IDOR на REST API, маніпуляція цінами та оплатою, обхід процедур скидання паролів.
  - Open Redirect, обхід автентифікації та небезпечні перенаправлення.
  - Витік конфігурацій, секретів, PII та облікових даних (із розділенням паролів, хешів, email та відсіканням шуму коду).
- **Підтвердження знахідок (Proof of Concept)**: кожна верифікована знахідка формує готовий `curl` для миттєвого відтворення в терміналі.

### 2.2. Corpus Scanner Engine
- Вбудована в Go-бінарник база **6521** сигнатурної перевірки (`corpus.tsv`), що перевіряє статус-коди (`CODE`), маркери в тілі відповіді (`BODY`), специфічні заголовки (`HEADER`) та комбіновані вирази `MatchAnd` (`AND`, `||`, `!`).
- Високопродуктивний асинхронний пул горутин із налаштуванням конкурентності (`corpusDefaultConcurrency = 8`, `corpusDefaultTimeout = 10s`, `corpusMaxBodyBytes = 1 MiB`) та паузою/продовженням/скасуванням завдань.
- Повний звіт виявлених артефактів, серверних панелей, прихованих бекапів, конфігураційних файлів та відомих уразливих точок входу.

---

## 3. Потокове відображення знахідок (SSE та Live Dashboard)

### 3.1. Архітектура потоку SSE
Сканер використовує потік Server-Sent Events:
- `GET /api/scanner/active/jobs/<job_id>/stream`
- `GET /api/scanner/corpus/jobs/<job_id>/stream`

Події потоку:
- `event: progress` — поточні лічильники перевірених сторінок, надісланих запитів та часу сканування.
- `event: finding` — кадр з детальною інформацією про виявлену вразливість (`id`, `title`, `severity`, `endpoint`, `method`, `payload`, `poc_curl`).
- `event: snapshot` (Corpus) / `event: paused` / `event: resumed` / `event: resend` — початковий знімок, зміна стану виконання та перевідправка.
- `event: done` — фінальний кадр із підсумковими лічильниками та повним звітом.

### 3.2. Миттєве потрапляння в Live Dashboard
При надходженні події `finding`:
1. Клієнтський обробник десеріалізує знахідку та перевіряє фінгерпринт (`getFindingFingerprint`) для виключення дублікатів.
2. Викликається `window.pushFindingToLiveDashboard(row, engine, targetUrl)`.
3. Оновлюються KPI-метрики (`hub-kpi-vulns`, лічильники за рівнями Critical, High, Med, Low).
4. Знахідка негайно відображається у стрічці **Security Findings Stream**.
5. Клік на знахідку відкриває модальне вікно (Drawer) із повним PoC cURL, описом та рекомендаціями.

---

## 4. Антидетект та маскування запитів

Усі перевірки сканера виконуються в режимі повного антидетекту:
- Заборонено використання будь-яких сигнатур сканера або бібліотек за замовчуванням (`Request Rider`, `Go-http-client` тощо).
- Заголовки `User-Agent` динамічно вибираються з пулу 182 реалістичних браузерних відбитків (`UserAgent.txt`).
- Забезпечено автентичні заголовки `Accept`, `Accept-Language`, `Sec-Ch-Ua`, характерні для актуальних версій Chrome, Firefox, Safari та Edge.
- Повна сумісність із маршрутизацією вихідного трафіку через Egress/Tor/Proxy прошарок.

---

## 5. Експорт звітів та налаштування (`⚙️`)

У верхній панелі Scanner реалізовано єдине меню експорту `#scanner-export-active` та окремий експорт OpenVAS:
- **`Active Scan` та `All Combined`**: `JSON`, `HTML`, `CSV`, `XML` та `Metasploit XML`.
- **`Corpus Scan`**: `JSON`, `HTML` (візуальний звіт **6521** сигнатури), `CSV` та `XML` (без `Metasploit XML`).
- **Налаштування (`⚙️` → `#tool-pane-scanner`)**: `#setting-scanner-profile` (`Safe`, `Standard` [дефолт], `Aggressive`) та `#setting-scanner-timeout` (`3–30` с, дефолт `10`).

---

## 6. HTTP API сканера

| Метод | Шлях | Призначення |
|---|---|---|
| `POST` | `/api/scanner/active/jobs` | Запуск активного сканування |
| `GET` | `/api/scanner/active/jobs/<job_id>` | Стан та прогрес активного сканування |
| `GET` | `/api/scanner/active/jobs/<job_id>/stream` | SSE-потік активного сканування |
| `POST` | `/api/scanner/active/jobs/<job_id>/<action>` | Керування станом (`pause`, `resume`, `cancel`, `resend`) |
| `GET` | `/api/scanner/corpus/stats` | Оцінка вибірки корпусного сканування |
| `POST` | `/api/scanner/corpus/run` | Одноразовий синхронний запуск корпусу |
| `POST` | `/api/scanner/corpus/jobs` | Асинхронний запуск корпусного сканування |
| `GET` | `/api/scanner/corpus/jobs/<job_id>` | Стан та прогрес корпусного сканування |
| `GET` | `/api/scanner/corpus/jobs/<job_id>/stream` | SSE-потік корпусного сканування |
| `POST` | `/api/scanner/corpus/jobs/<job_id>/pause` | Пауза корпусного сканування |
| `POST` | `/api/scanner/corpus/jobs/<job_id>/resume` | Продовження корпусного сканування |
| `DELETE` | `/api/scanner/corpus/jobs/<job_id>` | Скасування корпусного сканування |
