# AI-вкладка RequestRider

AI-вкладка призначена для аналізу конкретних результатів ручного тестування.
Вона не надсилає весь workspace автоматично.

## Актуальний стан ітерацій

AI працює лише з evidence, яке оператор явно прикріпив через UI. Зміна мови
не повинна змінювати або втрачати прикріплені дані. Після змін у AI або
пов'язаних workspace виконуйте алгоритм з [AGENTS.md](./AGENTS.md):
перевірка правил, targeted і regression-тести, живий браузер, reload і
перевірка console/network.

## Робочий сценарій

1. Виконайте потрібну дію у Repeater, OSINT, Target Map, Scanner або Intruder.
2. У History/Traffic виберіть потрібні рядки, якщо треба передати лише їх.
3. Натисніть відповідну кнопку `Send ... to AI`.
4. Відкрийте AI, поставте питання про прикріплені дані.
5. Перегляньте блок `Attached to chat` і переконайтеся, що прикріплено саме
   потрібне evidence.

Кнопки прикріплення передають дані в локальний стан браузерного чату. Нове
звичайне повідомлення без натиснутої кнопки не викликає завантаження History,
Traffic або іншого workspace context.

## Що можна передати

- повний Repeater request/response;
- результати Intruder;
- Target Map;
- OSINT і Scanner results;
- вибрані або доступні History records;
- вибрані або доступні Traffic records;
- власне operator observation у тексті повідомлення.

Exchange передається без автоматичного приховування полів: headers, cookies,
Authorization, JWT, request/response body, payloads, status, content type,
size, latency, tags і notes можуть бути частиною evidence. Для remote provider
перевірте політику endpoint-а та допустимість передачі цих даних.

## Provider

Для локальної інфраструктури використовуйте Ollama. Також доступні OpenAI,
Anthropic, OpenRouter, Gemini, Groq, Mistral і custom OpenAI-compatible
endpoint. API key надсилається adapter-ом у заголовку та не записується у
chat context.

Provider відповідає текстовим аналізом. AI не запускає Repeater, Intruder,
OSINT, Scanner, Target Map або інші функції RequestRider. Для remote provider
використовується HTTPS; локальний Ollama працює через loopback.

## Як ставити питання

Добре працюють запити:

- «Порівняй ці два response і назви спостережувані відмінності».
- «Які endpoint-и в цьому Target Map виглядають реальними, а які схожі на SPA
  fallback?»
- «Проаналізуй Intruder results і запропонуй мінімальну наступну перевірку».
- «Знайди підозрілі security headers у прикріплених Traffic records».

Просіть AI відокремлювати факти від гіпотез. Observable change не є автоматично
доказом уразливості.
