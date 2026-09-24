# Декодер

> Актуально на 2026-09-22. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).

## Архітектура

Decoder — browser-only transform pipeline.
Django gateway не має `/api/decoder`.
Go engine не має `/proxy/decoder`.
Жоден input не надсилається мережею.
Дані обробляються JavaScript у сторінці.

## UI схема

`#decoder-operation` містить operation IDs.
`#decoder-input` — editable textarea.
`#decoder-output` — readonly textarea.
`#decoder-apply` запускає вибрану операцію.
`#decoder-swap` переносить output у input.
`#decoder-clear` очищає input/output/status.
`#decoder-status` показує pipeline і elapsed milliseconds.
Workspace tabs дозволяють окремі Decoder contexts.

## Operation contract

`urlEncode` викликає `encodeURIComponent`.
`urlDecode` викликає `decodeURIComponent`.
`base64Encode` кодує UTF-8 bytes через TextEncoder і btoa.
`base64Decode` використовує atob і TextDecoder.
`base64UrlEncode` замінює `+` на `-`, `/` на `_` і прибирає padding.
`base64UrlDecode` валідовує URL-safe alphabet і відновлює padding.
`htmlEncode` escape-ить ampersand, angle brackets, quotes і apostrophe.
`htmlDecode` використовує тимчасовий DOM textarea.
`hexEncode` перетворює UTF-8 bytes у lowercase hex.
`hexDecode` вимагає парну кількість hex characters.
`byteEncode` повертає bytes як 8-bit binary groups.
`byteDecode` приймає binary groups або decimal 0..255.
`jsonPretty` робить JSON.parse і stringify з indent 2.
`jsonMinify` робить JSON.parse і compact stringify.
`sha256` використовує `crypto.subtle.digest('SHA-256', ...)`.

## Execution flow

`initializeDecoder` підключає UI handlers.
`runDecoder(operations)` бере input value.
Для кожної operation викликається `applyDecoderOperation`.
Output попередньої operation стає input наступної.
Успішний final value записується в `#decoder-output`.
Status містить labels, стрілку `→` і elapsed ms.
Одноопераційний UI flow передає selected operation array.
Pipeline може бути викликаний іншими browser functions.

## Error paths

Malformed URL encoding кидає browser URI exception.
Некоректний Base64 кидає atob exception.
URL-safe Base64 перевіряє символи та неможливу довжину.
Hex з неhex або odd characters дає явну Error.
Byte decoder відхиляє неbinary/недесяткові tokens.
JSON parse exception показується як decoder error.
Crypto failure також проходить catch.
Catch очищає output, не залишає старий success.
`#decoder-status` отримує локалізований `decoder.error` message.
Network retry або server fallback відсутні.

## State та integrations

Input/output існують у DOM і workspace context.
Workspace state зберігається у `requestrider-workspaces-v1`.
`sendToDecoder(value)` приймає дані з Comparer.
History, Traffic та Intruder можуть передавати request/response text.
Transfer лише заповнює поле, операція не запускається автоматично.
Swap змінює локальні поля.
Clear не видаляє History або Traffic.
Decoder result не записується в SQLite.

## Limitations і symbols

TextDecoder може відображати binary bytes як replacement characters.
Decoder не є повноцінним binary editor.
SHA-256 повертає hex string, не reversible data.
HTML decode залежить від browser DOM semantics.
Великі значення обмежуються memory/quota браузера.
Основні symbols: `decoderOperationLabels`.
Також `decoderUtf8ToBase64`, `decoderBase64ToUtf8`,
`decoderBase64Payload`, `decoderHexToText`, `decoderBytesToText`,
`decoderTextToHex`, `decoderTextToBytes`, `applyDecoderOperation`,
`runDecoder`, `sendToDecoder` у `web/templates/lab/index.html`.

## Розширений walkthrough

### DOM і handlers

`initializeDecoder` прив'язує `#decoder-apply`, `#decoder-swap`, `#decoder-clear`.
Select `#decoder-operation` визначає один operation ID.
`#decoder-input` є єдиним джерелом input string.
`#decoder-output` readonly і не є серверною відповіддю.
`#decoder-status` отримує timing або локальну помилку.

### Call chain

Click Apply -> `runDecoder([$('decoder-operation').value])`.
`runDecoder` читає input і викликає `applyDecoderOperation` у циклі.
Helper повертає Promise для SHA-256 і string для інших операцій.
Final value записується output після завершення всього pipeline.
Click Swap -> output читається, input замінюється output value.
Click Clear -> input/output/status отримують порожній стан.

### Дані та межі

Payload JSON відсутній, `call_engine` не викликається.
DOM state синхронізується workspace persistence після змін.
URL, Base64, HTML, Hex, bytes, JSON та SHA-256 мають різні validators.
Exception не замінюється старим результатом: output очищається.
`sendToDecoder` переносить значення з comparer/history/traffic без автозапуску.
Symbols/files: `initializeDecoder`, `runDecoder`, `applyDecoderOperation`,
`decoderOperationLabels`, `sendToDecoder` у `web/templates/lab/index.html`.

## Трасування повного lifecycle

1. Input з'являється через paste або transfer з Comparer/History/Traffic.
   Transfer лише заповнює textarea і не запускає операцію неявно.
2. `runDecoder` читає operation або pipeline, очищує попередній output і
   послідовно передає результат попереднього кроку в наступний.
3. Для synchronous operations result повертається одразу; SHA-256 проходить
   async `crypto.subtle`, але фінальний output публікується лише після всього
   pipeline.
4. Status фіксує operation labels і elapsed time. Успішний output може бути
   swapped назад в input та повторно оброблений іншою операцією.
5. Invalid URL/Base64/Hex/bytes/JSON або crypto error очищує output і дає
   localized explicit status; старий success не залишається поруч із error.
6. Workspace capture зберігає input/output/status локально. Clear очищує
   тільки decoder context, а не джерельний exchange.
7. Reload відновлює fields через workspace restore. Decoder не має API,
   SQLite row, Traffic event або server-side retry.

### Контрольні точки

`transfer/paste → operation selection → pipeline → validator/helper →
output/status → swap/clear → workspace restore` — canonical trace. Для
перевірки окремо проганяйте valid/invalid pair для кожної operation та
переконайтеся, що network panel залишається порожньою.
