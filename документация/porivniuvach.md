# Порівнювач

> Актуально на 2026-09-22. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).

## Архітектура

Comparer — повністю browser-only інструмент.
Django route для нього не існує.
Go endpoint для нього не існує.
Payload, network request і server response відсутні.
Вхідні дані — довільні текстові request/response fragments.

## UI схема

Вкладка має `#comparer-left` і `#comparer-right` textarea.
`#compare-words` запускає word comparison.
`#compare-bytes` запускає byte comparison.
`#send-comparer-left-decoder` відправляє left у Decoder.
`#send-comparer-right-decoder` відправляє right у Decoder.
`#clear-comparer` очищає обидва inputs і output.
`#swap-comparer` міняє місцями значення inputs.
`#comparer-output` є diff-output container.

## Послідовність Words

Handler читає `.value` left.
Handler читає `.value` right.
Викликається `renderWordComparison(left, right)`.
Результат встановлюється через `innerHTML` у output.
Word mode працює на текстових токенах.
Він показує збіги та відмінності у візуальному diff.
Порівняння не нормалізує HTTP headers.
Порівняння не робить canonical URL або JSON semantic comparison.

## Послідовність Bytes

Byte handler читає ті самі два strings.
Викликається `renderByteComparison(left, right)`.
Порівняння виконується для UTF-8 byte representation.
Output також записується у diff container.
Binary-like content з textarea все одно проходить browser string encoding.
Це не raw network byte capture.

## Передача з інших інструментів

`sendToComparer(value, side)` спочатку перевіряє value.
Порожній value ігнорується без створення workspace.
Потім викликається `persistWorkspaces()`.
Активний comparer отримує value у right, якщо left уже заповнений.
Інакше пошук іде по comparer contexts за номером.
Першим заповнюється вільний left.
Потім вільний right.
Якщо вільного context немає, викликається `createWorkspace('comparer', state)`.
Неактивний workspace стає active через `selectWorkspace`.

History, Traffic та Intruder викликають цей flow через row actions.
Це передача локального значення, а не API request.
Decoder integration викликає `sendToDecoder(value)`.
Після заповнення input користувач окремо запускає decoder.

## State і storage

Context містить `kind: 'comparer'`, id, number і state.
State має `left` та `right` strings.
Contexts зберігаються у `localStorage` key `requestrider-workspaces-v1`.
Active ID зберігається окремо.
Output diff не є окремим durable result.
Після reload inputs відновлюються через workspace restore.
Після зміни input output треба перерахувати кнопкою.
Clear скидає DOM values і placeholder output.
Swap не змінює backend або session server.

## Error paths і limitations

Окремої validation schema немає.
UI приймає будь-який текст.
Порожні поля дозволені для ручного порівняння.
Немає HTTP статусу, retry або network error.
Browser DOM/render exceptions залишаються client-side.
Дуже великі тексти обмежуються ресурсами браузера.
Результат не додається автоматично в History.
Comparer не запускає цільові запити.

## Symbols/files

Головний файл — `web/templates/lab/index.html`.
Ключові symbols — `sendToComparer`.
Також `renderWordComparison` і `renderByteComparison`.
Handlers — `compare-words`, `compare-bytes`, `clear-comparer`, `swap-comparer`.
Decoder links — `sendToDecoder`.
Workspace links — `persistWorkspaces`, `createWorkspace`, `selectWorkspace`.
Django `web/core/urls.py` не має comparer path.
Go `engine/main.go` не має comparer handler.

## Розширений code walkthrough

### DOM handlers

`#compare-words` читає left/right і викликає `renderWordComparison`.
`#compare-bytes` читає ті самі поля і викликає `renderByteComparison`.
`#clear-comparer` очищає inputs та output.
`#swap-comparer` міняє значення двох textarea.
Decode buttons викликають `sendToDecoder`.

### State transition

External row action викликає `sendToComparer(value, side)`.
Функція перевіряє порожній рядок і викликає `persistWorkspaces`.
Вона шукає active comparer, потім contexts за number.
Вільне поле отримує `left` або `right` у context.state.
При відсутності context виконується `createWorkspace('comparer', initialState)`.
Активний context синхронізує DOM через `selectWorkspace`.

### Contract and limitations

Точного JSON payload немає: значення передається як JavaScript string.
Django `views.py` і Go `main.go` не мають comparer handler.
Результат існує в `#comparer-output` до наступного clear/re-render.
Довільний HTML у diff обробляється renderer-ом, а не backend sanitizer.
Порівнювач не створює Traffic SSE, SQLite record або network request.
Symbols: `sendToComparer`, `renderWordComparison`, `renderByteComparison`,
`persistWorkspaces`, `createWorkspace`, `selectWorkspace`; файл `index.html`.

## Трасування повного lifecycle

1. Значення потрапляє у Comparer або ручним paste, або explicit action з
   History/Traffic/Intruder/Repeater. Передача не запускає network request.
2. `sendToComparer` шукає active comparer, визначає вільну сторону і при
   потребі створює новий comparer workspace. Після цього persist записує
   inputs у browser state.
3. Word mode tokenizes обидва strings і будує escaped diff HTML; byte mode
   порівнює UTF-8 representation. Обидва режими працюють synchronously у
   browser та не мають server progress.
4. Output живе в DOM до наступного compare/clear або workspace restore.
   Empty output нормалізується через поточну locale, тому український
   placeholder не залишається в English після reload.
5. Decode action переносить саме selected side у Decoder; result Comparer
   не змінюється автоматично. Swap міняє inputs і вимагає нового compare.
6. Clear очищає обидва inputs/output, але не видаляє джерельний History,
   Traffic або Intruder result.
7. Workspace autosave відновлює left/right strings, але не гарантує
   відновлення старого rendered diff; його потрібно повторити кнопкою.

### Контрольні точки

`source/action → side assignment → persist → word/byte renderer → output →
decode/swap/clear → reload` — повний локальний trace. Перевіряйте escaping
diff HTML, великі inputs, empty state і відсутність fetch/network у DevTools.
