# Робочі простори та сесії

> Актуально на 2026-09-24. Загальні правила ітерацій та перевірок див. у
> [AGENTS.md](../AGENTS.md), зведений статус — у [README.md](../README.md).

## Призначення

Workspace layer організовує окремі UI contexts для інструментів.
Це browser-local state, а не Django session і не Go job storage.
Автозбереження не виконує HTTP API calls.
Воно потрібне для відновлення форми, вибраних вкладок і tool state.

## Workspace schema

`workspaceKinds` містить repeater, intruder, target, osint, scanner,
comparer, decoder, proxy, ai та automation.
Кожен context має id, kind, number і state.
State залежить від kind: поля Repeater, attack settings, target inputs,
OSINT URL, scanner URL, comparer left/right, decoder input/output,
proxy check fields або AI data. Глобальна адреса route не належить
workspace snapshot: її завжди читає server-backed `GET /api/route`.
`workspaceContexts` — in-memory Map contexts.
`activeWorkspaceId` визначає показаний context.
`workspaceSequence` видає нові IDs/numbers.
History і Traffic є глобальними tabs, не workspace kinds.

## Active Project context

Active Project не належить browser workspace snapshots. Selector у вкладці
`Projects` надсилає CSRF-protected `POST /api/project-context`; Django middleware
перевіряє ID і записує його у валідований server session. Query parameter
`?project_id` не змінює контекст, а `requestrider-project` у `localStorage` є
лише mirror для diagnostics/backward compatibility і не читається при reload.
HTML bootstrap отримує server value через `data-active-project-id`; deleted або
invalid ID очищається middleware. Session context є локальним single-user
contract і не замінює authentication/project authorization для shared mode.

## Tab/UI flow

При старті викликається `restorePersistedWorkspaces`.
Кожен збережений item фільтрується через `workspaceKinds.includes`.
Якщо restore не вдався, створюється workspace кожного kind.
`renderWorkspaceTabs` будує tab buttons конкретного kind.
`selectWorkspace` змінює active ID і відновлює form state.
`createWorkspace` додає context і робить його доступним.
`closeWorkspace` видаляє context, renumber-ить siblings і вибирає інший.
Останній workspace конкретного kind не можна закрити.
UI показує повідомлення `Keep at least one workspace for each tool.`

## Перенесення tool workspace в Automation

У toolbar вкладок Repeater, Intruder, Target, OSINT, Scanner, Decoder, Comparer
та AI є кнопка `Send to Automation`. Вона читає саме active workspace, а не
останній збережений у браузері стан, серіалізує його у відповідний node params,
додає або оновлює вузол і зберігає workflow через Django API. Перехід на
Automation відбувається після збереження, тому selected node можна одразу
перевірити в inspector.

`Use current workspace` у inspector повторно читає активний tool context.
`Open in tool` переносить params назад у відповідну вкладку. Target зберігає
engine/browser/mode/actions та `capture_context_id` (лише ID, не token),
Intruder — mode/dictionaries/transformations/delay/concurrency, Decoder —
operation/input, Comparer — mode/left/right. AI API key у params не переноситься.
Перенесення не запускає активний tool job.

## Autosave

`persistWorkspaces` серіалізує contexts у JSON.
Storage key — `requestrider-workspaces-v1`.
Active ID зберігається у `requestrider-active-workspace`.
Загальний snapshot пишеться у `requestrider-session-v1`.
Мова живе у `requestrider-language`.
`queueWorkspacePersistence` debounce-ить запис приблизно 250 ms.
Після запису status може показати `Saved locally`.
Помилка localStorage ловиться і пишеться через `console.warn`.
Немає server-side migration або SQLite record для workspace.

## Session export schema

`buildSessionSnapshot` повертає:

```json
{
  "version": 1,
  "exportedAt": "2026-09-21T00:00:00.000Z",
  "activeWorkspaceId": "workspace-id",
  "workspaceSequence": 3,
  "contexts": [],
  "language": "uk"
}
```

`downloadSession` викликає `downloadTarget`.
Файл має ім'я `requestrider-session-<timestamp>.json`.
Export включає лише contexts і metadata snapshot.
Go attack execution state не копіюється в цей JSON.
Traffic live cache не є частиною workspace contexts.

## Import flow та помилки

Header Import відкриває hidden `#session-import-file`.
`importSessionFile` читає файл через FileReader.
Після read викликається JSON.parse.
`restoreSessionSnapshot` вимагає `version === 1`.
Також потрібен array `contexts`.
Після filtering має залишитися хоча б один valid kind.
Інакше помилки: `Unsupported session file` або
`Session has no valid workspaces`.
FileReader failure дає `Import error: file could not be read`.
Validation/parse errors відображаються як `Import error: ...`.
Успішний import записує keys і робить `window.location.reload()`.

## Інші local state та limitations

Intruder active attack має окремий localStorage key.
Traffic cursor і browser cache мають власні keys.
Вони не відновлюють повний серверний Go memory store.
Workspace export не містить секретів навмисно лише частково:
state може містити введені оператором request fields, тому файл чутливий.
Великі response bodies можуть перевищити localStorage quota.
Reload відновлює UI, але не гарантує відновлення завершених jobs.

## Symbols/files

Усі symbols реалізовані в `web/templates/lab/index.html`:
`workspaceKinds`, `workspaceContexts`, `persistWorkspaces`,
`queueWorkspacePersistence`, `buildSessionSnapshot`, `downloadSession`,
`restoreSessionSnapshot`, `importSessionFile`, `createWorkspace`,
`selectWorkspace`, `closeWorkspace`, `restorePersistedWorkspaces`.
Backend routes для workspace autosave/export/import відсутні.
Пов'язані browser flows Intruder/Traffic використовують окремі storage keys.

## Повний button walkthrough

`#session-save` виконує локальне збереження через `persistWorkspaces`.
`#session-export` викликає `buildSessionSnapshot` і `downloadSession`.
`#session-import` відкриває `#session-import-file`.
File change викликає `importSessionFile`.
`#language-toggle` пише `requestrider-language` і перерендерює i18n.
Workspace tab click викликає `selectWorkspace`.
Workspace create/close handlers змінюють Map і викликають persistence.

## Exact persistence flow

Input change -> `queueWorkspacePersistence`.
Timer 250 ms -> `persistWorkspaces`.
`persistWorkspaces` serializes contexts, active ID and snapshot.
Quota/serialization failures логуються через `console.warn`.
Reload -> `restorePersistedWorkspaces` -> `createWorkspace` fallback.
Export не звертається до Django.
Import валідовує version і `workspaceKinds` до запису.
Invalid state не стає active context.

## Contract

Серверного JSON payload для session немає.
Django `views.py` не має session endpoint.
Go engine не знає про browser workspace IDs.
Persisted state — localStorage, session file — downloaded JSON.
Intruder attack ID, Traffic cursor і Traffic cache зберігаються окремо.
Symbols/files: `persistWorkspaces`, `queueWorkspacePersistence`,
`buildSessionSnapshot`, `downloadSession`, `restoreSessionSnapshot`,
`importSessionFile`, `restorePersistedWorkspaces`, `index.html`.

## Трасування повного lifecycle

1. Startup читає language, workspace JSON і active ID. Невідомі `kind`,
   битий JSON або неповний context відкидаються; для відсутнього kind
   створюється безпечний default workspace.
2. Input change викликає debounce persistence. Перед записом active context
   capture-ить поточний DOM state, тому переключення вкладки не губить
   незбережені поля.
3. Tab click спочатку capture-ить старий context, потім restore-ить новий і
   перемальовує tool-specific dynamic state. Останній workspace kind не можна
   закрити, щоб UI не втратив точку входу.
4. Export збирає versioned snapshot, але не включає engine jobs, live SSE
   cache, secrets або server-side SQLite rows. Файл є переносимим описом
   browser state, а не backup усієї системи.
5. Import читає один файл, перевіряє version/contexts/kinds і лише після
   повної validation записує keys та reload-ить сторінку. Частковий або
   невалідний import не стає active state.
6. Language switch перерендерює labels, options, dynamic empty states і
   workspace default names. Збережений текст відомої локалі нормалізується
   через current dictionary; реальні operator values не перекладаються.
7. Clear tool state скидає лише конкретний context. Закриття workspace
   видаляє його з Map і renumber-ить siblings, але не видаляє durable
   History/Traffic/Project entities.

### Контрольні точки

`startup restore → capture → debounce persist → switch/close/create →
versioned export/import → language re-render → reload`. Перевіряйте quota,
corrupt file, unknown kind, duplicate active ID, language switch і відсутність
server requests під час локального autosave.
