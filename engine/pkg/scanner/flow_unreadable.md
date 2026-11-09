# Реєстр: вирази `flow:`, які цей бігун ще не читає

Виміряно на офіційному корпусі (`/home/kali/Desktop/nuclei-templates`):

    усього документів з flow: 1900
    читається: 1877
    лишилось: 23

Кожен рядок — один документ із **виміряною** причиною: текст помилки парсера, а не
припущення. Три рядки вище читає
`TestTheUnreadableFlowRegistryMatchesWhatTheParserActuallyRefuses` (за
`RR_FLOW_CORPUS=1`), а `TestEveryRegistryRowIsActuallyUnreadable` падає вже в
кожному прогоні, якщо рядок називає те, чого в корпусі немає, або те, що парсер уже
читає. Саме цей тест зупинив мене цього turn: він показав, що шість рядків реєстру
вже неправдиві.

## Скільки чого потрібно

| можливість | документів |
|---|---:|
| `for (;;)` — лічильник розпізнано, але його умова ще не читається | 7 |
| тернарний `? :` та IIFE `(function () { … })()` | 5 |
| складання рядків `+` у значенні | 2 |
| `.spec` та інші члени об'єкта, якого немає в мапі | 1 |
| `Array.isArray` | 1 |
| `.forEach` | 1 |
| значення, яким `set` не може скористатися | 1 |
| визначення функції з циклом і побітовими операціями | 2 |

**23 залишки — це один шар виразів JavaScript плюс лічильник у циклі, який уже
розпізнається і якому бракує умови.**

## Реєстр

| # | документ | причина, виміряна парсером |
|---:|---|---|
| 1 | `cloud/azure/storageaccounts/azure-blob-immutable-not-enabled.yaml` | член на розпарсеному JSON з великої літери + присвоєння |
| 2 | `cloud/gcp/loadbalancing/gcloud-alb-ssl-google-managed.yaml` | ланцюг членів на розпарсеному JSON |
| 3 | `cloud/kubernetes/kubernetes-exposing-docker-socket-hostpath.yaml` | ! + метод hasOwnProperty + ланцюг членів |
| 4 | `http/cves/2021/CVE-2021-28480.yaml` | складання рядків + та виклик toLowerCase на значенні |
| 5 | `http/cves/2021/CVE-2021-28481.yaml` | складання рядків + та виклик toLowerCase на значенні |
| 6 | `http/cves/2022/CVE-2022-31101.yaml` | тернарний оператор ? : з дужковими гілками |
| 7 | `http/cves/2023/CVE-2023-6063.yaml` | for (;;) з лічильником |
| 8 | `http/cves/2024/CVE-2024-4040.yaml` | ! та метод hasOwnProperty на значенні шаблону |
| 9 | `http/cves/2024/CVE-2024-6670.yaml` | виклик replace + ключове слово const |
| 10 | `http/cves/2024/CVE-2024-6671.yaml` | виклик replace + ключове слово const |
| 11 | `http/cves/2025/CVE-2025-29927.yaml` | функція-літерал, присвоєна змінній |
| 12 | `http/cves/2025/CVE-2025-51586.yaml` | інлайн-коментарі з `//` між твердженнями |
| 13 | `http/cves/2026/CVE-2026-26265.yaml` | Array.isArray та індексація масиву |
| 14 | `http/cves/2026/CVE-2026-34413.yaml` | for (;;) з лічильником |
| 15 | `http/cves/2026/CVE-2026-3584.yaml` | масивний літерал + for (;;) + .length |
| 16 | `http/cves/2026/CVE-2026-4257.yaml` | порожні літерали [] та {} та ! на елементі |
| 17 | `http/cves/2026/CVE-2026-48558.yaml` | IIFE (function () { … })() + parseInt та isNaN |
| 18 | `http/cves/2026/CVE-2026-82222.yaml` | виклик charAt, += та for (;;) |
| 19 | `http/cves/2026/CVE-2026-86426.yaml` | вкладений масивний літерал + for (;;) + .length + JSON.stringify |
| 20 | `http/cves/2026/CVE-2026-9082.yaml` | масивний літерал + for (;;) + .length |
| 21 | `http/miscellaneous/directory-listing.yaml` | визначення і виклик функції + метод startsWith |
| 22 | `javascript/cves/2026/CVE-2026-48908.yaml` | визначення функції з побітовими операціями та циклом у flow |
| 23 | `javascript/cves/2026/CVE-2026-48909.yaml` | складання рядків + у flow шаблона javascript: |
