"""Language of the server-rendered RequestRider report pages.

The application keeps its language in `localStorage`, which the server cannot
read. That is fine for a page the browser paints itself, and it is why the
reports used to carry both wordings in the markup and swap them in the browser.
A report is not painted that way: it is rendered here, once, and every string
it emits has to already be in the chosen language. So the same choice is also
written to a cookie, and the language is resolved here rather than guessed.

The rule this module exists to enforce: **a report speaks exactly the language
the workspace speaks.** A report in one language under an application in
another is the "переклад працює не завжди" defect in a different place, and it
is not acceptable here either.

Only wording the report itself owns is translated. Values that arrive from the
engine or from the data — a column name of the written file, an entity type, a
relation type, a provenance source, a file name, a graph name — are shown as
they arrived, in both languages, because translating them would mislabel the
data they stand for. `REPORT_LABELS` holds the invented labels; everything in it
must differ between the two languages, which a test asserts.
"""

# LANGUAGE_COOKIE is the same choice the application keeps in localStorage. The
# name matches the storage key so the two can never drift apart silently.
LANGUAGE_COOKIE = "requestrider-language"

LANGUAGES = ("en", "uk")

REPORT_LANGUAGE_DEFAULT = "en"

# REPORT_LABELS is every word a report page owns, in both languages. A key that
# has one value only would put an English sentence on a Ukrainian page, so the
# test walks this table and fails on a key the two languages share.
REPORT_LABELS = {
    "rows_in_file": ("rows in file", "рядків у файлі"),
    "matching": ("matching", "знайдено"),
    "on_disk": ("on disk", "на диску"),
    "graph": ("Graph", "Граф"),
    "back_to_workspace": ("← Back to workspace", "← Назад до воркспейсу"),
    "search": ("Search…", "Пошук…"),
    "search_aria": ("Search every column", "Пошук у всіх колонках"),
    "find": ("Find", "Знайти"),
    "reset": ("Reset", "Скинути"),
    "all_types": ("All types", "Усі типи"),
    "type_filter_aria": ("Filter by row type", "Фільтр за видом рядка"),
    "rows": ("Rows", "Рядки"),
    "of": ("of", "з"),
    "filtered_from": ("filtered from", "відфільтровано з"),
    "previous": ("Previous", "Назад"),
    "next": ("Next", "Далі"),
    "page_of": ("Page", "Сторінка"),
    "rows_per_page": ("Rows per page", "Рядків на сторінці"),
    "apply": ("Apply", "Застосувати"),
    "download": ("Download", "Завантажити"),
    "raw": ("Raw", "Сирий"),
    "files": ("Files", "Файли"),
    "no_match": ("No row matches this search.", "Жоден рядок не відповідає пошуку."),
    "hidden_columns": ("Hidden because no row uses them:", "Приховані, бо жоден рядок їх не використовує:"),
    "result_files": ("Result files", "Файли результатів"),
    "rows_in_total": ("rows in total", "рядків усього"),
    "file": ("File", "Файл"),
    "format": ("Format", "Формат"),
    "modified": ("Modified", "Змінено"),
    "actions": ("Actions", "Дії"),
    "view": ("View", "Переглянути"),
    "no_files_yet": (
        "This graph has no result files yet. A transform that returns more rows than the graph can hold writes them here.",
        "У цьому графі ще немає файлів результатів. Трансформація, яка повертає більше рядків, ніж може вмістити граф, записує їх сюди.",
    ),
    "switch_language": ("Switch language", "Змінити мову"),
    "open_file": ("Open file", "Відкрити файл"),
    # `link` is a label the report invented for a row that carries a relation
    # instead of a type. It is the one visible word on the page that is neither
    # data nor a column name, which is exactly why it has to be translated.
    "link": ("link", "зв’язок"),
}

# SCANNER_REPORT_LABELS is the same idea for the Scanner report, kept apart so
# that adding a scanner word cannot disturb the OSINT report's table, and so a
# test walking either dictionary walks only its own keys. Every pair differs
# between the two languages, for the reason the language test asserts.
#
# The per-status words are the ones that matter most here: they are what the
# report says about work that did or did not happen, so a status of `no_request`
# must never be worded the same as `not_matched`.
SCANNER_REPORT_LABELS = {
    "scanner.findings": ("findings", "знахідок"),
    "scanner.view_nuclei": ("Scanner · Nuclei", "Сканер · Nuclei"),
    "scanner.view_cms": ("Scanner · CMS", "Сканер · CMS"),
    "scanner.back_to_workspace": ("← Back to workspace", "← Назад до воркспейсу"),
    "scanner.files": ("files", "файлів"),
    "scanner.rejected": ("rejected", "відхилений"),
    "scanner.rejected_note": (
        "These values are not in the report's vocabulary and are shown, not counted:",
        "Ці значення не належать до словника звіту, вони показані, а не враховані:",
    ),
    "scanner.filtered_by": ("Filtered by", "Відфільтровано за"),
    "scanner.clear_filters": ("Clear filters", "Зняти фільтри"),
    "scanner.severity_filter": ("Filter by severity", "Фільтр за серйозністю"),
    "scanner.status_filter": ("Filter by file status", "Фільтр за статусом файлу"),
    "scanner.severity": ("Severity", "Серйозність"),
    "scanner.status": ("Status", "Статус"),
    "scanner.title": ("Title", "Назва"),
    "scanner.template": ("Template", "Шаблон"),
    "scanner.cve": ("CVE", "CVE"),
    "scanner.evidence": ("Evidence", "Доказ"),
    # `{count}` is the real character count the builder measured before it cut
    # the block, so the reader is told how much of the evidence is not shown.
    "scanner.evidence_truncated": (
        "Evidence truncated to {count} characters.",
        "Доказ обрізано до {count} символів.",
    ),
    "scanner.rows": ("rows", "рядків"),
    "scanner.statistic": ("Statistic", "Статистика"),
    "scanner.value": ("Value", "Значення"),
    "scanner.source_ip": ("source IP", "IP джерела"),
    "scanner.empty": (
        "This run produced no row that survives the report's vocabulary.",
        "Цей запуск не дав жодного рядка, який відповідає словнику звіту.",
    ),
    # Each status is a distinct claim about one file, so each one gets its own
    # wording. `not_matched` and `no_request` are the pair that must never share
    # a word: the first is "the check ran and found nothing", the second is "the
    # check never addressed the target at all".
    "scanner.status.matched": ("matched", "збіг"),
    "scanner.status.not_matched": ("not matched", "без збігу"),
    "scanner.status.no_request": ("made no request", "запиту не робило"),
    "scanner.status.skipped": ("skipped", "пропущено"),
    "scanner.status.invalid": ("invalid", "недійсний"),
    "scanner.status.duplicate": ("duplicate", "дубль"),
    "scanner.status.workflow": ("workflow", "воркфлоу"),
    # The two statuses that say the binary compiled nothing out of the file. They
    # are not "miss" and not "broken", and the report has to be able to say so in
    # its own words: a reader who sees `flow` alone cannot tell it from a status
    # that came from the operator's own filters.
    "scanner.status.flow": ("flow definition", "визначення потоку"),
    "scanner.status.uncompiled": ("not compiled", "не скомпільовано"),
    "scanner.status.unknown": ("not defined", "не визначено"),
    # A severity the engine did not declare is a fact about the template rather
    # than a word the report owns, and it is worded here instead of leaving a
    # blank cell that reads as "no severity".
    "scanner.severity.missing": ("not declared", "не задекларовано"),
}


def normalize_language(value):
    """Return a supported language code for any input."""
    code = str(value or "").strip().lower()
    if code.startswith("uk"):
        return "uk"
    if code.startswith("en"):
        return "en"
    return REPORT_LANGUAGE_DEFAULT


def report_language(request):
    """Resolve the language a report must be rendered in.

    The cookie is the only source. `Accept-Language` is deliberately ignored: a
    Ukrainian browser locale must not put a Ukrainian report under an English
    workspace, because the report belongs to the workspace and follows it.
    """
    if request is None:
        return REPORT_LANGUAGE_DEFAULT
    return normalize_language(request.COOKIES.get(LANGUAGE_COOKIE, ""))


def report_text(language, key):
    """Return one report label in the requested language.

    Both dictionaries are searched, with the shared one first. A key is either a
    page-level word or a scanner word and never both, so the order is a
    convenience rather than a resolution rule; what matters is that an unknown
    key still raises, because a label that silently renders as nothing is how a
    half-translated page happens.
    """
    pair = REPORT_LABELS.get(key)
    if pair is None:
        pair = SCANNER_REPORT_LABELS.get(key)
    if pair is None:
        raise KeyError(f"unknown report label: {key}")
    return pair[0] if normalize_language(language) == "en" else pair[1]


def set_report_language_cookie(response, language):
    """Write the language choice so the next report renders in it too.

    The cookie is a year long and `SameSite=Lax`, matching the session cookie's
    site policy: the report links out to the workspace, and a report opened from
    a link must still speak the workspace language.
    """
    response.set_cookie(
        LANGUAGE_COOKIE,
        normalize_language(language),
        max_age=60 * 60 * 24 * 365,
        samesite="Lax",
        path="/",
    )
    return response
