"""Підписи системного стану в шапці мають перекладатися.

Виміряно 2026-10-03 на живій цілі: в режимі UA підписи показували
`ENGINE`/`PROXY`/`ROUTE`. Причина не в словниках — `a11y.passiveProxy` має
українське значення — а в тому, що самі три `<span class="ss-label">` єдині в
шапці без `data-i18n`, тому `applyLanguage()` їх не торкався.

Тест перевіряє обидві половини: атрибут стоїть на кожній із трьох підписів, і
кожен ключ існує в обох словниках різними значеннями. Мутація (зняти
`data-i18n` з однієї підпису) робить тест червоним.
"""

import re
import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "lab" / "index.html"

# Три підписи шапки, які показують стан системи.
LABELS = {
    "Engine": "a11y.engineLabel",
    "Proxy": "a11y.proxyLabel",
    "Route": "a11y.routeLabel",
}


class HeaderStatusLabelTests(unittest.TestCase):
    def setUp(self):
        text = TEMPLATE.read_text(encoding="utf-8")
        inc = TEMPLATE.parent / "includes" / "_translations.html"
        if inc.exists():
            text += "\n" + inc.read_text(encoding="utf-8")
        self.template = text

    def test_every_header_status_label_is_bound_to_the_dictionary(self):
        for text, key in LABELS.items():
            with self.subTest(label=text):
                self.assertIn(f'data-i18n="{key}"', self.template,
                              f'the "{text}" label is not bound to a translation key')
                self.assertRegex(
                    self.template,
                    r'<span class="ss-label"\s+data-i18n="' + re.escape(key) + r'">' + text + r'</span>',
                    f'the "{text}" label is not the one carrying {key}',
                )

    def test_no_header_label_is_left_unbound(self):
        """The defect was an unbound label, so the guard is on every label."""
        unbound = re.findall(r'<span class="ss-label">(.*?)</span>', self.template)
        self.assertEqual(
            unbound, [],
            f"header labels without data-i18n: {unbound}",
        )

    def test_each_label_has_a_translation_that_differs_between_languages(self):
        for key in LABELS.values():
            with self.subTest(key=key):
                found = re.findall(r"'" + re.escape(key) + r"'\s*:\s*'([^']*)'", self.template)
                self.assertEqual(len(found), 2, f"{key}: {len(found)} entries, expected one per dictionary")
                uk, en = found
                self.assertTrue(uk.strip() and en.strip(), f"{key} is empty in one language")
                self.assertNotEqual(uk, en, f"{key} reads the same in both languages")


if __name__ == "__main__":
    unittest.main()