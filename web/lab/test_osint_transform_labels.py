"""Every transform the engine offers has to be named in both languages.

Measured 2026-10-02 against the engine registry: the wording used to live in a
hard-coded English table of thirteen entries while the engine offers sixteen, so
three transforms were shown to the operator as their raw identifier, and in the
Ukrainian UI not one name was translated.

The registry is the list of truth for *what is offered*; this file is the list of
truth for *how it is called*. Both have to cover the same sixteen, and the page
must not grow a second table that can fall out of date the way the first one did.
"""

import re
import unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "lab" / "index.html"

# The sixteen the engine registry offers, measured 2026-10-02.
TRANSFORM_IDS = (
    "url_host",
    "domain_normalize",
    "wayback_urls",
    "subdomains",
    "dns_records",
    "s3_buckets",
    "reverse_dns",
    "ip_geo",
    "email_recon",
    "email_domain",
    "username_normalize",
    "username_enum",
    "github_recon",
    "username_search",
    "git_secrets",
    "secret_scan",
    # 2026-10-07: `breach_exposure`, ported from `ibnaleem/gosearch` at commit
    # `687f9ed`. The twenty transforms above were measured 2026-10-02 and the
    # list was never bumped when `cidr_range`, `asn_lookup`, `technology_probe`
    # and `http_probe` arrived, which is exactly the drift this test exists to
    # catch — so the count is stated rather than implied.
    "breach_exposure",
    "identity_graph",
    "cidr_range",
    "asn_lookup",
    "technology_probe",
    # `http_probe` was added to the engine on 2026-10-03 and its two i18n keys
    # were written with it, but it was never added here — so this list covered
    # 19 of the engine's 20 and the miss was invisible, because the test only
    # asks whether a listed id has keys, never whether the engine offers an
    # unlisted one. `test_the_list_covers_every_transform_the_engine_offers` is
    # that second question.
    "http_probe",
)

# The engine registry, read from its own source. The list above is the list of
# truth for *how a transform is called*; this is the list of truth for *what is
# offered*, and nothing here is hand-maintained in a second place.
ENGINE_REGISTRY = (
    Path(__file__).resolve().parents[2] / "engine" / "osint_transforms.go"
)


def _engine_transform_ids() -> set:
    """Read `{"id": "...", ...}` out of the engine's registry literal."""
    text = ENGINE_REGISTRY.read_text(encoding="utf-8")
    marker = "var transformRegistry = []map[string]interface{}{"
    start = text.index(marker)
    end = text.index("\n}\n", start)
    # Only the literal itself, not the rest of the file: another map elsewhere in
    # `osint_transforms.go` may carry an `"id"` key, and reading past the closing
    # brace would let an unrelated id satisfy the coverage check.
    return set(re.findall(r'\{"id":\s*"([^"]+)"', text[start:end]))


def _dictionary(template: str, key: str):
    return re.findall(r"'" + re.escape(key) + r"'\s*:\s*'([^']*)'", template)


class OsintTransformLabelTests(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE.read_text(encoding="utf-8")

    def test_every_transform_has_a_name_in_both_languages(self):
        for transform in TRANSFORM_IDS:
            key = f"osint.transform.{transform}"
            with self.subTest(transform=transform):
                found = _dictionary(self.template, key)
                self.assertEqual(
                    len(found),
                    2,
                    f"{key} must be defined once per dictionary, found {len(found)}",
                )
                uk, en = found
                self.assertTrue(uk.strip(), f"{key} is empty in Ukrainian")
                self.assertTrue(en.strip(), f"{key} is empty in English")
                self.assertNotEqual(
                    uk, en, f"{key} is the same in both dictionaries, so one is not a translation"
                )

    def test_the_list_covers_every_transform_the_engine_offers(self):
        """The question the list could not answer about itself.

        Every other test in this file asks whether a *listed* id has keys. None
        of them asks whether the engine offers an id that is *not* listed — and
        that is exactly how `http_probe` sat in the engine with its two keys
        written and no row here, unnoticed from 2026-10-03 until `breach_exposure`
        made the registry twenty-one and someone counted.

        The list is maintained by hand, so this is a guard on the hand, not a
        replacement for it: the day a transform is added to the engine, this
        fails and names it.
        """
        offered = _engine_transform_ids()
        self.assertTrue(offered, "no transform ids were read from the engine registry")
        missing = sorted(offered - set(TRANSFORM_IDS))
        self.assertEqual(
            missing,
            [],
            f"the engine offers transforms with no row here: {missing}",
        )

    def test_no_second_table_of_names_survives(self):
        """The defect was a duplicate source of truth, so the guard is on the
        duplicate, not only on the missing keys."""
        self.assertNotIn(
            "OSINT_TRANSFORM_LABELS",
            self.template,
            "a hard-coded name table is back; the dictionary is the only source, "
            "otherwise it falls out of date exactly as it did before",
        )

    def test_the_label_is_read_from_the_dictionary(self):
        self.assertIn(
            "osint.transform.${id}",
            self.template,
            "the label must be looked up in the dictionary by transform id",
        )

    def test_an_unknown_id_falls_back_to_the_id(self):
        """A transform added to the engine tomorrow has no key yet. It must read
        as its own id rather than as an empty string or a stale neighbour."""
        body = re.search(
            r"function\s+osintTransformLabelForId\s*\([^)]*\)\s*\{(.*?)\n\}", self.template, re.S
        )
        self.assertIsNotNone(body, "osintTransformLabelForId is not declared")
        self.assertIn("osintTransformLabel", body.group(1))


class TransformLabelDictionaryTests(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE.read_text(encoding="utf-8")

    def test_the_fallback_exists_in_the_label_helper(self):
        """`osintTransformLabel` returns the input when the dictionary has no
        entry, which is what makes an unknown id readable."""
        self.assertIn(
            "return value === label ? label : value;",
            self.template,
            "osintTransformLabel must fall back to the key it was given, so an "
            "untranslated id stays visible instead of becoming empty",
        )


# The network flag has to come from the registry, not from a second list here.
#
# Measured 2026-10-03 from the browser: `username_search` failed with
# `NETWORK_CONFIRMATION_REQUIRED`. The page asked "is this a network transform?"
# with a hand-written array of six names and `username_search` was not in it, so the
# confirmation dialog never appeared and the engine refused a request the operator
# was never asked about. The same held for every network transform added after that
# array was written.
class OsintNetworkFlagComesFromTheRegistryTests(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE.read_text()

    def network_flag_code(self):
        """The code that decides whether a transform is network-using.

        The defect this class exists for was a second, hand-written list of
        transform ids consulted instead of the registry — the page asked "is this
        a network transform?" about an array of six names, `username_search` was
        not in it, and the engine refused a request the operator was never asked
        about. So the guard belongs on the code that asks the question, which is
        `osintTransformIsNetwork` and the single call site that consumes its
        answer.

        Scanning the whole page instead is what made this class useless: a
        substring search for `'subdomains'` matched three unrelated places added by
        the Target-enrichment session on 2026-10-03 — the English label
        `'target.enrichSubdomains': 'subdomains'`, the summary counter
        `sum('subdomains')` and the CSV column list — and failed a guard whose
        subject was correct. Measured here: three offenders, zero of them a
        network-flag list.

        Boundaries are the function's own, found from its name and the next
        top-level `async function`, so the guard follows the code rather than a
        line number that a neighbour's edit would move.
        """
        start = self.template.find("async function osintTransformIsNetwork(")
        self.assertNotEqual(start, -1, "the network-flag function was not found")
        end = self.template.find("\nasync function ", start + 1)
        self.assertNotEqual(end, -1, "the network-flag function is not closed by a sibling")
        return self.template[start:end]

    def test_the_page_carries_no_hand_written_list_of_network_transforms(self):
        code = self.network_flag_code()
        offenders = [
            name
            for name in ("reverse_dns", "dns_records", "subdomains")
            if f"'{name}'" in code
        ]
        self.assertEqual(
            offenders,
            [],
            "the page lists network transforms by name again; read the `network` flag "
            "off the registry entry the engine serves",
        )

    def test_the_guard_would_still_catch_a_real_offender(self):
        """A guard narrowed until it cannot fail is the same defect wearing a fix.

        So the scan is fed a synthetic offender of the shape it exists to catch — a
        quoted id inside an array, placed inside the network-flag function — and
        has to report it. Without this, "the guard passes" would say nothing about
        whether narrowing it left it working.
        """
        code = self.network_flag_code()
        for name in ("reverse_dns", "dns_records", "subdomains"):
            with_offender = code.replace(
                "  let capabilities = osintTransformCapabilities;",
                f"  if (['{name}'].includes(transform)) return true;\n"
                "  let capabilities = osintTransformCapabilities;",
                1,
            )
            self.assertNotEqual(with_offender, code, f"could not place the offender {name}")
            offenders = [
                candidate
                for candidate in ("reverse_dns", "dns_records", "subdomains")
                if f"'{candidate}'" in with_offender
            ]
            self.assertIn(name, offenders, f"{name} would not have been caught")

    def test_an_unrelated_quoted_id_elsewhere_is_not_an_offender(self):
        """The three real uses of `'subdomains'` that are not a network flag.

        Pinned by name and by value so a future edit that moves one of them into
        the flag function is caught by the guard above, and so nobody "fixes" this
        failure a second time by deleting a label the operator reads.
        """
        for snippet in (
            "'target.enrichSubdomains': 'subdomains'",  # English label
            "const subdomains = sum('subdomains');",  # enrichment counter
            "'secrets', 'subdomains'",  # CSV column list
        ):
            self.assertIn(snippet, self.template, snippet)
            self.assertNotIn(snippet, self.network_flag_code(), snippet)

    def test_the_flag_is_read_from_the_registry_entry(self):
        self.assertIn("async function osintTransformIsNetwork(", self.template)
        self.assertIn("entry && entry.network", self.template)
        self.assertIn(
            "const network = await osintTransformIsNetwork(transform);", self.template
        )

    def test_every_network_transform_in_the_registry_will_ask(self):
        """The list is the engine's, read from its own source file.

        Reading the engine source rather than repeating the ids here is the whole
        point: a second table in a test is the defect this file exists to prevent,
        repeated in the place that checks for it.
        """
        engine = Path(__file__).resolve().parents[2] / "engine" / "osint_transforms.go"
        source = engine.read_text()
        network_ids = set(re.findall(r'\{"id": "([a-z_]+)", "network": true', source))
        self.assertTrue(
            network_ids,
            "no network transforms found in the engine registry; the pattern or the "
            "registry changed and this test would otherwise pass on an empty set",
        )
        # The names must not appear as a bracket list anywhere: that shape is what a
        # hand-written roster looks like, and it is the shape that silently drops
        # every transform added after it was written.
        #
        # Scanned in the network-flag code rather than across the whole page, for
        # the reason the offender test above documents: the roster it hunts is the
        # one that answers "is this network-using", and a whole-page scan matches
        # the CSV export's column list — `['index', …, 'secrets', 'subdomains']` —
        # which is a list of column names and nothing to do with this flag. One
        # false positive is enough to make a guard unmaintained.
        code = self.network_flag_code()
        for transform in sorted(network_ids):
            self.assertNotRegex(
                code,
                r"\[[^\]]*'%s'" % transform,
                f"{transform} is listed by name in the page instead of read from the "
                "registry; it is network-using and the confirmation must be asked",
            )
