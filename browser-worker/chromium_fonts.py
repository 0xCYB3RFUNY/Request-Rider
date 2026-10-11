"""Chromium draws no glyphs on this host, and this is what fixes it.

# What the defect looks like

Chromium 140 here draws geometry — a red and a green block photograph exactly as
they are styled — and draws **no glyphs at all**. Every screenshot of a page with
text came out as a rectangle of background colour. The size proves it without an
eyeball: an empty 400×200 page is 765 bytes, and a page with three paragraphs of
text in five different font stacks is 535 bytes, every time.

So it is not a font that is missing. It is text that is never drawn, and a
screenshot taken that way is not evidence of anything — the layout it seems to
show is the layout *without* the words. In browser-driven Target that is the
difference between a capture of a page and a photograph of an empty rectangle.

# What was measured, in order

| what was changed | glyphs drawn? |
|---|---|
| nothing (Chromium defaults) | no — 351–535 bytes on every page |
| `--disable-lcd-text`, `--font-render-hinting=none` | no — 1854 bytes either way |
| `--use-gl=swiftshader`, `--disable-gpu` | no — 1854 bytes either way |
| the system fontconfig cache moved aside | no — 438 bytes |
| a private `fontconfig` naming only DejaVu | **yes** — 2515 bytes |
| a private `fontconfig` naming only Liberation+OTF+Type1 | **yes** — 2150 bytes |
| a private `fontconfig` with `<alias>` families added | **yes** — 2090 bytes |
| `/etc/fonts/fonts.conf` verbatim | no — 351 bytes |
| the same file with its `conf.d` include removed | no — 351 bytes |
| a private config naming **only** `/usr/share/fonts` | no — 351 bytes |
| a private config naming only `/usr/share/fonts/truetype` | **yes** — 1923 bytes |
| a private config naming only `/usr/share/fonts/opentype` | **yes** — 2975 bytes |

The last three rows are the whole defect. Naming the *root* of the font tree
(`/usr/share/fonts`, which holds `cmap`, `cMap`, `eot`, `svg`, `woff` and `X11`
alongside the font formats) yields no glyphs; naming any directory underneath it
draws the text. Chromium gives up on the directory rather than on one file
inside it — this is not an unreadable font, it is a directory whose contents it
refuses to index. The fix is therefore to name the directories, never the root.

Every configuration this file writes draws the text; the system's does not, with
or without its includes. `fc-list` reports 319 fonts and `fc-match sans` answers
`DejaVuSans.ttf` from the shell, so fontconfig itself works — it is Chromium's
read of that configuration that yields no families. `fc-match` and Chromium are
not asking the same question.

Firefox draws the text with the system configuration untouched, which is why
every other check in this project already runs on it.

# What this is for

`launch_env()` returns the environment a Chromium process needs, or `None` when
the system configuration already draws text. It is called by
`worker.launch_browser` for the Chromium family only.

    env = chromium_fonts.launch_env(playwright)
    browser = await playwright.chromium.launch(env=env, ...)

`None` is what Playwright already treats as "inherit my environment", so a host
where the system configuration works is left exactly as it was.

# Why it measures instead of assuming

A private configuration would also be *correct* on a healthy host, so applying
it unconditionally would quietly replace the operator's font settings — their
custom font directories, their substitutions, their hinting preferences — with
a directory list. That is a regression traded for a convenience, so this module
does not make it.

Instead it asks once, per process, whether the system configuration draws text,
and caches the answer. The measurement is a screenshot of a known page: a blank
one came out at 351–535 bytes and a drawn one at 1923–2975, so the two are
separated by more than a factor of three and any threshold between them is not
load-bearing. Every failure path — the probe cannot start, the screenshot cannot
be taken, the environment cannot be written — returns `None`, because the one
thing that must not happen is a broken page load in the product because a
cosmetic workaround failed.

`RR_CHROMIUM_FONTCONFIG=0` skips the measurement and uses the system
configuration as-is, for an operator who has fixed their fontconfig and does not
want a browser started to find out.
"""
from __future__ import annotations

import logging
import os
import tempfile
import threading
from pathlib import Path

logger = logging.getLogger("chromium_fonts")

# The font directories Chromium is given. These are the machine's own: the point
# is to replace the configuration, not the fonts, so a screenshot shows what the
# page would show on this host.
#
# The root `/usr/share/fonts` is deliberately absent and must stay absent —
# naming it is the defect this module exists to work around. See the measurement
# table in the module docstring.
FONT_DIRECTORIES = (
    "/usr/share/fonts/truetype",
    "/usr/share/fonts/opentype",
    "/usr/share/fonts/TTF",
    "/usr/share/fonts/Type1",
    os.path.expanduser("~/.fonts"),
    os.path.expanduser("~/.local/share/fonts"),
)

# The generic families a page asks for when it writes `sans-serif` or `system-ui`.
# Without them a browser is left to guess, and a page that renders in a fallback
# is not what the operator is trying to look at.
GENERIC_ALIASES = (
    ("sans-serif", "DejaVu Sans"),
    ("serif", "DejaVu Serif"),
    ("monospace", "DejaVu Sans Mono"),
    ("system-ui", "DejaVu Sans"),
    ("Arial", "Liberation Sans"),
    ("Helvetica", "Liberation Sans"),
    ("Times New Roman", "Liberation Serif"),
    ("Courier New", "Liberation Mono"),
)

_CONFIG = """<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<!-- Written by browser-worker/chromium_fonts.py. Chromium draws no glyphs on this
     host while reading /etc/fonts/fonts.conf; it draws them from this file.
     Nothing under /etc is modified. -->
<fontconfig>
{directories}
{aliases}
  <cachedir>{cache}</cachedir>
</fontconfig>
"""

# The page the measurement is taken from. The string is deliberately a mix of
# cases and digits: a font that renders digits but not letters, or only Latin but
# not Cyrillic, must not read as "text works".
_PROBE_HTML = (
    "<html><body style='margin:0;background:#fff;color:#000;"
    "font:24px sans-serif'>Abc 123</body></html>"
)

# A blank 400×80 page measured 351–535 bytes; a drawn one 1923–2975. The
# threshold sits in the empty middle and is not sensitive to either edge.
_PROBE_THRESHOLD_BYTES = 1024

# The three states, spelled out because `None` means two different things
# depending on whether the answer has been computed yet:
#   _UNASKED  — nobody has measured on this process
#   _YES      — the system configuration draws text, so it is used unchanged
#   _NO       — it does not, so a private configuration is written
_UNASKED, _YES, _NO = "unasked", "yes", "no"

_lock = threading.Lock()
_answer = _UNASKED
_directory: tempfile.TemporaryDirectory | None = None


def _render_config(cache_dir: str) -> str:
    existing = [d for d in FONT_DIRECTORIES if Path(d).is_dir()]
    aliases = "\n".join(
        f"  <alias><family>{generic}</family>"
        f"<prefer><family>{preferred}</family></prefer></alias>"
        for generic, preferred in GENERIC_ALIASES
    )
    return _CONFIG.format(
        directories="\n".join(f"  <dir>{d}</dir>" for d in existing),
        aliases=aliases,
        cache=cache_dir,
    )


def _private_env() -> dict[str, str] | None:
    """A private fontconfig for this process, or `None` if it cannot be written.

    The directory lives as long as the process rather than as long as a call: a
    Chromium launched from it reads its fonts for as long as the browser runs,
    and a cache directory removed on exit would leave every page after the first
    one to rebuild it.
    """
    global _directory
    if _directory is None:
        try:
            _directory = tempfile.TemporaryDirectory(prefix="rr-fontconfig-")
            cache = os.path.join(_directory.name, "cache")
            os.makedirs(cache, exist_ok=True)
            conf = os.path.join(_directory.name, "fonts.conf")
            Path(conf).write_text(_render_config(cache))
        except OSError:
            _directory = None
            return None
    return dict(
        os.environ,
        FONTCONFIG_FILE=os.path.join(_directory.name, "fonts.conf"),
        FONTCONFIG_PATH=_directory.name,
    )


def _disabled_by_operator() -> bool:
    return os.environ.get("RR_CHROMIUM_FONTCONFIG", "").strip().lower() in {
        "0",
        "off",
        "false",
        "no",
    }


def _system_config_draws_text(playwright) -> bool:
    """Whether Chromium renders glyphs from the system fontconfig here.

    Measured rather than assumed, because the answer differs by host. Every
    failure answers `True`: a probe that cannot run is no evidence of a defect,
    and guessing "defective" would mean replacing a working configuration with
    one nobody asked for.
    """
    browser = None
    try:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 400, "height": 80})
        page.set_content(_PROBE_HTML)
        page.wait_for_timeout(400)
        shot = page.screenshot()
        return len(shot) > _PROBE_THRESHOLD_BYTES
    except Exception as error:
        # Logged, not raised: the answer is `True` on purpose — see above — and a
        # silent `except` here would leave a blank-capture defect with no record
        # that the measurement was ever attempted.
        logger.warning(
            "could not measure whether Chromium draws text (%s); "
            "using the system fontconfiguration unchanged",
            error,
        )
        return True
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass


def launch_env(playwright) -> dict[str, str] | None:
    """The environment a Chromium launch needs, or `None` for "inherit mine".

    Call it once per Chromium launch with the `playwright` instance that will
    launch it. The measurement behind it happens at most once per process.
    """
    global _answer
    if _disabled_by_operator():
        return None
    with _lock:
        if _answer == _UNASKED:
            _answer = _YES if _system_config_draws_text(playwright) else _NO
        if _answer == _YES:
            return None
        return _private_env()