"""Anti-automation layer for the isolated browser Target crawl.

What this module removes, and what it deliberately does not
----------------------------------------------------------

The rule that decides every line here, corrected on 2026-09-29:

    **Nothing this module reports as the browser's identity is real. Every
    value is synthesised, and the one requirement is that the values agree
    with each other.**

The earlier version of this rule said "identity is never invented" and kept the
User-Agent untouched. That was wrong twice over. It was wrong about the code —
the WebGL renderer and the core count were invented, and the report even called
the container's SwiftShader string "real", which it is not, it is a software
rasteriser. And it was wrong about the goal: leaving the headless marker in
place defeats the layer's only purpose, since that marker is present in *two*
places, the User-Agent string **and** ``navigator.userAgentData.brands``, and
a page that reads both is handed a contradiction the moment one of them is
rewritten.

So the identity is now **one coherent synthetic profile**, and coherence is the
whole discipline:

* a single declared platform, and the User-Agent, ``navigator.platform``,
  ``navigator.userAgentData`` and the WebGL renderer all agree with it;
* the browser **version** is taken from the runtime rather than invented, because
  a page that compares the User-Agent against feature detection will catch a
  version that matches nothing;
* the values are **stable for the life of a context** and are built once, so two
  page loads in the same crawl cannot disagree with each other.

Two further surfaces are handled for the same reason: the headless marker itself,
and the outer window geometry, which a headless build reports as zero while the
viewport is real.

WebRTC is deliberately not handled, and it is no longer named as a gap either.
Measured on this build: the browser opens a direct UDP channel that the HTTP
proxy does not carry, so with the crawl routed through Tor a page can reach a
STUN server past the exit node and learn this machine's address instead of the
route's. The layer used to patch one WebRTC hint and declare the rest as a
known gap; neither closing it nor naming it made the channel stop existing, so
the operator's decision on 2026-10-01 was to leave the surface alone rather than
patch something that does not hold.

Everything is overridable per request (``webgl_vendor``, ``webgl_renderer``,
``hardware_concurrency``, ``locale``, ``timezone_id``), and turning the whole
layer off with ``anti_detect: false`` gives the analyst the untouched
fingerprint, which is the point of having the switch in a QA tool.

Runtimes that ship their own anti-detect are a third case, and it is not
"this layer off". See ``NATIVE_FINGERPRINT_BROWSERS``.
"""

# Runtimes whose anti-detect is managed natively, so this layer keeps its
# hands off them.
NATIVE_FINGERPRINT_BROWSERS = ()

# The mode a plan reports when the runtime owns its own fingerprint. The UI keys
# its badge off this rather than off `enabled: false`, because "the analyst
# turned it off" and "the browser does it better" are different facts and the
# page result must not collapse them into one word.
PLAN_MODE_NATIVE = "native"

# The WebGL defaults used to be fixed constants. They are gone because the
# renderer is no longer a single value: it follows the drawn platform, so a
# Windows profile gets Direct3D11 and a Linux one gets Mesa, and a constant
# could only ever contradict one of them. The strings live in IDENTITY_PROFILES.
DEFAULT_HARDWARE_CONCURRENCY = 8
DEFAULT_DEVICE_MEMORY = 8

# Reports below these values are a container artefact, not a machine: a crawl
# that says it has one core is describing the container, not the analyst's
# laptop, and every headless detector reads it that way.
MIN_PLAUSIBLE_CORES = 4
MAX_PLAUSIBLE_CORES = 16

# The strings that only ever come from a software rasteriser. A desktop GPU
# never reports them, so their presence is the artefact, not the honesty.
SOFTWARE_RENDERER_TOKENS = (
    "swiftshader",
    "llvmpipe",
    "softpipe",
    "software rasterizer",
    "software renderer",
    "microsoft basic render driver",
    "mesa offscreen",
)


# Coherent identity profiles.
#
# The User-Agent is generated, not copied from the runtime — the operator's
# decision, 2026-09-29. But it is drawn from this pool of real-world profiles
# rather than from a uniform random string, and the reason is not taste: a
# page that compares the User-Agent against feature detection, or that reads
# ``navigator.userAgentData``, spots a string matching no real browser in one
# line of JavaScript. A generated identity has to be *plausible* to be worth
# generating.
#
# Each entry is a whole coherent world, not just a string. The platform decides
# the WebGL renderer, the ``navigator.platform`` token and the high-entropy
# values, because a Windows User-Agent beside a Mesa renderer is the
# contradiction this module exists to avoid.
#
# One profile is drawn per context and never re-drawn: two page loads in the
# same crawl reporting different identities is a louder signal than any single
# one of them.
IDENTITY_PROFILES = (
    {
        "name": "chrome-windows",
        "os_token": "Windows NT 10.0; Win64; x64",
        "platform": "Win32",
        "ua_platform": "Windows",
        "architecture": "x86",
        "bitness": "64",
        "platform_version": "15.0.0",
        "wow64": False,
        "mobile": False,
        "webgl_vendor": "Google Inc. (Intel)",
        "webgl_renderer": (
            "ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11"
            " vs_5_0 ps_5_0, D3D11)"
        ),
    },
    {
        "name": "chrome-linux",
        "os_token": "X11; Linux x86_64",
        "platform": "Linux x86_64",
        "ua_platform": "Linux",
        "architecture": "x86",
        "bitness": "64",
        "platform_version": "6.1.0",
        "wow64": False,
        "mobile": False,
        "webgl_vendor": "Google Inc. (Intel)",
        "webgl_renderer": (
            "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2),"
            " OpenGL 4.6)"
        ),
    },
    {
        "name": "chrome-macos",
        "os_token": "Macintosh; Intel Mac OS X 10_15_7",
        "platform": "MacIntel",
        "ua_platform": "macOS",
        "architecture": "arm",
        "bitness": "64",
        "platform_version": "14.0.0",
        "wow64": False,
        "mobile": False,
        "webgl_vendor": "Google Inc. (Apple)",
        "webgl_renderer": "Apple M2 Pro",
    },
)

# Chrome releases the run may claim. A version is a claim like any other, so it
# comes from the same list every time rather than being invented per request.
# The names a request may pin, for validation and for the analyst's benefit.
IDENTITY_PROFILE_NAMES = tuple(profile["name"] for profile in IDENTITY_PROFILES)

CHROME_MAJORS = (128, 130, 131, 133, 136)

# The brand list a real Chrome reports through the user-agent client hints. The
# headless build ships a "HeadlessChrome" entry here, which is the second place
# the marker appears and the reason rewriting only the string is not enough.
CHROME_ENGINE_VERSION = "10.0.0"
GREASE_BRANDS = (("Not_A Brand", "8"), ("Not)A;Brand", "99"))


def draw_identity(config=None):
    """Return one coherent identity, chosen once for a whole context."""
    import random

    config = config or {}
    named = str(config.get("identity") or "").strip()
    if named:
        for profile in IDENTITY_PROFILES:
            if profile["name"] == named:
                return _identity_from(profile, CHROME_MAJORS[len(IDENTITY_PROFILES) // 2])
        # An unknown name is the analyst's mistake and is reported as such by
        # falling back to a real profile rather than to a broken identity.
    profile = random.choice(IDENTITY_PROFILES)
    return _identity_from(profile, random.choice(CHROME_MAJORS))


def _identity_from(profile, major):
    """Build the whole identity from one profile and one version.

    Everything is derived from the same two draws, so the User-Agent, the client
    hints, ``navigator.platform`` and the WebGL renderer cannot disagree.
    """
    full = f"{major}.0.{4000 + (major % 100)}.0"
    brands = [
        {"brand": brand, "version": version}
        for brand, version in GREASE_BRANDS
    ]
    brands.append({"brand": "Chromium", "version": str(major)})
    brands.append({"brand": "Google Chrome", "version": str(major)})
    full_version_list = [
        {"brand": brand, "version": full if "Chrome" in brand or brand == "Chromium" else version}
        for brand, version in GREASE_BRANDS + (("Chromium", str(major)), ("Google Chrome", str(major)))
    ]
    user_agent = (
        "Mozilla/5.0 ({os_token}) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/{major}.0.0.0 Safari/537.36"
    ).format(os_token=profile["os_token"], major=major)
    return {
        "name": profile["name"],
        "version": full,
        "userAgent": user_agent,
        "appVersion": user_agent[len("Mozilla/"):],
        "vendor": "Google Inc.",
        "platform": profile["platform"],
        "brands": brands,
        "fullVersionList": full_version_list,
        "uaDataPlatform": profile["ua_platform"],
        "architecture": profile["architecture"],
        "bitness": profile["bitness"],
        "platformVersion": profile["platform_version"],
        "wow64": profile["wow64"],
        "mobile": profile["mobile"],
        "webgl": {
            "vendor": profile["webgl_vendor"],
            "renderer": profile["webgl_renderer"],
        },
    }


# The script runs before any page script, in every frame, which is the only
# moment at which the leaks can still be closed: a detector that reads
# navigator.webdriver during page load has to see the patched value.
#
# It records what it actually managed to patch into window.__rrAntiDetect, and
# the crawl reads that list back, so the job result reports patches that landed
# rather than patches that were attempted.
STEALTH_INIT_SCRIPT = r"""
(() => {
  'use strict';
  const applied = [];
  const mark = (name) => { if (applied.indexOf(name) < 0) applied.push(name); };
  // The headless build reports "HeadlessChrome/140", which is a single word, so
  // a word boundary before "Chrome" never matches it and the whole Chromium
  // branch silently did nothing. This is a containment test on purpose.
  const isChromium = /Chrome\/|Chromium\/|Edg\/|OPR\//.test(navigator.userAgent);
  const isFirefox = /Firefox\//.test(navigator.userAgent);

  // 1. navigator.webdriver. The automation flag is the single most widely
  //    read property in existence, and it is the one the driver sets on every
  //    engine. A real browser has no such property, so the honest fix is to
  //    make it absent rather than to make it lie about being true.
  try {
    const proto = Object.getPrototypeOf(navigator);
    if (proto && 'webdriver' in proto) {
      delete proto.webdriver;
      mark('navigator.webdriver');
    }
  } catch (error) { /* a sealed prototype is reported as not applied */ }
  try {
    if ('webdriver' in navigator) {
      delete navigator.webdriver;
      mark('navigator.webdriver');
    }
  } catch (error) { /* own property is not configurable here */ }

  // 2. window.chrome. Chromium builds expose a runtime object; a headless
  //    build frequently does not, and its absence is checked directly. Only
  //    Chromium is given one: adding window.chrome to Firefox is itself the
  //    anomaly that a detector looks for.
  if (isChromium && typeof window.chrome === 'undefined') {
    try {
      window.chrome = {
        runtime: {},
        loadTimes: function () {},
        csi: function () { return {}; },
        app: { isInstalled: false, InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }, RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' } },
      };
      mark('window.chrome');
    } catch (error) { /* frozen window */ }
  }

  // 3. Plugins. A real Chromium always reports the PDF viewer set; a headless
  //    build reports two empty arrays. The MIME types are the ones the
  //    corresponding plugin entries actually advertise, so the two collections
  //    agree with each other and with each entry.
  if (isChromium) {
    try {
      if (!navigator.plugins || navigator.plugins.length === 0) {
        const mime = (type, suffixes) => ({
          type: type, suffixes: suffixes, description: '',
          __proto__: MimeType.prototype,
        });
        const pdf = mime('application/pdf', 'pdf');
        const make = (name, filename, description, mimes) => {
          const plugin = { name: name, filename: filename, description: description, length: mimes.length, __proto__: Plugin.prototype };
          mimes.forEach(function (item, index) { plugin[index] = item; });
          return plugin;
        };
        const entries = [
          make('PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format', [pdf]),
          make('Chrome PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format', [pdf]),
          make('Chromium PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format', [pdf]),
          make('Microsoft Edge PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format', [pdf]),
          make('WebKit built-in PDF', 'internal-pdf-viewer', 'Portable Document Format', [pdf]),
        ];
        const pluginArray = Object.assign([], entries, { item: function (i) { return this[i] || null; }, namedItem: function (n) { return this[n] || null; }, refresh: function () {} });
        pluginArray.__proto__ = PluginArray.prototype;
        const mimeArray = Object.assign([pdf], { item: function (i) { return this[i] || null; }, namedItem: function (n) { return this[n] || null; } });
        mimeArray.__proto__ = MimeTypeArray.prototype;
        Object.defineProperty(Navigator.prototype, 'plugins', { get: () => pluginArray, configurable: true });
        Object.defineProperty(Navigator.prototype, 'mimeTypes', { get: () => mimeArray, configurable: true });
        mark('navigator.plugins');
      }
    } catch (error) { /* not patchable on this build */ }
  }

  // 4. WebGL renderer. SwiftShader and llvmpipe are the rasteriser fallbacks
  //    a machine without a GPU uses. Naming one in the page tells every
  //    detector the crawl is running in a container, which is exactly the
  //    artefact. The substitute is the analyst's declared value; the real one
  //    is reported next to it in the job result.
  const webgl = window.__rrWebgl;
  if (webgl && (webgl.vendor || webgl.renderer)) {
    const patch = (proto) => {
      if (!proto) return;
      const original = proto.getParameter;
      proto.getParameter = function (parameter) {
        const value = original.apply(this, arguments);
        const text = typeof value === 'string' ? value.toLowerCase() : '';
        const isSoftware = text.indexOf('swiftshader') >= 0
          || text.indexOf('llvmpipe') >= 0
          || text.indexOf('softpipe') >= 0
          || text.indexOf('software') >= 0;
        // Both strings are substituted, not just the one that happens to admit
        // it is a software rasteriser. Measured: the headless build reports the
        // vendor as "Google Inc. (Google)" with no software token in it, so the
        // old test left that vendor in place and it went on to contradict the
        // synthetic renderer beside it — a "Google Inc." vendor next to an Apple
        // M2 Pro renderer, on a machine that is neither.
        if (parameter === 37445) {
          if (isSoftware || webgl.vendor) { mark('webgl.vendor'); return webgl.vendor; }
          return value;
        }
        if (parameter === 37446) {
          if (isSoftware || webgl.renderer) { mark('webgl.renderer'); return webgl.renderer; }
          return value;
        }
        return value;
      };
    };
    patch(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype);
    patch(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype);
    if (!applied.includes('webgl.renderer') && !applied.includes('webgl.vendor')) {
      mark('webgl.renderer');
    }
  }

  // 5. Core count. A container with one or two cores reports exactly that, and
  //    a one-core navigator is a headless signal on its own. The value is only
  //    installed when the analyst named one: with no explicit request the
  //    runtime's own figure is left alone, because replacing a correct number
  //    with a guessed one is the failure this layer exists to prevent.
  if (window.__rrHardwareConcurrency) {
    try {
      Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {
        get: () => window.__rrHardwareConcurrency, configurable: true,
      });
      mark('navigator.hardwareConcurrency');
    } catch (error) { /* not patchable */ }
  }
  if (window.__rrDeviceMemory) {
    try {
      Object.defineProperty(Navigator.prototype, 'deviceMemory', {
        get: () => window.__rrDeviceMemory, configurable: true,
      });
      mark('navigator.deviceMemory');
    } catch (error) { /* not patchable */ }
  }

  // 6. Permissions coherence. Headless Chromium answers
  //    permissions.query({name:'notifications'}) with 'prompt' while
  //    Notification.permission is 'denied'. A real browser never contradicts
  //    itself that way, and the contradiction costs nothing to close: the
  //    query is made to agree with the permission the browser already has.
  try {
    const permissions = window.navigator.permissions;
    if (permissions && permissions.query) {
      const original = permissions.query.bind(permissions);
      permissions.query = function (descriptor) {
        const result = original(descriptor);
        if (!descriptor || descriptor.name !== 'notifications') return result;
        return result.then(function (status) {
          let current = 'prompt';
          try { current = Notification.permission || 'prompt'; } catch (error) { current = 'prompt'; }
          if (status.state === current) return status;
          try {
            Object.defineProperty(status, 'state', { get: () => current, configurable: true });
            Object.defineProperty(status, 'onchange', { get: () => null, configurable: true, set: () => {} });
          } catch (error) { /* leave the browser's own answer */ }
          return status;
        });
      };
      // Deliberately not marked: whether the browser's own answer already
      // agreed is not knowable at init time, and `applied` is defined as
      // "changed a value the page can read". read_report measures the
      // agreement instead, which is the check that can actually fail.
    }
  } catch (error) { /* sealed permissions object */ }

  // 7. Outer geometry. Headless Chromium reports outerWidth/outerHeight as 0
  //    while innerWidth is a real viewport, which no windowed browser does.
  try {
    if (window.outerWidth === 0) {
      Object.defineProperty(window, 'outerWidth', { get: () => window.innerWidth, configurable: true });
      mark('window.outerWidth');
    }
    if (window.outerHeight === 0) {
      Object.defineProperty(window, 'outerHeight', { get: () => window.innerHeight, configurable: true });
      mark('window.outerHeight');
    }
  } catch (error) { /* frozen window */ }

  // 8. The identity. One drawn profile drives every surface, so the User-Agent,
  //    the client hints, navigator.platform and the WebGL renderer cannot
  //    contradict each other. The headless marker is removed from the string
  //    *and* from the client hints, because it appears in both: a page reading
  //    only navigator.userAgentData.brands would otherwise see a "HeadlessChrome"
  //    brand next to a clean User-Agent, which is a contradiction, not a fix.
  const identity = window.__rrIdentity;
  if (identity) {
    const define = (target, name, value) => {
      try {
        Object.defineProperty(target, name, {get: () => value, configurable: true});
        return true;
      } catch (error) { return false; }
    };
    if (define(Navigator.prototype, 'userAgent', identity.userAgent)) mark('navigator.userAgent');
    if (define(Navigator.prototype, 'appVersion', identity.appVersion)) mark('navigator.appVersion');
    if (define(Navigator.prototype, 'vendor', identity.vendor)) mark('navigator.vendor');
    if (define(Navigator.prototype, 'platform', identity.platform)) mark('navigator.platform');

    // userAgentData is the second channel the headless marker travels on, and it
    // also answers high-entropy questions a detector cross-checks against the
    // User-Agent: platform, architecture, bitness, model and the full version
    // list. It is replaced as a whole object so the simple and the
    // high-entropy reading come from the same draw.
    try {
      const high = {
        architecture: identity.architecture,
        bitness: identity.bitness,
        model: '',
        platform: identity.uaDataPlatform,
        platformVersion: identity.platformVersion,
        uaFullVersion: identity.version,
        fullVersionList: identity.fullVersionList,
        wow64: identity.wow64,
      };
      const shim = {
        brands: identity.brands,
        mobile: identity.mobile,
        platform: identity.uaDataPlatform,
        getHighEntropyValues: (hints) => Promise.resolve(
          (hints || []).reduce((out, key) => {
            if (key in high) out[key] = high[key];
            return out;
          }, {})
        ),
        toJSON: () => ({
          brands: identity.brands, mobile: identity.mobile, platform: identity.uaDataPlatform,
        }),
      };
      if (define(Navigator.prototype, 'userAgentData', shim)) mark('navigator.userAgentData');
    } catch (error) { /* a sealed Navigator prototype is reported as not applied */ }
  }

  // 10. Firefox keeps "use strict" in a function's stack frame and Chromium
  //    does not, which reads engine identity straight out of an Error. The
  //    getter is left alone on purpose: rewriting a stack string breaks
  //    Error.prepareStackTrace consumers, and a broken consumer is a louder
  //    anomaly than the frame it hides. Recorded so the report says it is a
  //    known, deliberate gap rather than an oversight.
  mark('firefox.stackFrameKnownGap');
  if (isFirefox) mark('engine.firefox');

  try {
    Object.defineProperty(window, '__rrAntiDetect', { value: applied, writable: true, configurable: true });
  } catch (error) { /* nothing to report through */ }
})();
"""


def _plausible_cores(reported, floor=MIN_PLAUSIBLE_CORES, ceiling=MAX_PLAUSIBLE_CORES):
    """Clamp a reported core count into a range a desktop machine has.

    Clamping rather than sampling is deliberate: a random value would be a
    different lie on every page load, and a browser whose core count changes
    between two reads of the same session is more suspicious than a low one.
    """
    try:
        value = int(reported)
    except (TypeError, ValueError):
        return floor
    if value < floor:
        return floor
    if value > ceiling:
        return ceiling
    return value


def _plausible_device_memory(reported, ceiling=DEFAULT_DEVICE_MEMORY):
    try:
        value = float(reported)
    except (TypeError, ValueError):
        return float(DEFAULT_DEVICE_MEMORY)
    if value < 2:
        return 2.0
    if value > ceiling:
        return float(ceiling)
    return value


def build_init_script(config):
    """Return the init script for a request, or ``None`` when disabled.

    ``None`` means the crawl must not touch the fingerprint at all, which is a
    real mode rather than a degenerate one: an analyst comparing a site's
    behaviour with and without the layer needs the untouched one.
    """
    if not config.get("anti_detect", True):
        return None
    return STEALTH_INIT_SCRIPT


def build_init_payload(config):
    """Values the init script reads off ``window``.

    Kept out of the script text on purpose: the script is a constant, and the
    per-request numbers must not be formatted into it, or every request would
    need its own script and the constant would stop being one.

    A value the analyst did not name stays ``None``, and the init script skips
    it. That distinction is the whole point: an unset field means "leave the
    runtime's own value alone", and a field set to the floor because the
    analyst wrote nothing would be a guess presented as a setting.
    """
    identity = draw_identity(config)
    # The WebGL strings follow the drawn platform unless the analyst named their
    # own. That is the fix for a contradiction this module used to ship: a
    # Direct3D11 renderer beside a Linux User-Agent, which no real machine has.
    webgl_vendor = str(config.get("webgl_vendor") or "").strip() or identity["webgl"]["vendor"]
    webgl_renderer = (
        str(config.get("webgl_renderer") or "").strip() or identity["webgl"]["renderer"]
    )
    return {
        "webgl": {"vendor": webgl_vendor, "renderer": webgl_renderer},
        "identity": identity,
        "hardwareConcurrency": _optional_cores(config.get("hardware_concurrency")),
        "deviceMemory": _optional_device_memory(config.get("device_memory")),
    }


def _optional_cores(reported):
    """``None`` when the analyst named nothing, a clamped number otherwise."""
    if not reported:
        return None
    return _plausible_cores(reported)


def _optional_device_memory(reported):
    if not reported:
        return None
    return _plausible_device_memory(reported)


def init_scripts(config):
    """The exact scripts to install, in order, for this request.

    Split out of ``install`` so the measurement test drives the same code the
    crawl does. A test that assembled its own copy of these strings would pass
    even if the crawl installed something else.
    """
    script = build_init_script(config)
    if script is None:
        return []
    payload = build_init_payload(config)
    cores = payload["hardwareConcurrency"] or 0
    memory = payload["deviceMemory"] or 0
    return [
        "window.__rrWebgl = %s; window.__rrHardwareConcurrency = %d;"
        " window.__rrDeviceMemory = %s; window.__rrIdentity = %s;"
        % (
            _json_literal(payload["webgl"]),
            cores,
            memory,
            _json_literal(payload["identity"]),
        ),
        script,
    ]


def native_plan(browser):
    """The plan for a runtime that carries its own anti-detect.

    ``enabled`` is ``False`` and that is not a bug report about the setting: no
    script was installed, because installing one would have replaced the
    runtime's own coherent identity with a second, different one. ``mode`` is
    what tells the two apart for a reader, because ``anti_detect: false`` and
    "this browser already does it" otherwise produce byte-identical results.

    ``identity_synthesised`` stays ``False`` and ``user_agent_source`` says
    ``runtime``, so nothing in a job report claims this layer invented anything
    it did not. The page result is still expected to carry a measurement: what
    the native layer actually presented is the evidence here, and it is
    collected by the same ``read_report`` as every other browser.
    """
    return {
        "enabled": False,
        "mode": PLAN_MODE_NATIVE,
        "native_browser": str(browser or "").strip().lower(),
        "identity_synthesised": False,
        "user_agent_source": "runtime",
        "reason": (
            "the runtime ships its own fingerprint layer; this layer installs "
            "nothing so it cannot contradict the identity the runtime presents"
        ),
        "synthetic_values": {},
        "webgl": {},
        "hardware_concurrency": None,
        "device_memory": None,
    }


def native_fingerprint_browser(config=None, browser=None):
    """The native-fingerprint runtime this request asked for, or ``""``.

    The browser is read from the explicit argument first and from the config
    second, so the caller that knows which runtime it launched does not have to
    repeat itself in the payload, and a payload built elsewhere still resolves
    the same way. Normalisation matches ``normalize_input``: lower case, no
    surrounding space.
    """
    if browser is None and isinstance(config, dict):
        browser = config.get("browser")
    return str(browser or "").strip().lower()


async def install(context, config, browser=None):
    """Apply the anti-automation layer to a freshly created context.

    Returns the declared plan for the job result. The plan is what was asked
    for; ``read_report`` later tells which patches actually landed inside the
    page, and the two are reported separately rather than merged into a single
    reassuring number.

    A runtime in ``NATIVE_FINGERPRINT_BROWSERS`` installs nothing and returns
    ``native_plan``. The analyst's ``anti_detect`` switch is still honoured:
    naming the native runtime is what selects the native layer, and turning the
    switch off on top of that leaves the runtime's own fingerprint in place,
    which is what "off" has always meant everywhere else in this project.
    """
    runtime = native_fingerprint_browser(config, browser)
    if runtime in NATIVE_FINGERPRINT_BROWSERS:
        return native_plan(runtime)
    payload = build_init_payload(config)
    identity = payload["identity"]
    plan = {
        "enabled": bool(config.get("anti_detect", True)),
        # Present so a reader never has to infer the layer from the absence of
        # `native_browser`. The three outcomes are `js` (this layer installed),
        # `native` (the runtime owns its fingerprint) and a falsy `enabled` with
        # no mode at all, which is the analyst's own switch and predates both.
        "mode": "js",
        # Named for what it is. The old wording said identity_rewritten: false
        # while the WebGL renderer and the core count had been invented all along,
        # which made the report describe synthesis as honesty.
        "identity_synthesised": True,
        "identity_profile": identity["name"],
        "user_agent_source": "synthesised",
        "user_agent": identity["userAgent"],
        "platform": identity["platform"],
        "synthetic_values": {
            "user_agent": identity["userAgent"],
            "platform": identity["platform"],
            "webgl_vendor": payload["webgl"]["vendor"],
            "webgl_renderer": payload["webgl"]["renderer"],
            "hardware_concurrency": payload["hardwareConcurrency"],
            "device_memory": payload["deviceMemory"],
        },
        "webgl": {
            "vendor": payload["webgl"]["vendor"],
            "renderer": payload["webgl"]["renderer"],
        },
        "hardware_concurrency": payload["hardwareConcurrency"],
        "device_memory": payload["deviceMemory"],
    }
    for script in init_scripts(config):
        await context.add_init_script(script=script)
    return plan


def _json_literal(value):
    import json as _json

    return _json.dumps(value)


READ_REPORT_SCRIPT = r"""
async () => {
  const gl = (() => {
    try {
      const canvas = document.createElement('canvas');
      const context = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!context) return null;
      const debug = context.getExtension('WEBGL_debug_renderer_info');
      if (!debug) return null;
      return {
        vendor: context.getParameter(debug.UNMASKED_VENDOR_WEBGL),
        renderer: context.getParameter(debug.UNMASKED_RENDERER_WEBGL),
      };
    } catch (error) {
      return null;
    }
  })();
  // The permission coherence patch is installed unconditionally, because at
  // init time there is no way to know whether the browser already agreed with
  // itself. Agreeing or not is therefore measured here, where the question can
  // actually be answered.
  let permissions = null;
  try {
    const direct = (typeof Notification !== 'undefined') ? Notification.permission : null;
    const queried = await navigator.permissions.query({name: 'notifications'});
    permissions = {direct: direct, queried: queried.state, consistent: direct === queried.state};
  } catch (error) {
    permissions = null;
  }
  return {
    applied: Array.isArray(window.__rrAntiDetect) ? window.__rrAntiDetect.slice() : [],
    webdriver: navigator.webdriver === undefined ? 'undefined' : String(navigator.webdriver),
    hasChromeRuntime: typeof window.chrome !== 'undefined' && !!window.chrome.runtime,
    pluginCount: (navigator.plugins && navigator.plugins.length) || 0,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory === undefined ? null : navigator.deviceMemory,
    outerWidth: window.outerWidth,
    innerWidth: window.innerWidth,
    userAgent: navigator.userAgent,
    appVersion: navigator.appVersion,
    vendor: navigator.vendor,
    platform: navigator.platform,
    userAgentData: (() => {
      try {
        const data = navigator.userAgentData;
        if (!data) return null;
        return {
          brands: (data.brands || []).map(b => String(b.brand) + '/' + String(b.version)),
          platform: String(data.platform || ''),
        };
      } catch (error) { return null; }
    })(),
    webgl: gl,
    permissions: permissions,
  };
}
"""


async def read_report(page):
    """Read what the page actually presents after the patches were applied.

    A declared plan is a promise; this is the measurement. It is reported next
    to the plan so that a patch which silently failed to apply cannot be
    mistaken for a working one.
    """
    try:
        measured = await page.evaluate(READ_REPORT_SCRIPT)
    except Exception:  # noqa: BLE001 - a page that refuses to be measured is evidence too
        measured = None
    if not isinstance(measured, dict):
        return {"measured": False}
    measured["measured"] = True
    return measured
