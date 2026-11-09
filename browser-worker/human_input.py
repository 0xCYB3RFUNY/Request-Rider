"""Human-like pointer input for the browser crawler.

Nothing here knows anything about challenges. This is the input layer the
crawler drives every page with: the pointer travels, pauses and overshoots the
way a hand does, and typing is paced the way fingers are.

The reason it exists is a measurement, not a taste. A bare
``locator.click()`` teleports: the page receives one ``mousemove`` at the
destination and nothing before it. That event stream is the whole signature a
behavioural detector reads, and it is identical for every click, on every
target, forever — so it is not merely "unhuman", it is a constant, and a
constant is easier to fingerprint than a variable.

What this produces instead is the three parts a real gesture has:

* an **eased** profile — ``easeOutCubic``, accelerating off the origin and
  decelerating into the target, rather than uniform per-step velocity;
* **jitter** on both axes, so no two steps share a slope;
* an **overshoot and settle** near the destination, which is what a hand aimed
  at a small control actually does.

Deliberately not a Bezier curve. A Bézier through two control points produces a
path whose curvature is symmetric and whose endpoints are approached along a
single stable tangent — the opposite of what makes a path non-identical between
attempts. What actually varies the signature is the per-step noise and the
easing, so that is where the variation is spent.

Every jitter value is drawn from a caller-supplied generator rather than from a
``random.Random()`` built at the call site. The reason is testability, and it was
measured before it was written down: on this Python a bare ``random.Random()``
seeds from ``os.urandom``, so two of them differ — but neither can be pinned, so
a test could only assert on shapes, never on the exact stream. Taking the
generator as an argument means a test seeds it and gets a reproducible path,
while production passes one long-lived instance.
"""

import asyncio
import math

__all__ = [
    "move_cursor_along",
    "click_control",
    "human_delay",
    "type_into",
    "steps_between",
]


# Above this span a real hand would not travel in one unbroken motion, so the
# pointer pauses mid-flight the way a hand does when it re-aims. Below it the
# pause would cost more than it buys.
LONG_TRAVEL_PX = 420.0

# Per-character typing cadence. The upper end is a fast typist, the lower end a
# deliberate one; the space between words and the end of a run are the two places
# real typing measurably pauses, so they are wider than the character cadence.
TYPE_KEY_MS = (38.0, 132.0)
TYPE_WORD_GAP_MS = (110.0, 260.0)
TYPE_SENTENCE_GAP_MS = (280.0, 640.0)

# A jittered pause between two consecutive actions on a page, so a run of
# clicks is not a metronome.
ACTION_GAP_MS = (140.0, 720.0)


def steps_between(start_x, start_y, end_x, end_y, generator, steps=18):
    """Yield ``(x, y)`` waypoints from one point to another.

    A no-op for a travel of under two pixels: a press that does not need to move
    should not emit motion, because emitting it anyway is the same tell as
    teleporting.
    """
    span = math.hypot(end_x - start_x, end_y - start_y)
    if span < 2.0:
        yield end_x, end_y
        return
    for step in range(1, steps + 1):
        progress = step / steps
        eased = 1 - math.pow(1 - progress, 3)
        # Jitter shrinks toward the target: noise on a resting hand is smaller
        # than noise mid-flight, and a constant amplitude reads as a synthetic
        # generator.
        amplitude = 0.9 * (1.0 - progress) + 0.15
        yield (
            start_x + (end_x - start_x) * eased + generator.uniform(-amplitude, amplitude),
            start_y + (end_y - start_y) * eased + generator.uniform(-amplitude, amplitude),
        )


async def move_cursor_along(page, start_x, start_y, end_x, end_y, generator,
                            steps=18, step_delay=0.014):
    """Move the pointer from one point to another the way a hand does.

    Long travels are re-aimed in two legs with a pause between them, because a
    pointer crossing a whole viewport in one unbroken microsecond stream is
    its own kind of constant.
    """
    if math.hypot(end_x - start_x, end_y - start_y) < 2.0:
        await page.mouse.move(end_x, end_y)
        return
    span = math.hypot(end_x - start_x, end_y - start_y)
    if span > LONG_TRAVEL_PX:
        # Re-aim roughly halfway, off the straight line so the two legs do not
        # form a detectable chevron.
        ratio = generator.uniform(0.42, 0.58)
        mid_x = start_x + (end_x - start_x) * ratio + generator.uniform(-90.0, 90.0)
        mid_y = start_y + (end_y - start_y) * ratio + generator.uniform(-70.0, 70.0)
        await _traverse(page, start_x, start_y, mid_x, mid_y, generator, steps, step_delay)
        await asyncio.sleep(generator.uniform(0.05, 0.19))
        await _traverse(page, mid_x, mid_y, end_x, end_y, generator, steps, step_delay)
    else:
        await _traverse(page, start_x, start_y, end_x, end_y, generator, steps, step_delay)
    # The settle: overshoot the target and come back onto it.
    await page.mouse.move(
        end_x + generator.uniform(1.0, 2.6), end_y + generator.uniform(-1.0, 1.0)
    )
    await asyncio.sleep(0.035)
    await page.mouse.move(end_x, end_y)


async def _traverse(page, start_x, start_y, end_x, end_y, generator, steps, step_delay):
    for x, y in steps_between(start_x, start_y, end_x, end_y, generator, steps):
        await page.mouse.move(x, y)
        await asyncio.sleep(step_delay)


async def click_control(scope, locator, timeout_ms, generator):
    """Press a control with a travelled approach, falling back to a plain click.

    The trajectory is the point; the fallback exists because the approach can
    fail where a direct click would have succeeded — an element scrolled out of
    the viewport has no box to travel to, and ``bounding_box()`` returns nothing
    for it. In that case the control is still clicked, because skipping a press
    that would have worked is worse than pressing it inarticulately.

    Returns whether the travelled approach was actually used, so a caller (or a
    test) can tell the two paths apart instead of inferring it from a successful
    click.
    """
    box = None
    try:
        box = await locator.bounding_box()
    except Exception:  # noqa: BLE001 - a box is an optimisation, never a gate
        box = None
    if not box:
        await locator.click(timeout=max(1, min(timeout_ms, 5000)))
        return False
    target_x = box["x"] + box["width"] / 2
    target_y = box["y"] + box["height"] / 2
    # Approach from a short distance away, offset from the target the way a hand
    # approaches a small control rather than landing dead centre from nowhere.
    angle = generator.uniform(0.0, math.tau)
    radius = generator.uniform(38.0, 74.0)
    start_x = target_x + math.cos(angle) * radius
    start_y = target_y + math.sin(angle) * radius
    try:
        await move_cursor_along(scope, start_x, start_y, target_x, target_y, generator)
        await scope.mouse.down()
        await asyncio.sleep(generator.uniform(0.05, 0.11))
        await scope.mouse.up()
        return True
    except Exception:  # noqa: BLE001 - the element moved under the pointer
        await locator.click(timeout=max(1, min(timeout_ms, 5000)))
        return False


async def human_delay(generator, low=ACTION_GAP_MS[0], high=ACTION_GAP_MS[1]):
    """Pause between two actions, jittered so a run is not a metronome."""
    await asyncio.sleep(generator.uniform(low, high) / 1000.0)


async def type_into(locator, value, generator, clear=True):
    """Type a string one key at a time at a human cadence.

    Playwright's ``fill()`` sets the value in a single assignment and fires one
    ``input`` event: instantaneous, and identical for every field on every page.
    This walks the string instead, widening the pause at a word boundary and at
    the end of a sentence, which is where real typing measurably hesitates.

    Returns the number of characters actually typed.
    """
    if clear:
        try:
            await locator.click(timeout=5000)
        except Exception:  # noqa: BLE001 - focus is best-effort
            pass
    typed = 0
    previous = ""
    for char in str(value):
        await locator.type(char, delay=generator.uniform(*TYPE_KEY_MS) / 1000.0)
        typed += 1
        if char == " " and previous and previous != " ":
            await asyncio.sleep(generator.uniform(*TYPE_WORD_GAP_MS) / 1000.0)
        elif char in ".!?":
            await asyncio.sleep(generator.uniform(*TYPE_SENTENCE_GAP_MS) / 1000.0)
        previous = char
    return typed