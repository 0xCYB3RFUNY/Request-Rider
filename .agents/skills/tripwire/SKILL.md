---
name: tripwire
description: Stops you from walking into the same trap twice. Asks one short question the moment you steer into a recurring trap from your own profile — another guard, reviewer or research round, automation after the first occurrence, architecture before a minimal version, a new thread before the current one is done, a closed decision reopened, scaling before it works for you — and adds a one-line note for pain well known to programmers, engineers and mathematicians — sunk cost, planning fallacy, second-system effect, bikeshedding, one green run as proof, "obviously" in a proof. Logs every flag and reviews weekly whether it changed a decision. Use when the user proposes a new guard, check, agent, automation, framework or platform, says "while this runs, let's also…", keeps pushing a stalled path, estimates, or declares something done; also for a roast, "am I overengineering this?", "tripwire review", or "tripwire setup" to build the profile of traps it watches for.
metadata:
  version: "0.4.0"
---

# Tripwire

A grilling happens when the user asks for it; traps open when nobody is asking. Tripwire is the grilling that shows up uninvited, once, at the moment it matters — and remembers. Scope guards stop the *agent* from building too much; tripwire watches the *user's* moves that lead into building too much or into avoidable pain. It never blocks. It flags the trap, and the user decides.

People who fall into these traps usually already know their patterns; another description won't help, a question at the right moment does. A flag costs seconds and a trap costs days, but a flag raised too often becomes the bureaucracy it was meant to prevent. So tripwire fires rarely, stays brief, and never asks twice about the same thing. It has two floors with different weight:

| | Floor 1: the user's own traps | Floor 2: general pain |
|---|---|---|
| Source | the user's profile (below); the default catalog if there is none | `references/catalog.md`, read only when floor 1 is silent |
| Form | **stop**: one question, then wait | **note**: one line at the end of the reply; the work goes on |
| Log agent field | `<agent>` | `<agent>:fieldguide` |

## Personal profile first

Look for the user's own trap list: a "triggers → questions" section in CLAUDE.md or AGENTS.md, a `whoami.md`, or a file the user points to. Their words and questions take priority over the default catalog, because they describe the traps this person actually falls into.

The profile or `AGENTS.md` may also name a **tripwire log** and a **review file**. If neither is named, skip logging entirely.

**No profile?** Use the default catalog below, and say so once per session — right after the first flag, never as an opening message:

> No trap profile found, so this question came from the built-in list. Want your own, in about ten minutes? Say `tripwire setup`.

On `tripwire setup`, or any request to build or rewrite the profile, read `references/setup.md` and follow it. Don't improvise the interview.

## Default floor-1 catalog (only when there is no profile)

| # | Trap | Typical signal | Question |
|---|---|---|---|
| 1 | Layer on layer | "add a guard / check / validator for that" | Which *observed* failure does this remove? What happens if it doesn't exist at all? |
| 2 | Shielding the symptom | a failure gets "fixed" by wrapping it in protection | Is this the cause, or protection against the symptom? |
| 3 | Early automation | a script, workflow or pipeline after the first occurrence | Has this happened twice yet? Can we do it once by hand? |
| 4 | Ritual reviewer | "add another agent / reviewer / audit" | What independent uncertainty is left after the first check? |
| 5 | Research escape | "one more round of research first" | What new fact would change the decision? If none, decide or run the cheap experiment. |
| 6 | Architecture escape | designing the final system before a minimal version exists | Has the minimal version been shown to fail? |
| 7 | Open loops | "while this runs, let's also…" | Does the current loop have a defined DONE? How many loops are open right now? |
| 8 | Reframed reopening | a closed decision comes back under a new name or angle | What changed in the *evidence* since it was closed, rather than in the framing? |
| 9 | Scale before one | "useful for everyone", "make it a plugin / platform" | Has it worked for you, more than once, yet? |
| 10 | Machine progress | progress reported as tests, routing, guards or docs | How would a real user notice this change? |
| 11 | Moving finish line | no stop condition, or "just a bit better" | What was the stop condition before we started? |

## When to flag

Flag only when all three hold:

- The **user** is steering toward the trap. Your own urge to overbuild is handled by ordinary discipline.
- The step adds **lasting cost**: a new component, dependency, maintenance burden, open loop, growing committed time, a conclusion later work will stand on, or an irreversible action.
- The conversation does **not already contain the answer**. Observed, repeated evidence already cited means the question is answered; just help.

Stay silent when the step is cheap and reversible, when the user is learning or just asking, when they said "yes, deliberately", or when either floor already flagged in the same logical block. An irreversible or high-cost step is the one exception and gets its own flag.

**One flag per move.** Check floor 1 first. Go to floor 2 only when floor 1 is silent, and skip catalog rows the profile already covers.

If you are about to flag a third time in one session (both floors together) and the user proceeded each time, go quiet. At a natural break, mention once that tripwire may be miscalibrated for them. Nagging is a trap of its own.

## How to flag

Write in the user's language. Frame everything as a question about cost, never as a moral judgment. Base the evidence only on what was said in the conversation; don't infer character traits.

### Floor 1: stop

Before doing any of the work:

> **Tripwire: <trap name>.** <One line of evidence: what the user just proposed, in their terms.>
> <One question, from their profile or the default catalog.>
> Minimal option: <the cheapest alternative, one line>.

Then stop and wait; starting the complex version in the same message answers the question on the user's behalf. Proceed → do it fully. No reluctance, no repeating the warning: the decision was theirs, and tripwire's job was only the question. Minimal → do the minimal option.

### Floor 2: note

Do the requested work, then end the reply with one line:

> **Tripwire · <trap> (<source>):** <catalog question, adapted to the case> Minimal option: <one line>.

The user can pick it up on the next turn or ignore it. When the flagged step is irreversible, use the floor-1 form instead and wait.

### Logging (only if the profile or `AGENTS.md` names a log and you can write files)

Append exactly one line per flag, after the user's answer; for a floor-2 note the user did not answer, write `noted` when the conversation moves on. Don't add any other bookkeeping.

```
- YYYY-MM-DD | <agent>[:fieldguide] | #<n> <trap> | <what was proposed, ≤12 words> | <proceed|minimal|dismissed|noted> | outcome: ?
```

Floor-2 lines carry the catalog id (`B2 second-system effect`). Test runs use `test` or `test:fieldguide` and are excluded from the numbers.

### Examples

**Floor 1 (trap 1):**
User: "Deploy failed because an env var was missing. Let's add a pre-deploy validator agent, a test for it, and wire it into the orchestrator."
> **Tripwire: layer on layer.** One missing variable → a new agent, its test and orchestrator wiring.
> Which failure besides this one would the agent catch?
> Minimal option: add the variable to the template and a line to the deploy checklist; build the validator if it happens again.

**Floor 1 (trap 7):**
User: "While the migration runs, let's sketch the metrics dashboard in parallel."
> **Tripwire: open loops.** The migration has no DONE yet, and a dashboard is already opening.
> What is the completion criterion for the migration?
> Minimal option: write the dashboard idea down in one line and come back to it after DONE.

**Floor 2 (sunk cost, profile silent):**
User: "Parser v2 is three evenings in and still breaks on nested quotes. Let's give it one more evening."
Help with the parser, then end with:
> **Tripwire · sunk cost (Arkes & Blumer 1985):** Starting today with zero invested, would you pick this parser? Minimal option: count only the evenings still ahead; park the branch, don't delete it.

**Silent:**
User: "Third time this month the cron job died silently. Let's add a watchdog."
The repetition is already established, so just help build the watchdog.

## Roast mode (only on request)

Use this when the user asks for a roast, a pattern review, or to be grilled:

- In a live conversation, work only from what is **already in context**: the conversation, loaded memory or profile, the log, and files the user provided. A roast that stops the work for a fresh audit is itself trap 5.
- **Exception: `tripwire setup` and `tripwire review` read the record first** — transcripts, git, the log — because both are about what already happened, not about the next decision. Reading there is the task, not an escape from it, and each has a stated ceiling — setup's in `references/setup.md`, review's in step 3 — so neither turns into the audit.
- Give 3–5 points, sharpest first. Each point goes **observation → evidence** (a fact, a phrase or a log line) **→ the question it raises**. Mark anything not directly evidenced as a guess, or leave it out. Name floor-2 points by catalog id and source.
- Name one real strength the evidence supports. The purpose is calibration, not comfort.
- A hard, self-ironic tone is fine when asked for. Aim it at the work patterns, never at the person.
- End with the one pattern to watch next and one concrete action. Don't add a list of improvements, because that list would be trap 7.

## Review mode ("tripwire review", scheduled by the user)

The review answers one question: **is tripwire changing decisions, or only producing text?**

Anything countable, count yourself. The user's part is confirming and correcting a list you bring, never recalling a number — a number recalled is trap A7 in the catalog, and a weekly quiz is how a review stops happening.

1. Read the log lines since the last review, the profile, and the last entry in the review file.
2. Go through the entries whose outcome is still `?` together with the user, one short answer each:
   - `enough`: the minimal option held up.
   - `needed-more`: the minimal option was not enough.
   - `false-alarm`: the flag was useless.
   - `n/a`: the user proceeded with the original plan, or ignored a note.
3. Find the traps walked into without a flag yourself, from the record since the last review: the sources in `references/setup.md` Step 1, at most **10 sessions** and **25 commits** — a week's worth, not a quarter's. Put each candidate to the user with its address, one line each, and they answer yes or no. Log each confirmed case as `missed`. Ask blind only when the record is unreachable.
4. Count the open directions yourself, cheapest source first: unmerged branches, running timers and units, open PRs and issues — one command each, no transcript mining here. Show the number and the list; the user corrects it.
5. Report the numbers **per floor, side by side** (floor 1 = `<agent>`, floor 2 = `<agent>:fieldguide`): flagged; changed course (chose minimal); false alarms; missed; of the minimal choices, how many were enough and how many needed more; open directions compared with the last review. Lines from an older setup where the two floors ran as separate skills could both fire on one move; report them separately.
6. Roast in 3–5 points, following roast mode, with log lines as evidence.
7. Propose **at most one** change to the skill, the catalog or the profile, tied to a specific log line. "No change" is a valid and often the best result. A catalog row that never fired is a candidate for deletion.
8. Check the gate the user set for this date: DONE / NOT DONE / UNKNOWN.
9. Append one entry to the review file: the date, the numbers, the one change (or "none"), and the gate result.

With one person and no control group, this data shows a direction, not proof. Course changes growing, false alarms staying low, minimal choices mostly holding and open directions shrinking over several weeks is a meaningful signal; a single good week is not.

## What tripwire is not

- Not a gatekeeper: the user always decides.
- Not a replacement for agent-side scope guards; it complements them.
- Not a personality assessment or therapy: only work decisions visible in the conversation.
