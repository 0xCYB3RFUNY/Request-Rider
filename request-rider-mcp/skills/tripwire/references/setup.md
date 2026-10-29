# Building the profile — a ten-minute interview

Read this file only when the user asked for the profile (`tripwire setup`, or any
request to create or rewrite their trap list). It replaces guessing: a profile
invented for the user fires on traps that aren't theirs, and false alarms are what
kills the skill.

## Ground rules

- **The record before memory.** Every trap in the finished profile traces back to an
  address in the record — a transcript line, a commit, a log line, a file — not to
  what the user recalls about themselves. Memory returns the patterns a person has
  already accepted; the record shows the ones still running. No inference from
  personality, job title or tone.
- **Their words win.** Write the triggers the way the user phrases them, even when a
  textbook name exists. The profile is read at the moment of a decision; it has to
  sound like their own voice, not a taxonomy.
- **One question at a time.** This is an interview, not a form. Wait for each answer.
- **Ten minutes, then stop.** A short profile that fires is worth more than a complete
  one that never gets finished. Three traps are enough to start.
- **Write one file, and only after they approve it.** The profile, at a path they
  confirmed. Their `CLAUDE.md` or `AGENTS.md` is theirs: hand them the line to paste,
  never paste it for them unless they ask.
- **Interview in the language the user writes in.** If their only message so far is the
  trigger phrase, use the language of the session around it and switch the moment they
  answer in another.

## Step 1 — read the record

First look for a profile that already exists, where `SKILL.md` says to look. If there is
one, show its triggers and ask whether to extend it or start over; don't quietly replace
somebody's file.

Open with two lines — about ten minutes, and it ends with a file they approve. Then
collect the evidence yourself, before asking anything. Go in this order and stop at the
ceiling below:

1. **This session** — what the user has already said, asked for and changed their mind
   about.
2. **Session transcripts** — `~/.claude/projects/**/*.jsonl` for Claude Code, the
   equivalent store for other clients (`~/.codex/sessions`, `~/.gemini`, an exported
   chat log). Look for repeated moves: "while this runs, let's also", "one more round
   of research", "add a guard for that", a plan replaced by a larger plan.
3. **git** — branches that never merged, first and last commit date of a theme, what
   appeared right after a single incident, work restarted under a new name.
4. **The log and reviews** — `tripwire-log.md` and `tripwire-reviews.md` if the user's
   `CLAUDE.md` or `AGENTS.md` names them: flags already raised, outcomes, `missed`
   lines.
5. **Scheduled and running work** — systemd timers and units, cron entries. Each one is
   an open direction somebody has to keep alive.
6. **Open PRs and issues** — started, not finished, not abandoned.

**Window and ceiling are not optional.** Look back **90 days**; read at most **20
sessions** and **50 commits**, newest first. Collection without a ceiling turns into
the endless audit that is itself trap 5. When you hit the ceiling, say what you left
unread instead of reading more.

Reading is all you do here. Bring back candidates, not conclusions, and give every
candidate an address: `file:line`, a commit hash, a log line, or a timestamp in a
transcript.

### Step 1b — fallback, only when there is no record

Use this when the record is unreachable — no transcripts, no repository, a fresh
machine — or the user declines access. Ask in order, one per message, and stop early if
the user is already naming patterns:

1. Think of the last thing you built that turned out bigger than it needed to be. What
   was the first step that made it grow?
2. What is currently open — started, not finished, not abandoned? How many of those?
3. When did you last postpone a decision to gather more information? Did the new
   information change it?
4. What do you already know about yourself here that keeps happening anyway?

Say plainly that this profile rests on recollection, and that the first `tripwire
review` with a log behind it will correct it.

If the session already contains a grilling — the user stress-testing a plan or a
decision with an agent — that counts as record: take the patterns from there first and
put them to the user for confirmation instead of asking the four questions again. A
grilling produces the insight; the profile is what makes it survive the week.

## Step 2 — grill

Follow **Roast mode** in `SKILL.md`: 3–5 points, sharpest first, each one
`observation → evidence → the question it raises`, one real strength. The "no fresh
audits" rule does not apply here — setup is *about* the past, and Step 1 is the audit.

**Evidence is an address, not a recollection.** `bot/handlers.py:140 — three guards
added after one 429` is evidence; "you tend to over-guard" is not. Drop a point you
cannot address.

When Step 1b was the path, the four answers may be all the evidence there is. That is
enough for three points — grill from what they said, and nothing else. If even that is too thin to grill honestly,
say so in one line and go to step 3: a pattern the user named themselves is already
confirmed and needs no roast to earn its row.

Then ask the user which of the points they recognise. **Only confirmed points become
traps.** A point they reject is dropped without argument — it is their profile, and a
trap they don't believe in produces a flag they will ignore.

## Step 3 — turn patterns into triggers

For each confirmed pattern, write one row: the **observable move** that starts it, and
**one question about cost** that fits it.

| Good row | Why |
|---|---|
| `I want to automate this` → `Is it a repeated problem or the first case?` | names a move the user can catch themselves making |
| `propose a new guard` → `Which observed failure does it remove?` | question is about cost, answerable in one line |

| Bad row | Why |
|---|---|
| `when I'm being a perfectionist` → `is this perfectionism?` | not observable, and the question judges the person |
| `before a big refactor` → `have you considered the alternatives?` | vague trigger, question can't be answered shortly |

Three to seven rows. More than that and nothing fires, because everything does.

Each trap also carries its `evidence:` — the address from Step 1 that produced it. **A
trap with no address is not written.** It is the line that makes the profile arguable
later: at review the user can go and look, instead of re-deciding from memory.

## Step 4 — write the file

Ask where it should live and whether the path is private — the profile describes how
the user works and does not belong in a public repository. For the default, look in the
user's global agent rules (`~/.claude/CLAUDE.md`, `AGENTS.md`) for a profile path they
have already named, and offer that one; only if none is named, offer `~/whoami.md`.

Those rules files are where the path is written down. They are never the file you write
the profile into, and you never edit them here. When you say what you are about to do,
name the profile's own path in full — "writing the profile at ~/.claude/CLAUDE.md" reads
to the user as their global rules being rewritten, which is the one thing this skill
promises not to do.

If that path already holds a file, show its first lines and ask before writing over it.

```markdown
# whoami — <name>

## My recurring traps

- **<trap, user's words>.** <one line of what it came from>
  evidence: <file:line | commit | log line | transcript timestamp>
- ...

## Triggers → questions

| When I… | Ask |
|---|---|
| <observable move> | <one question about cost> |
| ... | ... |

## How to talk to me

- <two or three lines, only if the user stated them; drop the whole section otherwise>
```

Write the file, then show the triggers table back in the reply so the user sees what
will fire without opening anything.

## Step 5 — wire it up

Give the user one line to paste into their global `CLAUDE.md` or `AGENTS.md`, with the
path they chose in Step 4 — give it, don't paste it. Editing the file that configures
every one of their sessions is their call, not a step you take on the way:

```text
Profile: <profile path>. Tripwire log: ~/tripwire-log.md. Reviews: ~/tripwire-reviews.md.
```

If that file already names the profile path, the line is already there — say so and
change nothing.

Logging is optional but it is the only thing that later answers "did this change any
decision?". Without a log named here, tripwire writes nothing.

## Step 6 — close

In three lines: how many triggers are live now, that flags start from the next move,
and one date about a week out for the first `tripwire review`. Then stop — no
improvement list, no second round of questions.

Tell the user plainly that the first version will be wrong in places: rows that never
fire get deleted at review, and traps they walk into unflagged get added. The profile
is meant to shrink and sharpen, not to grow.
