# Tripwire catalog — floor 2

Read this file only on floor 2 (see `SKILL.md`). It holds traps documented across the field: biases with experimental evidence, accepted laws of software engineering, named anti-patterns, classic mistakes in proofs.

Skip every row whose trap the user's profile already names — floor 1 owns it. Use the row's question and minimal option; the source goes in the note so the review can check it.

### A. Cognitive biases (experimental psychology)

| # | Trap | Source | Signal | Question | Minimal option |
|---|---|---|---|---|---|
| A1 | Sunk cost | Arkes & Blumer 1985 | "so much already invested, a shame to drop it" | If you were starting today with zero invested, would you pick this path? | Count only the cost still ahead; park the branch, don't delete it. |
| A2 | Planning fallacy | Kahneman & Tversky 1979; Buehler et al. 1994 | "one more evening and it's done", "definitely by Friday" | How long did the last three similar tasks actually take? | Multiply by your own past ratio; name the stop condition before continuing. |
| A3 | Confirmation bias | Wason 1960; Nickerson 1998 | one green run taken as proof; tests chosen to pass | What result would refute the fix — and did we run it? | One run that must fail if the fix is wrong. |
| A4 | Anchoring | Tversky & Kahneman 1974 | the first number or option named becomes the baseline ("at least half of that") | Where did that number come from? | Estimate from scratch before looking at the anchor. |
| A5 | Overconfidence / optimism | Weinstein 1980; Moore & Healy 2008 | "nothing can break here", "trivial change" | Of the last month's "certainly", how many held? | One probe before the claim. |
| A6 | IKEA / endowment effect | Norton, Mochon & Ariely 2012; Thaler 1980 | own tool valued above the mature one it replaces | If someone else had built this, would you keep it? | Compare with the ready-made option on the same criterion. |
| A7 | Availability | Tversky & Kahneman 1973 | yesterday's incident sets today's priority | How often did this happen this year, next to the alternatives? | Look in the ledger, not in memory. |
| A8 | Status quo / loss aversion | Samuelson & Zeckhauser 1988; Kahneman & Tversky 1979 | "don't touch it, it works" said about a known defect | Are both costs named — of leaving it and of changing it? | Name both numbers. |
| A9 | Base rate neglect | Kahneman & Tversky 1973 | the vivid rare cause is investigated first | How frequent is this cause among all causes of this symptom? | Start with the most common cause. |
| A10 | Survivorship bias | Wald 1943 | conclusions from the runs, repos or users that made it through | Where is the data on those that did not? | Add the failures to the sample. |

### B. Laws of software engineering (accepted by the field)

| # | Trap | Source | Signal | Question | Minimal option |
|---|---|---|---|---|---|
| B1 | Brooks's law | Brooks 1975 | adding people or agents to late work | What is slow — writing code, or agreeing on it? | Split off tasks that don't overlap; one executor per task, merge in sequence. |
| B2 | Second-system effect | Brooks 1975 | v2 "will do everything that didn't fit in v1" | Which three things can v1 not do, and who noticed? | v1 plus one thing. |
| B3 | Conway's law | Conway 1968 | code boundaries that don't match who maintains them | Does each boundary in the code match a boundary in ownership? | One boundary per owner. |
| B4 | Goodhart's law | Goodhart 1975; Strathern 1997 | a metric becomes the target: coverage, green CI, test count | How could this number rise without the system improving? If easily, it is no longer a measure. | Keep it as an observation; add one independent measure. |
| B5 | Gall's law | Gall 1975 | designing a complex system from scratch | Which simple system already works? | Start from the working one. |
| B6 | Hyrum's law | Wright (Google), 2012; *SWE at Google* 2020 | "nobody depends on this behavior, we can change it" | Who reads this output or format today? | grep the consumers before changing. |
| B7 | Premature optimization | Knuth 1974 | cache, rewrite, faster language — without a measurement | Which measurement showed it was slow? | Measure once; optimize after the number. |
| B8 | Parkinson's law | Parkinson 1955 | work expands to fill the time; "another week" | What would change if the deadline were tomorrow? | Timebox plus acceptance criterion. |
| B9 | Lehman's laws | Lehman 1980 | things are added, nothing is removed; complexity grows | What was deleted last month? | One removal per addition. |
| B10 | Chesterton's fence | Chesterton 1929 | "remove it, nobody knows why it's there" | Who put it there, and against what? | git blame or ledger before removal. |

### C. Anti-patterns and developer pain (named by the community)

| # | Trap | Source | Signal | Question | Minimal option |
|---|---|---|---|---|---|
| C1 | Bikeshedding | Parkinson 1957 (law of triviality) | long debate on a name, color or style while the substantive decision waits | Which decision is blocked by this name? | Pick the first acceptable; rename later with sed. |
| C2 | Yak shaving | MIT AI Lab 1990s; Godin 2005 | "to do X we first need Y, and for Y we need Z" | How many steps are we from the original task? | Write the chain down; return to link one with a workaround. |
| C3 | Not invented here | Katz & Allen 1982 | "we'll write our own, the existing ones don't fit" | Which specific requirement does the mature tool fail? | Try the ready-made one on a single case. |
| C4 | Gold plating | Brown et al. 1998; PMBOK | "while we're here, let's also add…" to finished work | Who asked for it? | Close as is; the idea gets one line. |
| C5 | Cargo cult | Feynman 1974; McConnell 2000 | a ritual without a mechanism: "best practice", "Google does it" | Which mechanism makes this useful in our case? | Name the mechanism or drop the ritual. |
| C6 | Shiny technology | McKinley 2015 ("Choose Boring Technology") | a new tool or language with no requirement behind it | Which requirement needs it? | The boring option. |
| C7 | Lava flow | Brown et al. 1998 | "leave it, might be needed": parked units, `.bak`, dead branches | Who will read this again? | Review date on every parked item; git already remembers. |
| C8 | Analysis paralysis | Brown et al. 1998 | another round of research before a cheap experiment | Which new fact would change the decision? | Run the cheap experiment. |
| C9 | Normalization of deviance | Vaughan 1996 | a red that is "always like that"; alerts nobody reads | When did this signal last change something? | Fix it or silence it; an ignored alarm is worse than none. |
| C10 | Toil | Google SRE 2016 | a manual step repeated, growing with the system | How many times this month, identically? | Same action three times → script it; fewer → keep doing it by hand. |
| C11 | Works on my machine | community folklore | proven only where it was built | On which other machine was it proven? | One run elsewhere, or a portable check that hides the source path. |

### D. Proofs and reasoning (mathematics)

| # | Trap | Source | Signal | Question | Minimal option |
|---|---|---|---|---|---|
| D1 | Proving the wrong theorem | Pólya 1945 | a solution for a simplified statement presented as the full one | Does the proven statement match the task word for word? | Restate the problem in your own words before solving. |
| D2 | Overgeneralizing from examples | Pólya 1945; Lakatos 1976 | "checked on three cases, so it holds for all" | Which case would be the counterexample, and did we look for it? | One boundary case: zero, one, empty, maximum. |
| D3 | Lost invariant | Hoare 1969; Dijkstra 1976 | a step changed without checking what must stay true | Which property must hold before and after every step? | Write the invariant in one line; check it on the changed step. |
| D4 | "Obviously" | Pólya 1945; Lakatos 1976 | "obviously", "trivially", "clearly" at the load-bearing step | Can this step be written out in a minute? | Write it out, or mark it unproven. |
| D5 | Definition drift | Lakatos 1976 (concept stretching) | one term in two meanings: "done", "works", "green" | In which of the two meanings is it used here? | One definition, stated once. |
