![RequestRider Interface](Documentation/screenshots_en/01-main-interface-1920.png)
![Repeater Workbench](Documentation/screenshots_en/42-repeater-response.png)
![Target Sitemap](Documentation/screenshots_en/92-target-map-built.png)
![OSINT Entity Graph](Documentation/screenshots_en/200-osint-graph-built.png)
![Intruder Attack](Documentation/screenshots_en/75-intruder-results-pitchfork.png)

# Request-Rider — User Guide

**[English](README_EN.md) | [Українська](README.md)**

<!--
This document is a comprehensive practical guide. All screenshots were captured
from a live running instance of the tool, not mocked or illustrated.
-->

## Table of Contents

1. [Introduction](#1-introduction)
2. [Features and Capabilities](#2-features-and-capabilities)
3. [Requirements](#3-requirements)
4. [Installation](#4-installation)
5. [First Launch](#5-first-launch)
6. [User Interface](#6-user-interface)
7. [Core Features](#7-core-features)
8. [Advanced Features](#8-advanced-features)
9. [CLI and API](#9-cli-and-api)
10. [Configuration](#10-configuration)
11. [Practical Scenarios](#11-practical-scenarios)
12. [Error Handling](#12-error-handling)
13. [Troubleshooting](#13-troubleshooting)
14. [FAQ](#14-faq)
15. [Best Practices](#15-best-practices)
16. [Complete Checklist](#16-complete-checklist)
17. [Feature Coverage Matrix](#17-feature-coverage-matrix)

---

## 1. Introduction

### What It Is

Request-Rider is a local (loopback-only) web-based tool for manual HTTP analysis
and authorized penetration testing. It consolidates into a single interface what
is usually scattered across dozens of separate applications:

- **Request Repeater** with raw HTTP editor,
- **Fuzzer** (Intruder) with four combination modes,
- **Target Crawler** in static and browser-driven modes,
- **Scanner** in three independent implementations,
- **Passive Reconnaissance** (OSINT) with an entity graph,
- **Passive MITM Proxy** capturing all browser traffic,
- **Automation Builder** with 22 node types,
- **Comparer, Decoder, AI Agent, Project Knowledge Hub**.

### Who It Is For

For security researchers conducting manual HTTP audits: security engineers,
bug bounty hunters, or QA engineers testing their own applications. The tool
has no private or public cloud pages and requires no account registration.

### Who This Document Is NOT For

For anyone looking for a push-button report claiming "scan all sites automatically".
Request-Rider has no autonomous "scan the entire Internet" mode: every operation
begins with the operator specifying a target and clicking the action button.

### General Architecture Diagram

```text
                     ┌──────────────────────────────────────────┐
   Operator Browser  │  Django :8000 — Gateway                 │
   (single window)   │  templates, browser API, PostgreSQL      │
                     └───────┬──────────────────────┬───────────┘
                             │                      │
                     HTTP    │                      │  ORM
                             ▼                      ▼
                     ┌───────────────┐        ┌──────────────┐
                     │ Go engine     │        │ PostgreSQL   │
                     │ :8081         │        │ :55433       │
                     │ outbound      │        │ History,     │
                     │ requests,     │        │ Traffic,     │
                     │ Intruder,     │        │ Projects,    │
                     │ scanners,     │        │ Workflows    │
                     │ OSINT         │        └──────────────┘
                     └───────┬───────┘
                             │
             ┌───────────────┼────────────────┐
             ▼               ▼                ▼
     ┌───────────────┐ ┌────────────┐ ┌────────────────┐
     │ passive proxy │ │ browser-   │ │ Target         │
     │ :8080 (MITM)  │ │ worker     │ │ (Network)      │
     └───────────────┘ │ :8090      │ └────────────────┘
                       └────────────┘
```

Key concept: **all outbound requests pass through the same passive proxy**.
Therefore, History and Traffic capture not only requests triggered inside the
tool UI, but also everything an ordinary browser does when configured to use
the proxy.

---

## 2. Features and Capabilities

Full inventory: 13 navigation tabs, 3 internal scanner views, 22 automation
node types, 16 OSINT transforms.

### 2.1 Working Tools

| Tab | Functionality | Details |
|---|---|---|
| **Projects** | Workspace: groups evidence, History, Traffic, and workflows | [7.1](#71-projects) |
| **Repeater** | Sends raw HTTP request and displays full raw response | [7.2](#72-repeater) |
| **Intruder** | Fuzzer with 4 modes, wordlists, transforms, login detection | [7.3](#73-intruder) |
| **Target** | Target site map: static and browser-driven crawlers | [7.4](#74-target) |
| **Recon (OSINT)** | Passive checks + entity graph + 16 transforms | [7.5](#75-reconnaissance-osint) |
| **Scanner** | CMS reconnaissance, active scanner (Active & Corpus Scanner) | [7.6](#76-scanner) |
| **Comparer** | Side-by-side and byte-by-byte comparison of two exchanges | [7.7](#77-comparer) |
| **Decoder** | 16 encoding and decoding operations | [7.8](#78-decoder) |
| **Tor/Proxy** | Unified outbound routing path for all tools | [7.9](#79-torproxy) |
| **Agent** | LLM analysis of attached evidence | [8.1](#81-ai-agent-and-autonomous-react-audit) |
| **Automation** | Node canvas, execution, scheduler, webhook, Template Store | [8.2](#82-automation) |
| **History** | Long-term archive of deliberate manual exchanges | [7.10](#710-history) |
| **Traffic** | Live stream of passive proxy + database archive | [7.11](#711-traffic) |

### 2.2 Tools Without a Dedicated Tab

These three operate **exclusively as automation nodes** or via direct engine
API calls. The absence of a separate tab is intentional by design.

| Tool | Status | Access Method |
|---|---|---|
| **Repeater Burst** | Operational | `repeater_burst` node; `POST /proxy/repeater-burst` |
| **Last-Byte Sync** | Operational | `last_byte_sync` node; `POST /proxy/last-byte` |
| **OAST Listener** | Operational | `oast_listener` + `oast_collect` nodes; ingestion at `POST /api/oast` |

### 2.3 Shared Mechanisms

- **Workspaces** — each tool can maintain multiple independent contexts
  and switch between them via `+` tabs.
- **Session Persistence** — `Save Session`, JSON export and import.
- **Commands** — `Ctrl/Cmd + K` opens the command palette across all tabs.
- **Language** — `English ⇄ Українська` switcher in the header; saved in a
  cookie so exported reports match the chosen interface language.
- **Export** — JSON, HTML, and CSV export available across almost every tool.

---

## 3. Requirements

### 3.1 Mandatory Prerequisites

| Component | Minimum | Verified On |
|---|---|---|
| OS | Linux x86_64 with or without `systemd` | Debian 12 / Kali rolling |
| Python | 3.12+ | 3.13 |
| Go | 1.21+ (for `go run .`) or prebuilt `bin/engine` | 1.24 |
| PostgreSQL | 15+ with UTF-8 template support | 18 on `:55433` |
| Redis | 6.2+ (`LMOVE`/`BLMOVE`) only if broker enabled | 7.x |
| Browser | Playwright Firefox | Firefox 1490 |

![System verification](Documentation/screenshots_en/300-install-01-prerequisites.png)

*Figure 1 — Operating system, kernel, and distribution. All commands throughout
this guide were verified on this environment.*

![Runtime versions](Documentation/screenshots_en/301-install-02-runtimes.png)

*Figure 2 — Versions of Python, Go, Docker, and Git. `start.sh` validates these
four prerequisites before attempting installation.*

### 3.2 Optional Components

| Component | When Needed | Behavior Without It |
|---|---|---|
| Docker | Running in containers instead of native stand | Native stand runs |
| Tor | Routing via `.onion` | Route defaults to "Direct" |
| LLM Provider | "Agent" tab | Chat messages not sent; displays error |
| CA Certificate | HTTPS interception via passive proxy | Generated automatically in `data/ca` |

### 3.3 Network Requirements

The tool binds **strictly to `127.0.0.1`**. It requires no external network
access except:

- Connectivity to audit targets you explicitly test;
- `https://check.torproject.org/api/ip` for Tor route verification;
- CA bundle retrieval on first launch (`curl` to `curl.se`).

No authentication, no test accounts, and no paid API keys are required to begin.

---

## 4. Installation

### Step 1 — Clone the Repository

```bash
git clone <repository-url> Request-Rider
cd Request-Rider
```

The repository must contain two essential executables:

![Repository entry points](Documentation/screenshots_en/302-install-03-entrypoints.png)

*Figure 3 — `start.sh` is the unified native entrypoint; `run-engine.sh` is the manual alternative.*

### Step 2 — Inspect the Header of `start.sh`

```bash
sed -n '1,40p' start.sh
```

![start.sh header](Documentation/screenshots_en/303-install-04-start-sh-head.png)

*Figure 4 — Initial lines of the script. Key takeaway: `start.sh` does not merely "run",
it **verifies every dependency and installs anything missing**.*

### Step 3 — View Command Flags

```bash
./start.sh --help
```

![start.sh help](Documentation/screenshots_en/304-install-05-start-sh-help.png)

*Figure 5 — Available flags: `--check`, `--status`, `--stop`, `--restart`, `--help`.*

### Step 4 — Launch the Stand

The standard startup command:

```bash
./start.sh
```

The script sequentially: verifies system packages → fetches Go modules →
creates `web/.venv` and installs `requirements.txt` → creates `browser-worker/.venv`
and installs Playwright → verifies Playwright Firefox binary → provisions
PostgreSQL cluster in `data/pg` on `:55433` and initializes `requestrider` DB →
starts Redis on `:6379` → starts Tor if route requires it → builds and launches
engine on `:8081` and proxy on `:8080` → starts `browser-worker` on `:8090` →
applies Django migrations → starts Django gateway on `:8000`.

The terminal remains attached by design so that pressing `Ctrl+C` cleanly shuts
down the entire stand.

### Step 5 — Verify Status

```bash
./start.sh --status
```

Every service must report `UP`. If any service reports `DOWN`, refer to
[13. Troubleshooting](#13-troubleshooting).

### Step 6 — Verify Engine Health

```bash
curl -s http://127.0.0.1:8081/health
```

![Engine health](Documentation/screenshots_en/308-install-09-engine-health.png)

*Figure 6 — The engine returns `ok` alongside **active transport boundaries**:
dial timeouts, TLS handshake timeouts, response header limits, and control-plane
body limits. These can be adjusted via environment variables.*

### Step 7 — Access the Web Interface

Open the gateway URL in your browser — `http://127.0.0.1:8000/`:

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download} bytes %{time_total}s\n' \
  http://127.0.0.1:8000/
```

![First launch HTTP response](Documentation/screenshots_en/309-install-10-first-page.png)

*Figure 7 — `HTTP 200` confirms the gateway is live and templates render properly.*

### Step 8 — Verify the REST API

No authentication required — the service binds exclusively to loopback:

```bash
curl -s http://127.0.0.1:8000/api/projects
```

![First API call](Documentation/screenshots_en/310-install-11-api-projects.png)

*Figure 8 — Empty project list on a fresh database.*

```bash
curl -s 'http://127.0.0.1:8000/api/traffic?detail=summary'
```

![Live traffic via API](Documentation/screenshots_en/311-install-12-api-traffic.png)

*Figure 9 — Snapshot of the passive proxy in-memory buffer. Populates with
hundreds of records as requests pass through.*

### Step 9 — Dispatch First Request via API

```bash
curl -s -X POST http://127.0.0.1:8000/api/execute \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","url":"http://127.0.0.1:8101/health"}'
```

![Executing request via API](Documentation/screenshots_en/312-install-13-api-execute.png)

*Figure 10 — Response includes `status`, `headers`, `body`, and `traffic_event_id`.
This is identical to the pipeline used by Repeater in the browser.*

### Step 10 — Run Built-in Diagnostics

```bash
./start.sh --check
```

The script verifies inline template syntax, whitespace/tabs in diffs, Django
configuration, engine tests (with race detection), and Django test suites.
Each check outputs `PASS`/`FAIL`, with full logs written to `data/logs/check-*.log`.
Exit code is non-zero if any test fails. See [9.1](#91-startsh--unified-entrypoint).

### Step 11 — Confirm Admin Endpoint Is Disabled

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/admin/
```

![Admin endpoint absent](Documentation/screenshots_en/315-install-16-admin-absent.png)

*Figure 11 — Returns `404`. This is deliberate: Request-Rider has no user
database, login forms, or Django admin interface.*

### Alternative: Manual Launch

If `start.sh` cannot be used (e.g. inside an unprivileged container):

```bash
cd engine && go run .            # Engine + proxy
cd ../web && python manage.py migrate && python manage.py runserver 127.0.0.1:8000
```

`run-engine.sh` performs the same while preparing `browser-worker` and migrations:

```bash
./run-engine.sh
```

Note: `run-engine.sh` **does not** install OS packages, **does not** spawn Redis
or Celery workers, and **does not** configure PostgreSQL.

---

## 5. First Launch

### Step 1 — Open the Application

Navigate to `http://127.0.0.1:8000/`.

![Main interface initial view](Documentation/screenshots_en/01-main-interface-1920.png)

*Figure 12 — Initial view presented to the user. Note the status bar in the upper
left: `ENGINE`, `PROXY`, `ROUTE` display real-time process states.*

> **Behavioral note:** On initial load without saved session state, the
> **Automation** tab may appear active. This occurs because
> `workspaceKinds.forEach(kind => createWorkspace(kind))` calls `selectWorkspace()`,
> and `automation` is the last item in the list. Clicking **Repeater** persists
> your active tab selection.

### Step 2 — Verify Health Indicators

The header status indicators should display green dots:

| Indicator | Green Meaning | Manual Check |
|---|---|---|
| `ENGINE` | Engine responds on `/health` | `curl -s http://127.0.0.1:8081/health` |
| `PROXY :8080` | Passive MITM proxy listening | `ss -tln \| grep ':8080 '` |
| `ROUTE` | Outbound route active (blank = "Direct") | **Tor/Proxy** tab |

If `ENGINE` is not green, click **↺** next to it (`#ss-engine-retry`) to trigger
an immediate re-check.

### Step 3 — Switch Language

Click the `English` button in the top right header.

![Language switcher to English](Documentation/screenshots_en/03-language-switch-english.png)

*Figure 13 — Interface switched to English. Re-renders all tabs, not just the active one.*

![Switch back to Ukrainian](Documentation/screenshots_en/04-language-switch-back-uk.png)

*Figure 14 — Switching back to Ukrainian. Preference is saved in cookie
`requestrider-language`, ensuring exported reports match workspace language.*

### Step 4 — Check Responsive Layout

![Main interface at 1920x1080](Documentation/screenshots_en/01-main-interface-1920.png)

*Figure 15 — Full desktop resolution (1920×1080): navigation sticky to top,
header retains three distinct zones.*

![Main interface at 1356x652](Documentation/screenshots_en/02-main-interface-1356x652.png)

*Figure 16 — Laptop resolution (1356×652). History and Traffic tables maintain
their dedicated area, while raw request/response panels adapt cleanly.*

### Step 5 — Open Command Palette

Press `Ctrl+K` (on macOS — `Cmd+K`):

![Command palette](Documentation/screenshots_en/05-command-palette.png)

*Figure 17 — All tabs accessible by keyboard navigation. Filter by typing; `Esc` dismisses.*

### Step 6 — Create First Project

Projects are optional, but without one, History, Traffic, scanners, and OSINT
will lack organizational context. Detailed in [7.1](#71-projects).

---

## 6. User Interface

### 6.1 Header

![Header with three zones](Documentation/screenshots_en/01-main-interface-1920.png)

*Figure 18 — Project and process status on the left, logo in center, session
controls and language switcher on the right.*

| Element | Position | Purpose |
|---|---|---|
| `Project: <name>` | Far left | Active project name. `No project` = standalone mode |
| `ENGINE ●` | Left | Engine health status + `↺` recheck button |
| `PROXY :8080 ●` | Left | Passive proxy listener status |
| `ROUTE Direct ●` | Left | Active outbound routing route |
| `⚙️` (gear) | Right | **Global Settings**: DNS (UDP/DoH), split-horizon rules, hosts overrides, JA3 TLS profiles, and DNS cache flush |
| `Save` | Right | Saves all workspaces to local session storage |
| `Export` | Right | Exports working session to JSON bundle |
| `Import` | Right | Imports working session from JSON file |
| `English` / `Українська` | Far right | Interface language toggle |

### 6.2 Navigation Bar

Eleven dedicated tool tabs + `History` + `Traffic` + `Projects`:

![Repeater tab](Documentation/screenshots_en/10-tab-repeater.png)

*Figure 19 — Repeater. Active tab highlighted in green with border.*

![Intruder tab](Documentation/screenshots_en/11-tab-intruder.png)

*Figure 20 — Intruder. Fuzzing with `§...§` markers, form detection, and Login Detection.*

![Target tab](Documentation/screenshots_en/12-tab-target.png)

*Figure 21 — Target. Application node map, status codes, crawler integration, and JS bundle analysis.*

![OSINT tab](Documentation/screenshots_en/13-tab-osint.png)

*Figure 22 — Reconnaissance (OSINT).*

![Scanner tab](Documentation/screenshots_en/14-tab-scanner.png)

*Figure 23 — Scanner. Note two subviews: CMS Recon and Active Scanner (Active & Corpus Scanner).*

![Comparer tab](Documentation/screenshots_en/16-tab-comparer.png)

*Figure 24 — Comparer.*

![Decoder tab](Documentation/screenshots_en/17-tab-decoder.png)

*Figure 25 — Decoder.*

![Tor/Proxy tab](Documentation/screenshots_en/15-tab-proxy.png)

*Figure 26 — Tor/Proxy.*

![Agent tab](Documentation/screenshots_en/18-tab-ai.png)

*Figure 27 — AI Agent. ReAct loop (Thought / Action / Observation), 16 MCP tools panel, audit report exports (HTML / JSON).*

![Automation tab](Documentation/screenshots_en/19-tab-automation.png)

*Figure 28 — Automation. Interactive node canvas, LLM analysis nodes, HTTP triggers, execution run log.*

![History tab](Documentation/screenshots_en/20-tab-history.png)

*Figure 29 — History. Shared view without workspace bar; aggregates all manual exchanges.*

![Traffic tab](Documentation/screenshots_en/21-tab-traffic.png)

*Figure 30 — Traffic.*

![Projects tab](Documentation/screenshots_en/22-tab-projects.png)

*Figure 31 — Projects with list of available projects.*

**Keyboard Navigation.** Arrow keys `←`/`→` switch tabs; `Home`/`End` jump to
first and last tabs, implemented via `setupAccessibleTabs`.

### 6.3 Workspace Bar

Located beneath the navigation bar for each individual tool:

![Single workspace](Documentation/screenshots_en/190-workspace-single.png)

*Figure 32 — "Repeater 1 ×" with `+` button to create additional workspaces.*

![Second workspace created](Documentation/screenshots_en/191-workspace-created.png)

*Figure 33 — After clicking `+`, "Repeater 2" appears. Two contexts operate
simultaneously with independent requests, responses, and states.*

![Workspace renamed](Documentation/screenshots_en/192-workspace-renamed.png)

*Figure 34 — **Double-clicking** a workspace tab opens the rename dialog.
Clicking `×` closes the tab (at least one workspace must remain).*

![Session saved](Documentation/screenshots_en/193-session-saved.png)

*Figure 35 — `Save Session` commits all workspaces locally; status updates to
"Saved locally fully".*

![Session exported](Documentation/screenshots_en/194-session-exported.png)

*Figure 36 — `Export` produces a JSON file portable to any other stand via `Import`.*

![Workspace closed](Documentation/screenshots_en/195-workspace-closed.png)

*Figure 37 — Closing the second workspace returns focus to the remaining workspace.*

### 6.4 Shared UI Elements

| Element | Location | Purpose |
|---|---|---|
| **Workspace Bar** | All tools | Independent concurrent contexts per tool |
| **Inspector** (Selected Request / Selected Response) | History, Traffic, Intruder | Full raw exchange view for highlighted row |
| **Text Filter** | History, Traffic, Target, Intruder | In-memory row filtering without server query |
| **Column Sorting** | History, Traffic, Target, Intruder | Sorts table rows ascending/descending |
| **"Show More · N of M" Button** | History, Traffic, Corpus Scanner | Fetches next page of database records |
| **Export Menu `Export ▾`** | Almost all tabs | JSON / HTML / CSV |
| **`Send to AI` / `Send to Automation`** | Repeater, Intruder, Target, OSINT, Scanner, Comparer, Decoder | Pipelines current record into other tools |
| **`table-resizer` Divider** | History, Traffic | Draggable border between table and raw inspection panels |
| **Toast Notifications** | All | Brief action confirmation or error notice (persists ≥ 4s) |
| **Context Menu `⋯`** | History, Traffic, Intruder, Target | Row-level contextual actions |

### 6.5 Resizable Divider

In History and Traffic, a draggable divider separates the table and raw panels:

- **Upward drag** — expands table row visibility;
- **Downward drag** — returns to layout default;
- **Keyboard arrow keys** — incremental stepping when focused.

Guaranteed constraint: the divider **never encroaches below `min(148px, 38%)`**,
ensuring the raw inspection panel always remains readable (verified by
`test_divider_never_covers_the_raw_block`).

---

## 7. Core Features

Request-Rider provides 11 dedicated functional tools, 2 aggregate audit
views (History and Traffic), and a Project workspace hub.

---

### 7.1 Projects

**What it is.** A project is an overarching workspace that aggregates everything
discovered on a specific target: endpoints, exchanges from History and Traffic,
scanner runs, OSINT entity graphs, automation workflows, and secret references.

**Why it is needed.** Without a project, individual tools function normally, but
their findings lack unified context: History records requests independently, and
scanners cannot correlate target severity. Projects answer the question: "What do
we know about this target system as a whole?"

**How to use:**

Step 1 — Open the **Projects** tab.

![Empty project list](Documentation/screenshots_en/20-projects-empty.png)

*Figure 38 — Fresh database state: no projects exist, active project indicates "No project".*

Step 2 — Click **New Project**.

![Create project dialog](Documentation/screenshots_en/21-project-create-dialog.png)

*Figure 39 — Dialog with required fields: Name and Target.*

Step 3 — Populate the fields.

![Populated create dialog](Documentation/screenshots_en/22-project-create-filled.png)

*Figure 40 — Name `Demo Audit Project`, target `https://news.mail.ru/`.*

Step 4 — Click **Save** in the dialog.

![Project created and Knowledge Hub opened](Documentation/screenshots_en/23-project-created-and-hub.png)

![Project created and activated](Documentation/screenshots_en/23-project-created.png)

*Figure 41 — Project created: appears in the active list, counters begin accumulating, and it becomes the global active project across all tools.*

![Project list before creation](Documentation/screenshots_en/20a-projects-clean-list.png)

*Figure 42 — Clean state prior to creation: empty list, zero counters, and an explicit hint reminding that tools function without a project, but findings will not be centralized.*

*Figure 43 — Project activated and **Knowledge Hub** opened — providing a unified summary of stored state.*

Step 5 — Click **Manage Project** to modify properties.

![Edit project dialog](Documentation/screenshots_en/23a-project-edit-dialog.png)

*Figure 44 — `Manage Project` dialog: Name, Target, Environment, Route Profile. Buttons: **Cancel** and **Save**.*

Step 6 — Review Knowledge Hub tabs.

![Asset map](Documentation/screenshots_en/25-project-hub-map.png)

*Figure 45 — "Asset Map": all endpoints gathered from History, Traffic, scanners, and browser crawls. Initially empty on a new project — populates automatically as tools operate.*

![Secrets](Documentation/screenshots_en/26-project-hub-secrets.png)

*Figure 46 — "Secrets": stores full credential values. JWT tokens, session cookies, and authorization headers are displayed verbatim without redaction or clipping, and flow into reports (`## Secrets`), JSON exports, and `## Notes`.*

![Scanner runs](Documentation/screenshots_en/27-project-hub-scanner.png)

*Figure 47 — "Scanner": stored execution logs and findings across all scanner engines.*

![Workflows](Documentation/screenshots_en/28-project-hub-workflows.png)

*Figure 48 — "Workflows": automation workflows linked to the project.*

![AI Snapshot](Documentation/screenshots_en/29-project-hub-ai.png)

![Knowledge Hub overview](Documentation/screenshots_en/24-project-hub-overview.png)

*Figure 49 — Comprehensive overview: endpoints, vulnerabilities, saved attacks, exchanges, and workspaces unified in a single dashboard.*

*Figure 50 — "AI Snapshot": structured Markdown context ready for ingestion by LLM agents.*

Step 7 — Export the project.

![Project export menu](Documentation/screenshots_en/30-project-export-menu.png)

*Figure 51 — Three export formats: **JSON** (portable bundle for re-import), **HTML** (standalone interactive report), and **CSV** (one row per record).*

Step 8 — Import project on another machine: Click **Import Project** → select `.json` bundle → imported project appears as a **new** project.

> **Important note on import:** `POST /api/projects/import` **always creates a new**
> project rather than updating existing ones. Identifiers, webhook slugs, and capture
> tokens are re-generated fresh, preventing collision. Imported workflows are initialized
> in an inactive state.

**Expected result:** The active project name is displayed in the header, History and Traffic automatically correlate exchanges with it, scanners record runs into the Knowledge Hub, and reports are clearly scoped.

**Potential Error: Project Creation Fails**

Cause: A project with this name already exists.

Detection: The header status bar indicates `Project error: project could not be saved`, and the project list remains unchanged.

Resolution: Choose a distinct name or delete the previous project via **Delete Project**.

![Project creation error](Documentation/screenshots_en/31-project-create-error.png)

*Figure 52 — State following failed creation: no active project selected, management buttons remain disabled, and Knowledge Hub is hidden.*

---

### 7.2 Repeater

**What it is.** A dedicated interface for manual HTTP request crafting and full raw response inspection. Requests are authored in **raw plaintext**, matching wire format.

**Why it is needed.** The fundamental workflow of security auditing: alter a single header, observe response differentials, and verify how the endpoint behaves under arbitrary methods or payloads.

**How to use:**

Step 1 — Open the **Repeater** tab.

![Repeater initial empty state](Documentation/screenshots_en/40-repeater-empty.png)

*Figure 53 — Empty state: "REQUEST" pane on the left, "RESPONSE" pane on the right.*

Step 2 — Enter raw HTTP request in the left pane.

![Repeater request entered](Documentation/screenshots_en/41-repeater-request-typed.png)

*Figure 54 — Request ready to send. First line specifies method and path, followed by headers, a blank line, and optional body.*

Step 3 — Click **Send** (or press `Ctrl/Cmd + Enter`).

![Repeater response received](Documentation/screenshots_en/42-repeater-response.png)

*Figure 55 — Full raw response displayed: status `HTTP/1.1 200 OK`, response headers, and body `ok`. Header metrics show `200 · 2 BYTES · 2 MS`. Action buttons enabled: **Copy Response**, **Compare Response**, **Clear**, **Send to AI**, **Send to Automation**, **cURL**.*

Step 4 — Open request inspector.

![Inspector: query parameters](Documentation/screenshots_en/43-repeater-inspector-query-params.png)

*Figure 56 — Inspector parses the raw request. "Query Parameters" tab presents parsed key-value pairs; **+ Add Parameter** appends a new pair.*

![Inspector: body parameters](Documentation/screenshots_en/44-repeater-inspector-body-params.png)

*Figure 57 — "Body Parameters" tab. Below, "Headers" and "Raw Request" sections remain accessible, ensuring the raw source of truth is never hidden.*

Step 5 — Dispatch request with payload body.

![POST with body and response](Documentation/screenshots_en/45-repeater-post-response.png)

*Figure 58 — POST request with `Content-Type`, `Cookie`, and form body `sort=desc`.*

Step 6 — Copy request as cURL command.

![Copy cURL button and toast](Documentation/screenshots_en/46-repeater-copy-curl-toast.png)

*Figure 59 — **cURL** button copies an exact command line string to your clipboard for terminal reproduction.*

Step 7 — Pipe response into Comparer.

![Response sent to Comparer](Documentation/screenshots_en/47-repeater-sent-to-comparer.png)

*Figure 60 — **Compare Response** copies response text into the left pane of the Comparer tab for differential analysis.*

Step 8 — Configure Repeater tab and HTTP/2 protocol.

In the upper right corner of the control bar, click the gear icon **`⚙️`** (or press `Ctrl+K` -> Tab Settings). The dialog configures:
- **HTTP Protocol Version**: Defaults to `Auto-negotiate` — engine negotiates **HTTP/2** via TLS ALPN `h2` if supported by target (reflected in status `HTTP/2.0 200 OK`). Modes available: `Force HTTP/1.0`, `Force HTTP/1.1`, and `Force HTTP/2`.
- **Request Timeout**: Request timeout in seconds (1–120s).
- **Follow Redirects**: Redirect behavior (`Off`, `Same Host Only`, `Always`).
- **Auto-update Content-Length**: Recalculates body length automatically upon edit.
- **Enable Baseline Auto-Diff**: Automatic inline diff highlighting against baseline response.

**Tool Parameters**

| Field | Function |
|---|---|
| `#repeater-host`, `#repeater-path` | Mirror first line of request for convenience; raw editor remains source of truth |
| Request textarea | Primary source of truth. In-editor `Host:` takes precedence |
| `Ctrl/Cmd + Enter` | Keyboard shortcut to dispatch |
| `Clear` | Clears request and response panes |
| **Inspector** | Collapsible structured parameter editor |
| **Gear `⚙️`** | Timeout, redirect handling, and HTTP version selection (HTTP/2, HTTP/1.1, HTTP/1.0) |

**Expected result:** Raw response displayed on the right; exchange logged into History with `source="repeater"`.

**Potential Error: `Request is empty`**

Cause: Request editor is blank or contains only whitespace.

Resolution: Provide at minimum `METHOD /path HTTP/1.1` and a `Host:` header.

**Potential Error: Request Fails to Reach Target**

Cause: Invalid `Host`, filtered port, or unreachable network.

Resolution: Verify `Host` resolution independently and verify **Tor/Proxy** settings do not route traffic to an unreachable proxy.

---

### 7.3 Intruder

**What it is.** An HTTP fuzzer: substitutes values from wordlists into marked request positions, executes combinations, and records structured results alongside full requests and responses.

**Why it is needed.** Discover parameters and payloads that elicit unique server responses: length deviations, anomalous status codes, redirects, or session tokens.

**How to use:**

Step 1 — Open the **Intruder** tab and enter a base request.

![Intruder empty state](Documentation/screenshots_en/70-intruder-empty.png)

*Figure 61 — Empty state: "REQUEST" pane on the left, "TARGET" and options on the right, wordlists below.*

Step 2 — Define injection markers.

![Markers in request editor](Documentation/screenshots_en/71-intruder-markers-in-request.png)

*Figure 62 — `§term§` wrapping target parameter. Three marker formats are supported: `§name§`, `{{name}}`, and `%name%`. Alternatively, highlight text in the editor and click **Add § markers**.*

Step 3 — Populate wordlists.

![Wordlists configured](Documentation/screenshots_en/72-intruder-dictionaries.png)

*Figure 63 — Two wordlists: `term` (8 items) and `page` (3 items). **Add Wordlist** creates a list; **Browse...** loads `.txt`/`.list`/`.dic`; **Delete** removes. One payload per line.*

Step 4 — Select attack mode and parameters.

![Pitchfork mode and task estimation](Documentation/screenshots_en/73-intruder-options-review.png)

*Figure 64 — **Pitchfork** mode selected, `0 ms` delay, concurrency `4`. "REVIEW" panel summarizes target, mode, delay, concurrency, and **estimated task count**.*

Step 5 — Click **Start Attack**.

![Attack executing](Documentation/screenshots_en/74-intruder-running.png)

*Figure 65 — Active attack controls: **Pause Attack**, **Resume Attack**, and **Cancel Attack**.*

Step 6 — Inspect execution results.

![Pitchfork results: 3 tasks](Documentation/screenshots_en/75-intruder-results-pitchfork.png)

*Figure 66 — **Pitchfork mode rule verification**: wordlist 1 (`term`, 8 items) and wordlist 2 (`page`, 3 items) generated exactly **3 requests**. Pitchfork iterates in parallel **up to the length of the shortest list**.*

Step 7 — Switch to Cartesian product (Cluster Bomb) and re-run.

![Cluster Bomb results: 24 tasks](Documentation/screenshots_en/75b-intruder-results-cluster-bomb.png)

*Figure 67 — **Cluster Bomb** produced 8 × 3 = **24 requests**. Status line: `8/24 matches · finished · 24/24 completed (100%) · 0 errors · shown 24/24`. "MATCH" column highlights divergence reason: `Different body +20 B`.*

**Attack Modes Matrix**

| Mode | Behavior | Example (8 and 3 items) |
|---|---|---|
| **Sniper** | Substitutes the **first** wordlist into each marker individually | 8 requests per marker |
| **Battering Ram** | Substitutes identical payload into **all** markers simultaneously | 8 requests |
| **Pitchfork** | Iterates through lists in lockstep **until shortest list exhausted** | 3 requests |
| **Cluster Bomb** | Full Cartesian product of all wordlists | 24 requests |

Step 8 — Inspect result row.

![Raw exchange of selected result](Documentation/screenshots_en/76-intruder-row-inspector.png)

*Figure 68 — Inspection panes: "SELECTED REQUEST" and "SELECTED RESPONSE" reveal exact wire exchanges for the selected payload.*

Step 9 — Filter and sort results.

![Status filter in Intruder](Documentation/screenshots_en/77-intruder-filter-status.png)

*Figure 69 — Filter by status code or payload string. Checking **MATCHES ONLY** isolates detected anomalies.*

![Sorted results](Documentation/screenshots_en/78-intruder-sorted-by-status.png)

*Figure 70 — Sorting by Status, Length, or Duration in ascending/descending order.*

Step 10 — Export findings.

![Intruder export menu](Documentation/screenshots_en/79-intruder-export-menu.png)

*Figure 71 — **JSON** (full raw exchanges), **HTML** (interactive report), **CSV** (row-per-result table).*

Step 11 — Save attack profile.

![Save attack dialog](Documentation/screenshots_en/80-intruder-save-dialog.png)

*Figure 72 — **Save Attack** stores complete configuration: request template, mode, wordlists, transforms, delay, and concurrency.*

![Saved attacks list](Documentation/screenshots_en/81-intruder-saved-list.png)

*Figure 73 — Saved attacks stored in PostgreSQL; **Load Selected** restores configuration, **Run Selected** executes immediately.*

Step 12 — Configure payload transformations.

![Transformation added](Documentation/screenshots_en/82-intruder-transformation-added.png)

*Figure 74 — Select operation (e.g. `base64Encode`) and click **Add Transformation**. Transforms execute left-to-right on each payload. Value fields appear dynamically for `prepend` and `append`.*

Step 13 — Enable Login Detection.

![Successful login detection enabled](Documentation/screenshots_en/83-intruder-login-detection.png)

*Figure 75 — Checkbox "Detect successful login" enabled. Analyzes status code, redirect targets, session cookies, response length, and body reflections.*

---

### 7.3.1 Authentication & Login Detection

Intruder features an intelligent response evaluator distinguishing authentication forms, successful logins (`AUTH SUCCESS`), and authentication bypasses (`AUTH BYPASS`):
- **Automatic Baseline Calibration**: Dispatches initial probe requests to profile failed login behavior (body size variance, HTTP status, parameter reflection).
- **Multi-signal Evaluation**: Simultaneously measures 5 vectors: session cookie issuance (`Set-Cookie: token/session`), HTTP redirects (`302 Found` to `/dashboard` or `/profile`), body length delta thresholds, status code shifts, and JSON token presence (JWT).
- **Match Indicator Column**: Tags requests successfully bypassing or authenticating against the target.

![Raw exchange inspection with auth detection](Documentation/screenshots_en/76-intruder-row-inspector.png)

*Figure 76 — Result inspector: left panel displays generated fuzzed request; right panel displays server response with identified authentication status and latency.*

---

### 7.4 Target

**What it is.** A web crawler mapping target architecture: URL hierarchy, depth, status codes, MIME types, and network evidence (in browser-driven mode).

**Why it is needed.** Maps attack surfaces prior to manual auditing: identifies static and dynamic pages, discovered scripts, API routes, and XHR requests.

**How to use:**

Step 1 — Open the **Target** tab.

![Target initial empty state](Documentation/screenshots_en/90-target-empty.png)

*Figure 79 — Empty state.*

Step 2 — Enter root URL and crawl constraints.

![Target crawl executing](Documentation/screenshots_en/91-target-running.png)

*Figure 80 — Active crawl controls: **Cancel** halts discovery.*

Step 3 — Inspect site map and crawler findings.

![Target map built](Documentation/screenshots_en/92-target-map-built.png)

*Figure 81 — **Built site map**: interactive URL tree on the left, resource table on the right displaying MIME types, HTTP statuses (`200`, `304`, `404`), byte sizes, and crawl depth.*

![JavaScript findings and endpoint badges](Documentation/screenshots_en/321-target-js-badges-1920.png)

*Figure 81a — **JavaScript Analysis (`js-findings`)**: automated parsing of modern SPA bundles (Angular/React/Vue). Discovers hidden API routes (`/rest/user/login`, `/api/Challenges`), login endpoints, and credentials, accompanied by HTTP method badges.*

Step 4 — Select table row.

![Selected target row](Documentation/screenshots_en/93-target-row-selected.png)

*Figure 82 — Selected row highlighted in inspector; `↩` in the Actions column forwards the URL to **Repeater**, while `⋯` opens contextual actions (Export evidence, Repeater, Intruder, Automation).*

Step 5 — Filter and organize tree.

![Filter target by URL](Documentation/screenshots_en/94-target-filtered.png)

*Figure 83 — Filter term `api` isolates matching endpoints.*

![Collapsed target tree](Documentation/screenshots_en/95-target-collapsed.png)

*Figure 84 — **Collapse All** and **Expand All** toggle tree levels; **Clear** resets the filter.*

Step 6 — Export and pipeline findings.

The action toolbar is organized into two tiers:
- **Crawler Control Bar**: **Build Map**, **Pause**, **Resume**, **Cancel**, and **Re-dispatch Undelivered Pages**.
- **Export & Transfer Bar**:
  - Unified **Export ▾** menu (JSON, CSV, HTML report). HTML export is self-contained with zero CDN dependencies.
  - Action buttons: **🤖 Send Map to AI** (injects map into LLM Agent context) and **🚀 Send to Automation** (pipes discovered URLs into workflow nodes).

![HTML target map export](Documentation/screenshots_en/96-target-export-html.png)

*Figure 85 — **Export JSON / CSV / HTML** via unified dropdown menu and rapid transfer buttons to AI and Automation.*

Step 7 — Validate URL format handling.

![Invalid URL error state](Documentation/screenshots_en/97-target-invalid-url-error.png)

*Figure 86 — Malformed input `ht!tp://not-a-url` is rejected with explanatory status banner.*

Step 8 — Enable Browser-Driven Mode.

![Browser crawler configuration](Documentation/screenshots_en/98-target-browser-options.png)

*Figure 87 — "ENGINE" switches to "Navigation mode", enabling browser selection (Firefox / Chromium / Chrome / Edge / WebKit) and "BROWSER CRAWLER" options: navigation timeout, SPA settlement delay, antidetect spoofing, challenge solvers, and challenge timeouts.*

Step 9 — Execute browser crawl.

![Browser crawl executing](Documentation/screenshots_en/99-target-browser-running.png)

*Figure 88 — Browser mode executes dynamic JavaScript, capturing DOM mutations and AJAX events.*

![Browser crawl results](Documentation/screenshots_en/100-target-browser-result.png)

*Figure 89 — Browser crawl results including client-side network evidence.*

Step 10 — Filter captured network traffic.

![Filter XHR requests](Documentation/screenshots_en/101-target-browser-network-filter.png)

*Figure 90 — Filter network events: `All / XHR / Documents / Scripts / Other`.*

**Configuration Parameters**

| Group | Field | Default | Function |
|---|---|---|---|
| Limits | Max pages | `0` | `0` or negative = **unlimited** |
| Limits | Max depth | `-1` | `-1` or negative = **unlimited** |
| Limits | Delay ms | `0` | Pause between successive requests |
| Limits | Same origin only | Enabled | Restrict crawls to initial host |
| Browser Crawler | Navigation timeout ms | `0` | `0` = unlimited |
| Browser Crawler | Settlement wait ms | `15000` | Wait duration for SPA JS rendering |
| Browser Crawler | Antidetect | Enabled | Masks automation signatures |
| Browser Crawler | Solve challenges | Enabled | Solves challenges and captchas |
| Static Crawler | Accept-Language | `uk-UA,uk;q=0.9` | Injected language header |
| Static Crawler | Retry attempts | `0` | `0` = no retries |
| Auto-traversal | Forms / Buttons / Forms & Buttons | Forms & buttons | Automatically triggers interactive elements |

> **User-controlled boundaries:** `0` and `-1` represent "unlimited", not "forbidden".
> Input parameters are passed directly to execution engines without artificial hard limits.

---

### 7.5 Reconnaissance (OSINT)

**What it is.** Passive intelligence gathering against a target without active vulnerability probing: DNS, HTTP responses, detected technologies, security headers, discovered links, cookies — coupled with an interactive entity graph enriched by transforms.

**Why it is needed.** Build target context prior to testing: domains, subdomains, IPs, emails, software stacks, and missing defensive headers.

**How to use:**

Step 1 — Open the **Reconnaissance (OSINT)** tab.

![OSINT initial empty state](Documentation/screenshots_en/110-osint-empty.png)

*Figure 91 — Empty state: URL input field, WAF canary toggle, six summary cards, and an empty entity graph canvas.*

Step 2 — Enter URL and optionally check **Run safe WAF canary**.

![OSINT scan running](Documentation/screenshots_en/111-osint-running.png)

*Figure 92 — Scan in progress.*

Step 3 — Review the summary banner and six data cards.

![OSINT summary](Documentation/screenshots_en/112-osint-summary.png)

*Figure 93 — **Live target execution result**: IP `95.163.61.53`, MX `emx.mail.ru`, status 200, detected technologies (kittenx, jQuery, Google Tag Manager, Google Analytics, React, Open Graph, PWA, RSS, HTTPS), security headers audit (`CSP: present false`, `X-Frame-Options: SAMEORIGIN`, `HSTS: max-age=16070400`), discovery of **660 links**, and verified `robots.txt` / `sitemap.xml` presence.*

**Summary Cards**

| Card | Contents |
|---|---|
| `DNS / IP` | A records, MX, NS, TXT |
| `HTTP / Redirects` | Status code, MIME type, payload length, redirect chain |
| `Security / WAF` | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| `Technologies` | Web server, CMS, frontend libraries, analytics, frameworks |
| `Discovery` | Count of extracted links, `robots.txt`, `sitemap.xml` |
| `Cookies` | Discovered cookies and security attributes |

Step 4 — Export findings.

![OSINT export buttons enabled](Documentation/screenshots_en/113-osint-exports-enabled.png)

*Figure 94 — **Export JSON** and **Export CSV** activate immediately upon scan completion.*

Step 5 — Create an entity graph.

![Entity graph created](Documentation/screenshots_en/114-osint-graph-created.png)

*Figure 95 — **Create Graph** prompts for a name. The graph is stored in PostgreSQL and linked to the active project.*

Step 6 — Add an initial entity.

![Add entity form dialog](Documentation/screenshots_en/115-osint-graph-add-entity-form.png)

*Figure 96 — **Add Entity**: Select entity type (Domain, Subdomain, IP, URL, Email, Username, ASN, Technology, Cloud Asset) and provide a value.*

![Entity rendered on canvas](Documentation/screenshots_en/116-osint-graph-entity-added.png)

*Figure 97 — The entity appears on the SVG canvas.*

Step 7 — Open context menu.

![Entity context menu](Documentation/screenshots_en/117-osint-graph-context-menu.png)

*Figure 98 — **Right-click** on an entity: Edit, Delete, and a list of transforms applicable to that entity type. Network transforms require explicit operator confirmation.*

Step 8 — Filter, scale, and layout.

![Entity filter](Documentation/screenshots_en/118-osint-graph-filter.png)

*Figure 99 — "Filter entities" isolates matching nodes in real time.*

![Graph zoom](Documentation/screenshots_en/119-osint-graph-zoomed.png)

*Figure 100 — `−`/`+` adjust zoom, `Fit` scales graph into canvas viewport, `Reset` restores 100% scale.*

![Breadthfirst graph layout](Documentation/screenshots_en/120-osint-graph-layout-breadthfirst.png)

*Figure 101 — Layout options: **Grid / Radial / Concentric / Breadthfirst**. **Auto-layout** recalculates node coordinates; manual placement is supported via dragging.*

![Graph HTML export](Documentation/screenshots_en/121-osint-graph-export-html.png)

*Figure 102 — **Export Graph HTML** generates a self-contained, standalone report.*

Step 9 — Refresh or manage graph.

![Graph refreshed](Documentation/screenshots_en/122-osint-graph-refreshed.png)

*Figure 103 — **Refresh** re-syncs state from the server; **Clear Graph** empties all nodes; **Delete Graph** removes the graph record entirely.*

**Canvas Accessibility.** In addition to pointer navigation, the graph is fully keyboard accessible: `select#osint-graph-focus-list` (labeled "keyboard") allows cycling through entities with arrow keys, `Enter` opens node details, and selection changes are announced via live regions for screen readers.

**Transforms** — 16 transform operations organized into functional categories:

| Category | Transforms |
|---|---|
| Identity | `email_recon`, `username_enum`, `username_search` |
| Network | `ip_geo`, `email_domain`, `username_normalize`, `domain_normalize`, `url_host`, `reverse_dns`, `dns_records`, `subdomains` |
| Code Repositories | `github_recon`, `git_secrets`, `secret_scan` |
| Historical Archives | `wayback_urls`, `s3_buckets` |

> **Network transforms require confirmation:** `subdomains`, `github_recon`,
> `reverse_dns`, `dns_records`, `wayback_urls`, and `s3_buckets` dispatch live
> external network requests. Calls require an explicit `confirm_network=true` parameter,
> without which the API returns `NETWORK_CONFIRMATION_REQUIRED`. Local transforms
> (`email_domain`, `url_host`, `domain_normalize`, etc.) execute instantly without confirmation.

**Expected result:** Six populated intelligence cards, an interactive entity graph exportable to HTML/JSON, and technology assets automatically correlated with the project.

---

#### 7.5.1 All Nineteen Transforms

A transform takes a single source entity and expands the graph with correlated entities: domains, IP addresses, technologies, usernames, or ASN nodes. Transforms are triggered via **the node context menu**: right-click any graph entity → select the transform name.

![Entity graph before transforms](Documentation/screenshots_en/200-osint-graph-built.png)

*Figure 104 — Entity graph before transformation: domain, subdomain, IP address, URL, email, technology, and username nodes.*

**Two Execution Tiers.** Eight transforms are **local** — parsing and normalizing existing string data without outbound traffic. Eleven transforms are **network-based** — querying external registries and services, prompting for confirmation prior to dispatch:

![Network transform confirmation dialog](Documentation/screenshots_en/210-osint-transform-reverse_dns-confirm.png)

*Figure 105 — Operator confirmation prompt for network-based transforms.*

**Complete Transform Registry & Compatibility Matrix:** The "Accepts" column indicates valid input entity types. Any mismatched input is immediately rejected with `TRANSFORM_NOT_APPLICABLE` **without issuing a network request**.

| Transform | Network | Accepts | Additional Parameters |
|---|---|---|---|
| `email_recon` | No | `email` | — |
| `username_enum` | No | `username` | — |
| `username_normalize` | No | `username` | — |
| `email_domain` | No | `email` | — |
| `domain_normalize` | No | `domain`, `subdomain` | — |
| `url_host` | No | `url` | — |
| `ip_geo` | No | `ip` | — |
| `reverse_dns` | Yes | `ip`, `domain`, `subdomain` | — |
| `dns_records` | Yes | `domain`, `subdomain` | — |
| `subdomains` | Yes | `domain`, `subdomain` | **Concurrency** |
| `technology_probe` | Yes | `technology` | — |
| `wayback_urls` | Yes | `domain`, `subdomain` | — |
| `s3_buckets` | Yes | `domain`, `subdomain` | **Concurrency** |
| `cidr_range` | Yes | `cidr` | **Concurrency** |
| `asn_lookup` | Yes | `asn` | **Concurrency** |
| `username_search` | Yes | `username` | Platform limit |
| `github_recon` | Yes | `username` | — |
| `git_secrets` | Yes | Any value | — |
| `secret_scan` | Yes | Any value | — |

Four transforms expose a **concurrency** slider. This control dynamically binds to the engine's worker pool configuration when supported.

#### 7.5.2 Local Transforms Step-by-Step

Local transforms operate entirely in-memory:

![email_recon on email address](Documentation/screenshots_en/203-osint-transform-email_recon-result.png)

*Figure 106 — `email_recon` on `noreply@mail.ru`: normalizes address and resolves domain entity. Status confirms **"local only → COMPLETED"**. Passing a domain yields `TRANSFORM_NOT_APPLICABLE`.*

![username_enum on username](Documentation/screenshots_en/204-osint-transform-username_enum-result.png)

*Figure 107 — `username_enum` on `admin`: canonicalizes username. External platform probing is isolated to `username_search`.*

![username_normalize](Documentation/screenshots_en/205-osint-transform-username_normalize-result.png)

*Figure 108 — `username_normalize` on `Admin.Mail`: produces canonical representation so identical handles across platforms merge into a single entity.*

![domain_normalize](Documentation/screenshots_en/206-osint-transform-domain_normalize-result.png)

*Figure 109 — `domain_normalize` on `WWW.MAIL.RU`: strips casing and trailing dots to yield `mail.ru`. `HTTPS://WWW.MAIL.RU/path` is rejected as incompatible; stripping schemes and paths is handled by `url_host`.*

![url_host](Documentation/screenshots_en/207-osint-transform-url_host-result.png)

*Figure 110 — `url_host` on `https://news.mail.ru/2026/10/02/`: extracts host entity from full URL.*

![ip_geo](Documentation/screenshots_en/208-osint-transform-ip_geo-result.png)

*Figure 111 — `ip_geo` on `95.163.61.53`. If the local GeoIP database is unconfigured, the status bar explicitly reports `GeoIP database is not configured; no database download or network lookup was performed`.*

![email_domain](Documentation/screenshots_en/209-osint-transform-email_domain-result.png)

*Figure 112 — `email_domain` on `noreply@mail.ru`: extracts normalized apex domain `mail.ru`.*

#### 7.5.3 Network Transforms Step-by-Step

Network transforms query external intelligence indices, providing real-time progress counters, **Pause, Resume, and Cancel** controls:

![reverse_dns](Documentation/screenshots_en/210-osint-transform-reverse_dns-result.png)

*Figure 113 — `reverse_dns` on `95.163.61.53`: resolves PTR name alongside neighboring domains co-hosted on that IP via public shared-hosting indices, linked with `hosted_on` and `provenance: shared_hosting_index`.*

![dns_records](Documentation/screenshots_en/211-osint-transform-dns_records-result.png)

*Figure 114 — `dns_records` on `mail.ru`: A/AAAA records combined with domain and IP reputation scores.*

![subdomains running](Documentation/screenshots_en/212-osint-transform-subdomains-running.png)

*Figure 115 — `subdomains` in progress: queries Certificate Transparency logs, crawls web pages, and performs DNS brute forcing.*

![subdomains completed result](Documentation/screenshots_en/212-osint-transform-subdomains-result.png)

*Figure 116 — `subdomains` on `mail.ru`: **9,702 names** collected, **3 of 5** Certificate Transparency logs queried at **15 names/second**. Progress counters reflect live telemetry.*

> **Zone handling detail:** Certificate Transparency indices are queried by apex zone
> rather than arbitrary subdomains. `subdomains` automatically traverses the zone chain
> from most specific to apex, halting at the first authoritative source yielding new records.

![technology_probe](Documentation/screenshots_en/213-osint-transform-technology_probe-result.png)

*Figure 117 — `technology_probe` on `https://news.mail.ru/`: validates fingerprint findings against live HTTP response headers.*

![wayback_urls](Documentation/screenshots_en/214-osint-transform-wayback_urls-result.png)

*Figure 118 — `wayback_urls` on `news.mail.ru`: retrieves archived URL indices from Wayback Machine (`web.archive.org`) and Common Crawl.*

![s3_buckets](Documentation/screenshots_en/215-osint-transform-s3_buckets-result.png)

*Figure 119 — `s3_buckets` on `mail.ru`: checks cloud storage buckets matching organizational naming schemes.*

![cidr_range](Documentation/screenshots_en/216-osint-transform-cidr_range-result.png)

*Figure 120 — `cidr_range` on `95.163.61.53`: identifies network boundary. Requires CIDR notation; raw IPs are rejected.*

![asn_lookup](Documentation/screenshots_en/217-osint-transform-asn_lookup-result.png)

*Figure 121 — `asn_lookup`: identifies autonomous system ownership.*

![username_search](Documentation/screenshots_en/218-osint-transform-username_search-result.png)

*Figure 122 — `username_search`: queries multi-platform catalog (merging Sherlock and Maigret definitions across **5,648 platforms**) with configurable search budget.*

![github_recon](Documentation/screenshots_en/219-osint-transform-github_recon-result.png)

*Figure 123 — `github_recon`: multi-phase audit covering profile, activity events, and commit history. Commits are attributed strictly when GitHub explicitly links author logins, filtering noreply and privacy masks.*

![git_secrets](Documentation/screenshots_en/220-osint-transform-git_secrets-result.png)

*Figure 124 — `git_secrets`: scans commit diffs across public repositories for leaked API keys, tokens, and private credentials.*

![secret_scan](Documentation/screenshots_en/221-osint-transform-secret_scan-result.png)

*Figure 125 — `secret_scan` on `mail.ru`: completed with 0 findings. Clean results are explicitly recorded without inventing false positives.*

#### 7.5.4 Graph State After All Transforms

![Entity graph after transforms](Documentation/screenshots_en/260-osint-graph-after-all-transforms.png)

*Figure 126 — Unified entity graph following execution of all nineteen transforms: cross-correlated assets annotated with source `provenance`.*

#### Potential Error: `TRANSFORM_NOT_APPLICABLE`

**Cause.** Transforms enforce strict typing. For example, `subdomains` queries Certificate Transparency logs and cannot process a `username` entity.

**Detection.** The status line displays an explanatory error code:

```
TRANSFORM_NOT_APPLICABLE: subdomains does not apply to username; it applies to domain, subdomain
```

**Resolution.** Right-click the appropriate node matching valid types: `domain`, `subdomain`, `ip`, `email`, `username`, `technology`, `asn`, `cidr`.

![Type mismatch rejection](Documentation/screenshots_en/231-scanner-error-invalid-url.png)

*Figure 127 — Type validation failure: explanatory error banner displayed without initiating external network requests.*

---

### 7.6 Scanner

The Scanner provides **two complementary subviews**. They do not overwrite each other:
CMS Reconnaissance does not erase Active Scan results, nor does an Active Scan clear CMS findings.
Each subview maintains its own results and export menus, while sharing target definition and status indicators.

![Two scanner subviews](Documentation/screenshots_en/14-tab-scanner.png)

*Figure 128 — Subview toggles: `CMS Recon` and `Active Scanner (Active & Corpus Scanner)` with unified `Target` field.*

---

#### 7.6.1 CMS Reconnaissance

**What it is.** Fast, read-only fingerprinting: detects CMS, server technologies, TLS configurations, cookies, allowed HTTP methods, security headers, and common sensitive paths.

**Why it is needed.** Rapidly profile application architecture within one minute prior to deploying resource-intensive active scans.

**How to use:**

Step 1 — Open the `CMS Recon` view and specify target.

![CMS recon empty state](Documentation/screenshots_en/200-scanner-cms-empty.png)

*Figure 129 — Initial view.*

Step 2 — Click **Run Safe CMS Recon**.

![CMS recon running](Documentation/screenshots_en/201-scanner-cms-running.png)

*Figure 130 — Status updates to `Running safe reconnaissance...`.*

Step 3 — Inspect findings.

![Live CMS recon findings](Documentation/screenshots_en/202-scanner-cms-findings.png)

*Figure 131 — **Live target execution result**: 5 findings, 14 read-only paths tested, cryptographic score `LOW`, and identified technology components with severity, proof, and remediations:*

- `[LOW] Admin panel path` — `/admin/` returned `HTTP 302`;
- `[LOW] Git metadata exposure` — `/.git/HEAD` returned `HTTP 301`;
- `[LOW] Server status exposure` — `/server-status` returned `HTTP 301`;
- `[INFO] Public HTTP service reachable`;
- `[INFO] Technology fingerprint detected`.*

Each finding includes actionable remediation guidance.

Step 4 — Export findings.

![CMS export menu](Documentation/screenshots_en/203-scanner-cms-export-menu.png)

*Figure 132 — Export options: **JSON / HTML / CSV**.*

> **Severity nuance:** A `LOW` finding with a redirect on `/admin/` is **not** a verified
> vulnerability. The tool reports path presence and leaves evaluation to the analyst:
> "Verify whether this endpoint is deliberately exposed."

---

#### 7.6.2 Active and Corpus Scanner (Active & Corpus Scanner)

**What it is.** An advanced vulnerability assessment engine (Scanner Pro) pairing active heuristic surface testing via nine detection modules with an extensive library of 5,522 signature tests (Corpus Database Checks).

**Why it is needed.** Identifies verifiable vulnerabilities with concrete **Proof of Impact**, generated reproduction cURL commands, and attack chain correlations without tedious manual fuzzing.

**Core Components:**
1. **Nine Heuristic Modules:**
   - `exposure` — Leaked credentials, API keys (AWS, GitHub, Stripe, Slack, JWT), with false-positive filtering.
   - `misconfig` — CORS misconfigurations, missing defensive headers (CSP, HSTS, X-Frame-Options), open directory listings.
   - `redirect` — Open Redirects across 12 vectors and client-side navigation primitives.
   - `ssrf` — Server-Side Request Forgery targeting internal metadata and cloud endpoints.
   - `sqli` — SQL Injection (error-based, boolean-blind, and time-based differentials).
   - `xss` — Cross-Site Scripting (reflected, DOM-based, script context escapes).
   - `traversal` — Path Traversal and Local File Inclusion (LFI).
   - `header_injection` — CRLF and HTTP Response Splitting.
   - `dependency` — Known CVEs and vulnerable component fingerprints.
2. **Corpus Database Checks:**
   - 5,522 curated vulnerability signatures categorized by technology, framework, and CVE.
3. **Multi-parameter Fuzzing Engine:**
   - Heuristic injection targeting query parameters (`QUERY`), body parameters (`BODY`), JSON payloads (`JSON`), and headers (`HEADER`).

**How to use:**

Step 1 — Open the `Active Scanner` view.

![Active scanner panel](Documentation/screenshots_en/220-scanner-active-panel.png)

*Figure 133 — Scanner operational rules and trigger controls.*

Step 2 — Configure crawl limits and scan options.

![Active scanner options](Documentation/screenshots_en/221-scanner-active-options.png)

*Figure 134 — Maximum pages, link recursion depth, workers, inter-request delay, request timeouts, same-host scope enforcement, redirect following, corpus check toggle, custom parameter wordlists, and hidden path lists.*

Step 3 — Click **Start Active Scan**.

![Active scan in progress](Documentation/screenshots_en/222-scanner-active-running.png)

*Figure 135 — Live progress telemetry: execution timer, running counters, and lifecycle controls (Pause, Resume, Cancel).*

Step 4 — Manage run lifecycle:
- **Pause**: Halts probe dispatch between requests, releases network sockets, and pauses timer without skewing metrics.
- **Resume**: Restores execution immediately from checkpoint.
- **Resend**: Re-dispatches timed-out or unacknowledged probes.
- **Cancel**: Terminates scan while preserving all findings gathered up to that moment.

Step 5 — Review verified findings with proof.

![Proven finding with proof](Documentation/screenshots_en/223-scanner-active-findings.png)

*Figure 136 — **Verified finding with proof of impact**:*

| Field | Value |
|---|---|
| Severity | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| Proof | **`Proven` (Proven impact)** |
| Module | `misconfig` (or `sqli`, `xss`, `ssrf`, etc.) |
| Endpoint | Target URL and HTTP method |
| Evidence | Response diff, confirming request, and **Show cURL** reproduction command |

Step 6 — Filter findings by severity and proof status.

![Filter by severity](Documentation/screenshots_en/224-scanner-active-severity-filter.png)

*Figure 137 — Rapid filtering: `All Severities / critical / high / medium / low / info` and toggle `Proven Only`.*

Step 7 — Inspect Corpus Database Checks & Details.
Expand `Corpus Database Checks & Details` to search checks by path, signature name, or paginate results via "Show more".

Step 8 — Export scan report.

![Active scanner export menu](Documentation/screenshots_en/225-scanner-active-export-menu.png)

*Figure 138 — Export formats: **JSON / HTML / CSV**.*

**Proof Status Definitions**

| Status | Meaning |
|---|---|
| **Proven** | Automated confirmation request succeeded and impact was verified. Real vulnerability with PoC |
| **Unconfirmed** | Server response exhibited anomalous divergence, but automated exploit confirmation did not complete. Requires manual validation |
| **Capped below high** | Proof verified, but severity is capped below high per safety and environmental constraints |

> Active scans operate strictly against targets you explicitly define, with no hidden
> rate or depth caps. Execution concludes upon user command or exhaustion of the crawl queue.

---

### 7.7 Comparer

**What it is.** Compares two arbitrary texts or raw HTTP exchanges: word-by-word or byte-by-byte.

**Why it is needed.** Pinpoint subtle deviations between "before" and "after" responses — highlighting hidden parameters or state shifts.

**How to use:**

Step 1 — Open the **Comparer** tab.

![Comparer initial empty state](Documentation/screenshots_en/50-comparer-words-diff.png)

*Figure 150 — Left and right input panes; differential results rendered below.*

Step 2 — Paste two payloads or HTTP exchanges into respective panes.

Step 3 — Click **Words**.

![Word-level comparison](Documentation/screenshots_en/50-comparer-words-diff.png)

*Figure 151 — Highlights diverging words. In this example, `Accept-Encoding: gzip` appears only in the right exchange.*

Step 4 — Click **Bytes**.

![Byte-level comparison](Documentation/screenshots_en/51-comparer-bytes-diff.png)

*Figure 152 — Byte-level inspection displaying byte offsets and mismatch lengths.*

Step 5 — Swap sides.

![Panes swapped](Documentation/screenshots_en/52-comparer-swapped.png)

*Figure 153 — **Swap** interchanges panes, reversing comparative direction.*

Step 6 — Pipe payload into Decoder.

![Left pane sent to Decoder](Documentation/screenshots_en/53-comparer-sent-to-decoder.png)

*Figure 154 — **Decode Left / Decode Right** transfers contents into Decoder input.*

### Potential Error: Comparison Shows Nothing

Cause: Both input fields are identical or one pane is empty.

Resolution: Verify both panes contain valid response bodies rather than duplicate requests.

---

### 7.8 Decoder

**What it is.** Local offline data encoding and decoding without external network requests.

**Why it is needed.** Decode obscure server response values: Base64, Hex, URL encoding, HTML entities, format minified JSON, or calculate cryptographic hashes.

**How to use:**

Step 1 — Open the **Decoder** tab.

Step 2 — Input text in the upper pane.

![Decoder with input text](Documentation/screenshots_en/60-decoder-default-operation.png)

*Figure 155 — Entered string `Hello, RequestRider! uid=1000 gid=1000`. Field accepts raw text or hexadecimal strings.*

Step 3 — Select operation and click **Apply**.

![Base64 encode](Documentation/screenshots_en/61-decoder-base64-encode.png)

*Figure 156 — `base64Encode`: `SGxsbG8sIFJlcXVlc3RSaWRlciEgdWlkPTEwMDA=`.*

![Base64 decode](Documentation/screenshots_en/62-decoder-base64-decode.png)

*Figure 157 — `base64Decode` restores original plaintext.*

![URL encode](Documentation/screenshots_en/63-decoder-url-encode.png)

*Figure 158 — `urlEncode` encodes `name=admin&role=1` to `name%3Dadmin%26role%3D1`.*

![Hex encode](Documentation/screenshots_en/64-decoder-hex-encode.png)

*Figure 159 — `hexEncode`: `deadbeef` → `6465616462656566`.*

![SHA-256 calculation](Documentation/screenshots_en/65-decoder-sha256.png)

*Figure 160 — `sha256` computes 64-character hash locally.*

![JSON pretty format](Documentation/screenshots_en/66-decoder-json-pretty.png)

*Figure 161 — `jsonPretty` indents compressed JSON for human analysis.*

Step 4 — Inspect error handling.

![Decoder error state](Documentation/screenshots_en/67-decoder-error-state.png)

*Figure 162 — Attempting `base64Decode` on non-Base64 text does not silently return garbage: output pane clears and explicit error message is displayed.*

Step 5 — Clear panes.

![Decoder panes cleared](Documentation/screenshots_en/68-decoder-cleared.png)

*Figure 163 — **Clear** resets input and output panes.*

**All Sixteen Operations**

| Category | Operations |
|---|---|
| URL | `urlEncode`, `urlDecode` |
| Base64 | `base64Encode`, `base64Decode`, `base64UrlEncode`, `base64UrlDecode` |
| HTML | `htmlEncode`, `htmlDecode` |
| Hex | `hexEncode`, `hexDecode` |
| Bytes | `byteEncode`, `byteDecode` |
| JSON | `jsonPretty`, `jsonMinify` |
| Hash | `sha256` |

> **Binary handling:** `base64Decode` and `hexDecode` safely handle binary bytes
> without failing when input is not valid UTF-8.

Clicking **Swap** transfers the output pane back to the input pane, enabling seamless multi-stage transform pipelines.

---

### 7.9 Tor / Proxy

**What it is.** A unified outbound routing path governing **all** tools: Repeater, Intruder, Target, OSINT, Scanner, passive proxy, and AI agents.

**Why it is needed.** Route all tool traffic through Tor or private SOCKS5 proxies without configuring individual applications. Validate route health and external visibility before initiating audits.

**How to use:**

Step 1 — Open the **Tor/Proxy** tab.

![Direct route](Documentation/screenshots_en/130-proxy-direct-route.png)

*Figure 164 — Empty input represents "Direct" connection. Right panel shows active route details: Protocol, Address, Status.*

Step 2 — Provide SOCKS5 endpoint and click **Apply Route**.

![Route applied unreachable](Documentation/screenshots_en/131-proxy-route-applied-unreachable.png)

*Figure 165 — Applied endpoint `127.0.0.1:1` (unbound port). Header indicates `ROUTE 127.0.0.1:1`; panel displays `Protocol: SOCKS5`, `Address: 127.0.0.1:1`, `Status: active`; status banner reports `Route applied; cancelled operations: 1`.*

> **Route Drain Semantics:** Applying or cancelling an outbound route drains the active
> route generation: in-flight engine tasks, passive captures, workflow runs, browser
> worker jobs, and LLM queries initiated under the prior route are cleanly cancelled
> returning `409 ROUTE_CHANGED`. This ensures no traffic leaks under stale route configurations.

Step 3 — Cancel route.

![Route cancelled](Documentation/screenshots_en/132-proxy-route-cancelled.png)

*Figure 166 — **Cancel Route** reverts back to direct outbound routing.*

Step 4 — Verify connectivity.

![Route connectivity check result](Documentation/screenshots_en/133-proxy-route-check-result.png)

*Figure 167 — Configure target, timeout, and click **Check Connection**. External connectivity verification queries public IP reflection endpoints. Quick links on the left provide manual validation resources: Tor Check, ifconfig.me, icanhazip, ipinfo.io, plus DNS leak diagnostics: DNSLeakTest, BrowserLeaks IP & DNS, and edns.ip-api.com.*

---

### 7.9.1 Zero DNS Leaks & DoH Tunneling

Outbound proxying in Request-Rider is engineered to prevent accidental DNS leakage:

1. **Remote Hostname Resolution:**
   Web traffic (Repeater, Intruder, Target, Scanner, AI) utilizes `x/net/proxy.SOCKS5` passing target hostnames formatted as ATYP `0x03` directly to the remote proxy or local Tor daemon (`127.0.0.1:9050`). The local operating system never issues DNS queries to local ISP resolvers; resolution occurs entirely on the remote exit node.

2. **Automated DoH Tunneling for OSINT & Raw DNS (`engine/dns_route.go`):**
   Tor nodes by default block outbound UDP traffic to port 53. Unmitigated raw UDP DNS lookups for OSINT transforms (`dns_records`, `reverse_dns`, `subdomains`) would either hang or deanonymize the operator.
   Request-Rider mitigates this automatically: when an outbound route is enabled (`ROUTE_ADDRESS != ""`), the engine routes all DNS queries through **`dohResolver` (DNS-over-HTTPS)**. DoH queries traverse the active Tor/SOCKS5 tunnel encrypted over HTTP, ensuring 0 leaked UDP 53 packets. Live queries via `edns.ip-api.com` confirm the resolver IP matches the Tor exit node.

3. **Global Network & DNS Settings (Header Gear ⚙️):**
   Clicking the gear icon in the header opens global network configurations:
   - Custom DNS resolvers (UDP and DoH);
   - Split-horizon DNS (custom routing rules for internal enterprise domains);
   - Static hosts overrides;
   - TLS/JA3 fingerprint profiles;
   - Instant DNS cache flush (`Flush DNS Cache`).
   Settings apply globally across all active tools.

4. **DNS Leak Testing Suite:**
   The quick link panel in the **Tor/Proxy** tab provides one-click access to:
   - `DNSLeakTest` — comprehensive resolver leak analysis;
   - `BrowserLeaks IP & DNS` — IP, DNS, and WebRTC audit;
   - `edns.ip-api.com` — returns executing resolver IP in JSON;
   - `Tor Check` (`check.torproject.org`) — official Tor connection validation.

**Parameters**

| Field | Default | Function |
|---|---|---|
| SOCKS5 Address | Blank | `host:port`. Blank indicates direct routing |
| Check Timeout | `15000` ms | Connectivity check duration |

### Potential Error: Route Applied but All Requests Fail

Cause: SOCKS5 proxy server is not listening at the specified address. The route indicates `Status: active`, which confirms the configuration was applied, not that the destination is reachable.

Resolution: Click **Check Connection**. If the check fails to return an external IP, verify the upstream proxy process.

---

### 7.10 History

**What it is.** Persistent audit history of exchanges dispatched **deliberately**: Repeater requests, all Intruder attack results, and Last-Byte Sync runs.

**Why it is needed.** Review requests dispatched hours or days ago in full wire format, surviving browser reloads and workspace restarts.

**Exchange Ingestion Policy**

| Source | Ingested? |
|---|---|
| `repeater` | Yes |
| `intruder` | Yes, all attack iterations |
| `last-byte` | Yes |
| `proxy` **with** capture context | Yes |
| `proxy` **without** capture context | **No** — classified as passive background noise |
| Target crawl results | **No** — managed in Target site map |
| Scanner findings (CMS, Active, Corpus) | **No** — managed in Scanner reports |

History records deliberate operator actions, excluding passive background noise.

**How to use:**

Step 1 — Open the **History** tab.

![History list table](Documentation/screenshots_en/140-history-list.png)

*Figure 168 — Table columns: `ID`, `Source`, `Host`, `Source IP`, `Method`, `URL`, `Status`, `Length`, `MIME`, `Actions`.*

Step 2 — Inspect a recorded row.

![Exchange in inspector](Documentation/screenshots_en/141-history-row-inspector.png)

*Figure 169 — Dual-pane inspector displays full raw request and raw response headers and bodies.*

Step 3 — Filter by host.

![Filter history by host](Documentation/screenshots_en/142-history-host-filter.png)

*Figure 170 — Filter search box isolates target domains; filters in-memory on the client.*

Step 4 — Sort table columns.

![Sorted history by URL](Documentation/screenshots_en/143-history-sorted-by-url.png)

*Figure 171 — Sort options: `Newest / Oldest / Host / Method / URL`.*

Step 5 — Paginate database records.

![Load more button](Documentation/screenshots_en/144-history-load-more-button.png)

![All records loaded](Documentation/screenshots_en/145-history-load-more-done.png)

*Figure 172 — After fetching all records, the button **disappears**: confirming completion.*

*Figure 173 — Button is located below the table with verified counters: `Show more from database · N of M`.*

Step 6 — Open row context menu.

![Row actions menu](Documentation/screenshots_en/146-history-row-menu.png)

*Figure 174 — `⋯` context menu: Inspect, Repeater, Intruder; Compare request/response, Decode request/response, Add tag/note; Copy cURL, JSON or plaintext, Delete, Send to Automation.*

Step 7 — Export selected records.

![Export selected history records](Documentation/screenshots_en/147-history-export-selected.png)

*Figure 175 — Select checkboxes in the left column and click **Export Selected JSON**.*

Step 8 — Clear history.

**Clear History** prompts for confirmation and permanently deletes matching database records.

---

### 7.11 Traffic

**What it is.** Live real-time stream of all traffic seen by the passive MITM proxy, backed by a persistent database archive.

**Why it is needed.** Inspect background requests from external browsers configured to use port `:8080` — observing exchanges not manually dispatched in the UI.

**How to use:**

Step 1 — Open the **Traffic** tab.

![Live traffic stream](Documentation/screenshots_en/150-traffic-live.png)

*Figure 176 — Stream updates via Server-Sent Events (SSE). Upper right controls: **Pause**, **Resume**, and "Recording" status.*

Step 2 — Highlight row for inspection.

![Traffic exchange in inspector](Documentation/screenshots_en/151-traffic-row-inspector.png)

*Figure 177 — Dual-pane inspector displays full raw HTTP request and response.*

Step 3 — Toggle capture state.

![Traffic capture paused](Documentation/screenshots_en/152-traffic-capture-paused.png)

*Figure 178 — **Pause** suspends stream ingestion while preserving already buffered items.*

![Traffic capture resumed](Documentation/screenshots_en/153-traffic-capture-resumed.png)

*Figure 179 — **Resume** restores live recording.*

Step 4 — Paginate archived records.

![Load traffic archive](Documentation/screenshots_en/144-history-load-more-button.png)

*Figure 180 — Beneath table: `Load from database · N of M` fetches older `source="proxy"` records.*

Step 5 — Export traffic snapshot.

![Export traffic snapshot](Documentation/screenshots_en/154-traffic-exported.png)

*Figure 181 — **Export All** dumps current capture buffer.*

**Clearing Traffic:** Clicking **Clear** prompts for confirmation and purges both the live in-memory buffer and the persistent proxy archive. Records from `repeater`, `intruder`, and `last-byte` remain intact in History. If the engine is unreachable, `DELETE /api/traffic` safely aborts to avoid partial or desynced data loss.

> **In-Memory vs. Database Storage:** Active live traffic resides in the engine's memory
> ring buffer and resets upon process restart. Complete long-term traffic records are
> queried from PostgreSQL via `GET /api/traffic/records` and the "Load from database" control.

---

## 8. Advanced Features

---

### 8.1 AI Agent and Autonomous ReAct Audit

**What it is.** Next-generation autonomous ReAct agent (v1.2) deeply integrated into the security testing platform. The agent supports full **Reasoning + Acting** execution loops (formulating hypotheses, selecting specialized tools via a hardened gateway, evaluating responses, and verifying impact).

**Why it is needed.** Fully automates routine vector analysis: auditing authentication flows, testing parameters for SQLi / IDOR / XSS, analyzing intercepted proxy traffic, validating findings without manual cURL transcription, and compiling verified audit reports.

**How to use:**

Step 1 — Open the **Agent** tab.

![Initial AI tab state](Documentation/screenshots_en/160-ai-empty.png)

*Figure 182 — AI workspace initial layout: left sidebar lists **16 MCP tools**, center renders conversation timeline and ReAct execution cards, right panel manages model provider and project context.*

Step 2 — Configure LLM provider and model parameters.

![Provider and context configuration](Documentation/screenshots_en/161-ai-provider-configured.png)

*Figure 183 — Connection configuration: specify API endpoint (OpenRouter, OpenAI, Ollama, Anthropic), model identifier (e.g. `anthropic/claude-3.5-sonnet` or `qwen/qwen3.8-27b`), and API key. Optionally toggle "Include active Project context".*

**Supported Providers**

| Provider | Endpoint | API Key |
|---|---|---|
| `ollama` | Required (e.g. `http://localhost:11434/v1`) | Not required |
| `openai` | Default | Required |
| `anthropic` | Default | Required |
| `openrouter` | Default | Required |
| `gemini` | Default | Required |
| `groq` | Default | Required |
| `mistral` | Default | Required |
| `openai_compatible` | Required | Optional |

Step 3 — Define an objective for the autonomous audit.

![Entering autonomous audit objective](Documentation/screenshots_en/162-ai-answer.png)

*Figure 184 — Objective input: define a concrete task, for example: "Perform an autonomous audit of the Juice Shop login endpoint (http://127.0.0.1:42000/rest/user/login). Test for SQLi resilience and record confirmed findings."*

Step 4 — ReAct Reasoning Phase (Thought) and Traffic Lookup.

![Thought phase and history_search action](Documentation/screenshots_en/164-ai-thinking.png)

*Figure 185 — **Step 1 of ReAct cycle**: agent formulates reasoning (`Thought`), schedules an action, and invokes `Action: history_search` to query existing project traffic for endpoint exchanges.*

Step 5 — Response Evaluation and Active Probing.

![Response analysis and request_send action](Documentation/screenshots_en/165-ai-real-answer.png)

*Figure 186 — **Step 2 of ReAct cycle**: evaluating the observation (`Observation`) regarding JSON schema structure, the agent dispatches an active probe (`Action: request_send`) injecting payload `' OR 1=1--` into the `email` field.*

Step 6 — Project Context and Sensitive Data Safeguards.

![Project context consideration](Documentation/screenshots_en/166-ai-project-context-hint.png)

*Figure 187 — Contextual grounding: agent incorporates known host assets and parameters while the built-in `ProjectContextBuilder` sanitizes credentials and private keys from prompts.*

Step 7 — Verifying Proof of Exploitability.

![Technical exploit proof](Documentation/screenshots_en/167-ai-received-scanner-evidence.png)

*Figure 188 — Vulnerability confirmation: target server returned `200 OK` issuing an administrative JWT token. The agent flags status as **VULNERABILITY CONFIRMED**.*

Step 8 — Automated Finding Registration and Executive Summary.

![Registering finding in scanner](Documentation/screenshots_en/168-ai-scanner-analysis.png)

*Figure 189 — Cycle completion: `Action: finding_record` registers the vulnerability into the project's `ScannerRun` with a deterministic `identity_hash`. A structured remediation report is output to the user.*

Step 9 — Export Audit Report in HTML and JSON.

![Report export menu](Documentation/screenshots_en/202-ai-agent-export-report.png)

*Figure 190 — Export menu (`#ai-export-btn`): save full research timeline as a styled **HTML** report (including complete proofs, raw ReAct steps, zero CDN dependencies) or machine-readable **JSON**.*

#### 8.1.1 Arsenal of 16 MCP Tools

The agent environment provides 16 specialized tools:
1. `history_search` — Semantic and literal substring querying over project HTTP traffic.
2. `request_send` — Dispatches raw HTTP requests via Go engine with SSRF guardrails and traffic tagging (`ai_agent`).
3. `finding_record` — Records verified vulnerabilities into scanner database.
4. `report_ingest` — Ingests external artifacts (HTML crawler maps, JSON scanner findings, HAR archives).
5. Encoding utilities: `url_encode`, `url_decode`, `base64_encode`, `base64_decode`, `hex_encode`, `hex_decode`.
6. `normalize_http` — RFC-compliant CRLF header normalization (PortSwigger style) preserving binary body fidelity.
7. Random nonce and canary generator: `random_string`.
8. Skill registry: browse and query 850+ security testing technique catalogs (`skills_list`, `skills_read`), including Burp Suite methodology references.

#### 8.1.2 External Control via MCP Server (`tools/mcp/server.py`)

The embedded MCP server allows invoking Request-Rider's autonomous agent and all 16 tools directly from IDEs and external agents (Antigravity, Cursor, Claude Desktop):
```json
{
  "mcpServers": {
    "request-rider": {
      "command": "python3",
      "args": ["/home/kali/Downloads/Request-Rider v1.2/tools/mcp/server.py"]
    }
  }
}
```

---

### 8.2 Automation

**What it is.** An interactive node canvas: triggers, security tools, and logic operators connected via directional edges, persisted in PostgreSQL, supporting schedulers, webhooks, and execution logging.

**Why it is needed.** Model repetitive audit workflows once and execute them reliably without manual re-configuration.

**How to use:**

Step 1 — Open the **Automation** tab.

![Automation initial empty state](Documentation/screenshots_en/170-automation-empty.png)

*Figure 186 — Left palette lists "NODES" across three groups, center displays empty canvas, bottom houses node configuration inspector and run log.*

**22 Supported Node Types**

| Group | Nodes |
|---|---|
| Triggers | Manual Trigger, Scheduled Trigger, Webhook Trigger |
| Tools | Repeater, Repeater Burst, Last-Byte Sync, Target Map, Browser Target, OAST Listener, OAST Collect, OSINT, Scanner, Intruder, Decoder, Comparer, AI Agent |
| Logic | Condition, Join, Set Value, Template, Delay, Output |

Step 2 — Assemble a workflow draft.

![Nodes added to canvas](Documentation/screenshots_en/171-automation-nodes-added.png)

*Figure 187 — Clicking nodes in the palette instantiates them on the canvas for repositioning. Example: Manual Trigger, Repeater, and Output.*

Step 3 — Connect nodes.

Draw connections between node handles: drag from the output port on the right of a node to the input port on the left of the downstream node. Connections auto-link when adding sequential nodes.

Step 4 — Configure node properties.

![Node inspector](Documentation/screenshots_en/172-automation-node-inspector.png)

*Figure 188 — "NODE CONFIGURATION" displays structured schema-driven inputs rather than raw JSON: Disabled toggle, typed parameters, and specialized overrides.*

![Node configured](Documentation/screenshots_en/173-automation-node-configured.png)

*Figure 189 — URL configured to `http://127.0.0.1:8101/health`. **Use Current** syncs settings from the active tool tab; **Open Tool** switches directly to that tool's tab.*

Step 5 — Save workflow.

![Workflow saved](Documentation/screenshots_en/174-automation-saved.png)

*Figure 190 — Click **Save**. Saving activates the **Activate** and **Run** actions.*

Step 6 — Execute workflow.

![Workflow executing](Documentation/screenshots_en/175-automation-running.png)

*Figure 191 — Lower run log streams real-time status; **Pause**, **Resume**, and **Cancel** controls activate.*

Step 7 — Inspect execution log.

![Run log entries](Documentation/screenshots_en/176-automation-runs.png)

*Figure 192 — Execution log records per-node telemetry: status, elapsed duration, and JSON output.*

Step 8 — Refresh and export.

![Run log refreshed](Documentation/screenshots_en/177-automation-runs-refreshed.png)

*Figure 193 — **Refresh Runs** updates execution history from server.*

![Export workflow](Documentation/screenshots_en/178-automation-export.png)

*Figure 194 — **Export** downloads JSON adhering to the `requestrider.workflow/v1` schema.*

Step 9 — Manage viewport.

![Canvas zoomed](Documentation/screenshots_en/179-automation-zoomed.png)

![Auto-layout executed](Documentation/screenshots_en/180-automation-auto-layout.png)

*Figure 195 — **Auto-layout** automatically organizes nodes into readable hierarchical tiers without manual dragging.*

*Figure 196 — `−`/`+` scales zoom (0.4× to 1.6×), **Fit** bounds all nodes into view. Mouse wheel zooms with Ctrl/Cmd; middle click or Alt+drag pans canvas. Minimap is positioned on the right.*

Step 10 — Open Template Store.

![Template Store](Documentation/screenshots_en/181-template-store.png)

*Figure 197 — Curated workflow template catalog organized by domain: Asset Discovery, Microservice APIs, Fuzzing & Injection, LLM Security, Compliance & DevSecOps, Auth & Sessions, Cloud Infra, Business Logic, OAST.*

![Search Template Store](Documentation/screenshots_en/182-template-store-search.png)

*Figure 198 — Substring title search with filters for category, execution type, and risk rating.*

![Template preview](Documentation/screenshots_en/183-template-store-preview.png)

*Figure 199 — Interactive preview renders topology, node specs, and runtime variables. **Import** creates an editable draft — **does not** automatically execute.*

![Template imported](Documentation/screenshots_en/184-template-store-imported.png)

*Figure 200 — Imported workflow draft placed on canvas ready for execution.*

**Execution Confirmations:** Nodes issuing external traffic or launching browsers require explicit operator confirmation before manual execution or activation: `Intruder`, `Repeater Burst`, `Last-Byte Sync`, `OAST Listener`, `Browser Target`. Without confirmation, the API responds with `CONFIRMATION_REQUIRED`.

**Schedulers and Webhooks:**
- **Scheduled Trigger** accepts standard cron syntax (default: `*/5 * * * *`).
- **Webhook Trigger** allocates a unique slug: `POST /api/workflows/hooks/<slug>`. Request payloads populate node input (`method`, `query`, `headers`, `body`). Incoming `authorization`, `cookie`, and `x-api-key` headers are **stripped** prior to execution.
- **Activate** registers the cron scheduler; **Deactivate** suspends it.

> **Runtime scope:** In this standalone architecture, active workflows execute in process memory.
> Stand restarts mark in-flight jobs as `interrupted`.

---

### 8.3 Tools Without a Dedicated Tab

These tools operate exclusively via automation nodes or direct engine API endpoints.

#### Repeater Burst

**What it is.** Dispatches N repetitions of a single HTTP request with controlled concurrency, delay, and timeout parameters.

**How to use:** Add the **Repeater Burst** node to an automation canvas, populate `url`, `iterations`, `concurrency`, `delay_ms`, `timeout_ms`, and trigger. Alternatively, call the engine directly:

```bash
curl -s -X POST http://127.0.0.1:8081/proxy/repeater-burst \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","url":"http://127.0.0.1:8101/health",
       "iterations":20,"concurrency":4,"delay_ms":50,"timeout_ms":5000}'
```

```bash
curl -s http://127.0.0.1:8081/proxy/repeater-burst/<burst_id>
curl -s -X POST http://127.0.0.1:8081/proxy/repeater-burst/<burst_id> \
  -d '{"action":"pause"}'     # or resume
curl -s -X DELETE http://127.0.0.1:8081/proxy/repeater-burst/<burst_id>
```

Completed requests are logged into History with `source="repeater-burst"`.

#### Last-Byte Sync

**What it is.** Raw TCP HTTP/1.1 synchronization with delayed final byte transmission: the target server receives the request stream but cannot complete response handling until the final byte is released. Useful for auditing race conditions, desync timeouts, and slow-read WAF behaviors.

**How to use:** Add the **Last-Byte Sync** node with non-empty payload body, configuring `iterations`, `concurrency`, `delay_ms`, `hold_ms`, and `timeout_ms`.

```bash
curl -s -X POST http://127.0.0.1:8081/proxy/last-byte \
  -H 'Content-Type: application/json' \
  -d '{"method":"POST","url":"http://127.0.0.1:8103/",
       "body":"a=1","iterations":1,"concurrency":1,"hold_ms":500,"timeout_ms":10000}'
```

#### OAST Listener

**What it is.** Registers an Out-of-Band Application Security Testing callback listener and polls for out-of-band interactions.

**How to use:** Configure **OAST Listener** (registration, poll intervals, timeout, protocols) and **OAST Collect** nodes. Callbacks are ingested on `POST /api/oast` and `GET /api/oast/<listener_id>`.

This endpoint is **exempt from origin validation** to permit external callback delivery. It validates that the incoming payload `project_id` matches the current active project.

---

### 8.4 Inter-Tool Data Transfers

Buttons **Send to AI** and **Send to Automation** are integrated across Repeater, Intruder, Target, OSINT, Scanner, Comparer, and Decoder.

**Behavior:** Automatically instantiates the corresponding node in Automation with pre-populated parameters, prepends a Manual Trigger, connects edges, **persists** the workflow, and transitions the UI to the Automation tab.

**Why it matters:** Eliminates manual re-entry: convert a discovered Intruder attack directly into a scheduled monitoring workflow.

---

### 8.5 HTML Export: Interactive Report

The **Export ▾** button across tools generates **standalone interactive HTML reports** ready for archival, customer delivery, or offline analysis.

**Location:** Accessible via the **Export ▾** dropdown menu in tool toolbars.

![Scanner export menu](Documentation/screenshots_en/225-scanner-active-export-menu.png)

*Figure 201 — Scanner export menu. Formats displayed before selection: `Esc`, outside click, or arrow keys close without action.*

**Architecture:** Reports match the application visual styling (palette, typography, layout) while operating completely offline: zero CDN scripts, external fonts, or remote assets.

![Scanner HTML report](Documentation/screenshots_en/320-export-html-scanner.png)

*Figure 202 — Scanner HTML report: file summary, findings table, and diagnostic metadata with client-side search and filtering.*

**Data Presentation:** Large raw exchange bodies are collapsed into interactive accordions and expand **on click**, keeping thousand-row reports fast and responsive.

![Intruder HTML report](Documentation/screenshots_en/321-export-html-intruder.png)

*Figure 203 — Intruder HTML report: fuzzed requests side-by-side with full server responses.*

![Project HTML report](Documentation/screenshots_en/322-export-html-project.png)

*Figure 204 — Project HTML report: endpoints, scanner findings, workspaces, and attacks. Secret values are masked with safe references.*

![Target HTML report](Documentation/screenshots_en/323-export-html-target.png)

*Figure 205 — Target HTML report including hierarchical site map.*

![Entity graph HTML report](Documentation/screenshots_en/121-osint-graph-export-html.png)

*Figure 206 — Entity graph standalone HTML report.*

**OSINT Export Distinction:** The **Export JSON** and **Export CSV** buttons in the OSINT overview export structured tables, while the HTML report is generated directly from the graph canvas via **Export Graph HTML**.

**Localization:** Reports render in the **active interface language**, governed by the `requestrider-language` cookie. On the report page, clicking `?lang=` at the top switches language dynamically.

---

### 8.6 LLM Integration: Chat, AI Node, and Grounded Evidence

Two distinct platform components query external language models:

| Attribute | Agent Tab | Automation AI Node |
|---|---|---|
| Key Input | **API Key** field in tab | **Not in UI** (Environment only) |
| Source | Saved in tab | `AGENT_LLM_API_KEY` |
| Model | **Model** field | `AGENT_LLM_MODEL` |
| Endpoint | **Endpoint** field | `AGENT_LLM_ENDPOINT` |
| Evidence | Conversation timeline | Workflow execution run log |

This separation protects credentials: keys configured in workflow nodes would leak into serialized JSON bundles, exports, and shared team databases.

#### 8.6.1 Conversational Analysis in the Agent Tab

Step 1 — Open the **Agent** tab.

![Empty AI chat](Documentation/screenshots_en/160-ai-empty.png)

*Figure 207 — Empty state: provider selector, endpoint, model, key, and prompt input.*

Step 2 — Configure **Provider**, **Endpoint**, **Model**, and **API Key** (e.g. OpenRouter: `https://openrouter.ai/api/v1` with model `qwen/qwen3.8-27b:free`).

![Provider configured](Documentation/screenshots_en/161-ai-provider-configured.png)

*Figure 208 — Provider configured.*

Step 3 — Enter API Key. The input is a masked password field.

![Masked API key](Documentation/screenshots_en/161-ai-provider-configured.png)

*Figure 209 — Model parameters and masked key dialog.*

Step 4 — Enter analysis prompt and click **Send**.

![Model reasoning indicator](Documentation/screenshots_en/164-ai-thinking.png)

*Figure 210 — Real-time generation indicator.*

Step 5 — Review model response.

![Model response](Documentation/screenshots_en/165-ai-real-answer.png)

*Figure 211 — Verified response from Qwen via OpenRouter assessing response headers on `https://news.mail.ru/`.*

#### 8.6.2 Grounded Evidence Over Speculation

The primary advantage of the Agent workspace is piping raw findings directly from tools into the model.

Step 6 — In Scanner or OSINT, click **Send to AI**.

![CMS scan before forwarding to AI](Documentation/screenshots_en/167-ai-received-scanner-evidence.png)

*Figure 212 — Discovered findings (admin panel path, git metadata exposure, exposed server status) transferred directly into Agent context.*

Step 7 — Prompt model to analyze evidence.

![Findings analysis](Documentation/screenshots_en/168-ai-scanner-analysis.png)

*Figure 213 — Structured breakdown separating verified impacts from unconfirmed hypotheses.*

Step 8 — Optionally check **Include active Project context**.

![Project context toggle](Documentation/screenshots_en/166-ai-project-context-hint.png)

*Figure 214 — Project context inclusion provides known endpoints, stacks, and relationships while sanitizing raw passwords and tokens.*

#### 8.6.3 Exporting Investigation Results

At the conclusion of an investigation, the dialogue and ReAct steps can be exported to HTML or JSON via the **Export** button in the top toolbar.

![Audit report export menu](Documentation/screenshots_en/202-ai-agent-export-report.png)

*Figure 215 — Exporting interactive HTML audit report or structured JSON.*

#### 8.6.4 AI Node in Automation

The **AI Agent** workflow node executes model queries headlessly, sourcing credentials from environment variables:

![AI node in workflow](Documentation/screenshots_en/502-automation-llm-node-config.png)

*Figure 216 — AI Agent node parameters: `prompt`, `provider`, `endpoint`, `model`. The API key is injected via `AGENT_LLM_API_KEY`.*

**Configuring Environment Credentials:**

```bash
export AGENT_LLM_API_KEY='<YOUR_API_KEY>'
export AGENT_LLM_ENDPOINT='https://openrouter.ai/api/v1'
export AGENT_LLM_MODEL='qwen/qwen3.8-27b:free'
```

Credentials are automatically scrubbed from run logs and workflow export bundles.

![Workflow with AI node](Documentation/screenshots_en/501-automation-llm-nodes.png)

*Figure 217 — Automation pipeline: Manual Trigger → Intruder → AI Agent.*

![Workflow execution](Documentation/screenshots_en/504-automation-llm-running.png)

*Figure 218 — Live execution: AI node awaits Intruder completion before processing output.*

![Run log output](Documentation/screenshots_en/505-automation-llm-runs.png)

*Figure 219 — Run log capturing AI node analysis results.*

![Run log refreshed](Documentation/screenshots_en/506-automation-llm-runs-refreshed.png)

*Figure 220 — Updated run log showing complete model output.*

---

## 9. CLI and API

### 9.1 `start.sh` — Unified Entrypoint

**Command:** `./start.sh`  
**Purpose:** Installs missing dependencies, launches full local standalone environment natively, and keeps terminal attached.

| Flag | Action |
|---|---|
| *(no flags)* | Complete setup and execution; blocks terminal on completion |
| `--check` | Same as default **plus** diagnostic validation suite (detailed below) |
| `--status` | Read-only status report; prints process status table and exits |
| `--stop` | Shuts down **only processes tracked by this script instance** |
| `--restart` | Executes clean stop followed by full launch |
| `-h`, `--help` | Outputs CLI help manual |

**Execution Order of `main()`**

1. Create `logs/` directory
2. If `--stop` — terminate tracked processes and exit
3. Display banner
4. If `--restart` — stop existing services
5. If `--status` — print service status and exit
6. Validate system package prerequisites
7. Run `go mod download`
8. Set up `web/.venv` and install `requirements.txt`
9. Rotate previous service logs
10. Set up `browser-worker/.venv` and install `playwright`
11. Verify Playwright Chromium and Firefox browser binaries
12. Provision PostgreSQL cluster in `data/pg` on `:55433` and verify `requestrider` database
13. Start Redis on `:6379` with AOF persistence
14. Start Tor daemon — **only if** route requires Tor
15. Launch Go engine on `:8081` and passive proxy on `:8080`
16. Launch `browser-worker` on `:8090`
17. Run `python manage.py migrate`
18. Spawn Celery and background result workers — **only if enabled via environment flags**
19. If `--check` — execute comprehensive test suite
20. Start Django `runserver` in foreground

**Diagnostic Checks in `--check` Suite**

| # | Check | Purpose |
|---|---|---|
| 1 | `node --check` (inline JS) | Syntax validation of template-embedded JavaScript |
| 2 | `git diff --check` | Detect whitespace errors and invalid tabs in diffs |
| 3 | `python manage.py check` | Django configuration and system integrity |
| 4 | `go test ./... -count=1` | Go engine unit and integration test suite |
| 5 | `go test ./... -count=1 -race` | **Race detector** — validates concurrency and mutex safety |
| 6 | `python manage.py test --noinput -v 2` | Django test suite |

Each test reports `PASS`/`FAIL`, writing full logs to `data/logs/check-*.log`. The script exits with non-zero code upon any failure.

![start.sh help](Documentation/screenshots_en/304-install-05-start-sh-help.png)

*Figure 221 — Command line options for `start.sh`.*

**Process Isolation Warning:** `--stop` identifies child processes via PID files stored in `data/`. If multiple sessions share a checkout directory, running stop will impact co-located instances. Always invoke lifecycle commands within dedicated stand workspaces.

---

### 9.2 `run-engine.sh`

**Command:** `./run-engine.sh`  
**Purpose:** Lightweight manual execution bypassing system package installation checks.

**No CLI Flags:** Accepts no arguments.

Lifecycle: Prepares environment → launches Go engine (`go run .`) → validates `browser-worker/.venv` and Firefox → initializes `web/.venv` → applies migrations (`manage.py migrate`) → runs Django gateway (`manage.py runserver 127.0.0.1:8000`).

What it **does not** do: does not install system packages, does not spawn Redis or Celery workers, and does not provision PostgreSQL clusters.

---

### 9.3 Gateway HTTP API (Django, `:8000`)

**Authentication-Free Loopback:** The gateway listens exclusively on `127.0.0.1`.

**Global Security & Routing Rules**

| Rule | Enforcement |
|---|---|
| `TRACE` / `TRACK` | `405 Method Not Allowed` with `reason: REFLEXIVE_METHOD_REFUSED` |
| Untrusted `Origin` mutation | `403 Forbidden` with `reason: CROSS_ORIGIN_REFUSED` |
| CSRF validation | Enforced on state mutations; client passes `X-CSRFToken` |
| Route drain cancellation | `409 Conflict` with `reason: ROUTE_CHANGED` |
| Engine unreachable | `502 Bad Gateway` with `ENGINE_UNAVAILABLE` / `BROWSER_WORKER_UNAVAILABLE` |
| Target response body | Stored verbatim without alteration |

**History Endpoints**

| Method | Path | Function |
|---|---|---|
| GET | `/api/history` | Query filtered history: `q`, `host`, `path`, `method`, `status`, `mime`, `body`, `size_min`, `size_max`, `latency_min`, `latency_max`, `sort`, `detail`, `offset`, `limit` |
| GET | `/api/history/export?ids=a,b,c` | Download records as JSON |
| POST | `/api/history/import` | Ingest JSON records (`{"items":[...]}` or flat array) |
| GET | `/api/history/<id>` | Full raw record details |
| PATCH | `/api/history/<id>` | Update record `tags` and `notes` |
| DELETE | `/api/history/<id>` | Delete individual record |
| POST | `/api/history/bulk` | Bulk operations: `clear`, `delete`, `metadata` |

**Traffic Endpoints**

| Method | Path | Function |
|---|---|---|
| GET | `/api/traffic?detail=full\|summary` | Snapshot of live in-memory capture buffer |
| POST | `/api/traffic` | Capture controls: `pause`, `resume`, `status` |
| DELETE | `/api/traffic` | Purge live capture buffer **and** persistent proxy archive |
| GET | `/api/traffic/records?offset=&limit=&detail=` | Paginate persistent database records |
| GET | `/api/traffic/record?id=` | Retrieve full individual database record |
| GET | `/api/traffic/detail?id=` | Retrieve full individual in-memory live record |
| GET | `/api/traffic/stream` | Server-Sent Events (SSE) with `Last-Event-ID` cursor |
| POST | `/api/traffic/save` | Transfer selected traffic captures into History |
| POST | `/api/traffic/annotate` | Apply tags and notes to exchange |
| GET/POST/PATCH/DELETE | `/api/traffic/capture-contexts[/<id>]` | Manage correlation capture contexts |

**Project Endpoints**

| Method | Path | Function |
|---|---|---|
| GET/POST | `/api/projects` | List projects / create project |
| GET/PATCH/DELETE | `/api/projects/<id>` | Project metadata management |
| GET | `/api/projects/<id>/hub` | Retrieve complete Knowledge Hub state |
| GET | `/api/projects/<id>/export` | Export project bundle (`requestrider.project/v1`) |
| POST | `/api/projects/import` | Ingest bundle → **always provisions new project** |
| POST | `/api/project-context` | Set or clear active project in session |

**Tool Endpoints**

| Method | Path | Function |
|---|---|---|
| POST | `/api/execute` | Dispatch single Repeater exchange |
| POST/GET/DELETE | `/api/intruder` | Launch / poll / cancel fuzzer attack |
| POST | `/api/intruder?attack_id=&action=` | Fuzzer lifecycle: `pause` / `resume` |
| GET/POST | `/api/intruder/saved` | Saved attack profile catalog |
| POST | `/api/intruder/saved/<id>/run` | Re-dispatch saved attack |
| POST/GET/DELETE | `/api/target-map` | Static crawler execution |
| POST/GET/DELETE | `/api/target-browser` | Browser-driven crawler execution |
| POST | `/api/scanner` | CMS reconnaissance (Safe CMS Recon) |
| POST/GET | `/api/scanner/active/jobs[/<id>]` | Asynchronous Active Scan job management |
| GET | `/api/scanner/active/jobs/<id>/stream` | SSE stream for active scan progress and findings |
| POST/DELETE | `/api/scanner/active/jobs/<id>/<action>` | Active scan controls: `pause`, `resume`, `cancel`, `resend` |
| GET | `/api/scanner/corpus/stats` | Corpus database signature statistics |
| POST | `/api/scanner/corpus/run` | Synchronous corpus scan execution |
| POST/GET | `/api/scanner/corpus/jobs[/<id>]` | Asynchronous corpus scan jobs |
| GET | `/api/scanner/corpus/jobs/<id>/stream` | SSE stream for corpus scan events |
| DELETE | `/api/scanner/corpus/jobs/<id>` | Abort corpus scan |
| GET | `/api/scanner/report` | Render server-side standalone HTML report |
| POST | `/api/osint` | Passive intelligence scan + safe WAF canary |
| GET | `/api/osint/transforms` | Catalog of 16 OSINT transforms |
| GET/POST/DELETE | `/api/osint/graphs[/<id>]` | Entity graph management |
| POST | `/api/osint/graphs/<id>/upsert` | Idempotent entity/relation merge |
| PATCH/DELETE | `/api/osint/graphs/<id>/entities/<entity_id>` | Edit or remove entity |
| DELETE | `/api/osint/graphs/<id>/relations/<relation_id>` | Remove relationship edge |
| POST | `/api/osint/graphs/<id>/transform` | Execute transform (synchronous) |
| POST/GET | `/api/osint/graphs/<id>/transform/jobs[/<job_id>]` | Execute transform (asynchronous background) |
| POST/DELETE | `/api/osint/graphs/<id>/transform/jobs/<job_id>/<action>` | Transform lifecycle: `cancel`, `pause`, `resume` |
| GET/POST | `/api/oast[/<listener_id>]` | Ingest OAST interaction callbacks |
| GET/POST/PUT | `/api/route` | Read or configure outbound routing profile |
| POST | `/api/route/check` | Test outbound route connectivity |
| POST | `/api/agent/chat` | AI agent evidence analysis query |

**Workflow Endpoints**

| Method | Path | Function |
|---|---|---|
| GET | `/api/workflows/node-types` | Catalog of 22 node schemas |
| GET | `/api/workflow-templates` | Template Store catalog |
| GET/POST | `/api/workflows` | List workflows / save workflow |
| GET/PATCH/DELETE | `/api/workflows/<id>` | Workflow configuration |
| POST | `/api/workflows/<id>/run` | Execute workflow (`confirm` required for hazardous nodes) |
| POST | `/api/workflows/<id>/activate` \| `/deactivate` | Toggle cron scheduler |
| GET | `/api/workflows/<id>/export` | Export schema-validated JSON |
| POST | `/api/workflows/import` | Ingest workflow as editable draft |
| GET | `/api/workflows/runs` | Retrieve execution run history |
| GET | `/api/workflows/runs/<id>[/export\|/stream]` | Run details, export, or SSE telemetry |
| POST | `/api/workflows/runs/<id>/<action>` | Run lifecycle: `cancel`, `pause`, `resume` |
| ANY | `/api/workflows/hooks/<slug>` | Public webhook entrypoint |

---

### 9.4 Engine HTTP API (Go, `:8081`)

The Go engine enforces two security constraints added automatically by the gateway:
- Request `Host` must be loopback (`127.0.0.1`), otherwise returns `403 FORBIDDEN_HOST`.
- Header `X-RequestRider-Internal-Key` must match `RR_INTERNAL_API_KEY` when configured.

| Method | Path | Function |
|---|---|---|
| GET | `/health` | Healthcheck and active transport limits |
| POST | `/proxy/request` | Forward outbound HTTP request |
| GET/PUT/POST | `/route` | Outbound route management |
| POST | `/route/check` | Test route connectivity |
| GET/POST/DELETE | `/events` | In-memory event ring buffer controls |
| GET | `/events/detail?id=` | Retrieve full individual wire exchange |
| POST | `/events/annotate` | Tag and annotate exchange |
| GET | `/events/stream` | SSE stream with `Last-Event-ID` support |
| POST/GET/DELETE | `/proxy/intruder[/<id>]` | Fuzzer lifecycle: run, poll, cancel, pause |
| POST/GET/DELETE | `/proxy/target-map[/<id>]` | Static crawler execution |
| POST | `/proxy/target-js` | JavaScript bundle analysis |
| POST/GET/DELETE | `/proxy/oast[/<listener_id>]` | OAST callback server |
| POST/GET/DELETE | `/proxy/repeater-burst[/<id>]` | Repeater Burst execution |
| POST/GET/DELETE | `/proxy/last-byte[/<id>]` | Last-Byte Sync execution |
| POST | `/proxy/osint`, `/proxy/osint/transform` | OSINT passive checks and transforms |
| POST/GET/DELETE | `/proxy/osint/transform/jobs[/<id>]` | Background transform workers |
| POST | `/proxy/scanner` | CMS reconnaissance |
| GET | `/proxy/scanner/corpus/stats` | Corpus database signature statistics |
| POST | `/proxy/scanner/corpus/run` | Execute corpus scan |
| POST/GET | `/proxy/scanner/corpus/jobs[/<id>]` | Asynchronous corpus jobs |
| GET | `/proxy/scanner/corpus/jobs/<id>/stream` | SSE stream for corpus jobs |
| POST/GET | `/proxy/scanner/active/jobs[/<id>]` | Active vulnerability scan |
| GET | `/proxy/scanner/active/jobs/<id>/stream` | SSE stream for active scan |
| POST/DELETE | `/proxy/scanner/active/jobs/<id>/cancel` | Terminate active scan |

The **passive MITM proxy on port `:8080`** acts as a standard HTTP/HTTPS forward proxy rather than a REST service.

---

### 9.5 Browser-Worker HTTP API (`:8090`)

| Method | Path | Function |
|---|---|---|
| GET | `/health` | Worker health and available browser engines |
| POST | `/target` | Dispatch browser-driven crawl job |
| GET | `/target/<job_id>` | Poll job progress and network events |
| DELETE | `/target` | Abort all running jobs |
| DELETE | `/target/<job_id>` | Abort specific job |

![Engine health](Documentation/screenshots_en/308-install-09-engine-health.png)

*Figure 222 — Output of `curl http://127.0.0.1:8081/health`: returns operational transport parameters.*

---

### 9.6 API Usage Examples

**Send Request via Gateway**

```bash
curl -s -X POST http://127.0.0.1:8000/api/execute \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","url":"https://news.mail.ru/","headers":{"Accept":"*/*"}}'
```

**Launch Intruder Attack and Poll Progress**

```bash
curl -s -X POST http://127.0.0.1:8000/api/intruder \
  -H 'Content-Type: application/json' \
  -d '{"base_request":{"method":"GET","url":"http://127.0.0.1:8101/search?q=%term%",
       "headers":{"Host":"127.0.0.1:8101"},"body":""},
       "mode":"sniper","payloads":[["requestrider","sqlmap","nikto"]],
       "delay_ms":0,"concurrency":2}'

curl -s 'http://127.0.0.1:8000/api/intruder?attack_id=<id>&since=0'
```

**Execute Passive Reconnaissance**

```bash
curl -s -X POST http://127.0.0.1:8000/api/osint \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://news.mail.ru/","waf_check":true}'
```

**Launch Active Scanner**

```bash
curl -s -X POST http://127.0.0.1:8000/api/scanner/active/jobs \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://news.mail.ru/","max_pages":12,"max_depth":2,
       "concurrency":4,"delay_ms":120,"timeout_ms":15000,"same_origin":true}'

curl -s http://127.0.0.1:8000/api/scanner/active/jobs/<job_id>
```

**Query Filtered History**

```bash
curl -s 'http://127.0.0.1:8000/api/history?host=127.0.0.1&sort=-timestamp&limit=50'
```

**Export Project Bundle**

```bash
curl -s http://127.0.0.1:8000/api/projects/1/export -o project.json
```

---

## 10. Configuration

### 10.1 Environment Variables Read by `start.sh`

| Variable | Default | Purpose |
|---|---|---|
| `RUNSERVER_PORT` | `8000` | Django gateway port |
| `ENGINE_PORT` | `8081` | Go engine API port |
| `PROXY_PORT` | `8080` | Passive MITM proxy listener port |
| `WORKER_PORT` | `8090` | Browser-worker service port |
| `POSTGRES_PORT` | `55433` | Local PostgreSQL cluster port |
| `REDIS_PORT` | `6379` | Redis broker port |
| `SOCKS_PORT` | `9050` | Tor SOCKS proxy port |
| `ENGINE_URL` | `http://127.0.0.1:$ENGINE_PORT` | Engine upstream URL used by Django |
| `POSTGRES_HOST` | `127.0.0.1` | Database host |
| `POSTGRES_DB` | `requestrider` | Database name |
| `POSTGRES_USER` | Current OS user | Database user |
| `POSTGRES_PASSWORD` | Empty | Database password |
| `POSTGRES_TEST_TEMPLATE` | `requestrider_utf8_tmpl` | UTF-8 DB template for test runners |
| `CA_DIR` | `data/ca` | Local CA certificate and key store |
| `BROWSER_WORKER_URL` | `http://127.0.0.1:$WORKER_PORT` | Browser-worker URL |
| `RR_ROUTE_VIA_TOR` | Unset | Automatic Tor daemon spawn toggle |
| `ROUTE_ADDRESS` | Unset | Outbound SOCKS5 proxy string |
| `WORKFLOW_CELERY_ENABLED` | `0` | Spawn Celery background worker |
| `WORKFLOW_ENGINE_BROKER_ENABLED` | `0` | Spawn background results consumer |
| `RR_DEBUG` | `0` | Django debug mode toggle |

**Broker Mode vs. Process Runtime:** Standalone execution defaults to an in-memory process runtime. Enabling `WORKFLOW_CELERY_ENABLED=1` activates distributed queues. Diagnostic test suites enforce process runtime isolation.

To run with Celery broker enabled:

```bash
WORKFLOW_CELERY_ENABLED=1 WORKFLOW_ENGINE_BROKER_ENABLED=1 ./start.sh
```

---

### 10.2 Engine Transport Boundaries

Exposed via `GET /health` to ensure operational transparency:

| Variable | Default Value | Description |
|---|---|---|
| `RR_DIAL_TIMEOUT_MS` | `30000` | Network dial timeout |
| `RR_TLS_HANDSHAKE_TIMEOUT_MS` | `10000` | TLS handshake timeout |
| `RR_RESPONSE_HEADER_TIMEOUT_MS` | `30000` | Header read timeout |
| `RR_IDLE_CONN_TIMEOUT_MS` | `90000` | Idle keep-alive connection timeout |
| `RR_CONTROL_PLANE_BODY_LIMIT_BYTES` | `1048576` | In-memory control plane body buffer limit |
| `RR_FINISHED_JOB_RETENTION_MIN` | `60` | Completed job retention duration |

---

### 10.3 State Storage Architecture

| Data Domain | Storage Medium | Lifecycle |
|---|---|---|
| History, Traffic Archive, Projects, Workflows, Attacks | PostgreSQL | Persistent across sessions |
| Live Traffic Buffer | Engine in-memory ring buffer | Ephemeral; reset on restart or Clear |
| Workspaces, Active Tab, UI Preferences | Browser `localStorage` | Per-client persistence |
| Session Backup Snapshots | Browser IndexedDB (`requestrider-workspace`) | Auto-recovery cache |
| Report Localization | Cookie `requestrider-language` | Governs report generation language |
| Outbound Route Profile | Engine memory + Django session | Synchronized via route manager |
| CA Certificate and Key | Local filesystem `data/ca` | Keep `ca.key` protected |

---

### 10.4 Core PostgreSQL Models

| Model | Function |
|---|---|
| `TrafficRecord` | Audited HTTP exchange: method, URL, host, client IP, status, size, MIME, raw headers, and bodies |
| `Project` | Workspace context: name, target URL, environment tag, route profile, technology stack |
| `ProjectEndpoint` | Discovered target endpoints mapped across tools |
| `ProjectExchange` | **Immutable copy** of an exchange tied to project — survives clearing History tab |
| `ProjectSecret` | Leaked credentials stored with **full verbatim values** in `value_ref` |
| `Workflow`, `WorkflowRun` | Automation DAG definition and execution logs |
| `IntruderAttack` | Fuzzer configuration and recorded payload results |
| `ScannerRun` | Vulnerability scanner jobs and correlated findings |
| `OSINTGraph` | Entity graph nodes, relations, and transform provenance |
| `TrafficCaptureContext` | Correlation context linking passive proxy traffic to specific audits |

---

## 11. Practical Scenarios

### Scenario A — Manual Endpoint Audit from Discovery to Report

**Objective:** Audit `/api/profile` for injection vulnerabilities and verify impact.

```text
1. Create Project           → Scope audit in dedicated workspace
2. Repeater                 → Issue baseline request; establish benchmark
3. Target (Static Crawl)    → Map related parameters and adjacent routes
4. Intruder                 → Fuzz parameters across injection lists
5. Comparer                 → Analyze "before" vs "after" response diffs
6. Row Inspector            → Validate full raw wire exchanges
7. Tag and Note             → Annotate verified exchange in History
8. Export JSON              → Export machine-readable findings package
```

![Raw exchange inspector](Documentation/screenshots_en/76-intruder-row-inspector.png)

*Figure 223 — Step 6: full raw wire exchange inspection in Intruder.*

---

### Scenario B — Comprehensive Target Audit via Scanner Pro

**Objective:** Rapid surface evaluation (CMS recon) combined with corpus signature testing and heuristic deep active scanning with Proof of Impact.

```text
1. Create Project             → Scope audit target
2. CMS Recon                  → Fast 1-minute profile: technologies, headers, sensitive paths
3. Active Scan + Corpus       → Heuristic injection testing backed by 5,522 corpus checks
4. Lifecycle Controls         → Utilize Pause, Resume, and Resend as needed
5. Filter Results             → Filter by "Proven" impact and high severity
6. Export                     → Produce interactive standalone HTML report
```

![Live CMS recon findings](Documentation/screenshots_en/202-scanner-cms-findings.png)

*Figure 224 — Step 2: CMS reconnaissance findings.*

![Proven finding with proof](Documentation/screenshots_en/223-scanner-active-findings.png)

*Figure 225 — Step 3: Verified vulnerability with Proof of Impact.*

---

### Scenario C — Reconnaissance with Graph Accumulation

**Objective:** Build target domain architecture map and enrich through transforms.

```text
1. OSINT URL Scan             → Passive DNS, headers, technologies, and link discovery
2. Create Graph               → Initialize graph canvas in project
3. Add Seed Entities          → Populate apex domain, IP, and seed URL
4. Execute Transforms         → Run subdomains, dns_records, and reverse_dns
5. Filter and Layout          → Apply layout algorithms to isolate critical clusters
6. Export Graph HTML          → Generate shareable interactive report
```

![OSINT summary](Documentation/screenshots_en/112-osint-summary.png)

*Figure 227 — Step 1: passive reconnaissance summary.*

![Entity context menu](Documentation/screenshots_en/117-osint-graph-context-menu.png)

*Figure 228 — Step 4: selecting transforms via node context menu.*

---

### Scenario D — Scheduled Recurring Scan

**Objective:** Establish autonomous background monitoring.

```text
1. Automation                 → Create new workflow
2. Scheduled Trigger          → Configure cron schedule (e.g. daily)
3. Scanner / Repeater         → Connect scanning nodes
4. Output Node                → Set format to JSON
5. Save & Activate            → Register with scheduler
6. Webhook Trigger            → Optionally expose endpoint for external CI/CD triggers
```

![Nodes added to canvas](Documentation/screenshots_en/171-automation-nodes-added.png)

*Figure 229 — Steps 2–4: triggers, tools, and output nodes connected on canvas.*

![Run log output](Documentation/screenshots_en/176-automation-runs.png)

*Figure 230 — Workflow run log detailing execution stages.*

---

### Scenario E — Login Detection in Intruder

**Objective:** Identify payloads resulting in successful authentication bypass.

```text
1. Intruder                   → Input login request with §password§ marker
2. Login Detection            → Enable "Detect successful login"
3. Calibration                → Configure 3 baseline probe requests
4. Wordlist                   → Attach credential wordlist
5. Execute                    → Monitor the MATCH column for positive indicators
```

![Login detection enabled](Documentation/screenshots_en/83-intruder-login-detection.png)

*Figure 231 — Step 2: login detection signals and calibration.*

![Cluster Bomb match tags](Documentation/screenshots_en/75b-intruder-results-cluster-bomb.png)

*Figure 232 — Step 5: "MATCH" column highlights divergent authentication responses.*

---

### Scenario F — Passive Traffic Inspection via Proxy

**Objective:** Intercept and evaluate external browser application traffic.

```text
1. Validate Proxy             → Verify PROXY :8080 indicator is green
2. Configure Browser          → Route browser HTTP/HTTPS proxy to 127.0.0.1:8080
3. Browse Target              → Navigate target application in external browser
4. Traffic Tab                → Observe real-time SSE event stream
5. Select Exchange            → Inspect raw request/response headers and bodies
6. Send to Repeater           → Replay and modify intercepted requests
```

![Live traffic stream](Documentation/screenshots_en/150-traffic-live.png)

*Figure 233 — Step 4: passive proxy live traffic stream.*

> **HTTPS Interception:** To inspect TLS encrypted traffic, install the root CA certificate
> from `data/ca/ca.crt` into your browser's trusted certificate authorities store.

---

## 12. Error Handling

### 12.1 Error Presentation in UI

| Location | Behavior |
|---|---|
| Tool Status Bar | Explanatory error message persists until next operation |
| Header Notification Area | Displays `Project error: ...` or storage conflict warnings |
| Toast Banner | Lower-right alert with color indicator (persists ≥ 4s) |
| Results Pane | Displays descriptive error states in place of blank panels |
| Progress Bar | Visual error phase indicator with failure counters |

**Predictable Diagnostics:** Failures never masquerade as empty successes: output panes display explicit failure reasons rather than misleading blank outputs.

---

### 12.2 Errors by Tool

#### Repeater

| Error | Cause | Resolution |
|---|---|---|
| `Request is empty` | Blank editor input | Supply at minimum `METHOD /path HTTP/1.1` and `Host:` header |
| Request hangs | Invalid host or filtered port | Validate DNS resolution independently; check Tor/Proxy routing |
| Empty response body | Server returned headers only (e.g. `204 No Content`) | Expected behavior for headless responses |

#### Intruder

| Error | Cause | Resolution |
|---|---|---|
| `Fill at least one payload dictionary` | Wordlists empty or cleared | Add entries or load a saved attack profile |
| `Request is empty` | Missing request template | Supply request containing position markers |
| Lower request count than anticipated | Shortest wordlist exhausted in Pitchfork mode | Expected Pitchfork behavior; switch to Cluster Bomb for full Cartesian matrix |
| Tasks fail consecutively | Target host down or proxy route broken | Check header `ROUTE` status and target availability |

#### Target

| Error | Cause | Resolution |
|---|---|---|
| URL rejected | Invalid URL syntax | Correct scheme and host formatting |
| 0 pages discovered | Target unreachable or scope limits too narrow | Verify `Max pages` setting (`0` = unlimited) |
| Browser mode slow | Dynamic SPA script execution delay | Increase `Settlement wait ms` timeout |

![Invalid URL error state](Documentation/screenshots_en/97-target-invalid-url-error.png)

*Figure 234 — Invalid URL syntax rejected with informative error message.*

#### Reconnaissance (OSINT)

| Error | Cause | Resolution |
|---|---|---|
| Blank result cards | DNS resolution failure or host down | Verify Internet connectivity and target hostname |
| `NETWORK_CONFIRMATION_REQUIRED` | Network transform invoked without confirmation | Check confirmation box in transform dialog |
| `TRANSFORM_NOT_APPLICABLE` | Incompatible entity type selected for transform | Check transform compatibility table |
| Graph empty after refresh | No entities saved to graph | Add entity or execute reconnaissance query |

#### Scanner

| Error | Cause | Resolution |
|---|---|---|
| CMS Recon finishes with `HTTP Status: 500` | Target host unreachable | See unreachable target note below |
| Export button disabled | Scan job still in progress | Wait for terminal state or cancel job |
| `PAUSE_UNSUPPORTED` | OS lacks `SIGSTOP` signal support | Fully supported on Linux; returns `501` on unsupported platforms |

> **Critical Note on Unreachable Targets in CMS Recon:** If run against an unbound local port
> (e.g. `http://127.0.0.1:9/`), the scanner finishes reporting "Completed successfully"
> with summary `HTTP Status: 500` and `[INFO] No passive findings`.
>
> ![Unreachable target scan](Documentation/screenshots_en/232-scanner-error-unreachable-target.png)
>
> *Figure 235 — Unreachable target reporting `HTTP 500`.*
>
> **Best practice:** Always check the `HTTP Status` field in the summary. Any code other
> than `200` or expected status indicates connection failure rather than a clean bill of health.

![Empty target input in scanner](Documentation/screenshots_en/230-scanner-error-empty-target.png)

*Figure 236 — Blank target input prevents scan dispatch.*

![Missing templates error](Documentation/screenshots_en/233-scanner-error-no-templates.png)

*Figure 237 — Launching scanner without selected templates is safely rejected.*

#### Traffic and History

| Error | Cause | Resolution |
|---|---|---|
| Traffic table empty | Engine restarted or Clear was clicked | Click "Load from database · N of M" to retrieve archives |
| Expected requests absent from History | Exchanges originated from external proxy traffic | Only deliberate manual tool exchanges log to History without capture context |
| Background traffic absent | Browser traffic lacked capture context | Expected behavior; create a capture context to persist background traffic |

![Empty traffic after clear](Documentation/screenshots_en/150-traffic-live.png)

*Figure 238 — Clear resets in-memory view; historical archives remain queryable.*

#### Automation

| Error | Cause | Resolution |
|---|---|---|
| `CONFIRMATION_REQUIRED` | Hazardous tool node triggered without operator confirmation | Approve confirmation prompt |
| `INVALID_WORKFLOW` | Missing trigger or disconnected edge | Ensure trigger node connects to downstream nodes |
| Run state `interrupted` | Backend process restarted during run | Process runtime reset; trigger execution manually |
| Webhook returns `404` | Invalid slug or missing webhook trigger | Validate webhook slug URL |

---

## 13. Troubleshooting

### Issue: Application Page Fails to Open

| Diagnostic Check | Command | Expected Output |
|---|---|---|
| Gateway responsive | `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/` | `200` |
| Engine responsive | `curl -s http://127.0.0.1:8081/health` | JSON containing `bound` |
| Browser-worker responsive | `curl -s http://127.0.0.1:8090/health` | `{"ok":true,...}` |
| PostgreSQL responsive | `pg_isready -h 127.0.0.1 -p 55433` | `accepting connections` |
| Redis responsive | `redis-cli -p 6379 ping` | `PONG` |
| Ports bound | `ss -tln \| grep -E ':(8000\|8080\|8081\|8090) '` | All ports listening |

If another process occupies these ports, stop the conflicting service or reassign ports via environment variables.

---

### Issue: `ENGINE` Status Indicator Is Not Green

1. Click **↺** next to the indicator to trigger an immediate healthcheck retry.
2. If unresolved, run `./start.sh --status`.
3. Inspect engine log: `data/logs/engine.log`.
4. Verify port binding: `ss -tln | grep 8081`.

---

### Issue: `TemplateSyntaxError` During Database Migrations

Cause: Database created without UTF-8 encoding support.

Resolution:

```sql
CREATE DATABASE requestrider_utf8_tmpl TEMPLATE template0
  ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';
```

Note: PostgreSQL does not support `ALTER DATABASE ... ENCODING`. Recreate the database using the template above.

---

### Issue: `--check` Fails on `WORKFLOW_CELERY_ENABLED`

Cause: Celery broker environment variables leaked into the execution context.

Resolution: Run `./start.sh --check` directly, which automatically sanitizes the environment before executing Django test suites.

---

### Issue: Browser Fails to Intercept HTTPS via Proxy

| Cause | Resolution |
|---|---|
| Root CA not trusted | Import `data/ca/ca.crt` into browser certificate store |
| Self-signed certificate rejection | Explicitly add security exception for domain in browser |
| Proxy listener down | Verify `PROXY` indicator is green in header |

---

### Issue: Long-Running Scans Terminate Unexpectedly

Avoid running long tasks within terminal sessions prone to disconnects. Run detached processes logging to disk:

```bash
setsid nohup <command> > data/logs/<name>.log 2>&1 &
echo "job=<id>  log=data/logs/<name>.log"
```

> **Playwright Note:** Do not redirect input with `< /dev/null` for Playwright tasks,
> as browser channels require valid standard input descriptors to avoid `EPIPE`.

---

### Issue: Chromium Does Not Render Text

In headless Linux environments missing fonts, Chromium may fail to rasterize text. Use Playwright Firefox (`firefox`), which handles font rendering reliably across Linux distributions.

---

### Issue: History Table Overflows Viewport

Verify that the resizable divider has not been dragged beyond viewport boundaries. Reset layout via command palette or run `./start.sh --check` to validate responsive layout tests.

---

## 14. FAQ

**Does Request-Rider require a username and password?**  
No. There is no user authentication database or Django admin interface. The service binds strictly to loopback (`127.0.0.1`). Navigating to `/admin/` deliberately returns `404`.

![Admin 404](Documentation/screenshots_en/315-install-16-admin-absent.png)

*Figure 239 — `/admin/` returns 404.*

**Why does the Automation tab appear active on initial launch?**  
When no saved session exists in `localStorage`, the UI runs `workspaceKinds.forEach(kind => createWorkspace(kind))`, where each creation triggers `selectWorkspace()`. Because `automation` is last in the initialization list, it gains focus initially. Clicking **Repeater** saves your preference.

**Can I load Nuclei templates from an entire directory?**  
Yes. The **Choose Folder** selector uses `webkitdirectory`. Files with identical basenames in different directories remain distinct because relative paths are preserved.

**What happens if I load 100,000 templates?**  
Templates load and persist in IndexedDB rather than `localStorage`, bypassing `localStorage`'s 5MB quota. The workspace handles extensive template libraries without memory exhaustion.

**Does application state survive browser reloads?**  
Yes. Active tabs, workspaces, and UI preferences persist in `localStorage`, with automated snapshots saved to IndexedDB (`requestrider-workspace`).

**Does closing the browser abort an active Intruder attack?**  
No. Window unloads (`pagehide`) do not cancel running fuzzer jobs. Active `attack_id` handles persist in `localStorage`, resuming telemetry polling upon page reload. Attacks must be explicitly aborted via **Cancel Attack**.

**Does passive proxy traffic automatically populate History?**  
No. All outbound requests pass through the proxy and stream to the **Traffic** tab. The **History** tab records deliberate actions (`repeater`, `intruder`, `last-byte`) and proxy traffic with assigned capture contexts.

**Why do `0` and `-1` represent unlimited instead of disabled?**  
To prevent ambiguity between "disabled" and "unbounded". Parameters `max_pages: 0` and `max_depth: -1` signify unlimited traversal.

**Does Request-Rider restrict scanning of internal or private IP ranges?**  
No. There are no artificial restrictions against auditing internal RFC1918 subnets or localhost targets.

**Why do entities appear automatically in Project and OSINT?**  
This is by design (**Observations Ingest**):
- **Target (Crawler):** Discovered pages, directories, and endpoints automatically map as `url`, subdomains as `subdomain`, external services as `domain`, and emails as `email` within the `"Target observations"` graph.
- **Passive OSINT:** Automatically records apex domains, DNS IP resolutions, and technology stacks into `"Passive OSINT observations"`.
- **Transforms:** Executing transforms on nodes generates child entities and relationship edges.

This centralizes target intelligence across tools without manual copy-pasting.

**Can I trust a `LOW` finding from CMS Recon?**  
A `LOW` finding indicates that a path exists or redirected. It is an informational indicator, not an automated proof of exploitability. Always evaluate the recommendation details.

**What does `Proven` mean in the Active Scanner?**  
It signifies that the scanner dispatched a verification probe confirming exploit impact, providing a verifiable Proof of Concept (PoC). `Unconfirmed` indicates an anomalous response requiring manual verification.

**Can I generate reports offline?**  
Yes. Exported HTML reports are 100% self-contained: zero external dependencies, CDN links, or web fonts.

**Does exported report language match workspace language?**  
Yes. Reports inspect the `requestrider-language` cookie. Appending `?lang=` to the report URL switches language without JavaScript.

**Can Request-Rider be deployed in Docker?**  
Yes. A production `docker-compose.yml` is included in the repository.

---

## 15. Best Practices

**Rule 1 — Always create a project before testing.**  
Without an active project, History records and scanner findings lack correlation, and the Knowledge Hub remains unpopulated.

**Rule 2 — Save Intruder attacks before clearing results.**  
Clicking `Clear Results` resets the entire configuration form. Save valuable configurations via `Save Attack` first.

**Rule 3 — Begin with low-impact reconnaissance.**  
Execute CMS Recon (1 minute) → Passive OSINT → Active Scanner with Corpus Checks. Active fuzzing generates high request volumes; scope targets deliberately.

**Rule 4 — Verify routing before initiating large test suites.**  
Click `Check Connection` in the Tor/Proxy tab to verify outbound IP routing and prevent accidental IP exposure.

**Rule 5 — Filter by proof rather than finding count.**  
Toggle `Proven Only` in Scanner Pro and `Matches Only` in Intruder to eliminate noise and prioritize actionable findings.

**Rule 6 — Inspect HTTP status codes in CMS Recon.**  
Unreachable hosts return an informational report with `HTTP Status: 500`. Verify status code before concluding an endpoint is secure.

**Rule 7 — Do not alter proxy routing mid-audit.**  
Applying or cancelling an outbound route drains in-flight jobs. Only alter routes between scan phases.

**Rule 8 — Install the root CA certificate for HTTPS inspection.**  
Import `data/ca/ca.crt` into your browser's trust store to inspect encrypted TLS traffic.

**Rule 9 — Export session bundles before major state changes.**  
Exporting session JSON bundles allows restoring complete audit states across machines.

**Rule 10 — Run verification checks when extending UI or code.**  
Run `./start.sh --check` to validate inline scripts, code styles, and unit test suites.

---

## 16. Complete Checklist

Use this checklist to ensure complete operational familiarity with Request-Rider:

### Installation
- [ ] Validated Python, Go, Docker, and Git versions
- [ ] Reviewed `start.sh` and CLI `--help`
- [ ] Started stand and verified all services report `UP`
- [ ] Queried `GET /health` and verified transport limits
- [ ] Accessed gateway URL and confirmed `HTTP 200`
- [ ] Queried `/api/projects` and `/api/traffic` via cURL
- [ ] Dispatched initial request via `/api/execute`
- [ ] Ran automated JS syntax and dictionary integrity checks

### User Interface
- [ ] Toggled language switcher and verified all tabs re-rendered
- [ ] Opened command palette via `Ctrl+K`
- [ ] Verified responsive layout at 1920×1080 and 1356×652
- [ ] Created second workspace tab, renamed via double-click, and closed it
- [ ] Saved, exported, and imported session JSON bundle

### Projects
- [ ] Created project and set as active workspace
- [ ] Edited project metadata via **Manage Project**
- [ ] Reviewed all Knowledge Hub overview tabs
- [ ] Exported project in JSON, HTML, and CSV formats
- [ ] Validated cascade deletion behavior

### Repeater
- [ ] Dispatched GET request and inspected raw response
- [ ] Dispatched POST request with body and `Cookie:` header
- [ ] Inspected query and body parameters in Inspector
- [ ] Copied request as cURL command
- [ ] Piped response into Comparer

### Intruder
- [ ] Configured position markers using `§...§`, `{{...}}`, and `%...%`
- [ ] Populated wordlists manually and loaded from file
- [ ] Evaluated Sniper, Battering Ram, Pitchfork, and Cluster Bomb modes
- [ ] Executed attack with Pause, Resume, and Cancel actions
- [ ] Inspected raw request and response for individual result row
- [ ] Filtered results by status and toggled "Matches Only"
- [ ] Exported attack results in JSON, HTML, and CSV
- [ ] Saved attack configuration and re-executed from saved catalog
- [ ] Applied payload transformations
- [ ] Configured Login Detection and inspected MATCH column

### Target
- [ ] Built static site map crawl
- [ ] Configured `0` / `-1` limits and validated unbounded crawling
- [ ] Filtered and navigated hierarchical URL tree
- [ ] Exported site map in JSON, CSV, and HTML
- [ ] Executed browser-driven crawl
- [ ] Filtered captured network traffic by XHR events

### Reconnaissance (OSINT)
- [ ] Executed passive scan and evaluated six intelligence cards
- [ ] Created entity graph and added manual nodes
- [ ] Executed transforms via node context menu
- [ ] Applied graph filters, zoom controls, and layout arrangements
- [ ] Exported standalone interactive HTML entity graph

### Scanner
- [ ] Executed CMS Recon and evaluated findings and severities
- [ ] **Verified HTTP status code in scan summary**
- [ ] Loaded Nuclei template directories and reviewed execution plan
- [ ] Executed Active Scanner and verified Proof of Impact findings
- [ ] Filtered findings by severity and proof status
- [ ] Exported all three scan reports

### Comparer and Decoder
- [ ] Compared exchanges by words and by bytes
- [ ] Swapped comparative panes
- [ ] Transferred comparison payload to Decoder
- [ ] Executed at least 6 distinct decoding/encoding operations
- [ ] Validated explicit decoding error handling

### Tor / Proxy
- [ ] Applied SOCKS5 route and inspected cancelled operations counter
- [ ] Cancelled route and restored direct routing
- [ ] Executed connection and DNS leak validation checks

### History and Traffic
- [ ] Highlighted exchange row and inspected raw panels
- [ ] Filtered history by host and sorted by URL/latency
- [ ] Paginated records via "Show more from database"
- [ ] Utilized row context menu actions (`⋯`)
- [ ] Exported selected records
- [ ] Paused and resumed live traffic stream
- [ ] Verified traffic clearing semantics

### AI and Automation
- [ ] Configured LLM provider and API endpoint
- [ ] Analyzed tool findings with grounded evidence
- [ ] Utilized active project context injection
- [ ] Built three-node automation workflow with connected edges
- [ ] Configured node parameters, executed workflow, and inspected run log
- [ ] Imported template from Template Store

### Specialized Headless Tools
- [ ] Executed Repeater Burst via engine REST API
- [ ] Executed Last-Byte Sync via engine REST API
- [ ] Verified OAST callback listener ingestion

### Diagnostics
- [ ] Distinguished unreachable targets from clean scan findings
- [ ] Distinguished decoding syntax errors from blank outputs
- [ ] Recognized `409 ROUTE_CHANGED` route drain semantics
- [ ] Inspected service logs in `data/logs/`
- [ ] Executed headless long-running scans detached with log capture

---

## 17. Feature Coverage Matrix

This matrix verifies that every feature is verified against live runtime environments:
- **Verified Live** — Feature tested on a running standalone instance;
- **Documented** — Complete operational procedure documented;
- **Screenshots** — Live UI screenshot provided;
- **End-to-End** — Covered within Practical Scenarios (Section 11).

| # | Feature | Verified Live | Documented | Screenshots | End-to-End |
|---:|---|:---:|:---:|:---:|:---:|
| 1 | Navigation across 13 tabs | ✅ | ✅ | ✅ | — |
| 2 | Command palette `Ctrl+K` | ✅ | ✅ | ✅ | — |
| 3 | Language toggle EN ⇄ UK | ✅ | ✅ | ✅ | — |
| 4 | Layouts (1920×1080 and 1356×652) | ✅ | ✅ | ✅ | — |
| 5 | Header process indicators + `↺` recheck | ✅ | ✅ | ✅ | — |
| 6 | Save / Export / Import session | ✅ | ✅ | ✅ | — |
| 7 | Workspace management: add, rename, close | ✅ | ✅ | ✅ | — |
| 8 | Projects: create | ✅ | ✅ | ✅ | ✅ B |
| 9 | Projects: edit metadata | ✅ | ✅ | ✅ | — |
| 10 | Projects: cascade deletion | ✅ | ✅ | ✅ | — |
| 11 | Knowledge Hub: Overview | ✅ | ✅ | ✅ | — |
| 12 | Knowledge Hub: Asset Map | ✅ | ✅ | ✅ | — |
| 13 | Knowledge Hub: Secrets | ✅ | ✅ | ✅ | — |
| 14 | Knowledge Hub: Scanner Runs | ✅ | ✅ | ✅ | — |
| 15 | Knowledge Hub: Workflows | ✅ | ✅ | ✅ | — |
| 16 | Knowledge Hub: AI Snapshot | ✅ | ✅ | ✅ | — |
| 17 | Projects: export JSON / HTML / CSV | ✅ | ✅ | ✅ | — |
| 18 | Projects: import bundle | ✅ | ✅ | — | — |
| 19 | Repeater: GET request & response | ✅ | ✅ | ✅ | ✅ A |
| 20 | Repeater: POST with body & cookie | ✅ | ✅ | ✅ | ✅ A |
| 21 | Repeater: request inspector | ✅ | ✅ | ✅ | — |
| 22 | Repeater: add parameter | ✅ | ✅ | ✅ | — |
| 23 | Repeater: copy response | ✅ | ✅ | ✅ | — |
| 24 | Repeater: copy as cURL | ✅ | ✅ | ✅ | — |
| 25 | Repeater: `Ctrl/Cmd+Enter` shortcut | ✅ | ✅ | — | — |
| 26 | Repeater: clear panes | ✅ | ✅ | — | — |
| 27 | Repeater: pipe to AI & Automation | ✅ | ✅ | — | ✅ A |
| 28 | Intruder: three marker syntaxes | ✅ | ✅ | ✅ | — |
| 29 | Intruder: wordlists (manual and file) | ✅ | ✅ | ✅ | ✅ E |
| 30 | Intruder: Sniper mode | ✅ | ✅ | — | — |
| 31 | Intruder: Battering Ram mode | ✅ | ✅ | — | — |
| 32 | Intruder: Pitchfork mode (shortest list bound) | ✅ **Verified** | ✅ | ✅ | — |
| 33 | Intruder: Cluster Bomb mode (Cartesian matrix) | ✅ **24/24 Verified** | ✅ | ✅ | — |
| 34 | Intruder: delay & concurrency | ✅ | ✅ | ✅ | — |
| 35 | Intruder: pause / resume / cancel | ✅ | ✅ | ✅ | — |
| 36 | Intruder: task estimation | ✅ | ✅ | ✅ | — |
| 37 | Intruder: MATCH column (detection) | ✅ **Verified** | ✅ | ✅ | ✅ E |
| 38 | Intruder: payload transforms | ✅ | ✅ | ✅ | — |
| 39 | Intruder: save / load / re-run attack | ✅ | ✅ | ✅ | — |
| 40 | Intruder: filter, sort, Matches Only | ✅ | ✅ | ✅ | ✅ A |
| 41 | Intruder: export JSON / HTML / CSV | ✅ | ✅ | ✅ | ✅ A |
| 42 | Target: static crawler | ✅ **Verified** | ✅ | ✅ | ✅ A |
| 43 | Target: `0` / `-1` unbounded limits | ✅ | ✅ | ✅ | — |
| 44 | Target: browser-driven crawler | ✅ | ✅ | ✅ | — |
| 45 | Target: XHR network filter | ✅ | ✅ | ✅ | — |
| 46 | Target: export JSON / CSV / HTML | ✅ | ✅ | ✅ | — |
| 47 | OSINT: passive scan (6 cards) | ✅ | ✅ | ✅ | ✅ C |
| 48 | OSINT: safe WAF canary | ✅ | ✅ | ✅ | — |
| 49 | OSINT: export JSON / CSV | ✅ | ✅ | ✅ | — |
| 50 | OSINT: entity graph create/upsert | ✅ | ✅ | ✅ | ✅ C |
| 51 | OSINT: 19 transforms (local & network) | ✅ | ✅ | ✅ | ✅ C |
| 52 | OSINT: graph layouts (Grid, Radial, etc.) | ✅ | ✅ | ✅ | — |
| 53 | OSINT: export graph HTML | ✅ | ✅ | ✅ | ✅ C |
| 54 | Scanner: CMS reconnaissance | ✅ | ✅ | ✅ | ✅ B |
| 55 | Scanner: Active & Corpus Scanner | ✅ **Proven Impact** | ✅ | ✅ | ✅ B |
| 56 | Scanner: filter by severity and proof | ✅ | ✅ | ✅ | ✅ B |
| 57 | Scanner: export JSON / HTML / CSV | ✅ | ✅ | ✅ | ✅ B |
| 58 | Comparer: words & bytes diff | ✅ | ✅ | ✅ | — |
| 59 | Comparer: swap panes | ✅ | ✅ | ✅ | — |
| 60 | Comparer: pipe to Decoder | ✅ | ✅ | ✅ | — |
| 61 | Decoder: 16 operations | ✅ | ✅ | ✅ | — |
| 62 | Decoder: error reporting | ✅ | ✅ | ✅ | — |
| 63 | Tor/Proxy: apply & drain route | ✅ | ✅ | ✅ | — |
| 64 | Tor/Proxy: Zero DNS Leaks & DoH | ✅ | ✅ | — | — |
| 65 | Tor/Proxy: check connection | ✅ | ✅ | ✅ | — |
| 66 | History: table inspection & sorting | ✅ | ✅ | ✅ | — |
| 67 | History: load more pagination | ✅ | ✅ | ✅ | — |
| 68 | History: row context menu | ✅ | ✅ | ✅ | — |
| 69 | History: export selected | ✅ | ✅ | ✅ | — |
| 70 | Traffic: live SSE stream | ✅ | ✅ | ✅ | ✅ F |
| 71 | Traffic: pause & resume capture | ✅ | ✅ | ✅ | ✅ F |
| 72 | Traffic: database archive pagination | ✅ | ✅ | ✅ | — |
| 73 | Traffic: purge and clear semantics | ✅ | ✅ | ✅ | — |
| 74 | AI Agent: ReAct loop | ✅ | ✅ | ✅ | — |
| 75 | AI Agent: 16 MCP tools | ✅ | ✅ | — | — |
| 76 | AI Agent: audit report export (HTML/JSON) | ✅ | ✅ | ✅ | — |
| 77 | Automation: 22 node types & canvas | ✅ | ✅ | ✅ | ✅ D |
| 78 | Automation: cron scheduler & webhook | ✅ | ✅ | — | ✅ D |
| 79 | Automation: Template Store | ✅ | ✅ | ✅ | ✅ D |
| 80 | Repeater Burst (Headless) | ✅ | ✅ | — | — |
| 81 | Last-Byte Sync (Headless) | ✅ | ✅ | — | — |
| 82 | OAST Listener (Headless) | ✅ | ✅ | — | — |
| 83 | CLI `start.sh --check` | ✅ | ✅ | ✅ | — |
| 84 | Gateway REST API | ✅ | ✅ | — | — |
| 85 | Engine REST API | ✅ | ✅ | ✅ | — |
| 86 | Browser-worker REST API | ✅ | ✅ | — | — |

---

### 17.1 Features Requiring External Dependencies

| Feature | Requirement | Notes |
|---|---|---|
| Tor Routing | Local Tor daemon or upstream SOCKS5 | Requires listening SOCKS5 endpoint; testing against unreachable port validates route drain |
| OAST Listener | Public OAST service provider | Requires Internet callback delivery; local mock fixture validates internal ingestion |
| AI Agent | Valid LLM Provider API Key | Local OpenAI-compatible mock endpoints require no keys; commercial providers require credentials |
| Celery Mode | `WORKFLOW_CELERY_ENABLED=1` | Optional distributed mode; standard standalone setup defaults to in-memory runtime |

---

### 17.2 Documented Operational Nuances

1. **Initial Active Tab:** Initial launch defaults to the **Automation** tab because initialization executes `workspaceKinds.forEach(createWorkspace)` where `automation` is last. Selecting **Repeater** persists workspace choice.
2. **Clear Results in Intruder:** Clicking `Clear Results` resets the **entire configuration form** (request template, markers, wordlists, and transforms). Save attacks first.
3. **CMS Recon Unreachable Target:** Probing an unbound port returns `HTTP Status: 500` under "Completed successfully". Check status codes.
4. **Intruder Task Estimation:** Task estimators project Cartesian or max lengths; Pitchfork mode executes to the length of the shortest wordlist.
5. **Manage Project vs. Knowledge Hub:** `Manage Project` opens metadata configuration; the Knowledge Hub renders automatically when an active project is selected.
6. **Language Toggle Scope:** Switching interface language re-renders **all** application tabs and views simultaneously.
7. **Transport Boundaries Visibility:** Active dial, TLS, and read timeouts are reported directly via `GET /health`.

---

