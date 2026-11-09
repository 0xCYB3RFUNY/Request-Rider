# Requirement fidelity and actual design-system use

Read during recon, verification and plan execution for work on an existing UI. This protocol supplements the design-system checks; it does not authorize source edits during an audit or impose a particular library, font, palette or layout.

## Establish the contract

Record the current user requirements and the project's existing design-system sources before judging or changing the UI. Keep a small project-local decision/evidence table:

| Requirement | Origin and source | Status | Component / role / variant | Verification and result |
|---|---|---|---|---|
| Preserve the catalog interaction | User message or accepted project contract, with locator | accepted / inherited / proposed / superseded | Actual source API | Behavioral check and observed result |

Separate direct user decisions, inherited documented constraints and agent proposals. An agent summary, generated brief, screenshot interpretation or prior implementation is not proof of user approval. Current explicit user corrections supersede contradictory summaries. Retain the source and mark the old interpretation superseded. An unresolved ambiguity is a gap, not permission to claim approval.

Audit structure, behavior, copy and visual treatment independently. A request to preserve structure while changing appearance does not authorize changing tabs into sections, removing sorting, hiding catalog records or changing the primary action. These examples illustrate contract drift, not universally preferred UI patterns.

## Check consumption, not installation

For each changed or contract-critical surface, including the hero, trace:

requirement → existing component and variant API → semantic type/surface/motion role → rendered state.

Inspect actual callers and winning computed styles. A configured registry, import count or token count is insufficient. Reaching past a composite typography role to a raw font variable, overriding an imported component locally, or copying its markup with custom styles remains a bypass.

Before proposing a new token/component/variant, identify the existing candidates and explain the missing capability. Moving an arbitrary page value to a newly named variable is not a fix by itself. Extend the shared source when the gap is real, record affected consumers and check them. Ordinary product-specific composition and dynamic content/layout values remain legitimate when consistent with the contract; literal syntax alone does not establish a violation.

## Evidence and enforcement

A fix plan must state the protected requirement, actual DS API, scope, regression check and visual reference/state where relevant. Inventory all changed and contract-critical surfaces before choosing test coverage. Report omissions explicitly; a hand-picked subset cannot establish project-wide compliance.

Where a project has enforcement tooling, require coverage for local typography and primitive overrides, raw-foundation access that bypasses a semantic role, unreviewed parallel tokens/variants, and structural regressions. Make checks contract-aware: identify DS source directories, generated files, allowed composition and explicit exceptions. Reproduce the violation, then confirm the check catches it and permits legitimate DS use. Do not weaken a gate, add a bypass token or bless an exception merely to obtain green output.

Report four outcomes separately: requirement fidelity, DS consumption, runtime/build checks and visual comparison. Passing one does not prove the others or owner visual acceptance. No new detector coverage is implied by this document; the detector rules live in `scripts/rules/`.

## Execution and approval

Use existing user authorization. Fixing an instance to consume an existing role, or mechanically extending the DS within the accepted scope, does not automatically require approval. TOUCHES-DS records a source change. REQUIRES-APPROVAL applies only to a genuinely unresolved owner decision, with the alternatives and tradeoff stated before execution. Do not stop ordinary authorized work merely because it touches a design system.
