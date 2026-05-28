# Milestone planning (PRD)

Every milestone needs a `PRD.md` at its root before any epics or tasks are created inside it. The PRD is the contract that defines what "this milestone is done" means.

**Prerequisites:** read `references/structure.md` for the PRD format.

## Why PRDs exist

Without a milestone-level PRD, two failure modes dominate:

1. **Task drift**: each task gets implemented in isolation, with no shared notion of how they fit together. Integration is whatever happens to emerge from the union of the tasks — often nothing coherent.
2. **Scope creep**: the milestone grows with each "while we're at it" idea, until it's never finished.

The PRD fixes both:

- Its **Integration contract** section forces tasks to compose toward known scenarios.
- Its **Out of scope** section is the explicit pushback against scope creep.

## When to write a PRD

- **Before** creating any epics in a new milestone. The PRD informs the epic decomposition, not the other way around.
- **Updated** if the milestone genuinely shifts during work (with a Discussion entry on the PRD itself explaining why).
- **Re-read** at the start of any task within the milestone (the working-on-task workflow expects this).

## Checklist for creating a PRD

```
- [ ] Confirm with the user what this milestone delivers (Goal)
- [ ] Draft 3-5 Success criteria — each must be externally observable
- [ ] Draft Out of scope — at least 2 items, ideally 3-5
- [ ] Draft Integration contract — concrete end-to-end scenarios
- [ ] Draft Constraints — anything cross-cutting that affects all epics
- [ ] Draft Risks — known unknowns that could derail the milestone
- [ ] Present the PRD to the user for validation
- [ ] On validation: save as M<N>-<slug>/PRD.md, then proceed to epic decomposition
```

## Writing each section

### Goal

One sentence. The hardest section to get right because of the temptation to add detail. Resist.

```markdown
## Goal
Users can authenticate via OAuth and stay signed in across browser sessions.
```

Not:

```markdown
## Goal
Implement a comprehensive authentication system supporting OAuth, refresh tokens,
session management, multi-device support, and integration with our user
profile service.
```

The second version is a wishlist disguised as a goal. The first defines a clear bar.

### Success criteria

3-5 bullets. Each must be observable by someone external to the code (a product person, a customer, a tester). If a criterion is something only the implementer can see, it belongs in a task's DoD, not the milestone PRD.

```markdown
## Success criteria

- A new user can sign in with Google in under 10 seconds end-to-end.
- A returning user is recognized without creating a duplicate account.
- A user's session persists across browser tabs and survives a browser restart.
- An expired access token is refreshed transparently without re-authentication prompt.
- All session activity is auditable from the `audit_logs` table.
```

These are not implementation steps — they are claims about the deployed system.

### Out of scope

This is the most-skipped section, and the most important. **Write at least 3 items.** If you can't think of 3, you haven't thought hard enough about scope.

```markdown
## Out of scope

- Multi-factor authentication (deferred to M3).
- Enterprise SSO via SAML or OIDC providers other than Google.
- "Sign in with email" (passwordless or magic link).
- Account recovery / password reset (we don't have passwords).
- Account deletion (compliance work, not auth work).
```

When new requests come up later ("just add MFA, it's easy"), this section is what justifies saying "not in this milestone."

### Integration contract

The most important section for guiding the integration-verify tasks. Each scenario is a Given/When/Then narrative concrete enough that an integration test can be written from it directly.

```markdown
## Integration contract

1. **First-time login**:
   Given: a user with no existing account, on the landing page.
   When: they click "Sign in with Google" and complete the IdP flow.
   Then: they land on `/app` with a session cookie set,
   and a `users` row exists with their email and Google sub,
   and an `audit_logs` row records `auth.first_login`.

2. **Returning user**:
   Given: a user with an existing account, on the landing page,
   no current session cookie.
   When: they sign in with Google.
   Then: they land on `/app` with a new session cookie,
   and the existing `users` row is unchanged (not duplicated),
   and `users.last_login_at` is updated.

3. **Silent refresh**:
   Given: a user with an expired access token but valid refresh token.
   When: any API call is made.
   Then: the call succeeds with a new access token,
   and the refresh token is rotated (old one no longer valid),
   and no UI prompt appears.

4. **Refresh failure on rotated token reuse**:
   Given: a refresh token that has been rotated.
   When: an attempt is made to use the old refresh token.
   Then: the API call fails with 401,
   and the session is invalidated server-side,
   and the user is redirected to sign in.
```

Scenarios should be exhaustive enough to catch realistic failure modes. The reuse-of-rotated-token case in scenario 4 is the kind of edge case that integration testing must cover.

Aim for 3-7 scenarios per milestone. Fewer means the milestone is probably too small; more means it's too big.

### Constraints

Cross-cutting requirements that affect every epic.

```markdown
## Constraints

- All endpoints must respond in < 500ms p95 under load of 100 req/s.
- All OAuth flows must work in iframes (for embedded contexts).
- No PII in logs (no emails, no names, no Google sub IDs in logs at INFO level or below).
- All session-related cookies must be httpOnly, SameSite=Lax, Secure.
- Must support graceful degradation if the IdP is unreachable (return 502, not 500).
```

These constraints are inherited by every epic and task. They influence DoD items in individual tasks.

### Risks

Things you don't know yet that could derail the milestone. Useful because they tell future-you what to investigate first.

```markdown
## Risks

- IdP rate limits unknown for the token endpoint at our expected scale —
  needs measurement during M1-auth/oauth epic.
- Cookie SameSite=Lax may interact poorly with the embedded iframe context
  we plan to support — needs validation early in the OAuth epic.
- Concurrent refresh requests from the same client may cause race conditions
  in the rotation logic — needs a specific stress test in integration-verify.
```

When a risk materializes, add a Discussion entry to the PRD (PRDs can have Discussion sections too, though it's optional).

## Presenting the PRD for validation

Format the PRD as Markdown (the spec file itself) and show it to the user. Ask:

> Does this PRD capture what we want for milestone M<N>-<slug>?
> Specifically:
> - Are the Success criteria the right bar?
> - Is anything in Out of scope you wanted included? Or vice versa?
> - Are the Integration contract scenarios complete enough?

Wait for explicit validation. Do not start creating epics or tasks until the user approves the PRD.

After validation, save the PRD to `.tasks/M<N>-<slug>/PRD.md` and proceed to epic decomposition (see `creating-feature.md`).

## How the PRD drives the rest of the plan

Once validated, the PRD cascades downward:

- **Epic decomposition**: each epic should contribute to one or more Success criteria. If an epic doesn't map to any criterion, ask whether it belongs in this milestone.
- **Epic doc.md**: the Acceptance criteria in each epic doc refine the PRD's Integration contract for that epic's slice.
- **Task DoD**: each task's DoD items should trace back to either a Success criterion or an Integration contract scenario.
- **Integration-verify tasks**: one per epic (typically the last task), with DoD items mirroring the scenarios from the Integration contract that the epic delivers.

If a task's DoD has items that don't trace to anything in the PRD, either the PRD is incomplete or the task is doing extra work. Both are worth flagging.

## When to update the PRD mid-milestone

Rare but legitimate cases:

- **Success criterion turns out to be wrong** (e.g., "sub-500ms p95" is unachievable with the chosen architecture). Update the criterion, add a Discussion entry explaining why.
- **A new constraint emerges** (e.g., a compliance requirement discovered mid-work). Add it, log it.
- **A scenario in the Integration contract turns out to be impossible or wrong**. Update it, log it, propagate to any tasks that referenced it.

What is NOT a legitimate update:

- "We want to add MFA too" — that's scope creep. Push it to a follow-up milestone.
- "Let's loosen the latency constraint because it's hard" — no. If the constraint was real, the architecture needs to change, not the constraint.

## PRD vs epic doc vs task

The hierarchy of intent:

| Level     | Document   | Scope                                              | Authoritative for                          |
| --------- | ---------- | -------------------------------------------------- | ------------------------------------------ |
| Milestone | PRD.md     | What "this milestone is done" means                | Success criteria, Integration contract     |
| Epic      | doc.md     | What "this epic is done" means within the milestone | Epic-specific acceptance criteria, design  |
| Task      | TASK-NNN.md | What "this specific task is done" means            | Concrete Actions and DoD for one unit of work |

Each level inherits and refines the level above. A task's DoD should never contradict the PRD's Success criteria — if it would, the PRD needs revision, not the task.
