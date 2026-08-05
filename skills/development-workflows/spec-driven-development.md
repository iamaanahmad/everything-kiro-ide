# Spec-Driven Development with Kiro

How Kiro's actual spec system works: three files, one per phase, each requiring explicit approval before the next begins.

## What a spec is

A spec formalizes a feature or fix into three markdown files under `.kiro/specs/{feature_name}/`:

- **requirements.md** — what needs to be built, in EARS format
- **design.md** — how it will be built, with interfaces and data models
- **tasks.md** — a numbered, checkbox-based implementation plan

Each phase must be explicitly approved by the user before Kiro moves to the next one. This is not optional pacing — it's the point of the workflow: catch misunderstandings in requirements before they become a wrong design, and catch design gaps before they become wrong code.

## The workflow

```
requirements.md → (approval) → design.md → (approval) → tasks.md → (approval) → task execution
```

Kiro also offers **Quick Spec**, a mode that generates all three phases in one pass after a short round of clarifying questions, for when the full gated workflow is more ceremony than the feature needs. Use the full workflow for anything touching more than a few files or with real ambiguity in scope; use Quick Spec for small, well-understood features.

## Phase 1: requirements.md (EARS format)

EARS (Easy Approach to Requirements Syntax) constrains acceptance criteria to a small set of testable patterns instead of free-form prose:

- `WHEN [event] THEN [system] SHALL [response]`
- `IF [precondition] THEN [system] SHALL [response]`
- `WHEN [event] AND [condition] THEN [system] SHALL [response]`

```markdown
# Requirements Document

## Introduction

Short summary of the feature and why it's needed.

## Requirements

### Requirement 1

**User Story:** As a returning user, I want to log in with email and password, so that I can access my account.

#### Acceptance Criteria

1. WHEN a user submits valid credentials THEN the system SHALL create an authenticated session
2. IF a user submits an incorrect password 5 times within 15 minutes THEN the system SHALL lock the account and notify the user
3. WHEN a user's session expires AND the user makes a request THEN the system SHALL return a 401 and redirect to login

### Requirement 2

**User Story:** As a security-conscious user, I want optional multi-factor authentication, so that my account is protected even if my password leaks.

#### Acceptance Criteria

1. WHEN a user enables MFA THEN the system SHALL generate a TOTP secret and display it as a QR code
2. WHEN a user with MFA enabled logs in with a correct password THEN the system SHALL require a valid TOTP code before creating a session
```

Kiro generates the first draft directly from your description — it does not interview you with sequential questions before writing something down. You then review and ask for revisions. The exact approval question Kiro asks is: *"Do the requirements look good? If so, we can move on to the design."* Nothing proceeds until you say yes.

## Phase 2: design.md

Written against the approved requirements, and should address every requirement — not just the parts that were easy to design.

Required sections: **Overview**, **Architecture**, **Components and Interfaces**, **Data Models**, **Error Handling**, **Testing Strategy**. Include code-level interfaces even for components that don't exist yet — a `interface AuthService { login(...): Promise<Session> }` sketch makes the design concrete enough to review, and concrete enough to turn directly into tasks.

Approval question: *"Does the design look good? If so, we can move on to the implementation plan."*

## Phase 3: tasks.md

Converts the design into a checkbox list of coding tasks — at most two levels of hierarchy, each referencing the requirement(s) it satisfies:

```markdown
# Implementation Plan

- [ ] 1. Set up auth module structure and core interfaces
  - Create `AuthService`, `TokenService` interfaces
  - _Requirements: 1.1_

- [ ] 2. Implement login endpoint
  - [ ] 2.1 Add credential verification and session creation
    - _Requirements: 1.1, 1.3_
  - [ ] 2.2 Add account lockout after repeated failures
    - _Requirements: 1.2_

- [ ] 3. Implement MFA
  - [ ] 3.1 TOTP secret generation and QR code endpoint
    - _Requirements: 2.1_
  - [ ] 3.2 TOTP verification in the login flow
    - _Requirements: 2.2_
```

**tasks.md is coding tasks only.** It explicitly excludes: user acceptance testing, production deployment, performance benchmarking, manual end-to-end runs, documentation/training, and anything else that isn't writing, modifying, or testing code. Those belong in the DevOps/QA process, not the spec's task list.

Each task should be independently demoable, build on the previous one, and end with an integration task that wires the pieces together — no orphaned code that never gets called.

Approval question: *"Do the tasks look good?"*

## Task execution

Execution is a separate phase from planning. When working through tasks.md:

- Read all three spec files before starting any task, not just tasks.md
- Work one task at a time; complete sub-tasks before the parent task
- Stop after each task and let the user review rather than chaining through the whole list automatically
- Update task status (`pending` → `in_progress` → `completed`) as you go, rather than batch-updating at the end

## Best practices

- **Requirements**: group related acceptance criteria under one requirement instead of fragmenting into many near-duplicate requirements. Use `SHALL` for mandatory behavior, `SHOULD` for recommended-but-not-required behavior.
- **Design**: keep terminology consistent with requirements.md — if requirements says "session," don't switch to "token" in design without an explicit reason.
- **Tasks**: if a requirement isn't referenced by any task, that's a signal something got dropped between design and planning — go back and check.
- **Scope creep during review**: if new ideas surface while reviewing design or tasks, redirect them to a new requirement rather than silently expanding scope mid-phase.

## Reference

`#[[file:path/to/file]]` works inside spec documents to pull in an existing file (an OpenAPI spec, an ERD, another spec) as supporting context.
