# TDD Workflow

RED → GREEN → REFACTOR, applied literally rather than as a slogan.

## RED — write a failing test first

- Write the test against the interface you want to exist, not the implementation you're about to write.
- Run it and confirm it fails for the expected reason (missing implementation), not a typo or import error.
- One behavior per test. If a test needs "and" to describe it, split it.

## GREEN — minimal implementation

- Write the smallest amount of code that makes the test pass. Resist adding functionality the test doesn't require yet.
- Run the full test suite, not just the new test, to confirm nothing else broke.

## REFACTOR — improve without changing behavior

- Clean up naming, remove duplication, extract functions — with tests green throughout.
- Re-run tests after every meaningful change, not just at the end.
- Do not add new behavior during this step; that goes back to RED.

## Coverage expectations

- Aim for 80%+ coverage on new code as a floor, not a target to game.
- Business-critical logic (billing, auth, data integrity) should be closer to 100%.
- A test suite with high coverage but only happy-path assertions is not done — add failure-path tests explicitly.

## Working with an agent

When delegating TDD work to an agent, ask for the RED step in isolation first and confirm the test fails before asking for the implementation. This catches tests that pass trivially (e.g., testing a mock instead of the real code path).
