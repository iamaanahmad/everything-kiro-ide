# Debugging Strategies

A repeatable loop for bugs and performance regressions, instead of guessing.

## 1. Reproduce

- Get exact repro steps, expected vs. actual behavior, and the environment (browser, OS, data state).
- If it can't be reproduced reliably, that inconsistency is itself a clue (race condition, cache, stale state).

## 2. Gather information

- Read relevant logs and error traces in full, not just the last line.
- Check recent changes touching the affected code path (`git log`, `git blame`).
- Reproduce with logging/tracing added if the existing signal isn't enough — don't guess blind.

## 3. Form a hypothesis

- State the suspected root cause as a falsifiable claim: "the N+1 query in `getUser` is the cause of the slowdown," not "something with the database."
- Rank hypotheses by likelihood given the evidence gathered so far.

## 4. Test the hypothesis

- Add targeted instrumentation or a minimal reproduction case that isolates the suspected cause.
- If the hypothesis is wrong, say so explicitly and move to the next one — don't quietly patch around the symptom.

## 5. Fix the root cause

- Fix the cause, not the symptom. A `try/catch` that hides the error is not a fix.
- Consider whether the same class of bug exists elsewhere in the codebase.

## 6. Verify and prevent regression

- Confirm the original repro steps no longer trigger the bug.
- Add a test that would have caught this bug before it shipped.
- Run the full test suite to confirm the fix didn't break something else.

## When stuck after two attempts

If two different hypotheses have failed, stop iterating on variations of the same approach. Step back and question the assumption underneath both attempts — the bug is often one layer removed from where it first appears to be.
