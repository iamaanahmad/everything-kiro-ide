# Code Review Process

A systematic order of operations for reviewing code, security first.

## 1. Security (always first)

- Hardcoded secrets, API keys, tokens, or credentials
- Injection risks: SQL, command, template, path traversal
- Authentication and authorization logic — check both presence and correctness, not just presence
- Input validation and output encoding on any user-controlled data
- Sensitive data in logs or error messages

Flag findings by severity: CRITICAL (block merge), HIGH (block merge unless justified), MEDIUM (fix before release), LOW (track as follow-up).

## 2. Correctness

- Does the change do what the PR description says it does?
- Are edge cases handled (empty input, null, concurrent access, network failure)?
- Are error paths handled explicitly rather than swallowed?

## 3. Performance

- Any new N+1 queries, unbounded loops over external data, or synchronous calls that should be async?
- Any obviously expensive operation on a hot path?

Don't chase micro-optimizations that don't affect a real bottleneck.

## 4. Test coverage

- New logic has tests covering the happy path and at least one failure/edge case
- Tests assert behavior, not implementation details
- No tests were only added to hit a coverage number

## 5. Readability and maintainability

- Naming is clear without needing the PR description to understand it
- No duplicated logic that already exists elsewhere in the codebase
- Function/file size stays reasonable relative to the surrounding codebase's own conventions

## Output format

State findings grouped by severity, each with a file:line reference and a concrete fix, not just a description of the problem. End with a clear recommendation: APPROVE, APPROVE WITH COMMENTS, or BLOCK (with the specific blocking items listed).
