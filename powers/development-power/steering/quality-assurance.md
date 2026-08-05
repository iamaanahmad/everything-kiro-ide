# Quality Assurance Checklist

Run through this before a release or before marking a feature complete.

## Tests

- [ ] Full test suite passes locally and in CI
- [ ] New code has unit tests for happy path and at least one failure case
- [ ] Integration tests cover the feature's interaction with real dependencies (DB, external APIs)
- [ ] No skipped or `.only` tests left in the suite

## Security

- [ ] No hardcoded secrets or credentials introduced
- [ ] Input validation present on all new user-facing inputs
- [ ] Dependency changes checked against known vulnerabilities (`npm audit` or equivalent)
- [ ] Auth/authorization changes reviewed specifically for privilege escalation risks

## Performance

- [ ] No obvious new N+1 queries or unbounded loops on hot paths
- [ ] Response times for changed endpoints measured, not assumed

## Documentation

- [ ] README, API docs, or OpenAPI spec updated to match behavior changes
- [ ] Environment variable changes reflected in `.env.example`
- [ ] Breaking changes called out explicitly in the PR/changelog

## Accessibility (UI changes)

- [ ] Interactive elements are keyboard-reachable and have visible focus states
- [ ] Images and icons have appropriate alt text or `aria-label`
- [ ] Color contrast meets at least WCAG AA for new UI

Note: this checklist supports a QA process but does not substitute for manual testing with assistive technology when a full accessibility review is required.

## Sign-off

Only mark a feature "done" when every checked item above is actually true, not aspirationally true. A checklist item that's unverified should stay unchecked.
