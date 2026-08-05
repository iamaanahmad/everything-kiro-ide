# CI/CD Patterns

## Pipeline structure

A typical pipeline should gate progressively:

1. **Lint & type-check** — fastest checks, fail fast
2. **Unit tests** — run in parallel where possible
3. **Build** — produce the deployable artifact/image
4. **Integration tests** — against the built artifact, not source
5. **Deploy to staging** — automatic on merge to main
6. **Deploy to production** — manual approval gate, or automatic after staging soak time

## Required gates

- No merge to main without passing CI (lint, tests, build)
- No production deploy without a passing staging deploy first
- No skipping hooks or checks (`--no-verify`) as a normal practice — if a check is wrong, fix the check

## Secrets handling

- Store secrets in the CI provider's secret manager (GitHub Actions secrets, GitLab CI/CD variables), never in the repo.
- Scope secrets to the minimum environment/job that needs them — don't expose a production deploy key to a PR-triggered job.
- Rotate secrets on a schedule and immediately after any suspected exposure.

## Caching

- Cache dependency installs (`node_modules`, pip cache, etc.) keyed on the lockfile hash, not the branch name.
- Invalidate caches on lockfile changes automatically — a stale cache with mismatched dependencies causes hard-to-reproduce CI failures.

## Failure handling

- A flaky test that's retried into passing is a bug, not a feature — track and fix flaky tests rather than adding retries indefinitely.
- Pipeline failures should produce actionable output (which check failed, why) directly in the CI UI, not just "build failed."
