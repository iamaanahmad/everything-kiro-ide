---
inclusion: manual
---

# Release Checklist

This file uses `inclusion: manual`, meaning it does **not** load automatically. It's pulled into context only when explicitly invoked as a slash command (`/release-checklist`) or referenced with `#release-checklist`. Use manual inclusion for content that's relevant occasionally, not on every turn — loading it always would waste context budget.

## Before tagging a release

- [ ] All CI checks green on the release branch
- [ ] CHANGELOG.md updated with user-facing changes
- [ ] Version bumped consistently across package.json/equivalent
- [ ] No open CRITICAL/HIGH severity issues from the last security scan

## Tagging and publishing

- [ ] Tag follows semver (`vX.Y.Z`)
- [ ] Release notes summarize changes by category (features, fixes, breaking changes)
- [ ] Breaking changes have a migration note

## Post-release

- [ ] Monitor error rates for the first hour after rollout
- [ ] Confirm the deployed version matches the tagged commit
