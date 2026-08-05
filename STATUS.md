# Everything Kiro — Status

## Current status: schemas verified against Kiro's actual current behavior (2026-08-05)

This repo was previously written against an early/assumed version of Kiro's hooks, specs, and powers systems, and the docs claimed several files that didn't actually exist on disk. Both problems are fixed as of this update.

## What's included

| Component | Count | Notes |
|---|---|---|
| Agents (`agents/*.md`) | 8 | architect, code-reviewer, test-engineer, devops-specialist, debug-detective, performance-optimizer, security-auditor, documentation-writer |
| Steering (`.kiro/steering/*.md`) | 5 | 3 `always`, 1 `fileMatch` example, 1 `manual` example |
| Hooks (`.kiro/hooks/*.json`) | 12 | v1 JSON schema, PascalCase triggers — see `hooks/README.md` |
| Powers (`powers/*`) | 3 | development-power, devops-power (Knowledge Base), database-power (Guided MCP) |
| Skills (`skills/**/*.md`) | 8 | development-workflows, language-patterns, infrastructure |
| Examples (`examples/*`) | 2 | example-spec (real `.kiro/specs/` layout), fullstack-webapp (config walkthrough) |
| Documentation | README, INSTALL, CONTRIBUTING, CHANGELOG, STATUS | all cross-checked against actual files |

## What changed in this pass

- **Hooks**: the previous `hooks/file-watchers.json` used a schema (`eventType`, `hookAction`, `outputPrompt`) that predates Kiro IDE 1.0 and does not run in current Kiro. Replaced with 12 files under `.kiro/hooks/` using the real v1 schema (`trigger`, `matcher`, `action.type`).
- **Powers**: `development-power` had a `power.json` file that doesn't exist in Kiro's actual schema (metadata belongs in `POWER.md` frontmatter), and its `POWER.md` referenced 4 steering files that didn't exist. Fixed the frontmatter and created the missing steering files. `devops-power` and `database-power` were documented in README/CHANGELOG as installed but had no directory at all — both now exist with real content.
- **Steering**: README and the previous STATUS.md claimed 3 steering files; only 1 (`coding-standards.md`) existed. Added the missing `security-rules.md` and `project-patterns.md`, plus two new examples (`api-conventions.md` for `fileMatch`, `release-checklist.md` for `manual`).
- **Specs**: README/STATUS/CHANGELOG all claimed a `specs/` directory with 3 templates that never existed. Kiro doesn't use standalone spec "templates" the way this repo previously implied — specs are generated per-feature under `.kiro/specs/{feature_name}/` using EARS-format requirements. Rewrote `skills/development-workflows/spec-driven-development.md` to match, and added a complete worked example under `examples/example-spec/`.
- **Documentation accuracy**: previous CHANGELOG.md claimed INSTALL.md, CONTRIBUTING.md, and COMPARISON.md were created; they didn't exist. INSTALL.md and CONTRIBUTING.md now exist for real. COMPARISON.md was dropped — its content is folded into README.md instead of living in a separate file.
- **Kiro Crew**: README now notes that [Kiro Crew](https://kiro.dev/blog/introducing-kiro-crew/) reads existing `.kiro` configuration, so the installed steering, hooks, skills, and custom-agent patterns are compatible. No Crew-specific manifest, schedules, Apps, integrations, or orchestration workflow is included.

## Known gaps / not attempted

- Language-specific skills beyond TypeScript/Python/React (Go, Rust, Java) — not added.
- No CI workflow validating hook JSON syntax or dead markdown links in this repo itself — worth adding if this grows.
