# Everything Kiro — Status

## Current status: updated for Kiro IDE 1.0+ through September 2026

Schemas verified against kiro.dev docs and the official changelog. This pass adds IDE 1.0 features: permissions, AGENTS.md, updated agent format with `tools` tags, Agent Focus Mode, Cloud Sessions, Cloud Configuration Sync, and Agent Plugin support for Powers.

## What's included

| Component | Count | Notes |
|---|---|---|
| Agents (`agents/*.md`) | 8 | IDE 1.0 Markdown format — frontmatter includes `tools`, `welcomeMessage`, and inline `permissions` where appropriate |
| Steering (`.kiro/steering/*.md`) | 5 | 3 `always`, 1 `fileMatch` example, 1 `manual` example |
| Hooks (`.kiro/hooks/*.json`) | 12 | v1 JSON schema, PascalCase triggers — see `hooks/README.md` |
| Powers (`powers/*`) | 3 | development-power, devops-power (Knowledge Base), database-power (Guided MCP) |
| Skills (`skills/**/*.md`) | 8 | development-workflows, language-patterns, infrastructure |
| Examples (`examples/*`) | 4 | example-spec, fullstack-webapp, AGENTS.md patterns, permissions.yaml reference |
| Documentation | README, INSTALL, CONTRIBUTING, CHANGELOG, STATUS | cross-checked against actual files |

## What changed in this pass (2026-09-04)

- **Agent format**: all 8 agents updated to IDE 1.0 Markdown format. Frontmatter now includes `tools` (short-form tags: `read`, `write`, `shell`, `web`) and `welcomeMessage`. `security-auditor` gets inline `permissions` to require approval on shell commands.
- **AGENTS.md**: new `examples/AGENTS.md` showing the directory-scoped instruction pattern added in IDE 1.0.309 — root-level, API-layer, and infra examples.
- **permissions.yaml**: new `examples/permissions.yaml` with a fully annotated reference for the capability-based permissions system that replaced Trusted Commands in IDE 1.0. Covers `deny`/`ask`/`allow` effects, glob patterns for filesystem, shell, and MCP capabilities.
- **README**: new sections covering Permissions, AGENTS.md, updated Custom Agents (IDE 1.0 format), Agent Focus Mode, Cloud Sessions, Cloud Configuration Sync, Agent Plugin format for Powers, global hooks, and hooks firing on agent-driven file changes.

## What changed in the previous pass (2026-08-05)

- **Hooks**: replaced `hooks/file-watchers.json` (legacy `eventType`/`hookAction` format) with 12 files under `.kiro/hooks/` using the real v1 schema.
- **Powers**: removed `development-power/power.json` (not a real schema file). Created missing steering files. Built out `devops-power` and `database-power`.
- **Steering**: added missing `security-rules.md` and `project-patterns.md` plus `api-conventions.md` (fileMatch) and `release-checklist.md` (manual).
- **Specs**: rewrote `skills/development-workflows/spec-driven-development.md` for the real EARS format; added `examples/example-spec/`.
- **Documentation**: created `INSTALL.md` and `CONTRIBUTING.md` for real; rewrote README file tree.
- **Kiro Crew**: README compatibility note added.

## Known gaps / not attempted

- Language-specific skills beyond TypeScript/Python/React (Go, Rust, Java) — not added.
- No CI workflow validating hook JSON syntax or dead markdown links — worth adding if this grows.
- `permissions.yaml` placed at `examples/` rather than `.kiro/settings/` because Kiro's hardcoded scope blocks agent writes to `.kiro/settings/`. Copy it manually.
- Cloud Configuration Sync and Cloud Sessions are documented but no cloud-specific config is included — those are account-level features managed in Kiro Web.
