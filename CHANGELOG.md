# Changelog

## [2026-09-04] IDE 1.0+ feature pass — permissions, AGENTS.md, updated agent format

This release tracks Kiro IDE changes from 1.0 (June 2026) through 1.0.437 (September 2026), adding the new features that landed in that window and updating existing components to match current schemas.

### Added

- **`examples/AGENTS.md`** — documents the `AGENTS.md` directory-scoped instruction pattern introduced in IDE 1.0.309. Shows three levels: root (whole project), `src/api/` (API conventions), and `infra/` (Terraform / destructive-op guardrails). Committed `AGENTS.md` files live next to the code they govern and are complementary to `.kiro/steering/`.
- **`examples/permissions.yaml`** — fully annotated reference for the capability-based permissions system that replaced Trusted Commands in IDE 1.0. Covers `deny`/`ask`/`allow` effects and glob patterns for `fs_read`, `fs_write`, `shell`, `web_fetch`, `web_search`, and `mcp` capabilities. Copy to `~/.kiro/settings/permissions.yaml` (user scope) or your workspace equivalent.

### Changed — agents (IDE 1.0 Markdown format)

All 8 agents in `agents/` now use the IDE 1.0 / CLI 3.0 agent configuration format:

- `tools` — short-form tags (`read`, `write`, `shell`, `web`) declare which capabilities each agent actually needs, replacing the previous "all tools, prompt for everything" default. Assignments by role:
  - `architect`, `code-reviewer` — `[read, web]` (analysis only, no writes)
  - `debug-detective`, `performance-optimizer` — `[read, shell, web]` (can run profiling/test commands)
  - `documentation-writer` — `[read, write, web]` (writes docs, no shell)
  - `devops-specialist` — `[read, write, shell, web]` (full access needed for infra work)
  - `test-engineer` — `[read, write, shell]` (writes tests, runs them)
  - `security-auditor` — `[read, web]` with inline `permissions: rules: [{capability: shell, effect: ask}]` (shell always prompts — auditors shouldn't execute silently)
- `welcomeMessage` — each agent now greets you with a context-setting prompt when you switch to it.

### Changed — README

Updated with new sections:

- **Permissions** — capability-based permissions system, YAML format, scope hierarchy, priority rules.
- **AGENTS.md** — directory-scoped instructions, nesting behavior, when to use vs steering.
- **Custom Agents** — IDE 1.0 format with `tools` tags, inline `permissions`, and `welcomeMessage`. Updated example.
- **Agent Focus Mode** — experimental multi-session layout (IDE 1.0), Cloud Sessions in Agent Focus (IDE 1.0.293).
- **Cloud Sessions** — cloud-hosted sessions, cloud configuration sync (IDE 1.0.437).
- **Powers** — Agent Plugin format note (IDE 1.0.288): powers can be packaged as open Agent Plugins installable from local folder or GitHub URL.
- **Hooks** — global (user-level) hooks note (IDE 1.0.182), hooks-on-agent-writes note (IDE 1.0.116).

### Reference: IDE releases covered in this pass

| Version | Date | Key additions tracked here |
|---|---|---|
| 1.0.0 | Jun 25 2026 | Permissions, Custom Agents (tools/permissions/welcomeMessage), Agent Focus Mode, natural-language hook creation |
| 1.0.116 | Jul 9 2026 | Hooks fire on agent-driven file changes |
| 1.0.182 | Jul 20 2026 | Global (user-level) hooks, searchable session history |
| 1.0.288 | Aug 7 2026 | Agent Plugin format for Powers |
| 1.0.293 | Aug 11 2026 | Cloud Sessions in Agent Focus Mode |
| 1.0.309 | Aug 13 2026 | Nested AGENTS.md files |
| 1.0.437 | Sep 1 2026 | Cloud Configuration Sync (steering, agents, skills, powers, hooks) |

---

## [2026-08-05] Schema correctness pass — align with Kiro's actual current behavior

This release fixes two classes of problems found in an audit against kiro.dev's current documentation and the [official Powers registry](https://github.com/kirodotdev/powers): configs written against an outdated/assumed schema, and documentation claiming files that never existed on disk.

### Fixed — outdated schemas

- **Hooks**: removed `hooks/file-watchers.json` (legacy `eventType`/`hookAction`/`outputPrompt` format, deprecated since Kiro IDE 1.0). Added 12 hooks under `.kiro/hooks/*.json` using the real v1 schema — `"version": "v1"`, PascalCase `trigger` (`PostFileSave`, `PostFileCreate`, `PreToolUse`, `PostTaskExec`, `SessionStart`, etc.), regex `matcher`, and `action.type` of `"command"` or `"agent"`. Added a `PreToolUse` hook demonstrating the exit-code-2 blocking behavior for guardrail use cases.
- **Powers**: removed `development-power/power.json` (not a real Kiro file — power metadata lives in `POWER.md` frontmatter). Rewrote `development-power/POWER.md` with correct frontmatter and created its 4 referenced steering files (`code-review-process.md`, `tdd-workflow.md`, `debugging-strategies.md`, `quality-assurance.md`), which previously didn't exist despite being documented. Built out `devops-power` (Knowledge Base Power: deployment checklist, Docker, CI/CD) and `database-power` (Guided MCP Power with a real `mcp.json` for Postgres) — both were referenced in old docs but had no directory.
- **Specs**: rewrote `skills/development-workflows/spec-driven-development.md` to use Kiro's actual EARS acceptance-criteria format (`WHEN/IF ... THEN ... SHALL ...`) and the real file location `.kiro/specs/{feature_name}/{requirements,design,tasks}.md`, including the per-phase approval gates and the "coding tasks only" constraint on tasks.md.

### Fixed — documentation vs. reality mismatches

- Added the 2 missing `.kiro/steering/` files (`security-rules.md`, `project-patterns.md`) that README and the previous STATUS.md claimed already existed.
- Removed all references to a `specs/feature-template.md` / `api-endpoint-template.md` / `refactor-template.md` directory — it never existed. Replaced with a real worked example at `examples/example-spec/.kiro/specs/password-reset/`.
- Created `INSTALL.md` and `CONTRIBUTING.md` for real — the previous CHANGELOG.md claimed both were already added when they weren't.
- Rewrote `README.md`'s file tree and `powers/README.md` to match what's actually in the repo, and to describe the real Powers/Hooks/Specs schemas instead of an earlier assumed version.

### Added

- README-level [Kiro Crew](https://kiro.dev/blog/introducing-kiro-crew/) compatibility note.
- `.kiro/steering/api-conventions.md` — example of `inclusion: fileMatch` scoped steering.
- `.kiro/steering/release-checklist.md` — example of `inclusion: manual` steering (loads via slash command).
- `hooks/README.md` — full trigger list, action types, and exit-code semantics reference.
- `powers/devops-power/`, `powers/database-power/` — previously documented, now real.
- `examples/example-spec/` — a complete, valid `.kiro/specs/password-reset/` example.

### Removed

- `hooks/file-watchers.json` (legacy schema, superseded by `.kiro/hooks/*.json`)
- `powers/development-power/power.json` (not part of Kiro's real Powers schema)
- Claims of a `COMPARISON.md` file — folded into README.md instead

---

## [2026-04-30] Initial release

Initial agent, steering, hook, power, and skill collection for Kiro IDE. Superseded by the 2026-08-05 pass above, which corrected several schema and documentation-accuracy issues introduced in this release.
