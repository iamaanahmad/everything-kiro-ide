# Changelog

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

- README-level [Kiro Crew](https://kiro.dev/blog/introducing-kiro-crew/) compatibility note: Crew reads existing `.kiro` configuration, so these steering, hooks, skills, and custom-agent patterns carry over after installation. No Crew-specific configuration or automation is included.
- `.kiro/steering/api-conventions.md` — example of `inclusion: fileMatch` scoped steering.
- `.kiro/steering/release-checklist.md` — example of `inclusion: manual` steering (loads via slash command, replacing the old "manual hook trigger" concept that Kiro removed in IDE 1.0).
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
