# Contributing to Everything Kiro

Contributions are welcome. Before opening a PR, a few things that matter more here than in most repos:

## Match Kiro's actual current schema

Kiro's hooks, specs, and powers formats have all changed since early preview. If you're adding or editing a hook, power, or spec example, check [kiro.dev/docs](https://kiro.dev/docs) or the [official powers repo](https://github.com/kirodotdev/powers) first rather than copying a pattern you saw in an older blog post or gist. A config that doesn't match Kiro's actual loader is worse than no config — it looks correct but silently does nothing.

Specifically:
- Hooks: `.kiro/hooks/*.json`, `version: "v1"`, PascalCase `trigger`, `action.type` of `"command"` or `"agent"`. Not `eventType`/`hookAction`.
- Powers: `POWER.md` with YAML frontmatter (`name`, `displayName`, `description`, `keywords`, `author`). No `power.json`, no `version` field.
- Specs: `.kiro/specs/{feature_name}/{requirements,design,tasks}.md`, EARS acceptance criteria in requirements, checkbox tasks with `_Requirements: x.x_` tags.

## Keep documentation honest

If you add a file, update the README.md tree diagram in the same PR. If you remove a file, remove its references from README.md, STATUS.md, and CHANGELOG.md too. This repo previously had a recurring problem of docs describing files that didn't exist (a `specs/` templates directory, extra steering files, extra powers) — don't reintroduce that. If something is planned but not built yet, say so explicitly rather than marking it ✅.

## What's useful to contribute

- New agents for domains not yet covered (mobile, data engineering, ML)
- New powers, following the real schema above — check they don't duplicate something already in the [official registry](https://github.com/kirodotdev/powers) before adding it here
- Corrections to anything that's drifted from Kiro's current behavior — these are the most valuable PRs this repo can get
- Additional worked examples under `examples/`

## Before submitting

- Verify JSON files are valid JSON (`hooks/*.json` — a syntax error means Kiro silently skips the whole file)
- Verify every internal markdown link resolves to a real file
- Keep secrets out of examples — use placeholder env var names, not real-looking keys
