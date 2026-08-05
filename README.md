# Everything Kiro

**A collection of Kiro IDE configurations — agents, hooks, steering files, powers, and skills — kept in sync with Kiro's actual current schemas.**

This repo is inspired by [everything-claude-code](https://github.com/affaan-m/everything-claude-code), adapted for Kiro. Kiro's hooks, specs, and powers systems have all changed shape since IDE 1.0 shipped, so every config here targets the *current* format rather than the early-preview one.

---

## What's Inside

```
everything-kiro/
├── .kiro/                        # Drop this whole folder into a workspace to use everything at once
│   ├── settings/
│   │   └── mcp.json              # MCP server configs (workspace-level)
│   ├── steering/                 # Always-active + conditional + manual context
│   │   ├── coding-standards.md   # inclusion: always
│   │   ├── security-rules.md     # inclusion: always
│   │   ├── project-patterns.md   # inclusion: always
│   │   ├── api-conventions.md    # inclusion: fileMatch (loads only for routes/controllers/api files)
│   │   └── release-checklist.md  # inclusion: manual (loads via /release-checklist)
│   └── hooks/                    # v1 JSON hooks, PascalCase triggers
│       └── *.json                # 12 hooks — see hooks/README.md for the list
│
├── agents/                       # 8 specialized sub-agents
│   ├── architect.md
│   ├── code-reviewer.md
│   ├── test-engineer.md
│   ├── devops-specialist.md
│   ├── debug-detective.md
│   ├── performance-optimizer.md
│   ├── security-auditor.md
│   └── documentation-writer.md
│
├── powers/                       # Kiro Powers (POWER.md + optional mcp.json + optional steering/)
│   ├── README.md                 # Real Powers schema reference
│   ├── development-power/        # Knowledge Base Power: code review, TDD, debugging, QA
│   ├── devops-power/             # Knowledge Base Power: deploy checklist, Docker, CI/CD
│   └── database-power/           # Guided MCP Power: Postgres inspection via MCP
│
├── skills/                       # Workflow documentation, invoked by agents or read directly
│   ├── development-workflows/
│   │   ├── spec-driven-development.md   # Real .kiro/specs/ format, EARS acceptance criteria
│   │   └── tdd-cycle.md
│   ├── language-patterns/
│   │   ├── typescript-best-practices.md
│   │   ├── python-conventions.md
│   │   └── react-patterns.md
│   └── infrastructure/
│       ├── docker-workflows.md
│       ├── ci-cd-patterns.md
│       └── monitoring-setup.md
│
├── hooks/
│   └── README.md                 # Hook schema reference — the runnable hooks live in .kiro/hooks/
│
├── examples/
│   ├── example-spec/             # A real, complete .kiro/specs/password-reset/ example
│   └── fullstack-webapp/         # Example project-level Kiro config (MCP, hooks, steering)
│
├── INSTALL.md
├── CONTRIBUTING.md
├── CHANGELOG.md
└── STATUS.md
```

---

## Key Concepts (as they actually work today)

### Steering files

Markdown files in `.kiro/steering/` (workspace) or `~/.kiro/steering/` (user), loaded based on frontmatter:

```markdown
---
inclusion: always        # default — every conversation
# inclusion: fileMatch
# fileMatchPattern: "**/*.api.ts"
# inclusion: manual      # loaded via slash command or #reference, not automatically
---
```

`manual` steering files show up as slash commands (`/filename`) — this replaced the old "manual hook trigger" concept entirely. If you're coming from a pre-1.0 setup that used manual hooks for on-demand routines, that functionality now belongs in steering, not hooks.

### Hooks

Hooks are versioned JSON files at `.kiro/hooks/*.json` (workspace) or `~/.kiro/hooks/*.json` (user, applies to every workspace):

```json
{
  "version": "v1",
  "hooks": [{
    "name": "lint-on-save",
    "trigger": "PostFileSave",
    "matcher": "\\.ts$",
    "action": { "type": "command", "command": "npm run lint" },
    "timeout": 30
  }]
}
```

Triggers: `SessionStart`, `Stop`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PreTaskExec`, `PostTaskExec`, `PostFileCreate`, `PostFileSave`, `PostFileDelete`. `PreToolUse`, `UserPromptSubmit`, and `PreTaskExec` can **block** — a command action exiting with code 2 stops the operation and returns stderr to the agent. See [`hooks/README.md`](hooks/README.md) for the full reference and every hook included here.

If you have hooks from before IDE 1.0 (the `.hook` file format with `eventType`/`hookAction`), they won't run until migrated — open the Agent Hooks panel and convert them via the upgrade badge.

### Specs

Kiro's structured feature workflow: three gated files under `.kiro/specs/{feature_name}/`.

1. **requirements.md** — EARS-format acceptance criteria (`WHEN [event] THEN [system] SHALL [response]`), approved before moving on
2. **design.md** — architecture, interfaces, data models, addressing every requirement
3. **tasks.md** — a checkbox list of coding-only tasks, each tagged with the requirement(s) it satisfies

Each phase requires explicit user approval before the next begins. See [`skills/development-workflows/spec-driven-development.md`](skills/development-workflows/spec-driven-development.md) for the full format and [`examples/example-spec/`](examples/example-spec/) for a complete worked example. **Quick Spec** mode generates all three in one pass for smaller features, skipping the per-phase approval gates.

### Powers

Powers package documentation (and optionally an MCP server) into something Kiro activates on demand, so you don't pay the context cost of every possible tool up front:

- **Knowledge Base Power** — `POWER.md` only, no MCP server (`development-power`, `devops-power` here)
- **Guided MCP Power** — `POWER.md` + `mcp.json` (`database-power` here)

There's no `power.json` — all metadata lives in `POWER.md`'s YAML frontmatter. See [`powers/README.md`](powers/README.md) for the schema and [github.com/kirodotdev/powers](https://github.com/kirodotdev/powers) for the official, much larger catalog (AWS, Stripe, Terraform, Zapier, and more) — install those through the Powers panel rather than reimplementing them here.

### Agents

Sub-agents with a scoped persona, defined in `agents/*.md` with minimal frontmatter:

```markdown
---
name: code-reviewer
description: Expert code reviewer specializing in security, performance, maintainability...
---
```

Kiro can invoke these proactively based on context, or you can ask for one by name.

### MCP

External tool servers configured in `.kiro/settings/mcp.json` (workspace) or `~/.kiro/settings/mcp.json` (user, used as fallback if no workspace config exists). Keep enabled servers to what a project actually needs — every enabled MCP server's tools count against context budget.

### Kiro Crew

[Kiro Crew](https://kiro.dev/blog/introducing-kiro-crew/) runs on Kiro CLI and reads existing `.kiro` configuration. After installation, this repository's steering, hooks, skills, and custom-agent patterns can therefore be used by Crew without a separate migration.

This is compatibility documentation only: Everything Kiro intentionally does **not** ship a Crew manifest, schedules, Apps, integrations, or autonomous orchestration workflows. Configure those in Kiro Crew when and if your project needs them.

---

## Installation

See [INSTALL.md](INSTALL.md) for the full walkthrough. Short version:

```bash
git clone https://github.com/iamaanahmad/everything-kiro.git
cp -r everything-kiro/.kiro your-project/.kiro
cp -r everything-kiro/agents your-project/.kiro/agents
```

Then edit `.kiro/settings/mcp.json` and replace the placeholder tokens with real credentials — never commit real secrets.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: match the real schema (check kiro.dev/docs if unsure), keep claims in README/STATUS/CHANGELOG in sync with what's actually on disk, and don't add a component without also updating the file tree above.

---

## Resources

- [Kiro IDE](https://kiro.dev)
- [Kiro Docs](https://kiro.dev/docs)
- [Kiro Changelog](https://kiro.dev/changelog/) — hooks, specs, and powers have all changed shape at least once; check here before assuming a schema is current
- [Official Powers registry](https://github.com/kirodotdev/powers)
- [Model Context Protocol](https://modelcontextprotocol.io)
- Inspired by [everything-claude-code](https://github.com/affaan-m/everything-claude-code)

---

## License

MIT — use freely, modify as needed, contribute back if you can.
