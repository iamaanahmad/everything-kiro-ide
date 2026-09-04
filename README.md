# Everything Kiro

**A collection of Kiro IDE configurations — agents, hooks, steering files, powers, and skills — kept in sync with Kiro's actual current schemas.**

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
├── agents/                       # 8 specialized agents (IDE 1.0 Markdown format)
│   ├── architect.md              # tools: read, web
│   ├── code-reviewer.md          # tools: read, web
│   ├── debug-detective.md        # tools: read, shell, web
│   ├── devops-specialist.md      # tools: read, write, shell, web
│   ├── documentation-writer.md   # tools: read, write, web
│   ├── performance-optimizer.md  # tools: read, shell, web
│   ├── security-auditor.md       # tools: read, web (shell: ask)
│   └── test-engineer.md          # tools: read, write, shell
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
│   ├── fullstack-webapp/         # Example project-level Kiro config (MCP, hooks, steering)
│   ├── AGENTS.md                 # AGENTS.md pattern: root, subdir, and infra examples
│   └── permissions.yaml          # permissions.yaml reference — copy to .kiro/settings/ or ~/.kiro/settings/
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

`manual` steering files show up as slash commands (`/filename`). This replaced the old "manual hook trigger" concept entirely.

### AGENTS.md

Place an `AGENTS.md` file anywhere in your workspace to give Kiro directory-scoped instructions — conventions, restrictions, stack details. A root-level `AGENTS.md` applies workspace-wide; nested ones narrow scope to their subtree. Instructions merge from parent to child; more specific files win on conflicts. Added in **IDE 1.0.309**.

```
my-project/
├── AGENTS.md          ← whole project
├── src/
│   └── AGENTS.md      ← src/ and below
└── infra/
    └── AGENTS.md      ← infra only
```

See [`examples/AGENTS.md`](examples/AGENTS.md) for root, API-layer, and infra examples.

### Hooks

Hooks are versioned JSON files at `.kiro/hooks/*.json` (workspace) or `~/.kiro/hooks/*.json` (user):

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

Triggers: `SessionStart`, `Stop`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PreTaskExec`, `PostTaskExec`, `PostFileCreate`, `PostFileSave`, `PostFileDelete`. `PreToolUse`, `UserPromptSubmit`, and `PreTaskExec` can **block** — a command action exiting with code 2 stops the operation. See [`hooks/README.md`](hooks/README.md) for the full reference.

Global (user-level) hooks apply across every workspace. Added in **IDE 1.0.182**.

Hooks also fire on **agent-driven file changes** (not just user saves). Added in **IDE 1.0.116**.

### Permissions

A capability-based system that controls what the agent can read, write, execute, and call. Replaces the old Trusted Commands / Command Denylist from 0.x. Rules live in YAML files:

- `~/.kiro/settings/permissions.yaml` — user scope, all projects
- `~/.kiro/workspace-roots/<hash>/permissions.yaml` — workspace scope, one project

Workspace permissions are stored *outside* the repo (per-user) so a cloned repo cannot inject rules.

```yaml
rules:
  - capability: shell
    match: ["git *", "npm *"]
    effect: allow
  - capability: fs_write
    match: ["**/.env", "**/*.key"]
    effect: deny
```

Capabilities: `fs_read`, `fs_write`, `shell`, `web_fetch`, `web_search`, `mcp`, `subagent`, `skill`, `power`. Priority: `deny > ask > allow`. See [`examples/permissions.yaml`](examples/permissions.yaml) for a full annotated reference.

### Custom Agents (IDE 1.0 format)

Agents are Markdown files in `.kiro/agents/` (workspace) or `~/.kiro/agents/` (user). The IDE 1.0 format adds `tools` tags, inline `permissions`, `welcomeMessage`, and more in the frontmatter:

```markdown
---
name: my-agent
description: What this agent does
tools: [read, write, shell, web]
welcomeMessage: "Ready. What are we working on?"
permissions:
  rules:
    - capability: shell
      match: ["npm *", "git *"]
      effect: allow
---

Your system prompt here...
```

Short-form `tools` tags: `read` = `fs_read`, `write` = `fs_write`, `shell`, `web` = web tools, `*` = all built-in tools. Switch agents mid-session without losing conversation history. The 8 agents in this repo each have an appropriate tools scope.

### Specs

Kiro's structured feature workflow: three gated files under `.kiro/specs/{feature_name}/`.

1. **requirements.md** — EARS-format acceptance criteria (`WHEN [event] THEN [system] SHALL [response]`)
2. **design.md** — architecture, interfaces, data models
3. **tasks.md** — checkbox list of coding-only tasks

Each phase requires explicit user approval before the next begins. **Quick Spec** mode generates all three in one pass for smaller features. See [`skills/development-workflows/spec-driven-development.md`](skills/development-workflows/spec-driven-development.md) and [`examples/example-spec/`](examples/example-spec/).

### Powers

Powers package documentation (and optionally an MCP server) into something Kiro activates on demand:

- **Knowledge Base Power** — `POWER.md` only (`development-power`, `devops-power`)
- **Guided MCP Power** — `POWER.md` + `mcp.json` (`database-power`)

Powers can also be packaged in the open **Agent Plugin format** (bundled skills + MCP), installable from a local folder or GitHub URL. Added in **IDE 1.0.288**.

No `power.json` — all metadata lives in `POWER.md` frontmatter. See [`powers/README.md`](powers/README.md) and the [official Powers registry](https://github.com/kirodotdev/powers).

### Agent Focus Mode

An experimental chat-first layout for directing multiple parallel agent sessions. Launch independent sessions, watch file changes as inline diffs, and use structured workflows (Spec, Plan, Bug Fix, Quick Spec) or freeform chat. Toggle from the top-right corner. Added in **IDE 1.0**; Cloud Sessions in Agent Focus added in **IDE 1.0.293**.

### Cloud Sessions

Run a session in the cloud alongside local ones. Start from Agent Focus Mode, pick the repositories it works against, and keep working after closing your laptop. Added in **IDE 1.0.293**.

### Cloud Configuration Sync

Steering files, custom agents, skills, powers, and hooks can be synced to your Kiro account and accessed across the IDE and Agent Focus. Cloud-managed items show a cloud indicator and open as read-only with an "Edit in web" action. Added in **IDE 1.0.437**.

### MCP

External tool servers configured in `.kiro/settings/mcp.json` (workspace) or `~/.kiro/settings/mcp.json` (user). Supports the latest MCP protocol revision including OAuth for servers that require sign-in. Keep enabled servers to what a project actually needs — every enabled MCP server's tools count against context budget.

### Kiro Crew

[Kiro Crew](https://kiro.dev/blog/introducing-kiro-crew/) runs on Kiro CLI and reads existing `.kiro` configuration. This repository's steering, hooks, skills, and custom-agent patterns carry over after installation without a separate migration.

This is compatibility documentation only: Everything Kiro does **not** ship a Crew manifest, schedules, Apps, integrations, or autonomous orchestration workflows.

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

See [CONTRIBUTING.md](CONTRIBUTING.md). Match the real schema (check kiro.dev/docs if unsure), keep claims in README/STATUS/CHANGELOG in sync with what's actually on disk, and don't add a component without also updating the file tree above.

---

## Resources

- [Kiro IDE](https://kiro.dev)
- [Kiro Docs](https://kiro.dev/docs)
- [Kiro Changelog](https://kiro.dev/changelog/) — check here before assuming a schema is current
- [Official Powers registry](https://github.com/kirodotdev/powers)
- [Model Context Protocol](https://modelcontextprotocol.io)
- Inspired by [everything-claude-code](https://github.com/affaan-m/everything-claude-code)

---

## License

MIT — use freely, modify as needed, contribute back if you can.
