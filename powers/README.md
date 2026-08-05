# Kiro Powers

**Powers package documentation, workflows, and (optionally) MCP servers into a unit Kiro can activate on demand.** They exist so an agent doesn't have to load every MCP tool up front — it activates a power's context only when the conversation actually needs it.

Official docs: [kiro.dev/docs/powers](https://kiro.dev/docs/powers/) · Official power registry: [github.com/kirodotdev/powers](https://github.com/kirodotdev/powers)

---

## Two types of powers

**Guided MCP Power** — connects to an MCP server plus documentation.
```
my-power/
├── POWER.md    # required: frontmatter + docs
└── mcp.json    # required: MCP server config
```

**Knowledge Base Power** — pure documentation, no MCP server.
```
my-power/
└── POWER.md    # required: frontmatter + docs
```

Either type can add a `steering/` directory once `POWER.md` would otherwise exceed ~500 lines, or when the power has multiple independent workflows that shouldn't all load at once:
```
my-power/
├── POWER.md
├── mcp.json          # only for Guided MCP Powers
└── steering/
    ├── workflow-a.md
    └── workflow-b.md
```

There is **no `power.json`** — all metadata (name, displayName, description, keywords, author) lives in `POWER.md`'s frontmatter. `version`, `tags`, `repository`, and `license` are not real fields; don't add them.

## POWER.md frontmatter

```yaml
---
name: "my-power"
displayName: "My Power"
description: "Clear description, max 3 sentences, focused on value not implementation."
keywords: ["keyword1", "keyword2", "keyword3"]
author: "Your Name"
---
```

`name`, `displayName`, and `description` are required. `keywords` and `author` are optional but improve discoverability — Kiro activates a power proactively when the user's message matches its keywords.

## mcp.json (Guided MCP Powers only)

```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "@scope/server-package"],
      "env": { "API_KEY": "API_KEY_ENV_VAR" },
      "disabled": false,
      "autoApprove": ["read_only_tool_name"]
    }
  }
}
```

Use either a local server (`command`/`args`) or a remote one (`url`/`headers`), not both in the same entry. Never put display metadata here — that belongs in `POWER.md`'s frontmatter.

## The 5 power actions

| Action | What it does |
|---|---|
| `list` | Show all installed powers |
| `activate` | Load a power's `POWER.md`, tool schemas, and steering file list |
| `use` | Call a tool from an activated power |
| `readSteering` | Load one specific steering file on demand |
| `configure` | Open the Powers management panel to browse/install |

**Always activate before using.** `activate` is what tells the agent which tools exist and what their parameters are — guessing tool names without activating first will fail.

## File locations

| What | Workspace | User |
|---|---|---|
| Installed powers | `.kiro/powers/` | `~/.kiro/powers/` |
| MCP config generated from powers | — | `~/.kiro/powers.mcp.json` (auto-generated, don't edit by hand) |

## Powers in this repo

| Power | Type | Covers |
|---|---|---|
| [`development-power`](development-power/) | Knowledge Base | Code review, TDD, debugging, QA — see its 4 steering files |
| [`devops-power`](devops-power/) | Knowledge Base | Deployment checklists, Docker, CI/CD patterns |
| [`database-power`](database-power/) | Guided MCP | Postgres inspection/query via the `postgres` MCP server |

All three are examples meant to be copied and adapted — not a complete catalog. For AWS, Stripe, Terraform, Zapier, and dozens of other maintained powers, install directly from the [official registry](https://github.com/kirodotdev/powers) via the Powers panel (`configure` action) rather than reimplementing them here.

## Creating your own power

Default to a single power per tool/workflow — don't split into multiple powers unless the workflows are genuinely independent (e.g. local vs. remote environments with different auth). See the official [power-builder](https://github.com/kirodotdev/powers/blob/main/power-builder/POWER.md) power for the full authoring guide, including an interactive steering-guided creation flow.

```bash
mkdir -p .kiro/powers/my-power
# add POWER.md (+ mcp.json if it's a Guided MCP Power, + steering/ if needed)
```

Test locally via the `configure` action before sharing. Only install third-party powers from sources you trust — like any MCP server, a power can execute code or make network calls on your behalf.

## Contributing

Have a useful power to add? Follow the structure above, keep `POWER.md` under ~500 lines (split into `steering/` if it grows past that), and document exact tool names and parameters. See [CONTRIBUTING.md](../CONTRIBUTING.md).
