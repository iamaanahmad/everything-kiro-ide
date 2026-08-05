# Installing Everything Kiro

## Option 1: Copy everything into a workspace

```bash
git clone https://github.com/iamaanahmad/everything-kiro.git
cd your-project

# Steering, hooks, and MCP config
cp -r ../everything-kiro/.kiro/steering .kiro/steering
cp -r ../everything-kiro/.kiro/hooks .kiro/hooks
cp ../everything-kiro/.kiro/settings/mcp.json .kiro/settings/mcp.json

# Agents (Kiro reads these from .kiro/agents, not a top-level agents/ folder)
mkdir -p .kiro/agents
cp ../everything-kiro/agents/*.md .kiro/agents/

# Powers
mkdir -p .kiro/powers
cp -r ../everything-kiro/powers/development-power .kiro/powers/
cp -r ../everything-kiro/powers/devops-power .kiro/powers/
cp -r ../everything-kiro/powers/database-power .kiro/powers/
```

Pick and choose — you don't need all 12 hooks or all 3 powers. Delete what doesn't fit your project before committing.

## Option 2: User-level install (applies to every workspace)

```bash
cp -r everything-kiro/.kiro/steering ~/.kiro/steering
cp -r everything-kiro/.kiro/hooks ~/.kiro/hooks
cp -r everything-kiro/agents ~/.kiro/agents
cp -r everything-kiro/powers/* ~/.kiro/powers/
```

User-level hooks and steering apply across all workspaces automatically — useful for things like lint-on-save or security rules you want everywhere, less useful for project-specific things like `api-conventions.md`'s `fileMatchPattern`.

## Configure MCP servers

Edit `.kiro/settings/mcp.json` and replace every `*_ENV_VAR` / `YOUR_*_HERE` placeholder with a real environment variable reference or your actual credential — via your shell environment, not hardcoded into the JSON file.

**Never commit a config file with a real API key, token, or connection string.** If you accidentally commit one, rotate the credential immediately — removing it from a later commit does not remove it from git history.

Only enable the MCP servers you actually need for the current project. Every enabled server's tools count against your context budget; the repo ships 17 example server entries in `mcp.json` but only 5 are enabled by default (github, postgres, filesystem, git, docker).

## Migrating pre-1.0 hooks

If you have hooks from before Kiro IDE 1.0 (files using `eventType`/`hookAction`/`outputPrompt`), they will not run automatically after upgrading. Open the Agent Hooks panel in the IDE — hooks needing migration show an upgrade badge. Clicking it converts the hook to the v1 JSON format in place. The old file stays on disk but is no longer loaded.

## Verify

After copying files:
1. Restart Kiro or reload the workspace so it picks up the new `.kiro/` contents.
2. Open the Agent Hooks panel and confirm the hooks you copied appear and are enabled.
3. Ask Kiro "what steering files are active?" to confirm the always-on steering files loaded.
4. If you copied a power, run `activate <power-name>` to confirm it loads without errors.
