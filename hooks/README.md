# Hooks

**The actual hook files live in [`.kiro/hooks/`](../.kiro/hooks/) — that's where Kiro loads them from.** This file just explains the format and how to install them.

## Why hooks moved to `.kiro/hooks/`

Kiro IDE 1.0 replaced the old `.hook` file format (`eventType` / `hookAction` / `outputPrompt`) with a versioned JSON schema. Hooks are now plain JSON files at:

- `.kiro/hooks/*.json` — workspace-scoped, checked into the repo
- `~/.kiro/hooks/*.json` — user-scoped, applies across every workspace

If you're migrating hooks created before IDE 1.0, open the Agent Hooks panel — hooks with an upgrade badge can be converted automatically, but the legacy files stay on disk unmigrated until you do that.

## Schema

```json
{
  "version": "v1",
  "hooks": [
    {
      "name": "lint-on-save",
      "trigger": "PostFileSave",
      "matcher": "\\.ts$",
      "action": { "type": "command", "command": "npm run lint" },
      "timeout": 30,
      "enabled": true
    }
  ]
}
```

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Unique identifier for the hook |
| `trigger` | yes | See trigger list below |
| `matcher` | no | Regex tested against the tool name (`PreToolUse`/`PostToolUse`) or file path (`PostFile*`). Omit to match everything |
| `action.type` | yes | `"command"` (shell) or `"agent"` (prompt injected into context) |
| `action.command` / `action.prompt` | yes | The shell command or the prompt text |
| `timeout` | no | Seconds before the command is killed (default 60) |
| `enabled` | no | Defaults to `true` |

## Triggers

| Trigger | Fires |
|---|---|
| `SessionStart` | New session begins |
| `Stop` | Agent turn completes |
| `UserPromptSubmit` | User sends a message (can block) |
| `PreToolUse` | Before a tool runs (can block, matcher = tool name) |
| `PostToolUse` | After a tool runs (matcher = tool name) |
| `PreTaskExec` | Before a spec task is marked in-progress (can block) |
| `PostTaskExec` | After a spec task is marked completed |
| `PostFileCreate` | A new file is created (matcher = file path) |
| `PostFileSave` | An existing file is saved (matcher = file path) |
| `PostFileDelete` | A file is deleted (matcher = file path) |

## Exit-code semantics (command actions)

- **Exit 0** — success. For `SessionStart`, `UserPromptSubmit`, and `PreToolUse`, stdout is forwarded into context.
- **Exit 2** — blocks the action. Only meaningful for `PreToolUse`, `UserPromptSubmit`, and `PreTaskExec`. Stderr is returned to the agent as the reason.
- **Any other exit code** — treated as a silent failure; the action proceeds.

For `PreToolUse`, a command can also exit 0 and print a JSON decision instead of blocking outright:

```json
{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"Writing to a config file — confirm first"}}
```

This prompts the user to confirm before the tool call proceeds, rather than hard-blocking it.

## What's in this repo

| File | Trigger | Purpose |
|---|---|---|
| `lint-and-format.json` | `PostFileSave` | Prettier + ESLint on JS/TS/JSON save |
| `type-check.json` | `PostFileSave` | `tsc --noEmit` on TS/TSX save |
| `test-related-files.json` | `PostFileSave` | Runs Jest for related tests under `src/` |
| `component-test-reminder.json` | `PostFileSave` | Agent check for missing component tests/a11y |
| `api-docs-reminder.json` | `PostFileSave` | Agent check for stale API docs |
| `migration-review.json` | `PostFileCreate` | Agent review of new DB migrations |
| `style-lint.json` | `PostFileSave` | Stylelint for CSS/SCSS |
| `env-security-check.json` | `PostFileSave` | Agent check for hardcoded secrets in env/Docker files |
| `security-audit-deps.json` | `PostFileSave` | Agent-driven `npm audit` on manifest changes |
| `block-sensitive-file-writes.json` | `PreToolUse` | **Blocking** — refuses writes to `.env`, `.pem`, `id_rsa`, etc. (exit 2) |
| `post-task-tests.json` | `PostTaskExec` | Runs the test suite after a spec task completes |
| `session-start-context.json` | `SessionStart` | Prints git status/last commit at session start |

All commands assume a Node.js project with `prettier`, `eslint`, `stylelint`, and `tsc` available. Adjust commands to match your stack, and always review a hook's `matcher` and `timeout` before relying on it — Kiro can generate hooks from natural language, but the generated JSON should still be checked by a human.

## Installing

Copy the files you want into your project's `.kiro/hooks/` directory, or into `~/.kiro/hooks/` if you want them to apply to every workspace:

```bash
mkdir -p .kiro/hooks
cp everything-kiro/.kiro/hooks/*.json .kiro/hooks/
```
