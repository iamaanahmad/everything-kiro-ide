---
name: "development-power"
displayName: "Development Power"
description: "Battle-tested workflows for code review, TDD, debugging, and quality assurance, packaged as guided steering for Kiro agents."
keywords: ["development", "code-review", "testing", "debugging", "tdd", "quality-assurance"]
author: "Everything Kiro"
---

# Development Power

A Knowledge Base Power — pure documentation and steering, no MCP servers. It packages four workflows that are otherwise easy to skip under deadline pressure: code review, TDD, debugging, and QA sign-off.

## Overview

Activate this power at the start of a development session and Kiro will follow these workflows instead of improvising ad hoc process each time. Because it's a Knowledge Base Power, activating it costs no MCP tool budget — it only loads documentation into context.

## Available Steering Files

Read these on-demand with the `readSteering` action rather than loading everything at once:

- **code-review-process.md** — Security-first review checklist (auth, injection, secrets) followed by performance and test-coverage checks. Use before merging PRs or reviewing security-sensitive code.
- **tdd-workflow.md** — RED-GREEN-REFACTOR cycle with concrete examples. Use when implementing new features or fixing bugs test-first.
- **debugging-strategies.md** — Systematic reproduce → gather → hypothesize → test → fix → verify loop. Use for bugs and performance regressions.
- **quality-assurance.md** — Pre-release checklist covering tests, security, performance, docs, and accessibility.

## Quick Start

```
activate development-power
read steering code-review-process.md from development-power
```

Then ask Kiro to review, implement, or debug — it will apply the relevant workflow instead of a generic response.

## Best Practices

- Activate before starting the task, not mid-way — the workflow shapes how work is sequenced.
- Reference a specific steering file when you know which workflow applies; let Kiro pick otherwise.
- Pair with the `code-reviewer`, `test-engineer`, and `debug-detective` agents in this repo — the power supplies the process, the agents supply the persona and tool scope.

## Troubleshooting

**Power doesn't activate** — confirm it's installed under `.kiro/powers/development-power/` (workspace) or `~/.kiro/powers/development-power/` (user), then retry `activate`.

**Steering file not found** — filenames are case-sensitive and must include `.md`; check the list above.
