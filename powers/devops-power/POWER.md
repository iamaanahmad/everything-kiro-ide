---
name: "devops-power"
displayName: "DevOps Power"
description: "Deployment, CI/CD, and container best practices for Kiro agents, covering Docker, release checklists, and rollback planning."
keywords: ["devops", "deployment", "cicd", "docker", "kubernetes", "release"]
author: "Everything Kiro"
---

# DevOps Power

A Knowledge Base Power — pure documentation, no MCP servers. It documents deployment and CI/CD practices so Kiro follows a consistent process instead of improvising release steps per project.

## Available Steering Files

- **deployment-checklist.md** — pre-deploy verification steps and rollback planning
- **docker-best-practices.md** — Dockerfile and docker-compose conventions (multi-stage builds, non-root users, layer caching)
- **cicd-patterns.md** — pipeline structure, required gates, and secrets handling in CI

## Quick Start

```
activate devops-power
read steering deployment-checklist.md from devops-power
```

## Best Practices

- Never let an agent run a production deployment command without explicit user confirmation — this power documents the process, it does not grant permission to bypass review.
- Pair with the `devops-specialist` agent in this repo for persona and tool scoping; this power supplies the checklist it should follow.

## Troubleshooting

**Steering file not found** — confirm the power is activated and the filename matches exactly, including `.md`.
