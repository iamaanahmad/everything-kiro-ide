# AGENTS.md — directory-scoped agent instructions

> **What this file is:** Kiro reads `AGENTS.md` files placed anywhere in your workspace and applies the instructions inside them when the agent is working in that directory tree. This is the same concept as `.cursorrules` or `CLAUDE.md` — scoped context without a steering file.
>
> Added in **IDE 1.0.309** (August 2026). A root-level `AGENTS.md` applies workspace-wide; nested ones narrow scope to that subtree.

---

## How it works

```
my-project/
├── AGENTS.md              ← applies to the whole project
├── src/
│   ├── AGENTS.md          ← overrides/extends for src/ and below
│   └── api/
│       └── AGENTS.md      ← even more specific rules for the api layer
└── infra/
    └── AGENTS.md          ← infra-specific conventions
```

Instructions from nested files are merged with parent instructions. More specific files take precedence when there's a conflict.

---

## Root-level example (place at project root as `AGENTS.md`)

```markdown
# Project conventions for Kiro

## Stack
- Node.js 22 + TypeScript 5.5
- Express for HTTP, Prisma for ORM, PostgreSQL 16
- Vitest for tests, ESLint + Prettier for linting

## Code style
- Use 2-space indentation for all TS/JS files
- Prefer `const` over `let`; avoid `var`
- Keep functions under 50 lines; split larger ones
- Always add explicit return types to exported functions

## Testing
- Test files live next to source files as `*.test.ts`
- Run tests with: `npm test`
- Minimum 80% coverage; 100% for auth and payment modules

## Git
- Commit message format: `type(scope): description` (conventional commits)
- Never commit to `main` directly — always use a feature branch

## What NOT to do
- Don't touch `src/legacy/` — read-only, migration pending
- Don't add new npm dependencies without noting them in chat
- Don't modify `docker-compose.prod.yml` without confirmation
```

---

## Subdirectory example (place at `src/api/AGENTS.md`)

```markdown
# API layer conventions

## Routing
- All routes live in `src/api/routes/`
- File name = resource name: `users.ts`, `orders.ts`
- Use resource nouns, HTTP methods for actions — no verb routes

## Response envelope
All responses must use this shape:
  { "success": true, "data": {}, "meta": { "timestamp": "..." } }
  { "success": false, "error": { "code": "...", "message": "..." }, "meta": { "timestamp": "..." } }

## Validation
- Validate all inputs with Zod at the route handler boundary
- Never pass raw `req.body` to the service layer

## Auth
- Every route that touches user data MUST call `requireAuth()` middleware
- User ID comes from `req.user.id` — never from URL params alone
```

---

## Infra example (place at `infra/AGENTS.md`)

```markdown
# Infrastructure conventions

## Terraform
- All resources must have `Name` and `Environment` tags
- Use `terraform plan` before applying any changes
- State stored in S3 — never run `terraform init` with local backend

## Secrets
- Never hardcode credentials in `.tf` files — use AWS Secrets Manager references
- Rotate access keys every 90 days

## Destructive operations
- Any resource deletion requires explicit user confirmation — always ask before proceeding
```

---

## Tips

- Keep instructions concise and actionable — the agent reads the whole file on every relevant turn.
- `AGENTS.md` is complementary to `.kiro/steering/`: steering files are for project-wide conventions shared across sessions; `AGENTS.md` is for directory-local rules that live right next to the code they govern.
- Commit `AGENTS.md` files to version control so the whole team benefits.
