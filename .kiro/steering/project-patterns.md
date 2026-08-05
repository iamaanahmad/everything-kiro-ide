---
inclusion: always
---

# Project Patterns

Common architectural and code-organization patterns to default to when a project doesn't already establish its own convention. If the existing codebase already has an established pattern, follow that instead of what's written here — consistency with the surrounding code wins over these defaults.

## Layered structure

Prefer separating concerns into layers with a one-way dependency direction:

```
presentation (controllers/routes) → application (use cases) → domain (business logic) → infrastructure (DB, external APIs)
```

Domain logic should not import from infrastructure directly; depend on an interface the infrastructure layer implements.

## API design

- RESTful resource naming: nouns for resources (`/users`, `/orders`), HTTP methods for actions.
- Consistent envelope for responses:
  ```json
  { "success": true, "data": {}, "meta": { "timestamp": "..." } }
  { "success": false, "error": { "code": "...", "message": "..." }, "meta": { "timestamp": "..." } }
  ```
- Version the API (`/api/v1/...`) once it has external consumers.
- Paginate list endpoints by default; don't return unbounded result sets.

## Error handling

- Use typed/custom error classes (`ValidationError`, `NotFoundError`, `AuthorizationError`) rather than throwing raw strings or generic `Error`.
- Map error types to HTTP status codes at the boundary, not scattered throughout business logic.
- Never swallow an error silently — log it with context, or let it propagate.

## Caching

- Cache-aside for read-heavy, infrequently-changing data (read from cache, populate on miss).
- Invalidate explicitly on writes rather than relying on TTL alone for data that must be consistent.
- Namespace cache keys by resource and version to avoid stale-data collisions after a schema change.

## State management (frontend)

- Keep server data (API responses) and client/UI state in separate stores — don't mix "data fetched from the API" with "is this modal open."
- Prefer colocating state with the component that owns it; lift state up only when multiple components genuinely need to share it.

## When patterns conflict

If this file's defaults conflict with a more specific steering file (e.g., a `fileMatch` steering file scoped to `backend/**`), the more specific file wins.
