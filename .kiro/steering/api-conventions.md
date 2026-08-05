---
inclusion: fileMatch
fileMatchPattern: "**/{routes,controllers,api}/**/*.{ts,js}"
---

# API Conventions

This file only loads into context when Kiro reads a file under a `routes/`, `controllers/`, or `api/` directory — it stays out of context the rest of the time to save tokens. Adjust `fileMatchPattern` to match your actual backend source layout.

## Response format

```typescript
// Success
res.json({ success: true, data, meta: { timestamp: new Date().toISOString() } })

// Error
res.status(statusCode).json({
  success: false,
  error: { code: 'VALIDATION_ERROR', message: '...' },
  meta: { timestamp: new Date().toISOString() }
})
```

## Status codes

- 200 success, 201 created
- 400 validation error, 401 unauthenticated, 403 unauthorized, 404 not found, 409 conflict, 422 unprocessable
- 500 only for genuinely unexpected server errors — don't use it for expected validation failures

## Validation

Validate every request body/query/params against a schema (Zod, Joi, class-validator) at the route boundary before it reaches business logic. Return field-level error details in the response so the client can highlight the specific input.
