# Design Document

## Overview

Two endpoints — request and confirm — backed by a single-use, time-limited token stored hashed in the database. No new infrastructure required beyond the existing email service.

## Architecture

```
Client → POST /api/auth/password-reset/request → generates token, emails link
Client → POST /api/auth/password-reset/confirm  → validates token, sets new password
```

## Components and Interfaces

```typescript
interface PasswordResetService {
  requestReset(email: string): Promise<void> // always resolves, never reveals whether the email exists
  confirmReset(token: string, newPassword: string): Promise<void>
}
```

## Data Models

```sql
CREATE TABLE password_reset_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_reset_tokens_hash ON password_reset_tokens(token_hash);
```

The token itself is a random 32-byte value; only its hash is stored, mirroring how passwords are stored. The raw token goes in the email link and is never persisted.

## Error Handling

- Unknown email on request: respond identically to a known email (Requirement 1.2) to avoid account enumeration.
- Expired/used token on confirm: generic "this link is no longer valid" message, no distinction between expired vs. used.
- Rate limit exceeded: 429 with a `Retry-After` header.

## Testing Strategy

- Unit: token generation/hashing, expiry check, rate-limit counter
- Integration: full request → email → confirm flow against a test database
- Security: confirm that requesting a reset for a nonexistent email is indistinguishable (timing and response body) from a real one
