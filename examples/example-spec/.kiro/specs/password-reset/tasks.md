# Implementation Plan

- [ ] 1. Add password_reset_tokens table and migration
  - _Requirements: 2.1, 2.2_

- [ ] 2. Implement reset request endpoint
  - [ ] 2.1 Generate and store hashed token, send email with raw token link
    - _Requirements: 1.1_
  - [ ] 2.2 Return identical response regardless of whether the email exists
    - _Requirements: 1.2_
  - [ ] 2.3 Add per-email rate limiting on the request endpoint
    - _Requirements: 1.3_

- [ ] 3. Implement reset confirm endpoint
  - [ ] 3.1 Validate token hash, expiry, and used flag
    - _Requirements: 2.1, 2.3_
  - [ ] 3.2 Hash and store new password, mark token used, invalidate existing sessions
    - _Requirements: 2.2_

- [ ] 4. Wire endpoints into the auth router and write integration tests for the full flow
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3_
