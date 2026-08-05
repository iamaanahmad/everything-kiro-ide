# Requirements Document

## Introduction

Self-service password reset for users who forget their password, delivered via a time-limited email link. This is a minimal example spec showing the real `.kiro/specs/{feature_name}/requirements.md` format and EARS acceptance criteria — copy the structure, not the specific feature.

## Requirements

### Requirement 1

**User Story:** As a user who forgot their password, I want to request a reset link by email, so that I can regain access without contacting support.

#### Acceptance Criteria

1. WHEN a user submits a valid, registered email to the reset-request endpoint THEN the system SHALL send an email containing a single-use reset link
2. WHEN a user submits an email that is not registered THEN the system SHALL return the same success response as a registered email, without indicating whether the account exists
3. IF a user requests more than 3 resets for the same email within 1 hour THEN the system SHALL reject further requests with a rate-limit response

### Requirement 2

**User Story:** As a user with a valid reset link, I want to set a new password, so that I can log in again.

#### Acceptance Criteria

1. WHEN a user opens a reset link that is less than 1 hour old and unused THEN the system SHALL allow submission of a new password
2. WHEN a user submits a new password that meets the complexity policy THEN the system SHALL hash and store it, invalidate the reset token, and invalidate all existing sessions for that user
3. IF a user opens a reset link that is expired or already used THEN the system SHALL reject the request and prompt them to request a new link

## Out of Scope

- Social login recovery
- Account recovery via SMS/phone
